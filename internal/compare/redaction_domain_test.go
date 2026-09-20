package compare

import (
	"errors"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// A support artifact's pseudonyms are assigned by one redaction pass over one
// artifact. Two artifacts sanitized separately are two vocabularies, and these
// tests pin what may and may not be concluded by reading one against the other.
//
// The rule is one sentence: for anything redaction replaces, a match across
// two artifacts establishes nothing and a mismatch establishes nothing. What
// redaction leaves alone (statuses, causes, ports, protocols, booleans,
// derived conclusions) keeps its full meaning, which is why comparing two
// support artifacts is still worth doing.

// targeted returns the fixture renamed to host, with no IP literal, so the
// target's identity rests on the one field redaction rewrites.
func targeted(t *testing.T, host string) snapshot.Snapshot {
	t.Helper()
	s := fixture(t)
	s.Target.Raw, s.Target.Host, s.Target.IP = host, host, ""
	return s
}

func hasComparisonCaveat(c Comparison, want string) bool {
	for _, caveat := range c.Caveats {
		if strings.Contains(caveat, want) {
			return true
		}
	}
	return false
}

// The reported case, reduced to the property behind it: separate redaction
// passes restart their alias counters, so two unrelated hosts can both be
// named host-2.invalid. Nothing may read that as one endpoint.
func TestCollidingAliasesAreNotOneTarget(t *testing.T) {
	full, other := targeted(t, "example.com"), targeted(t, "github.com")
	a, b := snapshot.SanitizeForSupport(full), snapshot.SanitizeForSupport(other)
	if a.Target.Host != b.Target.Host {
		t.Fatalf("aliases %q and %q did not collide; this test needs the collision to mean anything",
			a.Target.Host, b.Target.Host)
	}

	c := Snapshots(a, b)
	if c.SameTarget {
		t.Error("same_target = true for two different endpoints whose aliases collided")
	}
	if !hasComparisonCaveat(c, "Support pseudonyms are assigned inside one artifact") {
		t.Errorf("caveats = %v, want one naming the per-artifact pseudonyms", c.Caveats)
	}
	// The header must not claim the other thing either: from these two files,
	// two endpoints is as unfounded as one.
	text := c.Text()
	if !strings.Contains(text, "do not establish whether they observed one target") {
		t.Errorf("report does not say the identity is unestablished:\n%s", text)
	}
	if strings.Contains(text, "observed different targets") {
		t.Errorf("report claims two endpoints it cannot know:\n%s", text)
	}

	var unknown UnknownTargetIdentityError
	if _, err := TwoSidedSnapshots(a, b); !errors.As(err, &unknown) {
		t.Fatalf("two-sided err = %v, want UnknownTargetIdentityError; colliding aliases bypassed the guard", err)
	}
}

// The other half of the same rule, and the one a reader is likelier to want
// violated: two artifacts of one real target still do not establish it. The
// alias that matches today is the alias a run with one more check would spell
// differently, so believing it here would mean believing it above too.
func TestIndependentlySanitizedSameTargetIsStillUnestablished(t *testing.T) {
	a := snapshot.SanitizeForSupport(targeted(t, "example.com"))
	b := snapshot.SanitizeForSupport(targeted(t, "example.com"))
	if c := Snapshots(a, b); c.SameTarget {
		t.Error("same_target = true from two artifacts that only agree on a pseudonym")
	}
	var unknown UnknownTargetIdentityError
	if _, err := TwoSidedSnapshots(a, b); !errors.As(err, &unknown) {
		t.Errorf("two-sided err = %v, want UnknownTargetIdentityError", err)
	}
}

// Differing aliases are not two endpoints either. One real host sanitized in
// two artifacts that collected different values can come out with two names,
// and a reading that treated that as a difference would be as wrong as one
// that treated a collision as a match.
func TestDifferingAliasesAreNotTwoTargets(t *testing.T) {
	a := snapshot.SanitizeForSupport(targeted(t, "example.com"))
	b := snapshot.SanitizeForSupport(targeted(t, "example.com"))
	b.Target.Host = "host-7.invalid"

	c := Snapshots(a, b)
	if c.SameTarget {
		t.Error("same_target = true for two pseudonyms from separate artifacts")
	}
	if strings.Contains(c.Text(), "observed different targets") {
		t.Errorf("report claims two endpoints from two aliases:\n%s", c.Text())
	}
	var unknown UnknownTargetIdentityError
	if _, err := TwoSidedSnapshots(a, b); !errors.As(err, &unknown) {
		t.Errorf("two-sided err = %v, want UnknownTargetIdentityError", err)
	}
}

// Full fidelity is untouched by all of this: the machine's own values are the
// same vocabulary on both sides, and both answers stay available.
func TestFullFidelityIdentityIsUnchanged(t *testing.T) {
	same, other := targeted(t, "example.com"), targeted(t, "github.com")

	c := Snapshots(same, targeted(t, "example.com"))
	if !c.SameTarget {
		t.Error("same_target = false for two full-fidelity runs of one endpoint")
	}
	if len(c.Caveats) != 0 {
		t.Errorf("caveats = %v, want none on a full-fidelity pair", c.Caveats)
	}
	if _, err := TwoSidedSnapshots(same, targeted(t, "example.com")); err != nil {
		t.Errorf("two full-fidelity runs of one endpoint were refused: %v", err)
	}

	d := Snapshots(same, other)
	if d.SameTarget {
		t.Error("same_target = true for two full-fidelity runs of different endpoints")
	}
	if !strings.Contains(d.Text(), "observed different targets") {
		t.Errorf("report does not name the differing endpoints:\n%s", d.Text())
	}
	// Different endpoints are still refused as different, not as unknown: the
	// files answered the question, and the refusal says which answer it was.
	var different DifferentTargetsError
	if _, err := TwoSidedSnapshots(same, other); !errors.As(err, &different) {
		t.Errorf("two-sided err = %v, want DifferentTargetsError", err)
	}
}

// A support artifact read against itself is one artifact, so the comparison
// still does its job: every row, no spurious difference, exit 0. What it does
// not do is claim an identity, because nothing in the file says these two
// readings came from one redaction pass rather than two that agreed.
func TestSanitizedArtifactComparedWithItselfStaysUseful(t *testing.T) {
	s := snapshot.SanitizeForSupport(targeted(t, "example.com"))
	c := Snapshots(s, s)
	mustNotChange(t, c, "a sanitized support artifact compared with itself")
	if len(c.Checks) != len(s.Checks) {
		t.Errorf("checks = %d rows, want the artifact's %d", len(c.Checks), len(s.Checks))
	}
	if !hasComparisonCaveat(c, "Support pseudonyms are assigned inside one artifact") {
		t.Errorf("caveats = %v, want one naming the per-artifact pseudonyms", c.Caveats)
	}
}

// Two generic runs have no target to rename, so nothing about them rests on a
// pseudonym and the two-sided reading still runs. This is the one shape where
// support artifacts reach the localization, and it is exactly the shape where
// the identity question never arises.
func TestSanitizedGenericRunsAreStillRead(t *testing.T) {
	a, b := fixture(t), fixture(t)
	a.Target, b.Target = nil, nil
	sa, sb := snapshot.SanitizeForSupport(a), snapshot.SanitizeForSupport(b)
	got, err := TwoSidedSnapshots(sa, sb)
	if err != nil {
		t.Fatalf("two sanitized generic runs were refused: %v", err)
	}
	if !got.SameTarget {
		t.Error("same_target = false for two runs that both named no target")
	}
	if !hasCaveat(got, "Support pseudonyms are local to each artifact") {
		t.Errorf("caveats = %v, want one naming the per-artifact pseudonyms", got.Caveats)
	}
}

// The rule is not about the target field. Every other value redaction replaces
// is a name owned by its own artifact too, and the two-sided evidence reading
// is where those reach a cross-artifact comparison. Colliding aliases there
// must not come back as equivalence.
func TestPseudonymizedEvidenceIsNeverCrossArtifactEquality(t *testing.T) {
	a, b := fixture(t), fixture(t)
	a.Target, b.Target = nil, nil
	// Different originals on the two machines. Separate redaction passes can
	// still hand both of them the same alias, which is the whole problem.
	setIdentity(t, &a, "wlan0", "Cafe Wifi", "192.0.2.10")
	setIdentity(t, &b, "eth0", "Office 5G", "198.51.100.77")
	sa, sb := snapshot.SanitizeForSupport(a), snapshot.SanitizeForSupport(b)

	got, err := TwoSidedSnapshots(sa, sb)
	if err != nil {
		t.Fatalf("two sanitized generic runs were refused: %v", err)
	}
	// Every dimension that names an address or a host-local identity has to be
	// unknown for that reason, whatever the aliases came out as. The ones that
	// do not name an identity stay readable, which is the point of naming them
	// one at a time.
	identity := map[string]bool{
		"addresses": true, "selected_ip": true, "resolver": true, "resolver_targets": true,
		"attempts": true, "route_tunnel": true, "route_selection": true, "route_link_mtu": true,
	}
	seen := 0
	for _, row := range got.Checks {
		for _, e := range row.Evidence {
			if !identity[e.Dimension] {
				continue
			}
			seen++
			if e.Relation != "unknown" || e.Reason != "redacted_identity" {
				t.Errorf("%s/%s = %q (%q), want unknown/redacted_identity: aliases from two artifacts were read as identities",
					row.ID, e.Dimension, e.Relation, e.Reason)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no identity dimension was compared; the test proves nothing")
	}
}

// setIdentity puts one machine's own names on every row that records them, so
// a test can give the two sides genuinely different originals.
func setIdentity(t *testing.T, s *snapshot.Snapshot, iface, ssid, resolver string) {
	t.Helper()
	touched := false
	for i := range s.Checks {
		o := s.Checks[i].Observed
		if o == nil {
			continue
		}
		if o.Interface != "" {
			o.Interface, touched = iface, true
		}
		if o.SSID != "" {
			o.SSID, touched = ssid, true
		}
		if o.Resolver != "" {
			o.Resolver, touched = resolver, true
		}
		for j := range o.Routes {
			if o.Routes[j].Interface != "" {
				o.Routes[j].Interface = iface
			}
		}
	}
	if !touched {
		t.Fatal("the fixture records no interface, SSID, or resolver to rename")
	}
}

// Not every target dimension is a pseudonym. Redaction records the port, the
// protocol, whether the run had a target at all, and whether that target was
// an IP literal rather than a name, all verbatim. A difference in one of those
// is a difference in the endpoint that two sanitized artifacts do establish,
// and answering "unknown" there would discard what the files actually say.
func TestNonRedactedTargetDimensionsStillSeparateEndpoints(t *testing.T) {
	cases := []struct {
		name  string
		apply func(*snapshot.Snapshot)
	}{
		{"port", func(s *snapshot.Snapshot) { s.Target.Port = 8443 }},
		{"protocol", func(s *snapshot.Snapshot) { s.Target.Protocol = "tcp" }},
		{"no target at all", func(s *snapshot.Snapshot) { s.Target = nil }},
		{"IP literal against a name", func(s *snapshot.Snapshot) {
			s.Target.Raw, s.Target.Host, s.Target.IP = "192.0.2.10", "192.0.2.10", "192.0.2.10"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left := targeted(t, "example.com")
			right := targeted(t, "example.com")
			tc.apply(&right)
			a, b := snapshot.SanitizeForSupport(left), snapshot.SanitizeForSupport(right)

			c := Snapshots(a, b)
			if c.SameTarget {
				t.Error("same_target = true for two endpoints that differ in a field redaction keeps")
			}
			if !strings.Contains(c.Text(), "observed different targets") {
				t.Errorf("report hedges a difference the artifacts establish:\n%s", c.Text())
			}
			var different DifferentTargetsError
			if _, err := TwoSidedSnapshots(a, b); !errors.As(err, &different) {
				t.Errorf("two-sided err = %v, want DifferentTargetsError", err)
			}
		})
	}
}

// The mixed-fidelity caveat says what redaction can explain, and no more. Some
// values survive a support pass as themselves, a retained public resolver
// address among them, so a caveat claiming every name and address below differs
// would be false about the file it annotates.
func TestMixedFidelityCaveatDoesNotClaimEveryValueDiffers(t *testing.T) {
	plain := fixture(t)
	c := Snapshots(plain, snapshot.SanitizeForSupport(fixture(t)))
	if !hasComparisonCaveat(c, "may differ for that reason alone") {
		t.Errorf("caveats = %v, want one saying redaction may explain a differing name or address", c.Caveats)
	}
	for _, overstated := range []string{"every name", "every value", "differs for that reason alone."} {
		if hasComparisonCaveat(c, overstated) {
			t.Errorf("caveats = %v, want none claiming %q of the values below", c.Caveats, overstated)
		}
	}
}
