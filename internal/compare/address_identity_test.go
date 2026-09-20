package compare

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// One address has more than one spelling, and an artifact records whichever one
// its producer wrote. These tests pin the rule that both readings apply to the
// address-valued observations: equivalent spellings are one recording, real
// differences survive, and the two readings never answer differently about the
// same address.

// The fixture's own IPv6 answer, the expanded spelling of it, and an address
// that really is another one.
const (
	compressedV6 = "2606:2800:220:1:248:1893:25c8:1946"
	expandedV6   = "2606:2800:0220:0001:0248:1893:25c8:1946"
	otherV6      = "2606:2800:220:1:248:1893:25c8:1947"
)

// respellIPv6 rewrites every recording of one address on one row to another
// spelling, leaving every other reading the row made alone.
func respellIPv6(t *testing.T, s *snapshot.Snapshot, id, from, to string) {
	t.Helper()
	o := check(t, s, id).Observed
	found := false
	for i, address := range o.Addresses {
		if address == from {
			o.Addresses[i], found = to, true
		}
	}
	for i, attempt := range o.Attempts {
		if attempt.IP == from {
			o.Attempts[i].IP, found = to, true
		}
	}
	if !found {
		t.Fatalf("fixture row %s records no %s", id, from)
	}
}

// A resolver answered with one address, and the two files spell it
// differently. That is one recorded answer, and it is not a change in
// anything. An answer that really is a different address still is.
func TestEquivalentResolvedAddressSpellingsAreOneAnswer(t *testing.T) {
	before, after := fixture(t), fixture(t)
	respellIPv6(t, &after, "dns", compressedV6, expandedV6)
	mustNotChange(t, Snapshots(before, after), "respelling one resolved IPv6 address")

	other := fixture(t)
	respellIPv6(t, &other, "dns", compressedV6, otherV6)
	c := Snapshots(before, other)
	added := changeAt(t, c, "checks.dns.observed.addresses."+otherV6)
	if added.Kind != KindAdded || added.After != otherV6 {
		t.Errorf("added address = %+v, want the new answer", added)
	}
	removed := changeAt(t, c, "checks.dns.observed.addresses."+compressedV6)
	if removed.Kind != KindRemoved || removed.Before != compressedV6 {
		t.Errorf("removed address = %+v, want the old answer", removed)
	}
}

// A resolver target is an address and a port, so it has its own identity rule:
// the spelling of the address normalizes and the port never does.
func TestResolverTargetIdentityIsAddressAndPort(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"[2001:db8::53]:53", "[2001:0db8:0000:0000:0000:0000:0000:0053]:53", true},
		{"[2001:db8::53]:53", "[2001:DB8::53]:53", true},
		// An observation unmaps, the way every producer of one already writes
		// a mapped IPv4 address.
		{"192.0.2.53:53", "[::ffff:192.0.2.53]:53", true},
		// The port is half the identity. One resolver reached on two ports is
		// two recordings, and a respelling rule must not hide that.
		{"[2001:db8::53]:53", "[2001:db8::53]:5353", false},
		{"[2001:db8::53]:53", "[2001:db8::54]:53", false},
		// Not an endpoint at all. Nothing parses it into equality with
		// anything else, and it compares as the bytes it is.
		{"resolver.example", "resolver.example", true},
		{"resolver.example", "[2001:db8::53]:53", false},
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			before, after := fixture(t), fixture(t)
			check(t, &before, "dns").Observed.ResolverTargets = []string{tc.a}
			check(t, &after, "dns").Observed.ResolverTargets = []string{tc.b}
			c := Snapshots(before, after)
			if tc.same {
				mustNotChange(t, c, "respelling one resolver target")
				return
			}
			if len(c.Changes) != 2 {
				t.Fatalf("changes = %v, want the old target removed and the new one added", paths(c))
			}
			for _, change := range c.Changes {
				if change.Before != tc.a && change.After != tc.b {
					t.Errorf("change = %+v, want the two recorded spellings verbatim", change)
				}
			}
		})
	}
}

// A connection attempt is keyed by the address it went to, and that address is
// read as an address. The outcome recorded under it is untouched by that.
func TestEquivalentAttemptSpellingIsOneAttemptIdentity(t *testing.T) {
	before, after := fixture(t), fixture(t)
	respellIPv6(t, &after, "target_tcp", compressedV6, expandedV6)
	mustNotChange(t, Snapshots(before, after), "respelling one connection attempt address")

	attempts := check(t, &after, "target_tcp").Observed.Attempts
	for i := range attempts {
		if attempts[i].IP == expandedV6 {
			attempts[i].Cause = "connection_refused"
		}
	}
	// The identity survived the respelling, so the change is the outcome and
	// the path is the address both files are about.
	got := changeAt(t, Snapshots(before, after), "checks.target_tcp.observed.attempts."+compressedV6+".cause")
	if got.Kind != KindChanged || got.Before != "unreachable" || got.After != "connection_refused" {
		t.Errorf("attempt cause = %+v, want the outcome change", got)
	}
}

// Identity is internal. What the report publishes, in the path as much as in
// the values, is the spelling the artifact recorded, so normalizing equality
// does not change netdoc.comparison.v1 paths for files netdoc already accepted
// and does not rewrite the spelling a third-party file carries.
func TestRecordedSpellingsSurviveIntoComparisonPaths(t *testing.T) {
	const expandedOther = "2606:2800:0220:0001:0248:1893:25c8:1947"

	// A member gained, spelled the way the after artifact spells it.
	before, gained := fixture(t), fixture(t)
	o := check(t, &gained, "dns").Observed
	o.Addresses = append(o.Addresses, expandedOther)
	got := changeAt(t, Snapshots(before, gained), "checks.dns.observed.addresses."+expandedOther)
	if got.Kind != KindAdded || got.After != expandedOther {
		t.Errorf("added address = %+v, want the after artifact's spelling in path and value", got)
	}

	// The same member lost, spelled the way the before artifact spells it.
	got = changeAt(t, Snapshots(gained, before), "checks.dns.observed.addresses."+expandedOther)
	if got.Kind != KindRemoved || got.Before != expandedOther {
		t.Errorf("removed address = %+v, want the before artifact's spelling in path and value", got)
	}

	// A record matched across two spellings reports under the before
	// artifact's spelling, which is the path such a change has always had.
	noncanonical, canonical := fixture(t), fixture(t)
	respellIPv6(t, &noncanonical, "target_tcp", compressedV6, expandedV6)
	for i, a := range check(t, &canonical, "target_tcp").Observed.Attempts {
		if a.IP == compressedV6 {
			check(t, &canonical, "target_tcp").Observed.Attempts[i].Cause = "connection_refused"
		}
	}
	got = changeAt(t, Snapshots(noncanonical, canonical), "checks.target_tcp.observed.attempts."+expandedV6+".cause")
	if got.Before != "unreachable" || got.After != "connection_refused" {
		t.Errorf("attempt cause = %+v, want the outcome change verbatim", got)
	}

	// Routes the same way, matched through equivalent destinations.
	route := func(dst, gateway string) snapshot.Route {
		return snapshot.Route{Destination: dst, Family: "ipv6", Interface: "eth0", Gateway: gateway, Tunnel: snapshot.TunnelStateDirect}
	}
	from, to := fixture(t), fixture(t)
	withRoutes(t, &from, "target_tcp", route("2001:0db8:0000:0000:0000:0000:0000:0007", "2001:db8::1"))
	withRoutes(t, &to, "target_tcp", route("2001:db8::7", "2001:db8::2"))
	got = changeAt(t, Snapshots(from, to), "checks.target_tcp.observed.routes.2001:0db8:0000:0000:0000:0000:0000:0007.gateway")
	if got.Before != "2001:db8::1" || got.After != "2001:db8::2" {
		t.Errorf("gateway change = %+v, want the two recorded next hops", got)
	}
}

// An address dialed twice records two outcomes, and normalizing the identity
// key must not merge them. The canceled attempt and the retry that verified it
// are still two recordings under one address.
func TestRespelledRepeatedAttemptsKeepEveryOutcome(t *testing.T) {
	canceled := snapshot.Attempt{IP: compressedV6, Error: "canceled", Cause: "canceled", Aborted: true}
	verified := snapshot.Attempt{IP: compressedV6, Error: "deadline exceeded", Cause: "timeout"}
	respelled := []snapshot.Attempt{{IP: expandedV6, Error: verified.Error, Cause: verified.Cause}, {IP: expandedV6, Error: canceled.Error, Cause: canceled.Cause, Aborted: true}}

	before, after := fixture(t), fixture(t)
	check(t, &before, "target_tcp").Observed.Attempts = []snapshot.Attempt{canceled, verified}
	check(t, &after, "target_tcp").Observed.Attempts = respelled
	mustNotChange(t, Snapshots(before, after), "respelling both attempts to one address")

	check(t, &after, "target_tcp").Observed.Attempts = respelled[:1]
	got := changeAt(t, Snapshots(before, after), "checks.target_tcp.observed.attempts."+compressedV6+".outcomes")
	if got.Kind != KindChanged {
		t.Errorf("outcomes = %+v, want the lost cancellation reported", got)
	}
}

// The scalar address readings, one rule for all of them.
func TestEquivalentScalarAddressSpellingsAreOneObservation(t *testing.T) {
	for _, field := range []struct {
		name, id, path string
		set            func(*snapshot.Observed, string)
	}{
		{"selected_ip", "internet_tcp", "checks.internet_tcp.observed.selected_ip",
			func(o *snapshot.Observed, v string) { o.SelectedIP = v }},
		{"resolver", "dns_public", "checks.dns_public.observed.resolver",
			func(o *snapshot.Observed, v string) { o.Resolver = v }},
		{"source_ip", "iface", "checks.iface.observed.source_ip",
			func(o *snapshot.Observed, v string) { o.SourceIP = v }},
	} {
		t.Run(field.name, func(t *testing.T) {
			before, same, other := fixture(t), fixture(t), fixture(t)
			field.set(check(t, &before, field.id).Observed, compressedV6)
			field.set(check(t, &same, field.id).Observed, expandedV6)
			field.set(check(t, &other, field.id).Observed, otherV6)

			if c := Snapshots(before, same); slices.Contains(paths(c), field.path) {
				t.Errorf("changes = %v, want no %s change for one address spelled two ways", paths(c), field.name)
			}
			got := changeAt(t, Snapshots(before, other), field.path)
			if got.Before != compressedV6 || got.After != otherV6 {
				t.Errorf("change = %+v, want the two recorded spellings verbatim", got)
			}
		})
	}
}

// Every producer of an observation writes a mapped IPv4 address as IPv4, so the
// two spellings are one recording here. Target identity keeps them apart on
// purpose, and TestEquivalentIPLiteralSpellingsAreOneEndpoint pins that.
func TestMappedIPv4IsTheSameObservationAsIPv4(t *testing.T) {
	before, after := fixture(t), fixture(t)
	check(t, &before, "iface").Observed.SourceIP = "192.0.2.10"
	check(t, &after, "iface").Observed.SourceIP = "::ffff:192.0.2.10"
	mustNotChange(t, Snapshots(before, after), "a source address recorded in its IPv4-mapped form")
	if !Snapshots(before, after).SameTarget {
		t.Error("an observation respelling moved the target identity")
	}
}

// A route decision is keyed by its destination, and its next hop, local source
// and matched prefix are addresses too. Spelling normalizes; structure does not.
func TestRouteAddressIdentityNormalizesSpellingOnly(t *testing.T) {
	v6Route := func(dst, prefix, gateway, source string) snapshot.Route {
		return snapshot.Route{
			Destination: dst, Family: "ipv6", Interface: "eth0", Prefix: prefix,
			Gateway: gateway, Source: source, Tunnel: snapshot.TunnelStateDirect,
		}
	}
	before := fixture(t)
	withRoutes(t, &before, "target_tcp", v6Route("2001:db8::7", "2001:db8::/32", "2001:db8::1", "2001:db8::10"))

	after := fixture(t)
	withRoutes(t, &after, "target_tcp", v6Route(
		"2001:0db8:0000:0000:0000:0000:0000:0007", "2001:0db8:0000::/32", "2001:0DB8::1", "2001:db8:0:0:0:0:0:10"))
	mustNotChange(t, Snapshots(before, after), "respelling every address in one route decision")

	// A prefix that covers the same addresses from a different entry is a
	// different entry. Nothing masks it into the one above.
	host := fixture(t)
	withRoutes(t, &host, "target_tcp", v6Route("2001:db8::7", "2001:db8::7/32", "2001:db8::1", "2001:db8::10"))
	got := changeAt(t, Snapshots(before, host), "checks.target_tcp.observed.routes.2001:db8::7.prefix")
	if got.Before != "2001:db8::/32" || got.After != "2001:db8::7/32" {
		t.Errorf("prefix change = %+v, want the two recorded entries verbatim", got)
	}

	// A next hop that really moved is still reported, with what each file said.
	moved := fixture(t)
	withRoutes(t, &moved, "target_tcp", v6Route("2001:db8::7", "2001:db8::/32", "2001:db8::2", "2001:db8::10"))
	got = changeAt(t, Snapshots(before, moved), "checks.target_tcp.observed.routes.2001:db8::7.gateway")
	if got.Before != "2001:db8::1" || got.After != "2001:db8::2" {
		t.Errorf("gateway change = %+v, want the two recorded next hops", got)
	}

	// A destination on one side only is still a member change, reported with
	// the spelling the file that has it carries.
	gained := fixture(t)
	withRoutes(t, &gained, "target_tcp",
		v6Route("2001:db8::7", "2001:db8::/32", "2001:db8::1", "2001:db8::10"),
		v6Route("2001:0db8:0000:0000:0000:0000:0000:0008", "2001:db8::/32", "2001:db8::1", "2001:db8::10"))
	got = changeAt(t, Snapshots(before, gained), "checks.target_tcp.observed.routes.2001:0db8:0000:0000:0000:0000:0000:0008")
	if got.Kind != KindAdded || got.After != "2001:0db8:0000:0000:0000:0000:0000:0008" {
		t.Errorf("added destination = %+v, want the recorded spelling in the path and the value", got)
	}
}

// The derived path reading finds the decision for the address the check used
// by matching two recordings of one address, which two producers are free to
// spell differently.
func TestDerivedPathMatchesTheSelectedAddressAsAnAddress(t *testing.T) {
	onLink := func(dst string) snapshot.Route {
		return snapshot.Route{Destination: dst, Family: "ipv6", Interface: "wg0", Tunnel: snapshot.TunnelStateTunnel, TunnelKind: "wireguard"}
	}
	elsewhere := snapshot.Route{Destination: "2001:db8::99", Family: "ipv6", Interface: "eth0", Tunnel: snapshot.TunnelStateDirect}

	before, after := fixture(t), fixture(t)
	for _, side := range []struct {
		s        *snapshot.Snapshot
		selected string
		dst      string
	}{
		{&before, "2001:db8::7", "2001:db8::7"},
		{&after, "2001:0db8:0000:0000:0000:0000:0000:0007", "2001:0db8::7"},
	} {
		check(t, side.s, "target_tcp").Observed.SelectedIP = side.selected
		withRoutes(t, side.s, "target_tcp", elsewhere, onLink(side.dst))
	}
	c := Snapshots(before, after)
	for _, path := range []string{"paths.target.interface", "paths.target.tunnel"} {
		if slices.Contains(paths(c), path) {
			t.Errorf("changes = %v, want no %s change: both runs selected one address", paths(c), path)
		}
	}
}

// The prefix rule normalizes CIDR spelling, and the words the derived reading
// uses where there is no CIDR to report are not CIDR and compare as themselves.
func TestDerivedTargetPrefixNormalizesSpelling(t *testing.T) {
	before, after := fixture(t), fixture(t)
	for _, side := range []struct {
		s      *snapshot.Snapshot
		prefix string
	}{{&before, "2001:db8::/32"}, {&after, "2001:0db8:0000::/32"}} {
		selected := "2001:db8::7"
		check(t, side.s, "target_tcp").Observed.SelectedIP = selected
		route := snapshot.Route{Destination: selected, Family: "ipv6", Interface: "eth0", Prefix: side.prefix, Tunnel: snapshot.TunnelStateDirect}
		withRoutes(t, side.s, "target_tcp", route)
	}
	mustNotChange(t, Snapshots(before, after), "respelling the matched prefix")

	gone := fixture(t)
	check(t, &gone, "target_tcp").Observed.SelectedIP = "2001:db8::7"
	withRoutes(t, &gone, "target_tcp", snapshot.Route{Destination: "2001:db8::7", Family: "ipv6", Unreachable: true})
	if got := changeAt(t, Snapshots(before, gone), "paths.target.prefix"); got.After != "no route" {
		t.Errorf("matched route = %q -> %q, want it to say there is none", got.Before, got.After)
	}
}

// The support artifact's erasure marker is not an address, and no address rule
// may start reading it as one.
func TestRedactionMarkerIsNeverReadAsAnAddress(t *testing.T) {
	const marker = "<address-redacted>"
	before, after := fixture(t), fixture(t)
	check(t, &before, "iface").Observed.SourceIP = marker
	check(t, &after, "iface").Observed.SourceIP = marker
	mustNotChange(t, Snapshots(before, after), "two rows whose source address was erased")

	check(t, &after, "iface").Observed.SourceIP = "192.0.2.10"
	got := changeAt(t, Snapshots(before, after), "checks.iface.observed.source_ip")
	if got.Before != marker || got.After != "192.0.2.10" {
		t.Errorf("change = %+v, want an erased reading against a recorded one", got)
	}
}

// Normalizing spelling changes nothing about what a pseudonym is worth. Two
// separately sanitized files are still two vocabularies, the comparison still
// says so, and it still refuses to call their targets one endpoint.
func TestAddressIdentityDoesNotTrustPseudonymsAcrossArtifacts(t *testing.T) {
	a := snapshot.SanitizeForSupport(fixture(t))
	b := snapshot.SanitizeForSupport(fixture(t))
	c := Snapshots(a, b)
	if c.SameTarget {
		t.Error("two separately sanitized artifacts were read as one endpoint")
	}
	if len(c.Caveats) == 0 {
		t.Error("a comparison of two support artifacts carried no pseudonym caveat")
	}
	if _, err := TwoSidedSnapshots(a, b); err == nil {
		t.Error("two-sided read two separately sanitized artifacts as one endpoint")
	}
	// The address dimensions of a sanitized pair stay unknown rather than
	// becoming equivalence, whatever the pseudonyms happen to spell.
	rows := sideRows(a.Checks, b.Checks, true)
	for _, row := range rows {
		for _, e := range row.Evidence {
			if e.Reason == "redacted_identity" && e.Relation != "unknown" {
				t.Errorf("%s/%s = %q, want an identity dimension to stay unknown", row.ID, e.Dimension, e.Relation)
			}
		}
	}
}

// Both readings read; neither writes. The artifacts are the caller's, they
// keep the spellings their producers wrote, and comparing them must not
// normalize either one in place.
func TestAddressIdentityDoesNotRewriteEitherSnapshot(t *testing.T) {
	before, after := fixture(t), fixture(t)
	respellIPv6(t, &after, "dns", compressedV6, expandedV6)
	respellIPv6(t, &after, "target_tcp", compressedV6, expandedV6)
	check(t, &after, "dns").Observed.ResolverTargets = []string{"[2001:0db8:0000:0000:0000:0000:0000:0053]:53"}
	check(t, &after, "iface").Observed.SourceIP = "::ffff:192.0.2.10"
	withRoutes(t, &after, "target_tcp", snapshot.Route{
		Destination: "2001:0db8::7", Family: "ipv6", Interface: "eth0",
		Prefix: "2001:0db8:0000::/32", Gateway: "2001:0DB8::1", Tunnel: snapshot.TunnelStateDirect,
	})
	after.Options.Source = &snapshot.Source{Interface: "eth0", IPv4: "::ffff:192.0.2.10"}

	beforeJSON, afterJSON := encoded(t, before), encoded(t, after)
	Snapshots(before, after)
	if _, err := TwoSidedSnapshots(before, after); err != nil {
		t.Fatalf("two-sided refused the pair: %v", err)
	}
	if !bytes.Equal(beforeJSON, encoded(t, before)) {
		t.Error("the comparison rewrote the before snapshot")
	}
	if !bytes.Equal(afterJSON, encoded(t, after)) {
		t.Error("the comparison rewrote the after snapshot")
	}
}

func encoded(t *testing.T, s snapshot.Snapshot) []byte {
	t.Helper()
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return data
}

// The reader inconsistency this rule exists to remove: for each dimension the
// two readings both cover, a respelling is no change to one and equivalent to
// the other, and they say so together.
func TestCompareAndTwoSidedAgreeOnAddressIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, id, dimension, path string
		respell                   func(*snapshot.Observed)
	}{
		{"addresses", "dns", "addresses", "checks.dns.observed.addresses",
			func(o *snapshot.Observed) { o.Addresses = []string{"93.184.216.34", expandedV6} }},
		{"resolver_targets", "dns", "resolver_targets", "checks.dns.observed.resolver_targets",
			func(o *snapshot.Observed) {
				o.ResolverTargets = []string{"192.0.2.53:53", "[2001:0db8:0000:0000:0000:0000:0000:0053]:53"}
			}},
		{"attempts", "target_tcp", "attempts", "checks.target_tcp.observed.attempts",
			func(o *snapshot.Observed) { o.Attempts[1].IP = expandedV6 }},
		{"selected_ip", "internet_tcp", "selected_ip", "checks.internet_tcp.observed.selected_ip",
			func(o *snapshot.Observed) { o.SelectedIP = "::ffff:1.1.1.1" }},
		{"resolver", "dns_public", "resolver", "checks.dns_public.observed.resolver",
			func(o *snapshot.Observed) { o.Resolver = "::ffff:8.8.8.8" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, after := fixture(t), fixture(t)
			tc.respell(check(t, &after, tc.id).Observed)

			for _, path := range paths(Snapshots(before, after)) {
				if strings.HasPrefix(path, tc.path) {
					t.Errorf("--compare reported %q for one address spelled two ways", path)
				}
			}
			reading, err := TwoSidedSnapshots(before, after)
			if err != nil {
				t.Fatalf("two-sided refused the pair: %v", err)
			}
			for _, row := range reading.Checks {
				if row.ID != tc.id {
					continue
				}
				if got := dimension(t, row, tc.dimension); got.Relation != "equivalent" {
					t.Errorf("--two-sided %s = %q, want equivalent", tc.dimension, got.Relation)
				}
			}
		})
	}
}
