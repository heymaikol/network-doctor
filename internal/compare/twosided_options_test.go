package compare

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// snapshot.Options is the run settings that changed what the probes did, and
// caveats reads it one field at a time. That is deliberate: the struct carries
// slices, it carries a pointer, and two of its fields mean something only when
// read together, so comparing the struct would be wrong in three separate ways.
// The cost is that nothing in the compiler ties a new option to this boundary,
// and a setting that never reaches the caveats is a reading that looks fairer
// than it is.
//
// This file is the ledger that makes forgetting fail. Every field of
// snapshot.Options carries a decision below, and every decision is a pair of
// runs whose caveats are asserted, so a classification is a claim that gets
// checked rather than a comment that can go stale.
//
// Two machines is the premise of a two-sided reading, so the question each
// field has to answer is not "are these equal" but "did this setting make the
// two runs measure different things". Values that differ across two machines by
// construction, which is every host-local name and address, answer no.

// optionCase is one pair of runs that differ in the field it belongs to.
//
// want is the caveat substring the difference has to produce. An empty want is
// the opposite and equally testable claim: the two runs differ in this field
// and the reading must come out exactly as it does for a pair that does not,
// which is how a semantic equivalence rule and an irrelevant setting are both
// stated as behavior.
type optionCase struct {
	name   string
	mutate func(a, b *snapshot.Snapshot)
	want   string
}

// optionDecision is one field's treatment at this boundary. why is required,
// because the reason a setting weakens comparability, or the reason a
// difference in it is not a difference, is the thing a maintainer needs to read
// before adding the next one.
type optionDecision struct {
	why   string
	cases []optionCase
}

func bind(s *snapshot.Snapshot, iface, v4, v6 string) {
	s.Options.Source = &snapshot.Source{Interface: iface, IPv4: v4, IPv6: v6}
}

// twoSidedOptions is the ledger. A field missing from it fails the structural
// guard below; an entry naming a field that no longer exists fails it too.
var twoSidedOptions = map[string]optionDecision{
	"ProbeTimeoutMs": {
		why: "the budget every probe had. A shorter one turns a slow path into a timed-out row, so two " +
			"budgets make a timed-out row on one side mean something it does not mean on the other.",
		cases: []optionCase{{
			name:   "differing budgets",
			mutate: func(a, b *snapshot.Snapshot) { b.Options.ProbeTimeoutMs = 9000 },
			want:   "probe timeouts differ",
		}},
	},
	"PublicDNS": {
		why: "the resolver the second-opinion row asked. Two addresses are two questions, and the row's " +
			"outcome describes whichever server it reached.",
		cases: []optionCase{{
			name:   "differing resolvers",
			mutate: func(a, b *snapshot.Snapshot) { b.Options.PublicDNS = "9.9.9.9" },
			want:   "second-opinion resolvers differ",
		}},
	},
	"PublicDNSAuto": {
		why: "whether that resolver was named or defaulted. Only the run that did not name one could cross " +
			"to the other address family, so the same address reached two ways is still not the same question.",
		cases: []optionCase{{
			name:   "same address, named against defaulted",
			mutate: func(a, b *snapshot.Snapshot) { b.Options.PublicDNSAuto = true },
			want:   "took the default",
		}},
	},
	"Check": {
		why: "the probe selection as given. A different selection is a different set of rows, and the order " +
			"a person typed probe IDs in is not the shape of anything, so it is compared as a set.",
		cases: []optionCase{
			{
				name:   "differing selections",
				mutate: func(a, b *snapshot.Snapshot) { b.Options.Check = []string{"dns"} },
				want:   "selected different probes",
			},
			{
				name: "one selection typed in two orders",
				mutate: func(a, b *snapshot.Snapshot) {
					a.Options.Check = []string{"dns", "iface"}
					b.Options.Check = []string{"iface", "dns"}
				},
			},
		},
	},
	"Skip": {
		why: "the other half of the selection, read by the same set rule as Check for the same reason.",
		cases: []optionCase{
			{
				name:   "differing exclusions",
				mutate: func(a, b *snapshot.Snapshot) { b.Options.Skip = []string{"dns"} },
				want:   "selected different probes",
			},
			{
				name: "one exclusion typed in two orders",
				mutate: func(a, b *snapshot.Snapshot) {
					a.Options.Skip = []string{"dns", "iface"}
					b.Options.Skip = []string{"iface", "dns"}
				},
			},
		},
	},
	"Source": {
		why: "the --iface binding in effect, read as policy and never as identity. A binding overrides the " +
			"routing choice the machine would have made, so one bound run against one unbound run compares a " +
			"chosen egress against a system-chosen one. Probes bind by the resolved addresses, so the second " +
			"comparable fact is which address families the binding could dial from: a source with no address " +
			"for a family means that family was never attempted rather than unreachable. Interface names and " +
			"local addresses are host-local identities that two machines differ in by construction, the same " +
			"way they differ in hostname, so neither is compared and neither reaches the caveat text.",
		cases: []optionCase{
			{
				name:   "one side bound, the other on system routing",
				mutate: func(a, b *snapshot.Snapshot) { bind(a, "wg0", "10.8.0.2", "fd00::2") },
				want:   "used the machine's own routing choice",
			},
			{
				name: "both bound, host-local identities differing as two machines do",
				mutate: func(a, b *snapshot.Snapshot) {
					bind(a, "wg0", "10.8.0.2", "fd00::2")
					bind(b, "tun0", "10.9.0.7", "fd00::7")
				},
			},
			{
				name: "one binding named an interface, the other an exact local address",
				mutate: func(a, b *snapshot.Snapshot) {
					bind(a, "wg0", "10.8.0.2", "")
					bind(b, "", "10.9.0.7", "")
				},
			},
			{
				name: "bindings covering different address families",
				mutate: func(a, b *snapshot.Snapshot) {
					bind(a, "wg0", "10.8.0.2", "")
					bind(b, "tun0", "10.9.0.7", "fd00::7")
				},
				want: "did not cover the same address families",
			},
		},
	},
}

// The structural half. A field added to snapshot.Options has to be given a
// decision here, which is the whole point: the author of the new setting is the
// person who knows whether it weakens comparability across two machines, is
// covered by an equivalence rule, or cannot affect a two-machine reading at all.
func TestEveryRunSettingHasATwoSidedDisposition(t *testing.T) {
	typ := reflect.TypeOf(snapshot.Options{})
	known := map[string]bool{}
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		known[name] = true
		d, ok := twoSidedOptions[name]
		if !ok {
			t.Errorf("snapshot.Options.%s reaches the two-sided reading unclassified. Decide what it does to "+
				"comparability across two machines and add it to twoSidedOptions: a case with a want names the "+
				"caveat a difference has to produce, and a case without one claims the difference is not a "+
				"difference and is checked against the reading", name)
			continue
		}
		if d.why == "" {
			t.Errorf("snapshot.Options.%s has no reason recorded. A setting's treatment at this boundary has to say why", name)
		}
		if len(d.cases) == 0 {
			t.Errorf("snapshot.Options.%s is classified by prose alone. Give it at least one pair of runs that "+
				"differ in it, so the classification is checked rather than asserted", name)
		}
	}
	for name := range twoSidedOptions {
		if !known[name] {
			t.Errorf("twoSidedOptions classifies %s, which is no longer a field of snapshot.Options", name)
		}
	}
}

// The behavioral half, and the caveat contract in its own right: a setting that
// changed what was measured reaches the caveats, and one that did not leaves the
// reading alone. Each case is asserted against the same pair unmutated, so a
// caveat has to come from the field it is filed under and an equivalence claim
// cannot pass by producing a different caveat instead.
func TestSettingsThatChangeWhatWasMeasuredAreCaveats(t *testing.T) {
	for _, name := range slices.Sorted(maps.Keys(twoSidedOptions)) {
		for _, tc := range twoSidedOptions[name].cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				base := twoSided(t, fixture(t), fixture(t))
				a, b := fixture(t), fixture(t)
				tc.mutate(&a, &b)
				got := twoSided(t, a, b)
				if tc.want == "" {
					if !slices.Equal(got.Caveats, base.Caveats) {
						t.Errorf("caveats = %v, want the %v an undifferentiated pair produces: this difference "+
							"is classified as no difference", got.Caveats, base.Caveats)
					}
					return
				}
				if !hasCaveat(got, tc.want) {
					t.Errorf("caveats = %v, want one mentioning %q", got.Caveats, tc.want)
				}
				if hasCaveat(base, tc.want) {
					t.Errorf("an undifferentiated pair already carries %q, so the caveat does not come from %s", tc.want, name)
				}
			})
		}
	}
}

// A binding difference weakens the reading; it does not stop a row from having
// been measured. Two machines each bound to their own interface is the workflow
// the live command's -iface rejection points users at, so it has to produce a
// reading rather than an empty one.
func TestSourceBindingIsACaveatAndNotAComparabilityWall(t *testing.T) {
	a, b := fixture(t), fixture(t)
	bind(&a, "wg0", "10.8.0.2", "fd00::2")
	setStatus(t, &b, "target_tcp", snapshot.StatusPass)
	got := twoSided(t, a, b)
	if got.Diagnosis.Side != SideA || got.Diagnosis.ID != TwoSidedOneSideFails {
		t.Fatalf("side = %q id = %q, want %q %q: a binding must not erase a placement",
			got.Diagnosis.Side, got.Diagnosis.ID, SideA, TwoSidedOneSideFails)
	}
	if !rowFor(t, got, "target_tcp").Comparable {
		t.Error("a bound run still measured its rows; the binding is not a reason to stop reading them")
	}
	if !hasCaveat(got, "used the machine's own routing choice") {
		t.Errorf("caveats = %v, want one naming the differing source binding", got.Caveats)
	}
	// The placement stays the conservative one. A binding is a fact about the
	// run, and saying so must not turn into a claim about where the cause is.
	if !got.Diagnosis.Ambiguous {
		t.Error("a placement made under a differing binding is not less ambiguous")
	}
	if strings.Contains(got.Diagnosis.Summary, "wg0") || strings.Contains(got.Diagnosis.Summary, "binding") {
		t.Errorf("the binding reached the placement instead of the caveats: %q", got.Diagnosis.Summary)
	}
}

// Only one binding caveat at a time: a pair that differs in policy is not also
// reported for the family coverage that follows from the policy difference.
func TestSourceBindingProducesOneCaveat(t *testing.T) {
	a, b := fixture(t), fixture(t)
	bind(&a, "wg0", "10.8.0.2", "")
	n := 0
	for _, caveat := range twoSided(t, a, b).Caveats {
		if strings.Contains(caveat, "routing choice") || strings.Contains(caveat, "address families") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("one differing binding produced %d binding caveats, want 1", n)
	}
}

// The rule reads the artifact's structure and never a value, so sanitization
// cannot change the answer and cannot be leaked through it.
func TestSourceBindingCaveatSurvivesSanitizationWithoutLeaking(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(a, b *snapshot.Snapshot)
		want   string
	}{
		{"policy", func(a, b *snapshot.Snapshot) { bind(a, "wg0", "10.8.0.2", "fd00::2") }, "used the machine's own routing choice"},
		{"families", func(a, b *snapshot.Snapshot) {
			bind(a, "wg0", "10.8.0.2", "")
			bind(b, "tun0", "10.9.0.7", "fd00::7")
		}, "did not cover the same address families"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := fixture(t), fixture(t)
			tc.mutate(&a, &b)
			full := twoSided(t, a, b)
			got := twoSided(t, snapshot.SanitizeForSupport(a), snapshot.SanitizeForSupport(b))
			if caveatWith(full, tc.want) != caveatWith(got, tc.want) || caveatWith(got, tc.want) == "" {
				t.Fatalf("sanitized caveat = %q, full fidelity = %q: the rule read a value",
					caveatWith(got, tc.want), caveatWith(full, tc.want))
			}
			text := strings.Join(got.Caveats, "\n") + "\n" + got.Text()
			for _, secret := range []string{"wg0", "tun0", "10.8.0.2", "10.9.0.7", "fd00::2", "fd00::7"} {
				if strings.Contains(text, secret) {
					t.Errorf("a support artifact's original %q reached the reading:\n%s", secret, text)
				}
			}
		})
	}
}

func caveatWith(got TwoSided, want string) string {
	for _, caveat := range got.Caveats {
		if strings.Contains(caveat, want) {
			return caveat
		}
	}
	return ""
}
