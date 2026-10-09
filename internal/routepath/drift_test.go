package routepath

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// intent is a complete intended table for one node in the default domain.
func intent(node string, routes ...netmodel.Route) netmodel.Observation {
	return table(netmodel.PlaneIntended, node, "default", true, routes...)
}

var (
	viaR2 = nh("10.0.12.2", "eth1")
	viaR4 = nh("10.0.14.2", "eth2")
)

// r1Via replaces r1's FIB route toward srv in twoPathNet with one over hops.
func r1Via(obs []netmodel.Observation, hops ...netmodel.NextHop) []netmodel.Observation {
	return append(without(obs, "fib:r1:default"), table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.20.0.0/16", "kernel", hops...), route("10.0.1.0/24", "kernel", onLink("eth0"))))
}

// r4ToR3 gives r4 in twoPathNet a FIB route toward srv through r3, so a path
// through r4 also reaches srv.
func r4ToR3(obs []netmodel.Observation) []netmodel.Observation {
	return append(without(obs, "fib:r4:default"), table(netmodel.PlaneFIB, "r4", "default", true,
		route("10.20.0.0/16", "kernel", nh("10.0.34.3", "eth0")), route("10.0.1.0/24", "kernel", nh("10.0.14.1", "eth1"))))
}

// driftOf returns the drift section, and stops the test when there is none.
func driftOf(t *testing.T, e Explanation) *Drift {
	t.Helper()
	if e.Drift == nil {
		t.Fatal("Drift = nil, want a comparison because the topology holds intended routes")
	}
	return e.Drift
}

// driftAt returns the drift finding at node, and stops the test when there is none.
func driftAt(t *testing.T, d *Drift, node string) DriftFinding {
	t.Helper()
	for _, f := range d.Findings {
		if f.Node == node {
			return f
		}
	}
	t.Fatalf("drift findings = %+v, want one at %s", d.Findings, node)
	return DriftFinding{}
}

func hasFact(facts []Fact, want Fact) bool {
	return slices.ContainsFunc(facts, func(f Fact) bool { return reflect.DeepEqual(f, want) })
}

func TestDriftHealthyIntentMatchesFIB(t *testing.T) {
	obs := append(threeRouters(),
		intent("r1", route("10.20.0.0/16", "static", nh("10.0.12.2", "eth1"))),
		intent("r2", route("10.20.0.0/16", "static", nh("10.0.23.3", "eth1"))),
		intent("r3", route("10.20.40.0/24", "connected", onLink("eth1"))))
	d := driftOf(t, explainFrom(t, obs, nil, fromR1, dest))
	if d.Level != DriftNone || len(d.Findings) != 0 || d.Compared != 2 {
		t.Errorf("drift = %s with findings %+v and %d compared, want none with no findings and 2 compared: r3 owns the destination", d.Level, d.Findings, d.Compared)
	}
}

func TestDriftBenignWhenFIBTakesAnotherWorkingPath(t *testing.T) {
	obs := append(r4ToR3(r1Via(twoPathNet("r2"), viaR4)), intent("r1", route("10.20.0.0/16", "static", viaR2)))
	d := driftOf(t, explainTwoPath(t, obs, nil, nil, ""))
	if f := driftAt(t, d, "r1"); f.Level != DriftBenign {
		t.Errorf("r1 = %s (%s), want benign: the FIB path through r4 still reaches srv", f.Level, f.Detail)
	}
}

func TestDriftRedundancyLostWhileDestinationIsReached(t *testing.T) {
	obs := append(r4ToR3(twoPathNet("r2")), intent("r1", route("10.20.0.0/16", "static", viaR2, viaR4)))
	d := driftOf(t, explainTwoPath(t, obs, nil, nil, ""))
	if d.Level != DriftRedundancyLost {
		t.Errorf("drift = %s with findings %+v, want redundancy_lost: the FIB keeps one of two intended next hops", d.Level, d.Findings)
	}
}

func TestDriftMisdirectedNextHopLosesReachability(t *testing.T) {
	obs := append(r1Via(twoPathNet("r2"), viaR4), intent("r1", route("10.20.0.0/16", "static", viaR2)))
	d := driftOf(t, explainTwoPath(t, obs, nil, nil, ""))
	if f := driftAt(t, d, "r1"); f.Level != DriftReachabilityLost {
		t.Errorf("r1 = %s (%s), want reachability_lost: r4 holds no route, and the intended path through r2 reaches srv", f.Level, f.Detail)
	}
}

func TestDriftIgnoresNodesWithoutIntent(t *testing.T) {
	obs := append(without(threeRouters(), "control:r2:default"),
		table(netmodel.PlaneControl, "r2", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.23.9", "eth1"))),
		intent("r1", route("10.20.0.0/16", "static", nh("10.0.12.2", "eth1"))))
	e := explainFrom(t, obs, nil, fromR1, dest)
	d := driftOf(t, e)
	if d.Level != DriftNone || d.Compared != 1 {
		t.Errorf("drift = %s with %d compared, want none with 1: only r1 states intent", d.Level, d.Compared)
	}
	if got := findings(e, FindingFIBDiffers); len(got) != 1 || got[0].Node != "r2" {
		t.Errorf("fib_differs_from_control = %+v, want one at r2: drift does not replace the control comparison", got)
	}
}

func TestDriftPartialFIBIsUnknownNotLost(t *testing.T) {
	obs := append(without(threeRouters(), "fib:r2:default"),
		table(netmodel.PlaneFIB, "r2", "default", false),
		intent("r2", route("10.20.0.0/16", "static", nh("10.0.23.3", "eth1"))))
	d := driftOf(t, explainFrom(t, obs, nil, fromR1, dest))
	f := driftAt(t, d, "r2")
	if f.Level != DriftUnknown || d.Level != DriftUnknown {
		t.Errorf("r2 = %s, overall %s, want unknown: a partial FIB proves no absence", f.Level, d.Level)
	}
	if want := (Fact{Source: "fib:r2:default", CollectedAt: utcText(t0), Plane: netmodel.PlaneFIB}); !hasFact(f.Facts, want) {
		t.Errorf("facts = %+v, want %+v naming the partial table", f.Facts, want)
	}
}

func TestDriftCompleteFIBAbsenceIsReachabilityLost(t *testing.T) {
	obs := append(without(threeRouters(), "fib:r2:default"),
		table(netmodel.PlaneFIB, "r2", "default", true),
		intent("r2", route("10.20.0.0/16", "static", nh("10.0.23.3", "eth1"))))
	d := driftOf(t, explainFrom(t, obs, nil, fromR1, dest))
	f := driftAt(t, d, "r2")
	if f.Level != DriftReachabilityLost {
		t.Errorf("r2 = %s (%s), want reachability_lost", f.Level, f.Detail)
	}
	if f.Forwarding.Kind != KindNoRoute || !f.Forwarding.Proven {
		t.Errorf("r2 forwarding = %+v, want a proven no_route", f.Forwarding)
	}
	if want := (Fact{Source: "fib:r2:default", CollectedAt: utcText(t0), Plane: netmodel.PlaneFIB, Complete: true}); !hasFact(f.Facts, want) {
		t.Errorf("facts = %+v, want %+v naming the complete table that lacks the route", f.Facts, want)
	}
}

func TestDriftConflictingFIBSourcesStayVisible(t *testing.T) {
	obs := append(threeRouters(),
		tableFrom("frr-fib:r1:default", netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "frr", nh("10.0.13.2", "eth2"))),
		intent("r1", route("10.20.0.0/16", "static", nh("10.0.12.2", "eth1"))))
	f := driftAt(t, driftOf(t, explainFrom(t, obs, nil, fromR1, dest)), "r1")
	if f.Level != DriftUnknown {
		t.Errorf("r1 = %s, want unknown: conflicting FIB rows pick no winner", f.Level)
	}
	at := utcText(t0)
	for _, want := range []Fact{
		{Source: "fib:r1:default", CollectedAt: at, Plane: netmodel.PlaneFIB, Complete: true, Origin: "kernel", Prefix: "10.20.0.0/16", NextHops: []NextHop{{Addr: "10.0.12.2", Interface: "eth1"}}},
		{Source: "frr-fib:r1:default", CollectedAt: at, Plane: netmodel.PlaneFIB, Complete: true, Origin: "frr", Prefix: "10.20.0.0/16", NextHops: []NextHop{{Addr: "10.0.13.2", Interface: "eth2"}}},
	} {
		if !hasFact(f.Facts, want) {
			t.Errorf("facts = %+v, want %+v kept", f.Facts, want)
		}
	}
}

func TestDriftEquivalentSpellingAndOrderIsNotDrift(t *testing.T) {
	obs := append(r4ToR3(r1Via(twoPathNet("r2"), viaR2, viaR4)),
		intent("r1", route("10.20.0.0/16", "static", netmodel.NextHop{Addr: addr("10.0.14.2")}, netmodel.NextHop{Addr: addr("10.0.12.2")}, netmodel.NextHop{Addr: addr("::ffff:10.0.12.2")})))
	d := driftOf(t, explainTwoPath(t, obs, nil, nil, ""))
	if d.Level != DriftNone || len(d.Findings) != 0 || d.Compared != 1 {
		t.Errorf("drift = %s with findings %+v and %d compared, want none: the same next hops spelled and ordered differently", d.Level, d.Findings, d.Compared)
	}
}

func TestDriftOutputIsDeterministicAcrossInputOrder(t *testing.T) {
	forward := append(without(r4ToR3(r1Via(twoPathNet("r2"), viaR4)), "fib:r2:default"),
		table(netmodel.PlaneFIB, "r2", "default", true),
		intent("r1", route("10.20.0.0/16", "static", viaR2)),
		intent("r2", route("10.20.0.0/16", "static", nh("10.0.23.3", "eth1"))))
	var reversed []netmodel.Observation
	for _, o := range slices.Backward(forward) {
		o.Routes = slices.Clone(o.Routes)
		slices.Reverse(o.Routes)
		for i := range o.Routes {
			o.Routes[i].NextHops = slices.Clone(o.Routes[i].NextHops)
			slices.Reverse(o.Routes[i].NextHops)
		}
		reversed = append(reversed, o)
	}
	a := explainTwoPath(t, forward, nil, nil, "")
	b := explainTwoPath(t, reversed, nil, nil, "")
	if a.Text() != b.Text() {
		t.Errorf("human output depends on input order:\n%s\n---\n%s", a.Text(), b.Text())
	}
	ja, errA := a.JSON()
	jb, errB := b.JSON()
	if errA != nil || errB != nil {
		t.Fatalf("JSON: %v, %v", errA, errB)
	}
	if string(ja) != string(jb) {
		t.Errorf("JSON output depends on input order")
	}
	var got []string
	for _, f := range driftOf(t, a).Findings {
		got = append(got, f.Node+" "+string(f.Level))
	}
	if want := []string{"r1 benign", "r2 redundancy_lost"}; !slices.Equal(got, want) {
		t.Errorf("drift findings = %v, want %v in intended path order", got, want)
	}
}

func TestDriftFactsNameSourcePlaneAndTime(t *testing.T) {
	obs := append(r4ToR3(twoPathNet("r2")), intent("r1", route("10.20.0.0/16", "static", viaR2, viaR4)))
	for i := range obs {
		if obs[i].Source == "fib:r1:default" {
			obs[i].CollectedAt = t0.Add(5 * time.Minute)
		}
	}
	e := explainTwoPath(t, obs, nil, nil, "")
	f := driftAt(t, driftOf(t, e), "r1")
	want := []Fact{
		{Source: "intended:r1:default", CollectedAt: "2026-10-09T12:00:00Z", Plane: netmodel.PlaneIntended, Complete: true, Origin: "static", Prefix: "10.20.0.0/16",
			NextHops: []NextHop{{Addr: "10.0.12.2", Interface: "eth1"}, {Addr: "10.0.14.2", Interface: "eth2"}}},
		{Source: "fib:r1:default", CollectedAt: "2026-10-09T12:05:00Z", Plane: netmodel.PlaneFIB, Complete: true, Origin: "kernel", Prefix: "10.20.0.0/16",
			NextHops: []NextHop{{Addr: "10.0.12.2", Interface: "eth1"}}},
	}
	if !reflect.DeepEqual(f.Facts, want) {
		t.Errorf("facts = %+v, want %+v", f.Facts, want)
	}
	if line := "fib:r1:default (fib, complete) kernel 10.20.0.0/16 eth1 via 10.0.12.2 at 2026-10-09T12:05:00Z"; !strings.Contains(e.Text(), line) {
		t.Errorf("human text lacks %q:\n%s", line, e.Text())
	}
}

// Intent adds a drift section and changes nothing else, even when it disagrees
// with the FIB and lists the destination on an interface.
func TestIntentLeavesExistingExplanationUnchanged(t *testing.T) {
	planned := intent("r1", route("10.20.0.0/16", "static", nh("10.0.13.2", "eth2")))
	planned.Interfaces = []netmodel.Interface{ifc("lo", "10.20.40.8/32")}
	e1 := explainFrom(t, threeRouters(), nil, fromR1, dest)
	e2 := explainFrom(t, append(threeRouters(), planned), nil, fromR1, dest)
	driftOf(t, e2)
	e2.Drift = nil
	j1, err1 := e1.JSON()
	j2, err2 := e2.JSON()
	if err1 != nil || err2 != nil {
		t.Fatalf("JSON: %v, %v", err1, err2)
	}
	if string(j1) != string(j2) || e1.Text() != e2.Text() {
		t.Errorf("intent changed the explanation outside its drift section:\n%s\n---\n%s", e1.Text(), e2.Text())
	}
	if strings.Contains(string(j1), `"drift"`) {
		t.Errorf("JSON carries a drift key without intended routes:\n%s", j1)
	}
}

// One ECMP leg that blackholes fails some flows, so it is reachability, not
// lost redundancy.
func TestDriftBlackholedECMPLegIsReachabilityNotRedundancy(t *testing.T) {
	obs := append(r1Via(twoPathNet("r2"), viaR2, viaR4),
		intent("r1", route("10.20.0.0/16", "static", viaR2, viaR4)),
		intent("r4", route("10.20.0.0/16", "static", nh("10.0.34.3", "eth0"))))
	d := driftOf(t, explainTwoPath(t, obs, nil, nil, ""))
	if f := driftAt(t, d, "r4"); f.Level != DriftReachabilityLost || d.Level != DriftReachabilityLost {
		t.Errorf("r4 = %s, overall %s, want reachability_lost", f.Level, d.Level)
	}
}

func TestDriftPartialFIBMatchingIntentIsNotHealthy(t *testing.T) {
	obs := append(without(threeRouters(), "fib:r1:default"),
		table(netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"))),
		intent("r1", route("10.20.0.0/16", "static", nh("10.0.12.2", "eth1"))))
	d := driftOf(t, explainFrom(t, obs, nil, fromR1, dest))
	if f := driftAt(t, d, "r1"); f.Level != DriftUnknown || d.Level != DriftUnknown {
		t.Errorf("r1 = %s, overall %s, want unknown: a partial FIB cannot prove the match", f.Level, d.Level)
	}
}

// A bound hides part of the walk, so even a matching node cannot summarize as
// healthy.
func TestDriftTruncatedWalkIsAtLeastUnknown(t *testing.T) {
	hops := make([]netmodel.NextHop, 200)
	for i := range hops {
		hops[i] = netmodel.NextHop{Addr: netip.AddrFrom4([4]byte{10, 9, 0, byte(i + 1)}), Interface: "eth1"}
	}
	obs := append(without(threeRouters(), "fib:r1:default"),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", hops...)),
		intent("r1", route("10.20.0.0/16", "static", hops...)))
	d := driftOf(t, explainFrom(t, obs, nil, fromR1, dest))
	if !d.Truncated || d.Level != DriftUnknown || len(d.Findings) != 0 {
		t.Errorf("drift = %s, truncated %v, findings %+v, want unknown and truncated with no finding", d.Level, d.Truncated, d.Findings)
	}
}

// A policy that drops the destination while the FIB forwards it is a mismatch
// to look at, not evidence of harmless drift.
func TestDriftIntentDropsWhileFIBForwardsIsUnknown(t *testing.T) {
	cases := []struct {
		name    string
		planned netmodel.Observation
	}{
		{"discard", intent("r1", netmodel.Route{Prefix: pfx("10.20.0.0/16"), Origin: "static", Discard: true})},
		{"no route", intent("r1")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := driftOf(t, explainFrom(t, append(threeRouters(), c.planned), nil, fromR1, dest))
			if f := driftAt(t, d, "r1"); f.Level != DriftUnknown || !strings.Contains(f.Detail, "intent drops") {
				t.Errorf("r1 = %s (%s), want unknown naming the dropped intent", f.Level, f.Detail)
			}
		})
	}
}
