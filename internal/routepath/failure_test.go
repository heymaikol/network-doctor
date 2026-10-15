package routepath

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// diamond is r1 with two equal paths to r3, one through r2 and one through r4.
// 10.20.40.8 is an address on r3, and r1's FIB lists both legs.
func diamond() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth1", "10.0.12.1/30"), ifc("eth2", "10.0.14.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30")}),
		configured("r4", "default", []netmodel.Interface{ifc("eth0", "10.0.14.2/30"), ifc("eth1", "10.0.43.2/30")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24"), ifc("eth2", "10.0.43.3/30")}),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"), nh("10.0.14.2", "eth2"))),
		table(netmodel.PlaneFIB, "r2", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1"))),
		table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.43.3", "eth1"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.40.0/24", "kernel", onLink("eth1"))),
	}
}

// singleHomed is r1 -- r2 -- r3 with one path. r2 holds 10.30.0.1 on a LAN and
// r3 holds 10.20.40.8.
func singleHomed() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth1", "10.0.12.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30"), ifc("eth2", "10.30.0.1/24")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")),
			route("10.30.0.0/24", "kernel", nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneFIB, "r2", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1")),
			route("10.30.0.0/24", "kernel", onLink("eth2"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.40.0/24", "kernel", onLink("eth1"))),
	}
}

func simulateFrom(t *testing.T, obs []netmodel.Observation, src Start, fail Failure) Simulation {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	s, err := Simulate(File{Source: src, Model: m}, fail)
	if err != nil {
		t.Fatalf("Simulate(%+v): %v", fail, err)
	}
	return s
}

func simulate(t *testing.T, obs []netmodel.Observation, fail Failure) Simulation {
	t.Helper()
	return simulateFrom(t, obs, fromR1, fail)
}

// impacts maps each affected destination to its impact.
func impacts(s Simulation) map[string]Impact {
	out := map[string]Impact{}
	for _, a := range s.Affected {
		out[a.Destination] = a.Impact
	}
	return out
}

func affected(t *testing.T, s Simulation, d string) Affected {
	t.Helper()
	for _, a := range s.Affected {
		if a.Destination == d {
			return a
		}
	}
	t.Fatalf("%s is not affected: %+v", d, impacts(s))
	return Affected{}
}

func TestRedundantPathSurvivesALinkFailureOnTheAlternate(t *testing.T) {
	s := simulate(t, diamond(), Failure{Node: "r1", Interface: "eth1"})
	// 10.0.12.1 is the address of the interface that went down. Whether r1
	// still answers for it depends on its platform, so it is unknown.
	want := map[string]Impact{dest: ImpactRedundancyLost, "10.0.12.1": ImpactUnknown}
	if got := impacts(s); !reflect.DeepEqual(got, want) {
		t.Fatalf("impacts = %v, want %v", got, want)
	}
	after := affected(t, s, dest).After
	if after == nil || after.Node != "r1" || len(after.Next) != 2 {
		t.Fatalf("after = %s with %d branches, want r1 with both legs kept", after.Node, len(after.Next))
	}
	var cut, alternate bool
	for _, c := range after.Next {
		switch {
		case c.Decision.Kind == KindFailed:
			cut = c.Via.Interface == "eth1"
		case c.Node == "r4":
			alternate = len(c.Next) == 1 && c.Next[0].Node == "r3" && c.Next[0].Decision.Kind == KindLocal
		}
	}
	if !cut || !alternate {
		t.Errorf("after = %+v, want the eth1 leg failed and the alternate through r4 delivering at r3", after.Next)
	}
	// Each surviving decision keeps the rows it rests on.
	if len(after.Decision.Evidence) == 0 || after.Decision.Evidence[0].Source != "fib:r1:default" {
		t.Errorf("r1 evidence = %+v, want the r1 FIB", after.Decision.Evidence)
	}
}

func TestRedundantPathSurvivesARouterFailure(t *testing.T) {
	s := simulate(t, diamond(), Failure{Node: "r2"})
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactRedundancyLost}) {
		t.Fatalf("impacts = %v, want only %s redundancy_lost", got, dest)
	}
}

func TestSingleHomedFailureReportsTheAffectedSet(t *testing.T) {
	s := simulate(t, singleHomed(), Failure{Node: "r2"})
	want := []string{"10.20.40.8", "10.30.0.1"}
	var got []string
	for _, a := range s.Affected {
		got = append(got, a.Destination)
		if a.Impact != ImpactReachabilityLost {
			t.Errorf("%s impact = %s, want reachability_lost", a.Destination, a.Impact)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("affected = %v, want %v in address order", got, want)
	}
	if o := affected(t, s, "10.20.40.8").Owners; len(o) != 1 || o[0] != (Start{Node: "r3", VRF: "default"}) {
		t.Errorf("owners of 10.20.40.8 = %+v, want r3 (default)", o)
	}
	// Every address the topology holds is considered; the ones whose recorded
	// forwarding never reaches r2 are unchanged, not affected.
	if s.Considered != 6 || s.Unchanged != 4 {
		t.Errorf("considered %d, unchanged %d, want 6 and 4", s.Considered, s.Unchanged)
	}
}

func TestLinkFailureAffectsOnlyWhatCrossesIt(t *testing.T) {
	s := simulate(t, singleHomed(), Failure{Node: "r2", Interface: "eth1"})
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{"10.20.40.8": ImpactReachabilityLost}) {
		t.Errorf("impacts = %v, want only 10.20.40.8 reachability_lost", got)
	}
}

func TestFailedLinkEndCutsTrafficArrivingOnIt(t *testing.T) {
	// r2 eth0 is the far end of r1's only link. The segment r1 sends on eth1
	// arrives there, so it crosses the failure.
	s := simulate(t, singleHomed(), Failure{Node: "r2", Interface: "eth0"})
	want := map[string]Impact{"10.20.40.8": ImpactReachabilityLost, "10.30.0.1": ImpactReachabilityLost}
	if got := impacts(s); !reflect.DeepEqual(got, want) {
		t.Errorf("impacts = %v, want %v", got, want)
	}
}

func TestAddressOnTheFailedInterfaceIsUnknown(t *testing.T) {
	// 10.30.0.1 is held on r2 eth2. Traffic reaches r2 on eth0, which is up,
	// but the address it is for is on the interface that went down. A Linux r2
	// still delivers it, and many routers would not, so it is neither lost nor
	// unchanged, whatever r2's FIB says.
	for name, obs := range map[string][]netmodel.Observation{
		"recorded FIB": singleHomed(),
		"shadowed default route": append(without(singleHomed(), "fib:r2:default"),
			table(netmodel.PlaneFIB, "r2", "default", true,
				route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1")),
				route("10.30.0.0/24", "kernel", onLink("eth2")),
				route("0.0.0.0/0", "kernel", nh("10.0.23.3", "eth1")))),
		"no FIB at the owner": without(singleHomed(), "fib:r2:default"),
	} {
		t.Run(name, func(t *testing.T) {
			s := simulate(t, obs, Failure{Node: "r2", Interface: "eth2"})
			if got := impacts(s)["10.30.0.1"]; got != ImpactUnknown {
				t.Errorf("impact = %s, want unknown", got)
			}
			if after, _ := json.Marshal(affected(t, s, "10.30.0.1").After); !strings.Contains(string(after), "depends on its platform") {
				t.Errorf("the walk does not say why:\n%s", after)
			}
		})
	}
}

func TestAddressAlsoOnAnotherInterfaceIsUnknown(t *testing.T) {
	// r2 holds 10.30.0.1 on eth2 and eth9. Which one delivers it once eth2 is
	// down is not in the evidence, so the impact is neither none nor a loss.
	obs := append(without(singleHomed(), "config:r2:default"),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30"), ifc("eth2", "10.30.0.1/24"), ifc("eth9", "10.30.0.1/24")}))
	a := affected(t, simulate(t, obs, Failure{Node: "r2", Interface: "eth2"}), "10.30.0.1")
	if a.Impact != ImpactUnknown {
		t.Fatalf("impact = %s, want unknown", a.Impact)
	}
	if after, _ := json.Marshal(a.After); !strings.Contains(string(after), "eth2, eth9") {
		t.Errorf("the walk does not name both interfaces:\n%s", after)
	}
}

func TestEveryECMPLegCrossingTheFailureLosesReachability(t *testing.T) {
	s := simulate(t, diamond(), Failure{Node: "r3"})
	if got := impacts(s)[dest]; got != ImpactReachabilityLost {
		t.Errorf("%s impact = %s, want reachability_lost", dest, got)
	}
}

func TestBranchWithNoSurvivingNextHopIsALoss(t *testing.T) {
	// The r4 -> r3 link fails. r1 keeps both legs, because neither crosses the
	// failure, and r4 has no next hop left. Flows hashed to r4 are dropped, so
	// delivery is not preserved, whatever a protocol would converge to.
	s := simulate(t, diamond(), Failure{Node: "r4", Interface: "eth1"})
	if got := impacts(s)[dest]; got != ImpactReachabilityLost {
		t.Errorf("%s impact = %s, want reachability_lost", dest, got)
	}
	// The loss is partial: the walk keeps the r2 branch, which still delivers.
	delivers := false
	walkHops(affected(t, s, dest).After, func(h *Hop) { delivers = delivers || h.Decision.Kind == KindLocal })
	if !delivers {
		t.Error("the walk drops the r2 branch that still delivers, so a partial loss reads as complete")
	}
}

func TestIncompleteEvidenceIsUnknownNeverLost(t *testing.T) {
	cases := map[string][]netmodel.Observation{
		"partial source FIB": append(without(singleHomed(), "fib:r1:default"),
			table(netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")))),
		"missing FIB before the failure": without(singleHomed(), "fib:r2:default"),
	}
	for name, obs := range cases {
		t.Run(name, func(t *testing.T) {
			s := simulate(t, obs, Failure{Node: "r3"})
			a := affected(t, s, "10.20.40.8")
			if a.Impact != ImpactUnknown {
				t.Errorf("impact = %s, want unknown", a.Impact)
			}
			if a.Reason == "" {
				t.Error("an unknown impact gives no reason")
			}
		})
	}
}

func TestShadowedRouteLeavesALossUnknown(t *testing.T) {
	// Every leg of r1's /16 crosses r2, and a recorded default route also
	// matches. Whether it takes over depends on the /16 being withdrawn, which
	// the evidence cannot say.
	obs := append(without(singleHomed(), "fib:r1:default"),
		configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.15.2/30")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")),
			route("0.0.0.0/0", "kernel", nh("10.0.15.2", "eth3"))))
	s := simulate(t, obs, Failure{Node: "r2"})
	if got := impacts(s)["10.20.40.8"]; got != ImpactUnknown {
		t.Errorf("impact = %s, want unknown", got)
	}
}

func TestUndecidableLinkEndIsUnknown(t *testing.T) {
	cases := map[string]struct {
		obs  []netmodel.Observation
		fail Failure
	}{
		"far address held on two interfaces": {
			obs: append(without(singleHomed(), "config:r2:default"),
				configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30"), ifc("eth2", "10.30.0.1/24"), ifc("eth9", "10.0.12.2/30")})),
			fail: Failure{Node: "r2", Interface: "eth0"},
		},
		"next hop names no interface": {
			obs: append(without(singleHomed(), "fib:r1:default"),
				table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "")))),
			fail: Failure{Node: "r1", Interface: "eth1"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := affected(t, simulate(t, c.obs, c.fail), "10.20.40.8")
			if a.Impact != ImpactUnknown {
				t.Errorf("impact = %s, want unknown", a.Impact)
			}
		})
	}
}

func TestVRFsAreSimulatedSeparately(t *testing.T) {
	obs := append(diamond(),
		configured("r1", "red", []netmodel.Interface{ifc("eth5", "10.9.0.1/30")}),
		configured("r5", "red", []netmodel.Interface{ifc("eth0", "10.9.0.2/30"), ifc("eth1", "10.50.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "red", true, route("10.50.0.0/24", "kernel", nh("10.9.0.2", "eth5"))),
		table(netmodel.PlaneFIB, "r5", "red", true, route("10.50.0.0/24", "kernel", onLink("eth1"))),
	)
	red := Start{Node: "r1", VRF: "red"}
	if got := impacts(simulateFrom(t, obs, red, Failure{Node: "r2"})); len(got) != 0 {
		t.Errorf("red impacts of r2 failing = %v, want none", got)
	}
	if got := impacts(simulateFrom(t, obs, red, Failure{Node: "r5"})); !reflect.DeepEqual(got, map[string]Impact{"10.50.0.1": ImpactReachabilityLost}) {
		t.Errorf("red impacts of r5 failing = %v, want 10.50.0.1 reachability_lost", got)
	}
	if got := impacts(simulate(t, obs, Failure{Node: "r5"})); len(got) != 0 {
		t.Errorf("default impacts of r5 failing = %v, want none", got)
	}
}

func TestLoopIsNeverReportedAsALoss(t *testing.T) {
	obs := append(without(singleHomed(), "fib:r2:default"),
		table(netmodel.PlaneFIB, "r2", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.1", "eth0"))))
	s := simulate(t, obs, Failure{Node: "r2", Interface: "eth0"})
	a := affected(t, s, "10.20.40.8")
	if a.Impact != ImpactUnknown {
		t.Errorf("impact = %s, want unknown, since the loop delivers nothing before the failure", a.Impact)
	}
}

func TestSimulationIsDeterministicAcrossInputOrder(t *testing.T) {
	obs := diamond()
	want, _ := json.Marshal(simulate(t, obs, Failure{Node: "r2"}))
	// Every rotation of the list, then every rotation of its reverse.
	for range 2 {
		slices.Reverse(obs)
		for range obs {
			obs = append(obs[1:], obs[0])
			if got, _ := json.Marshal(simulate(t, obs, Failure{Node: "r2"})); string(got) != string(want) {
				t.Fatalf("output depends on input order:\n%s\n%s", got, want)
			}
		}
	}
}

func TestSimulationLeavesTheFileUnchanged(t *testing.T) {
	m, err := netmodel.New(diamond()...)
	if err != nil {
		t.Fatal(err)
	}
	f := File{Source: fromR1, Model: m}
	before := m.Observations()
	explained, _ := Explain(f, addr(dest)).JSON()
	if _, err := Simulate(f, Failure{Node: "r2"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.Model.Observations()) {
		t.Error("Simulate changed the model")
	}
	if again, _ := Explain(f, addr(dest)).JSON(); string(again) != string(explained) {
		t.Error("Simulate changed what Explain says about the same file")
	}
}

func TestSimulationBoundsDestinations(t *testing.T) {
	var ifaces []netmodel.Interface
	for i := range maxDestinations + 10 {
		ifaces = append(ifaces, ifc(fmt.Sprintf("lo%d", i), fmt.Sprintf("10.%d.%d.1/32", 100+i/256, i%256)))
	}
	obs := append(diamond(), configured("r9", "default", ifaces))
	s := simulate(t, obs, Failure{Node: "r2"})
	if !s.Truncated || s.Considered != maxDestinations {
		t.Errorf("truncated %v, considered %d, want true and %d", s.Truncated, s.Considered, maxDestinations)
	}
	if !strings.Contains(s.Text(), "not considered") {
		t.Errorf("the text does not say destinations were left unconsidered:\n%s", s.Text())
	}
}

func TestExtraDestinationIsConsidered(t *testing.T) {
	m, err := netmodel.New(singleHomed()...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Simulate(File{Source: fromR1, Model: m}, Failure{Node: "r2", Interface: "eth1"}, addr("10.20.40.99"), addr("10.20.40.8"))
	if err != nil {
		t.Fatal(err)
	}
	// 10.20.40.99 is on r3's LAN and no node owns it, so delivery to it is never
	// proven; it is unknown, not lost. 10.20.40.8 is counted once.
	want := map[string]Impact{"10.20.40.8": ImpactReachabilityLost, "10.20.40.99": ImpactUnknown}
	if got := impacts(s); !reflect.DeepEqual(got, want) || s.Considered != 7 {
		t.Errorf("impacts = %v, considered %d, want %v and 7", got, s.Considered, want)
	}
}

func TestFailureMustNameAModeledElement(t *testing.T) {
	m, err := netmodel.New(singleHomed()...)
	if err != nil {
		t.Fatal(err)
	}
	f := File{Source: fromR1, Model: m}
	for _, fail := range []Failure{{}, {Node: "r9"}, {Node: "r2", Interface: "eth7"}, {Node: "r1"}, {Interface: "eth0"}} {
		if _, err := Simulate(f, fail); err == nil {
			t.Errorf("Simulate(%+v) succeeded, want an error", fail)
		}
	}
}

func TestSimulationTextIsDeterministicAndQualified(t *testing.T) {
	s := simulate(t, singleHomed(), Failure{Node: "r2", Interface: "eth1"})
	text := s.Text()
	for _, want := range []string{"r2 eth1", "reachability_lost 10.20.40.8", "no route is recomputed"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if again := simulate(t, singleHomed(), Failure{Node: "r2", Interface: "eth1"}).Text(); again != text {
		t.Error("text differs between identical runs")
	}
}

// chain is n routers in a line, from r0, each forwarding 10.9.0.0/16 to the
// next. The last FIB is partial, so a walk that reaches it is unknown.
func chain(t *testing.T, n int) File {
	t.Helper()
	var obs []netmodel.Observation
	for i := range n {
		node := fmt.Sprintf("r%d", i)
		obs = append(obs,
			configured(node, "default", []netmodel.Interface{ifc("in", fmt.Sprintf("10.1.%d.2/24", i)), ifc("out", fmt.Sprintf("10.1.%d.1/24", i+1))}),
			table(netmodel.PlaneFIB, node, "default", i < n-1, route("10.9.0.0/16", "kernel", nh(fmt.Sprintf("10.1.%d.2", i+1), "out"))))
	}
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatal(err)
	}
	return File{Source: Start{Node: "r0", VRF: "default"}, Model: m}
}

func TestWalkStoppedAtItsOwnBoundSkipsNoDestination(t *testing.T) {
	// The chain is longer than maxDepth, so the walk to 10.9.0.1 stops at that
	// bound, while every destination is still considered.
	s, err := Simulate(chain(t, maxDepth+8), Failure{Node: "r0", Interface: "in"}, addr("10.9.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + 2*(maxDepth+8); !s.Truncated || s.Considered != want {
		t.Errorf("truncated %v, considered %d, want true and %d", s.Truncated, s.Considered, want)
	}
	text := s.Text()
	if strings.Contains(text, "not considered") {
		t.Errorf("the text says destinations were not considered, but every one was:\n%s", text)
	}
	if !strings.Contains(text, "walks stopped at a depth, state, or fan-out bound") {
		t.Errorf("the text does not say a walk stopped at its own bound:\n%s", text)
	}
}

func TestAfterWalksAreBoundedTogether(t *testing.T) {
	// A 30-router chain is listed with a 30-hop walk for every destination routed
	// along it. The chain stays under maxDepth, so no walk is stopped by a bound
	// of its own.
	var extra []netip.Addr
	for i := range 30 {
		extra = append(extra, addr(fmt.Sprintf("10.9.0.%d", i+1)))
	}
	s, err := Simulate(chain(t, 30), Failure{Node: "r0", Interface: "in"}, extra...)
	if err != nil {
		t.Fatal(err)
	}
	shown, omitted := 0, 0
	for _, a := range s.Affected {
		if a.After == nil {
			omitted++
			continue
		}
		walkHops(a.After, func(*Hop) { shown++ })
	}
	if omitted == 0 || shown > 2*maxStates {
		t.Errorf("shown %d hops, omitted %d walks; want some omitted and at most %d shown", shown, omitted, 2*maxStates)
	}
	// No destination or traversal bound applies here, so only the omitted walks
	// make the output incomplete, and the text must not say anything was left
	// unconsidered.
	if !s.Truncated {
		t.Error("walks were omitted, but the simulation is not marked truncated")
	}
	if want := 30 + 60; s.Considered != want {
		t.Errorf("considered %d, want %d", s.Considered, want)
	}
	text := s.Text()
	if !strings.Contains(text, "walk omitted") {
		t.Error("the text does not say a walk was omitted")
	}
	if strings.Contains(text, "not considered") {
		t.Errorf("the text says destinations were not considered, but every one was:\n%s", text)
	}
}
