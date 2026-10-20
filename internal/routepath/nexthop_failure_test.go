package routepath

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// gatewayLAN is r1 on one LAN, eth0, with two gateways: r2 at 10.0.1.2 and r4 at
// 10.0.1.4. r1 splits 10.20.0.0/16 over both toward r3, which holds
// 10.20.40.8, and reaches r2's LAN only through r2 and r4's LAN only through
// r4.
func gatewayLAN() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.1.2/24"), ifc("eth1", "10.0.23.2/30"), ifc("lan", "10.30.0.1/24")}),
		configured("r4", "default", []netmodel.Interface{ifc("eth0", "10.0.1.4/24"), ifc("eth1", "10.0.43.4/30"), ifc("lan", "10.40.0.1/24")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.0.43.3/30"), ifc("lan", "10.20.40.8/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.1.0/24", "kernel", onLink("eth0")),
			route("10.20.0.0/16", "kernel", nh("10.0.1.2", "eth0"), nh("10.0.1.4", "eth0")),
			route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0")),
			route("10.40.0.0/24", "kernel", nh("10.0.1.4", "eth0"))),
		table(netmodel.PlaneFIB, "r2", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1")),
			route("10.30.0.0/24", "kernel", onLink("lan"))),
		table(netmodel.PlaneFIB, "r4", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.43.3", "eth1")),
			route("10.40.0.0/24", "kernel", onLink("lan"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.40.0/24", "kernel", onLink("lan"))),
	}
}

// lostGateway is the next hop 10.0.1.2 of r1, the selector most tests use.
var lostGateway = Failure{Node: "r1", NextHop: "10.0.1.2"}

// simulateErr runs Simulate and returns its error, failing when there is none.
func simulateErr(t *testing.T, obs []netmodel.Observation, fail Failure) error {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	_, err = Simulate(File{Source: fromR1, Model: m}, fail)
	if err == nil {
		t.Fatalf("Simulate(%+v) succeeded, want an error", fail)
	}
	return err
}

// afterJSON is the walk after the failure for one destination, as JSON text.
func afterJSON(t *testing.T, s Simulation, d string) string {
	t.Helper()
	b, err := json.Marshal(affected(t, s, d).After)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNextHopLossOnTheOnlyPath(t *testing.T) {
	s := simulate(t, singleHomed(), Failure{Node: "r1", NextHop: "10.0.12.2"})
	want := map[string]Impact{"10.20.40.8": ImpactReachabilityLost, "10.30.0.1": ImpactReachabilityLost}
	if got := impacts(s); !reflect.DeepEqual(got, want) {
		t.Fatalf("impacts = %v, want %v", got, want)
	}
	if want := (Failure{Node: "r1", VRF: "default", NextHop: "10.0.12.2"}); s.Failure != want {
		t.Errorf("failure = %+v, want %+v with the routing domain filled in", s.Failure, want)
	}
	if got := afterJSON(t, s, "10.20.40.8"); !strings.Contains(got, `"kind":"failed"`) || !strings.Contains(got, "next hop 10.0.12.2 of r1 (default) unavailable") {
		t.Errorf("the walk does not show the cut leg:\n%s", got)
	}
}

func TestNextHopLossCutsOnlyThatGateway(t *testing.T) {
	for _, fail := range []Failure{lostGateway, {Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"}} {
		t.Run(fail.String(), func(t *testing.T) {
			s := simulate(t, gatewayLAN(), fail)
			// 10.40.0.1 leaves by the same eth0 through the other gateway, and
			// 10.0.1.1 is r1's own address on eth0, which stays up: neither moves.
			want := map[string]Impact{"10.0.1.2": ImpactUnknown, "10.20.40.8": ImpactUnknown, "10.30.0.1": ImpactReachabilityLost}
			if got := impacts(s); !reflect.DeepEqual(got, want) {
				t.Fatalf("impacts = %v, want %v", got, want)
			}
			if s.Considered != 10 || s.Unchanged != 7 {
				t.Errorf("considered %d, unchanged %d, want 10 and 7", s.Considered, s.Unchanged)
			}
			a := affected(t, s, "10.20.40.8")
			if !strings.Contains(a.Reason, "whether the node stops selecting it while its link stays up is not in the evidence") {
				t.Errorf("reason = %q, want the ECMP qualification", a.Reason)
			}
			var cut, other bool
			for _, c := range a.After.Next {
				switch {
				case c.Decision.Kind == KindFailed:
					cut = c.Via.NextHop == "10.0.1.2"
				case c.Node == "r4":
					other = len(c.Next) == 1 && c.Next[0].Node == "r3" && c.Next[0].Decision.Kind == KindLocal
				}
			}
			if !cut || !other {
				t.Errorf("after = %+v, want the 10.0.1.2 leg failed and the 10.0.1.4 leg delivering at r3", a.After.Next)
			}
		})
	}
	// The interface failure on the same file cuts the other gateway too, which
	// is what separates the two.
	if got := impacts(simulate(t, gatewayLAN(), Failure{Node: "r1", Interface: "eth0"}))["10.40.0.1"]; got != ImpactReachabilityLost {
		t.Errorf("interface r1 eth0 down: 10.40.0.1 = %s, want reachability_lost", got)
	}
}

func TestNextHopLossNeverRatesRedundancyLost(t *testing.T) {
	if got := impacts(simulate(t, diamond(), Failure{Node: "r1", Interface: "eth1"}))[dest]; got != ImpactRedundancyLost {
		t.Fatalf("interface r1 eth1 down: %s = %s, want redundancy_lost", dest, got)
	}
	s := simulate(t, diamond(), Failure{Node: "r1", NextHop: "10.0.12.2"})
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactUnknown}) {
		t.Errorf("next hop 10.0.12.2 of r1 lost: impacts = %v, want only %s unknown", got, dest)
	}
	for name, c := range map[string]struct {
		obs  []netmodel.Observation
		fail Failure
	}{
		"diamond":     {diamond(), Failure{Node: "r1", NextHop: "10.0.14.2"}},
		"gateway LAN": {gatewayLAN(), Failure{Node: "r1", NextHop: "10.0.1.4"}},
		"downstream":  {diamond(), Failure{Node: "r4", NextHop: "10.0.43.3"}},
	} {
		for d, i := range impacts(simulate(t, c.obs, c.fail)) {
			if i == ImpactRedundancyLost {
				t.Errorf("%s: %s is redundancy_lost", name, d)
			}
		}
	}
}

func TestNextHopLossDownstreamIsAPartialLoss(t *testing.T) {
	// r1 splits over r2 and r4, and r2's only leg to r3 is lost. r2 stays up, so
	// r1 has no reason to stop sending to it, and flows hashed to r2 are dropped.
	s := simulate(t, diamond(), Failure{Node: "r2", NextHop: "10.0.23.3"})
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactReachabilityLost}) {
		t.Fatalf("impacts = %v, want only %s reachability_lost", got, dest)
	}
	delivers := false
	walkHops(affected(t, s, dest).After, func(h *Hop) { delivers = delivers || h.Decision.Kind == KindLocal })
	if !delivers {
		t.Error("the walk drops the r4 branch that still delivers, so a partial loss reads as complete")
	}
}

func TestNextHopLossIsUnknownOnIncompleteEvidence(t *testing.T) {
	r1FIB := func(complete bool, routes ...netmodel.Route) []netmodel.Observation {
		return append(without(singleHomed(), "fib:r1:default"), table(netmodel.PlaneFIB, "r1", "default", complete, routes...))
	}
	cases := map[string]struct {
		obs  []netmodel.Observation
		fail Failure
		want map[string]Impact
	}{
		"partial FIB at the node": {
			obs:  r1FIB(false, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"))),
			fail: Failure{Node: "r1", NextHop: "10.0.12.2"},
			want: map[string]Impact{"10.20.40.8": ImpactUnknown, "10.30.0.1": ImpactUnknown},
		},
		"partial FIB upstream": {
			obs: append(without(diamond(), "fib:r1:default"),
				table(netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"), nh("10.0.14.2", "eth2")))),
			fail: Failure{Node: "r2", NextHop: "10.0.23.3"},
			want: map[string]Impact{dest: ImpactUnknown},
		},
		"less specific route at the node": {
			obs: append(r1FIB(true,
				route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")),
				route("0.0.0.0/0", "kernel", nh("10.0.15.2", "eth3"))),
				configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.15.2/30")})),
			fail: Failure{Node: "r1", NextHop: "10.0.12.2"},
			want: map[string]Impact{"10.20.40.8": ImpactUnknown},
		},
		"leg names no interface under a named one": {
			obs: r1FIB(true,
				route("10.20.0.0/16", "kernel", nh("10.0.12.2", "")),
				route("10.30.0.0/24", "kernel", nh("10.0.12.2", "eth1"))),
			fail: Failure{Node: "r1", NextHop: "10.0.12.2", Interface: "eth1"},
			want: map[string]Impact{"10.20.40.8": ImpactUnknown, "10.30.0.1": ImpactReachabilityLost},
		},
		"gateway held by no modeled node": {
			obs:  without(singleHomed(), "config:r2:default"),
			fail: Failure{Node: "r1", NextHop: "10.0.12.2"},
			want: map[string]Impact{"10.20.40.8": ImpactUnknown},
		},
		"gateway held by two nodes": {
			obs:  append(singleHomed(), configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30")})),
			fail: Failure{Node: "r1", NextHop: "10.0.12.2"},
			want: map[string]Impact{"10.20.40.8": ImpactUnknown, "10.30.0.1": ImpactUnknown},
		},
	}
	// Each case names the destinations its gap touches. Every other affected
	// destination must be unknown too, since forwarding to it is unproven.
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := simulate(t, c.obs, c.fail)
			got := impacts(s)
			for d, i := range c.want {
				if got[d] != i {
					t.Errorf("%s = %q, want %s", d, got[d], i)
				}
			}
			for _, a := range s.Affected {
				switch {
				case c.want[a.Destination] == "" && a.Impact != ImpactUnknown:
					t.Errorf("%s = %s, want unknown", a.Destination, a.Impact)
				case a.Impact == ImpactUnknown && a.Reason == "":
					t.Errorf("%s is unknown with no reason", a.Destination)
				}
			}
		})
	}
}

func TestNextHopOwnAddressIsUnknown(t *testing.T) {
	s := simulate(t, gatewayLAN(), lostGateway)
	if got := afterJSON(t, s, "10.0.1.2"); !strings.Contains(got, "10.0.1.2 is the lost next hop's own address, on link from r1 (default)") {
		t.Errorf("the walk does not say why the gateway's own address is unknown:\n%s", got)
	}
	// A host route sends 10.0.1.2 on link through eth9. Without an interface the
	// selector cannot tell the two links apart, so that leg is unknown too. With
	// %eth0 it is another neighbor, and it is not cut.
	obs := append(without(gatewayLAN(), "fib:r1:default"),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.1.0/24", "kernel", onLink("eth0")),
			route("10.0.1.2/32", "kernel", onLink("eth9")),
			route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0"))))
	if got := impacts(simulate(t, obs, lostGateway))["10.0.1.2"]; got != ImpactUnknown {
		t.Errorf("without an interface: 10.0.1.2 = %s, want unknown", got)
	}
	if got := impacts(simulate(t, obs, Failure{Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"})); !reflect.DeepEqual(got, map[string]Impact{"10.30.0.1": ImpactReachabilityLost}) {
		t.Errorf("on eth0: impacts = %v, want only 10.30.0.1 reachability_lost", got)
	}
}

// twoDomains is r1 forwarding to 10.30.0.0/24 through next hop 10.0.1.2 in two
// routing domains, red and blue, and r7 forwarding to it through the same
// address. Only r2 holds 10.0.1.2, so every walk resolves it.
func twoDomains() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "red", []netmodel.Interface{ifc("eth0", "10.0.1.1/24")}),
		configured("r1", "blue", []netmodel.Interface{ifc("eth5", "10.0.5.1/24")}),
		configured("r7", "default", []netmodel.Interface{ifc("eth0", "10.0.1.7/24")}),
		configured("r2", "red", []netmodel.Interface{ifc("eth0", "10.0.1.2/24"), ifc("lan", "10.30.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "red", true, route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0"))),
		table(netmodel.PlaneFIB, "r1", "blue", true, route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth5"))),
		table(netmodel.PlaneFIB, "r7", "default", true, route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0"))),
	}
}

func TestNextHopLossIsScopedToOneRoutingDomain(t *testing.T) {
	obs := twoDomains()
	if err := simulateErr(t, obs, lostGateway); !strings.Contains(err.Error(), "routing domains blue, red; name one as r1@VRF:10.0.1.2") {
		t.Errorf("error = %v, want both routing domains named", err)
	}
	red := Failure{Node: "r1", VRF: "red", NextHop: "10.0.1.2"}
	if got := impacts(simulateFrom(t, obs, Start{Node: "r1", VRF: "red"}, red)); !reflect.DeepEqual(got, map[string]Impact{"10.30.0.1": ImpactReachabilityLost}) {
		t.Errorf("red from red: impacts = %v, want 10.30.0.1 reachability_lost", got)
	}
	for _, src := range []Start{{Node: "r1", VRF: "blue"}, {Node: "r7", VRF: "default"}} {
		if got := impacts(simulateFrom(t, obs, src, red)); len(got) != 0 {
			t.Errorf("red from %+v: impacts = %v, want none", src, got)
		}
	}
	blue := Failure{Node: "r1", VRF: "blue", NextHop: "10.0.1.2"}
	if got := impacts(simulateFrom(t, obs, Start{Node: "r1", VRF: "blue"}, blue)); !reflect.DeepEqual(got, map[string]Impact{"10.30.0.1": ImpactReachabilityLost}) {
		t.Errorf("blue from blue: impacts = %v, want 10.30.0.1 reachability_lost", got)
	}
}

func TestNextHopInterfaceMustBeChosen(t *testing.T) {
	base := []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24"), ifc("eth1", "10.0.1.1/24")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.1.2/24"), ifc("lan3", "10.30.0.1/24"), ifc("lan4", "10.40.0.1/24"), ifc("lan5", "10.50.0.1/24")}),
	}
	twoLinks := append(slices.Clone(base), table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0")),
		route("10.40.0.0/24", "kernel", nh("10.0.1.2", "eth1")),
		route("10.50.0.0/24", "kernel", nh("10.0.1.2", ""))))
	if err := simulateErr(t, twoLinks, lostGateway); !strings.Contains(err.Error(), "name next hop 10.0.1.2 on eth0, eth1; name one as 10.0.1.2%INTERFACE") {
		t.Errorf("error = %v, want both interfaces named", err)
	}
	want := map[string]Impact{"10.30.0.1": ImpactReachabilityLost, "10.50.0.1": ImpactUnknown}
	if got := impacts(simulate(t, twoLinks, Failure{Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"})); !reflect.DeepEqual(got, want) {
		t.Errorf("on eth0: impacts = %v, want %v", got, want)
	}

	// One named interface beside an unnamed leg is one gateway: without a choice
	// both are cut, and with eth0 named the unnamed leg is unknown.
	oneLink := append(slices.Clone(base), table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.30.0.0/24", "kernel", nh("10.0.1.2", "eth0")),
		route("10.50.0.0/24", "kernel", nh("10.0.1.2", ""))))
	want = map[string]Impact{"10.30.0.1": ImpactReachabilityLost, "10.50.0.1": ImpactReachabilityLost}
	if got := impacts(simulate(t, oneLink, lostGateway)); !reflect.DeepEqual(got, want) {
		t.Errorf("no interface: impacts = %v, want %v", got, want)
	}
	s := simulate(t, oneLink, Failure{Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"})
	if got := afterJSON(t, s, "10.50.0.1"); !strings.Contains(got, "r1 (default) names no interface for next hop 10.0.1.2, so whether it is the lost next hop on eth0 is unknown") {
		t.Errorf("the unnamed leg does not say why it is unknown:\n%s", got)
	}
}

func TestNextHopIPv6(t *testing.T) {
	obs := []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "2001:db8:1::1/64"), ifc("swp1", "fe80::1/64")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "2001:db8:1::2/64"), ifc("swp1", "fe80::2/64"),
			ifc("lan", "2001:db8:30::1/64", "2001:db8:40::1/64", "10.60.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("2001:db8:30::/64", "kernel", nh("2001:db8:1::2", "eth0")),
			route("2001:db8:40::/64", "kernel", nh("fe80::2", "swp1")),
			route("10.60.0.0/24", "kernel", nh("2001:db8:1::2", "eth0"))),
	}
	s := simulate(t, obs, Failure{Node: "r1", NextHop: "2001:db8:1:0::2"})
	if s.Failure.NextHop != "2001:db8:1::2" {
		t.Errorf("next hop = %q, want the canonical 2001:db8:1::2", s.Failure.NextHop)
	}
	// An IPv4 prefix through an IPv6 next hop is cut with it.
	want := map[string]Impact{"2001:db8:30::1": ImpactReachabilityLost, "10.60.0.1": ImpactReachabilityLost}
	if got := impacts(s); !reflect.DeepEqual(got, want) {
		t.Errorf("global: impacts = %v, want %v", got, want)
	}
	if got := impacts(simulate(t, obs, Failure{Node: "r1", NextHop: "fe80::2", Interface: "swp1"})); !reflect.DeepEqual(got, map[string]Impact{"2001:db8:40::1": ImpactReachabilityLost}) {
		t.Errorf("link-local: impacts = %v, want 2001:db8:40::1 reachability_lost", got)
	}
	if err := simulateErr(t, obs, Failure{Node: "r1", NextHop: "fe80::2"}); !strings.Contains(err.Error(), "link-local next hop fe80::2 needs an interface: r1:fe80::2%INTERFACE") {
		t.Errorf("error = %v, want the interface asked for", err)
	}
	// A 4in6 spelling names the IPv4 next hop the model stores.
	s = simulate(t, singleHomed(), Failure{Node: "r1", NextHop: "::ffff:10.0.12.2"})
	if s.Failure.NextHop != "10.0.12.2" || impacts(s)["10.20.40.8"] != ImpactReachabilityLost {
		t.Errorf("4in6: failure %+v, impacts %v, want 10.0.12.2 and 10.20.40.8 reachability_lost", s.Failure, impacts(s))
	}
}

func TestNextHopMustBeRecordedInTheFIB(t *testing.T) {
	obs := append(singleHomed(),
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.12.7", "eth1"))),
		table(netmodel.PlaneConfigured, "r1", "default", true, route("10.20.0.0/16", "static", nh("10.0.12.8", "eth1"))),
		table(netmodel.PlaneIntended, "r1", "default", true, route("10.20.0.0/16", "static", nh("10.0.12.9", "eth1"))))
	for _, c := range []struct {
		fail Failure
		want string
	}{
		{Failure{NextHop: "10.0.12.2"}, "needs a node"},
		{Failure{Node: "r9", NextHop: "10.0.12.2"}, `no fib route of node "r9" names next hop 10.0.12.2`},
		{Failure{Node: "r1", NextHop: "10.0.12.6"}, `no fib route of node "r1" names next hop 10.0.12.6`},
		{Failure{Node: "r1", NextHop: "10.0.12.7"}, `no fib route of node "r1" names next hop 10.0.12.7`},
		{Failure{Node: "r1", NextHop: "10.0.12.8"}, `no fib route of node "r1" names next hop 10.0.12.8`},
		{Failure{Node: "r1", NextHop: "10.0.12.9"}, `no fib route of node "r1" names next hop 10.0.12.9`},
		// r2 reaches 10.30.0.1 on link: a destination, never a named next hop.
		{Failure{Node: "r2", NextHop: "10.30.0.1"}, `no fib route of node "r2" names next hop 10.30.0.1`},
		{Failure{Node: "r1", VRF: "red", NextHop: "10.0.12.2"}, `no fib route of node "r1" in routing domain "red" names next hop 10.0.12.2`},
		{Failure{Node: "r1", Interface: "eth9", NextHop: "10.0.12.2"}, "fib routes of r1 (default) name next hop 10.0.12.2 on eth1, not on eth9"},
		{Failure{Node: "r1", NextHop: "10.0.12"}, `next hop "10.0.12" is not an IP address`},
		{Failure{Node: "r1", NextHop: "010.0.12.2"}, "is not an IP address"},
		{Failure{Node: "r1", NextHop: "10.0.12.0/30"}, "is not an IP address"},
		{Failure{Node: "r1", NextHop: "[2001:db8::1]"}, "is not an IP address"},
		{Failure{Node: "r1", NextHop: "fe80::2%eth1"}, "is not an IP address"},
		{Failure{Node: "r1", NextHop: "10.0.12.2", OSPFNeighbor: "r2"}, "names no OSPF neighbor"},
	} {
		if err := simulateErr(t, obs, c.fail); !strings.Contains(err.Error(), c.want) {
			t.Errorf("Simulate(%+v) = %v, want %q", c.fail, err, c.want)
		}
	}
	// A next hop named only without an interface is on no named interface.
	unnamed := append(without(singleHomed(), "fib:r1:default"),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", ""))))
	if err := simulateErr(t, unnamed, Failure{Node: "r1", NextHop: "10.0.12.2", Interface: "eth1"}); !strings.Contains(err.Error(), "on no named interface, not on eth1") {
		t.Errorf("error = %v, want the unnamed row refused as proof of eth1", err)
	}
}

func TestNextHopReportNamesOwnersAndEvidence(t *testing.T) {
	fail := Failure{Node: "r1", NextHop: "10.0.12.2"}
	obs := append(singleHomed(),
		tableFrom("fib:r1:extra", netmodel.PlaneFIB, "r1", "default", false, route("10.31.0.0/24", "kernel", nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.12.2", "eth1"))))
	g := simulate(t, obs, fail).Gateway
	wantEv := []Support{{Source: "fib:r1:default", CollectedAt: utcText(t0)}, {Source: "fib:r1:extra", CollectedAt: utcText(t0)}}
	if g == nil || !reflect.DeepEqual(g.Owners, []Start{{Node: "r2", VRF: "default"}}) || !reflect.DeepEqual(g.Evidence, wantEv) {
		t.Fatalf("gateway = %+v, want r2 (default) and the two fib rows only", g)
	}

	none := simulate(t, without(singleHomed(), "config:r2:default"), fail)
	if b, _ := json.Marshal(none.Gateway); none.Gateway == nil || !strings.Contains(string(b), `"owners":[]`) {
		t.Errorf("no owner: gateway = %s, want an empty owner list", b)
	}
	if text := none.Text(); !strings.Contains(text, "Next hop: held by no modeled node; recorded in fib:r1:default.") {
		t.Errorf("no owner: text lacks the next-hop line:\n%s", text)
	}

	two := simulate(t, append(singleHomed(), configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30")})), fail)
	if got := two.Gateway.Owners; len(got) != 2 || !slices.Contains(got, Start{Node: "r2", VRF: "default"}) || !slices.Contains(got, Start{Node: "r5", VRF: "default"}) {
		t.Errorf("two owners: owners = %+v, want r2 and r5", got)
	}
}

func TestNextHopLossIsDeterministicAndLeavesTheFileUnchanged(t *testing.T) {
	obs := gatewayLAN()
	want, _ := json.Marshal(simulate(t, obs, lostGateway))
	for range 2 {
		slices.Reverse(obs)
		for range obs {
			obs = append(obs[1:], obs[0])
			if got, _ := json.Marshal(simulate(t, obs, lostGateway)); string(got) != string(want) {
				t.Fatalf("output depends on input order:\n%s\n%s", got, want)
			}
		}
	}
	m, err := netmodel.New(gatewayLAN()...)
	if err != nil {
		t.Fatal(err)
	}
	f := File{Source: fromR1, Model: m}
	before := m.Observations()
	explained, _ := Explain(f, addr(dest)).JSON()
	if _, err := Simulate(f, lostGateway); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.Model.Observations()) {
		t.Error("Simulate changed the model")
	}
	if again, _ := Explain(f, addr(dest)).JSON(); string(again) != string(explained) {
		t.Error("Simulate changed what Explain says about the same file")
	}
}

func TestNextHopLossIsBounded(t *testing.T) {
	var ifaces []netmodel.Interface
	for i := range maxDestinations + 10 {
		ifaces = append(ifaces, ifc(fmt.Sprintf("lo%d", i), fmt.Sprintf("10.%d.%d.1/32", 100+i/256, i%256)))
	}
	s := simulate(t, append(gatewayLAN(), configured("r9", "default", ifaces)), lostGateway)
	if !s.Truncated || s.Considered != maxDestinations {
		t.Errorf("truncated %v, considered %d, want true and %d", s.Truncated, s.Considered, maxDestinations)
	}
}

func TestNextHopTextAndJSONNameTheFailureType(t *testing.T) {
	s := simulate(t, gatewayLAN(), lostGateway)
	text := s.Text()
	for _, want := range []string{
		"Failure simulation: next hop 10.0.1.2 of r1 (default) unavailable, from r1 (default)",
		"Recorded FIB only: r1 (default) loses next hop 10.0.1.2, and nothing else changes: the interface stays up",
		"The loss is simulated, not observed.",
		"so a destination that keeps another recorded next hop is unknown, never redundancy_lost.",
		"Next hop: held by r2 (default); recorded in fib:r1:default.",
		"10 destinations considered, 7 unchanged.",
		"reachability_lost 10.30.0.1 (r2 default)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if again := simulate(t, gatewayLAN(), lostGateway).Text(); again != text {
		t.Error("text differs between identical runs")
	}
	on := simulate(t, gatewayLAN(), Failure{Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"}).Text()
	if !strings.Contains(on, "Failure simulation: next hop 10.0.1.2 on eth0 of r1 (default) unavailable") || !strings.Contains(on, "loses next hop 10.0.1.2 on eth0,") {
		t.Errorf("text does not name the interface:\n%s", on)
	}

	b, _ := json.Marshal(s)
	for _, want := range []string{`"failure":{"node":"r1","vrf":"default","next_hop":"10.0.1.2"}`, `"gateway":{"owners":[{"node":"r2","vrf":"default"}],"evidence":[{"source":"fib:r1:default","collected_at":"2026-10-09T12:00:00Z"}]}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON lacks %s:\n%s", want, b)
		}
	}
	for _, fail := range []Failure{{Node: "r2"}, {Node: "r1", Interface: "eth0"}} {
		f, _ := json.Marshal(fail)
		sim, _ := json.Marshal(simulate(t, gatewayLAN(), fail))
		if strings.Contains(string(f), "next_hop") || strings.Contains(string(sim), `"gateway"`) {
			t.Errorf("%s: failure %s or simulation carries a next-hop field", fail, f)
		}
	}
}
