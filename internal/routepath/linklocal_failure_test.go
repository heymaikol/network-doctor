package routepath

import (
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// linkLocalLine is r1 -- r2 -- r3 on IPv6 link-local next hops. r2 and r3 each
// hold fe80::2 on the link they share with r1, so the address names two nodes
// and only the interface can say which link a leg leaves by. r1 reaches r2's
// LAN through fe80::2 on eth0 and r3's through fe80::2 on eth1.
func linkLocalLine() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "fe80::1/64", "2001:db8:12::1/64"), ifc("eth1", "fe80::1/64", "2001:db8:13::1/64")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "fe80::2/64", "2001:db8:12::2/64"), ifc("lan", "2001:db8:20::1/64")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "fe80::2/64", "2001:db8:13::3/64"), ifc("lan", "2001:db8:30::1/64")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("2001:db8:20::/64", "kernel", nh("fe80::2", "eth0")),
			route("2001:db8:30::/64", "kernel", nh("fe80::2", "eth1"))),
		table(netmodel.PlaneFIB, "r2", "default", true, route("2001:db8:30::/64", "kernel", nh("2001:db8:12::1", "eth0")),
			route("2001:db8:20::/64", "kernel", onLink("lan"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("2001:db8:20::/64", "kernel", nh("2001:db8:13::1", "eth0")),
			route("2001:db8:30::/64", "kernel", onLink("lan"))),
	}
}

// uniqueLinkLocal is linkLocalLine with r3 holding its own link-local address,
// so fe80::2 names only r2 and a leg resolves to one node.
func uniqueLinkLocal() []netmodel.Observation {
	obs := linkLocalLine()
	obs[2] = configured("r3", "default", []netmodel.Interface{ifc("eth0", "fe80::3/64", "2001:db8:13::3/64"), ifc("lan", "2001:db8:30::1/64")})
	obs[3] = table(netmodel.PlaneFIB, "r1", "default", true,
		route("2001:db8:20::/64", "kernel", nh("fe80::2", "eth0")),
		route("2001:db8:30::/64", "kernel", nh("fe80::3", "eth1")))
	return obs
}

// TestLinkLocalNextHopNeedsItsInterface refuses a link-local next hop named
// without its link, and refuses an interface the next hop is not on.
func TestLinkLocalNextHopNeedsItsInterface(t *testing.T) {
	obs := linkLocalLine()
	if err := simulateErr(t, obs, Failure{Node: "r1", NextHop: "fe80::2"}); err == nil ||
		!strings.Contains(err.Error(), "link-local next hop fe80::2 needs an interface") {
		t.Errorf("no interface: error %v, want the interface asked for", err)
	}
	if err := simulateErr(t, obs, Failure{Node: "r1", NextHop: "fe80::2", Interface: "eth9"}); err == nil ||
		!strings.Contains(err.Error(), "not on eth9") {
		t.Errorf("wrong interface: error %v, want it refused", err)
	}
}

// TestLinkLocalNextHopCutsOnlyItsLink cuts fe80::2 on one interface and leaves
// the same address on the other interface standing, so the failure never reads
// a leg on another link as lost.
func TestLinkLocalNextHopCutsOnlyItsLink(t *testing.T) {
	obs := linkLocalLine()
	s := simulate(t, obs, Failure{Node: "r1", NextHop: "fe80::2", Interface: "eth0"})
	if got := s.Failure.NextHop; got != "fe80::2" {
		t.Errorf("next hop = %q, want fe80::2", got)
	}
	// The eth0 leg is the one cut; the eth1 leg reaches an address owned by
	// two nodes, so the walk cannot say where it lands and does not claim it.
	a := affected(t, s, "2001:db8:20::1")
	if a.After == nil || leafOf(a.After, "eth0") == nil || leafOf(a.After, "eth0").Decision.Kind != KindFailed {
		t.Errorf("eth0 leg not cut: %+v", a.After)
	}
	if got := impacts(s)["2001:db8:30::1"]; got != ImpactUnknown {
		t.Errorf("2001:db8:30::1 = %s, want unknown: the shared link-local next hop is not resolved", got)
	}
}

// TestLinkLocalAddressOnTwoNodesIsNeverLost checks that a link-local next hop
// shared by two nodes leaves the destination unknown. Losing r2 may cut the
// eth0 leg, but fe80::2 alone does not say which node that leg reaches.
func TestLinkLocalAddressOnTwoNodesIsNeverLost(t *testing.T) {
	obs := linkLocalLine()
	for _, fail := range []Failure{{Node: "r2"}, {Node: "r2", Interface: "eth0"}, {Node: "r3", Interface: "eth0"}} {
		got := impacts(simulate(t, obs, fail))
		for _, d := range []string{"2001:db8:20::1", "2001:db8:30::1"} {
			if i, ok := got[d]; !ok || i != ImpactUnknown {
				t.Errorf("%s: %s = %q, want unknown: the next hop is owned by two nodes", fail, d, i)
			}
		}
	}
}

// TestLinkLocalNextHopWithOneOwnerRatesLoss shows the same walk rates a loss once
// fe80::2 names one node: the leg's interface is then the far end's.
func TestLinkLocalNextHopWithOneOwnerRatesLoss(t *testing.T) {
	s := simulate(t, uniqueLinkLocal(), Failure{Node: "r2", Interface: "eth0"})
	if got := impacts(s)["2001:db8:20::1"]; got != ImpactReachabilityLost {
		t.Errorf("2001:db8:20::1 = %s, want reachability_lost with r2 eth0 down", got)
	}
	if got, ok := impacts(s)["2001:db8:30::1"]; ok {
		t.Errorf("2001:db8:30::1 = %s, want none: its leg leaves r1 by eth1 to fe80::3", got)
	}
}

// TestZoneNeverRidesAnAddressWithoutItsLink refuses every zone spelling where
// the zone would name the link, so no walk reads a link-local address as
// meaning some other link.
func TestZoneNeverRidesAnAddressWithoutItsLink(t *testing.T) {
	obs := linkLocalLine()
	for _, hop := range []string{"fe80::2%eth0", "2001:db8:12::2%eth0", "fe80::2%", "fe80::2%eth0%eth1"} {
		if err := simulateErr(t, obs, Failure{Node: "r1", NextHop: hop}); err == nil {
			t.Errorf("next hop %q accepted, want refused", hop)
		}
	}
	for _, dest := range []string{"fe80::2%eth0", "2001:db8:12::2%eth0"} {
		if _, err := Simulate(File{Source: fromR1, Model: mustModel(t, obs)}, Failure{Node: "r2"}, addr(dest)); err == nil {
			t.Errorf("extra destination %q accepted, want refused: the zone would be dropped", dest)
		}
	}
}

// TestLinkLocalSpellingIsCanonical reads an upper-case link-local address and
// reports it in canonical form with its interface.
func TestLinkLocalSpellingIsCanonical(t *testing.T) {
	s := simulate(t, linkLocalLine(), Failure{Node: "r1", NextHop: "FE80:0::2", Interface: "eth0"})
	if got := s.Failure.NextHop; got != "fe80::2" {
		t.Errorf("next hop = %q, want fe80::2", got)
	}
	if !strings.Contains(s.Failure.String(), "next hop fe80::2 on eth0 of r1") {
		t.Errorf("failure text = %q", s.Failure.String())
	}
}
