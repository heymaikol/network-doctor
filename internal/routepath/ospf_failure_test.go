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

// ospfNeighbor is one control-plane OSPF neighbor record. An empty state or
// remote address leaves that fact unreported.
func ospfNeighbor(iface, remote, remoteIface, remoteAddr, state string) netmodel.Neighbor {
	n := netmodel.Neighbor{LocalInterface: iface, RemoteNode: remote, RemoteInterface: remoteIface}
	if remoteAddr != "" {
		n.RemoteAddr = addr(remoteAddr)
	}
	n.Attributes = []netmodel.Attribute{{Key: "ospf.router_id", Value: "192.0.2.1"}}
	if state != "" {
		n.Attributes = append(n.Attributes, netmodel.Attribute{Key: keyOSPFState, Value: state})
	}
	return n
}

// ospfControl is one node's OSPF control plane in vrf: each interface reports
// network type netType, unless netType is empty, and the neighbor records.
func ospfControl(source, node, vrf, netType string, ifaces []string, neighbors ...netmodel.Neighbor) netmodel.Observation {
	o := netmodel.Observation{
		Provenance: netmodel.Provenance{Source: source, CollectedAt: t0},
		Plane:      netmodel.PlaneControl,
		Node:       node,
		VRF:        vrf,
		Neighbors:  neighbors,
	}
	for _, name := range ifaces {
		i := netmodel.Interface{Name: name}
		if netType != "" {
			i.Attributes = []netmodel.Attribute{{Key: keyOSPFNetworkType, Value: netType}}
		}
		o.Interfaces = append(o.Interfaces, i)
	}
	return o
}

// withOrigin rewrites every FIB route to origin.
func withOrigin(obs []netmodel.Observation, origin string) []netmodel.Observation {
	for i := range obs {
		if obs[i].Plane != netmodel.PlaneFIB {
			continue
		}
		obs[i].Routes = slices.Clone(obs[i].Routes)
		for j := range obs[i].Routes {
			obs[i].Routes[j].Origin = origin
		}
	}
	return obs
}

// r1Control is r1's control plane in the diamond: point-to-point adjacencies to
// r2 on eth1 and to r4 on eth2, both full.
func r1Control() netmodel.Observation {
	return ospfControl("frr:r1", "r1", "default", "point-to-point", []string{"eth1", "eth2"},
		ospfNeighbor("eth1", "r2", "eth0", "10.0.12.2", "Full"),
		ospfNeighbor("eth2", "r4", "eth0", "10.0.14.2", "Full"))
}

// ospfDiamond is the diamond with OSPF FIB routes, r1's adjacencies, and r2's
// and r4's records back toward r1.
func ospfDiamond() []netmodel.Observation {
	return append(withOrigin(diamond(), netmodel.OriginOSPF), r1Control(),
		ospfControl("frr:r2", "r2", "default", "point-to-point", []string{"eth0"}, ospfNeighbor("eth0", "r1", "eth1", "10.0.12.1", "Full")),
		ospfControl("frr:r4", "r4", "default", "point-to-point", []string{"eth0"}, ospfNeighbor("eth0", "r1", "eth2", "10.0.14.1", "Full")))
}

// ospfSingleHomed is the single-homed line with OSPF FIB routes and r1's one
// point-to-point adjacency to r2.
func ospfSingleHomed() []netmodel.Observation {
	return append(withOrigin(singleHomed(), netmodel.OriginOSPF),
		ospfControl("frr:r1", "r1", "default", "point-to-point", []string{"eth1"}, ospfNeighbor("eth1", "r2", "eth0", "10.0.12.2", "Full")))
}

var lostR1R2 = Failure{Node: "r1", Interface: "eth1", OSPFNeighbor: "r2"}

func TestOSPFAdjacencyLossKeepsTheRedundantPath(t *testing.T) {
	s := simulate(t, ospfDiamond(), lostR1R2)
	if s.Failure.VRF != "default" || s.Adjacency == nil || !s.Adjacency.Proven {
		t.Fatalf("failure %+v, adjacency %+v; want the default VRF filled in and the loss proven", s.Failure, s.Adjacency)
	}
	if a := s.Adjacency; a.NeighborAddr != "10.0.12.2" || a.RemoteInterface != "eth0" || len(a.Evidence) != 1 || a.Evidence[0].Source != "frr:r1" {
		t.Errorf("adjacency = %+v, want r2 at 10.0.12.2 on eth0 from frr:r1", a)
	}
	// The link stays up, so r1's own address on eth1 is not affected the way it
	// is when the interface goes down.
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactRedundancyLost}) {
		t.Fatalf("impacts = %v, want only %s redundancy_lost", got, dest)
	}
	var cut, alternate bool
	for _, c := range affected(t, s, dest).After.Next {
		switch {
		case c.Decision.Kind == KindFailed:
			cut = c.Via.Interface == "eth1" && strings.Contains(c.Decision.Reason, "OSPF adjacency r1 (default) eth1 to r2 lost")
		case c.Node == "r4":
			alternate = len(c.Next) == 1 && c.Next[0].Decision.Kind == KindLocal
		}
	}
	if !cut || !alternate {
		t.Errorf("after = %+v, want the eth1 leg failed and the leg through r4 delivering", affected(t, s, dest).After)
	}
}

func TestOSPFAdjacencyLossOnEitherEnd(t *testing.T) {
	// Each of r1's two adjacencies cuts only its own leg.
	s := simulate(t, ospfDiamond(), Failure{Node: "r1", Interface: "eth2", OSPFNeighbor: "r4"})
	for _, c := range affected(t, s, dest).After.Next {
		if failed := c.Decision.Kind == KindFailed; failed != (c.Via.Interface == "eth2") {
			t.Errorf("leg on %s failed = %v, want only the eth2 leg failed", c.Via.Interface, failed)
		}
	}
	// r2's record names the same adjacency from the far end. Losing it stops
	// r1's leg that arrives on r2 eth0, which is the other direction of the link.
	s = simulate(t, ospfDiamond(), Failure{Node: "r2", Interface: "eth0", OSPFNeighbor: "r1"})
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactRedundancyLost}) {
		t.Fatalf("impacts = %v, want only %s redundancy_lost", got, dest)
	}
	for _, c := range affected(t, s, dest).After.Next {
		if failed := c.Decision.Kind == KindFailed; failed != (c.Via.Interface == "eth1") {
			t.Errorf("leg on %s failed = %v, want only the leg arriving on r2 eth0 failed", c.Via.Interface, failed)
		}
	}

	// r3 holds adjacencies to r2 on eth0 and to r4 on eth2. Losing the one to
	// r2 stops only what arrives on eth0, so the leg through r4 still delivers.
	// r2 is left with no recorded next hop, and OSPF would recompute it, so the
	// destination is unknown, not lost.
	r3 := ospfControl("frr:r3", "r3", "default", "point-to-point", []string{"eth0", "eth2"},
		ospfNeighbor("eth0", "r2", "eth1", "10.0.23.2", "Full"),
		ospfNeighbor("eth2", "r4", "eth1", "10.0.43.2", "Full"))
	lostR3R2 := Failure{Node: "r3", Interface: "eth0", OSPFNeighbor: "r2"}
	s = simulate(t, append(ospfDiamond(), r3), lostR3R2)
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactUnknown}) {
		t.Fatalf("impacts = %v, want only %s unknown", got, dest)
	}
	for _, c := range affected(t, s, dest).After.Next {
		switch {
		case c.Node == "r2" && (len(c.Next) != 1 || c.Next[0].Decision.Kind != KindFailed):
			t.Errorf("r2 branch = %+v, want its segment into r3 eth0 failed", c)
		case c.Node == "r4" && (len(c.Next) != 1 || c.Next[0].Decision.Kind != KindLocal):
			t.Errorf("r4 branch = %+v, want it delivering on r3 eth2", c)
		}
	}
	// A segment arriving on eth0 from r4 contradicts the record that r2 is the
	// one neighbor on that point-to-point link, so it is unknown.
	obs := append(without(ospfDiamond(), "config:r4:default", "fib:r4:default"), r3,
		configured("r4", "default", []netmodel.Interface{ifc("eth0", "10.0.14.2/30"), ifc("eth3", "10.0.23.1/30")}),
		table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.23.3", "eth3"))))
	a := affected(t, simulate(t, obs, lostR3R2), dest)
	var reasons []string
	walkHops(a.After, func(h *Hop) { reasons = append(reasons, h.Decision.Reason) })
	if a.Impact != ImpactUnknown || !slices.ContainsFunc(reasons, func(r string) bool { return strings.Contains(r, "from r4, which is not the recorded neighbor r2") }) {
		t.Errorf("impact %s, reasons %q; want unknown because r4 is not the recorded neighbor", a.Impact, reasons)
	}
}

func TestOSPFAdjacencyLossIsUnknownNeverLost(t *testing.T) {
	// r1 routes 10.20.40.8 and 10.30.0.1 over the link and nothing else. With no
	// recorded alternate, OSPF may still compute one, so neither is lost.
	s := simulate(t, ospfSingleHomed(), lostR1R2)
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{"10.20.40.8": ImpactUnknown, "10.30.0.1": ImpactUnknown}) {
		t.Errorf("impacts = %v, want 10.20.40.8 and 10.30.0.1 unknown", got)
	}
	if r := affected(t, s, "10.20.40.8").Reason; !strings.Contains(r, "no SPF is run") {
		t.Errorf("reason = %q, want it to say no SPF is run", r)
	}
	// The same file under an interface failure is unknown for the same reason:
	// OSPF computes its routes again once the link is down, too. A static
	// route across the link tells the two failure types apart.
	if got := impacts(simulate(t, ospfSingleHomed(), Failure{Node: "r1", Interface: "eth1"})); got["10.20.40.8"] != ImpactUnknown {
		t.Errorf("interface failure impacts = %v, want 10.20.40.8 unknown", got)
	}
}

func TestOSPFAdjacencyLossLeavesTheLinkUp(t *testing.T) {
	// r1 reaches the LAN behind r2 by a static route and the far subnet by OSPF,
	// both across eth1. Only the OSPF route depends on the adjacency.
	obs := append(without(ospfSingleHomed(), "fib:r1:default"),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.12.0/30", netmodel.OriginConnected, onLink("eth1")),
			route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.12.2", "eth1")),
			route("10.30.0.0/24", netmodel.OriginStatic, nh("10.0.12.2", "eth1"))))
	got := impacts(simulate(t, obs, lostR1R2))
	if got["10.20.40.8"] != ImpactUnknown {
		t.Errorf("10.20.40.8 impact = %s, want unknown", got["10.20.40.8"])
	}
	// The static route and the connected neighbor keep forwarding, and r1 keeps
	// its own address on the link.
	for _, d := range []string{"10.30.0.1", "10.0.12.2", "10.0.12.1"} {
		if i, ok := got[d]; ok {
			t.Errorf("%s impact = %s, want unchanged, because the link is still up", d, i)
		}
	}
	link := impacts(simulate(t, obs, Failure{Node: "r1", Interface: "eth1"}))
	if link["10.30.0.1"] != ImpactReachabilityLost || link["10.0.12.1"] != ImpactUnknown {
		t.Errorf("interface failure impacts = %v, want the static route lost and the down address unknown", link)
	}
}

func TestOSPFAdjacencyLossKeepsTheLinkSubnet(t *testing.T) {
	// r1 reaches the r2 -- r3 link subnet by the stub network r2 advertises,
	// which a point-to-point router keeps advertising whatever its neighbor's
	// state, and r2 delivers it on the link by its connected route. Only the
	// LAN behind r3, which needs the link as a transit edge, depends on the
	// adjacency.
	obs := []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth1", "10.0.12.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.12.0/30", netmodel.OriginConnected, onLink("eth1")),
			route("10.0.23.0/30", netmodel.OriginOSPF, nh("10.0.12.2", "eth1")),
			route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneFIB, "r2", "default", true,
			route("10.0.23.0/30", netmodel.OriginConnected, onLink("eth1")),
			route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.23.3", "eth1"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.40.0/24", netmodel.OriginConnected, onLink("eth1"))),
		ospfControl("frr:r2", "r2", "default", "point-to-point", []string{"eth1"}, ospfNeighbor("eth1", "r3", "eth0", "10.0.23.3", "Full")),
	}
	s := simulate(t, obs, Failure{Node: "r2", Interface: "eth1", OSPFNeighbor: "r3"})
	if s.Adjacency == nil || !s.Adjacency.Proven {
		t.Fatalf("adjacency = %+v, want the transit dependency proven", s.Adjacency)
	}
	if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{"10.20.40.8": ImpactUnknown}) {
		t.Errorf("impacts = %v, want only 10.20.40.8 unknown; the link subnet stays reachable", got)
	}
}

func TestOSPFAdjacencyMustBeRecorded(t *testing.T) {
	obs := append(ospfDiamond(),
		// An expected neighbor on the configured plane is not an adjacency.
		configured("r4", "default", nil, ospfNeighbor("eth1", "r3", "eth2", "10.0.43.3", "Full")),
		// A control-plane neighbor with no OSPF attribute is not an OSPF record.
		netmodel.Observation{Provenance: netmodel.Provenance{Source: "lldp:r3", CollectedAt: t0}, Plane: netmodel.PlaneControl, Node: "r3", VRF: "default",
			Neighbors: []netmodel.Neighbor{{LocalInterface: "eth0", RemoteNode: "r2", RemoteAddr: addr("10.0.23.2")}}})
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatal(err)
	}
	f := File{Source: fromR1, Model: m}
	for _, fail := range []Failure{
		{Node: "r1", Interface: "eth1", OSPFNeighbor: "r9"},
		{Node: "r1", Interface: "eth2", OSPFNeighbor: "r2"},
		{Node: "r1", Interface: "eth1", OSPFNeighbor: "r2", VRF: "blue"},
		{Node: "r1", OSPFNeighbor: "r2"},
		{Interface: "eth1", OSPFNeighbor: "r2"},
		{Node: "r4", Interface: "eth1", OSPFNeighbor: "r3"},
		{Node: "r3", Interface: "eth0", OSPFNeighbor: "r2"},
		{Node: "r1", Interface: "eth1", VRF: "default"},
	} {
		if _, err := Simulate(f, fail); err == nil {
			t.Errorf("Simulate(%+v) succeeded, want an error", fail)
		}
	}
}

func TestOSPFAdjacencyIsReadInItsOwnVRF(t *testing.T) {
	// r1 also peers with r2 in VRF blue, on its own interface and subnet.
	blue := []netmodel.Observation{
		configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.92.1/30")}),
		configured("r2", "blue", []netmodel.Interface{ifc("eth3", "10.0.92.2/30"), ifc("eth4", "10.90.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "blue", true, route("10.90.0.0/24", netmodel.OriginOSPF, nh("10.0.92.2", "eth3"))),
		table(netmodel.PlaneFIB, "r2", "blue", true, route("10.90.0.0/24", netmodel.OriginConnected, onLink("eth4"))),
		ospfControl("frr:r1:blue", "r1", "blue", "point-to-point", []string{"eth3"}, ospfNeighbor("eth3", "r2", "eth3", "10.0.92.2", "Full")),
	}
	obs := append(ospfDiamond(), blue...)
	fromBlue := Start{Node: "r1", VRF: "blue"}
	if got := impacts(simulateFrom(t, obs, fromBlue, lostR1R2)); len(got) != 0 {
		t.Errorf("blue impacts of the default adjacency = %v, want none", got)
	}
	s := simulateFrom(t, obs, fromBlue, Failure{Node: "r1", Interface: "eth3", OSPFNeighbor: "r2"})
	if s.Failure.VRF != "blue" || impacts(s)["10.90.0.1"] != ImpactUnknown {
		t.Errorf("failure %+v, impacts %v; want the blue adjacency and 10.90.0.1 unknown", s.Failure, impacts(s))
	}
	if got := impacts(simulate(t, obs, Failure{Node: "r1", Interface: "eth3", OSPFNeighbor: "r2"})); len(got) != 0 {
		t.Errorf("default impacts of the blue adjacency = %v, want none", got)
	}

	// The same interface and neighbor recorded in two VRFs is ambiguous until
	// the failure names one.
	twice := append(slices.Clone(obs), ospfControl("frr:r1:red", "r1", "red", "point-to-point", []string{"eth1"}, ospfNeighbor("eth1", "r2", "eth0", "10.0.12.2", "Full")))
	m, err := netmodel.New(twice...)
	if err != nil {
		t.Fatal(err)
	}
	f := File{Source: fromR1, Model: m}
	if _, err := Simulate(f, lostR1R2); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("err = %v, want the adjacency named ambiguous", err)
	}
	named := lostR1R2
	named.VRF = "default"
	if s, err := Simulate(f, named); err != nil || impacts(s)[dest] != ImpactRedundancyLost {
		t.Errorf("err %v, impacts %v; want the named default adjacency simulated", err, impacts(s))
	}
}

func TestOSPFAdjacencyEvidenceGapsAreUnknown(t *testing.T) {
	r2 := func(state string) netmodel.Neighbor { return ospfNeighbor("eth1", "r2", "eth0", "10.0.12.2", state) }
	r4 := ospfNeighbor("eth2", "r4", "eth0", "10.0.14.2", "Full")
	ctl := func(source, netType string, ns ...netmodel.Neighbor) netmodel.Observation {
		return ospfControl(source, "r1", "default", netType, []string{"eth1", "eth2"}, ns...)
	}
	cases := []struct {
		name   string
		r1     []netmodel.Observation
		reason string
	}{
		{"state before full", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("2-Way"), r4)}, "is 2-way, not full"},
		{"state missing", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2(""), r4)}, "states no ospf.state"},
		{"states conflict", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("Full"), r4), ctl("frr:r1 again", "point-to-point", r2("Init"))}, "state full and init"},
		{"network type missing", []netmodel.Observation{ctl("frr:r1", "", r2("Full"), r4)}, "reports no ospf.network_type"},
		{"broadcast network", []netmodel.Observation{ctl("frr:r1", "broadcast", r2("Full"), r4)}, "network type broadcast"},
		{"network types conflict", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("Full"), r4), ctl("frr:r1 again", "broadcast")}, "network types broadcast and point-to-point"},
		{"address missing", []netmodel.Observation{ctl("frr:r1", "point-to-point", ospfNeighbor("eth1", "r2", "eth0", "", "Full"), r4)}, "no single address"},
		{"addresses conflict", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("Full"), r4), ctl("frr:r1 again", "point-to-point", ospfNeighbor("eth1", "r2", "eth0", "10.0.12.6", "Full"))}, "no single address"},
		{"remote interfaces conflict", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("Full"), r4), ctl("frr:r1 again", "point-to-point", ospfNeighbor("eth1", "r2", "eth9", "10.0.12.2", "Full"))}, "remote interfaces eth0 and eth9"},
		{"second neighbor on the link", []netmodel.Observation{ctl("frr:r1", "point-to-point", r2("Full"), r4, ospfNeighbor("eth1", "r5", "eth0", "10.0.12.3", "Full"))}, "also records OSPF neighbors r5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := append(without(ospfDiamond(), "frr:r1"), c.r1...)
			s := simulate(t, obs, lostR1R2)
			if s.Adjacency.Proven || !strings.Contains(s.Adjacency.Reason, c.reason) {
				t.Fatalf("adjacency = %+v, want it unproven because %q", s.Adjacency, c.reason)
			}
			if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: ImpactUnknown}) {
				t.Errorf("impacts = %v, want only %s unknown", got, dest)
			}
			if !strings.Contains(s.Text(), "Transit dependency not proven: ") {
				t.Errorf("text does not say the loss is unproven:\n%s", s.Text())
			}
		})
	}
}

func TestOSPFAdjacencyNeedsRouteAttribution(t *testing.T) {
	r1 := func(routes ...netmodel.Route) []netmodel.Observation {
		return append(without(ospfDiamond(), "fib:r1:default"), table(netmodel.PlaneFIB, "r1", "default", true, routes...))
	}
	both := []netmodel.NextHop{nh("10.0.12.2", "eth1"), nh("10.0.14.2", "eth2")}
	mixed := append(r1(route("10.20.0.0/16", netmodel.OriginOSPF, both...)), tableFrom("static:r1", netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", netmodel.OriginStatic, both...)))
	cases := []struct {
		name   string
		obs    []netmodel.Observation
		reason string
	}{
		{"origin not stated as OSPF", r1(route("10.20.0.0/16", "kernel", both...)), "forwards by origin kernel"},
		{"two origins agree", mixed, "forwards by origin ospf and static"},
		{"next hop names no interface", r1(route("10.20.0.0/16", netmodel.OriginOSPF, netmodel.NextHop{Addr: addr("10.0.12.2")}, nh("10.0.14.2", "eth2"))), "names no interface for next hop 10.0.12.2"},
		{"next hop is not the neighbor", r1(route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.12.3", "eth1"), nh("10.0.14.2", "eth2"))), "is not the neighbor's recorded address"},
		{"BGP route", r1(route("10.20.0.0/16", netmodel.OriginBGP, both...)), "BGP withdrawal is not modeled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, c.obs, lostR1R2)
			a := affected(t, s, dest)
			if a.Impact != ImpactUnknown {
				t.Errorf("impact = %s, want unknown", a.Impact)
			}
			var reasons []string
			walkHops(a.After, func(h *Hop) { reasons = append(reasons, h.Decision.Reason) })
			if !slices.ContainsFunc(reasons, func(r string) bool { return strings.Contains(r, c.reason) }) {
				t.Errorf("after walk reasons %q lack %q", reasons, c.reason)
			}
		})
	}
	// A BGP route is unknown even where it does not cross the link, because its
	// session may.
	obs := append(without(ospfDiamond(), "fib:r4:default"), table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", netmodel.OriginBGP, nh("10.0.43.3", "eth1"))))
	if got := impacts(simulate(t, obs, lostR1R2)); got[dest] != ImpactUnknown {
		t.Errorf("impacts = %v, want %s unknown while r4 forwards it by BGP", got, dest)
	}
}

func TestOSPFAdjacencyLossIsDeterministicAndLeavesTheFileUnchanged(t *testing.T) {
	obs := ospfDiamond()
	want, _ := json.Marshal(simulate(t, obs, lostR1R2))
	wantText := simulate(t, obs, lostR1R2).Text()
	for range 2 {
		slices.Reverse(obs)
		for range obs {
			obs = append(obs[1:], obs[0])
			s := simulate(t, obs, lostR1R2)
			if got, _ := json.Marshal(s); string(got) != string(want) || s.Text() != wantText {
				t.Fatalf("output depends on input order:\n%s\n%s", got, want)
			}
		}
	}
	m, err := netmodel.New(ospfDiamond()...)
	if err != nil {
		t.Fatal(err)
	}
	before := m.Observations()
	f := File{Source: fromR1, Model: m}
	if _, err := Simulate(f, lostR1R2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.Model.Observations()) {
		t.Error("Simulate changed the model")
	}
}

func TestOSPFAdjacencyLossIsBounded(t *testing.T) {
	var ifaces []netmodel.Interface
	for i := range maxDestinations + 10 {
		ifaces = append(ifaces, ifc(fmt.Sprintf("lo%d", i), fmt.Sprintf("10.%d.%d.1/32", 100+i/256, i%256)))
	}
	s := simulate(t, append(ospfDiamond(), configured("r9", "default", ifaces)), lostR1R2)
	if !s.Truncated || s.Considered != maxDestinations || len(s.Affected) > maxDestinations {
		t.Errorf("truncated %v, considered %d, affected %d; want true, %d, and at most that many", s.Truncated, s.Considered, len(s.Affected), maxDestinations)
	}
}

func TestOSPFAdjacencyTextAndJSONNameTheFailureType(t *testing.T) {
	s := simulate(t, ospfDiamond(), lostR1R2)
	text := s.Text()
	for _, want := range []string{
		"Failure simulation: OSPF adjacency r1 (default) eth1 to r2 lost",
		"The link stays up",
		"neighbor address 10.0.12.2, remote interface eth0, evidence frr:r1",
		"Transit dependency proven: the link is point-to-point and the neighbor is full, so once the adjacency is gone SPF cannot use the link as a transit edge",
		"It does not prove what the FIB holds after the loss, and the link's stub network may still be advertised.",
		"redundancy_lost 10.20.40.8",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	// The records prove a structural dependency, never the FIB after the loss.
	for _, claim := range []string{"withdrawn", "\nProven:", "next hop across it is gone"} {
		if strings.Contains(text, claim) {
			t.Errorf("text claims %q, which the records cannot prove:\n%s", claim, text)
		}
	}
	data, _ := json.Marshal(s)
	for _, want := range []string{`"failure":{"node":"r1","interface":"eth1","vrf":"default","ospf_neighbor":"r2"}`, `"adjacency":{"neighbor_addr":"10.0.12.2"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JSON lacks %s:\n%s", want, data)
		}
	}
	// A router or interface failure keeps its existing fields.
	data, _ = json.Marshal(simulate(t, diamond(), Failure{Node: "r1", Interface: "eth1"}))
	if !strings.Contains(string(data), `"failure":{"node":"r1","interface":"eth1"},"source"`) {
		t.Errorf("interface failure JSON changed:\n%s", data)
	}
}
