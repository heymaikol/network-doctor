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

// lineBy is the single-homed line with r1's FIB routes of origin at1 and r2's
// of origin at2.
func lineBy(at1, at2 string) []netmodel.Observation {
	obs := singleHomed()
	for i := range obs {
		switch obs[i].Source {
		case "fib:r1:default":
			withOrigin(obs[i:i+1], at1)
		case "fib:r2:default":
			withOrigin(obs[i:i+1], at2)
		}
	}
	return obs
}

// lostReason is the reason a loss that rests on a protocol route gives, naming
// the first node on the lost branch that holds one, and origin, the protocol of
// that node's FIB row.
func lostReason(node, origin string) string {
	return "but " + node + " (default) holds an OSPF or BGP route toward it, in fib:" + node + ":default (" + origin + "), and no route is recomputed here"
}

func TestInterfaceFailureUnderAProtocolRouteIsUnknown(t *testing.T) {
	// r1 reaches both destinations only across eth1, by routes a protocol
	// installed. Once eth1 is down that protocol computes its routes again,
	// and whether another path takes over is not in the file, which is what
	// --fail-ospf says of the same routes.
	for _, origin := range []string{netmodel.OriginOSPF, netmodel.OriginBGP} {
		t.Run(origin, func(t *testing.T) {
			s := simulate(t, withOrigin(singleHomed(), origin), Failure{Node: "r1", Interface: "eth1"})
			want := map[string]Impact{dest: ImpactUnknown, "10.30.0.1": ImpactUnknown, "10.0.12.1": ImpactUnknown}
			if got := impacts(s); !reflect.DeepEqual(got, want) {
				t.Fatalf("impacts = %v, want %v", got, want)
			}
			a := affected(t, s, dest)
			if !strings.Contains(a.Reason, lostReason("r1", origin)) {
				t.Errorf("reason = %q, want it to name r1 and its %s row", a.Reason, origin)
			}
			// The walk still shows the cut segment and the rows it rests on.
			if a.After == nil || len(a.After.Next) != 1 || a.After.Next[0].Decision.Kind != KindFailed || a.After.Decision.Evidence[0].Origin != origin {
				t.Errorf("after = %+v, want r1's %s route with its eth1 leg failed", a.After, origin)
			}
		})
	}
}

func TestStaticRouteLossStands(t *testing.T) {
	// No protocol remakes a static or kernel route, so the recorded loss is
	// the prediction, as the live namespace cases check.
	for _, origin := range []string{netmodel.OriginStatic, "kernel"} {
		s := simulate(t, withOrigin(singleHomed(), origin), Failure{Node: "r1", Interface: "eth1"})
		if got := impacts(s); got[dest] != ImpactReachabilityLost || got["10.30.0.1"] != ImpactReachabilityLost {
			t.Errorf("%s impacts = %v, want both destinations reachability_lost", origin, got)
		}
	}
}

func TestDestinationOnlyOnTheFailedRouterStaysLost(t *testing.T) {
	// r2 alone holds 10.30.0.1, so no path a protocol computes delivers it
	// once r2 is gone. 10.20.40.8 is on r3, which is still up behind r2.
	for _, origin := range []string{netmodel.OriginOSPF, netmodel.OriginBGP} {
		t.Run(origin, func(t *testing.T) {
			s := simulate(t, withOrigin(singleHomed(), origin), Failure{Node: "r2"})
			want := map[string]Impact{"10.30.0.1": ImpactReachabilityLost, dest: ImpactUnknown}
			if got := impacts(s); !reflect.DeepEqual(got, want) {
				t.Errorf("impacts = %v, want %v", got, want)
			}
			if got := impacts(simulate(t, withOrigin(diamond(), origin), Failure{Node: "r3"})); got[dest] != ImpactReachabilityLost {
				t.Errorf("diamond impacts with r3 failed = %v, want %s reachability_lost", got, dest)
			}
			// A down interface leaves r2 up, so its LAN may be reached another
			// way, and it is unknown.
			s = simulate(t, withOrigin(singleHomed(), origin), Failure{Node: "r2", Interface: "eth0"})
			if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{"10.30.0.1": ImpactUnknown, dest: ImpactUnknown}) {
				t.Errorf("impacts with r2 eth0 down = %v, want both unknown", got)
			}
		})
	}
}

func TestProtocolRouteAnywhereOnTheLostBranch(t *testing.T) {
	// r2 eth1 is down, so r2 is left with no next hop toward r3. A protocol
	// route at r2, or at r1 ahead of it, may move the branch.
	fail := Failure{Node: "r2", Interface: "eth1"}
	cases := []struct {
		name, at1, at2 string
		impact         Impact
		reason         string
		// lan is the impact on r2's LAN, which the failure does not cut. r1
		// forwards toward it by BGP in one case, so it is unknown there.
		lan Impact
	}{
		{"static throughout", netmodel.OriginStatic, "kernel", ImpactReachabilityLost, "", ""},
		{"protocol at the stranded node", netmodel.OriginStatic, netmodel.OriginOSPF, ImpactUnknown, lostReason("r2", netmodel.OriginOSPF), ""},
		{"protocol ahead of it", netmodel.OriginBGP, "kernel", ImpactUnknown, lostReason("r1", netmodel.OriginBGP), ImpactUnknown},
		{"both", netmodel.OriginOSPF, netmodel.OriginBGP, ImpactUnknown, lostReason("r1", netmodel.OriginOSPF), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, lineBy(c.at1, c.at2), fail)
			want := map[string]Impact{dest: c.impact}
			if c.lan != "" {
				want["10.30.0.1"] = c.lan
			}
			if got := impacts(s); !reflect.DeepEqual(got, want) {
				t.Fatalf("impacts = %v, want %v", got, want)
			}
			if r := affected(t, s, dest).Reason; !strings.Contains(r, c.reason) {
				t.Errorf("reason = %q, want %q", r, c.reason)
			}
		})
	}
}

func TestProtocolRouteOnAnotherBranch(t *testing.T) {
	// beyondR3 is the diamond with r5 behind r3, holding 10.20.50.5. r3
	// fails, so r2 and r4 are both left with no next hop, and r5 is up.
	beyondR3 := func(at2, at4 string) []netmodel.Observation {
		return append(without(diamond(), "config:r3:default", "fib:r3:default", "fib:r2:default", "fib:r4:default"),
			configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24"), ifc("eth2", "10.0.43.3/30"), ifc("eth3", "10.0.35.3/30")}),
			configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.35.5/30"), ifc("lan", "10.20.50.5/24")}),
			table(netmodel.PlaneFIB, "r2", "default", true, route("10.20.0.0/16", at2, nh("10.0.23.3", "eth1"))),
			table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", at4, nh("10.0.43.3", "eth1"))),
			table(netmodel.PlaneFIB, "r3", "default", true,
				route("10.20.40.0/24", "kernel", onLink("eth1")),
				route("10.20.50.0/24", "kernel", nh("10.0.35.5", "eth3"))),
			table(netmodel.PlaneFIB, "r5", "default", true, route("10.20.50.0/24", "kernel", onLink("lan"))))
	}
	far := "10.20.50.5"
	cases := []struct {
		name, at2, at4 string
		impact         Impact
	}{
		// Flows hashed onto a branch that no protocol decides on are dropped,
		// whatever the other branch does.
		{"static branch first", "kernel", netmodel.OriginOSPF, ImpactReachabilityLost},
		{"static branch second", netmodel.OriginOSPF, "kernel", ImpactReachabilityLost},
		{"protocol on both", netmodel.OriginOSPF, netmodel.OriginBGP, ImpactUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, beyondR3(c.at2, c.at4), Failure{Node: "r3"})
			if got := impacts(s); got[far] != c.impact || got[dest] != ImpactReachabilityLost {
				t.Errorf("impacts = %v, want %s %s and %s, which only r3 holds, reachability_lost", got, far, c.impact, dest)
			}
		})
	}
	// A protocol route on a branch that still delivers moves nothing: the
	// lost branch through r2 is static throughout.
	obs := append(without(diamond(), "fib:r4:default"), table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.43.3", "eth1"))))
	if got := impacts(simulate(t, obs, Failure{Node: "r2", Interface: "eth1"})); got[dest] != ImpactReachabilityLost {
		t.Errorf("impacts = %v, want %s reachability_lost, since r4 still delivers and r2 forwards by kernel", got, dest)
	}
}

func TestMixedRouteOriginsAreReadConservatively(t *testing.T) {
	fail := Failure{Node: "r1", Interface: "eth1"}
	cases := []struct {
		name   string
		obs    []netmodel.Observation
		want   map[string]Impact
		reason string
	}{
		{
			// Two FIB rows agree on forwarding and disagree on what installed
			// it, so the protocol may own the entry.
			"FIB rows of two origins",
			append(singleHomed(), tableFrom("frr:r1", netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.12.2", "eth1")))),
			map[string]Impact{dest: ImpactUnknown, "10.30.0.1": ImpactReachabilityLost},
			"holds an OSPF or BGP route toward it, in frr:r1 (ospf),",
		},
		{
			// The FIB row names kernel, and r1's control plane holds an OSPF
			// route for the destination, which can be installed in its place.
			"control-plane protocol route",
			append(singleHomed(), table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.12.2", "eth1")))),
			map[string]Impact{dest: ImpactUnknown, "10.30.0.1": ImpactReachabilityLost},
			"holds an OSPF or BGP route toward it, in control:r1:default (ospf),",
		},
		{
			"control-plane default route",
			append(singleHomed(), table(netmodel.PlaneControl, "r1", "default", true, route("0.0.0.0/0", netmodel.OriginBGP, nh("10.0.12.2", "eth1")))),
			map[string]Impact{dest: ImpactUnknown, "10.30.0.1": ImpactUnknown},
			"holds an OSPF or BGP route toward it, in control:r1:default (bgp),",
		},
		{
			"control-plane static route",
			append(singleHomed(), table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", netmodel.OriginStatic, nh("10.0.12.2", "eth1")))),
			map[string]Impact{dest: ImpactReachabilityLost, "10.30.0.1": ImpactReachabilityLost},
			"",
		},
		{
			// Another routing domain's protocol routes do not decide here.
			"protocol routes in another routing domain",
			append(singleHomed(),
				configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.92.1/30")}),
				table(netmodel.PlaneControl, "r1", "blue", true, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.92.2", "eth3"))),
				table(netmodel.PlaneFIB, "r1", "blue", true, route("10.20.0.0/16", netmodel.OriginOSPF, nh("10.0.92.2", "eth3")))),
			map[string]Impact{dest: ImpactReachabilityLost, "10.30.0.1": ImpactReachabilityLost},
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, c.obs, fail)
			got := impacts(s)
			delete(got, "10.0.12.1")
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("impacts = %v, want %v", got, c.want)
			}
			if r := affected(t, s, dest).Reason; !strings.Contains(r, c.reason) {
				t.Errorf("reason = %q, want %q", r, c.reason)
			}
		})
	}
}

func TestProtocolLossTextAndJSONQualifyTheUncertainty(t *testing.T) {
	s := simulate(t, withOrigin(singleHomed(), netmodel.OriginOSPF), Failure{Node: "r1", Interface: "eth1"})
	text := s.Text()
	want := "unknown 10.20.40.8 (r3 default): after the failure, a forwarding branch has no surviving recorded next hop, " + lostReason("r1", netmodel.OriginOSPF) + "; whether that protocol computes another path once it learns of the failure is not in the evidence"
	if !strings.Contains(text, want) {
		t.Errorf("text lacks %q:\n%s", want, text)
	}
	data, _ := json.Marshal(affected(t, s, dest))
	if !strings.Contains(string(data), `"impact":"unknown","reason":"after the failure, a forwarding branch has no surviving recorded next hop, `+lostReason("r1", netmodel.OriginOSPF)) {
		t.Errorf("JSON does not give the reason:\n%s", data)
	}
	// The reason qualifies the loss and predicts nothing about convergence.
	for _, claim := range []string{"converges", "recovers", "will "} {
		if strings.Contains(affected(t, s, dest).Reason, claim) {
			t.Errorf("reason claims %q: %s", claim, affected(t, s, dest).Reason)
		}
	}
	// The rows it names come in a fixed order, whatever order the file gives.
	obs := append(withOrigin(singleHomed(), netmodel.OriginOSPF),
		tableFrom("bgp:r1", netmodel.PlaneControl, "r1", "default", false, route("10.0.0.0/8", netmodel.OriginBGP, nh("10.0.12.2", "eth1"))))
	first := affected(t, simulate(t, obs, Failure{Node: "r1", Interface: "eth1"}), dest).Reason
	if !strings.Contains(first, "in fib:r1:default (ospf), bgp:r1 (bgp),") {
		t.Errorf("reason = %q, want both rows named", first)
	}
	slices.Reverse(obs)
	if got := affected(t, simulate(t, obs, Failure{Node: "r1", Interface: "eth1"}), dest).Reason; got != first {
		t.Errorf("reason depends on input order:\n%s\n%s", got, first)
	}
}

// offPath is r1 -- r4 -- r3, with rr on r1 eth9. r1 and r4 forward
// 10.20.0.0/16 by routes of origin at1 and at4, r1 forwards r4's LAN by a
// static route and r4's eth0 subnet by a connected one, and r1 records a full
// point-to-point OSPF adjacency to rr. No FIB row forwards anything through rr,
// and nothing in the file says what rr does for BGP: whether it peers with r1
// or r4, reflects their routes, or carries a session is not recorded.
func offPath(at1, at4 string) []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.14.1/30"), ifc("eth9", "10.0.19.1/30")}),
		configured("rr", "default", []netmodel.Interface{ifc("eth0", "10.0.19.2/30")}),
		configured("r4", "default", []netmodel.Interface{ifc("eth0", "10.0.14.2/30"), ifc("eth1", "10.0.43.2/30"), ifc("lan", "10.40.0.1/24")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.43.3/30"), ifc("lan", "10.20.40.8/24")}),
		ospfControl("frr:r1", "r1", "default", "point-to-point", []string{"eth9"}, ospfNeighbor("eth9", "rr", "eth0", "10.0.19.2", "Full")),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.14.0/30", netmodel.OriginConnected, onLink("eth0")),
			route("10.20.0.0/16", at1, nh("10.0.14.2", "eth0")),
			route("10.40.0.0/24", netmodel.OriginStatic, nh("10.0.14.2", "eth0"))),
		table(netmodel.PlaneFIB, "r4", "default", true, route("10.20.0.0/16", at4, nh("10.0.43.3", "eth1"))),
	}
}

// bgpReason is what an ordinary failure says of a destination it would rate
// claim, when node forwards toward it by BGP route 10.20.0.0/16 in rows.
func bgpReason(claim, node, rows string) string {
	return claim + ", but " + node + " (default) forwards toward it by BGP route 10.20.0.0/16, in " + rows + "; the file records no BGP session, peer, or next-hop resolution for that route, so whether the failure disrupts it is not in the evidence, and BGP withdrawal is not modeled"
}

const offTheWalk = "no recorded forwarding branch crosses the failure"

func TestBGPForwardingOffTheFailureIsUnknown(t *testing.T) {
	// No recorded branch toward 10.20.40.8 crosses rr or r1 eth9, so the
	// walk is the same with the failure as without it. But r1 forwards by
	// BGP, and whether its session or next-hop resolution runs through rr or
	// eth9 is not in the file. --fail-ospf r1:eth9:rr already says unknown,
	// and a failure that takes the whole router or interface away must not
	// say more.
	obs := offPath(netmodel.OriginBGP, netmodel.OriginBGP)
	// The connected control below is a delivery, not a missing route.
	if h := explainFrom(t, obs, nil, fromR1, "10.0.14.2").Forwarding; h.Decision.Evidence[0].Origin != netmodel.OriginConnected || len(h.Next) != 1 || h.Next[0].Decision.Kind != KindLocal {
		t.Fatalf("forwarding to 10.0.14.2 = %+v, want r1's connected route delivering at r4", h)
	}
	for _, fail := range []Failure{{Node: "rr"}, {Node: "r1", Interface: "eth9"}, {Node: "r1", Interface: "eth9", OSPFNeighbor: "rr"}} {
		t.Run(fail.String(), func(t *testing.T) {
			s := simulate(t, obs, fail)
			a := affected(t, s, dest)
			if a.Impact != ImpactUnknown {
				t.Fatalf("%s impact = %s, want unknown", dest, a.Impact)
			}
			// The static and connected routes beside it change nothing.
			got := impacts(s)
			if _, ok := got["10.40.0.1"]; ok {
				t.Errorf("impacts = %v, want 10.40.0.1, which r1 forwards by a static route, unchanged", got)
			}
			if _, ok := got["10.0.14.2"]; ok {
				t.Errorf("impacts = %v, want 10.0.14.2, which r1 reaches by a connected route, unchanged", got)
			}
			if s.Considered != 8 || s.Unchanged+len(s.Affected) != s.Considered {
				t.Errorf("considered %d, unchanged %d, affected %d, want 8 considered and the rest adding up", s.Considered, s.Unchanged, len(s.Affected))
			}
			if fail.OSPFNeighbor != "" {
				// The adjacency loss keeps its own reason and its unknown leaf.
				if strings.Contains(a.Reason, offTheWalk) {
					t.Errorf("adjacency loss reason = %q, want the one it gave before", a.Reason)
				}
				return
			}
			if want := bgpReason(offTheWalk, "r1", "fib:r1:default (bgp)"); a.Reason != want {
				t.Errorf("reason = %q, want %q", a.Reason, want)
			}
			// The walk is the recorded one, every decision with its rows.
			h := a.After
			if h == nil || h.Decision.Kind != KindForward || h.Decision.Evidence[0].Origin != netmodel.OriginBGP ||
				len(h.Next) != 1 || h.Next[0].Node != "r4" || len(h.Next[0].Next) != 1 || h.Next[0].Next[0].Decision.Kind != KindLocal {
				t.Errorf("after = %+v, want r1 and r4 forwarding by BGP to r3", h)
			}
		})
	}
	// An address on the down interface keeps its own reason.
	s := simulate(t, obs, Failure{Node: "r1", Interface: "eth9"})
	if after, _ := json.Marshal(affected(t, s, "10.0.19.1").After); !strings.Contains(string(after), "depends on its platform") {
		t.Errorf("10.0.19.1 walk does not say why it is unknown:\n%s", after)
	}
	// Losing the only router that holds a destination stays a loss whatever
	// forwards toward it.
	if got := impacts(simulate(t, obs, Failure{Node: "r3"})); got[dest] != ImpactReachabilityLost {
		t.Errorf("impacts with r3 failed = %v, want %s reachability_lost", got, dest)
	}
}

func TestBGPAnywhereOnTheWalkIsUnknown(t *testing.T) {
	cases := []struct {
		name, at1, at4 string
		node           string
	}{
		{"at the source", netmodel.OriginBGP, netmodel.OriginStatic, "r1"},
		{"further on", netmodel.OriginStatic, netmodel.OriginBGP, "r4"},
		{"behind an OSPF route", netmodel.OriginOSPF, netmodel.OriginBGP, "r4"},
		{"static throughout", netmodel.OriginStatic, "kernel", ""},
		{"OSPF throughout", netmodel.OriginOSPF, netmodel.OriginOSPF, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, offPath(c.at1, c.at4), Failure{Node: "rr"})
			if c.node == "" {
				if got := impacts(s); len(got) != 0 {
					t.Errorf("impacts = %v, want none: a failure off the walk leaves no protocol route a path through it", got)
				}
				return
			}
			want := bgpReason(offTheWalk, c.node, "fib:"+c.node+":default (bgp)")
			if a := affected(t, s, dest); a.Impact != ImpactUnknown || a.Reason != want {
				t.Errorf("%s %s: %q, want unknown: %q", dest, a.Impact, a.Reason, want)
			}
		})
	}
}

func TestBGPRowsOffTheSelectedRouteChangeNothing(t *testing.T) {
	// Each file adds BGP evidence that does not forward 10.20.40.8 from r1,
	// whose walk is static throughout.
	r1 := func(routes ...netmodel.Route) []netmodel.Observation {
		obs := without(offPath(netmodel.OriginStatic, netmodel.OriginStatic), "fib:r1:default")
		return append(obs, table(netmodel.PlaneFIB, "r1", "default", true, append([]netmodel.Route{
			route("10.0.14.0/30", netmodel.OriginConnected, onLink("eth0")),
			route("10.20.0.0/16", netmodel.OriginStatic, nh("10.0.14.2", "eth0")),
			route("10.40.0.0/24", netmodel.OriginStatic, nh("10.0.14.2", "eth0"))}, routes...)...))
	}
	cases := map[string][]netmodel.Observation{
		"on a node off the walk": append(offPath(netmodel.OriginStatic, netmodel.OriginStatic),
			table(netmodel.PlaneFIB, "rr", "default", true, route("10.20.0.0/16", netmodel.OriginBGP, nh("10.0.19.1", "eth0")))),
		"in another routing domain": append(offPath(netmodel.OriginStatic, netmodel.OriginStatic),
			configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.92.1/30")}),
			table(netmodel.PlaneFIB, "r1", "blue", true, route("10.20.0.0/16", netmodel.OriginBGP, nh("10.0.92.2", "eth3")))),
		"for another prefix":           r1(route("10.99.0.0/16", netmodel.OriginBGP, nh("10.0.14.2", "eth0"))),
		"shadowed by the static route": r1(route("10.0.0.0/8", netmodel.OriginBGP, nh("10.0.14.2", "eth0"))),
		"only on the control plane": append(offPath(netmodel.OriginStatic, netmodel.OriginStatic),
			table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", netmodel.OriginBGP, nh("10.0.14.2", "eth0")))),
	}
	for name, obs := range cases {
		t.Run(name, func(t *testing.T) {
			for _, fail := range []Failure{{Node: "rr"}, {Node: "r1", Interface: "eth9"}} {
				if got, ok := impacts(simulate(t, obs, fail))[dest]; ok {
					t.Errorf("%s: %s %s, want unchanged", fail, dest, got)
				}
			}
		})
	}
}

// diamondBy is the diamond with the FIB routes of r1, r2, and r4 of origins
// at1, at2, and at4.
func diamondBy(at1, at2, at4 string) []netmodel.Observation {
	obs := diamond()
	for i, at := range map[string]string{"fib:r1:default": at1, "fib:r2:default": at2, "fib:r4:default": at4} {
		withOrigin(obs[slices.IndexFunc(obs, func(o netmodel.Observation) bool { return o.Source == i }):][:1], at)
	}
	return obs
}

func TestBGPECMPRedundancyIsUnknown(t *testing.T) {
	// r1 eth1 is down, so r1 stops selecting its leg through r2, and the leg
	// through r4 still delivers. Where a BGP route forwards on that surviving
	// branch, its session may run over eth1, and the file does not say.
	const survives = "every surviving recorded branch delivers"
	cases := []struct {
		name, at1, at2, at4 string
		impact              Impact
		reason              string
	}{
		{"BGP throughout", netmodel.OriginBGP, netmodel.OriginBGP, netmodel.OriginBGP, ImpactUnknown, bgpReason(survives, "r1", "fib:r1:default (bgp)")},
		{"BGP on the surviving branch", netmodel.OriginOSPF, netmodel.OriginOSPF, netmodel.OriginBGP, ImpactUnknown, bgpReason(survives, "r4", "fib:r4:default (bgp)")},
		// Only the cut branch forwards by BGP, and nothing the failure leaves
		// in place depends on it.
		{"BGP only on the cut branch", netmodel.OriginOSPF, netmodel.OriginBGP, netmodel.OriginOSPF, ImpactRedundancyLost, ""},
		{"OSPF throughout", netmodel.OriginOSPF, netmodel.OriginOSPF, netmodel.OriginOSPF, ImpactRedundancyLost, ""},
		{"static throughout", netmodel.OriginStatic, netmodel.OriginStatic, netmodel.OriginStatic, ImpactRedundancyLost, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, diamondBy(c.at1, c.at2, c.at4), Failure{Node: "r1", Interface: "eth1"})
			a := affected(t, s, dest)
			if a.Impact != c.impact || (c.reason != "" && a.Reason != c.reason) {
				t.Fatalf("%s %s: %q, want %s: %q", dest, a.Impact, a.Reason, c.impact, c.reason)
			}
			// The walk still shows the cut leg and the surviving branch.
			if h := a.After; h == nil || len(h.Next) != 2 || h.Next[0].Decision.Kind != KindFailed || h.Next[1].Node != "r4" {
				t.Errorf("after = %+v, want r1 with its eth1 leg failed and its r4 leg kept", h)
			}
		})
	}
}

func TestBGPUncertaintyLeavesNextHopLossAlone(t *testing.T) {
	// A next-hop loss removes the recorded FIB leg whatever installed it.
	s := simulate(t, diamondBy(netmodel.OriginBGP, netmodel.OriginBGP, netmodel.OriginBGP), Failure{Node: "r1", NextHop: "10.0.12.2"})
	if a := affected(t, s, dest); a.Impact != ImpactUnknown || !strings.Contains(a.Reason, "still lists the lost next hop") {
		t.Errorf("%s %s: %q, want unknown for the kept leg", dest, a.Impact, a.Reason)
	}
	s = simulate(t, offPath(netmodel.OriginBGP, netmodel.OriginBGP), Failure{Node: "r1", NextHop: "10.0.14.2"})
	if got := impacts(s); got[dest] != ImpactReachabilityLost {
		t.Errorf("impacts = %v, want %s reachability_lost", got, dest)
	}
}

func TestBGPUncertaintyTextAndJSONAgree(t *testing.T) {
	// Two FIB rows of r1 agree on the BGP route, so both are named, in a fixed
	// order whatever order the file gives.
	obs := append(offPath(netmodel.OriginBGP, netmodel.OriginStatic),
		tableFrom("frr:r1:fib", netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", netmodel.OriginBGP, nh("10.0.14.2", "eth0"))))
	s := simulate(t, obs, Failure{Node: "rr"})
	reason := bgpReason(offTheWalk, "r1", "fib:r1:default (bgp), frr:r1:fib (bgp)")
	if got := affected(t, s, dest).Reason; got != reason {
		t.Fatalf("reason = %q, want %q", got, reason)
	}
	text := s.Text()
	for _, want := range []string{
		fmt.Sprintf("%d destinations considered, %d unchanged.", s.Considered, s.Unchanged),
		"unknown 10.20.40.8 (r3 default): " + reason,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	data, _ := json.Marshal(s)
	var got struct {
		Considered, Unchanged int
		Affected              []Affected
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Considered != s.Considered || got.Unchanged != s.Unchanged || got.Considered != got.Unchanged+len(got.Affected) {
		t.Errorf("JSON counts %d considered, %d unchanged, %d affected, want %d, %d, and the rest adding up", got.Considered, got.Unchanged, len(got.Affected), s.Considered, s.Unchanged)
	}
	for range 2 {
		slices.Reverse(obs)
		for range obs {
			obs = append(obs[1:], obs[0])
			if again, _ := json.Marshal(simulate(t, obs, Failure{Node: "rr"})); string(again) != string(data) {
				t.Fatalf("output depends on input order:\n%s\n%s", again, data)
			}
		}
	}
}
