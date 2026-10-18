package routepath

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
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
	}{
		{"static throughout", netmodel.OriginStatic, "kernel", ImpactReachabilityLost, ""},
		{"protocol at the stranded node", netmodel.OriginStatic, netmodel.OriginOSPF, ImpactUnknown, lostReason("r2", netmodel.OriginOSPF)},
		{"protocol ahead of it", netmodel.OriginBGP, "kernel", ImpactUnknown, lostReason("r1", netmodel.OriginBGP)},
		{"both", netmodel.OriginOSPF, netmodel.OriginBGP, ImpactUnknown, lostReason("r1", netmodel.OriginOSPF)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulate(t, lineBy(c.at1, c.at2), fail)
			if got := impacts(s); !reflect.DeepEqual(got, map[string]Impact{dest: c.impact}) {
				t.Fatalf("impacts = %v, want only %s %s", got, dest, c.impact)
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
