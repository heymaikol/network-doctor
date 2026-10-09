package routepath

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// twoPathNet is one flow from h1 (10.0.1.10) to srv (10.20.40.8). The forward
// route runs h1, r1, r2, r3, srv. The return leaves r3 toward h1 through r2 when
// returnVia is "r2", and through r4 otherwise. Every FIB table is complete.
func twoPathNet(returnVia string) []netmodel.Observation {
	back := nh("10.0.34.4", "eth2")
	if returnVia == "r2" {
		back = nh("10.0.23.2", "eth0")
	}
	return []netmodel.Observation{
		configured("h1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.10/24")}),
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24"), ifc("eth1", "10.0.12.1/30"), ifc("eth2", "10.0.14.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.1/24"), ifc("eth2", "10.0.34.3/30")}),
		configured("r4", "default", []netmodel.Interface{ifc("eth0", "10.0.34.4/30"), ifc("eth1", "10.0.14.2/30")}),
		configured("srv", "default", []netmodel.Interface{ifc("eth0", "10.20.40.8/24")}),
		table(netmodel.PlaneFIB, "h1", "default", true, route("0.0.0.0/0", "kernel", nh("10.0.1.1", "eth0"))),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")),
			route("10.0.1.0/24", "kernel", onLink("eth0"))),
		table(netmodel.PlaneFIB, "r2", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1")),
			route("10.0.1.0/24", "kernel", nh("10.0.12.1", "eth0"))),
		table(netmodel.PlaneFIB, "r3", "default", true,
			route("10.20.40.0/24", "kernel", onLink("eth1")),
			route("10.0.1.0/24", "kernel", back)),
		table(netmodel.PlaneFIB, "r4", "default", true, route("10.0.1.0/24", "kernel", nh("10.0.14.1", "eth1"))),
		table(netmodel.PlaneFIB, "srv", "default", true, route("0.0.0.0/0", "kernel", nh("10.20.40.1", "eth0"))),
	}
}

// explainTwoPath explains h1 toward srv. srcAddr names the source address, and
// empty means the topology does not name one.
func explainTwoPath(t *testing.T, obs []netmodel.Observation, checks []Check, bounds []Boundary, srcAddr string) Explanation {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	f := File{Source: Start{Node: "h1", VRF: "default"}, Model: m, Checks: checks, Boundaries: bounds}
	if srcAddr != "" {
		f.SourceAddr = addr(srcAddr)
	}
	return Explain(f, addr("10.20.40.8"))
}

func boundary(node, vrf string, kind BoundaryKind) Boundary {
	return Boundary{Provenance: netmodel.Provenance{Source: "policy:" + node, CollectedAt: t0}, Node: node, VRF: vrf, Kind: kind}
}

func stepNodes(steps []Step) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Node
	}
	return out
}

func concernKinds(a *Asymmetry) []string {
	var out []string
	for _, c := range a.Concerns {
		out = append(out, c.Kind+"/"+c.Direction)
	}
	return out
}

// A proven asymmetry with no boundary, VRF change, or failure is benign. The
// human text says so, and the JSON keeps each route separate.
func TestAsymmetryWithoutPolicyEvidenceIsBenign(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, nil, "10.0.1.10")
	a := e.Asymmetry
	if a == nil {
		t.Fatal("Asymmetry = nil, want a comparison because the topology names the source address")
	}
	if a.Assessment != AssessBenign {
		t.Errorf("Assessment = %q, want %q: asymmetry alone is not a failure", a.Assessment, AssessBenign)
	}
	if len(a.Concerns) != 0 {
		t.Errorf("Concerns = %+v, want none: nothing marks the asymmetry as relevant", a.Concerns)
	}
	if got, want := stepNodes(a.ForwardRoute), []string{"h1", "r1", "r2", "r3", "srv"}; !slices.Equal(got, want) {
		t.Errorf("forward route = %v, want %v", got, want)
	}
	if got, want := stepNodes(a.ReturnRoute), []string{"srv", "r3", "r4", "r1", "h1"}; !slices.Equal(got, want) {
		t.Errorf("return route = %v, want %v", got, want)
	}
	if len(e.Findings) != 0 || len(e.Regions) != 0 {
		t.Errorf("forward findings %+v and regions %+v, want none: asymmetry must not add forward findings", e.Findings, e.Regions)
	}
	txt := e.Text()
	for _, want := range []string{"asymmetric_benign", "not a fault by itself", "return route: srv (default) eth0 via 10.20.40.1"} {
		if !strings.Contains(txt, want) {
			t.Errorf("human text lacks %q:\n%s", want, txt)
		}
	}
}

// A stateful firewall on the return route alone is the case the issue names.
// Return traffic crosses state the forward flow never created.
func TestStatefulFirewallOnReturnOnlyRaisesAConcern(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, []Boundary{boundary("r4", "default", BoundaryStatefulFirewall)}, "10.0.1.10")
	a := e.Asymmetry
	if a.Assessment != AssessRisk {
		t.Fatalf("Assessment = %q, want %q", a.Assessment, AssessRisk)
	}
	if got := concernKinds(a); !slices.Equal(got, []string{"stateful_firewall/return"}) {
		t.Fatalf("concerns = %v, want one stateful_firewall on the return route", got)
	}
	c := a.Concerns[0]
	if c.Node != "r4" || len(c.Evidence) != 1 || c.Evidence[0].Source != "policy:r4" {
		t.Errorf("concern = %+v, want the firewall at r4 with its policy source as evidence", c)
	}
	txt := e.Text()
	for _, want := range []string{"asymmetric_risk", "concern stateful_firewall: the return route crosses stateful_firewall at r4 (default)", "state set on one path may not match traffic on the other"} {
		if !strings.Contains(txt, want) {
			t.Errorf("human text lacks %q:\n%s", want, txt)
		}
	}
}

// A NAT on the forward route alone breaks the return translation.
func TestNATOnForwardOnlyRaisesAConcern(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, []Boundary{boundary("r2", "default", BoundaryNAT)}, "10.0.1.10")
	if got := concernKinds(e.Asymmetry); !slices.Equal(got, []string{"nat/forward"}) {
		t.Fatalf("concerns = %v, want one nat on the forward route", got)
	}
	if e.Asymmetry.Assessment != AssessRisk {
		t.Errorf("Assessment = %q, want %q", e.Asymmetry.Assessment, AssessRisk)
	}
}

// A boundary that both directions cross does not separate them, so it is not a
// concern of asymmetry.
func TestBoundaryOnBothDirectionsIsNotAConcern(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, []Boundary{boundary("r1", "default", BoundaryTunnel)}, "10.0.1.10")
	if e.Asymmetry.Assessment != AssessBenign || len(e.Asymmetry.Concerns) != 0 {
		t.Errorf("assessment %q with concerns %+v, want benign with none", e.Asymmetry.Assessment, e.Asymmetry.Concerns)
	}
}

// When both directions cross the same routers, there is nothing to compare.
func TestSameRoutersBothWaysIsSymmetric(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r2"), nil, []Boundary{boundary("r4", "default", BoundaryStatefulFirewall)}, "10.0.1.10")
	a := e.Asymmetry
	if a.Assessment != AssessSymmetric || len(a.Concerns) != 0 {
		t.Errorf("assessment %q with concerns %+v, want symmetric with none", a.Assessment, a.Concerns)
	}
	if got, want := stepNodes(a.ReturnRoute), []string{"srv", "r3", "r2", "r1", "h1"}; !slices.Equal(got, want) {
		t.Errorf("return route = %v, want %v", got, want)
	}
}

// With no source address, the topology does not ask the return question, so the
// output is the same as before this comparison existed.
func TestNoSourceAddressLeavesOutputUnchanged(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, []Boundary{boundary("r4", "default", BoundaryStatefulFirewall)}, "")
	if e.Asymmetry != nil {
		t.Fatalf("Asymmetry = %+v, want nil without a source address", e.Asymmetry)
	}
	data, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(string(data), `"asymmetry"`) {
		t.Errorf("JSON carries an asymmetry key without a source address:\n%s", data)
	}
}

// A recorded failure on the return segment is a concern of the return direction.
// It is not a forward finding, and the forward walk is unchanged.
func TestRecordedReturnFailureIsAConcernOfTheReturnDirection(t *testing.T) {
	checks := []Check{
		check("r4", "default", "eth1", "10.0.1.10", CheckFail),
		check("r1", "default", "eth1", "10.20.40.8", CheckPass),
	}
	e := explainTwoPath(t, twoPathNet("r4"), checks, nil, "10.0.1.10")
	a := e.Asymmetry
	if got := concernKinds(a); !slices.Equal(got, []string{"recorded_failure/return"}) {
		t.Fatalf("concerns = %v, want one recorded_failure on the return route", got)
	}
	if a.Assessment != AssessRisk {
		t.Errorf("Assessment = %q, want %q", a.Assessment, AssessRisk)
	}
	if len(e.Findings) != 0 || len(e.Regions) != 0 {
		t.Errorf("forward findings %+v and regions %+v, want none: the failure is on the return route", e.Findings, e.Regions)
	}
	if len(a.Return.Regions) != 1 || len(findings(*a.Return, FindingForwardingFailed)) != 1 {
		t.Errorf("return regions %+v and findings %+v, want one failure region with its finding", a.Return.Regions, a.Return.Findings)
	}
}

// The forward and return routes are separate identities, and JSON names both.
func TestRouteIdentitiesAreIndependentInJSON(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, nil, "10.0.1.10")
	data, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var got struct {
		Asymmetry struct {
			ForwardRoute []Step      `json:"forward_route"`
			ReturnRoute  []Step      `json:"return_route"`
			Return       Explanation `json:"return"`
			ReturnTo     string      `json:"return_to"`
			Assessment   string      `json:"assessment"`
		} `json:"asymmetry"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Asymmetry.ReturnTo != "10.0.1.10" || got.Asymmetry.Assessment != string(AssessBenign) {
		t.Errorf("asymmetry = %+v, want return_to 10.0.1.10 and asymmetric_benign", got.Asymmetry)
	}
	if got, want := stepNodes(got.Asymmetry.ForwardRoute), []string{"h1", "r1", "r2", "r3", "srv"}; !slices.Equal(got, want) {
		t.Errorf("forward_route nodes = %v, want %v", got, want)
	}
	if got, want := stepNodes(got.Asymmetry.ReturnRoute), []string{"srv", "r3", "r4", "r1", "h1"}; !slices.Equal(got, want) {
		t.Errorf("return_route nodes = %v, want %v", got, want)
	}
	if got.Asymmetry.Return.Source.Node != "srv" || got.Asymmetry.Return.Destination != "10.0.1.10" {
		t.Errorf("return walk = from %s toward %s, want from srv toward 10.0.1.10", got.Asymmetry.Return.Source.Node, got.Asymmetry.Return.Destination)
	}
}

// Missing or partial evidence is unknown, never asymmetry. A direction that is
// proven keeps its route, and a direction that is not proven has none.
func TestUnprovenRouteIsUnknownNotAsymmetry(t *testing.T) {
	cases := []struct {
		name          string
		obs           func() []netmodel.Observation
		want          string
		forwardProven bool
	}{
		{
			name: "partial FIB on a return hop",
			obs: func() []netmodel.Observation {
				return append(without(twoPathNet("r4"), "fib:r4:default"), table(netmodel.PlaneFIB, "r4", "default", false, route("10.0.1.0/24", "kernel", nh("10.0.14.1", "eth1"))))
			},
			want:          "return route not proven: r4 (default): FIB for this node is partial",
			forwardProven: true,
		},
		{
			name: "return next hop no modeled node owns",
			obs: func() []netmodel.Observation {
				return append(without(twoPathNet("r4"), "config:r1:default"), configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24"), ifc("eth1", "10.0.12.1/30")}))
			},
			want:          "no modeled interface owns 10.0.14.1",
			forwardProven: true,
		},
		{
			// Forward resolution meets the same ambiguous owner set first, so the
			// forward route is the one reported unproven.
			name: "destination owned by several routing domains",
			obs: func() []netmodel.Observation {
				return append(twoPathNet("r4"), configured("r2", "tenant", []netmodel.Interface{ifc("eth5", "10.20.40.8/24")}))
			},
			want: "forward route not proven: r3 (default) eth1 on-link: 10.20.40.8 is owned by several nodes",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := explainTwoPath(t, c.obs(), nil, nil, "10.0.1.10")
			a := e.Asymmetry
			if a == nil || a.Assessment != AssessUnknown {
				t.Fatalf("Asymmetry = %+v, want unknown", a)
			}
			if !strings.Contains(a.Reason, c.want) {
				t.Errorf("reason = %q, want it to contain %q", a.Reason, c.want)
			}
			if got := len(a.ForwardRoute) > 0; got != c.forwardProven {
				t.Errorf("forward route present = %v, want %v", got, c.forwardProven)
			}
			if a.ReturnRoute != nil {
				t.Errorf("return route = %v, want none: it is not proven", stepNodes(a.ReturnRoute))
			}
		})
	}
}

// A routing domain can carry the return in a VRF the forward never enters. That
// is a routing-domain change, so it is a concern on both directions.
func TestReturnThroughAnotherVRFIsAConcern(t *testing.T) {
	obs := without(twoPathNet("r4"), "config:r4:default", "fib:r4:default")
	obs = append(obs,
		configured("r4", "tenant", []netmodel.Interface{ifc("eth0", "10.0.34.4/30"), ifc("eth1", "10.0.14.2/30")}),
		table(netmodel.PlaneFIB, "r4", "tenant", true, route("10.0.1.0/24", "kernel", nh("10.0.14.1", "eth1"))),
	)
	e := explainTwoPath(t, obs, nil, nil, "10.0.1.10")
	if got := concernKinds(e.Asymmetry); !slices.Equal(got, []string{"vrf_crossing/both"}) {
		t.Fatalf("concerns = %v, want one vrf_crossing", got)
	}
	if !strings.Contains(e.Asymmetry.Concerns[0].Detail, "return route uses default, tenant") {
		t.Errorf("detail = %q, want the return's routing domains", e.Asymmetry.Concerns[0].Detail)
	}
}

// The decoder keeps the source address and the boundaries with their provenance.
func TestDecodeReadsSourceAddressAndBoundaries(t *testing.T) {
	data := strings.Replace(threeRoutersFile, `"node": "r1", "vrf": "default"},`, `"node": "r1", "vrf": "default", "address": "10.0.12.1"},`, 1)
	data = strings.Replace(data, `"checks": [`, `"boundaries": [{"source": "policy:r2", "collected_at": "2026-10-09T12:00:00Z", "node": "r2", "vrf": "default", "kind": "stateful_firewall"}], "checks": [`, 1)
	f, err := Decode([]byte(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if f.SourceAddr != addr("10.0.12.1") {
		t.Errorf("SourceAddr = %v, want 10.0.12.1", f.SourceAddr)
	}
	if len(f.Boundaries) != 1 || f.Boundaries[0].Kind != BoundaryStatefulFirewall || f.Boundaries[0].Source != "policy:r2" {
		t.Errorf("boundaries = %+v, want one stateful firewall with its source", f.Boundaries)
	}
}

// A return that ends at a node other than the source is not this flow's return,
// even when every hop is proven. The source address on r2 means the reply stops
// at r2. The source address on srv means the reply never leaves srv.
func TestReturnThatMissesTheSourceIsUnknown(t *testing.T) {
	cases := []struct {
		name    string
		srcAddr string
		obs     []netmodel.Observation
		want    string
	}{
		{
			name:    "source address on a transit router",
			srcAddr: "10.0.12.2",
			obs: append(without(twoPathNet("r4"), "fib:r3:default"), table(netmodel.PlaneFIB, "r3", "default", true,
				route("10.20.40.0/24", "kernel", onLink("eth1")),
				route("10.0.12.0/30", "kernel", nh("10.0.23.2", "eth0")))),
			want: "the return ends at r2 (default), not at the source h1 (default)",
		},
		{
			name:    "source address owned by the destination",
			srcAddr: "10.20.40.8",
			obs:     twoPathNet("r4"),
			want:    "the return ends at srv (default), not at the source h1 (default)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := explainTwoPath(t, c.obs, nil, nil, c.srcAddr).Asymmetry
			if a == nil || a.Assessment != AssessUnknown {
				t.Fatalf("Asymmetry = %+v, want unknown", a)
			}
			if !strings.Contains(a.Reason, c.want) {
				t.Errorf("reason = %q, want it to contain %q", a.Reason, c.want)
			}
			if len(a.ForwardRoute) == 0 || a.ReturnRoute != nil {
				t.Errorf("forward route %v and return route %v, want forward kept and return withheld", stepNodes(a.ForwardRoute), stepNodes(a.ReturnRoute))
			}
		})
	}
}

// Two owners of the destination leave the return with no single start. The
// forward route still ends at a local owner, so only the return is unproven.
func TestReturnWithSeveralOwnersIsUnknown(t *testing.T) {
	obs := append(without(twoPathNet("r4"), "config:r3:default"), configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24"), ifc("eth2", "10.0.34.3/30")}))
	a := explainTwoPath(t, obs, nil, nil, "10.0.1.10").Asymmetry
	if a == nil || a.Assessment != AssessUnknown {
		t.Fatalf("Asymmetry = %+v, want unknown", a)
	}
	if !strings.Contains(a.Reason, "return route not proven: 10.20.40.8 is owned by 2 routing domains") {
		t.Errorf("reason = %q, want the return named as unproven", a.Reason)
	}
	if len(a.ForwardRoute) == 0 || a.Return != nil {
		t.Errorf("forward route %v and return %+v, want forward kept and no return walk", stepNodes(a.ForwardRoute), a.Return)
	}
}

// ECMP on the return leaves more than one path, so no single return route is
// proven.
func TestReturnEcmpIsUnknown(t *testing.T) {
	obs := append(without(twoPathNet("r4"), "fib:r3:default"), table(netmodel.PlaneFIB, "r3", "default", true,
		route("10.20.40.0/24", "kernel", onLink("eth1")),
		route("10.0.1.0/24", "kernel", nh("10.0.34.4", "eth2"), nh("10.0.23.2", "eth0"))))
	a := explainTwoPath(t, obs, nil, nil, "10.0.1.10").Asymmetry
	if a == nil || a.Assessment != AssessUnknown || a.ReturnRoute != nil {
		t.Fatalf("Asymmetry = %+v, want unknown with no return route", a)
	}
	if !strings.Contains(a.Reason, "return route not proven: ") {
		t.Errorf("reason = %q, want the return named as unproven", a.Reason)
	}
}

// A recorded failure on the forward route is a concern of the forward direction.
func TestRecordedForwardFailureIsAConcernOfTheForwardDirection(t *testing.T) {
	checks := []Check{check("r2", "default", "eth1", "10.20.40.8", CheckFail)}
	e := explainTwoPath(t, twoPathNet("r4"), checks, nil, "10.0.1.10")
	if got := concernKinds(e.Asymmetry); !slices.Equal(got, []string{"recorded_failure/forward"}) {
		t.Fatalf("concerns = %v, want one recorded_failure on the forward route", got)
	}
	if e.Asymmetry.Assessment != AssessRisk {
		t.Errorf("Assessment = %q, want %q", e.Asymmetry.Assessment, AssessRisk)
	}
}

// A boundary in another routing domain does not sit on the default-VRF routes.
func TestBoundaryInAnotherVRFIsNotAConcern(t *testing.T) {
	e := explainTwoPath(t, twoPathNet("r4"), nil, []Boundary{boundary("r4", "tenant", BoundaryNAT)}, "10.0.1.10")
	if e.Asymmetry.Assessment != AssessBenign || len(e.Asymmetry.Concerns) != 0 {
		t.Errorf("assessment %q with concerns %+v, want benign with none", e.Asymmetry.Assessment, e.Asymmetry.Concerns)
	}
}

// Boundaries that share node, routing domain, and kind still sort the same way
// in either file order, so the concern evidence does not depend on the file.
func TestBoundaryOrderIsTotal(t *testing.T) {
	a := boundary("r4", "default", BoundaryNAT)
	a.Source = "policy:a"
	b := boundary("r4", "default", BoundaryNAT)
	b.Source = "policy:b"
	for _, in := range [][]Boundary{{a, b}, {b, a}} {
		got := slices.Clone(in)
		slices.SortFunc(got, compareBoundaries)
		if got[0].Source != "policy:a" || got[1].Source != "policy:b" {
			t.Errorf("order from input %v = %q, %q; want policy:a then policy:b", in[0].Source, got[0].Source, got[1].Source)
		}
	}
}
