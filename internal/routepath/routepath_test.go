package routepath

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

var t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

func ifc(name string, addrs ...string) netmodel.Interface {
	i := netmodel.Interface{Name: name}
	for _, a := range addrs {
		i.Addresses = append(i.Addresses, pfx(a))
	}
	return i
}

func nh(a, iface string) netmodel.NextHop  { return netmodel.NextHop{Addr: addr(a), Interface: iface} }
func onLink(iface string) netmodel.NextHop { return netmodel.NextHop{Interface: iface} }

func route(prefix, origin string, hops ...netmodel.NextHop) netmodel.Route {
	return netmodel.Route{Prefix: pfx(prefix), Origin: origin, NextHops: hops}
}

// configured is one node's interfaces and neighbors in its configured plane.
func configured(node, vrf string, ifaces []netmodel.Interface, neighbors ...netmodel.Neighbor) netmodel.Observation {
	return netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "config:" + node + ":" + vrf, CollectedAt: t0},
		Plane:      netmodel.PlaneConfigured,
		Node:       node,
		VRF:        vrf,
		Interfaces: ifaces,
		Neighbors:  neighbors,
	}
}

// table is one node's routes in one plane. Its source name is fixed by plane,
// node, and VRF, so a test can drop it by name and put a replacement in its place.
func table(plane netmodel.Plane, node, vrf string, complete bool, routes ...netmodel.Route) netmodel.Observation {
	return tableFrom(string(plane)+":"+node+":"+vrf, plane, node, vrf, complete, routes...)
}

func tableFrom(source string, plane netmodel.Plane, node, vrf string, complete bool, routes ...netmodel.Route) netmodel.Observation {
	return netmodel.Observation{
		Provenance:     netmodel.Provenance{Source: source, CollectedAt: t0},
		Plane:          plane,
		Node:           node,
		VRF:            vrf,
		RoutesComplete: complete,
		Routes:         routes,
	}
}

func without(obs []netmodel.Observation, sources ...string) []netmodel.Observation {
	var out []netmodel.Observation
	for _, o := range obs {
		if !slices.Contains(sources, o.Source) {
			out = append(out, o)
		}
	}
	return out
}

// threeRouters is r1 -- r2 -- r3 in the default domain. Traffic to 10.20.40.8,
// which is an address on r3, should leave r1 for r2 and then r3.
func threeRouters() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.1.1/24"), ifc("eth1", "10.0.12.1/30")},
			netmodel.Neighbor{LocalInterface: "eth1", RemoteNode: "r2", RemoteInterface: "eth0", RemoteAddr: addr("10.0.12.2")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.23.2/30")},
			netmodel.Neighbor{LocalInterface: "eth0", RemoteNode: "r1", RemoteInterface: "eth1", RemoteAddr: addr("10.0.12.1")},
			netmodel.Neighbor{LocalInterface: "eth1", RemoteNode: "r3", RemoteInterface: "eth0", RemoteAddr: addr("10.0.23.3")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.23.3/30"), ifc("eth1", "10.20.40.8/24")},
			netmodel.Neighbor{LocalInterface: "eth0", RemoteNode: "r2", RemoteInterface: "eth1", RemoteAddr: addr("10.0.23.2")}),
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneControl, "r2", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.23.3", "eth1"))),
		table(netmodel.PlaneControl, "r3", "default", true, route("10.20.40.0/24", "connected", onLink("eth1"))),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneFIB, "r2", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.23.3", "eth1"))),
		table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.40.0/24", "kernel", onLink("eth1"))),
	}
}

var (
	fromR1 = Start{Node: "r1", VRF: "default"}
	dest   = "10.20.40.8"
)

func explainFrom(t *testing.T, obs []netmodel.Observation, checks []Check, src Start, destination string) Explanation {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return Explain(File{Source: src, Model: m, Checks: checks}, addr(destination))
}

func check(node, vrf, iface, destination string, result CheckResult) Check {
	return Check{
		Provenance:  netmodel.Provenance{Source: "recorded-probe", CollectedAt: t0},
		Node:        node,
		VRF:         vrf,
		Interface:   iface,
		Destination: addr(destination),
		Result:      result,
	}
}

// spine follows the first next hop from h. It is the only branch in a
// topology with no ECMP.
func spine(h Hop) []Hop {
	out := []Hop{h}
	for len(h.Next) > 0 {
		h = h.Next[0]
		out = append(out, h)
	}
	return out
}

func nodesIn(h Hop) []string {
	names := []string{h.Node}
	for _, c := range h.Next {
		names = append(names, nodesIn(c)...)
	}
	return names
}

func findings(e Explanation, kind FindingKind) []Finding {
	var out []Finding
	for _, f := range e.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestThreeRouterPathPredictsEveryHop(t *testing.T) {
	e := explainFrom(t, threeRouters(), nil, fromR1, dest)

	fwd := spine(e.Forwarding)
	if got := nodesOf(fwd); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("forwarding path = %v, want [r1 r2 r3]", got)
	}
	if fwd[2].Decision.Kind != KindLocal {
		t.Errorf("r3 kind = %s, want local: the destination is r3's own address", fwd[2].Decision.Kind)
	}
	r1 := fwd[0].Decision
	if r1.Kind != KindForward || r1.Basis != netmodel.PlaneFIB || r1.Prefix != "10.20.0.0/16" || !r1.Proven {
		t.Errorf("r1 decision = %+v, want proven FIB forward on 10.20.0.0/16", r1)
	}
	if len(r1.Evidence) != 1 || r1.Evidence[0].Source != "fib:r1:default" || r1.Evidence[0].Origin != "kernel" {
		t.Errorf("r1 evidence = %+v, want the kernel FIB row by source", r1.Evidence)
	}
	if r1.Agreement != AgreementAgrees {
		t.Errorf("r1 agreement = %s, want agrees: control and FIB name the same hop", r1.Agreement)
	}
	if via := fwd[1].Via; via == nil || via.From != "r1" || via.Interface != "eth1" || via.NextHop != "10.0.12.2" {
		t.Errorf("segment into r2 = %+v, want r1 eth1 via 10.0.12.2", via)
	}
	if got := nodesOf(spine(e.Expected)); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Errorf("expected path = %v, want [r1 r2 r3]", got)
	}
	if len(e.Findings) != 0 || len(e.Regions) != 0 || e.Truncated {
		t.Errorf("healthy path reported findings %+v, regions %+v, truncated %v", e.Findings, e.Regions, e.Truncated)
	}
}

func nodesOf(hops []Hop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.Node
	}
	return out
}

func TestMissingNodeGivesPartialPathWithoutContinuation(t *testing.T) {
	obs := without(threeRouters(), "config:r2:default")
	e := explainFrom(t, obs, nil, fromR1, dest)

	fwd := spine(e.Forwarding)
	if len(fwd) != 2 {
		t.Fatalf("forwarding path = %v, want r1 then one unresolved leaf", nodesOf(fwd))
	}
	leaf := fwd[1]
	if leaf.Decision.Kind != KindUnresolved || leaf.Node != "" || len(leaf.Next) != 0 {
		t.Errorf("leaf = %+v, want unresolved with no node and no continuation", leaf)
	}
	if !strings.Contains(leaf.Decision.Reason, "10.0.12.2") || !strings.Contains(leaf.Decision.Reason, "r2") {
		t.Errorf("reason = %q, want it to name the address and the neighbor that reports it", leaf.Decision.Reason)
	}
	if slices.Contains(nodesIn(e.Forwarding), "r3") {
		t.Errorf("tree reaches r3 without a modeled hop to it: %v", nodesIn(e.Forwarding))
	}
	if !slices.ContainsFunc(e.Limitations, func(s string) bool { return strings.Contains(s, "10.0.12.2") }) {
		t.Errorf("limitations = %q, want the unresolved hop named", e.Limitations)
	}
}

func TestControlRouteMissingFromFIBIsNotForwardingFailure(t *testing.T) {
	obs := without(threeRouters(), "fib:r2:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r2", "default", true))
	e := explainFrom(t, obs, nil, fromR1, dest)

	fwd := spine(e.Forwarding)
	if last := fwd[len(fwd)-1]; last.Node != "r2" || last.Decision.Kind != KindNoRoute || !last.Decision.Proven {
		t.Fatalf("forwarding ends at %s %s proven=%v, want r2 no_route proven", last.Node, last.Decision.Kind, last.Decision.Proven)
	}
	if got := findings(e, FindingControlNotInFIB); len(got) != 1 || got[0].Node != "r2" {
		t.Errorf("control_route_not_in_fib findings = %+v, want one at r2", got)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 0 {
		t.Errorf("a route missing from the FIB was reported as forwarding failure: %+v", got)
	}
	if exp := spine(e.Expected); nodesOf(exp)[len(exp)-1] != "r3" {
		t.Errorf("expected path = %v, want it to continue to r3 through control state", nodesOf(exp))
	}
}

func TestInstalledFIBRouteWhoseTrafficFailsIsNamedBySegment(t *testing.T) {
	checks := []Check{
		check("r1", "default", "eth1", dest, CheckPass),
		check("r2", "default", "eth1", dest, CheckFail),
	}
	e := explainFrom(t, threeRouters(), checks, fromR1, dest)

	fwd := spine(e.Forwarding)
	if fwd[1].Decision.Kind != KindForward || fwd[1].Decision.Prefix != "10.20.0.0/16" {
		t.Errorf("r2 decision = %+v, want the FIB route still installed", fwd[1].Decision)
	}
	if fwd[1].Via.Outcome != OutcomePass {
		t.Errorf("r1 to r2 outcome = %s, want pass", fwd[1].Via.Outcome)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 1 || got[0].Node != "r2" {
		t.Fatalf("fib_forwarding_failed = %+v, want one at r2", got)
	}
	if got := findings(e, FindingControlNotInFIB); len(got) != 0 {
		t.Errorf("an installed route was reported as missing from the FIB: %+v", got)
	}
	if len(e.Regions) != 1 {
		t.Fatalf("regions = %+v, want one", e.Regions)
	}
	region := e.Regions[0]
	if region.Fail.From != "r2" || region.Fail.Interface != "eth1" || region.Fail.Outcome != OutcomeFail {
		t.Errorf("failed segment = %+v, want r2 eth1 fail", region.Fail)
	}
	if len(region.Candidates) != 1 || region.Candidates[0].From != "r2" {
		t.Errorf("candidates = %+v, want only the segment after the last pass", region.Candidates)
	}
	for _, f := range e.Findings {
		if strings.Contains(f.Detail, "r3 failed") {
			t.Errorf("finding named a hop as failing: %+v", f)
		}
	}
}

func TestUnrecordedSegmentIsUnknownNotFailed(t *testing.T) {
	e := explainFrom(t, threeRouters(), nil, fromR1, dest)
	if len(spine(e.Forwarding)) != 3 {
		t.Fatalf("forwarding path = %v, want three hops to check", nodesOf(spine(e.Forwarding)))
	}
	for _, h := range spine(e.Forwarding)[1:] {
		if h.Via.Outcome != OutcomeNone {
			t.Errorf("segment into %s outcome = %s, want none when nothing was recorded", h.Node, h.Via.Outcome)
		}
	}
	if len(e.Regions) != 0 || len(findings(e, FindingForwardingFailed)) != 0 {
		t.Errorf("silence was read as failure: regions %+v findings %+v", e.Regions, e.Findings)
	}
}

func TestECMPKeepsEveryAlternativeWithoutChoosing(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"), nh("10.0.13.2", "eth2"))))
	e := explainFrom(t, obs, nil, fromR1, dest)

	r1 := e.Forwarding
	if r1.Decision.Kind != KindForward || len(r1.Decision.NextHops) != 2 || !r1.Decision.Proven {
		t.Fatalf("r1 decision = %+v, want a proven forward with two next hops", r1.Decision)
	}
	if len(r1.Next) != 2 {
		t.Fatalf("r1 has %d children, want one per alternative", len(r1.Next))
	}
	var reachedR3 bool
	for _, c := range r1.Next {
		if c.Node == "r2" {
			reachedR3 = len(c.Next) == 1 && c.Next[0].Node == "r3"
		}
	}
	if !reachedR3 {
		t.Errorf("the r2 alternative did not continue to r3: %+v", r1.Next)
	}
	// The control plane names one hop and the FIB names two, so the FIB
	// disagreement is a finding, and the extra alternative is not dropped.
	if got := findings(e, FindingFIBDiffers); len(got) != 1 || got[0].Node != "r1" {
		t.Errorf("fib_differs_from_control = %+v, want one at r1", got)
	}
}

func TestVRFsSeparateRoutingDomains(t *testing.T) {
	obs := append(threeRouters(),
		configured("r1", "red", []netmodel.Interface{ifc("eth5", "10.9.0.1/30")}),
		configured("r4", "red", []netmodel.Interface{ifc("eth0", "10.9.0.2/30")}),
		table(netmodel.PlaneFIB, "r1", "red", true, route("10.20.0.0/16", "kernel", nh("10.9.0.2", "eth5"))),
	)
	red := explainFrom(t, obs, nil, Start{Node: "r1", VRF: "red"}, dest)
	redPath := spine(red.Forwarding)
	if len(redPath) < 2 || redPath[1].Node != "r4" || redPath[1].VRF != "red" {
		t.Fatalf("red domain path = %v, want r4 in red", nodesOf(redPath))
	}
	if slices.Contains(nodesIn(red.Forwarding), "r2") {
		t.Errorf("red traffic reached r2 in the default domain: %v", nodesIn(red.Forwarding))
	}

	def := explainFrom(t, obs, nil, fromR1, dest)
	if got := spine(def.Forwarding)[1]; got.Node != "r2" || got.VRF != "default" {
		t.Errorf("default domain next hop = %s/%s, want r2/default", got.Node, got.VRF)
	}
}

func TestConflictingFIBOriginsKeepBothProvenances(t *testing.T) {
	obs := append(threeRouters(),
		tableFrom("frr-fib:r1:default", netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "frr", nh("10.0.13.2", "eth2"))))
	e := explainFrom(t, obs, nil, fromR1, dest)

	r1 := e.Forwarding
	if r1.Decision.Kind != KindConflicting || len(r1.Next) != 0 {
		t.Fatalf("r1 = %+v, want conflicting with no path chosen", r1.Decision)
	}
	var sources []string
	for _, s := range r1.Decision.Evidence {
		sources = append(sources, s.Source)
	}
	slices.Sort(sources)
	if !slices.Equal(sources, []string{"fib:r1:default", "frr-fib:r1:default"}) {
		t.Errorf("evidence sources = %v, want both FIB rows kept", sources)
	}
	if len(findings(e, FindingConflict)) != 1 {
		t.Errorf("findings = %+v, want one conflicting_evidence at r1", e.Findings)
	}
}

func TestUnknownNextHopIsNeverInvented(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.20.0.0/16", "kernel", nh("10.77.0.9", "eth1"))))
	e := explainFrom(t, obs, nil, fromR1, dest)

	if len(e.Forwarding.Next) != 1 || e.Forwarding.Next[0].Decision.Kind != KindUnresolved {
		t.Fatalf("r1 children = %+v, want one unresolved leaf", e.Forwarding.Next)
	}
	if got := e.Forwarding.Next[0]; len(got.Next) != 0 || got.Node != "" {
		t.Errorf("unresolved hop continues: %+v", got)
	}
}

func TestRouteWithoutNextHopIsUnknown(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel")))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if e.Forwarding.Decision.Kind != KindUnknown || len(e.Forwarding.Next) != 0 {
		t.Errorf("r1 = %+v, want unknown with no path, since a route with no forwarding proves nothing", e.Forwarding.Decision)
	}
}

func TestDiscardRouteDropsAndDiffersFromControl(t *testing.T) {
	obs := without(threeRouters(), "fib:r2:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r2", "default", true,
		netmodel.Route{Prefix: pfx("10.20.0.0/16"), Origin: "kernel", Discard: true}))
	e := explainFrom(t, obs, nil, fromR1, dest)

	if last := spine(e.Forwarding); last[len(last)-1].Decision.Kind != KindDiscard {
		t.Errorf("forwarding ends %s, want discard at r2", last[len(last)-1].Decision.Kind)
	}
	if got := findings(e, FindingFIBDiffers); len(got) != 1 || got[0].Node != "r2" {
		t.Errorf("fib_differs_from_control = %+v, want one at r2", got)
	}
}

func TestPartialFIBDoesNotProveAbsence(t *testing.T) {
	obs := without(threeRouters(), "fib:r2:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r2", "default", false))
	e := explainFrom(t, obs, nil, fromR1, dest)

	fwd := spine(e.Forwarding)
	if last := fwd[len(fwd)-1]; last.Node != "r2" || last.Decision.Kind != KindUnknown || last.Decision.Proven {
		t.Errorf("r2 = %+v, want unknown and unproven: a partial table can omit the route", last.Decision)
	}
	if len(findings(e, FindingControlNotInFIB)) != 0 {
		t.Errorf("absence was claimed from a partial table: %+v", e.Findings)
	}
}

func TestUnprovenFIBRouteStopsForwardingButExpectedContinues(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", false, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"))))
	e := explainFrom(t, obs, nil, fromR1, dest)

	if e.Forwarding.Decision.Kind != KindUnknown || e.Forwarding.Decision.Prefix != "10.20.0.0/16" || e.Forwarding.Decision.Proven || len(e.Forwarding.Next) != 0 {
		t.Errorf("forwarding r1 = %+v, want unknown on the candidate prefix, unproven, no path", e.Forwarding.Decision)
	}
	if got := nodesOf(spine(e.Expected)); got[len(got)-1] != "r3" {
		t.Errorf("expected path = %v, want it to reach r3 through the control plane", got)
	}
}

func TestSourceWithoutEvidenceIsUnknownNotAbsent(t *testing.T) {
	e := explainFrom(t, threeRouters(), nil, Start{Node: "nowhere", VRF: "default"}, dest)
	if e.Forwarding.Decision.Kind != KindUnknown || e.Expected.Decision.Kind != KindUnknown {
		t.Errorf("forwarding %s, expected %s; a node the model never saw must be unknown", e.Forwarding.Decision.Kind, e.Expected.Decision.Kind)
	}
}

func TestOnLinkDestinationWithoutOwnerStopsAtEndpoint(t *testing.T) {
	obs := without(threeRouters(), "fib:r3:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r3", "default", true, route("10.20.0.0/16", "kernel", onLink("eth1"))))
	e := explainFrom(t, obs, nil, fromR1, "10.20.40.99")

	fwd := spine(e.Forwarding)
	last := fwd[len(fwd)-1]
	if last.Node != "" || last.Decision.Kind != KindOnLink || len(last.Next) != 0 {
		t.Errorf("end = %+v, want an on_link leaf with no invented endpoint", last)
	}
	if !slices.ContainsFunc(e.Limitations, func(s string) bool { return strings.Contains(s, "on-link") }) {
		t.Errorf("limitations = %q, want the unmodeled endpoint named", e.Limitations)
	}
}

func TestLoopTerminatesAndIsReported(t *testing.T) {
	obs := without(threeRouters(), "fib:r2:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r2", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.1", "eth0"))))
	e := explainFrom(t, obs, nil, fromR1, dest)

	fwd := spine(e.Forwarding)
	if got := nodesOf(fwd); !slices.Equal(got, []string{"r1", "r2", "r1"}) {
		t.Fatalf("forwarding path = %v, want r1 r2 r1", got)
	}
	if fwd[2].Decision.Kind != KindLoop {
		t.Errorf("return to r1 kind = %s, want loop", fwd[2].Decision.Kind)
	}
	if len(findings(e, FindingLoop)) != 1 {
		t.Errorf("findings = %+v, want one loop finding", e.Findings)
	}
}

func TestWalkIsBoundedOnLongChains(t *testing.T) {
	const n = 40
	var obs []netmodel.Observation
	for i := 0; i < n; i++ {
		node := "n" + strconv.Itoa(i)
		ifaces := []netmodel.Interface{ifc("in", "10.50."+strconv.Itoa(i)+".1/24")}
		var routes []netmodel.Route
		if i < n-1 {
			routes = append(routes, route("10.99.0.0/16", "kernel", nh("10.50."+strconv.Itoa(i+1)+".1", "out")))
		} else {
			ifaces = append(ifaces, ifc("lo", "10.99.0.1/32"))
		}
		obs = append(obs, configured(node, "default", ifaces), table(netmodel.PlaneFIB, node, "default", true, routes...))
	}
	e := explainFrom(t, obs, nil, Start{Node: "n0", VRF: "default"}, "10.99.0.1")

	if !e.Truncated {
		t.Fatalf("a %d-router chain was not truncated", n)
	}
	if depth := len(spine(e.Forwarding)); depth == 0 || depth > maxDepth+1 {
		t.Errorf("walk depth = %d, want at most %d", depth, maxDepth+1)
	}
}

func TestExplanationIsDeterministicAcrossInputOrder(t *testing.T) {
	forward := threeRouters()
	reversed := make([]netmodel.Observation, len(forward))
	for i := range forward {
		reversed[len(forward)-1-i] = forward[i]
	}
	checks := []Check{check("r1", "default", "eth1", dest, CheckPass), check("r2", "default", "eth1", dest, CheckFail)}

	a := explainFrom(t, forward, checks, fromR1, dest)
	b := explainFrom(t, reversed, checks, fromR1, dest)
	if a.Text() == "" {
		t.Fatal("human output is empty")
	}
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
	if again, _ := a.JSON(); string(again) != string(ja) {
		t.Errorf("JSON output changed between two encodings of one explanation")
	}
}

// A planned or observed address is not evidence that a node owns it, so it must
// not turn a forwarding decision into local delivery.
func TestIntendedAndObservedAddressesOwnNothing(t *testing.T) {
	obs := append(threeRouters(),
		netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "intent:r1", CollectedAt: t0},
			Plane:      netmodel.PlaneIntended,
			Node:       "r1",
			VRF:        "default",
			Interfaces: []netmodel.Interface{ifc("lo", "10.20.40.8/32")},
		},
		netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "observed:r1", CollectedAt: t0},
			Plane:      netmodel.PlaneObserved,
			Node:       "r1",
			VRF:        "default",
			Interfaces: []netmodel.Interface{ifc("lo0", "10.20.40.8/32")},
		})
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := e.Forwarding.Decision.Kind; got != KindForward {
		t.Errorf("r1 forwarding = %s, want forward: intended and observed addresses must not own the destination", got)
	}
	if got := e.Expected.Decision.Kind; got == KindLocal {
		t.Errorf("r1 expected = %s, want anything but local", got)
	}
}

// A planned neighbor is not evidence of a node either, so it must not explain
// an unresolved next hop.
func TestIntendedNeighborNamesNoNextHop(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs,
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.77.0.9", "eth1"))),
		netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "intent:r1", CollectedAt: t0},
			Plane:      netmodel.PlaneIntended,
			Node:       "r1",
			VRF:        "default",
			Neighbors:  []netmodel.Neighbor{{LocalInterface: "eth1", RemoteNode: "r9", RemoteAddr: addr("10.77.0.9")}},
		})
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := e.Forwarding.Next[0].Decision.Reason; strings.Contains(got, "r9") {
		t.Errorf("unresolved reason = %q, want no claim from the intended neighbor", got)
	}
}

// A partial control table may hide a more specific route, so a complete FIB
// that differs from it cannot be called a disagreement.
func TestPartialControlTableCannotContradictCompleteFIB(t *testing.T) {
	obs := without(threeRouters(), "control:r1:default", "fib:r1:default")
	obs = append(obs,
		table(netmodel.PlaneControl, "r1", "default", false, route("10.20.0.0/16", "ospf", nh("10.0.12.2", "eth1"))),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1")),
			route("10.20.40.0/24", "kernel", nh("10.0.13.2", "eth2"))))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := findings(e, FindingFIBDiffers); len(got) != 0 {
		t.Errorf("fib_differs_from_control = %+v, want none: a partial control table cannot show a difference", got)
	}
	if got := e.Forwarding.Decision.Agreement; got != AgreementUnknown {
		t.Errorf("r1 agreement = %q, want unknown rather than agrees or disagrees", got)
	}
}

// A recorded check applies to the alternative it names. Without a name, it
// applies to an interface only when that interface carries one next hop.
func TestSharedInterfaceCheckNamesItsNextHopOrNone(t *testing.T) {
	ecmp := func() []netmodel.Observation {
		obs := without(threeRouters(), "fib:r1:default")
		return append(obs, table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"), nh("10.0.12.9", "eth1"))))
	}
	t.Run("named next hop", func(t *testing.T) {
		c := check("r1", "default", "eth1", dest, CheckFail)
		c.NextHop = addr("10.0.12.2")
		e := explainFrom(t, ecmp(), []Check{c}, fromR1, dest)
		outcome := map[string]Outcome{}
		for _, s := range e.Forwarding.Next {
			outcome[s.Via.NextHop] = s.Via.Outcome
		}
		if outcome["10.0.12.2"] != OutcomeFail || outcome["10.0.12.9"] != OutcomeNone {
			t.Errorf("segment outcomes = %v, want the named alternative failed and the other unrecorded", outcome)
		}
		if got := findings(e, FindingForwardingFailed); len(got) != 1 {
			t.Errorf("fib_forwarding_failed = %+v, want one", got)
		}
	})
	t.Run("unnamed check on a shared interface", func(t *testing.T) {
		e := explainFrom(t, ecmp(), []Check{check("r1", "default", "eth1", dest, CheckFail)}, fromR1, dest)
		for _, s := range e.Forwarding.Next {
			if s.Via.Outcome != OutcomeUnattributed {
				t.Errorf("segment via %s outcome = %s, want unattributed", s.Via.NextHop, s.Via.Outcome)
			}
		}
		if got := findings(e, FindingForwardingFailed); len(got) != 0 {
			t.Errorf("fib_forwarding_failed = %+v, want none: the failure cannot be placed on one alternative", got)
		}
		if !strings.Contains(strings.Join(e.Limitations, "\n"), "names no next hop") {
			t.Errorf("limitations = %v, want the unattributed check named", e.Limitations)
		}
	})
}

// A route can list thousands of next hops. The walk follows the first
// maxFanout, and the explanation says it stopped early.
func TestWideNextHopListIsBounded(t *testing.T) {
	hops := make([]netmodel.NextHop, 200)
	for i := range hops {
		hops[i] = netmodel.NextHop{Addr: netip.AddrFrom4([4]byte{10, 9, 0, byte(i + 1)}), Interface: "eth1"}
	}
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", hops...)))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if !e.Truncated {
		t.Error("a 200-way route did not mark the explanation truncated")
	}
	if got := len(e.Forwarding.Next); got != maxFanout {
		t.Errorf("r1 followed %d next hops, want the first %d", got, maxFanout)
	}
	if got := len(e.Forwarding.Decision.NextHops); got != len(hops) {
		t.Errorf("decision lists %d next hops, want all of them: %d", got, len(hops))
	}
}

// A failure must say which recorded check supports it, so it traces to a source.
func TestFailureNamesItsRecordedSource(t *testing.T) {
	c := check("r1", "default", "eth1", dest, CheckFail)
	c.Source = "probe:r1"
	e := explainFrom(t, threeRouters(), []Check{c}, fromR1, dest)
	got := findings(e, FindingForwardingFailed)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "probe:r1 at ") {
		t.Fatalf("fib_forwarding_failed = %+v, want the detail to name probe:r1 and when it ran", got)
	}
}

// A no-route decision must name the complete table that proves the absence.
func TestMissingRouteNamesItsAbsenceEvidence(t *testing.T) {
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true))
	e := explainFrom(t, obs, nil, fromR1, dest)
	d := e.Forwarding.Decision
	if d.Kind != KindNoRoute {
		t.Fatalf("r1 forwarding = %s, want no_route from the complete FIB", d.Kind)
	}
	if len(d.Evidence) != 1 || !d.Evidence[0].Absent || d.Evidence[0].Source != "fib:r1:default" {
		t.Errorf("no_route evidence = %+v, want the complete fib:r1:default table named as absent", d.Evidence)
	}
}

// Routes that agree on the first maxFanout next hops and differ after them do
// not agree. The comparison reads every next hop, not only the followed ones.
func TestRoutesDifferingPastTheFanOutCapDisagree(t *testing.T) {
	wide := func(last string) []netmodel.NextHop {
		hops := make([]netmodel.NextHop, maxFanout+1)
		for i := range maxFanout {
			hops[i] = netmodel.NextHop{Addr: netip.AddrFrom4([4]byte{10, 9, 0, byte(i + 1)}), Interface: "eth1"}
		}
		hops[maxFanout] = netmodel.NextHop{Addr: addr(last), Interface: "eth1"}
		return hops
	}
	obs := without(threeRouters(), "control:r1:default", "fib:r1:default")
	obs = append(obs,
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", wide("10.9.0.200")...)),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", wide("10.9.0.201")...)))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := findings(e, FindingFIBDiffers); len(got) != 1 {
		t.Errorf("fib_differs_from_control = %+v, want one: the routes differ at next hop %d", got, maxFanout+1)
	}
	if got := e.Forwarding.Decision.Agreement; got != AgreementDisagrees {
		t.Errorf("r1 agreement = %q, want disagrees", got)
	}
}

// An unnamed check on a shared interface cannot be placed on the hops that are
// followed. The shared count reads every next hop, so the omitted hop on eth1
// still makes the followed hop unattributed rather than failed.
func TestUnnamedCheckIsNotPlacedPastTheFanOutCap(t *testing.T) {
	hops := make([]netmodel.NextHop, maxFanout+1)
	for i := range maxFanout {
		hops[i] = netmodel.NextHop{Addr: netip.AddrFrom4([4]byte{10, 9, 0, byte(i + 1)}), Interface: "eth2"}
	}
	hops[0].Interface = "eth1"
	hops[maxFanout] = netmodel.NextHop{Addr: addr("10.9.0.200"), Interface: "eth1"}
	obs := without(threeRouters(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", hops...)))
	e := explainFrom(t, obs, []Check{check("r1", "default", "eth1", dest, CheckFail)}, fromR1, dest)
	if len(e.Forwarding.Next) != maxFanout {
		t.Fatalf("followed %d next hops, want %d", len(e.Forwarding.Next), maxFanout)
	}
	if got := e.Forwarding.Next[0].Via.Outcome; got != OutcomeUnattributed {
		t.Errorf("followed hop on eth1 outcome = %s, want unattributed: a next hop on eth1 is omitted from the walk", got)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 0 {
		t.Errorf("fib_forwarding_failed = %+v, want none", got)
	}
}

// A named pass does not hide an unnamed failure on a single-hop interface. Both
// apply to the one segment, so the recorded results conflict.
func TestNamedPassDoesNotHideAnUnnamedFailure(t *testing.T) {
	pass := check("r1", "default", "eth1", dest, CheckPass)
	pass.NextHop = addr("10.0.12.2")
	e := explainFrom(t, threeRouters(), []Check{pass, check("r1", "default", "eth1", dest, CheckFail)}, fromR1, dest)
	if got := e.Forwarding.Next[0].Via.Outcome; got != OutcomeConflicting {
		t.Errorf("segment outcome = %s, want conflicting: a pass and an unnamed fail both apply", got)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 0 {
		t.Errorf("fib_forwarding_failed = %+v, want none: the recorded checks conflict, so no failure is claimed", got)
	}
}

// Next hops are a set. netmodel sorts them when it validates a model, so the
// order a file lists them in does not change what the walks agree on.
func TestNextHopOrderDoesNotChangeAgreement(t *testing.T) {
	obs := without(threeRouters(), "control:r1:default", "fib:r1:default")
	obs = append(obs,
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.12.2", "eth1"), nh("10.0.12.9", "eth1"))),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.9", "eth1"), nh("10.0.12.2", "eth1"))))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := findings(e, FindingFIBDiffers); len(got) != 0 {
		t.Errorf("fib_differs_from_control = %+v, want none: the same next hops listed in another order", got)
	}
	if got := e.Forwarding.Decision.Agreement; got != AgreementAgrees {
		t.Errorf("r1 agreement = %q, want agrees", got)
	}
}

// hasLimitation reports whether one limitation holds every part, so a test can
// find its limitation without matching the whole wording.
func hasLimitation(e Explanation, parts ...string) bool {
	for _, l := range e.Limitations {
		matched := true
		for _, p := range parts {
			matched = matched && strings.Contains(l, p)
		}
		if matched {
			return true
		}
	}
	return false
}

// Local ownership decides the hop, as the kernel's local table does. The
// decision must still name the rows that own the address, and it must not claim
// a proof that no complete table backs.
func TestLocalDecisionNamesTheRowsThatOwnTheAddress(t *testing.T) {
	e := explainFrom(t, threeRouters(), nil, fromR1, dest)
	for _, walk := range []struct {
		name string
		h    Hop
	}{{"expected", spine(e.Expected)[2]}, {"forwarding", spine(e.Forwarding)[2]}} {
		d := walk.h.Decision
		if d.Kind != KindLocal {
			t.Fatalf("%s r3 = %+v, want local", walk.name, d)
		}
		if d.Basis != netmodel.PlaneConfigured {
			t.Errorf("%s r3 basis = %q, want configured: the address is listed in config:r3:default", walk.name, d.Basis)
		}
		if len(d.Evidence) != 1 || d.Evidence[0].Source != "config:r3:default" {
			t.Errorf("%s r3 evidence = %+v, want config:r3:default", walk.name, d.Evidence)
		}
		if d.Proven {
			t.Errorf("%s r3 proven = true: interface lists are partial, so no complete table backs ownership", walk.name)
		}
	}
}

// r3 owns the destination in its configured plane, and its complete FIB holds a
// route to the destination that contradicts that ownership. Ownership still
// decides the hop, but the FIB route must not vanish: the explanation has to
// name it as unchecked.
func TestConfiguredOwnershipKeepsAContradictingFIBRouteVisible(t *testing.T) {
	cases := []struct {
		name string
		fib  netmodel.Route
		want string
	}{
		{"discard", netmodel.Route{Prefix: pfx("10.20.40.0/24"), Origin: "kernel", Discard: true}, "discard 10.20.40.0/24"},
		{"forward to r2", netmodel.Route{Prefix: pfx("10.20.40.0/24"), Origin: "kernel", NextHops: []netmodel.NextHop{nh("10.0.23.2", "eth0")}}, "forward 10.20.40.0/24 via eth0 10.0.23.2"},
		{"local route without next hops", netmodel.Route{Prefix: pfx("10.20.40.8/32"), Origin: "local"}, "unknown: route names no next hop"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := append(without(threeRouters(), "fib:r3:default"), table(netmodel.PlaneFIB, "r3", "default", true, c.fib))
			e := explainFrom(t, obs, nil, fromR1, dest)
			if got := spine(e.Forwarding)[2].Decision.Kind; got != KindLocal {
				t.Fatalf("forwarding r3 = %v, want local: ownership decides the hop", got)
			}
			if !hasLimitation(e, "r3 (default)", "fib:r3:default", c.want) {
				t.Errorf("limitations = %q, want one naming r3, fib:r3:default, and %q, the route local ownership did not check", e.Limitations, c.want)
			}
		})
	}
}

// A FIB that agrees with ownership, or says nothing about the address, adds
// no limitation. A connected on-link route is the normal case, not a conflict.
func TestLocalOwnershipAddsNoLimitationWhenTheFIBAgreesOrIsSilent(t *testing.T) {
	cases := []struct {
		name string
		obs  []netmodel.Observation
	}{
		{"connected on-link route", threeRouters()},
		{"complete table without a route", append(without(threeRouters(), "fib:r3:default"), table(netmodel.PlaneFIB, "r3", "default", true))},
		{"partial table without a route", append(without(threeRouters(), "fib:r3:default"), table(netmodel.PlaneFIB, "r3", "default", false))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := explainFrom(t, c.obs, nil, fromR1, dest)
			if got := spine(e.Forwarding)[2].Decision.Kind; got != KindLocal {
				t.Fatalf("forwarding r3 = %v, want local", got)
			}
			if len(e.Limitations) != 0 {
				t.Errorf("limitations = %q, want none", e.Limitations)
			}
		})
	}
}

// Two equal-cost next hops reach the same owner, so the walk visits it twice.
// The contradicting FIB route is still named once.
func TestRepeatedOwnerNamesTheContradictingRouteOnce(t *testing.T) {
	obs := []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth1", "10.0.12.1/30"), ifc("eth2", "10.0.13.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.13.2/30"), ifc("lan", "10.20.40.8/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"), nh("10.0.13.2", "eth2"))),
		table(netmodel.PlaneFIB, "r2", "default", true, netmodel.Route{Prefix: pfx("10.20.40.0/24"), Origin: "kernel", Discard: true}),
	}
	e := explainFrom(t, obs, nil, fromR1, dest)
	n := 0
	for _, l := range e.Limitations {
		if strings.Contains(l, "fib:r2:default") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("limitations naming fib:r2:default = %d, want 1: %q", n, e.Limitations)
	}
}

// The control plane lists the destination on r2, while configured says r3 owns
// it. The walk stops at its first owner, so the other claim must be named, not
// dropped from both walks.
func TestConflictingOwnersAcrossPlanesAreNamed(t *testing.T) {
	owner := netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "ospf:r2:default", CollectedAt: t0},
		Plane:      netmodel.PlaneControl,
		Node:       "r2",
		VRF:        "default",
		Interfaces: []netmodel.Interface{ifc("lan", "10.20.40.8/24")},
	}
	cases := []struct {
		name, label string
		obs         []netmodel.Observation
	}{
		// Both walks reach r2, so the owner note is shared and carries no walk label.
		{"both walks reach the owner", "", append(threeRouters(), owner)},
		// Only the forwarding walk reaches r2, so the note names that walk.
		{"only the forwarding walk reaches the owner", " (forwarding walk)", append(without(threeRouters(), "control:r1:default"), owner)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := explainFrom(t, c.obs, nil, fromR1, dest)
			if !hasLimitation(e, "r2 (default)", "ospf:r2:default", "r3 (default)", "config:r3:default") {
				t.Errorf("limitations = %q, want one naming both owners of %s and their sources", e.Limitations, dest)
			}
			if !hasLimitation(e, "both list", c.label+"") || (c.label == "" && hasLimitation(e, "both list", " walk)")) {
				t.Errorf("limitations = %q, want the owner note labelled %q", e.Limitations, c.label)
			}
		})
	}
}

// Control may report a gateway without naming the interface it leaves by, while
// the FIB names it. An omitted field is unreported, not different, so the pair
// must not be reported as fib_differs_from_control.
func TestOmittedInterfaceIsNotADisagreement(t *testing.T) {
	obs := without(threeRouters(), "control:r1:default", "fib:r1:default")
	obs = append(obs,
		table(netmodel.PlaneControl, "r1", "default", true, route("10.20.0.0/16", "ospf", nh("10.0.12.2", ""))),
		table(netmodel.PlaneFIB, "r1", "default", true, route("10.20.0.0/16", "kernel", nh("10.0.12.2", "eth1"))))
	e := explainFrom(t, obs, nil, fromR1, dest)
	if got := findings(e, FindingFIBDiffers); len(got) != 0 {
		t.Errorf("fib_differs_from_control = %+v, want none: the FIB only names the interface control omitted", got)
	}
	if got := e.Forwarding.Decision.Agreement; got != AgreementAgrees {
		t.Errorf("r1 agreement = %q, want agrees", got)
	}
}
