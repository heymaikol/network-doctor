package ospf

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

var (
	t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Minute)
)

func attrs(kv ...string) []netmodel.Attribute {
	var out []netmodel.Attribute
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, netmodel.Attribute{Key: kv[i], Value: kv[i+1]})
	}
	return out
}

func nb(local, peer, peerIf string, a ...netmodel.Attribute) netmodel.Neighbor {
	return netmodel.Neighbor{LocalInterface: local, RemoteNode: peer, RemoteInterface: peerIf, Attributes: a}
}

func iface(name string, a ...netmodel.Attribute) netmodel.Interface {
	return netmodel.Interface{Name: name, Attributes: a}
}

// view is one observation of node in the default routing domain.
func view(source string, at time.Time, plane netmodel.Plane, node string, complete bool, ns []netmodel.Neighbor, is []netmodel.Interface) netmodel.Observation {
	return netmodel.Observation{
		Provenance:        netmodel.Provenance{Source: source, CollectedAt: at},
		Plane:             plane,
		Node:              node,
		VRF:               "default",
		NeighborsComplete: complete,
		Neighbors:         ns,
		Interfaces:        is,
	}
}

func model(t *testing.T, obs ...netmodel.Observation) netmodel.Model {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return m
}

// summary lists each finding as kind/strength, in report order.
func summary(r Report) []string {
	out := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		out[i] = string(f.Kind) + "/" + string(f.Strength)
	}
	return out
}

func wantSummary(t *testing.T, r Report, want ...string) {
	t.Helper()
	if got := summary(r); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v\n%+v", got, want, r.Findings)
	}
}

func only(t *testing.T, r Report, kind Kind) Finding {
	t.Helper()
	var hits []Finding
	for _, f := range r.Findings {
		if f.Kind == kind {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%s findings = %d, want 1; all: %v", kind, len(hits), summary(r))
	}
	return hits[0]
}

// A reported FULL neighbor is reported as the reporter's claim, with its
// provenance and a limit that says what FULL does not prove.
func TestReportedFullAdjacencyIsReportedWithLimits(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full", KeyArea, "0")...)}, nil),
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0", attrs(KeyState, "full", KeyArea, "0")...)}, nil),
	)
	r := Analyze(m)
	wantSummary(t, r, "neighbor_state/reported", "neighbor_state/reported")
	f := r.Findings[0]
	if f.Limit != limitFull || !strings.Contains(f.Limit, "does not prove") {
		t.Errorf("limit = %q, want the FULL limit", f.Limit)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Source != "frr:r1" || f.Evidence[0].CollectedAt != t0.Format(time.RFC3339Nano) || f.Evidence[0].Plane != "control" {
		t.Errorf("evidence = %+v, want one row from frr:r1 at t0 on control", f.Evidence)
	}
}

// A state before FULL is reported as the state, and it names no root cause.
// 2-way gets its own limit, because it is normal on broadcast segments.
func TestStateBeforeFullIsReportedWithoutACause(t *testing.T) {
	for state, limit := range map[string]string{"init": limitBeforeFull, "2-way": limitTwoWay, "exstart": limitBeforeFull} {
		m := model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
			[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, state)...)}, nil))
		f := only(t, Analyze(m), KindNeighborState)
		if f.Strength != Reported || f.Limit != limit {
			t.Errorf("state %s: strength %s limit %q, want reported with %q", state, f.Strength, f.Limit, limit)
		}
		if strings.Contains(f.Detail+f.Limit, "stuck") {
			t.Errorf("state %s: finding uses the word stuck: %+v", state, f)
		}
	}
}

// An expected neighbor with no operational inventory to check is unknown.
func TestMissingExpectedNeighborWithPartialInventoryIsUnknown(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, nil, nil),
	)
	f := only(t, Analyze(m), KindMissingNeighbor)
	if f.Strength != Unknown || !strings.Contains(f.Detail, "partial") {
		t.Errorf("finding = %+v, want unknown for a partial inventory", f)
	}
}

// A complete OSPF inventory that lacks the expected neighbor is a fact about the
// inventory. It does not say the adjacency is down.
func TestMissingNeighborInCompleteOSPFInventoryIsConsistentWith(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full")...)}, nil),
	)
	r := Analyze(m)
	f := only(t, r, KindMissingNeighbor)
	if f.Strength != ConsistentWith {
		t.Errorf("strength = %s, want consistent_with", f.Strength)
	}
	if strings.Contains(strings.ToLower(f.Detail), "down") {
		t.Errorf("detail %q claims the adjacency is down", f.Detail)
	}
	if !strings.Contains(f.Limit, "does not prove the adjacency is down") {
		t.Errorf("limit = %q, want the no-proof-of-down limit", f.Limit)
	}
	wantSummary(t, r, "missing_neighbor/consistent_with", "neighbor_state/reported")
}

// A complete inventory with no OSPF record does not show that the reporter covers
// OSPF. Its absence of an OSPF neighbor proves nothing.
func TestCompleteInventoryWithoutOSPFRecordsDoesNotProveOSPFAbsence(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0")}, nil),
	)
	f := only(t, Analyze(m), KindMissingNeighbor)
	if f.Strength != Unknown || !strings.Contains(f.Detail, "holds no OSPF records") {
		t.Errorf("finding = %+v, want unknown with the OSPF-coverage reason", f)
	}
}

// NeighborsComplete alone, with no OSPF evidence anywhere, is no OSPF reading.
func TestCompletenessFlagAloneYieldsNoFindings(t *testing.T) {
	m := model(t, view("lldp:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0")}, nil))
	if r := Analyze(m); len(r.Findings) != 0 || r.Text() != "" {
		t.Errorf("findings = %+v, want none", r.Findings)
	}
}

// The configured areas on both ends of a link that both sides report disagree.
func TestAreaMismatchNeedsAMirroredLink(t *testing.T) {
	configured := []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}
	remote := []netmodel.Interface{iface("eth0", attrs(KeyArea, "1")...)}
	mirrored := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, configured),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, remote),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	f := only(t, Analyze(mirrored), KindAreaMismatch)
	if f.Strength != ConsistentWith || f.Node != "r1" || f.Interface != "eth0" || f.Peer != "r2" || f.PeerInterface != "eth0" {
		t.Errorf("finding = %+v, want consistent_with on r1 eth0 to r2 eth0", f)
	}

	// One side reports only. Without a link both sides report, nothing is matched.
	oneSided := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, configured),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, remote),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
	)
	if r := Analyze(oneSided); len(r.Findings) != 0 {
		t.Errorf("one-sided link produced %v", summary(r))
	}
}

// An area on an interface with no link to the other area's interface is never
// compared with it, even when the values differ.
func TestUnrelatedAreaValuesAreNotCorrelated(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{
			iface("eth0", attrs(KeyArea, "0")...), iface("eth9", attrs(KeyArea, "5")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	if r := Analyze(m); len(r.Findings) != 0 {
		t.Errorf("unrelated area 5 on eth9 was compared: %v", summary(r))
	}
}

// Area 0 is written "0" or "0.0.0.0", and the two spellings name one area.
func TestAreaSpellingsAreOneArea(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0.0.0.0")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	if r := Analyze(m); len(r.Findings) != 0 {
		t.Errorf("0 and 0.0.0.0 were treated as different areas: %v", summary(r))
	}
	if a, ok := parseArea("0.0.0.1"); !ok || a != 1 {
		t.Errorf("parseArea(0.0.0.1) = %d, %v; want 1", a, ok)
	}
	if _, ok := parseArea("backbone"); ok {
		t.Errorf("parseArea(backbone) accepted a non-area")
	}
}

// An area that is not a number or dotted address cannot be compared, so it is
// unknown, never a mismatch.
func TestUnreadableAreaIsUnknown(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "backbone")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "1")...)}),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	r := Analyze(m)
	f := only(t, r, KindIncompleteAttributes)
	if f.Strength != Unknown || !strings.Contains(f.Detail, `"backbone"`) {
		t.Errorf("finding = %+v, want unknown naming the bad area", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("bad area also produced %v", summary(r))
	}
}

// Two reporters that state different states for one identity are both kept. The
// newer one does not win.
func TestConflictingStatesFromTwoReportersAreBothKept(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
	)
	r := Analyze(m)
	f := only(t, r, KindNeighborState)
	if f.Strength != Conflicting || len(f.Evidence) != 2 || !strings.Contains(f.Detail, "full") || !strings.Contains(f.Detail, "init") {
		t.Errorf("finding = %+v, want conflicting with both states and both rows", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("conflict also produced %v", summary(r))
	}
}

// One key with two states in one record is a conflict too. Neither is picked.
func TestTwoStatesUnderOneKeyConflict(t *testing.T) {
	m := model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
		[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full", KeyState, "init")...)}, nil))
	if f := only(t, Analyze(m), KindNeighborState); f.Strength != Conflicting {
		t.Errorf("strength = %s, want conflicting", f.Strength)
	}
}

// Two configured areas for one interface, from two reporters, are a conflict and
// no mismatch is claimed.
func TestConflictingAreaValuesAreAConflict(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("cisco:r1", t1, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "1")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	r := Analyze(m)
	if f := only(t, r, KindAttributeConflict); f.Strength != Conflicting || f.Interface != "eth0" {
		t.Errorf("finding = %+v, want conflicting on r1 eth0", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("conflicting areas also produced %v", summary(r))
	}
}

// A router ID names no peer. It can only be confirmed or contradicted by the
// peer node's own records, so an unconfirmed ID stays unknown.
func TestUnknownRouterIDMappingStaysUnknown(t *testing.T) {
	neighbor := view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
		[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full", KeyRouterID, "2.2.2.2")...)}, nil)

	// r3 holds that router ID, but r2 is the named peer and reports nothing.
	unconfirmed := model(t, neighbor,
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("eth0")}),
		view("frr:r3", t0, netmodel.PlaneControl, "r3", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyRouterID, "2.2.2.2")...)}),
	)
	r := Analyze(unconfirmed)
	if f := only(t, r, KindRouterIDUnconfirmed); f.Strength != Unknown || f.Node != "r1" || f.Peer != "r2" {
		t.Errorf("finding = %+v, want unknown on r1 toward r2", f)
	}

	confirmed := model(t, neighbor,
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyRouterID, "2.2.2.2")...)}))
	if r := Analyze(confirmed); len(r.Findings) != 1 || r.Findings[0].Kind != KindNeighborState {
		t.Errorf("confirmed router ID produced %v", summary(r))
	}

	disagree := model(t, neighbor,
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyRouterID, "3.3.3.3")...)}))
	if f := only(t, Analyze(disagree), KindAttributeConflict); f.Strength != Conflicting {
		t.Errorf("router ID disagreement strength = %s, want conflicting", f.Strength)
	}
}

// A routing domain is part of every identity. Records in another VRF never pair
// with this one, and an inventory in another VRF is not this node's inventory.
func TestDifferentRoutingDomainsDoNotCorrelate(t *testing.T) {
	red := view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full")...)}, nil)
	red.VRF = "red"
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		red,
	)
	if f := only(t, Analyze(m), KindMissingNeighbor); f.Strength != Unknown || !strings.Contains(f.Detail, "no operational inventory") {
		t.Errorf("finding = %+v, want unknown because the red inventory is not the default domain", f)
	}
}

// Configured rows are not operational state. A configured state never conflicts
// with the control-plane state, and it does not change it.
func TestPlanesAreNotCompared(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
	)
	r := Analyze(m)
	f := only(t, r, KindNeighborState)
	if f.Strength != Reported || !strings.Contains(f.Detail, "full") {
		t.Errorf("finding = %+v, want the control-plane full state only", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("configured state produced %v", summary(r))
	}
}

// FIB and observed rows carry no OSPF reading. They are not read here.
func TestFIBAndObservedRowsAreNotRead(t *testing.T) {
	m := model(t,
		view("fib:r1", t0, netmodel.PlaneFIB, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
		view("obs:r1", t0, netmodel.PlaneObserved, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
	)
	if r := Analyze(m); len(r.Findings) != 0 {
		t.Errorf("fib or observed row produced %v", summary(r))
	}
}

// A route with origin ospf, and even OSPF route attributes, starts no adjacency
// reasoning.
func TestRouteOriginAloneYieldsNoFindings(t *testing.T) {
	o := view("frr:r1", t0, netmodel.PlaneControl, "r1", true, nil, nil)
	o.Routes = []netmodel.Route{{
		Prefix:     netip.MustParsePrefix("10.2.0.0/16"),
		Origin:     netmodel.OriginOSPF,
		NextHops:   []netmodel.NextHop{{Addr: netip.MustParseAddr("10.0.0.2"), Interface: "eth0"}},
		Attributes: attrs("ospf.route_type", "intra", KeyArea, "0"),
	}}
	if r := Analyze(model(t, o)); len(r.Findings) != 0 {
		t.Errorf("route origin produced %v", summary(r))
	}
}

// A state outside the vocabulary is reported unreadable. It is not read as FULL.
func TestUnrecognizedStateIsUnknown(t *testing.T) {
	m := model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
		[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "Full/DR")...)}, nil))
	r := Analyze(m)
	if f := only(t, r, KindIncompleteAttributes); f.Strength != Unknown || !strings.Contains(f.Detail, `"Full/DR"`) {
		t.Errorf("finding = %+v, want unknown naming the value", f)
	}
	if len(r.Findings) != 1 {
		t.Errorf("unrecognized state also produced %v", summary(r))
	}
}

// A record with no state is incomplete. Its missing state is not guessed.
func TestMissingStateIsIncomplete(t *testing.T) {
	m := model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
		[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil))
	f := only(t, Analyze(m), KindIncompleteAttributes)
	if f.Strength != Unknown || !strings.Contains(f.Detail, "no ospf.state") {
		t.Errorf("finding = %+v, want unknown for the missing state", f)
	}
}

// Identical duplicate records are one reading with one evidence row.
func TestDuplicateIdenticalRecordsAreOneReading(t *testing.T) {
	dup := nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)
	m := model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{dup, dup}, nil))
	r := Analyze(m)
	f := only(t, r, KindNeighborState)
	if f.Strength != Reported || len(f.Evidence) != 1 {
		t.Errorf("finding = %+v, want one reported reading with one evidence row", f)
	}
}

// A configured neighbor with no remote interface cannot be matched at the far
// end, so it is unknown.
func TestExpectedNeighborWithoutRemoteInterfaceIsUnknown(t *testing.T) {
	m := model(t, view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "", attrs(KeyArea, "0")...)}, nil))
	if f := only(t, Analyze(m), KindMissingNeighbor); f.Strength != Unknown || !strings.Contains(f.Detail, "remote interface") {
		t.Errorf("finding = %+v, want unknown about the remote interface", f)
	}
}

// One reporter has the expected neighbor, and a complete OSPF inventory lacks it.
// The reporters disagree, and the finding says so.
func TestReportersDisagreeOverAnExpectedNeighbor(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
	)
	f := only(t, Analyze(m), KindMissingNeighbor)
	if f.Strength != Conflicting {
		t.Errorf("strength = %s, want conflicting", f.Strength)
	}
}

// Output does not depend on the order observations or neighbors arrive in.
func TestOutputIsIndependentOfInputOrder(t *testing.T) {
	obs := []netmodel.Observation{
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...), nb("eth2", "r4", "eth0", attrs(KeyArea, "0")...)}, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "1")...)}),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full", KeyRouterID, "3.3.3.3")...)}, nil),
		view("frr:r3", t0, netmodel.PlaneControl, "r3", false, []netmodel.Neighbor{nb("eth0", "r1", "eth1", attrs(KeyState, "init")...)}, nil),
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0", attrs(KeyState, "full")...)}, []netmodel.Interface{iface("eth0")}),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "exstart")...)}, nil),
	}
	rev := slices.Clone(obs)
	slices.Reverse(rev)
	a, _ := json.Marshal(Analyze(model(t, obs...)))
	b, _ := json.Marshal(Analyze(model(t, rev...)))
	if len(a) == 0 || string(a) != string(b) {
		t.Fatalf("order changed the output:\n%s\n%s", a, b)
	}
	if got := Analyze(model(t, obs...)); len(got.Findings) < 4 {
		t.Errorf("fixture produced too few findings to prove ordering: %v", summary(got))
	}
	if !reflect.DeepEqual(Analyze(model(t, obs...)), Analyze(model(t, rev...))) {
		t.Errorf("reports differ by input order")
	}
}

func TestTextIsEmptyWithoutFindingsAndCarriesLimits(t *testing.T) {
	if (Report{}).Text() != "" {
		t.Fatalf("empty report rendered text")
	}
	r := Analyze(model(t, view("frr:r1", t0, netmodel.PlaneControl, "r1", false,
		[]netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil)))
	text := r.Text()
	for _, want := range []string{"OSPF (from recorded evidence", "neighbor_state [reported]", "evidence: frr:r1 at", "limit: FULL is the reporter's own claim"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

// A source can leave the remote interface unreported. That record is the same
// adjacency as an expected one on the same node, VRF, interface, and peer, so it
// is present, not a missing neighbor.
func TestUnreportedRemoteInterfaceMatchesTheExpectedNeighbor(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth0", "r2", "", attrs(KeyState, "full")...)}, nil),
	)
	wantSummary(t, Analyze(m), "neighbor_state/reported")
}

// Two sources that name one adjacency, one with the remote interface and one
// without, state one neighbor. Their states are compared, not split into two
// readings that each look reported.
func TestUnreportedRemoteInterfaceJoinsTheNamedGroup(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
	)
	f := only(t, Analyze(m), KindNeighborState)
	if f.Strength != Conflicting || len(f.Evidence) != 2 {
		t.Errorf("finding = %+v, want one conflicting neighbor state with both rows", f)
	}
}

// A record that names a different remote interface is not the expected adjacency.
// The expected one is not shown, so the absence is unknown, never consistent_with.
func TestDifferentRemoteInterfaceIsNotTheExpectedNeighbor(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth0", "r2", "eth5", attrs(KeyState, "full")...)}, nil),
	)
	f := only(t, Analyze(m), KindMissingNeighbor)
	if f.Strength != Unknown || !strings.Contains(f.Detail, "eth5") {
		t.Errorf("finding = %+v, want unknown naming the other remote interface", f)
	}
}

// Two sources that name one adjacency with different remote interfaces disagree.
// Neither adjacency is chosen, and no state is reported for either.
func TestConflictingRemoteInterfacesAreAConflict(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth5", attrs(KeyState, "full")...)}, nil),
	)
	wantSummary(t, Analyze(m), "attribute_conflict/conflicting")
}

// Area mismatch matches the mirrored link exactly. An unreported remote interface
// leaves the link unpaired, so no mismatch is claimed.
func TestAreaMismatchNeedsExactRemoteInterfaces(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "0")...)}),
		view("config:r2", t0, netmodel.PlaneConfigured, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyArea, "1")...)}),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "")}, nil),
		view("lldp:r2", t0, netmodel.PlaneControl, "r2", false, []netmodel.Neighbor{nb("eth0", "r1", "eth0")}, nil),
	)
	if r := Analyze(m); len(r.Findings) != 0 {
		t.Errorf("unpaired link produced %v", summary(r))
	}
}

// A generic neighbor record, such as LLDP, names the same link as an expected
// OSPF neighbor. It carries no OSPF key, so it is not OSPF presence.
func TestGenericNeighborDoesNotSatisfyExpectedOSPFNeighbor(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
	)
	if f := only(t, Analyze(m), KindMissingNeighbor); f.Strength != Unknown {
		t.Errorf("strength = %s, want unknown: a generic record is not OSPF presence", f.Strength)
	}
}

// A complete OSPF list lacks the expected neighbor, and a generic record for the
// same link sits in another list. The generic record must not become a conflict.
func TestGenericNeighborBesideCompleteOSPFListIsNotOSPFPresence(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full")...)}, nil),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0")}, nil),
	)
	wantSummary(t, Analyze(m), "missing_neighbor/consistent_with", "neighbor_state/reported")
}

// A generic record with an unreported remote interface is not OSPF presence either.
func TestGenericUnreportedRemoteInterfaceIsNotOSPFPresence(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("lldp:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth0", "r2", "")}, nil),
	)
	if f := only(t, Analyze(m), KindMissingNeighbor); f.Strength != Unknown {
		t.Errorf("strength = %s, want unknown", f.Strength)
	}
}

// An OSPF-attributed record with the same identity still satisfies the expectation.
func TestOSPFRecordSatisfiesExpectedNeighbor(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
	)
	wantSummary(t, Analyze(m), "neighbor_state/reported")
}

// One reporter's readable state beside another's unreadable one is not agreement.
// The aggregate stays unknown, and both rows stay as evidence.
func TestReadableStateBesideUnreadableStateIsNotAgreement(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "Full/DR")...)}, nil),
	)
	r := Analyze(m)
	wantSummary(t, r, "incomplete_attributes/unknown")
	if f := only(t, r, KindIncompleteAttributes); len(f.Evidence) != 2 {
		t.Errorf("evidence rows = %d, want both reporters", len(f.Evidence))
	}
}

// A reporter that omits the state, beside one that reports it, is incomplete too.
func TestReadableStateBesideMissingStateIsNotAgreement(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
	)
	r := Analyze(m)
	wantSummary(t, r, "incomplete_attributes/unknown")
	if f := only(t, r, KindIncompleteAttributes); !strings.Contains(f.Detail, "carry no ospf.state") {
		t.Errorf("detail = %q, want the missing state named", f.Detail)
	}
}

// Two sources that agree on a readable state still report it.
func TestAgreeingReadableStatesAreReported(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "FULL")...)}, nil),
	)
	f := only(t, Analyze(m), KindNeighborState)
	if f.Strength != Reported || len(f.Evidence) != 2 {
		t.Errorf("finding = %+v, want reported with both rows", f)
	}
}

// Two readable states still conflict when a third source is unreadable, and the
// unreadable value is reported too.
func TestConflictingStatesStayConflictingBesideUnreadable(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full")...)}, nil),
		view("cisco:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "init")...)}, nil),
		view("juniper:r1", t1, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "Full/DR")...)}, nil),
	)
	wantSummary(t, Analyze(m), "incomplete_attributes/unknown", "neighbor_state/conflicting")
}

// An OSPF router ID is a 32-bit identifier written as dotted IPv4. An IPv6 address
// or an IPv4-mapped IPv6 address is not one, so it cannot confirm an identity.
func TestIPv6RouterIDIsNotOSPFIdentity(t *testing.T) {
	for _, id := range []string{"2001:db8::2", "::ffff:2.2.2.2"} {
		m := model(t,
			view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full", KeyRouterID, id)...)}, nil),
			view("frr:r2", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyRouterID, id)...)}),
		)
		r := Analyze(m)
		wantSummary(t, r, "incomplete_attributes/unknown", "neighbor_state/reported")
		f := only(t, r, KindIncompleteAttributes)
		if !strings.Contains(f.Detail, KeyRouterID+` "`+id+`" is not a dotted IPv4 router ID`) {
			t.Errorf("%s: detail = %q, want the router ID rejected by name", id, f.Detail)
		}
	}
}

// The completeness flag says the neighbor list is complete. It does not say every
// OSPF source was collected, so the wording must not claim that it does.
func TestMissingNeighborWordingDoesNotClaimFullCollection(t *testing.T) {
	m := model(t,
		view("config:r1", t0, netmodel.PlaneConfigured, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyArea, "0")...)}, nil),
		view("frr:r1", t0, netmodel.PlaneControl, "r1", true, []netmodel.Neighbor{nb("eth1", "r3", "eth0", attrs(KeyState, "full")...)}, nil),
	)
	f := only(t, Analyze(m), KindMissingNeighbor)
	if !strings.Contains(f.Limit, "does not show that every OSPF source was collected") {
		t.Errorf("limit = %q, want the no-full-collection limit", f.Limit)
	}
	if strings.Contains(f.Detail, "complete OSPF inventory") {
		t.Errorf("detail = %q, want no claim of a complete OSPF inventory", f.Detail)
	}
}

// A peer's IPv6 router ID is unreadable, so it cannot contradict an IPv4 identity.
// The unreadable value is skipped, and the IPv4 ID is left unconfirmed.
func TestIPv6PeerRouterIDDoesNotContradictIPv4Identity(t *testing.T) {
	m := model(t,
		view("frr:r1", t0, netmodel.PlaneControl, "r1", false, []netmodel.Neighbor{nb("eth0", "r2", "eth0", attrs(KeyState, "full", KeyRouterID, "2.2.2.2")...)}, nil),
		view("frr:r2", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("eth0", attrs(KeyRouterID, "2001:db8::2")...)}),
	)
	wantSummary(t, Analyze(m), "neighbor_state/reported", "router_id_unconfirmed/unknown")
}
