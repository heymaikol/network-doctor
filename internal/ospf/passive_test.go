package ospf

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// mutualLinkE1E2 declares the e1 to e2 link between r1 and r2 from both ends, in
// the intended plane. Nothing else is declared.
func mutualLinkE1E2(source string) []netmodel.Observation {
	return []netmodel.Observation{
		view(source+":r1", t0, netmodel.PlaneIntended, "r1", false, []netmodel.Neighbor{nb("e1", "r2", "e2")}, nil),
		view(source+":r2", t0, netmodel.PlaneIntended, "r2", false, []netmodel.Neighbor{nb("e2", "r1", "e1")}, nil),
	}
}

// TestTwoDistinctPassiveValuesAreAmbiguous gives r1 e1 two control-plane values
// for ospf.passive, one true and one false. No value is chosen, so the mutual
// declaration yields no passive reading.
func TestTwoDistinctPassiveValuesAreAmbiguous(t *testing.T) {
	obs := append(mutualLinkE1E2("decl"),
		view("a", t0, netmodel.PlaneControl, "r1", false, nil, []netmodel.Interface{iface("e1", attrs("ospf.passive", "true")...)}),
		view("b", t0, netmodel.PlaneControl, "r1", false, nil, []netmodel.Interface{iface("e1", attrs("ospf.passive", "false")...)}),
		view("c", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("e2", attrs("ospf.router_id", "2.2.2.2")...)}),
	)
	if got := summary(Analyze(model(t, obs...))); slices.Contains(got, "missing_neighbor/consistent_with") {
		t.Errorf("two passive values produced a passive reading: %v", got)
	}
}

// TestOSPFMembershipChangeIsHarmless adds an interface that carries only ospf.cost
// and no router ID. It joins the interface list, and no finding changes, because
// each reader looks for its own key.
func TestOSPFMembershipChangeIsHarmless(t *testing.T) {
	base := append(mutualLinkE1E2("decl"),
		view("a", t0, netmodel.PlaneControl, "r1", false, nil, []netmodel.Interface{iface("e1", attrs("ospf.router_id", "1.1.1.1")...)}),
		view("c", t0, netmodel.PlaneControl, "r2", false, nil, []netmodel.Interface{iface("e2", attrs("ospf.router_id", "2.2.2.2")...)}),
	)
	extra := append(slices.Clone(base),
		view("d", t0, netmodel.PlaneControl, "r1", false, nil, []netmodel.Interface{iface("e9", attrs("ospf.cost", "10")...)}),
	)
	if a, b := Analyze(model(t, base...)), Analyze(model(t, extra...)); !reflect.DeepEqual(a, b) {
		t.Errorf("an interface with only ospf.cost changed the report:\nbase  %v\nextra %v", summary(a), summary(b))
	}
}

// TestReportJSONAdditiveOnly checks that every field a report reader used before
// is still written under the same name. Fields may be added, not renamed.
func TestReportJSONAdditiveOnly(t *testing.T) {
	f := Finding{
		Kind: KindMissingNeighbor, Strength: ConsistentWith, Node: "r1", VRF: "default",
		Interface: "e1", Peer: "r2", PeerInterface: "e2", Detail: "d", Limit: "l",
		Evidence: []Evidence{{
			Source: "s", CollectedAt: "t", Plane: "control", Node: "r1", VRF: "default",
			Interface: "e1", Peer: "r2", PeerInterface: "e2", State: "full", Area: "0.0.0.0",
			EffectiveArea: "0.0.0.0", RouterID: "1.1.1.1", Note: "n",
		}},
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"kind", "strength", "node", "vrf", "interface", "peer", "peer_interface", "detail", "limit", "evidence"} {
		if _, ok := top[k]; !ok {
			t.Errorf("finding JSON lacks %q", k)
		}
	}
	rows, _ := top["evidence"].([]any)
	if len(rows) != 1 {
		t.Fatalf("evidence rows = %d, want 1", len(rows))
	}
	row, _ := rows[0].(map[string]any)
	for _, k := range []string{"source", "collected_at", "plane", "node", "vrf", "interface", "peer", "peer_interface", "state", "area", "effective_area", "router_id", "note"} {
		if _, ok := row[k]; !ok {
			t.Errorf("evidence JSON lacks %q", k)
		}
	}
}
