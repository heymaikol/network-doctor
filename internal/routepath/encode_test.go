package routepath

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// populatedFile uses every field version 1 can carry: known and unknown metrics,
// a discard route, next hops with and without an address, attributes on each
// row, checks with and without a next hop, out-of-order boundaries, a source
// address, and a time that is not in UTC.
func populatedFile(t *testing.T) File {
	t.Helper()
	at := time.Date(2026, 10, 10, 17, 41, 19, 500, time.FixedZone("UTC+2", 2*3600))
	m, err := netmodel.New(
		netmodel.Observation{
			Provenance:        netmodel.Provenance{Source: "frr r1", CollectedAt: at},
			Plane:             netmodel.PlaneControl,
			Node:              "r1",
			VRF:               "default",
			RoutesComplete:    true,
			NeighborsComplete: false,
			Interfaces: []netmodel.Interface{
				{Name: "e1", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.1/24")}, Attributes: []netmodel.Attribute{{Key: "ospf.router_id", Value: "1.1.1.1"}}},
				{Name: "lo"},
			},
			Neighbors: []netmodel.Neighbor{{
				LocalInterface:  "e1",
				RemoteNode:      "r2",
				RemoteInterface: "e2",
				RemoteAddr:      netip.MustParseAddr("10.0.1.2"),
				Attributes:      []netmodel.Attribute{{Key: "ospf.router_id", Value: "2.2.2.2"}, {Key: "ospf.state", Value: "Full"}},
			}},
			Routes: []netmodel.Route{
				{Prefix: netip.MustParsePrefix("10.20.0.0/16"), Origin: "ospf", Metric: 20, MetricKnown: true,
					NextHops:   []netmodel.NextHop{{Addr: netip.MustParseAddr("10.0.1.2"), Interface: "e1"}, {Interface: "e2"}},
					Attributes: []netmodel.Attribute{{Key: "bgp.as_path", Value: "65001"}}},
				{Prefix: netip.MustParsePrefix("10.30.0.0/16"), Origin: "static", Discard: true},
				{Prefix: netip.MustParsePrefix("10.40.0.0/16"), Origin: "kernel", NextHops: []netmodel.NextHop{{Addr: netip.MustParseAddr("10.0.1.2")}}},
			},
		},
		netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "config r2", CollectedAt: at.Add(time.Minute)},
			Plane:      netmodel.PlaneConfigured,
			Node:       "r2",
			VRF:        "default",
			Interfaces: []netmodel.Interface{{Name: "e2", Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/24")}}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return File{
		Source:     Start{Node: "r1", VRF: "default"},
		SourceAddr: netip.MustParseAddr("10.0.1.1"),
		Model:      m,
		Checks: []Check{
			{Provenance: netmodel.Provenance{Source: "probe r1", CollectedAt: at.Add(2 * time.Minute)}, Node: "r1", VRF: "default", Interface: "e1",
				Destination: netip.MustParseAddr("10.20.40.8"), NextHop: netip.MustParseAddr("10.0.1.2"), Result: CheckFail},
			{Provenance: netmodel.Provenance{Source: "probe r1", CollectedAt: at.Add(3 * time.Minute)}, Node: "r1", VRF: "default", Interface: "e2",
				Destination: netip.MustParseAddr("10.20.40.9"), Result: CheckPass},
		},
		Boundaries: []Boundary{
			{Provenance: netmodel.Provenance{Source: "config r2", CollectedAt: at}, Node: "r2", VRF: "default", Kind: BoundaryNAT},
			{Provenance: netmodel.Provenance{Source: "config r1", CollectedAt: at}, Node: "r1", VRF: "default", Kind: BoundaryStatefulFirewall},
		},
	}
}

func TestEncodeRoundTripsEveryFieldVersionOneCarries(t *testing.T) {
	f := populatedFile(t)
	data, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode of Encode output: %v\n%s", err, data)
	}
	if !sameEvidence(f, back) {
		t.Errorf("decoded file differs from the encoded one:\n%s", data)
	}
	if back.Source != f.Source || back.SourceAddr != f.SourceAddr {
		t.Errorf("source = %+v %v, want %+v %v", back.Source, back.SourceAddr, f.Source, f.SourceAddr)
	}
}

// TestEncodeWritesCompletenessFlagsExplicitly checks that the file says false
// rather than leaving the flags out. An absent flag reads as false too, but a
// reader of the file should see that nothing claimed completeness.
func TestEncodeWritesCompletenessFlagsExplicitly(t *testing.T) {
	f := populatedFile(t)
	data, err := Encode(f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"neighbors_complete": false`) {
		t.Errorf("file lacks explicit neighbors_complete false:\n%s", text)
	}
	if !strings.Contains(text, `"routes_complete": false`) {
		t.Errorf("file lacks explicit routes_complete false:\n%s", text)
	}
}

func TestEncodeLeavesUnknownMetricsAndAbsentAddressesOut(t *testing.T) {
	data, err := Encode(populatedFile(t))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"metric": 20`) {
		t.Errorf("known metric not written:\n%s", text)
	}
	if strings.Count(text, `"metric"`) != 1 {
		t.Errorf("unknown metrics were written as values:\n%s", text)
	}
	if strings.Contains(text, `"address": ""`) || strings.Contains(text, `"remote_addr": ""`) {
		t.Errorf("an absent address was written as an empty string:\n%s", text)
	}
}

func TestEncodeRefusesAVLANItCannotCarry(t *testing.T) {
	m, err := netmodel.New(netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "config r1", CollectedAt: time.Unix(1, 0)},
		Plane:      netmodel.PlaneConfigured,
		Node:       "r1",
		VRF:        "default",
		Interfaces: []netmodel.Interface{{Name: "eth0", VLANKnown: true, VLAN: 10}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Encode(File{Source: Start{Node: "r1", VRF: "default"}, Model: m})
	if err == nil || !strings.Contains(err.Error(), "VLAN") {
		t.Fatalf("Encode with a VLAN: err = %v, want a refusal that names the VLAN", err)
	}
}

func TestEncodeRefusesAFileOverTheLimit(t *testing.T) {
	m, err := netmodel.New(netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "config r1", CollectedAt: time.Unix(1, 0)},
		Plane:      netmodel.PlaneConfigured,
		Node:       "r1",
		VRF:        "default",
		Interfaces: []netmodel.Interface{{Name: "eth0", Attributes: []netmodel.Attribute{{Key: "note", Value: strings.Repeat("x", MaxFileBytes)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Encode(File{Source: Start{Node: "r1", VRF: "default"}, Model: m})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("Encode over the limit: err = %v, want a size refusal", err)
	}
}

func TestEncodeRequiresASourceNodeAndVRF(t *testing.T) {
	for _, s := range []Start{{Node: "", VRF: "default"}, {Node: "r1", VRF: ""}} {
		if _, err := Encode(File{Source: s}); err == nil {
			t.Errorf("Encode with source %+v succeeded, want a refusal", s)
		}
	}
}

// TestSameEvidenceSeesADroppedField checks that the comparison is not vacuous:
// removing one attribute, or changing the instant, is a difference. A changed
// offset alone is not, because both sides compare in UTC.
func TestSameEvidenceSeesADroppedField(t *testing.T) {
	f := populatedFile(t)
	dropped := populatedFile(t)
	obs := dropped.Model.Observations()
	r1 := observationOf(t, obs, "r1")
	r1.Neighbors[0].Attributes = r1.Neighbors[0].Attributes[:1]
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatal(err)
	}
	dropped.Model = m
	if sameEvidence(f, dropped) {
		t.Error("a dropped neighbor attribute compared as the same evidence")
	}

	moved := populatedFile(t)
	obs = moved.Model.Observations()
	observationOf(t, obs, "r1").CollectedAt = observationOf(t, obs, "r1").CollectedAt.Add(time.Second)
	if m, err = netmodel.New(obs...); err != nil {
		t.Fatal(err)
	}
	moved.Model = m
	if sameEvidence(f, moved) {
		t.Error("a changed collection time compared as the same evidence")
	}

	sameInstant := populatedFile(t)
	obs = sameInstant.Model.Observations()
	observationOf(t, obs, "r1").CollectedAt = observationOf(t, obs, "r1").CollectedAt.UTC()
	if m, err = netmodel.New(obs...); err != nil {
		t.Fatal(err)
	}
	sameInstant.Model = m
	if !sameEvidence(f, sameInstant) {
		t.Error("the same instant in another zone compared as different evidence")
	}
}

// observationOf returns the observation for node. Model order is by plane first,
// so tests find rows by name, never by index.
func observationOf(t *testing.T, obs []netmodel.Observation, node string) *netmodel.Observation {
	t.Helper()
	for i := range obs {
		if obs[i].Node == node {
			return &obs[i]
		}
	}
	t.Fatalf("no observation for %s", node)
	return nil
}

// TestEncodeCoversEveryFieldOfTheModel fails when a field is added to a type
// that Encode mirrors. The new field must be written, refused, or deliberately
// left out before the expected count changes here.
func TestEncodeCoversEveryFieldOfTheModel(t *testing.T) {
	want := map[string]struct {
		value any
		count int
	}{
		"netmodel.Observation": {netmodel.Observation{}, 9},
		"netmodel.Interface":   {netmodel.Interface{}, 5},
		"netmodel.Neighbor":    {netmodel.Neighbor{}, 5},
		"netmodel.Route":       {netmodel.Route{}, 7},
		"netmodel.NextHop":     {netmodel.NextHop{}, 2},
		"netmodel.Attribute":   {netmodel.Attribute{}, 2},
		"netmodel.Provenance":  {netmodel.Provenance{}, 2},
		"routepath.File":       {File{}, 5},
		"routepath.Start":      {Start{}, 2},
		"routepath.Check":      {Check{}, 7},
		"routepath.Boundary":   {Boundary{}, 4},
	}
	for name, tc := range want {
		if got := reflect.TypeOf(tc.value).NumField(); got != tc.count {
			t.Errorf("%s has %d fields, want %d; teach Encode about the new field", name, got, tc.count)
		}
	}
}
