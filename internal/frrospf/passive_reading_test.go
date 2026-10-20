package frrospf

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"github.com/heymaikol/network-doctor/v2/internal/ospf"
)

// TestPassiveInterfaceExplainsMissingNeighbor imports the passive lab, where r1
// e1 is passive and r2 e2 is active, and declares the link from both ends. The
// only finding is the passive reading, and its evidence names the passive end.
func TestPassiveInterfaceExplainsMissingNeighbor(t *testing.T) {
	caps := []Capture{fixture(t, "passive1", "r1", CommandInterface), fixture(t, "passive1", "r2", CommandInterface)}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1", "r2")...)
	if got := summarize(r); !slices.Equal(got, []string{"missing_neighbor/consistent_with"}) {
		t.Fatalf("findings = %v, want exactly missing_neighbor/consistent_with", got)
	}
	f := r.Findings[0]
	if f.Node != "r1" || f.Interface != "e1" || f.Peer != "r2" || f.PeerInterface != "e2" {
		t.Errorf("finding on %s %s to %s %s, want r1 e1 to r2 e2", f.Node, f.Interface, f.Peer, f.PeerInterface)
	}
	for _, word := range []string{"absent", "configured", "forward", "failed"} {
		if strings.Contains(f.Detail, word) {
			t.Errorf("detail %q contains %q, which claims more than the evidence shows", f.Detail, word)
		}
	}
	var passive bool
	for _, row := range evidenceRows(t, f) {
		if row["passive"] == "true" && row["source"] != "" && row["collected_at"] != "" {
			passive = true
		}
	}
	if !passive {
		t.Errorf("no evidence row holds passive true with source and collected_at: %v", evidenceRows(t, f))
	}
}

// farEndRecord is a control-plane OSPF neighbor record on node, from local
// interface to peer on remote interface. It stands for a record the import of
// a real capture would write.
func farEndRecord(node, local, peer, remote string) netmodel.Observation {
	return netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "synthetic " + node + " neighbor", CollectedAt: time.Date(2026, 10, 10, 17, 0, 0, 0, time.UTC)},
		Plane:      netmodel.PlaneControl,
		Node:       node,
		VRF:        "default",
		Neighbors: []netmodel.Neighbor{{
			LocalInterface: local, RemoteNode: peer, RemoteInterface: remote,
			Attributes: []netmodel.Attribute{{Key: "ospf.state", Value: "full"}},
		}},
	}
}

// TestPassiveReadingBlockedByFarEndRecord adds a synthetic control-plane record
// on r2 that names the pair from its own end. That record blocks the passive
// reading, because the far end has OSPF evidence for the pair.
func TestPassiveReadingBlockedByFarEndRecord(t *testing.T) {
	caps := []Capture{fixture(t, "passive1", "r1", CommandInterface), fixture(t, "passive1", "r2", CommandInterface)}
	overlay := append(declaredOverlay(t, "r1", "r2"), farEndRecord("r2", "e2", "r1", "e1"))
	r := analyzeWith(t, caps, overlay...)
	if slices.Contains(summarize(r), "missing_neighbor/consistent_with") {
		t.Errorf("passive reading fired against a far-end OSPF record: %v", summarize(r))
	}
}

// TestPassiveReadingBlockedByOtherRemoteInterface adds a synthetic record on r1
// for the same pair that names another remote interface. The pair still has OSPF
// evidence, so the passive reading does not fire.
func TestPassiveReadingBlockedByOtherRemoteInterface(t *testing.T) {
	caps := []Capture{fixture(t, "passive1", "r1", CommandInterface), fixture(t, "passive1", "r2", CommandInterface)}
	overlay := append(declaredOverlay(t, "r1", "r2"), farEndRecord("r1", "e1", "r2", "e9"))
	r := analyzeWith(t, caps, overlay...)
	if slices.Contains(summarize(r), "missing_neighbor/consistent_with") {
		t.Errorf("passive reading fired against a record with another remote interface: %v", summarize(r))
	}
}

// TestPassiveOneSidedDeclarationIsSilent declares the passive link from one end
// only. One declaration does not confirm the link, so no passive reading fires.
func TestPassiveOneSidedDeclarationIsSilent(t *testing.T) {
	caps := []Capture{fixture(t, "passive1", "r1", CommandInterface), fixture(t, "passive1", "r2", CommandInterface)}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1")...)
	if slices.Contains(summarize(r), "missing_neighbor/consistent_with") {
		t.Errorf("one-sided declaration produced a passive reading: %v", summarize(r))
	}
}

// TestPassivePlaneFilter puts ospf.passive true on a configured interface, with
// no control-plane record, under a mutual declaration. Only control-plane
// evidence may support the passive reading.
func TestPassivePlaneFilter(t *testing.T) {
	configured := netmodel.Observation{
		Provenance: netmodel.Provenance{Source: "synthetic configured r1", CollectedAt: time.Date(2026, 10, 10, 17, 0, 0, 0, time.UTC)},
		Plane:      netmodel.PlaneConfigured,
		Node:       "r1",
		VRF:        "default",
		Interfaces: []netmodel.Interface{{Name: "e1", Attributes: []netmodel.Attribute{{Key: "ospf.passive", Value: "true"}}}},
	}
	overlay := append(declaredOverlay(t, "r1", "r2"), configured)
	m, err := netmodel.New(overlay...)
	if err != nil {
		t.Fatal(err)
	}
	if r := ospf.Analyze(m); slices.Contains(summarize(r), "missing_neighbor/consistent_with") {
		t.Errorf("configured-plane passive produced a passive reading: %v", summarize(r))
	}
}
