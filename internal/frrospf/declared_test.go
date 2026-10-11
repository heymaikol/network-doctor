package frrospf

import (
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
)

// declaredOverlay is a synthetic intended plane. Each named node declares its
// e1 to e2 link on the remote node. FRR wrote none of it; the test does, and
// the test's name says which link it declares.
func declaredOverlay(t *testing.T, ends ...string) []netmodel.Observation {
	t.Helper()
	at := time.Date(2026, 10, 10, 17, 0, 0, 0, time.UTC)
	var out []netmodel.Observation
	for _, n := range ends {
		peer, local, remote := "r2", "e1", "e2"
		if n == "r2" {
			peer, local, remote = "r1", "e2", "e1"
		}
		out = append(out, netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "overlay " + n, CollectedAt: at},
			Plane:      netmodel.PlaneIntended,
			Node:       n,
			VRF:        "default",
			Neighbors:  []netmodel.Neighbor{{LocalInterface: local, RemoteNode: peer, RemoteInterface: remote}},
		})
	}
	return out
}

// analyzeWith imports captures, adds the overlay, and runs the OSPF analyzer.
func analyzeWith(t *testing.T, caps []Capture, overlay ...netmodel.Observation) ospf.Report {
	t.Helper()
	res, err := Import(caps)
	if err != nil {
		t.Fatal(err)
	}
	m, err := netmodel.New(append(res.Observations, overlay...)...)
	if err != nil {
		t.Fatal(err)
	}
	return ospf.Analyze(m)
}

func summarize(r ospf.Report) []string {
	out := make([]string, len(r.Findings))
	for i, f := range r.Findings {
		out[i] = string(f.Kind) + "/" + string(f.Strength)
	}
	return out
}

// TestAreaLabWithMutualDeclarationIsConsistentWithFailedAdjacency imports the
// area lab. Each side reports a different area, and no adjacency forms. With the
// link declared from both ends, the reading is consistent_with, and no neighbor
// record shows the link.
func TestAreaLabWithMutualDeclarationIsConsistentWithFailedAdjacency(t *testing.T) {
	caps := []Capture{fixture(t, "area", "r1", CommandInterface), fixture(t, "area", "r2", CommandInterface)}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1", "r2")...)
	if got := summarize(r); len(got) != 1 || got[0] != "area_mismatch/consistent_with" {
		t.Fatalf("findings = %v, want exactly area_mismatch/consistent_with", got)
	}
	if f := r.Findings[0]; f.Node != "r1" || f.Interface != "e1" || f.Peer != "r2" || f.PeerInterface != "e2" {
		t.Errorf("finding on %s %s to %s %s, want r1 e1 to r2 e2", f.Node, f.Interface, f.Peer, f.PeerInterface)
	}
}

// TestAreaLabWithOneSidedDeclarationIsOneSidedUnknown checks that the same lab,
// declared from one end only, gives the one-sided kind and never area_mismatch.
func TestAreaLabWithOneSidedDeclarationIsOneSidedUnknown(t *testing.T) {
	caps := []Capture{fixture(t, "area", "r1", CommandInterface), fixture(t, "area", "r2", CommandInterface)}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1")...)
	if got := summarize(r); len(got) != 1 || got[0] != "declared_link_one_sided/unknown" {
		t.Fatalf("findings = %v, want exactly declared_link_one_sided/unknown", got)
	}
}

// TestBroadcastWithMutualDeclarationAddsNothing checks that a declaration whose
// areas agree changes no finding. The baseline is the same capture without it.
func TestBroadcastWithMutualDeclarationAddsNothing(t *testing.T) {
	base := analyzeWith(t, broadcastCaptures(t))
	with := analyzeWith(t, broadcastCaptures(t), declaredOverlay(t, "r1", "r2")...)
	if len(with.Findings) != len(base.Findings) {
		t.Fatalf("declaration changed findings: %v, baseline %v", summarize(with), summarize(base))
	}
	for _, f := range with.Findings {
		if strings.Contains(string(f.Kind), "area") || strings.Contains(string(f.Kind), "declared") {
			t.Errorf("unexpected %s/%s from matching areas", f.Kind, f.Strength)
		}
	}
}

// TestBroadcastWithOneSidedDeclarationAddsNothing checks that a one-sided
// declaration with equal areas is silent.
func TestBroadcastWithOneSidedDeclarationAddsNothing(t *testing.T) {
	base := analyzeWith(t, broadcastCaptures(t))
	with := analyzeWith(t, broadcastCaptures(t), declaredOverlay(t, "r2")...)
	if len(with.Findings) != len(base.Findings) {
		t.Fatalf("one-sided declaration changed findings: %v, baseline %v", summarize(with), summarize(base))
	}
}

// TestBroadcastLabelledMismatchWithDeclarationIsUnknown is a labeled mutation.
// The bcast capture of r2 is edited so e2 reports area 0.0.0.1 while r1 keeps
// 0.0.0.0. The lab adjacency is Full, so the neighbor record exists, and the
// reading must be unknown, not consistent_with.
func TestBroadcastLabelledMismatchWithDeclarationIsUnknown(t *testing.T) {
	caps := broadcastCaptures(t)
	for i := range caps {
		if caps[i].Node == "r2" && caps[i].Command == CommandInterface {
			caps[i].Data = editInterface(t, caps[i].Data, "e2", func(rec map[string]any) { rec["area"] = "0.0.0.1" })
		}
	}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1", "r2")...)
	var mismatch []string
	for _, f := range r.Findings {
		if f.Kind == "area_mismatch" {
			mismatch = append(mismatch, string(f.Strength))
		}
	}
	if len(mismatch) != 1 || mismatch[0] != "unknown" {
		t.Fatalf("area_mismatch strengths = %v, want [unknown]; findings %v", mismatch, summarize(r))
	}
}

// TestSecondaryAddressDoesNotReadAsAFailedAdjacency imports the secondary lab.
// The Full adjacency on e1 is in area 0.0.0.0, but FRR's e1 record names only
// the secondary, 0.0.0.1. The importer withholds that area, because the
// adjacency's neighbor record disagrees with it. So the declared link has an
// end with no area, and the reading is incomplete, not a failed adjacency.
func TestSecondaryAddressDoesNotReadAsAFailedAdjacency(t *testing.T) {
	caps := []Capture{
		fixture(t, "secondary", "r1", CommandInterface),
		fixture(t, "secondary", "r1", CommandNeighborDetail),
		fixture(t, "secondary", "r2", CommandInterface),
		fixture(t, "secondary", "r2", CommandNeighborDetail),
	}
	r := analyzeWith(t, caps, declaredOverlay(t, "r1", "r2")...)
	if got := summarize(r); len(got) != 1 || got[0] != "incomplete_attributes/unknown" {
		t.Fatalf("findings = %v, want exactly incomplete_attributes/unknown", got)
	}
	if d := r.Findings[0].Detail; !strings.Contains(d, "r1 e1 is missing") {
		t.Errorf("detail %q does not name r1 e1 as missing", d)
	}
}
