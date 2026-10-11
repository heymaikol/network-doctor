package frrospf

import (
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
)

// TestAnalyzerReadsAuthenticImports feeds genuine imports to the existing OSPF
// analyzer, which is unchanged. An import claims no completeness, so the
// analyzer must not report a missing neighbor from it.
func TestAnalyzerReadsAuthenticImports(t *testing.T) {
	res, err := Import(broadcastCaptures(t))
	if err != nil {
		t.Fatal(err)
	}
	m, err := netmodel.New(res.Observations...)
	if err != nil {
		t.Fatal(err)
	}
	report := ospf.Analyze(m)
	for _, f := range report.Findings {
		if f.Kind == ospf.KindMissingNeighbor {
			t.Errorf("analyzer reported a missing neighbor from an import that claims no completeness: %+v", f)
		}
		if f.Kind == ospf.KindRouterIDUnconfirmed {
			t.Errorf("router ID unconfirmed on a capture where both sides agree: %+v", f)
		}
	}
	var states int
	for _, f := range report.Findings {
		if f.Kind == ospf.KindNeighborState && f.Strength == ospf.Reported {
			states++
		}
	}
	if states != 2 {
		t.Fatalf("got %d reported neighbor_state findings, want one per side (2):\n%s", states, report.Text())
	}
	text := report.Text()
	for _, src := range []string{"bcast r1 show ip ospf neighbor detail json", "bcast r2 show ip ospf neighbor detail json"} {
		if !strings.Contains(text, src) {
			t.Errorf("report does not carry provenance %q:\n%s", src, text)
		}
	}
}

// TestAnalyzerLimitsPreFullStates feeds the MTU-mismatch lab, where neither side
// reaches FULL. Each reported state must carry the before-FULL limit, and no
// finding may claim FULL.
func TestAnalyzerLimitsPreFullStates(t *testing.T) {
	res, err := Import([]Capture{
		fixture(t, "mtu", "r1", CommandInterface),
		fixture(t, "mtu", "r1", CommandNeighborDetail),
		fixture(t, "mtu", "r2", CommandInterface),
		fixture(t, "mtu", "r2", CommandNeighborDetail),
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := netmodel.New(res.Observations...)
	if err != nil {
		t.Fatal(err)
	}
	report := ospf.Analyze(m)
	var states []string
	for _, f := range report.Findings {
		if f.Kind != ospf.KindNeighborState {
			continue
		}
		if f.Strength != ospf.Reported {
			t.Errorf("neighbor state strength = %s, want reported: %+v", f.Strength, f)
		}
		if !strings.Contains(f.Limit, "before FULL") {
			t.Errorf("state %q lacks the before-FULL limit: %q", f.Detail, f.Limit)
		}
		states = append(states, f.Detail)
	}
	slices.Sort(states)
	want := []string{"reports state exchange", "reports state exstart"}
	if !slices.Equal(states, want) {
		t.Fatalf("neighbor states = %q, want %q:\n%s", states, want, report.Text())
	}
}

// TestKeysMatchTheOSPFAnalyzer checks that each attribute key this package writes
// is the key the OSPF analyzer reads, so a rename in one cannot go unseen.
func TestKeysMatchTheOSPFAnalyzer(t *testing.T) {
	for _, p := range [][2]string{
		{keyState, ospf.KeyState},
		{keyRouterID, ospf.KeyRouterID},
		{keyEffectiveArea, ospf.KeyEffectiveArea},
	} {
		if p[0] != p[1] {
			t.Errorf("this package writes %q, and the analyzer reads %q", p[0], p[1])
		}
	}
}
