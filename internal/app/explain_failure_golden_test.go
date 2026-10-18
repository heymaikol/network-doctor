package app

import (
	"path/filepath"
	"testing"
)

// explainFailureGoldenDir holds the pinned --explain reports of each simulated
// failure. The router, interface, and OSPF adjacency files were written at
// 6815109, before any other failure kind existed, so a later failure kind must
// leave them byte for byte as they are. The interface file changed once since,
// when a loss behind a route that r1's control plane names OSPF became unknown.
const explainFailureGoldenDir = "testdata/failure/golden"

// explainFailureGoldenCases names each pinned report: the topology it reads
// and the failure flags after the destination.
func explainFailureGoldenCases() []struct {
	name, topology string
	args           []string
} {
	return []struct {
		name, topology string
		args           []string
	}{
		{"router", omittedInterfaceTopology, []string{"--fail", "r2"}},
		{"interface", omittedInterfaceTopology, []string{"--fail", "r1:eth1"}},
		{"ospf-adjacency", ospfAdjacencyTopology, []string{"--fail-ospf", "r1:eth1:r2"}},
		{"next-hop", nextHopTopology, []string{"--fail-next-hop", "r1:10.0.1.2"}},
	}
}

// TestExplainFailureReportIsByteStable pins the text and JSON report of each
// failure kind.
func TestExplainFailureReportIsByteStable(t *testing.T) {
	for _, c := range explainFailureGoldenCases() {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"--explain", writeTopology(t, c.topology), "10.20.40.8"}, c.args...)
			code, text, stderr := runNetdoc(t, args...)
			if code != 0 {
				t.Fatalf("text exit %d, want 0; stderr %q", code, stderr)
			}
			code, js, stderr := runNetdoc(t, append(args, "--json")...)
			if code != 0 {
				t.Fatalf("json exit %d, want 0; stderr %q", code, stderr)
			}
			dir := filepath.Join(explainFailureGoldenDir, c.name)
			assertGolden(t, filepath.Join(dir, "text.txt"), text)
			assertGolden(t, filepath.Join(dir, "json.json"), js)
		})
	}
}
