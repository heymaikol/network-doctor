package app

import (
	"encoding/json"
	"testing"

	"github.com/heymaikol/network-doctor/internal/routepath"
)

// omittedInterfaceTopology is a complete two-hop topology where r1's control
// plane names the next-hop gateway without the interface it leaves by, while
// the FIB names it. An omitted field is unreported, so the pair is the same
// forwarding and must not read as a difference.
const omittedInterfaceTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "control:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "control", "node": "r1", "vrf": "default", "routes_complete": true,
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}],
     "routes": [{"prefix": "10.20.0.0/16", "origin": "ospf", "next_hops": [{"addr": "10.0.12.2"}]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}],
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "lan", "addresses": ["10.20.40.8/24"]}]}
  ]
}`

// TestExplainTreatsAnOmittedInterfaceAsUnreported drives the whole --explain
// path: it decodes a topology file, runs the app, and reads the JSON findings.
// The routepath unit test builds the model in memory; this one proves the CLI
// boundary emits no fib_differs_from_control for the same input.
func TestExplainTreatsAnOmittedInterfaceAsUnreported(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Findings []struct {
			Kind string `json:"kind"`
			Node string `json:"node"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	for _, f := range decoded.Findings {
		if f.Kind == string(routepath.FindingFIBDiffers) {
			t.Errorf("findings = %+v, want no fib_differs_from_control: the FIB only names the interface the control plane omitted", decoded.Findings)
		}
	}
}
