package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/routepath"
)

// explainTopology is a two-router path whose FIB route fails on the segment r1
// leaves through. It is enough for every exit code and output shape below.
const explainTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "lan", "addresses": ["10.20.40.8/24"]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]}
  ],
  "checks": [
    {"source": "probe:r1", "collected_at": "2026-10-09T12:01:00Z", "node": "r1", "vrf": "default", "interface": "eth1", "destination": "10.20.40.8", "result": "fail"}
  ]
}`

func writeTopology(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "topology.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runNetdoc(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run("dev", args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestExplainPrintsTheForwardingPathAndItsFailure(t *testing.T) {
	path := writeTopology(t, explainTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	for _, want := range []string{"Destination 10.20.40.8 from r1 (default)", "fib_forwarding_failed at r1 (default)", "[check fail]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestExplainJSONIsTheStableEncoding(t *testing.T) {
	path := writeTopology(t, explainTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Destination string `json:"destination"`
		Findings    []struct {
			Kind string `json:"kind"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if decoded.Destination != "10.20.40.8" || len(decoded.Findings) != 1 || decoded.Findings[0].Kind != string(routepath.FindingForwardingFailed) {
		t.Errorf("decoded = %+v, want the destination and the forwarding failure", decoded)
	}
}

// omittedInterfaceTopology is a complete path from r1 where the control plane
// names the next-hop gateway without the interface it leaves by, while the FIB
// names it. An omitted field is unreported, not different, so the pair is the
// same forwarding and must read as agreement, not a difference.
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
// path: it decodes a topology file, runs the app, and reads the JSON. It checks
// both halves of the claim -- that no fib_differs_from_control finding is
// emitted, and that the FIB decision is reported as agreeing with control -- so
// valid JSON with no findings cannot pass the test on its own.
func TestExplainTreatsAnOmittedInterfaceAsUnreported(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Forwarding struct {
			Decision struct {
				Agreement string `json:"agreement"`
			} `json:"decision"`
		} `json:"forwarding"`
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
	if got := decoded.Forwarding.Decision.Agreement; got != string(routepath.AgreementAgrees) {
		t.Errorf("forwarding.decision.agreement = %q, want %q: an omitted interface is the same forwarding", got, routepath.AgreementAgrees)
	}
}

// Drift that loses reachability is part of the explanation, not a failed run,
// so the exit code stays 0.
func TestExplainDriftKeepsExitZero(t *testing.T) {
	topology := strings.Replace(explainTopology, `"next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]}`, `"discard": true}]},
    {"source": "intent:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "intended", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "static", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]}`, 1)
	topology = strings.Replace(topology, `"result": "fail"`, `"result": "pass"`, 1)
	code, out, errOut := runNetdoc(t, "--explain", writeTopology(t, topology), "10.20.40.8")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	if !strings.Contains(out, "reachability_lost at r1 (default)") {
		t.Errorf("output lacks the reachability_lost drift at r1:\n%s", out)
	}
}

func TestExplainRefusesBadUsageWithExitTwo(t *testing.T) {
	path := writeTopology(t, explainTopology)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no destination", []string{"--explain", path}, "needs a topology file and a destination"},
		{"hostname destination", []string{"--explain", path, "server.example"}, "must be an IP address"},
		{"port in destination", []string{"--explain", path, "10.20.40.8:443"}, "must be an IP address"},
		{"zoned destination", []string{"--explain", path, "fe80::1%eth0"}, "must not carry an interface zone"},
		// The OS error text differs by platform ("no such file" on Unix, "cannot
		// find the file" on Windows), so the case checks for the path it names.
		{"missing file", []string{"--explain", filepath.Join(t.TempDir(), "absent.json"), "10.20.40.8"}, "absent.json"},
		{"combined with compare", []string{"--explain", "--compare", path, path}, "cannot be combined with -compare or -two-sided"},
		{"combined with two-sided", []string{"--explain", "--two-sided", path, path}, "cannot be combined with -compare or -two-sided"},
		{"probe setting", []string{"--explain", path, "10.20.40.8", "--timeout", "2s"}, "-timeout cannot be combined with -explain"},
		{"via", []string{"--explain", path, "10.20.40.8", "--via", "ssh-host"}, "cannot be combined"},
		{"profile", []string{"--explain", "--profile", "github"}, "cannot be combined"},
		{"toolbox", []string{"--explain", path, "10.20.40.8", "--toolbox"}, "cannot be combined"},
		{"watch", []string{"--explain", path, "10.20.40.8", "--watch"}, "cannot be combined"},
		{"peer-connect", []string{"--explain", path, "10.20.40.8", "--peer-connect"}, "cannot be combined"},
		{"peer-listen", []string{"--explain", path, "10.20.40.8", "--peer-listen", "127.0.0.1:9000"}, "cannot be combined"},
		{"save", []string{"--explain", path, "10.20.40.8", "--save", filepath.Join(t.TempDir(), "run.ndoc")}, "cannot be combined"},
		{"list-checks", []string{"--explain", "--list-checks"}, "cannot be combined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runNetdoc(t, c.args...)
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", code, errOut)
			}
			if !strings.Contains(errOut, c.want) {
				t.Errorf("stderr = %q, want it to mention %q", errOut, c.want)
			}
		})
	}
}

func TestExplainRefusesAnInvalidFileWithExitTwo(t *testing.T) {
	path := writeTopology(t, strings.Replace(explainTopology, `"version": 1`, `"version": 9`, 1))
	code, _, errOut := runNetdoc(t, "--explain", path, "10.20.40.8")
	if code != 2 || !strings.Contains(errOut, "not supported") {
		t.Errorf("exit = %d, stderr = %q; want 2 and a version error", code, errOut)
	}
}

func TestExplainAdvertisesTheFlagInUsage(t *testing.T) {
	code, out, _ := runNetdoc(t, "--help")
	if code != 0 || !strings.Contains(out, "netdoc --explain topology.json DEST") || !strings.Contains(out, "-explain") {
		t.Errorf("--help exit %d lacks the explain usage line or flag:\n%s", code, out)
	}
}
