package app

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
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

// ospfObservation adds one control-plane OSPF neighbor record to explainTopology.
const ospfObservation = `,
    {"source": "frr:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "control", "node": "r1", "vrf": "default",
     "neighbors": [{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "attributes": [{"key": "ospf.state", "value": "init"}]}]}`

// legacyExplain is what --explain printed before the OSPF section existed, built
// from the same file through routepath alone.
func legacyExplain(t *testing.T, path string) routepath.Explanation {
	t.Helper()
	// #nosec G304 -- path is a topology file this test wrote itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := routepath.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return routepath.Explain(f, netip.MustParseAddr("10.20.40.8"))
}

// A file with no OSPF evidence must print the same bytes it always printed, in
// both forms, including a file that sets neighbors_complete and an OSPF route.
func TestExplainWithoutOSPFIsByteIdentical(t *testing.T) {
	quiet := strings.Replace(explainTopology, "\n  ],\n  \"checks\"", ",\n    {\"source\": \"frr:r1\", \"collected_at\": \"2026-10-09T12:00:00Z\", \"plane\": \"control\", \"node\": \"r1\", \"vrf\": \"default\", \"neighbors_complete\": true,\n     \"neighbors\": [{\"local_interface\": \"eth1\", \"remote_node\": \"r2\", \"remote_interface\": \"eth0\"}],\n     \"routes\": [{\"prefix\": \"10.20.0.0/16\", \"origin\": \"ospf\", \"attributes\": [{\"key\": \"ospf.route_type\", \"value\": \"intra\"}]}]}\n  ],\n  \"checks\"", 1)
	for name, topology := range map[string]string{"plain": explainTopology, "neighbors complete and ospf origin": quiet} {
		t.Run(name, func(t *testing.T) {
			path := writeTopology(t, topology)
			result := legacyExplain(t, path)
			encoded, err := result.JSON()
			if err != nil {
				t.Fatal(err)
			}
			code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8")
			if code != 0 || out != result.Text() {
				t.Fatalf("text exit %d (stderr %q) differs from routepath output:\n%s", code, errOut, out)
			}
			code, out, errOut = runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
			if code != 0 || out != string(encoded)+"\n" {
				t.Fatalf("json exit %d (stderr %q) differs from routepath output:\n%s", code, errOut, out)
			}
		})
	}
}

// OSPF evidence adds its section after the route-path text, and an additive ospf
// JSON field. The route-path part of both forms keeps its own bytes.
func TestExplainPrintsTheOSPFSectionWhenEvidenceApplies(t *testing.T) {
	path := writeTopology(t, strings.Replace(explainTopology, "\n  ],\n  \"checks\"", ospfObservation+"\n  ],\n  \"checks\"", 1))
	result := legacyExplain(t, path)
	report := ospf.Analyze(legacyModel(t, path))
	if len(report.Findings) == 0 {
		t.Fatal("fixture has no OSPF finding")
	}

	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	if want := result.Text() + report.Text(); out != want {
		t.Errorf("text output is not the route-path text followed by the OSPF section:\n%s", out)
	}
	for _, want := range []string{"neighbor_state [reported] r1 eth1 to r2 eth0", "limit: A state before FULL"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	code, out, errOut = runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
	if code != 0 {
		t.Fatalf("json exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Destination string `json:"destination"`
		OSPF        *struct {
			Findings []struct {
				Kind     string `json:"kind"`
				Strength string `json:"strength"`
				Evidence []struct {
					Source string `json:"source"`
					State  string `json:"state"`
				} `json:"evidence"`
			} `json:"findings"`
		} `json:"ospf"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if decoded.Destination != "10.20.40.8" || decoded.OSPF == nil || len(decoded.OSPF.Findings) != 1 {
		t.Fatalf("decoded = %+v, want the destination and one ospf finding", decoded)
	}
	f := decoded.OSPF.Findings[0]
	if f.Kind != string(ospf.KindNeighborState) || f.Strength != string(ospf.Reported) || f.Evidence[0].Source != "frr:r1" || f.Evidence[0].State != "init" {
		t.Errorf("ospf finding = %+v, want reported init from frr:r1", f)
	}
}

// legacyModel reads the topology's model the way runExplain does.
func legacyModel(t *testing.T, path string) netmodel.Model {
	t.Helper()
	// #nosec G304 -- path is a topology file this test wrote itself.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := routepath.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return f.Model
}

// The OSPF attributes on a neighbor are the only difference between these two
// files. The route-path reading of both must be the same bytes, so OSPF evidence
// never changes a route-path finding.
func TestOSPFAttributesLeaveRoutePathFindingsUnchanged(t *testing.T) {
	plain := strings.Replace(ospfObservation, `, "attributes": [{"key": "ospf.state", "value": "init"}]`, "", 1)
	if plain == ospfObservation {
		t.Fatal("fixture did not strip the ospf attribute")
	}
	withOSPF := legacyExplain(t, writeTopology(t, strings.Replace(explainTopology, "\n  ],\n  \"checks\"", ospfObservation+"\n  ],\n  \"checks\"", 1)))
	without := legacyExplain(t, writeTopology(t, strings.Replace(explainTopology, "\n  ],\n  \"checks\"", plain+"\n  ],\n  \"checks\"", 1)))
	a, err := withOSPF.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := without.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("ospf attributes changed the route-path JSON:\n%s\n%s", a, b)
	}
	if withOSPF.Text() != without.Text() {
		t.Errorf("ospf attributes changed the route-path text")
	}
}
