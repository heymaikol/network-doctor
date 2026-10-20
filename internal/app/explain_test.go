package app

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"github.com/heymaikol/network-doctor/v2/internal/ospf"
	"github.com/heymaikol/network-doctor/v2/internal/routepath"
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

func TestExplainFailReportsWhatTheFailureCuts(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--fail", "r2", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Failure *routepath.Simulation `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	s := decoded.Failure
	if s == nil || len(s.Affected) != 1 || s.Affected[0].Destination != "10.20.40.8" || s.Affected[0].Impact != routepath.ImpactReachabilityLost {
		t.Fatalf("failure = %+v, want 10.20.40.8 reachability_lost", s)
	}

	// r1's control plane holds an OSPF route to 10.20.40.8, which may replace
	// its FIB entry once eth1 is down, so the loss is unknown.
	code, out, errOut = runNetdoc(t, "--explain", path, "10.20.40.8", "--fail", "r1:eth1")
	if code != 0 || !strings.Contains(out, "Failure simulation: interface r1 eth1 down, from r1 (default)") || !strings.Contains(out, "unknown 10.20.40.8 (r2 default)") {
		t.Errorf("exit = %d, stderr %q, text:\n%s", code, errOut, out)
	}
}

func TestExplainWithoutFailHasNoFailureField(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	_, out, _ := runNetdoc(t, "--explain", path, "10.20.40.8", "--json")
	if strings.Contains(out, `"failure"`) {
		t.Errorf("JSON without --fail carries a failure field:\n%s", out)
	}
}

func TestFailIsRefusedWhereItCannotApply(t *testing.T) {
	path := writeTopology(t, omittedInterfaceTopology)
	for _, args := range [][]string{
		{"--fail", "r2", "example.com"},
		{"--compare", "--fail", "r2", "a.ndoc", "b.ndoc"},
		{"--explain", path, "10.20.40.8", "--fail", ""},
		{"--explain", path, "10.20.40.8", "--fail", "r9"},
		{"--explain", path, "10.20.40.8", "--fail", "r1:eth7"},
		{"--explain", path, "10.20.40.8", "--fail", "r2:"},
		{"--explain", path, "10.20.40.8", "--fail", "r1"},
	} {
		if code, _, errOut := runNetdoc(t, args...); code != 2 || !strings.Contains(errOut, "-fail") {
			t.Errorf("netdoc %q = %d, stderr %q; want 2 naming -fail", args, code, errOut)
		}
	}
}

// ospfAdjacencyTopology is r1 -- r2 over one point-to-point OSPF adjacency that
// r1 records as full, with r1's OSPF route to the LAN behind r2 across it.
const ospfAdjacencyTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "lan", "addresses": ["10.20.40.8/24"]}]},
    {"source": "frr:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "control", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "attributes": [{"key": "ospf.network_type", "value": "point-to-point"}]}],
     "neighbors": [{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "remote_addr": "10.0.12.2",
       "attributes": [{"key": "ospf.state", "value": "Full"}]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "ospf", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]}
  ]
}`

func TestExplainFailOSPFReportsTheAdjacencyLoss(t *testing.T) {
	path := writeTopology(t, ospfAdjacencyTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1:r2", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Failure *routepath.Simulation `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	s := decoded.Failure
	want := routepath.Failure{Node: "r1", Interface: "eth1", VRF: "default", OSPFNeighbor: "r2"}
	if s == nil || s.Failure != want || s.Adjacency == nil || !s.Adjacency.Proven {
		t.Fatalf("failure = %+v, want the proven adjacency %+v", s, want)
	}
	// A single-homed OSPF destination is unknown, never lost: OSPF recomputes
	// its routes after the loss, which is not modeled.
	if len(s.Affected) != 1 || s.Affected[0].Destination != "10.20.40.8" || s.Affected[0].Impact != routepath.ImpactUnknown {
		t.Errorf("affected = %+v, want 10.20.40.8 unknown", s.Affected)
	}

	code, out, errOut = runNetdoc(t, "--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1:r2")
	if code != 0 || !strings.Contains(out, "Failure simulation: OSPF adjacency r1 (default) eth1 to r2 lost, from r1 (default)") || !strings.Contains(out, "unknown 10.20.40.8 (r2 default)") {
		t.Errorf("exit = %d, stderr %q, text:\n%s", code, errOut, out)
	}
}

func TestExplainFailRatesAnOSPFRouteLossLikeFailOSPF(t *testing.T) {
	// r1 reaches 10.20.40.8 only by its OSPF route across eth1. Taking either
	// end of the link down makes OSPF compute its routes again, as losing the
	// adjacency does, so the destination is unknown, never lost. r2 failing
	// takes the destination with it, which no recomputed path delivers.
	path := writeTopology(t, ospfAdjacencyTopology)
	for fail, want := range map[string]routepath.Impact{
		"r1:eth1": routepath.ImpactUnknown,
		"r2:eth0": routepath.ImpactUnknown,
		"r2":      routepath.ImpactReachabilityLost,
	} {
		code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--fail", fail, "--json")
		if code != 0 {
			t.Fatalf("--fail %s exit = %d, want 0; stderr: %s", fail, code, errOut)
		}
		var decoded struct {
			Failure *routepath.Simulation `json:"failure"`
		}
		if err := json.Unmarshal([]byte(out), &decoded); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, out)
		}
		i := slices.IndexFunc(decoded.Failure.Affected, func(a routepath.Affected) bool { return a.Destination == "10.20.40.8" })
		if i < 0 || decoded.Failure.Affected[i].Impact != want {
			t.Errorf("--fail %s affected = %+v, want 10.20.40.8 %s", fail, decoded.Failure.Affected, want)
		}
	}
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--fail", "r1:eth1")
	if want := "unknown 10.20.40.8 (r2 default): after the failure, a forwarding branch has no surviving recorded next hop, but r1 (default) holds an OSPF or BGP route toward it, in fib:r1 (ospf)"; code != 0 || !strings.Contains(out, want) {
		t.Errorf("exit = %d, stderr %q, text lacks %q:\n%s", code, errOut, want, out)
	}
}

func TestFailOSPFIsRefusedWhereItCannotApply(t *testing.T) {
	path := writeTopology(t, ospfAdjacencyTopology)
	for _, args := range [][]string{
		{"--fail-ospf", "r1:eth1:r2", "example.com"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", ""},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1:r2", "--fail", "r2"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r1::r2"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1:"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", ":eth1:r2"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r1:eth1:r9"},
		{"--explain", path, "10.20.40.8", "--fail-ospf", "r2:eth0:r1"},
	} {
		if code, _, errOut := runNetdoc(t, args...); code != 2 || !strings.Contains(errOut, "-fail-ospf") {
			t.Errorf("netdoc %q = %d, stderr %q; want 2 naming -fail-ospf", args, code, errOut)
		}
	}
}

// nextHopTopology is r1 on one LAN, eth0, with two gateways: r2 at 10.0.1.2
// and r4 at 10.0.1.4. r1 splits 10.20.0.0/16 over both toward r3, and reaches
// r2's LAN only through r2 and r4's LAN only through r4.
const nextHopTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.1.1/24"]}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.1.2/24"]}, {"name": "eth1", "addresses": ["10.0.23.2/30"]}, {"name": "lan", "addresses": ["10.30.0.1/24"]}]},
    {"source": "config:r4", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r4", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.1.4/24"]}, {"name": "eth1", "addresses": ["10.0.43.4/30"]}, {"name": "lan", "addresses": ["10.40.0.1/24"]}]},
    {"source": "config:r3", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r3", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.23.3/30"]}, {"name": "eth1", "addresses": ["10.0.43.3/30"]}, {"name": "lan", "addresses": ["10.20.40.8/24"]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [
       {"prefix": "10.0.1.0/24", "origin": "kernel", "next_hops": [{"interface": "eth0"}]},
       {"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.1.2", "interface": "eth0"}, {"addr": "10.0.1.4", "interface": "eth0"}]},
       {"prefix": "10.30.0.0/24", "origin": "kernel", "next_hops": [{"addr": "10.0.1.2", "interface": "eth0"}]},
       {"prefix": "10.40.0.0/24", "origin": "kernel", "next_hops": [{"addr": "10.0.1.4", "interface": "eth0"}]}]},
    {"source": "fib:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r2", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.23.3", "interface": "eth1"}]}]},
    {"source": "fib:r4", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r4", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.43.3", "interface": "eth1"}]}]}
  ]
}`

// linkLocalTopology starts in routing domain blue of r1, which reaches two
// LANs of r2 through one link-local next hop on two interfaces whose names hold
// a colon and a percent sign. r1's default domain names the same next hop.
const linkLocalTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "blue"},
  "observations": [
    {"source": "config:r1:blue", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "blue",
     "interfaces": [{"name": "Gi0/0:1", "addresses": ["fe80::1/64"]}, {"name": "ve%1", "addresses": ["fe80::1/64"]}]},
    {"source": "config:r2:blue", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "blue",
     "interfaces": [{"name": "Gi0/1", "addresses": ["fe80::2/64"]}, {"name": "lan", "addresses": ["2001:db8:50::1/64", "2001:db8:60::1/64"]}]},
    {"source": "fib:r1:blue", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "blue", "routes_complete": true,
     "routes": [
       {"prefix": "2001:db8:50::/64", "origin": "kernel", "next_hops": [{"addr": "fe80::2", "interface": "Gi0/0:1"}]},
       {"prefix": "2001:db8:60::/64", "origin": "kernel", "next_hops": [{"addr": "fe80::2", "interface": "ve%1"}]}]},
    {"source": "fib:r1:default", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "2001:db8:70::/64", "origin": "kernel", "next_hops": [{"addr": "fe80::2", "interface": "eth9"}]}]}
  ]
}`

// explainFailure runs --explain --json with the given failure flags and
// returns the simulation it reports.
func explainFailure(t *testing.T, topology, dest string, args ...string) *routepath.Simulation {
	t.Helper()
	code, out, errOut := runNetdoc(t, append([]string{"--explain", writeTopology(t, topology), dest, "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, errOut)
	}
	var decoded struct {
		Failure *routepath.Simulation `json:"failure"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil || decoded.Failure == nil {
		t.Fatalf("output has no failure: %v\n%s", err, out)
	}
	return decoded.Failure
}

func simImpacts(s *routepath.Simulation) map[string]routepath.Impact {
	out := map[string]routepath.Impact{}
	for _, a := range s.Affected {
		out[a.Destination] = a.Impact
	}
	return out
}

func TestExplainFailNextHopReportsTheGatewayLoss(t *testing.T) {
	s := explainFailure(t, nextHopTopology, "10.20.40.8", "--fail-next-hop", "r1:10.0.1.2")
	if want := (routepath.Failure{Node: "r1", VRF: "default", NextHop: "10.0.1.2"}); s.Failure != want {
		t.Errorf("failure = %+v, want %+v", s.Failure, want)
	}
	if s.Gateway == nil || len(s.Gateway.Owners) != 1 || s.Gateway.Owners[0] != (routepath.Start{Node: "r2", VRF: "default"}) {
		t.Errorf("gateway = %+v, want held by r2 (default)", s.Gateway)
	}
	want := map[string]routepath.Impact{"10.0.1.2": routepath.ImpactUnknown, "10.20.40.8": routepath.ImpactUnknown, "10.30.0.1": routepath.ImpactReachabilityLost}
	if got := simImpacts(s); !reflect.DeepEqual(got, want) {
		t.Errorf("impacts = %v, want %v", got, want)
	}

	path := writeTopology(t, nextHopTopology)
	code, out, errOut := runNetdoc(t, "--explain", path, "10.20.40.8", "--fail-next-hop", "r1:10.0.1.2%eth0")
	for _, want := range []string{
		"Failure simulation: next hop 10.0.1.2 on eth0 of r1 (default) unavailable, from r1 (default)",
		"Next hop: held by r2 (default); recorded in fib:r1.",
		"reachability_lost 10.30.0.1 (r2 default)",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("exit = %d, stderr %q, text lacks %q:\n%s", code, errOut, want, out)
		}
	}
}

func TestExplainFailNextHopReadsVRFAndInterfaceNames(t *testing.T) {
	for spec, lost := range map[string]string{
		"r1@blue:fe80::2%Gi0/0:1": "2001:db8:50::1",
		"r1@blue:fe80::2%ve%1":    "2001:db8:60::1",
	} {
		s := explainFailure(t, linkLocalTopology, "2001:db8:50::1", "--fail-next-hop", spec)
		_, iface, _ := strings.Cut(spec, "%")
		if want := (routepath.Failure{Node: "r1", VRF: "blue", NextHop: "fe80::2", Interface: iface}); s.Failure != want {
			t.Errorf("%s: failure = %+v, want %+v", spec, s.Failure, want)
		}
		if got := simImpacts(s); !reflect.DeepEqual(got, map[string]routepath.Impact{lost: routepath.ImpactReachabilityLost}) {
			t.Errorf("%s: impacts = %v, want only %s reachability_lost", spec, got, lost)
		}
	}
}

func TestSplitNextHopKeepsEachDelimiterInItsPlace(t *testing.T) {
	for _, c := range []struct{ spec, node, vrf, addr, iface string }{
		{"r1:10.0.1.2", "r1", "", "10.0.1.2", ""},
		{"r1:10.0.1.2%eth0", "r1", "", "10.0.1.2", "eth0"},
		{"r1@blue:10.0.1.2", "r1", "blue", "10.0.1.2", ""},
		{"r1:2001:db8:1::2", "r1", "", "2001:db8:1::2", ""},
		{"r1@blue:2001:db8:1::2", "r1", "blue", "2001:db8:1::2", ""},
		{"r1:fe80::1%swp1", "r1", "", "fe80::1", "swp1"},
		{"r1@blue:fe80::1%swp1", "r1", "blue", "fe80::1", "swp1"},
		{"r1:10.0.1.2%Gi0/0:1", "r1", "", "10.0.1.2", "Gi0/0:1"},
		{"r1:10.0.1.2%GigabitEthernet0/0/0.100", "r1", "", "10.0.1.2", "GigabitEthernet0/0/0.100"},
		{"r1:fe80::1%eth0%1", "r1", "", "fe80::1", "eth0%1"},
		{"r1:fe80::1%%", "r1", "", "fe80::1", "%"},
		{"r1@red@x:10.0.1.2", "r1", "red@x", "10.0.1.2", ""},
		// The address is checked against the file, not here.
		{"r1:10.0.1.2@x", "r1", "", "10.0.1.2@x", ""},
	} {
		node, vrf, addr, iface, ok := splitNextHop(c.spec)
		if !ok || node != c.node || vrf != c.vrf || addr != c.addr || iface != c.iface {
			t.Errorf("splitNextHop(%q) = %q %q %q %q %v, want %q %q %q %q", c.spec, node, vrf, addr, iface, ok, c.node, c.vrf, c.addr, c.iface)
		}
	}
	for _, spec := range []string{"", "r1", "r1:", ":10.0.1.2", "@blue:10.0.1.2", "r1@:10.0.1.2", "r1:10.0.1.2%", "r1:%eth0", "r1@blue"} {
		if _, _, _, _, ok := splitNextHop(spec); ok {
			t.Errorf("splitNextHop(%q) is ok, want it refused", spec)
		}
	}
}

func TestFailNextHopIsRefusedWhereItCannotApply(t *testing.T) {
	path := writeTopology(t, nextHopTopology)
	explain := func(spec string, extra ...string) []string {
		return append([]string{"--explain", path, "10.20.40.8", "--fail-next-hop", spec}, extra...)
	}
	const usage = "netdoc: -fail-next-hop needs -explain and node[@vrf]:address[%interface], and no -fail or -fail-ospf\n"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--fail-next-hop", "r1:10.0.1.2", "example.com"}, usage},
		{[]string{"--compare", "--fail-next-hop", "r1:10.0.1.2", "a.ndoc", "b.ndoc"}, usage},
		{explain(""), usage},
		{explain("r1:10.0.1.2", "--fail", "r2"), usage},
		{explain("r1:10.0.1.2", "--fail-ospf", "r1:eth0:r2"), usage},
		{explain("r1"), `netdoc: -fail-next-hop: "r1" is not node[@vrf]:address[%interface]` + "\n"},
		{explain("r1:"), `"r1:" is not node[@vrf]:address[%interface]`},
		{explain(":10.0.1.2"), `":10.0.1.2" is not`},
		{explain("@blue:10.0.1.2"), `"@blue:10.0.1.2" is not`},
		{explain("r1@:10.0.1.2"), `"r1@:10.0.1.2" is not`},
		{explain("r1:10.0.1.2%"), `"r1:10.0.1.2%" is not`},
		{explain("r1:10.0.1"), `netdoc: -fail-next-hop: next hop "10.0.1" is not an IP address` + "\n"},
		{explain("r1:010.0.1.2"), `next hop "010.0.1.2" is not an IP address`},
		{explain("r1:10.0.1.0/24"), `next hop "10.0.1.0/24" is not an IP address`},
		{explain("r1:[2001:db8::1]"), `next hop "[2001:db8::1]" is not an IP address`},
		{explain("r1:gw.example"), `next hop "gw.example" is not an IP address`},
		{explain("r1:fe80::1"), "netdoc: -fail-next-hop: link-local next hop fe80::1 needs an interface: r1:fe80::1%INTERFACE\n"},
		{explain("r9:10.0.1.2"), `no fib route of node "r9" names next hop 10.0.1.2`},
		{explain("r1:10.0.1.9"), `no fib route of node "r1" names next hop 10.0.1.9`},
		{explain("r1@blue:10.0.1.2"), `no fib route of node "r1" in routing domain "blue" names next hop 10.0.1.2`},
		{explain("r1:10.0.1.2%eth9"), "fib routes of r1 (default) name next hop 10.0.1.2 on eth0, not on eth9"},
	} {
		code, out, errOut := runNetdoc(t, c.args...)
		if code != 2 || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("netdoc %q = %d, stdout %q, stderr %q; want 2 and %q", c.args, code, out, errOut, c.want)
		}
	}

	path = writeTopology(t, linkLocalTopology)
	for spec, want := range map[string]string{
		"r1@blue:fe80::2":            "link-local next hop fe80::2 needs an interface: r1@blue:fe80::2%INTERFACE",
		"r1:fe80::2%Gi0/0:1":         "fib routes of node \"r1\" name next hop fe80::2 in routing domains blue, default; name one as r1@VRF:fe80::2",
		"r1@blue:fe80::2%Gi0/0":      "fib routes of r1 (blue) name next hop fe80::2 on Gi0/0:1, ve%1, not on Gi0/0",
		"r1@default:fe80::2%Gi0/0:1": "fib routes of r1 (default) name next hop fe80::2 on eth9, not on Gi0/0:1",
	} {
		code, _, errOut := runNetdoc(t, "--explain", path, "2001:db8:50::1", "--fail-next-hop", spec)
		if code != 2 || errOut != "netdoc: -fail-next-hop: "+want+"\n" {
			t.Errorf("%s: exit %d, stderr %q; want 2 and %q", spec, code, errOut, want)
		}
	}
}
