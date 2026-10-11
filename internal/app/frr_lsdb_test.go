package app

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/frrospf"
	"github.com/heymaikol/network-doctor/internal/ospf"
)

// frrLSDBDir holds the recorded OSPF LSDB lab, one directory per scenario. Each
// .raw file is a vtysh transcript, framed the same way as the broadcast captures.
const frrLSDBDir = "../../testdata/frr/10.7.0/lsdb"

// lsdbRoles are the four bracket captures of one node, in the order the lab took
// them, with the command each one declares.
var lsdbRoles = []struct{ role, command string }{
	{"A", frrospf.CommandProcessState},
	{"B", frrospf.CommandLSDB},
	{"E", frrospf.CommandRoute},
	{"D", frrospf.CommandProcessState},
}

// addFRRLSDB stages the bracket captures of one node of one LSDB lab scenario
// into dir and appends them to the manifest. Each capture is unframed as the
// broadcast captures are, and its declared collection time comes from the lab.
func addFRRLSDB(t *testing.T, dir, manifest, scenario, node string) {
	t.Helper()
	// #nosec G304 -- manifest is a file this test staged in its own temporary directory.
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	captures := m["captures"].([]any)
	for _, r := range lsdbRoles {
		stem := node + "-" + r.role + "-" + strings.ReplaceAll(r.command, " ", "_")
		// #nosec G304 -- the lab directory and stem are this test's own table.
		framed, err := os.ReadFile(filepath.Join(frrLSDBDir, scenario, stem+".raw"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(framed), "\r\n", "\n"), "\n"), "\n")
		if len(lines) < 3 || lines[0] != r.command {
			t.Fatalf("%s: echoed command is not %q", stem, r.command)
		}
		file := scenario + "-" + stem + ".json"
		payload := strings.Join(lines[1:len(lines)-1], "\n") + "\n"
		// #nosec G703 -- file is built from this test's own table.
		if err := os.WriteFile(filepath.Join(dir, file), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		// #nosec G304 -- the lab directory and stem are this test's own table.
		stamp, err := os.ReadFile(filepath.Join(frrLSDBDir, scenario, stem+".collected_at"))
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, map[string]any{
			"file": file, "source": fmt.Sprintf("%s %s %s", scenario, node, r.role),
			"node": node, "vrf": "default", "frr_version": frrospf.Version,
			"command": r.command, "collected_at": strings.TrimSpace(string(stamp)),
		})
	}
	m["captures"] = captures
	writeFRRJSON(t, manifest, m)
}

// writeFRRJSONRaw writes data as a staged capture file.
func writeFRRJSONRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// frrTopologyBytes reads a written topology file.
func frrTopologyBytes(t *testing.T, path string) []byte {
	t.Helper()
	// #nosec G304 -- path is this test's own temporary output file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The LSDB captures add a comparison, and they must not change the topology. The
// same broadcast captures, with and without the LSDB captures, must write the
// same bytes.
func TestFRRImportLSDBCapturesLeaveTheTopologyByteIdentical(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	plain := filepath.Join(dir, "plain.json")
	if code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", plain); code != 0 {
		t.Fatalf("plain import exit %d: %s", code, stderr)
	}
	addFRRLSDB(t, dir, manifest, "steady", "r1")
	addFRRLSDB(t, dir, manifest, "steady", "r2")
	withLSDB := filepath.Join(dir, "with-lsdb.json")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", withLSDB, "--json")
	if code != 0 {
		t.Fatalf("LSDB import exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if string(frrTopologyBytes(t, plain)) != string(frrTopologyBytes(t, withLSDB)) {
		t.Fatal("the LSDB captures changed the written topology")
	}
	fields := frrReportFields(t, stdout)
	if _, ok := fields["ospf_lsdb"]; !ok {
		t.Fatal("report has no ospf_lsdb section")
	}
	if !strings.Contains(stdout, "the OSPF link-state database: read for the ospf_lsdb section only") {
		t.Error("not_imported does not name the LSDB reading")
	}
}

// A report without LSDB captures keeps its old wording and has no ospf_lsdb
// section.
func TestFRRImportWithoutLSDBKeepsTheLegacyReport(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if _, ok := frrReportFields(t, stdout)["ospf_lsdb"]; ok {
		t.Fatal("legacy report carries an ospf_lsdb section")
	}
	if !strings.Contains(stdout, "the OSPF link-state database: not read") {
		t.Error("legacy report lost its not-read line")
	}
}

// The killed-neighbor bracket reaches the text and JSON reports. Interface and
// neighbor captures come from the broadcast lab, and the LSDB captures from the
// kill9 lab, so this checks the wiring of the comparison, not a whole network.
func TestFRRImportReportsTheKilledNeighborFindings(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "kill9", "r1")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"OSPF LSDB comparison:",
		"lsdb_prefix_not_calculated (consistent_with):",
		"No calculated route has that prefix.",
		"10.20.0.0/24",
		"10.10.2.0/24",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text report lacks %q:\n%s", want, stdout)
		}
	}
	jsonCode, jsonOut, _ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if jsonCode != 0 {
		t.Fatalf("JSON exit %d", jsonCode)
	}
	var rep struct {
		OSPFLSDB struct {
			Nodes []struct {
				Node     string `json:"node"`
				Findings []struct {
					Kind   string `json:"kind"`
					Prefix string `json:"prefix"`
				} `json:"findings"`
			} `json:"nodes"`
		} `json:"ospf_lsdb"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range rep.OSPFLSDB.Nodes {
		if n.Node != "r1" {
			t.Errorf("finding for node %s; only r1 has LSDB captures", n.Node)
		}
		for _, f := range n.Findings {
			got = append(got, f.Kind+" "+f.Prefix)
		}
	}
	want := []string{
		"lsdb_prefix_not_calculated 10.20.0.0/24",
		"lsdb_prefix_not_calculated 10.10.2.0/24",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("JSON findings = %q; want %q", got, want)
	}
}

// A refused LSDB capture makes the import incomplete: exit 1, and no topology is
// written, as for any other refused capture.
func TestFRRImportRefusedLSDBCaptureExitsOneAndWritesNothing(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "kill9", "r1")
	// Replace the staged LSDB capture with a truncated one, found by its source label.
	editFRRJSON(t, manifest, func(m map[string]any) {
		for _, c := range m["captures"].([]any) {
			entry := c.(map[string]any)
			if entry["source"] == "kill9 r1 B" {
				writeFRRJSONRaw(t, filepath.Join(dir, entry["file"].(string)), []byte(`{"routerId":"1.1.1.1",`))
			}
		}
	})
	target := filepath.Join(dir, "topology.json")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("topology written for an incomplete import: %v", err)
	}
	if !strings.Contains(stdout, "not written: the import is incomplete") {
		t.Errorf("report does not say the topology was withheld:\n%s", stdout)
	}
}

// A node with one process-state capture, not two, is a manifest error: exit 2,
// before any capture is read.
func TestFRRImportMissingProcessStateIsAManifestError(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "kill9", "r1")
	editFRRJSON(t, manifest, func(m map[string]any) {
		var kept []any
		for _, c := range m["captures"].([]any) {
			if c.(map[string]any)["source"] != "kill9 r1 D" {
				kept = append(kept, c)
			}
		}
		m["captures"] = kept
	})
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr, "needs exactly 2") {
		t.Errorf("stderr lacks the count refusal: %s", stderr)
	}
}

// A node with no finding still shows what its captures reported. The facts are
// the process state, the advertisements, and the calculated routes, each with
// its source, so the report is not only the findings.
func TestFRRImportLSDBTextShowsTheReportedFacts(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "kill9", "r1")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, want := range []string{
		"router ID 1.1.1.1, holdtime maximum 5000 ms, SPF delay 0 ms",
		"area 0.0.0.0: SPF executed 5",
		"rows matched",
		"router advertisement 1.1.1.1 from 1.1.1.1, area 0.0.0.0",
		"prefixes 10.0.1.0/24, 10.10.1.0/24",
		"external advertisement 10.20.0.0 from 2.2.2.2, AS scope",
		"10.0.1.0/24, type N, cost 10, area 0.0.0.0, next hops 1",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text report lacks %q:\n%s", want, stdout)
		}
	}
}

// The facts block is bounded. A list with more items than its limit shows the
// first ones and a count of the rest. Two renders of one report are identical.
func TestLSDBTextFactsAreBoundedAndDeterministic(t *testing.T) {
	at := time.Date(2026, 10, 11, 2, 39, 0, 0, time.UTC)
	node := ospf.NodeReport{
		Node: "r1", VRF: "default", Guard: ospf.Guard{Passed: true},
		LSDBRead:   &ospf.ReadInfo{Source: "lsdb.json", CollectedAt: at},
		RoutesRead: &ospf.ReadInfo{Source: "routes.json", CollectedAt: at},
	}
	for i := range 25 {
		node.LSAs = append(node.LSAs, ospf.LSAFact{
			LSA: ospf.LSA{Type: ospf.LSAExternal, LinkStateID: fmt.Sprintf("10.%d.0.0", i), AdvertisingRouter: "2.2.2.2",
				Sequence: "80000001", Checksum: 1, Prefixes: []ospf.Prefix{{Prefix: netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", i))}}},
			Use: "compared",
		})
		node.Routes = append(node.Routes, ospf.Route{Prefix: netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/24", i)), RouteType: "N", Cost: 10, NextHops: 1})
	}
	var many []ospf.Prefix
	for i := range 9 {
		many = append(many, ospf.Prefix{Prefix: netip.MustParsePrefix(fmt.Sprintf("192.0.%d.0/24", i))})
	}
	// The router LSA comes first, so the 20-item cut cannot hide its prefixes.
	router := ospf.LSAFact{LSA: ospf.LSA{Type: ospf.LSARouter, Area: "0.0.0.0", LinkStateID: "3.3.3.3", AdvertisingRouter: "3.3.3.3", Sequence: "80000001", Prefixes: many}, Use: "compared"}
	node.LSAs = append([]ospf.LSAFact{router}, node.LSAs...)
	rep := &ospf.LSDBReport{Nodes: []ospf.NodeReport{node}}

	var first, second strings.Builder
	renderLSDB(&first, rep)
	renderLSDB(&second, rep)
	if first.String() != second.String() {
		t.Fatal("two renders of one report differ")
	}
	out := first.String()
	for _, want := range []string{"... 6 more advertisements", "... 5 more routes", "and 4 more"} {
		if !strings.Contains(out, want) {
			t.Errorf("bounded facts lack %q:\n%s", want, out)
		}
	}
	// Each list shows its first twenty items. The router LSA and twenty-five
	// routes are in the report, so the counts below are exact.
	if n := strings.Count(out, " advertisement "); n != lsdbFactLimit {
		t.Errorf("advertisement lines = %d; want %d", n, lsdbFactLimit)
	}
	if n := strings.Count(out, ", type N, cost "); n != lsdbFactLimit {
		t.Errorf("route lines = %d; want %d", n, lsdbFactLimit)
	}
}
