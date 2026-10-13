package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// frrBGPSteady holds the committed BGP transcripts. The tests read them and never
// write them.
const frrBGPSteady = "../../testdata/frr/10.7.0/bgp/steady"

// openRoot opens dir for this test. Each file the test reads or writes in dir is
// named relative to it, so no name can leave dir. The root closes when the test
// ends.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// stageFRRBGP copies the committed r1 and r2 summary transcripts and their
// collection times into a new directory, and writes a manifest that names both.
// The transcripts are copied byte for byte, so their framing is FRR's own. Each
// test edits its own copy, never the committed fixtures.
func stageFRRBGP(t *testing.T) (dir, manifest string) {
	t.Helper()
	dir = t.TempDir()
	steady := openRoot(t, frrBGPSteady)
	staged := openRoot(t, dir)
	var captures []any
	for _, node := range []string{"r1", "r2"} {
		file := node + "-show_ip_bgp_summary_json.raw"
		raw, err := steady.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := staged.WriteFile(file, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		stamp, err := steady.ReadFile(node + "-show_ip_bgp_summary_json.collected_at")
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, map[string]any{
			"file": file, "source": node + " bgp summary", "node": node, "vrf": "default",
			"frr_version": "10.7.0", "command": "show ip bgp summary json",
			"collected_at": strings.TrimSpace(string(stamp)),
		})
	}
	manifest = filepath.Join(dir, "manifest.json")
	writeFRRJSON(t, manifest, map[string]any{"version": 1, "captures": captures})
	return dir, manifest
}

// failWriter stands for a standard output that cannot take the report.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// partialWriter accepts the first 16 bytes it is given and then fails, as a
// standard output that fills part way through the report does.
type partialWriter struct{ buf bytes.Buffer }

func (w *partialWriter) Write(p []byte) (int, error) {
	n := min(len(p), 16)
	w.buf.Write(p[:n])
	return n, errors.New("disk full")
}

func TestFRRBGPStagedTranscriptsAreThePreservedBytes(t *testing.T) {
	steady := openRoot(t, frrBGPSteady)
	sums, err := steady.ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := stageFRRBGP(t)
	staged := openRoot(t, dir)
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasSuffix(fields[1], "_summary_json.raw") {
			continue
		}
		raw, err := staged.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != fields[0] {
			t.Errorf("%s hashes to %s, want %s: the staged copy is not the preserved transcript", fields[1], got, fields[0])
		}
		checked++
	}
	if checked != 2 {
		t.Fatalf("checked %d staged transcripts, want 2", checked)
	}
}

func TestFRRBGPImportReportsEstablishedAndActiveSessions(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"router ID 1.1.1.1, local AS 65001",
		"peer 10.0.1.2: remote AS 65002, local AS 65001, state Established",
		"peer 10.0.1.3: remote AS 65003, local AS 65001, state Active",
		"router ID 2.2.2.2, local AS 65002",
		"peer 10.0.1.1: remote AS 65001, local AS 65002, state Established",
		"declared (not verified): node r1, vrf default, FRR 10.7.0",
		"collected 2026-10-13T01:22:26.451780317Z",
		"Exit 0 does not mean any session is up.",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Index(stdout, "router ID 1.1.1.1") > strings.Index(stdout, "router ID 2.2.2.2") {
		t.Errorf("captures are out of manifest order:\n%s", stdout)
	}
	if n := strings.Count(stdout, "observed family: IPv4 unicast (summary section ipv4Unicast)"); n != 2 {
		t.Errorf("output names the observed family %d times, want once per capture:\n%s", n, stdout)
	}
}

func TestFRRBGPImportJSONIsItsOwnReport(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	fields := frrReportFields(t, stdout)
	for _, name := range []string{"version", "protocol", "manifest", "captures", "not_read", "limitations"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("report lacks %q", name)
		}
	}
	var rep frrBGPReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Version != 1 || rep.Protocol != "bgp" {
		t.Errorf("version = %d, protocol = %q; want 1 and bgp", rep.Version, rep.Protocol)
	}
	if len(rep.Captures) != 2 {
		t.Fatalf("captures = %d, want 2", len(rep.Captures))
	}
	peers := rep.Captures[0].Peers
	if len(peers) != 2 || peers[0].Address != "10.0.1.2" || peers[0].State != "Established" || peers[1].Address != "10.0.1.3" || peers[1].State != "Active" {
		t.Errorf("r1 peers = %+v, want 10.0.1.2 Established then 10.0.1.3 Active", peers)
	}
	// A summary carries no routes, so the report must not name any.
	if strings.Contains(stdout, `"routes"`) || strings.Contains(stdout, `"prefixes"`) {
		t.Errorf("report carries route fields:\n%s", stdout)
	}
}

// Each capture names the family its summary section was observed as. No peer
// carries one, since a peer's negotiated families are not read.
func TestFRRBGPImportJSONNamesTheObservedFamilyPerCapture(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	var captures []map[string]any
	if err := json.Unmarshal(frrReportFields(t, stdout)["captures"], &captures); err != nil {
		t.Fatal(err)
	}
	if len(captures) != 2 {
		t.Fatalf("captures = %d, want 2", len(captures))
	}
	for i, c := range captures {
		if got := c["observed_family"]; got != "IPv4 unicast" {
			t.Errorf("capture %d observed_family = %v, want \"IPv4 unicast\"", i, got)
		}
		for _, p := range c["peers"].([]any) {
			if _, ok := p.(map[string]any)["observed_family"]; ok {
				t.Errorf("capture %d: a peer carries observed_family; the family is observed per capture only", i)
			}
		}
	}
}

func TestFRRBGPImportLeavesTheOSPFReportAlone(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	_, stdout, _ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	fields := frrReportFields(t, stdout)
	if _, ok := fields["protocol"]; ok {
		t.Error("the OSPF report gained a protocol field")
	}
	if strings.Contains(stdout, "observed_family") {
		t.Error("the OSPF report gained an observed_family field")
	}
	if got := string(fields["version"]); got != "1" {
		t.Errorf("OSPF report version = %s, want 1", got)
	}
}

// A transcript whose prompt names another node is refused whole: exit 2, and no
// report reaches standard output.
func TestFRRBGPImportRefusesABadTranscriptWithNoReport(t *testing.T) {
	dir, manifest := stageFRRBGP(t)
	staged := openRoot(t, dir)
	name := "r1-show_ip_bgp_summary_json.raw"
	raw, err := staged.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(raw, []byte("\r\nr1> "), []byte("\r\nr9> "), 1)
	if bytes.Equal(mutated, raw) {
		t.Fatal("fixture prompt not found; the test cannot change it")
	}
	if err := staged.WriteFile(name, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest)
	if code != 2 || stdout != "" {
		t.Fatalf("exit = %d, stdout = %q; want exit 2 and no report", code, stdout)
	}
	if !strings.Contains(stderr, "prompt") {
		t.Errorf("stderr = %q, want the prompt named", stderr)
	}
}

// An empty peer collection is observed empty. The report says so, and it never
// says the session is down.
func TestFRRBGPImportObservedEmptyIsNotDown(t *testing.T) {
	dir, manifest := stageFRRBGP(t)
	staged := openRoot(t, dir)
	name := "r2-show_ip_bgp_summary_json.raw"
	raw, err := staged.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(raw, []byte(`"peers":{`))
	end := bytes.Index(raw, []byte(`"failedPeers"`))
	if start < 0 || end < start {
		t.Fatal("fixture layout changed; the peers object is not where the test expects it")
	}
	emptied := bytes.Join([][]byte{raw[:start], []byte("\"peers\":{},\r\n  "), raw[end:]}, nil)
	if err := staged.WriteFile(name, emptied, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "observed empty and not down") {
		t.Errorf("text does not say the collection is observed empty:\n%s", stdout)
	}
	if i := strings.Index(stdout, "router ID 2.2.2.2"); i < 0 || !strings.Contains(stdout[i:], "observed family: IPv4 unicast") {
		t.Errorf("the emptied capture does not name its observed family:\n%s", stdout)
	}
	if _, jsonOut, _ := runNetdoc(t, "--import-frr-bgp", manifest, "--json"); !strings.Contains(jsonOut, `"peers": []`) {
		t.Errorf("JSON peers is not an empty array:\n%s", jsonOut)
	}
}

// The manifest may name only the one command, FRR version, and VRF this import
// reads, and it may name one summary capture per node.
func TestFRRBGPImportRefusesWhatItDoesNotRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(m map[string]any)
		want string
	}{
		{"OSPF command", func(m map[string]any) { frrManifestCapture(m, 0)["command"] = "show ip ospf interface json" }, "is not read by -import-frr-bgp"},
		{"other FRR version", func(m map[string]any) { frrManifestCapture(m, 0)["frr_version"] = "10.6.0" }, "FRR version"},
		{"other VRF", func(m map[string]any) { frrManifestCapture(m, 0)["vrf"] = "blue" }, "VRF"},
		{"source_node", func(m map[string]any) { m["source_node"] = "r1" }, "refuses source_node"},
		{"two captures of one node", func(m map[string]any) { frrManifestCapture(m, 1)["node"] = "r1" }, "more than one summary capture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, manifest := stageFRRBGP(t)
			editFRRJSON(t, manifest, tc.edit)
			code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest)
			if code != 2 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want exit 2 with %q and no report", code, stdout, stderr, tc.want)
			}
		})
	}
}

// The BGP import takes its manifest and nothing else. Every other flag and
// argument is refused by name, and none reaches the OSPF import.
func TestFRRBGPImportNeedsItsFlagAndNoOthers(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"write-topology", []string{"--import-frr-bgp", manifest, "--write-topology", "topology.json"}, "-write-topology cannot be combined with -import-frr-bgp"},
		{"import-frr-ospf", []string{"--import-frr-bgp", manifest, "--import-frr-ospf", manifest}, "-import-frr-ospf cannot be combined with -import-frr-bgp"},
		{"explain", []string{"--import-frr-bgp", manifest, "--explain"}, "-explain cannot be combined with -import-frr-bgp"},
		{"compare", []string{"--import-frr-bgp", manifest, "--compare"}, "-compare cannot be combined"},
		{"two-sided", []string{"--import-frr-bgp", manifest, "--two-sided"}, "-two-sided cannot be combined"},
		{"version", []string{"--import-frr-bgp", manifest, "--version"}, "-version cannot be combined"},
		{"list-checks", []string{"--import-frr-bgp", manifest, "--list-checks"}, "-list-checks cannot be combined"},
		{"probe timeout", []string{"--import-frr-bgp", manifest, "--timeout", "2s"}, "-timeout cannot be combined"},
		{"probe setting", []string{"--import-frr-bgp", manifest, "--public-dns", "8.8.8.8"}, "-public-dns cannot be combined"},
		{"target", []string{"--import-frr-bgp", manifest, "example.com"}, "unexpected arguments"},
		{"second file", []string{"--import-frr-bgp", manifest, manifest}, "unexpected arguments"},
		{"no manifest name", []string{"--import-frr-bgp", ""}, "needs a manifest file name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runNetdoc(t, tc.args...)
			if code != 2 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want exit 2 containing %q", code, stdout, stderr, tc.want)
			}
		})
	}
}

// A standard output that cannot take the report is an output that cannot be
// used, so the import exits 2 and names the error, in both the text and JSON forms.
func TestFRRBGPImportWriteFailureExitsTwo(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	for _, jsonOut := range []bool{false, true} {
		var stderr bytes.Buffer
		code := runFRRBGPImport(map[string]bool{"import-frr-bgp": true}, manifest, jsonOut, failWriter{}, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "disk full") {
			t.Errorf("json = %v: exit = %d, stderr = %q; want exit 2 naming the write error", jsonOut, code, stderr.String())
		}
	}
}

// A standard output that takes part of the report and then fails is still a
// write failure. The test checks the exit and the error only. It makes no claim
// about what standard output holds, since part of the report may have arrived.
func TestFRRBGPImportPartialWriteFailureExitsTwo(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	for _, jsonOut := range []bool{false, true} {
		w := &partialWriter{}
		var stderr bytes.Buffer
		code := runFRRBGPImport(map[string]bool{"import-frr-bgp": true}, manifest, jsonOut, w, &stderr)
		if w.buf.Len() == 0 {
			t.Fatalf("json = %v: the writer took no bytes, so the partial write was not exercised", jsonOut)
		}
		if code != 2 || !strings.Contains(stderr.String(), "disk full") {
			t.Errorf("json = %v: exit = %d, stderr = %q; want exit 2 naming the write error", jsonOut, code, stderr.String())
		}
	}
}

func TestUsageNamesTheBGPImport(t *testing.T) {
	code, stdout, _ := runNetdoc(t, "--help")
	if code != 0 || !strings.Contains(stdout, "netdoc --import-frr-bgp manifest.json [--json]") {
		t.Errorf("exit = %d; usage does not name the BGP import:\n%s", code, stdout)
	}
}
