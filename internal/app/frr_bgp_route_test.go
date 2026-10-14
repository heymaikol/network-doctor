package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/frrospf"
)

// frrBGPRouteEntry is the manifest entry for the show ip bgp json capture of node. The
// capture is staged as node-show_ip_bgp_json.raw.
func frrBGPRouteEntry(node, stamp string) map[string]any {
	return map[string]any{
		"file": node + "-show_ip_bgp_json.raw", "source": node + " bgp table", "node": node, "vrf": "default",
		"frr_version": "10.7.0", "command": "show ip bgp json", "collected_at": stamp,
	}
}

// committedRouteTable returns the committed route table of node and its collection
// time. Neither is changed.
func committedRouteTable(t *testing.T, node string) ([]byte, string) {
	t.Helper()
	steady := openRoot(t, frrBGPSteady)
	raw, err := steady.ReadFile(node + "-show_ip_bgp_json.raw")
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := steady.ReadFile(node + "-show_ip_bgp_json.collected_at")
	if err != nil {
		t.Fatal(err)
	}
	return raw, strings.TrimSpace(string(stamp))
}

// addFRRBGPCapture writes raw as the file that entry names in dir, then appends entry to
// the staged manifest.
func addFRRBGPCapture(t *testing.T, dir, manifest string, entry map[string]any, raw []byte) {
	t.Helper()
	if err := openRoot(t, dir).WriteFile(entry["file"].(string), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	editFRRJSON(t, manifest, func(m map[string]any) {
		m["captures"] = append(m["captures"].([]any), entry)
	})
}

// stageFRRBGPRoutes stages the two committed summaries, then the two committed route
// tables. Each node has one of each, and the route tables are manifest entries 2 and 3.
func stageFRRBGPRoutes(t *testing.T) (dir, manifest string) {
	t.Helper()
	dir, manifest = stageFRRBGP(t)
	for _, node := range []string{"r1", "r2"} {
		raw, stamp := committedRouteTable(t, node)
		addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry(node, stamp), raw)
	}
	return dir, manifest
}

// replaceStaged replaces the one occurrence of old in a staged file. It fails the test
// unless old occurs exactly once, so a stale needle cannot leave the file unchanged.
func replaceStaged(t *testing.T, dir, file, old, repl string) {
	t.Helper()
	staged := openRoot(t, dir)
	raw, err := staged.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte(old)); n != 1 {
		t.Fatalf("%s: %q occurs %d times, want 1", file, old, n)
	}
	if err := staged.WriteFile(file, bytes.Replace(raw, []byte(old), []byte(repl), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeStaged replaces a staged file with raw.
func writeStaged(t *testing.T, dir, file string, raw []byte) {
	t.Helper()
	if err := openRoot(t, dir).WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// frrBGPTableFrame frames a route table body the way FRR's VTY prints it for node: the
// echo, the body with CRLF line ends, and the node's prompt.
func frrBGPTableFrame(node, body string) []byte {
	return []byte("show ip bgp json\r\n" + strings.ReplaceAll(body, "\n", "\r\n") + "\r\n" + node + "> ")
}

// runBGPJSON runs the BGP import on manifest with --json and decodes the report. The test
// fails unless the exit code is 0.
func runBGPJSON(t *testing.T, manifest string) (frrBGPReport, string) {
	t.Helper()
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	var rep frrBGPReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	return rep, stdout
}

// TestFRRBGPStagedRouteTablesArePreservedBytes checks that the route tables a test stages
// hash to the digests SHA256SUMS records.
func TestFRRBGPStagedRouteTablesArePreservedBytes(t *testing.T) {
	sums, err := openRoot(t, frrBGPSteady).ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := stageFRRBGPRoutes(t)
	staged := openRoot(t, dir)
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.HasSuffix(fields[1], "-show_ip_bgp_json.raw") {
			continue
		}
		raw, err := staged.ReadFile(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != fields[0] {
			t.Errorf("%s hashes to %s, want %s: the staged copy is not the preserved table", fields[1], got, fields[0])
		}
		checked++
	}
	if checked != 2 {
		t.Fatalf("checked %d staged route tables, want 2", checked)
	}
}

// The committed r1 table has one path for 10.10.2.0/24, from peer 10.0.1.2. The committed
// r2 table has the same prefix with peerId (unspec), so it is counted and never learned.
func TestFRRBGPRouteTablesReportLearnedAndNotLearned(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	rep, stdout := runBGPJSON(t, manifest)
	if len(rep.RouteTables) != 2 {
		t.Fatalf("route tables = %d, want 2", len(rep.RouteTables))
	}
	r1, r2 := rep.RouteTables[0], rep.RouteTables[1]
	if r1.File != "r1-show_ip_bgp_json.raw" || r1.Protocol != "bgp" || r1.RouterID != "1.1.1.1" || r1.LocalAS != 65001 || r1.VRFName != "default" {
		t.Errorf("r1 table = %+v, want file r1-show_ip_bgp_json.raw, protocol bgp, router ID 1.1.1.1, local AS 65001, VRF default", r1)
	}
	if d := r1.Declared; d.Source != "r1 bgp table" || d.Node != "r1" || d.VRF != "default" || d.Command != "show ip bgp json" || d.CollectedAt != "2026-10-13T01:22:29.612752736Z" {
		t.Errorf("r1 declared = %+v, want its source, node, VRF, command, and collection time", d)
	}
	want := frrBGPLearnedRoute{Prefix: "10.10.2.0/24", Peer: "10.0.1.2", PathFrom: "external", ASPath: "65002", BGPOrigin: "IGP", NextHops: []string{"10.0.1.2"}}
	if r1.Prefixes != 1 || len(r1.Learned) != 1 || !reflect.DeepEqual(r1.Learned[0], want) || r1.NoPeerPaths != 0 || r1.UnknownPaths != 0 {
		t.Errorf("r1 = prefixes %d, learned %+v, no peer %d, unknown %d; want one learned route %+v", r1.Prefixes, r1.Learned, r1.NoPeerPaths, r1.UnknownPaths, want)
	}
	if r2.RouterID != "2.2.2.2" || r2.LocalAS != 65002 || r2.Prefixes != 1 || r2.NoPeerPaths != 1 || r2.UnknownPaths != 0 || len(r2.Learned) != 0 {
		t.Errorf("r2 = %+v, want one prefix, one path with no peer, and no learned route", r2)
	}
	if !strings.Contains(stdout, `"learned_routes": []`) {
		t.Errorf("r2 learned_routes is not an empty array:\n%s", stdout)
	}

	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest)
	for _, line := range []string{
		"Route tables (2)",
		"printed by FRR: router ID 1.1.1.1, local AS 65001, VRF default",
		"prefixes: 1; learned paths: 1; not learned: 0 with peerId (unspec), 0 with no peer ID naming a peer",
		"learned route 10.10.2.0/24 from peer 10.0.1.2: path from external, AS path 65002, BGP origin IGP, next hops 10.0.1.2",
		"printed by FRR: router ID 2.2.2.2, local AS 65002, VRF default",
		"prefixes: 1; learned paths: 0; not learned: 1 with peerId (unspec), 0 with no peer ID naming a peer",
		"no path names a peer, so no route is reported as learned",
		"collected 2026-10-13T01:22:35.923164705Z",
	} {
		if !strings.Contains(text, line) {
			t.Errorf("text lacks %q:\n%s", line, text)
		}
	}
	// Text and JSON agree: every learned route in the JSON appears in the text.
	for _, rt := range rep.RouteTables {
		for _, l := range rt.Learned {
			if line := fmt.Sprintf("learned route %s from peer %s:", l.Prefix, l.Peer); !strings.Contains(text, line) {
				t.Errorf("text lacks %q, which the JSON report carries", line)
			}
		}
	}
}

// A summary-only manifest keeps the report it had before: the same six top-level keys, no
// route_tables key, the same not_read and limitations lines, and no route text.
func TestFRRBGPSummaryOnlyReportIsUnchanged(t *testing.T) {
	_, manifest := stageFRRBGP(t)
	_, stdout := runBGPJSON(t, manifest)
	fields := frrReportFields(t, stdout)
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	// findings is the one key a summary with peers adds; route_tables stays out.
	if want := []string{"captures", "findings", "limitations", "manifest", "not_read", "protocol", "version"}; !slices.Equal(keys, want) {
		t.Errorf("top-level keys = %q, want %q", keys, want)
	}
	var notRead, limitations []string
	if err := json.Unmarshal(fields["not_read"], &notRead); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fields["limitations"], &limitations); err != nil {
		t.Fatal(err)
	}
	wantNotRead := []string{
		"routes and prefixes: not read; the summary carries none, so no route is claimed",
		"routing table, FIB, and kernel installation: not read",
		"nodes and peers that no capture names: unknown, not down",
		"session state after its collection time: not observed",
	}
	wantLimitations := []string{
		"declared metadata (source, node, VRF, FRR version, command, collection time) is the manifest's claim; netdoc checks the FRR version, the command, the VRF, and that the transcript prompt names the declared node, but cannot verify which router produced a capture",
		"each state is the JSON state field FRR printed at collection; peerState is not read",
		"the observed family names the summary section FRR printed; it does not establish which address families any session negotiated",
		"exit 0 means every capture is valid; it does not mean any session is Established or that the network is healthy",
		"an empty peer collection is observed empty; it is not reported as a down session",
	}
	if !slices.Equal(notRead, wantNotRead) {
		t.Errorf("not_read = %q, want %q", notRead, wantNotRead)
	}
	if !slices.Equal(limitations, wantLimitations) {
		t.Errorf("limitations = %q, want %q", limitations, wantLimitations)
	}
	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest)
	if strings.Contains(text, "Route tables") || strings.Contains(text, "learned route") {
		t.Errorf("summary-only text names route tables:\n%s", text)
	}
}

// A node with a summary and no route table has its routes not read. The report does not
// say that node has no routes, and it does not say a route was withdrawn.
func TestFRRBGPRouteTableMissingForANodeIsNotRead(t *testing.T) {
	dir, manifest := stageFRRBGP(t)
	raw, stamp := committedRouteTable(t, "r1")
	addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry("r1", stamp), raw)
	rep, stdout := runBGPJSON(t, manifest)
	if len(rep.RouteTables) != 1 || rep.RouteTables[0].Declared.Node != "r1" {
		t.Fatalf("route tables = %+v, want r1 alone", rep.RouteTables)
	}
	for _, want := range []string{"a node with no such capture has its routes not read", "does not show that a route was withdrawn"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report lacks %q:\n%s", want, stdout)
		}
	}
}

// A manifest may name a route table for a node with no summary. The table is checked and
// reported, and no summary is claimed for the node.
func TestFRRBGPRouteTableWithoutSummaryIsReported(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	editFRRJSON(t, manifest, func(m map[string]any) {
		m["captures"] = m["captures"].([]any)[2:]
	})
	rep, _ := runBGPJSON(t, manifest)
	if len(rep.Captures) != 0 || len(rep.RouteTables) != 2 {
		t.Errorf("captures = %d, route tables = %d; want 0 and 2", len(rep.Captures), len(rep.RouteTables))
	}
}

// An empty table is observed empty at collection time. The report does not call it a
// withdrawal.
func TestFRRBGPRouteTableEmptyIsObservedEmpty(t *testing.T) {
	dir, manifest := stageFRRBGP(t)
	_, stamp := committedRouteTable(t, "r1")
	raw := frrBGPTableFrame("r1", `{"routerId": "1.1.1.1", "localAS": 65001, "vrfName": "default", "routes": {}} `)
	addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry("r1", stamp), raw)
	rep, stdout := runBGPJSON(t, manifest)
	if len(rep.RouteTables) != 1 || rep.RouteTables[0].Prefixes != 0 || len(rep.RouteTables[0].Learned) != 0 {
		t.Fatalf("route tables = %+v, want one empty table", rep.RouteTables)
	}
	if !strings.Contains(stdout, `"learned_routes": []`) {
		t.Errorf("learned_routes is not an empty array:\n%s", stdout)
	}
	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest)
	if !strings.Contains(text, "table holds no prefixes: observed empty at collection time; this is not a withdrawal") {
		t.Errorf("text does not say the table is observed empty:\n%s", text)
	}
}

// One prefix has two learned paths, from 10.0.1.3 and 10.0.1.2. Another path names
// (unspec), and a third has no peerId. The learned paths keep FRR's order, and the two
// others are counted but never listed.
func TestFRRBGPRouteTableMultiplePeers(t *testing.T) {
	dir, manifest := stageFRRBGP(t)
	_, stamp := committedRouteTable(t, "r1")
	raw := frrBGPTableFrame("r1", `{"routerId": "1.1.1.1", "localAS": 65001, "vrfName": "default", "routes": {
 "10.10.2.0/24": [
  {"valid": true, "bestpath": true, "pathFrom": "external", "peerId": "10.0.1.3", "path": "65003", "origin": "IGP", "nexthops": [{"ip": "10.0.1.3"}]},
  {"valid": true, "pathFrom": "external", "peerId": "10.0.1.2", "path": "65002", "origin": "IGP", "nexthops": [{"ip": "10.0.1.2"}]}
 ],
 "10.20.0.0/16": [
  {"pathFrom": "external", "peerId": "(unspec)", "path": "", "origin": "IGP", "nexthops": [{"ip": "0.0.0.0"}]}
 ],
 "10.30.0.0/16": [
  {"pathFrom": "external", "path": "65004", "origin": "IGP", "nexthops": [{"ip": "10.0.1.4"}]}
 ]
}} `)
	addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry("r1", stamp), raw)
	rep, _ := runBGPJSON(t, manifest)
	rt := rep.RouteTables[0]
	if rt.Prefixes != 3 || rt.NoPeerPaths != 1 || rt.UnknownPaths != 1 || len(rt.Learned) != 2 {
		t.Fatalf("table = prefixes %d, no peer %d, unknown %d, learned %+v; want 3, 1, 1, and two learned routes", rt.Prefixes, rt.NoPeerPaths, rt.UnknownPaths, rt.Learned)
	}
	if rt.Learned[0].Peer != "10.0.1.3" || rt.Learned[1].Peer != "10.0.1.2" || rt.Learned[0].Prefix != "10.10.2.0/24" {
		t.Errorf("learned = %+v, want 10.0.1.3 then 10.0.1.2 for 10.10.2.0/24", rt.Learned)
	}
	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest)
	first, second := strings.Index(text, "from peer 10.0.1.3"), strings.Index(text, "from peer 10.0.1.2")
	if first < 0 || second < first {
		t.Errorf("text does not list the two learned paths in FRR's order:\n%s", text)
	}
	if !strings.Contains(text, "prefixes: 3; learned paths: 2; not learned: 1 with peerId (unspec), 1 with no peer ID naming a peer") {
		t.Errorf("text counts do not match:\n%s", text)
	}
	if strings.Contains(text, "10.20.0.0/16") || strings.Contains(text, "10.30.0.0/16") {
		t.Errorf("text lists a prefix that has no learned path:\n%s", text)
	}
}

// A table of 25 learned routes lists 20 in text and says how many more there are. The JSON
// report keeps all 25.
func TestFRRBGPRouteTableTextLimitKeepsEveryRouteInJSON(t *testing.T) {
	var body strings.Builder
	body.WriteString(`{"routerId": "1.1.1.1", "localAS": 65001, "vrfName": "default", "routes": {`)
	for i := range 25 {
		if i > 0 {
			body.WriteString(",")
		}
		fmt.Fprintf(&body, `"10.%d.0.0/16": [{"pathFrom": "external", "peerId": "10.0.1.2", "path": "65002", "origin": "IGP", "nexthops": [{"ip": "10.0.1.2"}]}]`, i)
	}
	body.WriteString("} } ")
	dir, manifest := stageFRRBGP(t)
	_, stamp := committedRouteTable(t, "r1")
	addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry("r1", stamp), frrBGPTableFrame("r1", body.String()))
	rep, _ := runBGPJSON(t, manifest)
	if got := len(rep.RouteTables[0].Learned); got != 25 {
		t.Errorf("JSON learned routes = %d, want 25", got)
	}
	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest)
	if got := strings.Count(text, "\n    learned route "); got != frrBGPLearnedLimit {
		t.Errorf("text lists %d learned routes, want %d:\n%s", got, frrBGPLearnedLimit, text)
	}
	for _, want := range []string{"... 5 more learned routes; see --json", "prefixes: 25; learned paths: 25"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}

// Each refused staging exits 2 and writes no report, and names the reason. The route
// tables are the committed ones, changed one way at a time.
func TestFRRBGPRouteTableRefusals(t *testing.T) {
	const r1Table, r1Summary = "r1-show_ip_bgp_json.raw", "r1-show_ip_bgp_summary_json.raw"
	for _, tc := range []struct {
		name  string
		stage func(t *testing.T, dir, manifest string)
		want  string
	}{
		{"second route table for a node", func(t *testing.T, dir, manifest string) {
			raw, stamp := committedRouteTable(t, "r1")
			entry := frrBGPRouteEntry("r1", stamp)
			entry["file"], entry["source"] = "r1-again.raw", "r1 again"
			addFRRBGPCapture(t, dir, manifest, entry, raw)
		}, "has more than one route table"},
		{"route table names another router", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, `"routerId": "1.1.1.1"`, `"routerId": "9.9.9.9"`)
		}, "but its summary names"},
		{"route table names another local AS", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, `"localAS": 65001`, `"localAS": 65009`)
		}, "but its summary names"},
		{"route table names another VRF", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, `"vrfName": "default"`, `"vrfName": "blue"`)
		}, `vrfName "blue" is not "default"`},
		{"route table with another node's prompt", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, "\r\nr1> ", "\r\nr9> ")
		}, "prompt"},
		{"summary transcript in the route table's place", func(t *testing.T, dir, manifest string) {
			raw, err := openRoot(t, frrBGPSteady).ReadFile(r1Summary)
			if err != nil {
				t.Fatal(err)
			}
			writeStaged(t, dir, r1Table, raw)
		}, "command echo"},
		{"route table in the summary's place", func(t *testing.T, dir, manifest string) {
			raw, _ := committedRouteTable(t, "r1")
			writeStaged(t, dir, r1Summary, raw)
		}, "command echo"},
		{"no closing brace", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, "} \r\nr1> ", " \r\nr1> ")
		}, "not a JSON object"},
		{"tab before the CRLF", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, "} \r\nr1> ", "}\t\r\nr1> ")
		}, "not a JSON object"},
		{"duplicate key in the table", func(t *testing.T, dir, manifest string) {
			replaceStaged(t, dir, r1Table, `"totalRoutes": 1`, `"totalRoutes": 1, "totalRoutes": 1`)
		}, "duplicate key"},
		{"oversized route table", func(t *testing.T, dir, manifest string) {
			writeStaged(t, dir, r1Table, bytes.Repeat([]byte(" "), frrospf.MaxCaptureBytes+1))
		}, "larger than"},
		{"command the import does not read", func(t *testing.T, dir, manifest string) {
			editFRRJSON(t, manifest, func(m map[string]any) { frrManifestCapture(m, 2)["command"] = "show ip route json" })
		}, "is not read by -import-frr-bgp"},
		{"other FRR version for a route table", func(t *testing.T, dir, manifest string) {
			editFRRJSON(t, manifest, func(m map[string]any) { frrManifestCapture(m, 2)["frr_version"] = "10.6.0" })
		}, "FRR version"},
		{"other VRF declared for a route table", func(t *testing.T, dir, manifest string) {
			editFRRJSON(t, manifest, func(m map[string]any) { frrManifestCapture(m, 2)["vrf"] = "blue" })
		}, "VRF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, manifest := stageFRRBGPRoutes(t)
			tc.stage(t, dir, manifest)
			code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest)
			if code != 2 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q; want exit 2 with %q and no report", code, stdout, stderr, tc.want)
			}
		})
	}
}

// A route table may precede its node's summary in the manifest.
// The importer must match evidence by node rather than manifest position.
// Each output collection preserves its own manifest-relative order.
func TestFRRBGPRouteBeforeSummaryInManifest(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)

	editFRRJSON(t, manifest, func(m map[string]any) {
		entries := m["captures"].([]any)
		if len(entries) != 4 {
			t.Fatalf("captures = %d, want 4", len(entries))
		}

		// r2 route, r1 summary, r1 route, r2 summary.
		m["captures"] = []any{
			entries[3],
			entries[0],
			entries[2],
			entries[1],
		}
	})

	rep, _ := runBGPJSON(t, manifest)

	if len(rep.Captures) != 2 {
		t.Fatalf("summaries = %d, want 2", len(rep.Captures))
	}
	if len(rep.RouteTables) != 2 {
		t.Fatalf("route tables = %d, want 2", len(rep.RouteTables))
	}

	if rep.Captures[0].Declared.Node != "r1" ||
		rep.Captures[1].Declared.Node != "r2" {
		t.Errorf("summary ordering incorrect: %+v", rep.Captures)
	}

	if rep.RouteTables[0].Declared.Node != "r2" ||
		rep.RouteTables[1].Declared.Node != "r1" {
		t.Errorf("route table ordering incorrect: %+v", rep.RouteTables)
	}

	if rep.RouteTables[0].RouterID != "2.2.2.2" ||
		rep.RouteTables[0].LocalAS != 65002 {
		t.Error("r2 route table identity incorrect")
	}

	if rep.RouteTables[1].RouterID != "1.1.1.1" ||
		rep.RouteTables[1].LocalAS != 65001 {
		t.Error("r1 route table identity incorrect")
	}

	if len(rep.RouteTables[0].Learned) != 0 {
		t.Error("r2 local path incorrectly classified as learned")
	}

	if len(rep.RouteTables[1].Learned) != 1 ||
		rep.RouteTables[1].Learned[0].Peer != "10.0.1.2" {
		t.Error("r1 learned route missing or incorrectly attributed")
	}
}
