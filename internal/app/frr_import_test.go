package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/frrospf"
	"github.com/heymaikol/network-doctor/internal/routepath"
)

// frrBcastDir holds the genuine broadcast-lab captures. Each .raw file is a vtysh
// transcript: the echoed command, the recorded output, and the prompt.
const frrBcastDir = "../../testdata/frr/10.7.0/bcast"

// stageFRRBcast copies the four broadcast captures into a new directory, unframed:
// the echoed command and the prompt are removed, as the frrospf fixtures remove
// them. It writes a manifest that names every capture and returns the manifest
// path. Each test edits its own copy, never the committed fixtures.
func stageFRRBcast(t *testing.T) (dir, manifest string) {
	t.Helper()
	dir = t.TempDir()
	specs := []struct{ stem, file, label, node, command string }{
		{"r1-show_ip_ospf_interface_json", "r1-interface.json", "r1 interface", "r1", "show ip ospf interface json"},
		{"r1-show_ip_ospf_neighbor_detail_json", "r1-neighbor.json", "r1 neighbor detail", "r1", "show ip ospf neighbor detail json"},
		{"r2-show_ip_ospf_interface_json", "r2-interface.json", "r2 interface", "r2", "show ip ospf interface json"},
		{"r2-show_ip_ospf_neighbor_detail_json", "r2-neighbor.json", "r2 neighbor detail", "r2", "show ip ospf neighbor detail json"},
	}
	var captures []any
	for _, s := range specs {
		raw, err := os.ReadFile(filepath.Join(frrBcastDir, s.stem+".raw"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n"), "\n")
		if len(lines) < 3 || lines[0] != s.command {
			t.Fatalf("%s: echoed command is not %q", s.stem, s.command)
		}
		payload := strings.Join(lines[1:len(lines)-1], "\n") + "\n"
		// #nosec G703 -- s.file is a literal name from this test's own table.
		if err := os.WriteFile(filepath.Join(dir, s.file), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		stamp, err := os.ReadFile(filepath.Join(frrBcastDir, s.stem+".collected_at"))
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, map[string]any{
			"file": s.file, "source": s.label, "node": s.node, "vrf": "default",
			"frr_version": frrospf.Version, "command": s.command,
			"collected_at": strings.TrimSpace(string(stamp)),
		})
	}
	manifest = filepath.Join(dir, "manifest.json")
	writeFRRJSON(t, manifest, map[string]any{"version": 1, "source_node": "r1", "captures": captures})
	return dir, manifest
}

func writeFRRJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// editFRRJSON changes one staged JSON file, decoded as an object. The manifest
// and each capture are edited this way.
func editFRRJSON(t *testing.T, path string, edit func(m map[string]any)) {
	t.Helper()
	// #nosec G304 -- path is a file this test staged in its own temporary directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	writeFRRJSON(t, path, m)
}

// frrReportFields decodes a JSON report into its top-level fields, so a test
// checks the names on the wire rather than the Go types that produced them.
func frrReportFields(t *testing.T, stdout string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &fields); err != nil {
		t.Fatalf("report is not one JSON object: %v\n%s", err, stdout)
	}
	return fields
}

// frrManifestCapture returns the capture entry at i of a staged manifest.
func frrManifestCapture(m map[string]any, i int) map[string]any {
	return m["captures"].([]any)[i].(map[string]any)
}

func TestFRRImportCompleteWritesATopologyThatReadsBack(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	target := filepath.Join(dir, "topology.json")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"Result: complete", "Topology: written to " + target} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report lacks %q:\n%s", want, stdout)
		}
	}
	// #nosec G304 -- target is this test's temporary output path.
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	file, err := routepath.Decode(data)
	if err != nil {
		t.Fatalf("the written topology does not decode: %v", err)
	}
	if file.Source != (routepath.Start{Node: "r1", VRF: "default"}) {
		t.Errorf("source = %+v, want r1 default", file.Source)
	}
	var interfaces, neighbors int
	for _, o := range file.Model.Observations() {
		interfaces += len(o.Interfaces)
		neighbors += len(o.Neighbors)
	}
	if interfaces != 4 || neighbors != 2 {
		t.Errorf("topology holds %d interfaces and %d neighbors; want 4 and 2", interfaces, neighbors)
	}
	for _, want := range []string{`"neighbors_complete": false`, `"routes_complete": false`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("topology lacks %s", want)
		}
	}
}

// The OSPF evidence alone never gives a route-path answer. The explanation must
// say the route is unknown, not that the path is broken or healthy.
func TestFRRImportedTopologyKeepsRoutePathUnknown(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	target := filepath.Join(dir, "topology.json")
	if code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target); code != 0 {
		t.Fatalf("import exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runNetdoc(t, "--explain", target, "10.20.0.1")
	if code != 0 {
		t.Fatalf("--explain exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "unknown: no complete table") {
		t.Errorf("route path is not unknown:\n%s", stdout)
	}
	if !strings.Contains(stdout, "neighbor_state [reported]") {
		t.Errorf("OSPF evidence missing from the explanation:\n%s", stdout)
	}
}

func TestFRRImportJSONReportKeepsItsWireShape(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	fields := frrReportFields(t, stdout)
	for _, key := range []string{"version", "manifest", "complete", "source_node", "neighbors_complete", "routes_complete",
		"counts", "captures", "records", "not_imported", "limitations", "topology"} {
		if _, ok := fields[key]; !ok {
			t.Errorf("report lacks %q", key)
		}
	}
	if string(fields["version"]) != "1" {
		t.Errorf("version = %s, want 1", fields["version"])
	}
	if string(fields["complete"]) != "true" {
		t.Errorf("complete = %s, want true", fields["complete"])
	}
	if string(fields["neighbors_complete"]) != "false" || string(fields["routes_complete"]) != "false" {
		t.Errorf("completeness claimed: neighbors %s routes %s", fields["neighbors_complete"], fields["routes_complete"])
	}
	var captures []map[string]any
	if err := json.Unmarshal(fields["captures"], &captures); err != nil || len(captures) != 4 {
		t.Fatalf("captures = %d entries, err %v; want 4", len(captures), err)
	}
	declared, ok := captures[0]["declared"].(map[string]any)
	if !ok || declared["frr_version"] != frrospf.Version {
		t.Errorf("first capture declared = %v; want the manifest's declared fields", captures[0]["declared"])
	}
	if captures[0]["accepted"] != true {
		t.Errorf("first capture accepted = %v, want true", captures[0]["accepted"])
	}
}

func TestFRRImportExitCodesFollowCompleteness(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(t *testing.T, dir, manifest string)
		write bool
		want  int
	}{
		{name: "complete", want: 0},
		{
			name: "a refused capture is incomplete",
			edit: func(t *testing.T, dir, manifest string) {
				editFRRJSON(t, manifest, func(m map[string]any) {
					frrManifestCapture(m, 2)["frr_version"] = "10.6.0"
				})
			},
			want: 1,
		},
		{
			name: "an unconfirmed neighbor record is incomplete",
			edit: func(t *testing.T, dir, manifest string) {
				editFRRJSON(t, filepath.Join(dir, "r2-interface.json"), func(m map[string]any) {
					delete(m["interfaces"].(map[string]any)["e2"].(map[string]any), "routerId")
				})
			},
			want: 1,
		},
		{
			name: "a source node with no interface capture is refused before reading",
			edit: func(t *testing.T, dir, manifest string) {
				editFRRJSON(t, manifest, func(m map[string]any) {
					m["captures"] = m["captures"].([]any)[1:]
				})
			},
			write: true,
			want:  2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, manifest := stageFRRBcast(t)
			if tc.edit != nil {
				tc.edit(t, dir, manifest)
			}
			args := []string{"--import-frr-ospf", manifest}
			target := filepath.Join(dir, "topology.json")
			if tc.write {
				args = append(args, "--write-topology", target)
			}
			code, stdout, stderr := runNetdoc(t, args...)
			if code != tc.want {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tc.want, stdout, stderr)
			}
			if _, err := os.Lstat(target); tc.want != 0 && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a failed import left a topology file behind: %v", err)
			}
		})
	}
}

// A partial import must not leave a topology behind, and must not leave a
// temporary file either.
func TestFRRImportIncompleteWritesNothing(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	editFRRJSON(t, manifest, func(m map[string]any) {
		frrManifestCapture(m, 2)["frr_version"] = "10.6.0"
	})
	target := filepath.Join(dir, "topology.json")
	code, stdout, _ := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(stdout, "Topology: not written: the import is incomplete") {
		t.Errorf("report does not say why no topology was written:\n%s", stdout)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "topology.json" || strings.HasPrefix(e.Name(), ".netdoc-topology-") {
			t.Errorf("an incomplete import left %s behind", e.Name())
		}
	}
}

// The unmapped record keeps its state, address, and reason in the report, so
// the reader sees what FRR said and why it was not used.
func TestFRRImportReportKeepsAnUnmappedRecord(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	editFRRJSON(t, filepath.Join(dir, "r2-interface.json"), func(m map[string]any) {
		delete(m["interfaces"].(map[string]any)["e2"].(map[string]any), "routerId")
	})
	code, stdout, _ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	var records []map[string]any
	if err := json.Unmarshal(frrReportFields(t, stdout)["records"], &records); err != nil {
		t.Fatal(err)
	}
	var unmapped map[string]any
	for _, r := range records {
		if r["mapped"] == false {
			unmapped = r
		}
	}
	if unmapped == nil {
		t.Fatalf("no unmapped record in the report:\n%s", stdout)
	}
	if unmapped["neighbor_address"] != "10.0.1.2" || unmapped["state"] != "Full/DR" {
		t.Errorf("unmapped record = %v; want its address and state kept", unmapped)
	}
	if reason, _ := unmapped["reason"].(string); !strings.Contains(reason, "unconfirmed") {
		t.Errorf("reason = %q; want the unconfirmed router ID named", reason)
	}
}

func TestFRRImportRefusesToOverwriteOutput(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	target := filepath.Join(dir, "topology.json")
	if err := os.WriteFile(target, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 2 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("exit %d, stderr %q; want 2 and an already-exists refusal", code, stderr)
	}
	// #nosec G304 -- target is this test's temporary output path.
	if data, _ := os.ReadFile(target); string(data) != "keep me\n" {
		t.Errorf("existing output changed to %q", data)
	}
}

func TestFRRImportRefusesAMissingOutputDirectory(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	target := filepath.Join(t.TempDir(), "absent", "topology.json")
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 2 {
		t.Fatalf("exit %d, stderr %q; want 2", code, stderr)
	}
	if _, err := os.Lstat(filepath.Dir(target)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the output directory was created: %v", err)
	}
}

// Each case fails at publish time. The result is exit 2, the target is left as
// it was, and no temporary file remains. The link factory receives the test's
// own t, so a failure inside it reports against the right test.
func TestFRRImportPublishFailuresLeaveTheTargetAlone(t *testing.T) {
	t.Cleanup(func() { linkFile = os.Link })
	cases := []struct {
		name   string
		racing bool
		link   func(t *testing.T, target string) func(oldname, newname string) error
		want   string
	}{
		{
			name: "hard links unsupported",
			link: func(_ *testing.T, _ string) func(string, string) error {
				return func(oldname, newname string) error {
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errors.New("operation not supported")}
				}
			},
			want: "hard links may be unsupported",
		},
		{
			name:   "target appears after the check",
			racing: true,
			link: func(t *testing.T, target string) func(string, string) error {
				return func(oldname, newname string) error {
					if err := os.WriteFile(target, []byte("racing writer\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: fs.ErrExist}
				}
			},
			want: "already exists; nothing was written",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, manifest := stageFRRBcast(t)
			target := filepath.Join(dir, "topology.json")
			linkFile = tc.link(t, target)
			code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target, "--json")
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, stderr, tc.want)
			}
			var topo map[string]any
			if err := json.Unmarshal(frrReportFields(t, stdout)["topology"], &topo); err != nil {
				t.Fatal(err)
			}
			if topo["written"] != false || !strings.Contains(fmt.Sprint(topo["reason"]), "not written") {
				t.Errorf("topology section = %v; want not written, with the reason", topo)
			}
			if tc.racing {
				// #nosec G304 -- target is this test's temporary output path.
				if data, _ := os.ReadFile(target); string(data) != "racing writer\n" {
					t.Errorf("the racing file was replaced: %q", data)
				}
			} else if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("a failed publish created the target: %v", err)
			}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".netdoc-topology-") {
					t.Errorf("temporary file %s was not removed", e.Name())
				}
			}
		})
	}
}

// A hard link names the same file, so one capture would count twice. The import
// refuses it, whatever the names are.
func TestFRRImportRefusesTwoCapturesThatAreOneFile(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	if err := os.Link(filepath.Join(dir, "r1-interface.json"), filepath.Join(dir, "alias.json")); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}
	editFRRJSON(t, manifest, func(m map[string]any) {
		c := frrManifestCapture(m, 1)
		c["file"] = "alias.json"
		c["source"] = "alias interface"
	})
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 2 || !strings.Contains(stderr, "same file") {
		t.Fatalf("exit %d, stderr %q; want 2 and a same-file refusal", code, stderr)
	}
}

func TestFRRImportRefusesUnsafeAndUnreadableCaptures(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, dir string, m map[string]any)
		want string
	}{
		{
			name: "absolute capture path",
			edit: func(_ *testing.T, _ string, m map[string]any) {
				frrManifestCapture(m, 0)["file"] = "/etc/passwd"
			},
			want: "must be a relative path",
		},
		{
			name: "capture path climbs out of the directory",
			edit: func(_ *testing.T, _ string, m map[string]any) {
				frrManifestCapture(m, 0)["file"] = "../r1-interface.json"
			},
			want: "must be a relative path",
		},
		{
			name: "capture file is missing",
			edit: func(t *testing.T, dir string, _ map[string]any) {
				if err := os.Remove(filepath.Join(dir, "r1-interface.json")); err != nil {
					t.Fatal(err)
				}
			},
			want: "captures[0] r1-interface.json:",
		},
		{
			name: "capture path is a directory",
			edit: func(t *testing.T, dir string, m map[string]any) {
				if err := os.Mkdir(filepath.Join(dir, "captures"), 0o700); err != nil {
					t.Fatal(err)
				}
				frrManifestCapture(m, 0)["file"] = "captures"
			},
			want: "is not a regular file",
		},
		{
			name: "capture is over the per-file limit",
			edit: func(t *testing.T, dir string, _ map[string]any) {
				if err := os.Truncate(filepath.Join(dir, "r1-interface.json"), frrospf.MaxCaptureBytes+1); err != nil {
					t.Fatal(err)
				}
			},
			want: "is larger than",
		},
		{
			name: "captures together are over the aggregate limit",
			edit: func(t *testing.T, dir string, m map[string]any) {
				base := frrManifestCapture(m, 0)
				var bulk []any
				for i := range 33 {
					name := fmt.Sprintf("bulk-%02d.json", i)
					if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
						t.Fatal(err)
					}
					// Sparse: the size is 1 MiB, the bytes are zero, and the disk use is small.
					if err := os.Truncate(filepath.Join(dir, name), frrospf.MaxCaptureBytes); err != nil {
						t.Fatal(err)
					}
					c := map[string]any{}
					for k, v := range base {
						c[k] = v
					}
					c["file"] = name
					c["source"] = fmt.Sprintf("bulk %02d", i)
					bulk = append(bulk, c)
				}
				m["captures"] = bulk
			},
			want: "together are larger than",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, manifest := stageFRRBcast(t)
			editFRRJSON(t, manifest, func(m map[string]any) { tc.edit(t, dir, m) })
			code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, stderr, tc.want)
			}
		})
	}
}

// A prompt left after the JSON is trailing data. The capture is refused, not
// read as if the prompt were not there.
func TestFRRImportRefusesATrailingPrompt(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	// #nosec G304 -- r1-interface.json is staged in this test's temporary directory.
	f, err := os.OpenFile(filepath.Join(dir, "r1-interface.json"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("r1> \n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, stdout)
	}
	var captures []map[string]any
	if err := json.Unmarshal(frrReportFields(t, stdout)["captures"], &captures); err != nil {
		t.Fatal(err)
	}
	if captures[0]["accepted"] != false {
		t.Errorf("capture with a trailing prompt accepted: %v", captures[0])
	}
}

func TestFRRImportRefusesMalformedManifests(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	if err := os.WriteFile(manifest, []byte(`{"version":1,"version":1,"captures":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 2 || !strings.Contains(stderr, `duplicate key "version"`) {
		t.Errorf("exit %d, stderr %q; want 2 and the duplicate key named", code, stderr)
	}
	missing := filepath.Join(t.TempDir(), "absent.json")
	if code, _, _ := runNetdoc(t, "--import-frr-ospf", missing); code != 2 {
		t.Errorf("missing manifest exit %d, want 2", code)
	}
}

// The import takes its manifest and optional output, and nothing that describes
// a probe run, another reading, or a finished run.
func TestFRRImportNeedsItsFlagsAndNoOthers(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"write without import", []string{"--write-topology", "x.json"}, "needs -import-frr-ospf"},
		{"import without a name", []string{"--import-frr-ospf", ""}, "needs a manifest file name"},
		{"write without a name", []string{"--import-frr-ospf", manifest, "--write-topology", ""}, "needs a file name"},
		{"explain", []string{"--import-frr-ospf", manifest, "--explain"}, "-explain cannot be combined"},
		{"compare", []string{"--import-frr-ospf", manifest, "--compare"}, "-compare cannot be combined"},
		{"two-sided", []string{"--import-frr-ospf", manifest, "--two-sided"}, "-two-sided cannot be combined"},
		{"route file", []string{"--import-frr-ospf", manifest, "--route-a", "x.json"}, "-route-a and -route-b need offline"},
		{"live target", []string{"--import-frr-ospf", manifest, "--via", "host"}, "-via cannot be combined"},
		{"probe timeout", []string{"--import-frr-ospf", manifest, "--timeout", "2s"}, "-timeout cannot be combined"},
		{"probe setting", []string{"--import-frr-ospf", manifest, "--public-dns", "8.8.8.8"}, "-public-dns cannot be combined"},
		{"version", []string{"--import-frr-ospf", manifest, "--version"}, "-version cannot be combined"},
		{"list checks", []string{"--import-frr-ospf", manifest, "--list-checks"}, "-list-checks cannot be combined"},
		{"positional target", []string{"--import-frr-ospf", manifest, "example.com"}, "unexpected arguments"},
		{"positional second file", []string{"--import-frr-ospf", manifest, "x.json"}, "unexpected arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runNetdoc(t, tc.args...)
			if code != 2 || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, stderr %q; want 2 and %q", code, stderr, tc.want)
			}
		})
	}
}

// A declared source node needs a default-VRF interface capture to write from,
// but a report alone needs none. Without the write, the records of a node with
// no interface capture stay unmapped, and the report names why.
func TestFRRImportReportWithoutSourceNodeInterface(t *testing.T) {
	_, manifest := stageFRRBcast(t)
	editFRRJSON(t, manifest, func(m map[string]any) {
		m["captures"] = m["captures"].([]any)[1:]
	})
	code, stdout, _ := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 1 {
		t.Fatalf("exit %d, want 1: records of a node with no interface capture stay unmapped", code)
	}
	if !strings.Contains(stdout, "has no accepted interface capture") {
		t.Errorf("report does not name the missing interface capture:\n%s", stdout)
	}
}

// Import reports are printed to a terminal, and every value in them comes from
// a file someone else wrote. Escape sequences must not reach the screen.
func TestFRRTextReportSanitizesEveryValue(t *testing.T) {
	r := frrReport{
		Manifest: "manifest\x1b]52;c;ZXZpbA==\a.json",
		Captures: []frrCapture{{
			File:     "r1\x1b[2J.json",
			Declared: frrDeclared{Source: "r1\x1b[31m", Node: "r1", VRF: "default", FRRVersion: "10.7.0", Command: "cmd", CollectedAt: "t"},
			Reason:   "refused\x1b[0m",
		}},
		Records: []frrRecord{{Node: "r1", LocalInterface: "e1", NeighborAddress: "10.0.1.2", State: "Full/DR", Area: "0.0.0.0", Reason: "bad\x1b[2K"}},
	}
	out := renderFRRText(r)
	if strings.ContainsRune(out, '\x1b') || strings.ContainsRune(out, '\a') {
		t.Errorf("report carries control characters: %q", out)
	}
}
