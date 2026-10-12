package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// C8: the recorded steady r1 route table with the via key of 10.10.2.0/24
// spelled VIA is accepted, and the text report is byte-identical to the golden.
// The JSON report is not pinned here, because a folded hop key is now
// identified as ambiguous in the JSON.
func TestCharacterizeFoldedViaKeyLeavesTheTextReportAlone(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDB(t, dir, manifest, "steady", "r1")
	addFRRLSDB(t, dir, manifest, "steady", "r2")
	routeFile := filepath.Join(dir, "steady-r1-E-show_ip_ospf_route_json.json")
	// #nosec G304 -- routeFile is the staged capture this test wrote.
	raw, err := os.ReadFile(routeFile)
	if err != nil {
		t.Fatal(err)
	}
	anchor := `"10.10.2.0/24":{"routeType":"N","transit":false,"cost":20,"area":"0.0.0.0","nexthops":[{"ip":"10.0.1.2","via":"e1"`
	if n := strings.Count(string(raw), anchor); n != 1 {
		t.Fatalf("anchor occurs %d times; want 1", n)
	}
	edited := strings.Replace(string(raw), anchor, strings.Replace(anchor, `"via"`, `"VIA"`, 1), 1)
	writeFRRJSONRaw(t, routeFile, []byte(edited))

	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	assertGolden(t, filepath.Join(frrLSDBGoldenDir, "steady", "text.txt"), strings.ReplaceAll(stdout, manifest, "manifest.json"))
}

// C15: the import exits 0 when every capture is read, 1 when a capture is
// refused, and 2 for a manifest error.
func TestCharacterizeImportExitCodes(t *testing.T) {
	t.Run("0 complete", func(t *testing.T) {
		dir, manifest := stageFRRBcast(t)
		addFRRLSDB(t, dir, manifest, "steady", "r1")
		if code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest); code != 0 {
			t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})
	t.Run("1 refused capture", func(t *testing.T) {
		dir, manifest := stageFRRBcast(t)
		addFRRLSDB(t, dir, manifest, "kill9", "r1")
		editFRRJSON(t, manifest, func(m map[string]any) {
			for _, c := range m["captures"].([]any) {
				entry := c.(map[string]any)
				if entry["source"] == "kill9 r1 E" {
					writeFRRJSONRaw(t, filepath.Join(dir, entry["file"].(string)), []byte(`{"routerId":"1.1.1.1",`))
				}
			}
		})
		if code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest); code != 1 {
			t.Fatalf("exit %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})
	t.Run("2 manifest error", func(t *testing.T) {
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
		if code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest); code != 2 {
			t.Fatalf("exit %d, want 2\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})
}
