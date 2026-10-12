package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The LSDB report is pinned byte for byte for each recorded scenario. The golden
// files were written from the import path before the route evidence changed,
// so any change to the text or JSON report shows up here. The staged manifest
// lives in a temporary directory, and the text report prints its path, so the
// path is replaced with manifest.json before the comparison.
func TestFRRImportLSDBReportIsByteStable(t *testing.T) {
	cases := []struct {
		name  string
		nodes []string // nodes of the scenario named by the case
	}{
		{"steady", []string{"r1", "r2"}},
		{"flap", []string{"r1", "r2"}},
		{"kill9", []string{"r1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, manifest := stageFRRBcast(t)
			for _, node := range c.nodes {
				addFRRLSDB(t, dir, manifest, c.name, node)
			}
			// The JSON report escapes each backslash of the manifest path, so a Windows
			// path appears twice: plain in the text, and doubled in the JSON.
			escaped, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			quoted := strings.Trim(string(escaped), `"`)
			norm := func(s string) string {
				return strings.ReplaceAll(strings.ReplaceAll(s, quoted, "manifest.json"), manifest, "manifest.json")
			}
			code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
			if code != 0 {
				t.Fatalf("text exit %d, want 0; stderr %q", code, stderr)
			}
			codeJ, stdoutJ, stderrJ := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
			if codeJ != 0 {
				t.Fatalf("json exit %d, want 0; stderr %q", codeJ, stderrJ)
			}
			goldenDir := filepath.Join(frrLSDBGoldenDir, c.name)
			assertGolden(t, filepath.Join(goldenDir, "text.txt"), norm(stdout))
			assertGolden(t, filepath.Join(goldenDir, "json.json"), norm(stdoutJ))
		})
	}
}

// frrLSDBGoldenDir holds the pinned LSDB report of each scenario.
const frrLSDBGoldenDir = "testdata/lsdb/golden"

// assertGolden fails when got differs from the golden file at path.
func assertGolden(t *testing.T, path, got string) {
	t.Helper()
	// #nosec G304 -- path is built from this test's own table of golden files.
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("output drifted from %s\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}
