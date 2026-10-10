package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Offline --two-sided output is pinned byte for byte. The golden files were
// captured from the build before route-path evidence existed, so any change to
// the no-evidence text, JSON, or exit code shows up here, not in a Contains check.
func TestTwoSidedNoEvidenceOutputIsByteStable(t *testing.T) {
	dir := filepath.Join("testdata", "twosided")
	here := filepath.Join(dir, "here.ndoc")
	there := filepath.Join(dir, "there.ndoc")
	cases := []struct {
		name   string
		paths  []string
		json   bool
		exit   int
		golden string
	}{
		{"divergent text", []string{here, there}, false, 1, "divergent.txt"},
		{"divergent json", []string{here, there}, true, 1, "divergent.json"},
		{"no failure text", []string{there, there}, false, 0, "no-failure.txt"},
		{"no failure json", []string{there, there}, true, 0, "no-failure.json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := runTwoSided(c.paths, map[string]bool{}, c.json, &stdout, &stderr); got != c.exit {
				t.Fatalf("exit = %d, want %d; stderr %q", got, c.exit, stderr.String())
			}
			want, err := os.ReadFile(filepath.Join(dir, "golden", c.golden))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stdout.Bytes(), want) {
				t.Fatalf("output drifted from %s\n--- got\n%s\n--- want\n%s", c.golden, stdout.String(), want)
			}
		})
	}
}
