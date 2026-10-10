//go:build unix

package app

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A symbolic link named as a capture is refused, even when it points at a valid
// capture. The manifest must name the file itself.
func TestFRRImportRefusesASymlinkedCapture(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	if err := os.Remove(filepath.Join(dir, "r1-interface.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "r1-neighbor.json"), filepath.Join(dir, "r1-interface.json")); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest)
	if code != 2 || !strings.Contains(stderr, "is a symbolic link") {
		t.Fatalf("exit %d, stderr %q; want 2 and a symbolic-link refusal", code, stderr)
	}
}

// Lstat counts a dangling symbolic link as present, so the output is refused
// rather than written through the link.
func TestFRRImportRefusesADanglingSymlinkAsOutput(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	target := filepath.Join(dir, "topology.json")
	dangling := filepath.Join(dir, "nowhere.json")
	if err := os.Symlink(dangling, target); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target)
	if code != 2 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("exit %d, stderr %q; want 2 and an already-exists refusal", code, stderr)
	}
	if _, err := os.Lstat(dangling); !os.IsNotExist(err) {
		t.Errorf("the dangling link's target was created: %v", err)
	}
}

// A successful publish leaves the topology and no temporary file.
func TestFRRImportSuccessLeavesNoTemporaryFile(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	target := filepath.Join(dir, "topology.json")
	if code, _, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", target); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if strings.HasPrefix(e.Name(), ".netdoc-topology-") {
			t.Errorf("temporary file %s survived a successful publish", e.Name())
		}
	}
	if !slices.Contains(names, "topology.json") {
		t.Errorf("topology.json missing from %v", names)
	}
}
