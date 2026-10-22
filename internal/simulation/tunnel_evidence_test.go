package simulation

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// tunnelEvidenceEntry is what metadata.json records about one capture file: the
// node it came from, the exact command that produced it, its source label, and
// the UTC time that command ran.
type tunnelEvidenceEntry struct {
	Source      string    `json:"source"`
	Node        string    `json:"node"`
	Command     string    `json:"command"`
	CollectedAt time.Time `json:"collected_at"`
	File        string    `json:"file"`
}

// writeTunnelEvidence writes one case's evidence into dir, which must not exist or
// must be empty. Each capture is its own file, then metadata.json describes them
// and outcome.txt holds the case's path and dial table. A non-nil base is the
// topology the import merged onto, written as base-topology.json so the import can
// be run again from the evidence alone. SHA256SUMS comes last and lists every other
// file in dir, so a file the manifest does not cover is a file nothing wrote. Every
// file is created exclusively, so no capture overwrites another.
func writeTunnelEvidence(dir string, captures []routepath.TunnelCapture, base []byte, outcome string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil && len(entries) > 0:
		return fmt.Errorf("%s already holds %d entries; refusing to overwrite evidence", dir, len(entries))
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var meta []tunnelEvidenceEntry
	for _, c := range captures {
		file := c.Source + ".json"
		meta = append(meta, tunnelEvidenceEntry{Source: c.Source, Node: c.Node, Command: c.Command, CollectedAt: c.CollectedAt.UTC(), File: file})
		if err := writeNewFile(filepath.Join(dir, file), c.Data); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(dir, "metadata.json"), append(data, '\n')); err != nil {
		return err
	}
	if base != nil {
		if err := writeNewFile(filepath.Join(dir, "base-topology.json"), base); err != nil {
			return err
		}
	}
	if err := writeNewFile(filepath.Join(dir, "outcome.txt"), []byte(outcome)); err != nil {
		return err
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		return err
	}
	var sums bytes.Buffer
	for _, e := range entries {
		if e.Name() == "SHA256SUMS" {
			continue
		}
		if e.IsDir() {
			return fmt.Errorf("%s holds a directory, %s, which the manifest cannot cover", dir, e.Name())
		}
		b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, e.Name())))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(b), e.Name())
	}
	return writeNewFile(filepath.Join(dir, "SHA256SUMS"), sums.Bytes())
}

// writeNewFile creates path with data, failing if it already exists.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// testFileSum returns the SHA-256 of the file at path, in hex.
func testFileSum(t *testing.T, path string) string {
	t.Helper()
	return fmt.Sprintf("%x", sha256.Sum256([]byte(readTestFile(t, path))))
}

// TestWriteTunnelEvidenceCoversEveryFile writes one case and checks the manifest
// against the directory: every file but SHA256SUMS is listed with the hash it has
// on disk, and the outcome and metadata are among them.
func TestWriteTunnelEvidenceCoversEveryFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "case")
	first := time.Date(2026, 10, 21, 3, 14, 5, 123456789, time.UTC)
	captures := []routepath.TunnelCapture{
		{Source: "ip-link-r1", Node: "r1", Command: routepath.TunnelCommandIPLink, CollectedAt: first, Data: []byte("[{\"ifname\":\"gre1\"}]\n")},
		{Source: "ip-rule-r1", Node: "r1", Command: routepath.TunnelCommandRules, CollectedAt: first.Add(time.Second), Data: []byte("[]\n")},
	}
	const outcome = "path before the fault\n"
	if err := writeTunnelEvidence(dir, captures, []byte("{}\n"), outcome); err != nil {
		t.Fatal(err)
	}

	sums := readTestSums(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "SHA256SUMS" {
			continue
		}
		want, ok := sums[e.Name()]
		if !ok {
			t.Errorf("%s is on disk but not in SHA256SUMS", e.Name())
			continue
		}
		if got := testFileSum(t, filepath.Join(dir, e.Name())); got != want {
			t.Errorf("%s: SHA256SUMS has %s, the file hashes to %s", e.Name(), want, got)
		}
	}
	for name := range sums {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("SHA256SUMS lists %s, which is not on disk: %v", name, err)
		}
	}
	for _, name := range []string{"ip-link-r1.json", "ip-rule-r1.json", "base-topology.json", "metadata.json", "outcome.txt"} {
		if _, ok := sums[name]; !ok {
			t.Errorf("%s is not covered by SHA256SUMS", name)
		}
	}
	if got := readTestFile(t, filepath.Join(dir, "outcome.txt")); got != outcome {
		t.Errorf("outcome.txt = %q, want %q", got, outcome)
	}
}

// TestWriteTunnelEvidenceMetadataRoundTrips reads metadata.json back and checks it
// holds each capture's node, exact command, source label, file, and the UTC time
// that capture was collected.
func TestWriteTunnelEvidenceMetadataRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "case")
	first := time.Date(2026, 10, 21, 3, 14, 5, 123456789, time.UTC)
	captures := []routepath.TunnelCapture{
		{Source: "ip-link-r1", Node: "r1", Command: routepath.TunnelCommandIPLink, CollectedAt: first, Data: []byte("[]\n")},
		{Source: "ip-rule-r1", Node: "r1", Command: routepath.TunnelCommandRules, CollectedAt: first.Add(40 * time.Millisecond), Data: []byte("[]\n")},
	}
	if err := writeTunnelEvidence(dir, captures, nil, ""); err != nil {
		t.Fatal(err)
	}

	var got []tunnelEvidenceEntry
	if err := json.Unmarshal([]byte(readTestFile(t, filepath.Join(dir, "metadata.json"))), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(captures) {
		t.Fatalf("metadata lists %d captures, want %d", len(got), len(captures))
	}
	for i, c := range captures {
		e := got[i]
		if e.Source != c.Source || e.Node != c.Node || e.Command != c.Command || e.File != c.Source+".json" {
			t.Errorf("entry %d = %+v, want source %s node %s command %q file %s", i, e, c.Source, c.Node, c.Command, c.Source+".json")
		}
		if !e.CollectedAt.Equal(c.CollectedAt) {
			t.Errorf("entry %d collected %s, want %s", i, e.CollectedAt, c.CollectedAt)
		}
	}
	if raw := readTestFile(t, filepath.Join(dir, "metadata.json")); !strings.Contains(raw, "2026-10-21T03:14:05.123456789Z") {
		t.Errorf("metadata.json does not record the collection time in UTC: %s", raw)
	}
}

// TestWriteTunnelEvidenceRefusesAnExistingCase checks that a case directory which
// already holds files is refused and left as it was, and that a source label
// used twice is refused rather than overwriting its file.
func TestWriteTunnelEvidenceRefusesAnExistingCase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.json"), []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTunnelEvidence(dir, nil, nil, ""); err == nil {
		t.Fatal("wrote into a directory that already holds files")
	}
	if got := readTestFile(t, filepath.Join(dir, "old.json")); got != "kept\n" {
		t.Errorf("old.json changed to %q", got)
	}

	empty := filepath.Join(t.TempDir(), "case")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeTunnelEvidence(empty, nil, nil, ""); err != nil {
		t.Errorf("an empty directory is refused: %v", err)
	}

	twice := []routepath.TunnelCapture{
		{Source: "ip-link-r1", Node: "r1", Command: routepath.TunnelCommandIPLink, Data: []byte("a")},
		{Source: "ip-link-r1", Node: "r1", Command: routepath.TunnelCommandIPLink, Data: []byte("b")},
	}
	if err := writeTunnelEvidence(filepath.Join(t.TempDir(), "case"), twice, nil, ""); err == nil {
		t.Error("two captures with one source label were written")
	}
}

// readTestSums parses a SHA256SUMS file into a map from file name to hash.
func readTestSums(t *testing.T, dir string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(readTestFile(t, filepath.Join(dir, "SHA256SUMS"))), "\n") {
		hash, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q is not in sha256sum form", line)
		}
		sums[name] = hash
	}
	return sums
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
