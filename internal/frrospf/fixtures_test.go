package frrospf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixtureRoot holds the genuine FRR 10.7.0 lab captures. See its README.
var fixtureRoot = filepath.Join("..", "..", "testdata", "frr", "10.7.0")

// promptLine matches the vty prompt that ends every recorded output.
var promptLine = regexp.MustCompile(`^r\d+> ?$`)

// fixture loads one recorded capture from a lab scenario. CollectedAt comes from
// the scenario's collected_at file, and Data is the unframed payload. The test
// declares the Source label, the node, the VRF, and the FRR version.
func fixture(tb testing.TB, scenario, node, command string) Capture {
	tb.Helper()
	stem := node + "-" + strings.ReplaceAll(command, " ", "_")
	return loadCapture(tb, scenario, stem, node, command, scenario+" "+node+" "+command)
}

// earlyNBMANeighbors is the neighbor-detail dump taken 15 seconds into the NBMA
// lab, while the static neighbor was still in Attempt. See the README.
func earlyNBMANeighbors(tb testing.TB) Capture {
	tb.Helper()
	return loadCapture(tb, "nbma", "r1-early-show_ip_ospf_neighbor_detail_json", "r1",
		CommandNeighborDetail, "nbma r1 early "+CommandNeighborDetail)
}

// loadCapture reads the raw output and collected_at file named stem in scenario.
func loadCapture(tb testing.TB, scenario, stem, node, command, source string) Capture {
	tb.Helper()
	dir := filepath.Join(fixtureRoot, scenario)
	raw := readFile(tb, filepath.Join(dir, stem+".raw"))
	stamp := readFile(tb, filepath.Join(dir, stem+".collected_at"))
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(string(stamp)))
	if err != nil {
		tb.Fatalf("collected_at for %s: %v", stem, err)
	}
	return Capture{
		Node:        node,
		VRF:         "default",
		Source:      source,
		CollectedAt: at,
		FRRVersion:  Version,
		Command:     command,
		Data:        unframe(tb, raw, command),
	}
}

func readFile(tb testing.TB, path string) []byte {
	tb.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return data
}

// unframe removes the vty framing from a recorded output: the echoed command
// on the first line and the prompt on the last. Line endings are normalized to
// LF. It fails when the echo is not the command the caller declares, so a
// mislabeled fixture cannot pass.
func unframe(tb testing.TB, raw []byte, command string) []byte {
	tb.Helper()
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) < 3 {
		tb.Fatalf("recorded output has %d lines; want echo, payload, prompt", len(lines))
	}
	if lines[0] != command {
		tb.Fatalf("echoed command %q is not the declared command %q", lines[0], command)
	}
	last := lines[len(lines)-1]
	if !promptLine.MatchString(last) {
		tb.Fatalf("last line %q is not a vty prompt", last)
	}
	return []byte(strings.Join(lines[1:len(lines)-1], "\n") + "\n")
}

// replaceOnce returns data with its single occurrence of old replaced by new.
// The anchor must be unique, so a mutation cannot land somewhere unintended.
func replaceOnce(tb testing.TB, data []byte, old, new string) []byte {
	tb.Helper()
	s := string(data)
	if n := strings.Count(s, old); n != 1 {
		tb.Fatalf("mutation anchor %q occurs %d times; want 1", old, n)
	}
	return []byte(strings.Replace(s, old, new, 1))
}

// mutateJSON decodes data, applies edit, and encodes the result. It is for
// structural edits that a byte anchor cannot express.
func mutateJSON(tb testing.TB, data []byte, edit func(top map[string]any)) []byte {
	tb.Helper()
	var top map[string]any
	if err := json.Unmarshal(data, &top); err != nil {
		tb.Fatal(err)
	}
	edit(top)
	out, err := json.Marshal(top)
	if err != nil {
		tb.Fatal(err)
	}
	return append(out, '\n')
}

// broadcastCaptures is the genuine broadcast lab: both routers' interface and
// neighbor-detail output.
func broadcastCaptures(tb testing.TB) []Capture {
	tb.Helper()
	return []Capture{
		fixture(tb, "bcast", "r1", CommandInterface),
		fixture(tb, "bcast", "r1", CommandNeighborDetail),
		fixture(tb, "bcast", "r2", CommandInterface),
		fixture(tb, "bcast", "r2", CommandNeighborDetail),
	}
}
