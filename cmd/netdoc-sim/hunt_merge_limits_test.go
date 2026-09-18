package main

// The hunt merge ingestion boundary. The library owns the budget, the shard
// ceiling and the structural limits simulation.DecodeHuntResult holds an input
// to; what these prove is that the command puts them in the right order: a
// merge refuses more inputs than a hunt can have been split into before it
// opens a file, refuses a result one byte over the budget before a decoder sees
// it, and still refuses a second top-level value once both are in place.
//
// The byte boundary is pinned against the reader rather than against files on
// disk. It is the same reader the command hands an opened file, the fill is
// generated rather than materialized, and one file-backed case keeps the
// command-line path honest, so proving the exact ceiling costs one oversized
// file instead of six.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/simulation"
)

// completeShardJSON is one whole hunt as a single shard: shard 0 of 1 owns
// every requested case, so one file is a complete and semantically valid merge
// input. Dry run, so no backend and no netdoc process is involved.
func completeShardJSON(t *testing.T) []byte {
	t.Helper()
	base, err := simulation.LibraryScenario("healthy-routed-network")
	if err != nil {
		t.Fatal(err)
	}
	shard := simulation.HuntShard{Index: 0, Count: 1}
	result := simulation.RunHunt(context.Background(), "healthy-routed-network", base, nil,
		simulation.HuntOptions{Cases: 4, Seed: 20260917, MaxFaults: 2, DryRun: true, Shard: &shard})
	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() >= simulation.HuntMaxResultBytes {
		t.Fatalf("fixture shard is already %d bytes, at or over the %d byte budget",
			buf.Len(), simulation.HuntMaxResultBytes)
	}
	return buf.Bytes()
}

// fillReader repeats one pattern, endlessly. Bounded by the io.LimitReader in
// sizedInput, which is what makes a multi-megabyte input cost nothing to build.
// The offset carries across reads, so a read that ends mid-pattern resumes
// where it stopped instead of restarting and splicing the pattern in half.
type fillReader struct {
	pattern string
	offset  int
}

func (f *fillReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.pattern[f.offset%len(f.pattern)]
		f.offset++
	}
	return len(p), nil
}

// sizedInput is prefix, then fill, then suffix, exactly total bytes long. The
// length is exact by construction rather than by measurement: io.LimitReader
// delivers precisely the remaining byte count. Nothing is taken on trust
// either, because a boundary pinned at total and total+1 cannot pass at both
// ends if this is off by one.
//
// A pattern of more than one byte only spells legal JSON when it lands whole,
// so whatever the fill cannot divide is taken up by JSON whitespace ahead of
// it. That keeps the total exact and the document valid at both ends of the
// boundary, whichever way the remainder falls.
func sizedInput(t *testing.T, prefix, suffix, fill string, total int) io.Reader {
	t.Helper()
	body := total - len(prefix) - len(suffix)
	if body < 0 {
		t.Fatalf("prefix and suffix are %d bytes, over the requested total %d", len(prefix)+len(suffix), total)
	}
	pad := body % len(fill)
	return io.MultiReader(strings.NewReader(prefix+strings.Repeat(" ", pad)),
		io.LimitReader(&fillReader{pattern: fill}, int64(body-pad)), strings.NewReader(suffix))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// oversizeMessage is the specific complaint a result over the budget has to
// draw, named once so every boundary case asserts the same one.
func oversizeMessage() string {
	return "hunt result exceeds the supported maximum of " + strconv.Itoa(simulation.HuntMaxResultBytes) + " bytes"
}

// TestHuntMergeAcceptsTheLargestGeneratedShard merges the widest shard the
// generator can build in a rootless test: HuntMaxCases cases, all of them in
// one shard, produced by the real hunt machinery rather than hand-written JSON.
// A normal multi-shard merge is covered by
// TestHuntMergeCommandReadsArbitraryFileOrder; what this adds is that the
// bounded read does not stand in the way of a result at the legal upper shape.
func TestHuntMergeAcceptsTheLargestGeneratedShard(t *testing.T) {
	base, err := simulation.LibraryScenario("healthy-routed-network")
	if err != nil {
		t.Fatal(err)
	}
	shard := simulation.HuntShard{Index: 0, Count: 1}
	result := simulation.RunHunt(context.Background(), "healthy-routed-network", base, nil,
		simulation.HuntOptions{Cases: simulation.HuntMaxCases, Seed: 20260917,
			MaxFaults: simulation.HuntMaxFaults, DryRun: true, Shard: &shard})
	if len(result.Cases) != simulation.HuntMaxCases {
		t.Fatalf("generated %d cases, want %d", len(result.Cases), simulation.HuntMaxCases)
	}
	var encoded bytes.Buffer
	if err := result.WriteJSON(&encoded); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "widest.json")
	writeFile(t, path, encoded.Bytes())
	t.Logf("largest generated shard the command line can build: %d of %d budgeted bytes",
		encoded.Len(), simulation.HuntMaxResultBytes)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"hunt", "merge", path}, &stdout, &stderr); code != exitOK {
		t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitOK, stderr.String())
	}
	var merged simulation.HuntResult
	if err := json.Unmarshal(stdout.Bytes(), &merged); err != nil {
		t.Fatal(err)
	}
	if err := simulation.ValidateMergedHuntResult(&merged); err != nil {
		t.Fatal(err)
	}
	if len(merged.Cases) != simulation.HuntMaxCases {
		t.Fatalf("merged %d cases, want %d", len(merged.Cases), simulation.HuntMaxCases)
	}
}

// TestHuntResultByteBoundaryIsExact pins N and N+1 on the accepted encoded
// size. Both inputs hold the same semantically valid shard; the only difference
// is the trailing whitespace that takes one of them one byte past the ceiling.
// The ceiling is the sum of the model's enforced section limits rather than a
// size a real shard reaches, so padding is what makes the exact boundary
// reachable at all, and trailing whitespace after a JSON document is legal
// input that has to stay accepted.
func TestHuntResultByteBoundaryIsExact(t *testing.T) {
	shard := string(completeShardJSON(t))

	if _, err := simulation.DecodeHuntResult(sizedInput(t, shard, "", " ", simulation.HuntMaxResultBytes)); err != nil {
		t.Fatalf("a result exactly on the ceiling was refused: %v", err)
	}
	_, err := simulation.DecodeHuntResult(sizedInput(t, shard, "", " ", simulation.HuntMaxResultBytes+1))
	if err == nil {
		t.Fatal("a result one byte over the ceiling was accepted")
	}
	if err.Error() != oversizeMessage() {
		t.Fatalf("error = %q, want %q", err, oversizeMessage())
	}
}

// TestHuntResultReadStopsAllocationShapedInput proves the byte boundary is what
// refuses a hostile shape, and that it is the size and nothing else that
// decides. Each shape appears twice: at the ceiling, where it is read whole and
// answered on its merits, and one byte over, where the size complaint is the
// answer. Both inputs are valid JSON documents that differ by one byte, so the
// size is the only thing left that can account for the difference, and a size
// check placed after the decoder could not tell them apart.
//
// Validity is what each shape is asserted on. A *json.SyntaxError would mean
// the input was malformed somewhere and the decoder stopped there rather than
// walking the whole document, so its absence is the proof that the shape is a
// real multi-megabyte string or array to its last byte. The array is pointed at
// a string-typed field on purpose: encoding/json scans a value it cannot store
// in full and reports the mismatch, which walks the entire array for a fixed
// amount of memory. Pointing it at case_results instead would make the decoder
// grow one 432 byte struct per element, tens of gigabytes at this ceiling, so
// the shape would prove the boundary by exhausting the machine behind it.
func TestHuntResultReadStopsAllocationShapedInput(t *testing.T) {
	for _, shape := range []struct {
		name string
		// prefix, fill and suffix spell a valid JSON document at any total
		// sizedInput is asked for, so the shape stays valid on both sides of
		// the boundary.
		prefix        string
		suffix        string
		fill          string
		wantTypeError bool
	}{
		// One string field holding the whole input.
		{"one enormous string", `{"base_scenario":"`, `"}`, "a", false},
		// One array holding millions of elements.
		{"one enormous array", `{"base_scenario":[`, `0]}`, "0,", true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			// At the ceiling the shape is decoded, so whatever comes back is
			// about its content. Only the size complaint is wrong here.
			_, err := simulation.DecodeHuntResult(sizedInput(t, shape.prefix, shape.suffix, shape.fill,
				simulation.HuntMaxResultBytes))
			var syntaxErr *json.SyntaxError
			if errors.As(err, &syntaxErr) {
				t.Fatalf("the shape at the ceiling is not valid JSON: %v", err)
			}
			if err != nil && err.Error() == oversizeMessage() {
				t.Fatalf("a result at the ceiling was refused for its size: %v", err)
			}
			var typeErr *json.UnmarshalTypeError
			if got := errors.As(err, &typeErr); got != shape.wantTypeError {
				t.Fatalf("the decoder answered %v, want a type mismatch = %v", err, shape.wantTypeError)
			}

			_, err = simulation.DecodeHuntResult(sizedInput(t, shape.prefix, shape.suffix, shape.fill,
				simulation.HuntMaxResultBytes+1))
			if err == nil {
				t.Fatal("an allocation-shaped result over the ceiling was accepted")
			}
			if err.Error() != oversizeMessage() {
				t.Fatalf("error = %q, want %q", err, oversizeMessage())
			}
		})
	}
}

// TestHuntMergeRefusesAnOversizeShardFile is the one file-backed size case: it
// keeps the command line itself honest, so the boundary proved against the
// reader above is known to be the boundary a merge applies to a real file, with
// the specific complaint and the usage exit code.
func TestHuntMergeRefusesAnOversizeShardFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize.json")
	// #nosec G304 -- path is inside t.TempDir.
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	total := simulation.HuntMaxResultBytes + 1
	written, err := io.Copy(file, sizedInput(t, `{"base_scenario":"`, `"}`, "a", total))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(total) {
		t.Fatalf("wrote %d bytes, want %d", written, total)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"hunt", "merge", path}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), oversizeMessage()) {
		t.Fatalf("stderr = %q, want %q", stderr.String(), oversizeMessage())
	}
}

// TestHuntMergeRefusesTooManyInputsBeforeOpeningAny pins the shard ceiling on
// the input count, and pins the order it is checked in. Every path is
// deliberately nonexistent, so an open would fail with certainty: at
// HuntMaxShards the merge reports the first path it could not read, which is
// only reachable by opening it, and at HuntMaxShards+1 it reports the count
// instead and never names a path at all.
func TestHuntMergeRefusesTooManyInputsBeforeOpeningAny(t *testing.T) {
	dir := t.TempDir()
	paths := func(n int) []string {
		out := make([]string, 0, n+2)
		out = append(out, "hunt", "merge")
		for i := 0; i < n; i++ {
			out = append(out, filepath.Join(dir, "absent-"+strconv.Itoa(i)+".json"))
		}
		return out
	}
	count := "accepts at most " + strconv.Itoa(simulation.HuntMaxShards) + " shard JSON files"

	var stdout, stderr bytes.Buffer
	if code := run(paths(simulation.HuntMaxShards), &stdout, &stderr); code != exitUsage {
		t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "read hunt result") {
		t.Fatalf("%d inputs did not reach the file open: %s", simulation.HuntMaxShards, stderr.String())
	}
	if strings.Contains(stderr.String(), count) {
		t.Fatalf("%d inputs was refused as too many: %s", simulation.HuntMaxShards, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(paths(simulation.HuntMaxShards+1), &stdout, &stderr); code != exitUsage {
		t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), count) {
		t.Fatalf("stderr = %q, want a complaint containing %q", stderr.String(), count)
	}
	// The ordering proof: nothing was opened, so no path can be named.
	if strings.Contains(stderr.String(), "read hunt result") || strings.Contains(stderr.String(), "absent-") {
		t.Fatalf("a path was opened before the count was refused: %s", stderr.String())
	}
}

// TestHuntMergeInputRulesSurviveTheBoundedRead keeps the input rules intact now
// that a bounded read stands in front of the decoder. The second top-level value
// matters most: decoding runs over a complete in-memory buffer, so the EOF that
// ends the trailing-value check is the file's own and never an artificial one
// the limiter produced mid-value. Malformed JSON already has its own case in
// TestHuntMergeCommandRejectsMalformedJSON.
func TestHuntMergeInputRulesSurviveTheBoundedRead(t *testing.T) {
	shard := string(completeShardJSON(t))
	dir := t.TempDir()
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{"a second top-level value", strings.TrimRight(shard, "\n") + ` {"second":"object"}`, "multiple JSON values"},
		{"trailing whitespace only", shard + "\n\t  \n", ""},
		{"empty file", "", "EOF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(test.name, " ", "-")+".json")
			writeFile(t, path, []byte(test.content))
			var stdout, stderr bytes.Buffer
			code := run([]string{"hunt", "merge", path}, &stdout, &stderr)
			if test.want == "" {
				if code != exitOK {
					t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitOK, stderr.String())
				}
				return
			}
			if code != exitUsage {
				t.Fatalf("merge exit = %d, want %d; stderr: %s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}
