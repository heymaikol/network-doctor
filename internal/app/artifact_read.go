package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// runCompare reports what changed between two saved snapshots. It opens no
// socket: both arguments are files, and everything reported comes out of them.
//
// Exit code says whether anything changed, which is the question the command
// answers: 0 for two runs that describe the same diagnostic state, 1 for any
// meaningful difference, and 2 when an argument or an artifact is unusable, the
// same environment-is-wrong code the rest of the CLI spends. A snapshot that
// records a failed run is not itself an error here; a comparison is about
// change, not about health.
func runCompare(paths []string, setFlags map[string]bool, jsonOut bool, stdout, stderr io.Writer) int {
	if rejectRunFlags("compare", setFlags, stderr) {
		return 2
	}
	snapshots, ok := readSnapshotPair("compare", paths, "before"+snapshot.Extension+" after"+snapshot.Extension, stderr)
	if !ok {
		return 2
	}
	result := compare.Snapshots(snapshots[0], snapshots[1])
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	} else {
		fmt.Fprint(stdout, result.Text())
	}
	if result.Same() {
		return 0
	}
	return 1
}

// readSnapshotPair reads the two files a snapshot reading is given. Both
// readings take the same two arguments and refuse the same unusable files, so
// the rules are stated once: exactly two paths, one decoder, and the file that
// could not be read is named, because with two arguments which one is wrong is
// the useful half.
func readSnapshotPair(mode string, paths []string, usage string, stderr io.Writer) ([2]snapshot.Snapshot, bool) {
	var snapshots [2]snapshot.Snapshot
	if len(paths) != 2 {
		fmt.Fprintf(stderr, "netdoc: -%s needs two snapshot files: netdoc --%s %s\n", mode, mode, usage)
		return snapshots, false
	}
	for i, path := range paths {
		// #nosec G304 -- the path is the user's own argument, and reading the
		// file they named is the whole command.
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "netdoc: -%s: %s\n", mode, textsafe.Clean(err.Error()))
			return snapshots, false
		}
		// One decoder for both files, the same one that reads a snapshot
		// anywhere else, so the schema check and the row rules are stated once.
		s, err := snapshot.Decode(data)
		if err != nil {
			fmt.Fprintf(stderr, "netdoc: -%s: %s: %s\n", mode, textsafe.Clean(path), textsafe.Clean(err.Error()))
			return snapshots, false
		}
		snapshots[i] = s
	}
	return snapshots, true
}

// runTwoSided reads two snapshots of one target as two machines looking at it,
// and says which side the evidence places a failure on. Like --compare it opens
// no socket and runs no probe: both machines already did their probing, and
// this is the reading of what they recorded.
//
// Exit code says whether a failure was placed at all, which is the ordinary
// netdoc meaning of 1 rather than --compare's "something moved": 0 when no
// check failed on either machine, 1 when a failure was placed anywhere or the
// evidence could not place one, and 2 when an argument or an artifact is
// unusable. Two runs that observed different endpoints are exit 2 as well:
// unlike a comparison, a localization across two endpoints is not a question
// with an answer, since a row that failed against one host and passed against
// another says nothing about which machine is at fault.
func runTwoSided(paths []string, setFlags map[string]bool, jsonOut bool, stdout, stderr io.Writer) int {
	if rejectRunFlags("two-sided", setFlags, stderr) {
		return 2
	}
	snapshots, ok := readSnapshotPair("two-sided", paths, "here"+snapshot.Extension+" there"+snapshot.Extension, stderr)
	if !ok {
		return 2
	}
	result, err := compare.TwoSidedSnapshots(snapshots[0], snapshots[1])
	if err != nil {
		fmt.Fprintln(stderr, "netdoc: -two-sided:", textsafe.Clean(err.Error()))
		return 2
	}
	return emitTwoSided(result, jsonOut, result.Text(), stdout, stderr)
}
