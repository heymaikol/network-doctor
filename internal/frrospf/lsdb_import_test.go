package frrospf

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/ospf"
)

var lsdbStart = time.Date(2026, 10, 11, 2, 35, 26, 550000000, time.UTC)

func processOutcome(source string, at time.Time) outcome {
	return outcome{capture: Capture{Node: "r1", VRF: "default", Source: source, CollectedAt: at, Command: CommandProcessState}}
}

// TestProcessPairAtDistinctTimesIsAccepted is the failing-before check for the
// process-state pair. The OSPF comparison needs two process states, A and D, so
// markDuplicates must not refuse exactly two of them taken at different times.
func TestProcessPairAtDistinctTimesIsAccepted(t *testing.T) {
	outcomes := []outcome{
		processOutcome("r1 A", lsdbStart),
		processOutcome("r1 D", lsdbStart.Add(12*time.Second+560*time.Millisecond)),
	}
	markDuplicates(outcomes)
	for _, o := range outcomes {
		if o.reason != "" {
			t.Fatalf("%s refused as duplicate: %s", o.capture.Source, o.reason)
		}
	}
}

// TestProcessGroupsThatAreNotPairsAreRefused keeps the refusal for every other
// shape: three process states, or two taken at the same instant, have no order
// that the comparison may trust.
func TestProcessGroupsThatAreNotPairsAreRefused(t *testing.T) {
	cases := map[string][]outcome{
		"three process states": {
			processOutcome("r1 A", lsdbStart),
			processOutcome("r1 B-process", lsdbStart.Add(3*time.Second)),
			processOutcome("r1 D", lsdbStart.Add(15*time.Second)),
		},
		"two at the same instant": {
			processOutcome("r1 A", lsdbStart),
			processOutcome("r1 D", lsdbStart),
		},
	}
	for name, outcomes := range cases {
		t.Run(name, func(t *testing.T) {
			markDuplicates(outcomes)
			for _, o := range outcomes {
				if o.reason == "" {
					t.Fatalf("%s accepted; want refused as a repeat", o.capture.Source)
				}
			}
		})
	}
}

// lsdbBracket returns the four captures of one node's bracket in one lab run, in
// the order the lab took them: A, B, E, D.
func lsdbBracket(t *testing.T, scenario, node string) []Capture {
	t.Helper()
	return []Capture{
		lsdbCapture(t, scenario, node, "A"),
		lsdbCapture(t, scenario, node, "B"),
		lsdbCapture(t, scenario, node, "E"),
		lsdbCapture(t, scenario, node, "D"),
	}
}

func importLSDB(t *testing.T, captures []Capture) Result {
	t.Helper()
	res, err := Import(captures)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	return res
}

func nodeReport(t *testing.T, res Result, node string) ospfNodeReport {
	t.Helper()
	if res.LSDB == nil {
		t.Fatal("LSDB report is nil; want the comparison")
	}
	for _, n := range res.LSDB.Nodes {
		if n.Node == node {
			return ospfNodeReport{n.Guard.Passed, n.Guard.Reasons, findingKinds(n.Findings)}
		}
	}
	t.Fatalf("no LSDB report for node %s", node)
	return ospfNodeReport{}
}

// ospfNodeReport is the part of one node's comparison these tests check.
type ospfNodeReport struct {
	passed   bool
	reasons  []string
	findings []string
}

func findingKinds(fs []ospf.LSDBFinding) []string {
	var out []string
	for _, f := range fs {
		var parts []string
		for _, v := range []string{string(f.Kind), f.Area, f.Scope, string(f.Type), f.Prefix} {
			if v != "" {
				parts = append(parts, v)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// TestKilledNeighborBracketGivesTheExactFindings is the end-to-end check on the
// kill9 lab: the two prefixes r2 advertised and no longer has a route for, and
// nothing else.
func TestKilledNeighborBracketGivesTheExactFindings(t *testing.T) {
	res := importLSDB(t, lsdbBracket(t, "kill9", "r1"))
	n := nodeReport(t, res, "r1")
	if !n.passed {
		t.Fatalf("guard failed: %v", n.reasons)
	}
	want := []string{
		"lsdb_prefix_not_calculated external 10.20.0.0/24",
		"lsdb_prefix_not_calculated 0.0.0.0 router 10.10.2.0/24",
	}
	if !slices.Equal(n.findings, want) {
		t.Fatalf("findings = %q; want %q", n.findings, want)
	}
	if len(res.Observations) != 0 {
		t.Fatalf("LSDB captures wrote %d observations; want none", len(res.Observations))
	}
}

// TestHealthyBracketIsQuiet is the negative control: the steady lab's two nodes
// pass the guard and give no finding.
func TestHealthyBracketIsQuiet(t *testing.T) {
	res := importLSDB(t, append(lsdbBracket(t, "steady", "r1"), lsdbBracket(t, "steady", "r2")...))
	for _, node := range []string{"r1", "r2"} {
		n := nodeReport(t, res, node)
		if !n.passed {
			t.Errorf("%s guard failed: %v", node, n.reasons)
		}
		if len(n.findings) != 0 {
			t.Errorf("%s findings = %q; want none", node, n.findings)
		}
	}
}

// TestFlappingBracketIsUnverifiedOnly checks that a moving OSPF state gives only
// the unverified finding, and that the reasons name the counter that moved.
func TestFlappingBracketIsUnverifiedOnly(t *testing.T) {
	res := importLSDB(t, lsdbBracket(t, "flap", "r1"))
	n := nodeReport(t, res, "r1")
	if n.passed {
		t.Fatal("guard passed for a flapping bracket")
	}
	if got := strings.Join(n.reasons, "; "); !strings.Contains(got, "the SPF counter of area 0.0.0.0 changed from 4 to 5") {
		t.Fatalf("reasons = %q; want the SPF counter change named", got)
	}
	if len(n.findings) != 1 || !strings.HasPrefix(n.findings[0], "ospf_comparison_unverified") {
		t.Fatalf("findings = %q; want only ospf_comparison_unverified", n.findings)
	}
}

// TestLSDBCaptureOrderDoesNotChangeTheReport permutes the captures and compares
// the whole result, so no map walk may leak into the output.
func TestLSDBCaptureOrderDoesNotChangeTheReport(t *testing.T) {
	forward := append(lsdbBracket(t, "kill9", "r1"), lsdbBracket(t, "steady", "r2")...)
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)
	a := mustJSON(t, importLSDB(t, forward).LSDB)
	b := mustJSON(t, importLSDB(t, reversed).LSDB)
	if a != b {
		t.Fatal("LSDB report depends on capture order")
	}
}

// TestRefusedLSDBCaptureIsIncompleteNotEmpty corrupts the LSDB capture. The
// refusal must reach the report as incomplete evidence, not as an empty LSDB.
func TestRefusedLSDBCaptureIsIncompleteNotEmpty(t *testing.T) {
	captures := lsdbBracket(t, "kill9", "r1")
	captures[1].Data = []byte(`{"routerId":"1.1.1.1",`)
	res := importLSDB(t, captures)
	for _, c := range res.Report.Captures {
		if c.Command == CommandLSDB && c.Accepted {
			t.Fatal("corrupt LSDB capture accepted")
		}
	}
	n := nodeReport(t, res, "r1")
	if len(n.findings) == 0 || !strings.HasPrefix(n.findings[0], "lsdb_incomplete") {
		t.Fatalf("findings = %q; want lsdb_incomplete for the refused LSDB", n.findings)
	}
	for _, f := range n.findings {
		if strings.HasPrefix(f, "lsdb_prefix_not_calculated") {
			t.Fatalf("prefix finding %q from a refused LSDB", f)
		}
	}
}

// TestRepeatedProcessStateIsRefusedForEveryCapture checks the three-capture
// refusal end to end: the comparison has no A and D, so the guard fails.
func TestRepeatedProcessStateIsRefusedForEveryCapture(t *testing.T) {
	captures := lsdbBracket(t, "kill9", "r1")
	extra := captures[0]
	extra.Source = "kill9 r1 A again"
	extra.CollectedAt = extra.CollectedAt.Add(time.Second)
	res := importLSDB(t, append(captures, extra))
	for _, c := range res.Report.Captures {
		if c.Command == CommandProcessState && c.Accepted {
			t.Fatalf("%s accepted; three process states must all be refused", c.Source)
		}
	}
	if n := nodeReport(t, res, "r1"); n.passed {
		t.Fatal("guard passed with no readable process pair")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestManifestRequiresTheFullLSDBSetPerNode checks the count rule. A node with
// any LSDB command needs exactly two process states, one LSDB, and one route
// capture, and the manifest refuses anything else before a capture is read.
func TestManifestRequiresTheFullLSDBSetPerNode(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		ok   bool
	}{
		{"full set", []string{CommandProcessState, CommandLSDB, CommandRoute, CommandProcessState}, true},
		{"one process state", []string{CommandProcessState, CommandLSDB, CommandRoute}, false},
		{"three process states", []string{CommandProcessState, CommandProcessState, CommandProcessState, CommandLSDB, CommandRoute}, false},
		{"no route", []string{CommandProcessState, CommandProcessState, CommandLSDB}, false},
		{"two LSDB", []string{CommandProcessState, CommandProcessState, CommandLSDB, CommandLSDB, CommandRoute}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var captures []any
			for i, cmd := range tc.cmds {
				file := fmt.Sprintf("r1-%d.raw", i)
				captures = append(captures, captureEntry(file, fmt.Sprintf("r1 %d", i), "r1", cmd))
			}
			data, err := json.Marshal(map[string]any{"version": 1, "source_node": "r1", "captures": captures})
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeManifest(data)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("refused a full set: %v", err)
			case !tc.ok && (err == nil || !strings.Contains(err.Error(), "needs exactly 2")):
				t.Fatalf("err = %v; want the LSDB count refusal", err)
			}
		})
	}
}
