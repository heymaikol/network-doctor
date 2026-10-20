package simulation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// Triage turns hunt findings into GitHub issues. A finding earns an issue only
// after its exact generated case has been re-run and produced the same finding
// again, so a one-off timing artifact never becomes a bug report.

const (
	TriageResultClean    = "clean"
	TriageResultFindings = "findings"
	TriageResultError    = "error"

	// triageFingerprintDomain separates issue fingerprints from every other
	// hash in the simulator. Changing it re-files every open issue, so it
	// must stay fixed unless the identity of a finding genuinely changes.
	triageFingerprintDomain = "netdoc-sim-triage-v2"

	IssueStatusNotFiled = "not_filed"
	IssueStatusExisting = "existing"
	IssueStatusCreated  = "created"
)

// TriageBaseline is a known-good scenario and its fixed regression seed.
// Automated exploration may override it, and historical findings reproduce
// from the numeric seed recorded in their hunt report.
type TriageBaseline struct {
	Scenario string `json:"scenario"`
	Seed     int64  `json:"seed"`
}

// The set is chosen so that every operator in the hunt registry is reachable
// from at least one baseline, which TestEveryHuntOperatorReachesABaseline
// holds it to. A single-path base cannot host a route-choice fault: repointing
// or deleting the only default there is indistinguishable from the network
// beyond it dying, so those operators refuse to generate and the nightly hunt
// never sees them. The multi-path bases are what give them somewhere to land,
// and their second test is also the control that route findings are built from.
var triageBaselines = []TriageBaseline{
	{Scenario: "healthy", Seed: 20260101},
	{Scenario: "healthy-routed-network", Seed: 20260102},
	{Scenario: "dual-stack-healthy", Seed: 20260103},
	{Scenario: "tls-valid", Seed: 20260104},
	{Scenario: "socks5h-remote-dns-succeeds", Seed: 20260105},
	{Scenario: "two-path-healthy", Seed: 20260106},
	{Scenario: "two-path-ipv6-healthy", Seed: 20260107},
	{Scenario: "two-router-healthy", Seed: 20260108},
}

// TriageBaselines returns the baseline scenarios and fixed regression seeds.
func TriageBaselines() []TriageBaseline { return append([]TriageBaseline(nil), triageBaselines...) }

// TriageBaselineFor returns the fixed regression seed for a baseline scenario.
func TriageBaselineFor(scenario string) (TriageBaseline, bool) {
	for _, b := range triageBaselines {
		if b.Scenario == scenario {
			return b, true
		}
	}
	return TriageBaseline{}, false
}

type TriageScenarioResult struct {
	Scenario   string `json:"scenario"`
	Seed       int64  `json:"seed"`
	Cases      int    `json:"executed_cases"`
	Candidates int    `json:"candidate_findings"`
	Filtered   int    `json:"below_severity_floor"`
	HuntResult string `json:"hunt_result"`
	// Coverage is this baseline's hunt coverage, carried through unchanged. A
	// nightly report that files nothing is the report that most needs it: it
	// is the difference between netdoc surviving everything this baseline can
	// throw and netdoc surviving the three faults it happened to throw.
	Coverage HuntCoverage `json:"coverage"`
}

// ParseSeverity maps a flag value onto the hunt severity vocabulary.
func ParseSeverity(name string) (HuntSeverity, bool) {
	severity := HuntSeverity(name)
	if severityRank(severity) == 0 {
		return "", false
	}
	return severity, true
}

// SeverityAtLeast reports whether a finding meets the severity floor. The
// hunt's low and info findings are mostly known coverage limits of netdoc's
// probes rather than defects, so a nightly job files from medium up.
func SeverityAtLeast(severity, floor HuntSeverity) bool {
	return severityRank(severity) >= severityRank(floor)
}

type TriageIssue struct {
	Status string `json:"status"`
	URL    string `json:"url,omitempty"`
}

type TriageFinding struct {
	Fingerprint      string               `json:"fingerprint"`
	Scenario         string               `json:"scenario"`
	Seed             int64                `json:"seed"`
	Case             int                  `json:"case"`
	CaseSeed         int64                `json:"case_seed"`
	MaxFaults        int                  `json:"max_faults"`
	CaseFingerprint  string               `json:"case_fingerprint"`
	GeneratorVersion string               `json:"generator_version"`
	Lane             HuntLane             `json:"lane,omitempty"`
	Finding          HuntFinding          `json:"finding"`
	Reproducible     bool                 `json:"reproducible"`
	Truth            ObservedTruth        `json:"simulator_truth"`
	Diagnosis        DiagnosisFingerprint `json:"diagnosis_fingerprint"`
	Mutations        []GeneratedMutation  `json:"mutations"`
	Issue            TriageIssue          `json:"issue"`
}

type TriageReport struct {
	Revision  string                 `json:"revision"`
	Lane      HuntLane               `json:"lane,omitempty"`
	Context   string                 `json:"context,omitempty"`
	Baselines []TriageScenarioResult `json:"baselines"`
	Findings  []TriageFinding        `json:"findings"`
	Result    string                 `json:"result"`
	Error     string                 `json:"error,omitempty"`
}

// NewTriageFinding derives the stable issue identity for one hunt finding.
// Scenario, seed, case and case fingerprint pin the generated network; the
// hunt fingerprint pins what disagreed. The same bug in the same case therefore
// keeps one issue.
func NewTriageFinding(finding HuntFinding) TriageFinding {
	repro := finding.Reproduce
	return TriageFinding{
		Fingerprint:      triageFingerprint(repro.BaseScenario, repro.Seed, repro.Case, repro.CaseFingerprint, finding.Fingerprint),
		Scenario:         repro.BaseScenario,
		Seed:             repro.Seed,
		Case:             repro.Case,
		CaseSeed:         repro.CaseSeed,
		MaxFaults:        repro.MaxFaults,
		CaseFingerprint:  repro.CaseFingerprint,
		GeneratorVersion: repro.GeneratorVersion,
		Lane:             repro.Lane,
		Finding:          finding,
		Issue:            TriageIssue{Status: IssueStatusNotFiled},
	}
}

func triageFingerprint(scenario string, seed int64, caseNumber int, caseFingerprint, findingFingerprint string) string {
	h := sha256.New()
	// NUL-separated: no field can contain one, so no two different findings
	// can hash the same bytes by running into each other.
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%s\x00%s",
		triageFingerprintDomain, scenario, seed, caseNumber, caseFingerprint, findingFingerprint)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// ReproduceCommand is the copy/pasteable single-case reproduction, built from
// this finding's own flattened coordinates through the one place that decides
// the command's shape, so the hunt report and a filed issue cannot drift into
// printing two different commands for one case.
func (f *TriageFinding) ReproduceCommand() string {
	return HuntReproduction{BaseScenario: f.Scenario, Seed: f.Seed, Case: f.Case, MaxFaults: f.MaxFaults,
		GeneratorVersion: f.GeneratorVersion, Lane: f.Lane}.Command()
}

// IssueTitle carries the fingerprint as a bare hex word, which is what the
// duplicate search matches on: GitHub tokenizes it whole, and no other title
// text can collide with it.
func (f *TriageFinding) IssueTitle() string {
	return fmt.Sprintf("netdoc-sim hunt: %s in %s (case %d) [%s]",
		textsafe.Clean(f.Finding.Code), textsafe.Clean(f.Scenario), f.Case, f.Fingerprint)
}

// IssueBody renders the report a human needs to start debugging without
// re-running anything first.
func (f *TriageFinding) IssueBody(revision, runContext string) string {
	var b strings.Builder
	finding := f.Finding
	fmt.Fprintf(&b, "`netdoc-sim hunt` found a disagreement between the simulator's observed truth\n")
	fmt.Fprintf(&b, "and Network Doctor's diagnosis, and reproduced it by re-running the exact\n")
	fmt.Fprintf(&b, "generated case.\n\n")

	fmt.Fprintf(&b, "| field | value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| scenario | `%s` |\n", textsafe.Clean(f.Scenario))
	fmt.Fprintf(&b, "| hunt seed | `%d` |\n", f.Seed)
	fmt.Fprintf(&b, "| case | `%d` |\n", f.Case)
	fmt.Fprintf(&b, "| case seed | `%d` |\n", f.CaseSeed)
	fmt.Fprintf(&b, "| max faults | `%d` |\n", f.MaxFaults)
	fmt.Fprintf(&b, "| case fingerprint | `%s` |\n", textsafe.Clean(f.CaseFingerprint))
	fmt.Fprintf(&b, "| finding | `%s` (%s, %s) |\n", textsafe.Clean(finding.Code),
		textsafe.Clean(finding.Category), finding.Severity)
	if finding.Probe != "" {
		fmt.Fprintf(&b, "| probe | `%s` |\n", textsafe.Clean(finding.Probe))
	}
	fmt.Fprintf(&b, "| generator | `%s` |\n", textsafe.Clean(f.GeneratorVersion))
	lane, _ := ResolveHuntLane(f.GeneratorVersion, f.Lane)
	fmt.Fprintf(&b, "| Hunt lane | `%s` |\n", lane)
	fmt.Fprintf(&b, "| revision | `%s` |\n", textsafe.Clean(revision))

	fmt.Fprintf(&b, "\n## Why they disagree\n\n%s\n", textsafe.Clean(finding.Summary))
	if finding.Expected != "" || finding.Actual != "" {
		fmt.Fprintf(&b, "\n- simulator expected: `%s`\n- netdoc reported: `%s`\n",
			textsafe.Clean(orNone(finding.Expected)), textsafe.Clean(orNone(finding.Actual)))
	}
	if finding.Cause != "" {
		fmt.Fprintf(&b, "- cause: `%s`\n", textsafe.Clean(finding.Cause))
	}
	if finding.Evidence != "" {
		fmt.Fprintf(&b, "- evidence: %s\n", textsafe.Clean(finding.Evidence))
	}
	fmt.Fprintf(&b, "- occurrences in the hunt: %d (cases %s)\n", finding.Occurrences, intList(finding.ExampleCases))

	fmt.Fprintf(&b, "\n## Simulator truth (what the network actually was)\n\n")
	fmt.Fprintf(&b, "```\n")
	for _, line := range truthLines(f.Truth) {
		fmt.Fprintf(&b, "%s\n", line)
	}
	fmt.Fprintf(&b, "```\n")

	fmt.Fprintf(&b, "\n## Network Doctor diagnosis\n\n")
	fmt.Fprintf(&b, "```\n")
	fmt.Fprintf(&b, "fingerprint %s\nverdicts    %s\n", textsafe.Clean(orNone(f.Diagnosis.ID)),
		textsafe.Clean(orNone(strings.Join(f.Diagnosis.Verdicts, ", "))))
	for _, probe := range f.Diagnosis.Probes {
		fmt.Fprintf(&b, "probe       %s %s %s %s\n", textsafe.Clean(probe.Test), textsafe.Clean(probe.ID),
			textsafe.Clean(probe.Status), textsafe.Clean(probe.Cause))
	}
	fmt.Fprintf(&b, "```\n")

	fmt.Fprintf(&b, "\n## Simulator mutations\n\n")
	if len(f.Mutations) == 0 {
		fmt.Fprintf(&b, "None recorded.\n")
	}
	for _, mutation := range f.Mutations {
		fmt.Fprintf(&b, "- `%s`: %s%s\n", textsafe.Clean(mutation.ID),
			textsafe.Clean(mutation.Description), mutationTarget(mutation))
	}

	fmt.Fprintf(&b, "\n## Reproduce\n\n```sh\ngo build -o netdoc . && go build -o netdoc-sim ./cmd/netdoc-sim\n./%s\n```\n",
		f.ReproduceCommand())
	fmt.Fprintf(&b, "\nThe hunt above was re-run for this single case and produced the same finding\n")
	fmt.Fprintf(&b, "fingerprint `%s`, which is why this issue exists.\n", textsafe.Clean(finding.Fingerprint))

	if runContext != "" {
		fmt.Fprintf(&b, "\n## Context\n\n%s\n", textsafe.Clean(runContext))
	}
	fmt.Fprintf(&b, "\n<!-- netdoc-sim triage fingerprint: %s, keep it in the title; duplicates are suppressed by it. -->\n",
		f.Fingerprint)
	return b.String()
}

func orNone(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func truthLines(truth ObservedTruth) []string {
	lines := []string{
		"dns      " + truth.DNS,
		"ipv4     " + truth.IPv4,
		"ipv6     " + truth.IPv6,
		"gateway  " + truth.Gateway,
		"proxy    " + truth.Proxy,
		"tls      " + truth.TLS,
		"tcp      " + truth.TCP,
		"link     " + truth.Link,
		"packet   " + truth.Packet,
		"route    " + truth.Route,
		"faults   " + orNone(strings.Join(truth.ObservedFaults, ", ")),
	}
	for i := range lines {
		lines[i] = textsafe.Clean(lines[i])
	}
	return lines
}

func mutationTarget(mutation GeneratedMutation) string {
	var parts []string
	for _, field := range [][2]string{{"node", mutation.Node}, {"segment", mutation.Segment},
		{"service", mutation.Service}, {"family", mutation.Family}} {
		if field[1] != "" {
			parts = append(parts, field[0]+"="+textsafe.Clean(field[1]))
		}
	}
	if mutation.LossPercent > 0 {
		parts = append(parts, fmt.Sprintf("loss=%.2f%%", mutation.LossPercent))
	}
	if mutation.LatencyMS > 0 {
		parts = append(parts, fmt.Sprintf("latency=%dms", mutation.LatencyMS))
	}
	if mutation.JitterMS > 0 {
		parts = append(parts, fmt.Sprintf("jitter=%dms", mutation.JitterMS))
	}
	if mutation.DurationMS > 0 {
		parts = append(parts, fmt.Sprintf("start=%dms duration=%dms", mutation.StartMS, mutation.DurationMS))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func (r *TriageReport) WriteJSON(w io.Writer) error { return writeJSON(w, r) }

func (r *TriageReport) WriteText(w io.Writer) {
	fmt.Fprintln(w, "Network Doctor hunt triage")
	fmt.Fprintf(w, "\nLane:     %s\nRevision: %s\n", r.Lane, textsafe.Clean(orNone(r.Revision)))
	if r.Context != "" {
		fmt.Fprintf(w, "Context:  %s\n", textsafe.Clean(r.Context))
	}
	fmt.Fprintln(w, "\nScenarios")
	for _, baseline := range r.Baselines {
		fmt.Fprintf(w, "  %-24s seed %-12d cases %-4d candidates %-3d below floor %-3d %s\n",
			textsafe.Clean(baseline.Scenario), baseline.Seed, baseline.Cases, baseline.Candidates,
			baseline.Filtered, baseline.HuntResult)
		applicable, generated, observed, conditions, established := baseline.Coverage.Counts()
		fmt.Fprintf(w, "    coverage: operators %d/%d generated, %d observed; conditions %d/%d established; %d set(s), %d experiment(s)\n",
			generated, applicable, observed, established, conditions,
			baseline.Coverage.MutationSets, baseline.Coverage.DistinctExperiments)
		fmt.Fprintf(w, "    faults:   %d generated (%s), %d observed; %d case(s) observed two or more at once\n",
			huntFaultsGenerated(baseline.Coverage), huntCardinality(baseline.Coverage),
			huntFaultsObserved(baseline.Coverage), baseline.Coverage.MultiFaultCases)
		for _, gap := range baseline.Coverage.Gaps() {
			fmt.Fprintf(w, "      gap: %-30s %s\n", gap.Kind, textsafe.Clean(gap.ID))
		}
	}
	reproducible, existing, created := 0, 0, 0
	for _, finding := range r.Findings {
		if finding.Reproducible {
			reproducible++
		}
		switch finding.Issue.Status {
		case IssueStatusExisting:
			existing++
		case IssueStatusCreated:
			created++
		}
	}
	fmt.Fprintf(w, "\nCandidate findings:    %d\nReproducible findings: %d\nExisting issues:       %d\nNew issues created:    %d\n",
		len(r.Findings), reproducible, existing, created)
	for _, finding := range r.Findings {
		verdict := "not reproducible, not filed"
		if finding.Reproducible {
			verdict = finding.Issue.Status
			if finding.Issue.URL != "" {
				verdict += " " + textsafe.Clean(finding.Issue.URL)
			}
		}
		fmt.Fprintf(w, "\n%-8s %s case %d  %s\n  %s\n  %s\n  %s\n", strings.ToUpper(string(finding.Finding.Severity)),
			textsafe.Clean(finding.Scenario), finding.Case, finding.Fingerprint,
			textsafe.Clean(finding.Finding.Summary), verdict, finding.ReproduceCommand())
	}
	if r.Error != "" {
		fmt.Fprintf(w, "\nError: %s\n", textsafe.Clean(r.Error))
	}
}
