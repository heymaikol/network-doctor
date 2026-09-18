package simulation

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
)

const (
	HuntResultClean     = "clean"
	HuntResultFindings  = "findings"
	HuntResultError     = "error"
	HuntResultCancelled = "cancelled"
	HuntMaxShards       = 500
)

// HuntShard selects global case numbers using zero-based modulo partitioning.
type HuntShard struct {
	Index int `json:"index"`
	Count int `json:"count"`
}

func (s HuntShard) Validate() error {
	if s.Count < 1 || s.Count > HuntMaxShards {
		return fmt.Errorf("shard count must be between 1 and %d", HuntMaxShards)
	}
	if s.Index < 0 || s.Index >= s.Count {
		return fmt.Errorf("shard index must be between 0 and %d", s.Count-1)
	}
	return nil
}

func (s HuntShard) Includes(caseNumber int) bool { return caseNumber%s.Count == s.Index }

type HuntOptions struct {
	Run              Options
	Cases            int
	Seed             int64
	Case             *int
	Shard            *HuntShard
	MaxFaults        int
	GeneratorVersion string
	Lane             HuntLane
	FailFast         bool
	DryRun           bool
}

type HuntCaseResult struct {
	Manifest             GeneratedCaseManifest `json:"manifest"`
	Truth                ObservedTruth         `json:"truth"`
	TruthFingerprint     string                `json:"truth_fingerprint"`
	DiagnosisFingerprint DiagnosisFingerprint  `json:"diagnosis_fingerprint"`
	Findings             []HuntCaseFinding     `json:"findings"`
	Report               *Report               `json:"report,omitempty"`
	Status               string                `json:"status"`
}

type HuntSuggestion struct {
	Code            string           `json:"code"`
	Description     string           `json:"description"`
	Evidence        int              `json:"evidence_cases"`
	HighestSeverity HuntSeverity     `json:"highest_severity"`
	FirstCase       int              `json:"first_case"`
	ExampleCases    []int            `json:"example_cases"`
	Reproduce       HuntReproduction `json:"reproduce"`
}

type HuntResult struct {
	GeneratorVersion    string           `json:"generator_version"`
	Lane                HuntLane         `json:"lane,omitempty"`
	BaseScenario        string           `json:"base_scenario"`
	HuntSeed            int64            `json:"hunt_seed"`
	RequestedCases      int              `json:"requested_cases"`
	MaxFaults           int              `json:"max_faults"`
	FailFast            bool             `json:"fail_fast,omitempty"`
	DryRun              bool             `json:"dry_run,omitempty"`
	Shard               *HuntShard       `json:"shard,omitempty"`
	GeneratedCases      int              `json:"generated_cases"`
	ExecutedCases       int              `json:"executed_cases"`
	UniqueCases         int              `json:"unique_cases"`
	DuplicateCandidates int              `json:"duplicate_candidates"`
	CleanCases          int              `json:"clean_cases"`
	Findings            []HuntFinding    `json:"findings"`
	Suggestions         []HuntSuggestion `json:"suggestions"`
	Cases               []HuntCaseResult `json:"case_results"`
	// Coverage is how much ground this hunt stood on, which is a separate
	// question from what it found. It is derived from the case results and
	// never changes them, so a clean result stays clean and gains a way to say
	// how much confidence it deserves.
	Coverage        HuntCoverage `json:"coverage"`
	FailFastStopped bool         `json:"fail_fast_stopped"`
	Cancelled       bool         `json:"cancelled"`
	RuntimeFailure  bool         `json:"runtime_failure"`
	Result          string       `json:"result"`
	ErrorKind       string       `json:"error_kind,omitempty"`
	Error           string       `json:"error,omitempty"`
}

func (o *HuntOptions) withDefaults() error {
	if o.GeneratorVersion == "" {
		o.GeneratorVersion = HuntGeneratorVersion
	}
	if err := validateHuntGeneratorVersion(o.GeneratorVersion); err != nil {
		return err
	}
	lane, err := ResolveHuntLane(o.GeneratorVersion, o.Lane)
	if err != nil {
		return err
	}
	o.Lane = lane
	if o.Cases == 0 {
		o.Cases = 50
	}
	if o.MaxFaults == 0 {
		o.MaxFaults = 2
	}
	if o.Cases < 1 || o.Cases > HuntMaxCases {
		return fmt.Errorf("cases must be between 1 and %d", HuntMaxCases)
	}
	if o.MaxFaults < 1 || o.MaxFaults > HuntMaxFaults {
		return fmt.Errorf("max faults must be between 1 and %d", HuntMaxFaults)
	}
	if o.Case != nil && (*o.Case < 0 || *o.Case > HuntMaxCaseNumber) {
		return fmt.Errorf("case must be between 0 and %d", HuntMaxCaseNumber)
	}
	if o.Shard != nil {
		if err := o.Shard.Validate(); err != nil {
			return err
		}
		if o.Case != nil {
			return fmt.Errorf("case and shard selectors are mutually exclusive")
		}
	}
	return nil
}

// huntCaseStream owns the existing global sequence: candidates begin at zero,
// duplicate identities under the selected generator do not count toward the
// requested case total, and every accepted manifest keeps its original global
// case number.
type huntCaseStream struct {
	version, baseID string
	lane            HuntLane
	base            *Scenario
	seed            int64
	maxFaults       int
	candidate       int
	attempts        int
	maxCandidates   int
	target          int
	accepted        int
	deduplicate     bool
	seen            map[string]bool
	duplicates      int
}

func newHuntCaseStream(version string, lane HuntLane, baseID string, base *Scenario, seed int64, cases, maxFaults int, only *int) *huntCaseStream {
	stream := &huntCaseStream{version: version, lane: lane, baseID: baseID, base: base, seed: seed,
		maxFaults: maxFaults, target: cases, maxCandidates: cases * 20, deduplicate: true,
		seen: make(map[string]bool, cases)}
	if only != nil {
		stream.candidate, stream.target, stream.maxCandidates, stream.deduplicate = *only, 1, 1, false
	}
	return stream
}

func (s *huntCaseStream) next() (*GeneratedCase, error) {
	for s.attempts < s.maxCandidates && s.accepted < s.target {
		caseNumber := s.candidate
		s.candidate++
		s.attempts++
		if caseNumber > HuntMaxCaseNumber {
			break
		}
		generated, err := generateHuntCaseInLane(s.version, s.lane, s.baseID, s.base, s.seed, caseNumber, s.maxFaults)
		if err != nil {
			return nil, fmt.Errorf("case %d: %w", caseNumber, err)
		}
		if s.deduplicate && s.seen[generated.Manifest.CaseFingerprint] {
			s.duplicates++
			continue
		}
		s.seen[generated.Manifest.CaseFingerprint] = true
		s.accepted++
		return generated, nil
	}
	if s.accepted < s.target {
		return nil, fmt.Errorf("generated %d unique cases after %d bounded candidates; requested %d",
			s.accepted, s.maxCandidates, s.target)
	}
	return nil, nil
}

// canonicalHuntCaseResult is the one place a simulation report becomes part of
// a hunt case result, on the generating side and in the merge validation that
// recomputes a stored case from its manifest and report. It is therefore also
// the one place the stored size has to be settled: a report that does not fit
// HuntMaxCaseResultBytes is replaced by a bounded stand-in, and the case's
// truth, fingerprints, findings and status are derived from the stand-in, so
// what a hunt writes and what a merge recomputes are the same object. The
// substitution is deterministic and cannot cascade, because the stand-in is
// under a kilobyte.
func canonicalHuntCaseResult(manifest GeneratedCaseManifest, report *Report) HuntCaseResult {
	item := huntCaseResultFrom(manifest, report)
	if report == nil || huntEncodedElementSize(item) <= HuntMaxCaseResultBytes {
		return item
	}
	return huntCaseResultFrom(manifest, oversizedHuntReport(report))
}

func huntCaseResultFrom(manifest GeneratedCaseManifest, report *Report) HuntCaseResult {
	item := HuntCaseResult{Manifest: manifest, Status: "generated",
		Truth: collectObservedTruth(manifest, nil), Findings: []HuntCaseFinding{},
		DiagnosisFingerprint: DiagnosisFingerprint{Verdicts: []string{}, Probes: []ProbeFingerprint{}}, Report: report}
	if report == nil {
		return item
	}
	if report.Error != "" || !report.Cleanup.Done {
		item.Status = "runtime_error"
		item.Findings = analyzeHuntCase(manifest, report, item.Truth)
		return item
	}
	item.Truth = collectObservedTruth(manifest, report)
	item.TruthFingerprint = truthFingerprint(item.Truth)
	item.DiagnosisFingerprint = diagnosisFingerprint(report)
	item.Findings = analyzeHuntCase(manifest, report, item.Truth)
	item.Status = "clean"
	if len(item.Findings) > 0 {
		item.Status = "findings"
	}
	return item
}

// RunHunt generates cases independently, skips generator-defined duplicate
// identities in batch mode, and runs each accepted case sequentially through
// the normal simulator.
//
// Each case runs netdoc exactly once, and the hunt therefore makes no claim
// about whether a diagnosis is reproducible. It cannot: a second run inside the
// same live topology inherits the neighbour, route and resolver caches the
// first one warmed, so the two are not the same experiment and a verdict that
// changed between them says only that the first probe paid for a cold path.
// Comparing two different cases is no better, since the coarse observed truth
// records that a path was impaired without recording by how much. Determinism
// is campaign mode's question, where `--iteration N --runs K` repeats one
// schedule through a whole fresh topology each time.
func RunHunt(ctx context.Context, baseID string, base *Scenario, backend func() Backend, opts HuntOptions) *HuntResult {
	result := &HuntResult{BaseScenario: baseID, HuntSeed: opts.Seed}
	err := opts.withDefaults()
	result.GeneratorVersion, result.Lane = opts.GeneratorVersion, opts.Lane
	if err != nil {
		result.Result, result.ErrorKind, result.Error = HuntResultError, "configuration", clip(err.Error())
		result.finish()
		return result
	}
	result.RequestedCases, result.MaxFaults = opts.Cases, opts.MaxFaults
	result.FailFast, result.DryRun = opts.FailFast, opts.DryRun
	if opts.Shard != nil {
		shard := *opts.Shard
		result.Shard = &shard
	}
	if opts.Case != nil {
		result.RequestedCases = 1
	}
	if !opts.DryRun && backend == nil {
		result.Result, result.ErrorKind, result.Error = HuntResultError, "configuration", "hunt backend is nil"
		result.finish()
		return result
	}
	stream := newHuntCaseStream(opts.GeneratorVersion, opts.Lane, baseID, base, opts.Seed, result.RequestedCases, opts.MaxFaults, opts.Case)
	for stream.accepted < stream.target {
		if err := ctx.Err(); err != nil {
			result.Cancelled, result.RuntimeFailure = true, true
			result.Result, result.ErrorKind, result.Error = HuntResultCancelled, "cancellation", clip(err.Error())
			break
		}
		generated, err := stream.next()
		if err != nil {
			result.Result, result.ErrorKind = HuntResultError, FindingGeneratorDefect
			result.Error = clip(err.Error())
			break
		}
		if generated == nil {
			break
		}
		if opts.Shard != nil && !opts.Shard.Includes(generated.Manifest.Case) {
			continue
		}
		item := canonicalHuntCaseResult(generated.Manifest, nil)
		result.GeneratedCases++
		if !opts.DryRun {
			item = canonicalHuntCaseResult(generated.Manifest, Run(ctx, generated.Scenario, backend(), opts.Run))
			result.ExecutedCases++
			if item.Status == "runtime_error" {
				result.RuntimeFailure = true
			}
		}
		result.Cases = append(result.Cases, item)
		if opts.FailFast && len(item.Findings) > 0 {
			result.FailFastStopped = true
			break
		}
		if opts.Case != nil {
			break
		}
	}
	result.DuplicateCandidates = stream.duplicates
	result.UniqueCases = len(result.Cases)
	result.finish()
	return result
}

func (r *HuntResult) finish() {
	if r.Cases == nil {
		r.Cases = []HuntCaseResult{}
	}
	for i := range r.Cases {
		if r.Cases[i].Findings == nil {
			r.Cases[i].Findings = []HuntCaseFinding{}
		}
		if r.Cases[i].Status == "clean" {
			r.CleanCases++
		}
	}
	r.Coverage = huntCoverageFor(r.GeneratorVersion, r.Lane, r.BaseScenario, r.Cases)
	r.Findings = aggregateHuntFindings(r.Cases)
	r.Suggestions = aggregateHuntSuggestions(r.Findings)
	if r.Findings == nil {
		r.Findings = []HuntFinding{}
	}
	if r.Suggestions == nil {
		r.Suggestions = []HuntSuggestion{}
	}
	if r.Result == HuntResultError || r.Result == HuntResultCancelled {
		return
	}
	switch {
	case r.RuntimeFailure:
		r.Result = HuntResultError
		if r.ErrorKind == "" {
			r.ErrorKind = "runtime"
		}
		if r.Error == "" {
			r.Error = firstCaseFailure(r.Cases)
		}
	case len(r.Findings) > 0:
		r.Result = HuntResultFindings
	default:
		r.Result = HuntResultClean
	}
}

// firstCaseFailure names what actually went wrong in a run that failed. Without
// it a runtime failure reports its kind and nothing else, leaving the one useful
// sentence, the command the simulator could not run, buried in a per-case
// report that callers reporting only the summary never print. Bounded, because
// the text can carry a subprocess's whole complaint.
func firstCaseFailure(cases []HuntCaseResult) string {
	for _, item := range cases {
		if item.Report == nil {
			continue
		}
		switch {
		case item.Report.Error != "":
			return fmt.Sprintf("case %d: %s", item.Manifest.Case, clip(item.Report.Error))
		case !item.Report.Cleanup.Done:
			return fmt.Sprintf("case %d: cleanup did not finish: %s", item.Manifest.Case,
				clip(strings.Join(item.Report.Cleanup.Errors, "; ")))
		}
	}
	return ""
}

func clip(s string) string {
	const max = 400
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func aggregateHuntSuggestions(findings []HuntFinding) []HuntSuggestion {
	byCode := make(map[string]*HuntSuggestion)
	for _, finding := range findings {
		if finding.SuggestionCode == "" {
			continue
		}
		item := byCode[finding.SuggestionCode]
		if item == nil {
			item = &HuntSuggestion{Code: finding.SuggestionCode, Description: finding.Summary,
				HighestSeverity: finding.Severity, FirstCase: finding.FirstCase, Reproduce: finding.Reproduce}
			byCode[finding.SuggestionCode] = item
		}
		item.Evidence += finding.Occurrences
		if severityRank(finding.Severity) > severityRank(item.HighestSeverity) {
			item.HighestSeverity = finding.Severity
		}
		for _, caseNumber := range finding.ExampleCases {
			if len(item.ExampleCases) >= 3 || slices.Contains(item.ExampleCases, caseNumber) {
				continue
			}
			item.ExampleCases = append(item.ExampleCases, caseNumber)
		}
	}
	out := make([]HuntSuggestion, 0, len(byCode))
	for _, item := range byCode {
		sort.Ints(item.ExampleCases)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if severityRank(out[i].HighestSeverity) != severityRank(out[j].HighestSeverity) {
			return severityRank(out[i].HighestSeverity) > severityRank(out[j].HighestSeverity)
		}
		if out[i].Evidence != out[j].Evidence {
			return out[i].Evidence > out[j].Evidence
		}
		return strings.Compare(out[i].Code, out[j].Code) < 0
	})
	return boundEncodedList(out, huntMaxAggregateSuggestionsBytes)
}
