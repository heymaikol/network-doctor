package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/simulation"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// `netdoc-sim triage` hunts the known-good baselines at fixed seeds, proves
// each candidate finding by re-running its exact generated case, and files the
// survivors as GitHub issues through `gh`. Anything it cannot do, whether a hunt
// that could not run, output it cannot parse, a case it cannot re-run, or a `gh`
// call that fails, is an error, never a quietly filed guess.

// huntFunc runs one hunt and returns its parsed report. caseNumber is negative
// for a full hunt, or the exact case to regenerate and re-run.
type huntFunc func(ctx context.Context, scenario string, seed int64, cases, caseNumber int,
	generatorVersion string, lane simulation.HuntLane) (*simulation.HuntResult, error)

// ghFunc runs the `gh` CLI. The token lives in gh's environment and never
// appears in an argument, so nothing here can log it.
type ghFunc func(ctx context.Context, args ...string) ([]byte, error)

type triageOptions struct {
	baselines   []simulation.TriageBaseline
	cases       int
	maxFaults   int
	lane        simulation.HuntLane
	minSeverity simulation.HuntSeverity
	create      bool
	revision    string
	context     string
}

type triageFlags struct {
	fs          *flag.FlagSet
	json        *bool
	scenarios   *string
	cases       *int
	huntResults *string
	seed        optionalSeed
	maxFaults   *int
	lane        *string
	minSeverity *string
	create      *bool
	context     *string
	revision    *string
	netdoc      *string
	timeout     *time.Duration
	verbose     *bool
}

func newTriageFlags(out io.Writer) *triageFlags {
	f := &triageFlags{fs: flag.NewFlagSet("netdoc-sim triage", flag.ContinueOnError)}
	f.fs.SetOutput(out)
	f.json = f.fs.Bool("json", false, "print the machine-readable triage report")
	f.scenarios = f.fs.String("scenarios", "", "comma-separated baselines to hunt (default: all)")
	f.cases = f.fs.Int("cases", 20, "unique generated cases per baseline")
	f.huntResults = f.fs.String("hunt-results", "", "directory of canonical merged hunt JSON reports")
	f.fs.Var(&f.seed, "seed", "override the fixed seed of every selected baseline")
	f.maxFaults = f.fs.Int("max-faults", 2, "maximum mutations per case")
	f.lane = f.fs.String("lane", string(simulation.HuntLaneBugOracle), "Hunt lane: bug-oracle, stress, or all for historical reports")
	f.minSeverity = f.fs.String("min-severity", string(simulation.SeverityMedium),
		"lowest finding severity worth reproducing and filing")
	f.create = f.fs.Bool("create", false, "file reproducible findings as GitHub issues with gh")
	f.context = f.fs.String("context", "", "debugging context recorded in the issue body")
	f.revision = f.fs.String("revision", "", "commit SHA to record (default: the build's VCS revision)")
	f.netdoc = f.fs.String("netdoc", "", "path to the netdoc binary")
	f.timeout = f.fs.Duration("timeout", 4*time.Second, "netdoc per-probe timeout")
	f.verbose = f.fs.Bool("v", false, "log each privileged command as it runs")
	return f
}

func (f *triageFlags) parse(args []string) (*triageOptions, error) {
	if _, err := parseRef(f.fs, args); err != nil {
		return nil, err
	}
	if *f.cases < 1 || *f.cases > simulation.HuntMaxCases {
		return nil, fmt.Errorf("-cases must be between 1 and %d", simulation.HuntMaxCases)
	}
	if *f.maxFaults < 1 || *f.maxFaults > simulation.HuntMaxFaults {
		return nil, fmt.Errorf("-max-faults must be between 1 and %d", simulation.HuntMaxFaults)
	}
	if !slices.Contains(simulation.HuntLaneNames(), *f.lane) {
		return nil, fmt.Errorf("-lane must be one of %s", strings.Join(simulation.HuntLaneNames(), ", "))
	}
	// Validated the way netdoc validates its own -timeout, because that is
	// where this value is going: runner.go spells it onto the child's command
	// line. A value netdoc refuses would otherwise surface as every spawned run
	// exiting 2 with the real complaint buried in a child process.
	if err := diagnostic.ValidateProbeTimeout(*f.timeout); err != nil {
		return nil, err
	}
	baselines := simulation.TriageBaselines()
	if *f.scenarios != "" {
		baselines = nil
		for _, name := range strings.Split(*f.scenarios, ",") {
			name = strings.TrimSpace(name)
			baseline, ok := simulation.TriageBaselineFor(name)
			if !ok {
				return nil, fmt.Errorf("unsupported triage baseline %q (have: %s)",
					textsafe.Clean(name), strings.Join(triageBaselineNames(), ", "))
			}
			baselines = append(baselines, baseline)
		}
	}
	if f.seed.set {
		for i := range baselines {
			baselines[i].Seed = f.seed.v
		}
	}
	severity, ok := simulation.ParseSeverity(*f.minSeverity)
	if !ok {
		return nil, fmt.Errorf("-min-severity must be one of critical, high, medium, low, info")
	}
	return &triageOptions{baselines: baselines, cases: *f.cases, maxFaults: *f.maxFaults, lane: simulation.HuntLane(*f.lane), minSeverity: severity,
		create: *f.create, revision: buildRevision(*f.revision), context: *f.context}, nil
}

func triageBaselineNames() []string {
	baselines := simulation.TriageBaselines()
	names := make([]string, len(baselines))
	for i, baseline := range baselines {
		names[i] = baseline.Scenario
	}
	return names
}

func launchTriage(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newTriageFlags(stderr)
	opts, err := f.parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if caps := newBackend(false, nil).Capabilities(ctx); !caps.Supported {
		fmt.Fprintln(stderr, "netdoc-sim:", caps.Reason)
		return exitError
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	netdoc, err := findNetdoc(*f.netdoc, self)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	hunt := directorHunt(self, netdoc, *f.timeout, *f.maxFaults, *f.verbose, stderr)
	if *f.huntResults != "" {
		hunt, err = precomputedHunts(*f.huntResults, *opts, hunt)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc-sim: load hunt results:", err)
			return exitError
		}
	}
	report := triage(ctx, *opts, hunt, realGH)
	if *f.json {
		if err := report.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", err)
			return exitError
		}
	} else {
		report.WriteText(stdout)
	}
	return triageExit(report)
}

// triageExit keeps a captured bug out of the workflow's failure column: a
// reproducible finding that became an issue is a success for this tool. Only
// findings nobody recorded, and errors, are failures.
func triageExit(report *simulation.TriageReport) int {
	if report.Result == simulation.TriageResultError {
		return exitError
	}
	for _, finding := range report.Findings {
		if finding.Reproducible && finding.Issue.Status == simulation.IssueStatusNotFiled {
			return exitMismatch
		}
	}
	return exitOK
}

func triage(ctx context.Context, opts triageOptions, hunt huntFunc, gh ghFunc) *simulation.TriageReport {
	report := &simulation.TriageReport{Revision: opts.revision, Context: opts.context, Lane: opts.lane,
		Baselines: []simulation.TriageScenarioResult{}, Findings: []simulation.TriageFinding{},
		Result: simulation.TriageResultClean}
	fail := func(format string, args ...any) *simulation.TriageReport {
		report.Result, report.Error = simulation.TriageResultError, fmt.Sprintf(format, args...)
		return report
	}
	for _, baseline := range opts.baselines {
		result, err := hunt(ctx, baseline.Scenario, baseline.Seed, opts.cases, -1, simulation.HuntGeneratorVersion, opts.lane)
		if err != nil {
			return fail("hunt %s seed %d: %v", baseline.Scenario, baseline.Seed, err)
		}
		report.Baselines = append(report.Baselines, simulation.TriageScenarioResult{Scenario: baseline.Scenario,
			Seed: baseline.Seed, Cases: result.ExecutedCases, Candidates: len(result.Findings),
			HuntResult: result.Result, Coverage: result.Coverage})
		summary := &report.Baselines[len(report.Baselines)-1]
		if result.Result == simulation.HuntResultError || result.Result == simulation.HuntResultCancelled {
			return fail("hunt %s seed %d: %s: %s", baseline.Scenario, baseline.Seed, result.ErrorKind, result.Error)
		}
		for _, candidate := range result.Findings {
			// Reproducing a case costs a whole simulated run, so the floor is
			// applied before the work, not after it.
			if !simulation.SeverityAtLeast(candidate.Severity, opts.minSeverity) {
				summary.Filtered++
				continue
			}
			finding, err := verify(ctx, hunt, candidate)
			if err != nil {
				return fail("reproduce %s seed %d case %d: %v", candidate.Reproduce.BaseScenario,
					candidate.Reproduce.Seed, candidate.Reproduce.Case, err)
			}
			report.Findings = append(report.Findings, finding)
		}
	}
	for i := range report.Findings {
		if !report.Findings[i].Reproducible {
			continue
		}
		report.Result = simulation.TriageResultFindings
		if !opts.create {
			continue
		}
		if err := file(ctx, gh, &report.Findings[i], opts.revision, opts.context); err != nil {
			return fail("file issue %s: %v", report.Findings[i].Fingerprint, err)
		}
	}
	return report
}

// verify re-runs the one generated case the finding came from. Reproducible
// means the same case fingerprint produced the same finding fingerprint again.
func verify(ctx context.Context, hunt huntFunc, candidate simulation.HuntFinding) (simulation.TriageFinding, error) {
	out := simulation.NewTriageFinding(candidate)
	result, err := hunt(ctx, out.Scenario, out.Seed, 1, out.Case, out.GeneratorVersion, out.Lane)
	if err != nil {
		return out, err
	}
	if result.Result == simulation.HuntResultError || result.Result == simulation.HuntResultCancelled {
		return out, fmt.Errorf("%s: %s", result.ErrorKind, result.Error)
	}
	if len(result.Cases) != 1 {
		return out, fmt.Errorf("re-run produced %d cases, want 1", len(result.Cases))
	}
	replay := result.Cases[0]
	if replay.Manifest.CaseFingerprint != out.CaseFingerprint {
		return out, fmt.Errorf("re-run generated case fingerprint %s, want %s",
			replay.Manifest.CaseFingerprint, out.CaseFingerprint)
	}
	out.Truth, out.Diagnosis, out.Mutations = replay.Truth, replay.DiagnosisFingerprint, replay.Manifest.Mutations
	for _, found := range replay.Findings {
		if found.Fingerprint == candidate.Fingerprint {
			out.Reproducible = true
			break
		}
	}
	return out, nil
}

// file searches open issues for the fingerprint before creating one. The
// fingerprint is a bare hex word in the title, so the search cannot half-match
// something else, and the returned titles are checked again anyway.
func file(ctx context.Context, gh ghFunc, finding *simulation.TriageFinding, revision, runContext string) error {
	raw, err := gh(ctx, "issue", "list", "--state", "open", "--limit", "50",
		"--search", finding.Fingerprint+" in:title", "--json", "number,title,url")
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	var existing []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(raw, &existing); err != nil {
		return fmt.Errorf("search: cannot parse gh output: %w", err)
	}
	for _, issue := range existing {
		if strings.Contains(issue.Title, finding.Fingerprint) {
			finding.Issue = simulation.TriageIssue{Status: simulation.IssueStatusExisting, URL: issue.URL}
			return nil
		}
	}
	body, err := os.CreateTemp("", "netdoc-sim-triage-*.md")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(body.Name()) }() // gh has read it by then
	if _, err := io.WriteString(body, finding.IssueBody(revision, runContext)); err != nil {
		_ = body.Close()
		return err
	}
	if err := body.Close(); err != nil {
		return err
	}
	created, err := gh(ctx, "issue", "create", "--title", finding.IssueTitle(), "--body-file", body.Name())
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	finding.Issue = simulation.TriageIssue{Status: simulation.IssueStatusCreated,
		URL: strings.TrimSpace(string(created))}
	return nil
}

func realGH(ctx context.Context, args ...string) ([]byte, error) {
	// #nosec G204 -- gh is fixed and args remain separate argv elements, never shell text.
	cmd := exec.CommandContext(ctx, "gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gh %s: %w: %s", args[0], err, textsafe.Clean(strings.TrimSpace(stderr.String())))
	}
	return stdout.Bytes(), nil
}

// directorHunt runs a real hunt exactly as `netdoc-sim hunt -json` does, with the
// same flag parsing, director argv and namespaces, and captures the report.
func directorHunt(self, netdoc string, timeout time.Duration, maxFaults int, verbose bool, stderr io.Writer) huntFunc {
	return func(ctx context.Context, scenario string, seed int64, cases, caseNumber int,
		generatorVersion string, lane simulation.HuntLane) (*simulation.HuntResult, error) {
		f := newHuntFlags(io.Discard)
		if _, err := f.parse([]string{scenario, "-json", "-seed", strconv.FormatInt(seed, 10),
			"-cases", strconv.Itoa(cases), "-case", strconv.Itoa(caseNumber),
			"-max-faults", strconv.Itoa(maxFaults), "-generator-version", generatorVersion, "-lane", string(lane), "-timeout", timeout.String(),
			fmt.Sprintf("-v=%t", verbose)}); err != nil {
			return nil, err
		}
		var out bytes.Buffer
		code, err := launchDirector(ctx, self, huntDirectorArgv(f, scenario, netdoc), nil, &out, stderr)
		if err != nil {
			return nil, err
		}
		// A failed hunt still writes its report, and that report is the only
		// place the reason lives: the director puts it on stdout, not stderr.
		// Reporting the exit code alone would throw away the sentence CI needs.
		var result simulation.HuntResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			if code == exitUsage || code == exitError {
				return nil, fmt.Errorf("hunt exited %d without a readable report: %w", code, err)
			}
			return nil, fmt.Errorf("cannot parse the hunt report: %w", err)
		}
		// A report that disagrees with the exit code is not a report to hunt on.
		if (code == exitUsage || code == exitError) &&
			result.Result != simulation.HuntResultError && result.Result != simulation.HuntResultCancelled {
			return nil, fmt.Errorf("hunt exited %d but reported %q", code, textsafe.Clean(result.Result))
		}
		return &result, nil
	}
}

// precomputedHunts replaces only triage's full hunts. Exact-case verification
// still launches a fresh director, so a merged candidate earns an issue under
// the same reproduction rule as a locally generated one.
func precomputedHunts(dir string, opts triageOptions, replay huntFunc) (huntFunc, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	wanted := make(map[string]simulation.TriageBaseline, len(opts.baselines))
	for _, baseline := range opts.baselines {
		wanted[baseline.Scenario] = baseline
	}
	reports := make(map[string]*simulation.HuntResult, len(wanted))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		result, err := readHuntResult(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := simulation.ValidateMergedHuntResult(result); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		baseline, ok := wanted[result.BaseScenario]
		if !ok {
			return nil, fmt.Errorf("%s contains unrequested baseline %q", entry.Name(), result.BaseScenario)
		}
		if _, exists := reports[result.BaseScenario]; exists {
			return nil, fmt.Errorf("duplicate hunt result for %s", result.BaseScenario)
		}
		if result.HuntSeed != baseline.Seed || result.RequestedCases != opts.cases ||
			result.MaxFaults != opts.maxFaults || result.DryRun || result.FailFast {
			return nil, fmt.Errorf("%s hunt configuration does not match triage", result.BaseScenario)
		}
		resolvedLane, err := simulation.ResolveHuntLane(result.GeneratorVersion, result.Lane)
		if err != nil || resolvedLane != opts.lane {
			return nil, fmt.Errorf("%s hunt lane does not match triage", result.BaseScenario)
		}
		reports[result.BaseScenario] = result
	}
	for _, baseline := range opts.baselines {
		if reports[baseline.Scenario] == nil {
			return nil, fmt.Errorf("missing hunt result for %s", baseline.Scenario)
		}
	}
	return func(ctx context.Context, scenario string, seed int64, cases, caseNumber int,
		generatorVersion string, lane simulation.HuntLane) (*simulation.HuntResult, error) {
		if caseNumber >= 0 {
			return replay(ctx, scenario, seed, cases, caseNumber, generatorVersion, lane)
		}
		result := reports[scenario]
		if result == nil || result.HuntSeed != seed || result.RequestedCases != cases {
			return nil, fmt.Errorf("no matching merged hunt for %s seed %d with %d cases", scenario, seed, cases)
		}
		resolvedLane, _ := simulation.ResolveHuntLane(result.GeneratorVersion, result.Lane)
		if resolvedLane != lane {
			return nil, fmt.Errorf("no matching merged %s hunt for %s", lane, scenario)
		}
		return result, nil
	}, nil
}

// buildRevision prefers what the caller passed, then the VCS revision the Go
// toolchain stamps into the binary.
func buildRevision(want string) string {
	if want != "" {
		return want
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if i := slices.IndexFunc(info.Settings, func(s debug.BuildSetting) bool { return s.Key == "vcs.revision" }); i >= 0 {
		return info.Settings[i].Value
	}
	return "unknown"
}
