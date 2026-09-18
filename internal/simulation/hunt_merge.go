package simulation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// MergeHuntResults reconstructs one logical hunt from a complete set of shard
// reports. Input order is irrelevant; case order comes from global case ids.
func MergeHuntResults(inputs ...*HuntResult) (*HuntResult, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no hunt shard results")
	}
	for i, input := range inputs {
		if input == nil {
			return nil, fmt.Errorf("input %d is nil", i)
		}
		if input.Shard == nil {
			return nil, fmt.Errorf("input %d has no shard metadata", i)
		}
		if err := validateHuntMetadata(input); err != nil {
			return nil, fmt.Errorf("input %d: %w", i, err)
		}
	}

	first := inputs[0]
	count := first.Shard.Count
	ordered := make([]*HuntResult, count)
	for i, input := range inputs {
		if err := compatibleHuntResults(first, input); err != nil {
			return nil, fmt.Errorf("input %d: %w", i, err)
		}
		index := input.Shard.Index
		if ordered[index] != nil {
			return nil, fmt.Errorf("duplicate shard %d/%d", index, count)
		}
		ordered[index] = input
	}
	for index, input := range ordered {
		if input == nil {
			return nil, fmt.Errorf("missing shard %d/%d", index, count)
		}
	}

	expected, duplicates, err := expectedHuntManifests(first)
	if err != nil {
		return nil, err
	}
	owners := make(map[int]int, len(expected))
	for _, input := range ordered {
		for _, item := range input.Cases {
			caseNumber := item.Manifest.Case
			if owner, exists := owners[caseNumber]; exists {
				return nil, fmt.Errorf("duplicate global case %d in shards %d/%d and %d/%d",
					caseNumber, owner, count, input.Shard.Index, count)
			}
			owners[caseNumber] = input.Shard.Index
		}
	}

	lane, _ := resolveRecordedHuntLane(first.GeneratorVersion, first.Lane)
	merged := &HuntResult{GeneratorVersion: first.GeneratorVersion, Lane: lane, BaseScenario: first.BaseScenario,
		HuntSeed: first.HuntSeed, RequestedCases: first.RequestedCases, MaxFaults: first.MaxFaults,
		FailFast: first.FailFast, DryRun: first.DryRun, Cases: []HuntCaseResult{}}
	complete := true
	var failures []string
	for _, input := range ordered {
		want := manifestsForShard(expected, *input.Shard)
		if err := validateHuntCases(input, want, duplicates); err != nil {
			return nil, fmt.Errorf("shard %d/%d: %w", input.Shard.Index, input.Shard.Count, err)
		}
		complete = complete && len(input.Cases) == len(want)
		merged.Cases = append(merged.Cases, input.Cases...)
		merged.ExecutedCases += input.ExecutedCases
		merged.FailFastStopped = merged.FailFastStopped || input.FailFastStopped
		merged.Cancelled = merged.Cancelled || input.Cancelled
		merged.RuntimeFailure = merged.RuntimeFailure || input.RuntimeFailure
		if input.Result == HuntResultError || input.Result == HuntResultCancelled {
			failures = append(failures, fmt.Sprintf("shard %d/%d: %s: %s",
				input.Shard.Index, input.Shard.Count, input.ErrorKind, input.Error))
		}
	}
	sort.Slice(merged.Cases, func(i, j int) bool {
		return merged.Cases[i].Manifest.Case < merged.Cases[j].Manifest.Case
	})
	merged.GeneratedCases, merged.UniqueCases = len(merged.Cases), len(merged.Cases)
	if complete {
		merged.DuplicateCandidates = duplicates
	} else {
		for _, input := range ordered {
			merged.DuplicateCandidates = max(merged.DuplicateCandidates, input.DuplicateCandidates)
		}
	}
	if len(failures) > 0 {
		merged.Result, merged.ErrorKind, merged.Error = HuntResultError, "shard", clip(strings.Join(failures, "; "))
		if merged.Cancelled && !slicesContainResult(ordered, HuntResultError) {
			merged.Result, merged.ErrorKind = HuntResultCancelled, "cancellation"
		}
	}
	merged.finish()
	return merged, nil
}

// ValidateMergedHuntResult validates a canonical, unsharded result before a
// downstream consumer trusts its findings or reproduction coordinates.
func ValidateMergedHuntResult(result *HuntResult) error {
	if result == nil {
		return fmt.Errorf("hunt result is nil")
	}
	if result.Shard != nil {
		return fmt.Errorf("hunt result still carries shard metadata")
	}
	if err := validateHuntMetadata(result); err != nil {
		return err
	}
	expected, duplicates, err := expectedHuntManifests(result)
	if err != nil {
		return err
	}
	return validateHuntCases(result, expected, duplicates)
}

func validateHuntMetadata(result *HuntResult) error {
	if err := validateHuntGeneratorVersion(result.GeneratorVersion); err != nil {
		return err
	}
	if _, err := resolveRecordedHuntLane(result.GeneratorVersion, result.Lane); err != nil {
		return err
	}
	if !validHuntBase(result.BaseScenario) {
		return fmt.Errorf("unsupported base scenario %q", result.BaseScenario)
	}
	if result.RequestedCases < 1 || result.RequestedCases > HuntMaxCases {
		return fmt.Errorf("requested cases must be between 1 and %d", HuntMaxCases)
	}
	if result.MaxFaults < 1 || result.MaxFaults > HuntMaxFaults {
		return fmt.Errorf("max faults must be between 1 and %d", HuntMaxFaults)
	}
	if result.Shard != nil {
		if err := result.Shard.Validate(); err != nil {
			return err
		}
	}
	if result.FailFastStopped && !result.FailFast {
		return fmt.Errorf("fail-fast stopped without fail-fast enabled")
	}
	switch result.Result {
	case HuntResultClean, HuntResultFindings, HuntResultError, HuntResultCancelled:
	default:
		return fmt.Errorf("unknown hunt result %q", result.Result)
	}
	return nil
}

func compatibleHuntResults(want, got *HuntResult) error {
	if got.GeneratorVersion != want.GeneratorVersion {
		return fmt.Errorf("generator version %q does not match %q", got.GeneratorVersion, want.GeneratorVersion)
	}
	wantLane, _ := resolveRecordedHuntLane(want.GeneratorVersion, want.Lane)
	gotLane, _ := resolveRecordedHuntLane(got.GeneratorVersion, got.Lane)
	if gotLane != wantLane {
		return fmt.Errorf("hunt lane %q does not match %q", gotLane, wantLane)
	}
	if got.BaseScenario != want.BaseScenario {
		return fmt.Errorf("base scenario %q does not match %q", got.BaseScenario, want.BaseScenario)
	}
	if got.HuntSeed != want.HuntSeed {
		return fmt.Errorf("hunt seed %d does not match %d", got.HuntSeed, want.HuntSeed)
	}
	if got.RequestedCases != want.RequestedCases {
		return fmt.Errorf("requested cases %d does not match %d", got.RequestedCases, want.RequestedCases)
	}
	if got.MaxFaults != want.MaxFaults {
		return fmt.Errorf("max faults %d does not match %d", got.MaxFaults, want.MaxFaults)
	}
	if got.Shard.Count != want.Shard.Count {
		return fmt.Errorf("shard count %d does not match %d", got.Shard.Count, want.Shard.Count)
	}
	if got.FailFast != want.FailFast {
		return fmt.Errorf("fail-fast setting does not match")
	}
	if got.DryRun != want.DryRun {
		return fmt.Errorf("dry-run setting does not match")
	}
	return nil
}

func expectedHuntManifests(result *HuntResult) ([]GeneratedCaseManifest, int, error) {
	base, err := LibraryScenario(result.BaseScenario)
	if err != nil {
		return nil, 0, err
	}
	lane, err := resolveRecordedHuntLane(result.GeneratorVersion, result.Lane)
	if err != nil {
		return nil, 0, err
	}
	stream := newHuntCaseStream(result.GeneratorVersion, lane, result.BaseScenario, base, result.HuntSeed,
		result.RequestedCases, result.MaxFaults, nil)
	manifests := make([]GeneratedCaseManifest, 0, result.RequestedCases)
	for stream.accepted < stream.target {
		generated, err := stream.next()
		if err != nil {
			return nil, 0, err
		}
		manifests = append(manifests, generated.Manifest)
	}
	return manifests, stream.duplicates, nil
}

func manifestsForShard(all []GeneratedCaseManifest, shard HuntShard) []GeneratedCaseManifest {
	out := make([]GeneratedCaseManifest, 0, len(all)/shard.Count+1)
	for _, manifest := range all {
		if shard.Includes(manifest.Case) {
			out = append(out, manifest)
		}
	}
	return out
}

func validateHuntCases(result *HuntResult, expected []GeneratedCaseManifest, duplicates int) error {
	partial := result.FailFastStopped || result.Cancelled || result.Result == HuntResultCancelled
	if !partial && len(result.Cases) != len(expected) {
		return fmt.Errorf("missing expected cases: have %d, want %d", len(result.Cases), len(expected))
	}
	if len(result.Cases) > len(expected) {
		return fmt.Errorf("have %d cases, want at most %d", len(result.Cases), len(expected))
	}
	if result.GeneratedCases != len(result.Cases) || result.UniqueCases != len(result.Cases) {
		return fmt.Errorf("case counters do not match %d case results", len(result.Cases))
	}
	if !partial && result.DuplicateCandidates != duplicates {
		return fmt.Errorf("duplicate candidate count %d does not match %d", result.DuplicateCandidates, duplicates)
	}

	expectedByCase := make(map[int]GeneratedCaseManifest, len(expected))
	for _, manifest := range expected {
		expectedByCase[manifest.Case] = manifest
	}
	clean, executed := 0, 0
	for i, item := range result.Cases {
		if i > 0 && result.Cases[i-1].Manifest.Case >= item.Manifest.Case {
			return fmt.Errorf("case results are not in increasing global order")
		}
		want, ok := expectedByCase[item.Manifest.Case]
		if !ok {
			return fmt.Errorf("unexpected global case %d", item.Manifest.Case)
		}
		// The stored case, weighed as written. canonicalHuntCaseResult below
		// bounds what it derives, so without this a shard whose derived fields
		// were computed from an oversized report it also carries would pass
		// into a merged result that no longer fits the budget its own reader
		// enforces.
		if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
			return fmt.Errorf("global case %d result is %d bytes, over the maximum of %d",
				item.Manifest.Case, size, HuntMaxCaseResultBytes)
		}
		if result.Shard != nil && i < len(expected) && !partial {
			want = expected[i]
		}
		if !reflect.DeepEqual(item.Manifest, want) {
			return fmt.Errorf("global case %d manifest does not match deterministic generation", item.Manifest.Case)
		}
		if result.Shard != nil && partial && i < len(expected) && !reflect.DeepEqual(item.Manifest, expected[i]) {
			return fmt.Errorf("partial shard skipped expected global case %d", expected[i].Case)
		}
		for _, finding := range item.Findings {
			if finding.Fingerprint != huntFindingFingerprint(finding) {
				return fmt.Errorf("global case %d has invalid finding fingerprint %q", item.Manifest.Case, finding.Fingerprint)
			}
			if !reflect.DeepEqual(finding.Reproduce, reproductionFor(item.Manifest)) {
				return fmt.Errorf("global case %d has incompatible reproduction metadata", item.Manifest.Case)
			}
		}
		if result.DryRun {
			if item.Report != nil || item.Status != "generated" {
				return fmt.Errorf("dry-run global case %d carries execution output", item.Manifest.Case)
			}
		} else if item.Report == nil || item.Status == "generated" {
			return fmt.Errorf("executed global case %d has no execution output", item.Manifest.Case)
		}
		wantItem := canonicalHuntCaseResult(item.Manifest, item.Report)
		if result.DryRun {
			wantItem.Report = nil
		}
		if !reflect.DeepEqual(item.Truth, wantItem.Truth) ||
			item.TruthFingerprint != wantItem.TruthFingerprint ||
			!reflect.DeepEqual(item.DiagnosisFingerprint, wantItem.DiagnosisFingerprint) ||
			!reflect.DeepEqual(item.Findings, wantItem.Findings) || item.Status != wantItem.Status {
			return fmt.Errorf("global case %d result does not match its manifest and report", item.Manifest.Case)
		}
		if item.Report != nil {
			executed++
		}
		if item.Status == "clean" {
			clean++
		}
		if item.Status == "clean" || item.Status == "findings" {
			if item.TruthFingerprint != truthFingerprint(item.Truth) {
				return fmt.Errorf("global case %d has invalid truth fingerprint", item.Manifest.Case)
			}
		}
	}
	if result.ExecutedCases != executed {
		return fmt.Errorf("executed case count %d does not match %d reports", result.ExecutedCases, executed)
	}
	if result.CleanCases != clean {
		return fmt.Errorf("clean case count %d does not match %d", result.CleanCases, clean)
	}
	// Coverage is derived from the case results and nothing else, so a merged
	// hunt's coverage has to equal what the same cases would produce unsharded.
	// Recomputing it here is what holds that, and what stops a hand-edited
	// artifact from claiming ground it never stood on.
	wantCoverage := huntCoverageFor(result.GeneratorVersion, result.Lane, result.BaseScenario, result.Cases)
	if !reflect.DeepEqual(result.Coverage, wantCoverage) {
		return fmt.Errorf("coverage does not match case results")
	}
	wantFindings := aggregateHuntFindings(result.Cases)
	wantSuggestions := aggregateHuntSuggestions(wantFindings)
	if !reflect.DeepEqual(result.Findings, wantFindings) {
		return fmt.Errorf("aggregate findings do not match case findings")
	}
	if !reflect.DeepEqual(result.Suggestions, wantSuggestions) {
		return fmt.Errorf("aggregate suggestions do not match findings")
	}
	if result.FailFastStopped {
		if len(result.Cases) == 0 || len(result.Cases[len(result.Cases)-1].Findings) == 0 {
			return fmt.Errorf("fail-fast result did not stop on a finding")
		}
	}
	if result.Result == HuntResultClean && (len(result.Findings) > 0 || result.RuntimeFailure || result.Cancelled) {
		return fmt.Errorf("clean result carries findings or failures")
	}
	if result.Result == HuntResultFindings && len(result.Findings) == 0 {
		return fmt.Errorf("findings result carries no findings")
	}
	if result.Result == HuntResultCancelled && !result.Cancelled {
		return fmt.Errorf("cancelled result is not marked cancelled")
	}
	return nil
}

func slicesContainResult(results []*HuntResult, want string) bool {
	for _, result := range results {
		if result.Result == want {
			return true
		}
	}
	return false
}
