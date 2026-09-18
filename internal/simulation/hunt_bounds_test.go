package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// netdocReportWithSummary is netdoc's own report JSON with a summary of the
// requested length: the shortest route to a simulation report whose size the
// model does not control, since nothing between a subprocess's stdout and a
// stored hunt case shortens what netdoc wrote there.
func netdocReportWithSummary(n int) string {
	return `{"checks":[{"id":"internet_tcp","status":"WARN","cause":"gateway_unreachable",` +
		`"detail":"d","address_families":{"IPv4":"unreachable","IPv6":"unavailable"}}],` +
		`"verdict":"network","summary":"` + strings.Repeat("x", n) + `"}`
}

// huntCaseWithStderr is one stored case whose report carries the given captured
// stderr, which is the field with the clearest claim to being unbounded: the
// runner cleans a subprocess's stderr and never truncates it.
func huntCaseWithStderr(t *testing.T, stderr string) HuntCaseResult {
	t.Helper()
	base := loadHuntBase(t, "healthy")
	generated, err := generateHuntCase(HuntGeneratorVersion, "healthy", base, 20260917, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	report := &Report{Scenario: "healthy", ID: "case-3", Backend: "fake", Result: ResultPass,
		Cleanup: CleanupInfo{Done: true},
		Tests:   []TestOutcome{{Name: "client", Node: "client", ProcessOutcome: ProcessExited, Stderr: stderr}}}
	report.finish()
	return canonicalHuntCaseResult(generated.Manifest, report)
}

// huntCaseFillToCeiling is the stderr length that lands a stored case exactly
// on HuntMaxCaseResultBytes. It is measured rather than assumed, and measured
// against a case that already carries one byte of fill, because the field is
// omitempty and an absent key is not the same baseline as a present one. The
// fill encodes one byte per byte, so the remaining distance is the answer.
func huntCaseFillToCeiling(t *testing.T) int {
	t.Helper()
	one := huntEncodedElementSize(huntCaseWithStderr(t, "x"))
	if one > HuntMaxCaseResultBytes {
		t.Fatalf("a case with one byte of fill already measures %d bytes, over the %d byte ceiling",
			one, HuntMaxCaseResultBytes)
	}
	return HuntMaxCaseResultBytes - one + 1
}

// TestHuntCaseBudgetIsEnforcedAtItsExactBoundary pins the per-case ceiling from
// both sides. A case sitting exactly on HuntMaxCaseResultBytes keeps the report
// it was given; one byte more and the stored report is the bounded stand-in,
// which is what makes HuntMaxCaseResultBytes a property of the model rather
// than an estimate of what hunts usually produce.
func TestHuntCaseBudgetIsEnforcedAtItsExactBoundary(t *testing.T) {
	fill := huntCaseFillToCeiling(t)
	at := huntCaseWithStderr(t, strings.Repeat("x", fill))
	if size := huntEncodedElementSize(at); size != HuntMaxCaseResultBytes {
		t.Fatalf("the boundary case measures %d bytes, want exactly %d", size, HuntMaxCaseResultBytes)
	}
	if at.Report == nil || len(at.Report.Tests) != 1 || len(at.Report.Tests[0].Stderr) != fill {
		t.Fatalf("a case exactly on the ceiling did not keep its report: %+v", at.Report)
	}
	if at.Status == "runtime_error" {
		t.Fatalf("a case exactly on the ceiling was treated as oversized")
	}

	over := huntCaseWithStderr(t, strings.Repeat("x", fill+1))
	if over.Report == nil || len(over.Report.Tests) > 0 {
		t.Fatalf("a case one byte over the ceiling kept its report: %+v", over.Report)
	}
	want := "simulation report exceeds the " + strconv.Itoa(HuntMaxCaseResultBytes) + " byte hunt case budget"
	if over.Report.Error != want {
		t.Errorf("stand-in error is %q, want %q", over.Report.Error, want)
	}
	if over.Status != "runtime_error" {
		t.Errorf("oversized case status is %q, want runtime_error", over.Status)
	}
	if size := huntEncodedElementSize(over); size > HuntMaxCaseResultBytes {
		t.Errorf("the stand-in case still measures %d bytes, over the %d byte ceiling", size, HuntMaxCaseResultBytes)
	}
}

// TestHuntCaseBudgetCountsJSONEscaping is why the ceiling is applied to encoded
// bytes and not to Go string lengths. Text made of characters the encoder
// expands sixfold is well inside the ceiling as a string and well outside it as
// JSON, and it is the JSON that a merge has to allocate.
func TestHuntCaseBudgetCountsJSONEscaping(t *testing.T) {
	// Each of these encodes as <, so the stored case is about six times
	// the size of the text it holds.
	stderr := strings.Repeat("<", HuntMaxCaseResultBytes/2)
	if len(stderr) >= HuntMaxCaseResultBytes {
		t.Fatalf("the fill is %d bytes, which a length check would already refuse", len(stderr))
	}
	item := huntCaseWithStderr(t, stderr)
	if item.Status != "runtime_error" {
		t.Fatalf("a case whose text escapes past the ceiling was stored verbatim, status %q", item.Status)
	}
	if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
		t.Errorf("the stand-in measures %d bytes, over the %d byte ceiling", size, HuntMaxCaseResultBytes)
	}
}

// TestOversizedHuntReportsMergeAsTheSameCanonicalCase is the symmetry the
// bound stands on. A hunt whose every case produced an oversized report writes
// a shard, and merging that shard back recomputes truth, fingerprints,
// findings and status from the stored stand-in and agrees with what generation
// stored. If the two sides canonicalized differently this fails, whatever the
// sizes are.
func TestOversizedHuntReportsMergeAsTheSameCanonicalCase(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	shard := HuntShard{Index: 0, Count: 1}
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{
			stdout:   netdocReportWithSummary(HuntMaxCaseResultBytes),
			evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 3, Seed: 20260917, MaxFaults: 2, Shard: &shard})
	if len(result.Cases) != 3 {
		t.Fatalf("generated %d cases, want 3", len(result.Cases))
	}
	for _, item := range result.Cases {
		if item.Status != "runtime_error" {
			t.Fatalf("case %d status is %q, want runtime_error from the oversized report", item.Manifest.Case, item.Status)
		}
		if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
			t.Fatalf("case %d stores %d bytes, over the %d byte ceiling", item.Manifest.Case, size, HuntMaxCaseResultBytes)
		}
	}

	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > HuntMaxResultBytes {
		t.Fatalf("the shard writes %d bytes, over HuntMaxResultBytes %d", buf.Len(), HuntMaxResultBytes)
	}
	var decoded HuntResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	merged, err := MergeHuntResults(&decoded)
	if err != nil {
		t.Fatalf("merging a shard of oversized reports: %v", err)
	}
	if err := ValidateMergedHuntResult(merged); err != nil {
		t.Fatalf("validating the merge of oversized reports: %v", err)
	}
}

// TestMergeRefusesACaseResultOverTheCeiling closes the one gap a hand-written
// shard could still walk through. canonicalHuntCaseResult bounds what it
// derives, so a shard can carry an oversized report next to derived fields that
// match the stand-in and satisfy every semantic check. The stored case is
// therefore weighed as well, and this builds exactly that shard: a case whose
// derived fields are the stand-in's and whose report is not.
func TestMergeRefusesACaseResultOverTheCeiling(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	shard := HuntShard{Index: 0, Count: 1}
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{
			stdout:   netdocReportWithSummary(HuntMaxCaseResultBytes),
			evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 2, Seed: 20260917, MaxFaults: 2, Shard: &shard})
	if _, err := MergeHuntResults(result); err != nil {
		t.Fatalf("the unmodified shard does not merge: %v", err)
	}

	// The stand-in keeps only fields oversizedHuntReport copies, so growing it
	// leaves every derived field, and every recomputation of them, unchanged.
	result.Cases[0].Report.Tests = []TestOutcome{{Name: "client", Node: "client",
		ProcessOutcome: ProcessExited, Stderr: strings.Repeat("x", HuntMaxCaseResultBytes)}}
	if size := huntEncodedElementSize(result.Cases[0]); size <= HuntMaxCaseResultBytes {
		t.Fatalf("the tampered case measures %d bytes, which is not over the %d byte ceiling",
			size, HuntMaxCaseResultBytes)
	}
	_, err := MergeHuntResults(result)
	if err == nil {
		t.Fatal("a shard carrying an oversized case result merged")
	}
	if !strings.Contains(err.Error(), "over the maximum of "+strconv.Itoa(HuntMaxCaseResultBytes)) {
		t.Fatalf("error = %q, want it to name the per-case maximum", err)
	}
}

// TestHuntAggregateSectionsAreBounded covers the two sections whose row count
// is a function of the cases rather than of a fixed vocabulary. Both are
// deterministically ordered projections of case findings, so bounding them
// costs a summary its tail and costs the artifact nothing, and the bounded list
// is what the deterministic merge validation recomputes.
func TestHuntAggregateSectionsAreBounded(t *testing.T) {
	summary := strings.Repeat("y", 8<<10)
	codes := []string{SuggestMissedFinding, SuggestWrongSeverity, SuggestWrongCause, SuggestFalsePositive,
		SuggestWrongVerdict, SuggestProbeTimedOut, SuggestNoFixHint, SuggestNondeterministic, SuggestNoDiagnosis}
	cases := make([]HuntCaseResult, 0, 512)
	for i := 0; i < 512; i++ {
		finding := HuntCaseFinding{Fingerprint: "fp" + strconv.Itoa(i), Category: FindingFalseNegative,
			Severity: SeverityHigh, Code: "code" + strconv.Itoa(i), SuggestionCode: codes[i%len(codes)],
			Summary: summary, Evidence: summary}
		cases = append(cases, HuntCaseResult{Manifest: GeneratedCaseManifest{Case: i}, Status: "findings",
			Findings: []HuntCaseFinding{finding}})
	}

	findings := aggregateHuntFindings(cases)
	if len(findings) == 0 || len(findings) >= len(cases) {
		t.Fatalf("kept %d of %d distinct findings, want a bounded prefix", len(findings), len(cases))
	}
	if size := len(mustMarshalIndent(t, findings)); size > huntMaxAggregateFindingsBytes {
		t.Errorf("the findings section measures %d bytes, over %d", size, huntMaxAggregateFindingsBytes)
	}
	suggestions := aggregateHuntSuggestions(findings)
	if size := len(mustMarshalIndent(t, suggestions)); size > huntMaxAggregateSuggestionsBytes {
		t.Errorf("the suggestions section measures %d bytes, over %d", size, huntMaxAggregateSuggestionsBytes)
	}

	// The same comparison validateHuntCases makes: a bounded section has to be
	// exactly what recomputing it from the cases produces, or a merge rejects
	// every hunt large enough to reach the ceiling.
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, BaseScenario: "healthy",
		RequestedCases: len(cases), MaxFaults: 2, Cases: cases}
	result.finish()
	if !reflect.DeepEqual(result.Findings, aggregateHuntFindings(result.Cases)) {
		t.Error("the stored findings section is not what recomputing it produces")
	}
	if !reflect.DeepEqual(result.Suggestions, aggregateHuntSuggestions(result.Findings)) {
		t.Error("the stored suggestions section is not what recomputing it produces")
	}
}

// TestHuntRunSummaryFitsItsBudget holds huntMaxRunSummaryBytes against the
// largest run metadata and coverage model the vocabularies allow: every
// registry operator and every oracle condition for the base and lane, the fault
// cardinality filled to HuntMaxFaults, and an error string clipped from text
// that encodes six bytes to the character.
func TestHuntRunSummaryFitsItsBudget(t *testing.T) {
	worst := 0
	for _, name := range HuntBaseNames() {
		base := loadHuntBase(t, name)
		for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
			result := RunHunt(context.Background(), name, base, func() Backend {
				return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
			}, HuntOptions{Cases: 24, Seed: 777, MaxFaults: HuntMaxFaults, Lane: lane})
			// The three weighed sections are budgeted separately, so what is
			// left is what this ceiling has to cover.
			result.Cases, result.Findings, result.Suggestions = []HuntCaseResult{}, []HuntFinding{}, []HuntSuggestion{}
			result.Error, result.ErrorKind = clip(strings.Repeat("<", 4<<10)), "runtime"
			for len(result.Coverage.Cardinality) < HuntMaxFaults {
				result.Coverage.Cardinality = append(result.Coverage.Cardinality, HuntMaxCases)
			}
			var buf bytes.Buffer
			if err := result.WriteJSON(&buf); err != nil {
				t.Fatal(err)
			}
			if buf.Len() > worst {
				worst = buf.Len()
			}
			if buf.Len() > huntMaxRunSummaryBytes {
				t.Errorf("%s %s writes a %d byte run summary, over huntMaxRunSummaryBytes %d",
					name, lane, buf.Len(), huntMaxRunSummaryBytes)
			}
		}
	}
	t.Logf("largest run summary: %d/%d bytes", worst, huntMaxRunSummaryBytes)
}

// TestMaximumBudgetedHuntResultFitsTheDeclaredMaximum is the byte accounting
// theorem the reader depends on: HuntMaxResultBytes is the sum of four enforced
// ceilings, so a result built with every one of them saturated still fits, and
// the four ceilings add up to the document the writer emits.
//
// What it builds is a budget object, not a hunt. Every section is filled to the
// limit its own producer enforces: HuntMaxCases copies of one synthetic case
// that measures exactly HuntMaxCaseResultBytes, and aggregate sections
// saturated on their own rather than derived from those cases. Duplicate case
// manifests alone make it something no hunt produces and no merge would accept.
// Semantic validity is proved elsewhere, by
// TestHuntMergeAcceptsTheLargestGeneratedShard on a real generated shard. What
// this proves is the arithmetic.
func TestMaximumBudgetedHuntResultFitsTheDeclaredMaximum(t *testing.T) {
	saturated := huntCaseWithStderr(t, strings.Repeat("x", huntCaseFillToCeiling(t)))
	if size := huntEncodedElementSize(saturated); size != HuntMaxCaseResultBytes {
		t.Fatalf("the saturated case measures %d bytes, want exactly %d", size, HuntMaxCaseResultBytes)
	}

	base := loadHuntBase(t, "healthy")
	result := RunHunt(context.Background(), "healthy", base, func() Backend {
		return &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport, evidence: deadRouteEvidence()}}
	}, HuntOptions{Cases: 8, Seed: 555, MaxFaults: HuntMaxFaults})
	result.Error, result.ErrorKind = clip(strings.Repeat("<", 4<<10)), "runtime"
	result.Cases = make([]HuntCaseResult, HuntMaxCases)
	for i := range result.Cases {
		result.Cases[i] = saturated
	}
	result.Findings = saturateEncodedList(t, huntMaxAggregateFindingsBytes, func(i int) HuntFinding {
		return HuntFinding{Fingerprint: "fp" + strconv.Itoa(i), Category: FindingFalseNegative,
			Severity: SeverityHigh, Code: "c", Summary: strings.Repeat("y", 4<<10), Evidence: strings.Repeat("z", 4<<10)}
	})
	result.Suggestions = saturateEncodedList(t, huntMaxAggregateSuggestionsBytes, func(i int) HuntSuggestion {
		return HuntSuggestion{Code: "s" + strconv.Itoa(i), Description: strings.Repeat("y", 8<<10),
			HighestSeverity: SeverityHigh, ExampleCases: []int{1, 2, 3}}
	})

	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > HuntMaxResultBytes {
		t.Fatalf("the maximum budgeted hunt result writes %d bytes, over HuntMaxResultBytes %d",
			buf.Len(), HuntMaxResultBytes)
	}
	// The formula and the writer have to agree, or the ceilings bound something
	// other than the document. Sections are weighed at the indentation writeJSON
	// gives them, and the summary is measured with every list present and empty,
	// so summing them reproduces the encoded length byte for byte: property
	// names, punctuation, indentation and the trailing newline included.
	summary, err := huntRunSummarySize(result)
	if err != nil {
		t.Fatal(err)
	}
	accounted := summary + huntEncodedListSize(result.Findings) +
		huntEncodedListSize(result.Suggestions) + huntEncodedListSize(result.Cases)
	if accounted != buf.Len() {
		t.Errorf("the budget accounts for %d bytes and writeJSON wrote %d", accounted, buf.Len())
	}
	t.Logf("maximum budgeted hunt result: %d/%d bytes", buf.Len(), HuntMaxResultBytes)
}

// saturateEncodedList fills a section right up to the ceiling boundEncodedList
// enforces on it, so the whole-result accounting is tested against sections at
// their maximum rather than at their typical size.
func saturateEncodedList[T any](t *testing.T, max int, build func(int) T) []T {
	t.Helper()
	var out []T
	for i := 0; ; i++ {
		next := append(out, build(i))
		if len(boundEncodedList(next, max)) != len(next) {
			break
		}
		out = next
	}
	if len(out) == 0 {
		t.Fatalf("no element of this section fits its %d byte budget", max)
	}
	return out
}

func mustMarshalIndent(t *testing.T, v any) []byte {
	t.Helper()
	blob, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// huntSummaryAtSize builds a hunt result with no cases, findings or
// suggestions, whose run summary encodes to exactly total bytes. The padding
// goes into base_scenario, a field with no omitempty and no escaping in it, so
// one character of padding is one byte of document.
func huntSummaryAtSize(t *testing.T, total int) *HuntResult {
	t.Helper()
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, RequestedCases: 1, MaxFaults: 1,
		Findings: []HuntFinding{}, Suggestions: []HuntSuggestion{}, Cases: []HuntCaseResult{}}
	empty, err := huntRunSummarySize(result)
	if err != nil {
		t.Fatal(err)
	}
	if empty > total {
		t.Fatalf("an empty run summary already measures %d bytes, over the %d asked for", empty, total)
	}
	result.BaseScenario = strings.Repeat("x", total-empty)
	if size, err := huntRunSummarySize(result); err != nil || size != total {
		t.Fatalf("the padded run summary measures %d bytes (err %v), want exactly %d", size, err, total)
	}
	return result
}

// TestHuntRunSummaryBudgetIsEnforcedAtWrite pins huntMaxRunSummaryBytes as a
// production limit rather than a measurement. At the ceiling the result writes,
// and what it writes is the size the accounting predicted; one byte over, the
// write is refused and nothing reaches the writer.
func TestHuntRunSummaryBudgetIsEnforcedAtWrite(t *testing.T) {
	var buf bytes.Buffer
	if err := huntSummaryAtSize(t, huntMaxRunSummaryBytes).WriteJSON(&buf); err != nil {
		t.Fatalf("a run summary at its exact ceiling was refused: %v", err)
	}
	if buf.Len() != huntMaxRunSummaryBytes {
		t.Errorf("the run summary wrote %d bytes, want the %d the accounting measured",
			buf.Len(), huntMaxRunSummaryBytes)
	}

	buf.Reset()
	err := huntSummaryAtSize(t, huntMaxRunSummaryBytes+1).WriteJSON(&buf)
	if err == nil {
		t.Fatal("a run summary one byte over its ceiling was written")
	}
	want := fmt.Sprintf("hunt run summary is %d bytes, over the maximum of %d",
		huntMaxRunSummaryBytes+1, huntMaxRunSummaryBytes)
	if err.Error() != want {
		t.Errorf("refusal says %q, want %q", err.Error(), want)
	}
	if buf.Len() != 0 {
		t.Errorf("the refused result still wrote %d bytes", buf.Len())
	}
}

// TestAnOutgrownCoverageModelCannotBeWritten is the mistake the ceiling exists
// to catch: a future registry with far more operators than today's grows the
// coverage model past the run summary budget. Production refuses the artifact
// instead of writing one its own merge command would reject for its size, so
// the failure lands on the developer who grew the registry and does not depend
// on anyone rerunning the budget test.
func TestAnOutgrownCoverageModelCannotBeWritten(t *testing.T) {
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, BaseScenario: "healthy",
		RequestedCases: 1, MaxFaults: 1,
		Findings: []HuntFinding{}, Suggestions: []HuntSuggestion{}, Cases: []HuntCaseResult{}}
	for i := 0; ; i++ {
		result.Coverage.Operators = append(result.Coverage.Operators, HuntOperatorCoverage{
			ID: fmt.Sprintf("operator-%04d", i), Contract: "oracle", Applicable: true})
		size, err := huntRunSummarySize(result)
		if err != nil {
			t.Fatal(err)
		}
		if size > huntMaxRunSummaryBytes {
			break
		}
	}
	var buf bytes.Buffer
	if err := result.WriteJSON(&buf); err == nil {
		t.Fatalf("a %d operator coverage model wrote %d bytes instead of being refused",
			len(result.Coverage.Operators), buf.Len())
	} else if !strings.Contains(err.Error(), "hunt run summary is") {
		t.Errorf("refusal says %q, want the run summary budget", err.Error())
	}
	t.Logf("refused at %d coverage operators", len(result.Coverage.Operators))
}
