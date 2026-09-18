package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The ingestion boundary, from the outside.
//
// What every test here is about is the difference between the bytes a document
// spends and the memory decoding it costs. encoding/json reserves a Go struct
// for an array element before it knows whether the element can be stored in
// one, so two bytes of input buy a 432 byte HuntCaseResult, and a document well
// inside HuntMaxResultBytes buys gigabytes. Sizes alone therefore prove
// nothing: each shape below is checked against what it allocated as well as
// against what it answered, because a refusal that arrives after the allocation
// is the bug rather than the fix.

// huntFillReader repeats one pattern, endlessly, so an input larger than any
// test wants to hold costs nothing to produce. The offset carries across reads,
// which is what keeps a read that ends mid-pattern from splicing the pattern in
// half and spelling something that is not JSON.
type huntFillReader struct {
	pattern string
	offset  int
}

func (f *huntFillReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = f.pattern[f.offset%len(f.pattern)]
		f.offset++
	}
	return len(p), nil
}

// huntSizedInput is prefix, then fill, then suffix, exactly total bytes long.
// Whatever the fill pattern cannot divide is taken up by JSON whitespace ahead
// of it, so a multi-byte pattern always lands whole and the document is legal
// JSON at any total asked for.
func huntSizedInput(t *testing.T, prefix, suffix, fill string, total int) io.Reader {
	t.Helper()
	body := total - len(prefix) - len(suffix)
	if body < 0 {
		t.Fatalf("prefix and suffix are %d bytes, over the requested total %d", len(prefix)+len(suffix), total)
	}
	pad := body % len(fill)
	return io.MultiReader(strings.NewReader(prefix+strings.Repeat(" ", pad)),
		io.LimitReader(&huntFillReader{pattern: fill}, int64(body-pad)), strings.NewReader(suffix))
}

// allocatedDecoding is how many bytes reading this document allocated in total.
// It is the measurement that separates a structural refusal from a refusal the
// decoder reached after building the thing being refused, because the two say
// the same words and cost different orders of magnitude.
func allocatedDecoding(t *testing.T, document string) (*HuntResult, uint64, error) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	result, err := DecodeHuntResult(strings.NewReader(document))
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(result)
	return result, after.TotalAlloc - before.TotalAlloc, err
}

// repeatedElements is a JSON array of n copies of one element, as a document
// member. Every element is a legal empty object, so nothing here is refused for
// being malformed or for being the wrong type: the shapes below are exactly as
// valid as they are impossible.
func repeatedElements(n int, element string) string {
	return "[" + strings.Repeat(element+",", n-1) + element + "]"
}

// TestHuntResultDecodeRefusesAmplifyingSections walks every growable section of
// the document and offers each one two hundred thousand empty objects. None of
// them is malformed, none is the wrong type, and every one of them would have
// been decoded in full before any hunt limit was consulted: the sections are
// bounded by encoded bytes, and empty objects are the cheapest bytes that still
// cost a whole struct each.
//
// The allocation ceiling each shape is held to is the size of the typed slice
// the old path built, so a shape that passes this has demonstrably not built
// one. The sections differ in which limit refuses them, which is the point:
// case results have a count of their own, the two aggregate sections have their
// encoded ceilings, and coverage rides on the run summary's.
func TestHuntResultDecodeRefusesAmplifyingSections(t *testing.T) {
	const elements = 200001
	for _, shape := range []struct {
		name     string
		document string
		want     string
		element  any
	}{
		{"case results", `{"case_results":` + repeatedElements(elements, "{}") + `}`,
			fmt.Sprintf("hunt result has more than %d case results", HuntMaxCases), HuntCaseResult{}},
		{"findings", `{"findings":` + repeatedElements(elements, "{}") + `}`,
			fmt.Sprintf("hunt findings exceed the supported encoded maximum of %d bytes",
				huntMaxAggregateFindingsBytes), HuntFinding{}},
		{"suggestions", `{"suggestions":` + repeatedElements(elements, "{}") + `}`,
			fmt.Sprintf("hunt suggestions exceed the supported encoded maximum of %d bytes",
				huntMaxAggregateSuggestionsBytes), HuntSuggestion{}},
		{"coverage operators", `{"coverage":{"operators":` + repeatedElements(elements, "{}") + `}}`,
			fmt.Sprintf("hunt coverage exceeds the supported encoded maximum of %d bytes",
				huntMaxRunSummaryBytes), HuntOperatorCoverage{}},
	} {
		t.Run(shape.name, func(t *testing.T) {
			if !json.Valid([]byte(shape.document)) {
				t.Fatal("the shape is not valid JSON, so it proves nothing about decoding one")
			}
			result, allocated, err := allocatedDecoding(t, shape.document)
			if err == nil {
				t.Fatalf("a section of %d empty objects was accepted: %+v", elements, result)
			}
			if err.Error() != shape.want {
				t.Fatalf("error = %q, want %q", err, shape.want)
			}
			typed := uint64(elements) * uint64(reflect.TypeOf(shape.element).Size())
			if allocated >= typed {
				t.Fatalf("reading the section allocated %d bytes, which is the %d a typed slice of "+
					"every element offered would have cost: the refusal came after the allocation",
					allocated, typed)
			}
			t.Logf("%d bytes allocated, against %d for the typed slice alone", allocated, typed)
		})
	}
}

// TestHuntCaseCountIsRefusedAtItsExactBoundary pins the cardinality preflight
// from both sides with the smallest elements that are still objects.
// HuntMaxCases of them is a document this package's own budget covers, so it
// reads; one more is refused on the count, and refused by name, because there
// is no size left for the refusal to be about.
func TestHuntCaseCountIsRefusedAtItsExactBoundary(t *testing.T) {
	at := `{"case_results":` + repeatedElements(HuntMaxCases, "{}") + `}`
	result, err := DecodeHuntResult(strings.NewReader(at))
	if err != nil {
		t.Fatalf("a result holding exactly %d case results was refused: %v", HuntMaxCases, err)
	}
	if len(result.Cases) != HuntMaxCases {
		t.Fatalf("read %d case results, want %d", len(result.Cases), HuntMaxCases)
	}

	over := `{"case_results":` + repeatedElements(HuntMaxCases+1, "{}") + `}`
	if _, err = DecodeHuntResult(strings.NewReader(over)); err == nil {
		t.Fatalf("a result holding %d case results was accepted", HuntMaxCases+1)
	}
	want := fmt.Sprintf("hunt result has more than %d case results", HuntMaxCases)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
}

// TestHuntCaseCountStopsAStreamedArrayAtTheCeiling is the same refusal against
// the largest input the reader will accept at all: a valid case_results array
// filled to HuntMaxResultBytes with empty objects, eleven million of them,
// generated rather than held. The count is what stops it, after five hundred
// and one elements of a document that offers twenty thousand times that, so the
// cost of refusing it is set by the limit and not by the file.
func TestHuntCaseCountStopsAStreamedArrayAtTheCeiling(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := DecodeHuntResult(huntSizedInput(t, `{"case_results":[`, `{}]}`, "{},", HuntMaxResultBytes))
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a case_results array filled to the byte ceiling was accepted")
	}
	want := fmt.Sprintf("hunt result has more than %d case results", HuntMaxCases)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
	elements := HuntMaxResultBytes / len("{},")
	allocated := after.TotalAlloc - before.TotalAlloc
	typed := uint64(elements) * uint64(reflect.TypeOf(HuntCaseResult{}).Size())
	if allocated >= typed {
		t.Fatalf("reading the array allocated %d bytes, which is the %d a typed slice of every "+
			"element offered would have cost: the count did not stop it", allocated, typed)
	}
	t.Logf("%d bytes allocated for an array of about %d elements, against %d for the typed slice alone",
		allocated, elements, typed)
}

// TestHuntCaseEncodedSizeIsCheckedBeforeTypedDecode covers the per-case ceiling
// in the two places it has to hold. A case at exactly HuntMaxCaseResultBytes is
// read, because the ceiling is the size a case is allowed to be. One byte over
// is refused on what it weighs. A case whose own bytes are over the ceiling is
// refused on those bytes alone, before it is decoded at all, which is the only
// version of the check that bounds what an amplifying case can cost: the one
// below would otherwise buy thirty-six megabytes of typed structs with three
// hundred kilobytes of empty objects.
func TestHuntCaseEncodedSizeIsCheckedBeforeTypedDecode(t *testing.T) {
	saturated := huntCaseWithStderr(t, strings.Repeat("x", huntCaseFillToCeiling(t)))
	if size := huntEncodedElementSize(saturated); size != HuntMaxCaseResultBytes {
		t.Fatalf("the saturated case measures %d bytes, want exactly %d", size, HuntMaxCaseResultBytes)
	}
	document := func(item HuntCaseResult) string {
		blob, err := json.Marshal([]HuntCaseResult{item})
		if err != nil {
			t.Fatal(err)
		}
		return `{"case_results":` + string(blob) + `}`
	}

	result, err := DecodeHuntResult(strings.NewReader(document(saturated)))
	if err != nil {
		t.Fatalf("a case at exactly the per-case ceiling was refused: %v", err)
	}
	if len(result.Cases) != 1 || len(result.Cases[0].Report.Tests) != 1 {
		t.Fatalf("the case at the ceiling did not come back whole: %+v", result.Cases)
	}

	// One byte more of the same text. The element's own bytes are still inside
	// the ceiling, so it is what the case weighs once decoded that refuses it.
	over := saturated
	report := *saturated.Report
	report.Tests = append([]TestOutcome(nil), report.Tests...)
	report.Tests[0].Stderr += "x"
	over.Report = &report
	if _, err = DecodeHuntResult(strings.NewReader(document(over))); err == nil {
		t.Fatal("a case one byte over the per-case ceiling was accepted")
	}
	want := fmt.Sprintf("hunt case result 0 is %d bytes, over the maximum of %d",
		HuntMaxCaseResultBytes+1, HuntMaxCaseResultBytes)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}

	// A case whose encoded bytes are over the ceiling, spent on the cheapest
	// elements that still cost a struct each.
	const checks = 100000
	amplifying := `{"case_results":[{"report":{"tests":[{"checks":` +
		repeatedElements(checks, "{}") + `}]}}]}`
	_, allocated, err := allocatedDecoding(t, amplifying)
	if err == nil {
		t.Fatal("a case over the per-case ceiling was accepted")
	}
	want = fmt.Sprintf("hunt case result 0 exceeds the supported encoded maximum of %d bytes",
		HuntMaxCaseResultBytes)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
	typed := uint64(checks) * uint64(reflect.TypeOf(CheckComparison{}).Size())
	if allocated >= typed {
		t.Fatalf("reading the case allocated %d bytes, which is the %d its checks alone would have "+
			"cost: the case was decoded before its size was checked", allocated, typed)
	}
	t.Logf("%d bytes allocated, against %d for the checks alone", allocated, typed)
}

// TestHuntCaseMutationCountIsRefusedStructurally is the one cardinality inside
// a case that the model already fixes, and the largest amplifier the per-case
// byte ceiling leaves open: mutations are the densest list in the graph, so a
// case can spend its whole byte allowance on empty ones and come back a
// quarter of a megabyte heavier. A case is drawn under a ceiling of at most
// HuntMaxFaults and carries one mutation per fault, so more than that is not a
// case, whatever it weighs.
func TestHuntCaseMutationCountIsRefusedStructurally(t *testing.T) {
	document := func(n int) string {
		return `{"case_results":[{"manifest":{"mutations":` + repeatedElements(n, "{}") + `}}]}`
	}
	if _, err := DecodeHuntResult(strings.NewReader(document(HuntMaxFaults))); err != nil {
		t.Fatalf("a case carrying %d mutations was refused: %v", HuntMaxFaults, err)
	}
	_, err := DecodeHuntResult(strings.NewReader(document(HuntMaxFaults + 1)))
	if err == nil {
		t.Fatalf("a case carrying %d mutations was accepted", HuntMaxFaults+1)
	}
	want := fmt.Sprintf("hunt case result carries %d mutations, over the maximum of %d",
		HuntMaxFaults+1, HuntMaxFaults)
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}

	// The same limit on the write side, so the reader refuses nothing this
	// package could have produced.
	result := &HuntResult{GeneratorVersion: HuntGeneratorVersion, BaseScenario: "healthy",
		RequestedCases: 1, MaxFaults: 1, Findings: []HuntFinding{}, Suggestions: []HuntSuggestion{},
		Cases: []HuntCaseResult{{Manifest: GeneratedCaseManifest{
			Mutations: make([]GeneratedMutation, HuntMaxFaults+1)}}}}
	if err = result.WriteJSON(io.Discard); err == nil {
		t.Fatalf("a result carrying %d mutations in one case was written", HuntMaxFaults+1)
	}
	if err.Error() != want {
		t.Fatalf("the write side says %q, want %q", err, want)
	}
}

// TestHuntResultDecodePreservesJSONBehaviour holds the decoder's answers to the
// document shapes that have nothing to do with size. The sections are held back
// as raw bytes and taken apart separately now, so the ordinary JSON contract is
// the thing most at risk of quietly moving: an unknown field is still ignored,
// a second top-level value is still refused, trailing whitespace is still legal,
// a malformed document is still a syntax error, and the last of two duplicate
// keys still wins.
func TestHuntResultDecodePreservesJSONBehaviour(t *testing.T) {
	valid := `{"generator_version":"` + HuntGeneratorVersion + `","base_scenario":"healthy",` +
		`"requested_cases":1,"max_faults":1,"result":"clean","case_results":[]}`
	for _, shape := range []struct {
		name     string
		document string
		want     string
		cases    int
	}{
		{"unknown field", strings.Replace(valid, `{`, `{"not_a_field":{"deep":[1,2,3]},`, 1), "", 0},
		{"trailing whitespace", valid + "\n\t \n", "", 0},
		{"duplicate section, last wins", strings.Replace(valid,
			`"case_results":[]`, `"case_results":[{},{}],"case_results":[{}]`, 1), "", 1},
		{"second top-level value", valid + valid, "multiple JSON values", 0},
		{"malformed", valid[:len(valid)-1], "unexpected EOF", 0},
	} {
		t.Run(shape.name, func(t *testing.T) {
			result, err := DecodeHuntResult(strings.NewReader(shape.document))
			if shape.want == "" {
				if err != nil {
					t.Fatalf("the document was refused: %v", err)
				}
				if len(result.Cases) != shape.cases {
					t.Fatalf("read %d case results, want %d", len(result.Cases), shape.cases)
				}
				return
			}
			if err == nil {
				t.Fatalf("the document was accepted: %+v", result)
			}
			if err.Error() != shape.want {
				t.Fatalf("error = %q, want %q", err, shape.want)
			}
		})
	}
}

// TestHuntResultDecodeReadsTheLargestGeneratedShard is the other direction:
// every limit above has to leave the real upper shape alone. A HuntMaxCases
// hunt is written, read back through the boundary, merged and validated, so the
// structural ceilings are known to refuse nothing the generator produces.
func TestHuntResultDecodeReadsTheLargestGeneratedShard(t *testing.T) {
	base := loadHuntBase(t, "healthy")
	shard := HuntShard{Index: 0, Count: 1}
	result := RunHunt(context.Background(), "healthy", base, nil, HuntOptions{Cases: HuntMaxCases,
		Seed: 20260917, MaxFaults: HuntMaxFaults, DryRun: true, Shard: &shard})
	var encoded strings.Builder
	if err := result.WriteJSON(&encoded); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeHuntResult(strings.NewReader(encoded.String()))
	if err != nil {
		t.Fatalf("the largest generated shard did not read back: %v", err)
	}
	if !reflect.DeepEqual(decoded, result) {
		t.Fatal("the shard that came back is not the one that was written")
	}
	merged, err := MergeHuntResults(decoded)
	if err != nil {
		t.Fatalf("merging the largest generated shard: %v", err)
	}
	if err := ValidateMergedHuntResult(merged); err != nil {
		t.Fatalf("validating the largest generated shard: %v", err)
	}
	t.Logf("largest generated shard: %d of %d budgeted bytes", encoded.Len(), HuntMaxResultBytes)
}
