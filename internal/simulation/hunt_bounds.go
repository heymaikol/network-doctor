package simulation

import (
	"encoding/json"
	"fmt"
	"math"
)

// The hunt result byte budget.
//
// A merge reads shard results other processes wrote, so the reader has to know
// what a legitimate one can weigh before a decoder is handed any of it. The
// ceilings below are not estimates of what hunts happen to produce. Each one is
// enforced where the section it bounds is built, so "the largest legal hunt
// result" is a definition rather than a measurement, and HuntMaxResultBytes is
// their sum. checkHuntResultBudget then holds every one of them, and the sum,
// against the result about to be written, so the budget is a property of what
// this package can serialize and not of what its tests happen to measure.
//
// Bounding the sections rather than the fields is deliberate. The simulator
// writes most of a hunt result out of vocabularies the model already fixes, but
// the simulation report embedded in each case carries free text a netdoc
// subprocess wrote, and the report type graph reaches more than two hundred
// strings and fifty lists before that text runs out of places to hide. Naming a
// maximum for each one would be a large surface to keep correct for no extra
// strength: what the budget needs to know is how many bytes a section costs,
// and that is one measurement of the section itself.
//
// Weighing the encoded form is also what settles JSON escaping. A rune that
// expands sixfold under encoding is counted after it expands, so the budget
// needs no separate allowance for it and cannot be defeated by choosing text
// that encodes badly.
const (
	// HuntMaxCaseResultBytes bounds one entry of case_results as WriteJSON
	// writes it. canonicalHuntCaseResult enforces it: a case whose report does
	// not fit stores a bounded stand-in that says so, keeping the case named
	// and reproducible. 64 KiB is about four times the largest case result the
	// generator produces across every base and lane at HuntMaxCases and
	// HuntMaxFaults, and about nine times the largest real netdoc artifact
	// recorded in testdata/field, so the substitution is a backstop against a
	// runaway subprocess and not a routine event.
	HuntMaxCaseResultBytes = 64 << 10
	// huntMaxAggregateFindingsBytes bounds the findings section. Its rows are a
	// deduplicating projection of case findings, so their count is bounded only
	// by the cases, and their text is netdoc's. aggregateHuntFindings enforces
	// the ceiling by keeping the longest prefix of its own deterministic order
	// that fits, which costs a summary its tail rows and costs the artifact
	// nothing: every row here restates a finding case_results still carries in
	// full. A full HuntMaxCases run measures under 5 KiB.
	huntMaxAggregateFindingsBytes = 1 << 20
	// huntMaxAggregateSuggestionsBytes bounds the suggestions section the same
	// way. It holds one row per suggestion code, a fixed vocabulary of a dozen
	// or so, but each row quotes a finding summary, so it is weighed rather
	// than counted.
	huntMaxAggregateSuggestionsBytes = 256 << 10
	// huntMaxRunSummaryBytes bounds everything outside those three sections:
	// the scalar run metadata and the coverage model. Every string there comes
	// from a fixed vocabulary except Error, which clip bounds, and coverage
	// holds one row per registry operator and one per oracle condition with
	// Cardinality no longer than HuntMaxFaults. checkHuntResultBudget weighs it
	// before any hunt result is written, so a future field or registry that
	// outgrows this ceiling refuses to serialize rather than producing an
	// artifact the reader will not take. TestHuntRunSummaryFitsItsBudget builds
	// the largest one the current vocabularies allow and shows the ceiling is
	// not a constraint hunts actually meet.
	huntMaxRunSummaryBytes = 64 << 10
	// HuntMaxResultBytes is the maximum encoded size of one hunt result. A
	// shard carries at most every case the hunt requested, because a shard
	// count of one is legal and HuntMaxCases bounds the request.
	HuntMaxResultBytes = huntMaxRunSummaryBytes + huntMaxAggregateFindingsBytes +
		huntMaxAggregateSuggestionsBytes + HuntMaxCases*HuntMaxCaseResultBytes
)

// huntListIndentPrefix is the indentation writeJSON gives an element of a
// top-level list in a hunt result: the result object indents its own fields one
// level, and the list indents its elements one more.
const huntListIndentPrefix = "    "

// huntEncodedElementSize is how many bytes one list element occupies in a hunt
// result written by WriteJSON, counting the indentation of its opening line and
// the separator that follows it. A value that cannot be encoded weighs more
// than any budget, so it is refused rather than waved through.
func huntEncodedElementSize(v any) int {
	blob, err := json.MarshalIndent(v, huntListIndentPrefix, "  ")
	if err != nil {
		return math.MaxInt32
	}
	return len(huntListIndentPrefix) + len(blob) + len(",\n")
}

// boundEncodedList keeps the longest prefix of an already ordered list that
// fits max bytes. The function that builds a section is the only place a
// section is built, on the generating side and in the validation that
// recomputes it, so a bounded section is the same list on both sides.
func boundEncodedList[T any](items []T, max int) []T {
	total := len("[]")
	for i := range items {
		total += huntEncodedElementSize(items[i])
		if total > max {
			return items[:i]
		}
	}
	return items
}

// oversizedHuntReport stands in for a simulation report too large to store in a
// hunt result. It keeps the coordinates that identify the run, records why the
// output is not there, and drops everything whose size the model does not
// control. A case that lands here is a runtime error rather than a silent gap:
// the hunt still names it, still says how to reproduce it, and still reports
// itself as failed.
func oversizedHuntReport(r *Report) *Report {
	stand := &Report{Scenario: clip(r.Scenario), ID: clip(r.ID), Backend: clip(r.Backend),
		StartedAt: r.StartedAt, Duration: r.Duration, Cleanup: CleanupInfo{Done: r.Cleanup.Done},
		Error: fmt.Sprintf("simulation report exceeds the %d byte hunt case budget", HuntMaxCaseResultBytes)}
	stand.finish()
	return stand
}

// huntEncodedListSize is what one top-level list of a hunt result accounts for:
// the two bytes an empty list occupies plus the weight of every element. It is
// the same accounting boundEncodedList bounds a section by.
func huntEncodedListSize[T any](items []T) int {
	total := len("[]")
	for i := range items {
		total += huntEncodedElementSize(items[i])
	}
	return total
}

// huntRunSummarySize is how many bytes a hunt result costs outside its three
// weighed lists: the scalar run metadata and the coverage model, encoded
// exactly as writeJSON encodes them, with each list reduced to the two bytes of
// an empty one. Emptying the lists rather than dropping them keeps their
// property names and punctuation in the measurement, so the summary is charged
// for the structure it contributes to the document.
func huntRunSummarySize(r *HuntResult) (int, error) {
	summary := *r
	summary.Findings, summary.Suggestions, summary.Cases = []HuntFinding{}, []HuntSuggestion{}, []HuntCaseResult{}
	blob, err := json.MarshalIndent(&summary, "", "  ")
	if err != nil {
		return 0, err
	}
	// writeJSON encodes through json.Encoder.Encode, which ends the document
	// with a newline MarshalIndent does not write.
	return len(blob) + len("\n"), nil
}

// checkHuntCaseStructure holds the one cardinality inside a case result that
// the model already fixes. A case is drawn under a fault ceiling of at most
// HuntMaxFaults and carries one mutation per fault, so a case offering more
// than that is not a case whatever else is true of it. The check is cheap and
// it is the largest amplifier left inside the per-case byte ceiling: mutations
// are the densest list in the graph, so refusing an impossible count is worth
// more here than a table of per-field limits would be.
func checkHuntCaseStructure(item *HuntCaseResult) error {
	if n := len(item.Manifest.Mutations); n > HuntMaxFaults {
		return fmt.Errorf("hunt case result carries %d mutations, over the maximum of %d", n, HuntMaxFaults)
	}
	return nil
}

// checkHuntResultBudget refuses a hunt result the budget does not cover. It is
// what makes the write side of that budget hold in production rather than only
// under the tests that measure it: a section that grows past its ceiling, a
// scalar field nobody budgeted for, or a registry that gained hundreds of rows
// stops the artifact from being written instead of producing one this program's
// own merge command would reject.
//
// The accounting is the document. A hunt result is its run summary plus its
// three lists, each list costs the two bytes of an empty one plus the weight of
// its elements, and that is exactly what the summary charges for an emptied
// list, so summary plus sections is the encoded length. The one inexactness is
// two bytes per list that is empty rather than absent, which the sum
// overstates, so a result this accepts is never larger than it measured.
func checkHuntResultBudget(r *HuntResult) error {
	if len(r.Cases) > HuntMaxCases {
		return fmt.Errorf("hunt result holds %d case results, over the maximum of %d",
			len(r.Cases), HuntMaxCases)
	}
	for i := range r.Cases {
		if err := checkHuntCaseStructure(&r.Cases[i]); err != nil {
			return err
		}
		if size := huntEncodedElementSize(r.Cases[i]); size > HuntMaxCaseResultBytes {
			return fmt.Errorf("hunt case %d result is %d bytes, over the maximum of %d",
				r.Cases[i].Manifest.Case, size, HuntMaxCaseResultBytes)
		}
	}
	findings := huntEncodedListSize(r.Findings)
	if findings > huntMaxAggregateFindingsBytes {
		return fmt.Errorf("hunt findings are %d bytes, over the maximum of %d",
			findings, huntMaxAggregateFindingsBytes)
	}
	suggestions := huntEncodedListSize(r.Suggestions)
	if suggestions > huntMaxAggregateSuggestionsBytes {
		return fmt.Errorf("hunt suggestions are %d bytes, over the maximum of %d",
			suggestions, huntMaxAggregateSuggestionsBytes)
	}
	summary, err := huntRunSummarySize(r)
	if err != nil {
		return err
	}
	if summary > huntMaxRunSummaryBytes {
		return fmt.Errorf("hunt run summary is %d bytes, over the maximum of %d",
			summary, huntMaxRunSummaryBytes)
	}
	if total := summary + findings + suggestions + huntEncodedListSize(r.Cases); total > HuntMaxResultBytes {
		return fmt.Errorf("hunt result is %d bytes, over the maximum of %d", total, HuntMaxResultBytes)
	}
	return nil
}
