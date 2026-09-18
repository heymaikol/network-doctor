package simulation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Reading a hunt result back.
//
// The byte budget above bounds the document. It does not bound what decoding
// the document costs, and the gap between the two is wide enough to matter: a
// JSON array element can be two bytes and still make encoding/json reserve a
// whole Go struct for it, because the decoder grows the typed slice first and
// records the type mismatch afterwards. At 432 bytes per HuntCaseResult and two
// bytes per element, a document well inside HuntMaxResultBytes asks for tens of
// gigabytes before any hunt limit is consulted. Amplification is what the
// ingestion boundary has to bound, not size.
//
// So the sections that can grow are held back as raw bytes and taken one
// element at a time, each element measured against the ceiling its own producer
// enforces before the next one is read. The cost of the whole read is then
// proportional to the bounded input rather than to the element count an author
// of the file chose, and every ceiling that decides a rejection is a hunt limit
// rather than a decoder detail.
//
// Two temporaries are as large as the input allows and are named here rather
// than hidden: the bounded read itself, and the raw bytes of the sections held
// back from it, which together are at most twice HuntMaxResultBytes. Both are
// flat byte slices, so neither amplifies.

// huntResultSections is one whole document with its four growable sections held
// back undecoded. The embedded HuntResult carries every scalar field, and the
// raw fields shadow the four that can grow: encoding/json resolves a name to
// the shallowest field that claims it, so these four win and the embedded ones
// are left for the section decoders below to fill. Holding the sections back
// this way keeps unknown fields, duplicate keys and malformed input on exactly
// the path they were on before, because the top level is still one ordinary
// struct decode.
type huntResultSections struct {
	HuntResult
	Findings    json.RawMessage `json:"findings"`
	Suggestions json.RawMessage `json:"suggestions"`
	Cases       json.RawMessage `json:"case_results"`
	Coverage    json.RawMessage `json:"coverage"`
}

// DecodeHuntResult reads one hunt result from a reader nobody in this process
// wrote. The limit is applied to the reader, not to a file measured after the
// fact: the input is bounded before the JSON decoder is handed any of it, and
// the one byte past the ceiling is all it takes to know the result is too large
// to support. Decoding then runs over a complete in-memory buffer, so the EOF
// the trailing-value check reads is the input's own and never an artificial one
// a limiter produced mid-value.
//
// What it returns has passed the same budget checkHuntResultBudget holds a
// hunt result to before writing one, so this command accepts only documents
// this package could have produced. It is not a semantic check: whether the
// cases are the ones deterministic generation produces is still MergeHuntResults
// and ValidateMergedHuntResult's question.
func DecodeHuntResult(r io.Reader) (*HuntResult, error) {
	blob, err := io.ReadAll(io.LimitReader(r, HuntMaxResultBytes+1))
	if err != nil {
		return nil, err
	}
	if len(blob) > HuntMaxResultBytes {
		return nil, fmt.Errorf("hunt result exceeds the supported maximum of %d bytes",
			HuntMaxResultBytes)
	}
	var sections huntResultSections
	decoder := json.NewDecoder(bytes.NewReader(blob))
	if err := decoder.Decode(&sections); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}

	result := sections.HuntResult
	// Coverage is one object of short lists rather than a list itself, and the
	// run summary ceiling already covers it, so its encoded size is the whole
	// bound it needs: what it can hold at that size decodes to a couple of
	// megabytes at the very worst.
	if err := huntBoundedSection(sections.Coverage, &result.Coverage, huntMaxRunSummaryBytes,
		"hunt coverage"); err != nil {
		return nil, err
	}
	if result.Findings, err = huntBoundedList[HuntFinding](sections.Findings,
		huntMaxAggregateFindingsBytes, "hunt findings"); err != nil {
		return nil, err
	}
	if result.Suggestions, err = huntBoundedList[HuntSuggestion](sections.Suggestions,
		huntMaxAggregateSuggestionsBytes, "hunt suggestions"); err != nil {
		return nil, err
	}
	if result.Cases, err = decodeHuntCaseResults(sections.Cases); err != nil {
		return nil, err
	}
	if err := checkHuntResultBudget(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// huntBoundedSection decodes one section whose encoded size is the only bound
// it needs. The encoded bytes are the ones the document actually spends, and
// indentation only adds to them, so a section this refuses is one the write
// side would have refused too.
func huntBoundedSection(raw json.RawMessage, into any, max int, name string) error {
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > max {
		return fmt.Errorf("%s exceeds the supported encoded maximum of %d bytes", name, max)
	}
	return json.Unmarshal(raw, into)
}

// huntBoundedList decodes one top-level list element by element, holding the
// running total against the same accounting boundEncodedList bounds the section
// by on the way out. Stopping on the element that crosses the ceiling is what
// keeps the typed slice proportional to the ceiling instead of to the number of
// elements the document offers.
func huntBoundedList[T any](raw json.RawMessage, max int, name string) ([]T, error) {
	out, total := []T{}, len("[]")
	array, err := huntWalkArray(raw, func(element json.RawMessage) error {
		var item T
		if err := json.Unmarshal(element, &item); err != nil {
			return err
		}
		total += huntEncodedElementSize(item)
		if total > max {
			return fmt.Errorf("%s exceed the supported encoded maximum of %d bytes", name, max)
		}
		out = append(out, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !array {
		// Absent, null, or not a list at all. The stock decoder owns what each
		// of those means, so it answers, and none of them costs anything to
		// hand it.
		return huntStockList[T](raw)
	}
	return out, nil
}

// decodeHuntCaseResults is the list the whole boundary exists for. Three
// ceilings decide a case before it becomes a Go value, in the order that keeps
// the cost of refusing it low: the count, so the five hundred and first element
// is refused without the five hundred and first struct; the encoded bytes of
// the element, so no case is decoded out of more input than one case is allowed
// to weigh; and the encoded bytes of what came back, so a case cannot spend its
// allowance on elements the decoder reserves a struct for and then discards.
func decodeHuntCaseResults(raw json.RawMessage) ([]HuntCaseResult, error) {
	out := []HuntCaseResult{}
	array, err := huntWalkArray(raw, func(element json.RawMessage) error {
		if len(out) == HuntMaxCases {
			return fmt.Errorf("hunt result has more than %d case results", HuntMaxCases)
		}
		if len(element) > HuntMaxCaseResultBytes {
			return fmt.Errorf("hunt case result %d exceeds the supported encoded maximum of %d bytes",
				len(out), HuntMaxCaseResultBytes)
		}
		var item HuntCaseResult
		if err := json.Unmarshal(element, &item); err != nil {
			return err
		}
		if err := checkHuntCaseStructure(&item); err != nil {
			return err
		}
		if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
			return fmt.Errorf("hunt case result %d is %d bytes, over the maximum of %d",
				len(out), size, HuntMaxCaseResultBytes)
		}
		out = append(out, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !array {
		return huntStockList[HuntCaseResult](raw)
	}
	return out, nil
}

// huntStockList is what a section that is not a list decodes to: whatever the
// stock decoder says, including the nil slice an absent or null section has
// always produced and the type error a scalar has always produced.
func huntStockList[T any](raw json.RawMessage) ([]T, error) {
	var out []T
	if len(raw) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// huntWalkArray hands visit one element of a JSON array at a time, so the
// memory a section costs to inspect is one element rather than all of them. It
// reports whether the value was an array at all and leaves anything else
// untouched, which is how an absent section, a null one and a wrongly typed one
// keep answering the way the stock decoder answers for them.
func huntWalkArray(raw json.RawMessage, visit func(json.RawMessage) error) (bool, error) {
	if len(raw) == 0 {
		return false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '[' {
		return false, nil
	}
	for decoder.More() {
		var element json.RawMessage
		if err := decoder.Decode(&element); err != nil {
			return true, err
		}
		if err := visit(element); err != nil {
			return true, err
		}
	}
	_, err = decoder.Token()
	return true, err
}
