package simulation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Reading a hunt result back.
//
// The byte budget in hunt_bounds.go bounds the document. It does not bound what
// decoding the document costs, and the gap between the two is wide enough to
// matter in two separate ways.
//
// The first is amplification. A JSON array element can be two bytes and still
// make encoding/json reserve a whole Go struct for it, because the decoder
// grows the typed slice first and records the type mismatch afterwards. At 432
// bytes per HuntCaseResult and two bytes per element, a document well inside
// HuntMaxResultBytes asks for tens of gigabytes before any hunt limit is
// consulted.
//
// The second is duplication, and it is why this file streams. json.Decoder has
// to hold a complete value in its own buffer before it can hand it over, and
// json.RawMessage copies what it is handed, so reading the document as one
// value and holding its sections back as raw bytes cost the whole document
// twice over and the case list a third time. A ceiling of four hundred and
// twenty megabytes was being enforced at a peak of well over a gigabyte.
//
// So nothing here reads the document as a value. One bounded reader delivers
// it, one json.Decoder walks the top-level object a token at a time, and every
// section that can grow is taken element by element: the element is the largest
// encoded thing that ever exists in memory, and it is bounded by the ceiling
// its own producer enforces. What the read costs is then the final typed
// HuntResult plus one element, rather than the document plus a copy of it.
//
// The run summary is the exception, and deliberately so. Everything outside the
// three lists is bounded to huntMaxRunSummaryBytes on the way out, so the
// reader holds it to the same ceiling on the way in, which is what keeps a
// single scalar field from carrying the whole document into one Go string.

// errHuntOverLimit is what huntBoundedReader returns once it has delivered
// every byte its current ceiling allows. It is never returned to a caller of
// this package: each section translates it into the ceiling that was actually
// crossed, and DecodeHuntResult translates what is left into the document's.
var errHuntOverLimit = errors.New("hunt input is over its ceiling")

// huntBoundedReader delivers at most limit+1 bytes and then refuses.
//
// The extra byte is the whole point of the design. A document of exactly the
// ceiling has to be accepted and a document of one byte more has to be refused,
// and the two are indistinguishable to a reader that stops at the ceiling
// itself: both end in an artificial EOF the JSON decoder cannot tell from a
// real one. Delivering the byte past the ceiling makes the distinction a fact
// about n rather than an inference about EOF, and the check on n runs whether
// the decoder asked for that byte or stopped before it.
//
// limit moves. A section that has a smaller ceiling than the document lowers it
// for the length of that section, which is what bounds the decoder's own buffer
// to the section rather than to the input.
type huntBoundedReader struct {
	r     io.Reader
	n     int64
	limit int64
}

func (b *huntBoundedReader) Read(p []byte) (int, error) {
	room := b.limit + 1 - b.n
	if room <= 0 {
		return 0, errHuntOverLimit
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

// section lowers the ceiling to max bytes past what the decoder has consumed so
// far, and returns the ceiling to put back afterwards.
//
// Two clamps make it safe. It never drops below what has already been
// delivered, because the decoder reads ahead and bytes already in its buffer
// are not a cost the next section can be charged for; a section whose value is
// entirely in that buffer is decoded without a read and is bounded by the
// buffer instead. And it never rises above the ceiling in force, so no section
// can lift the document's own.
func (b *huntBoundedReader) section(dec *json.Decoder, max int) int64 {
	previous := b.limit
	limit := dec.InputOffset() + int64(max)
	if limit < b.n {
		limit = b.n
	}
	if limit > previous {
		limit = previous
	}
	b.limit = limit
	return previous
}

// DecodeHuntResult reads one hunt result from a reader nobody in this process
// wrote. The ceiling is applied to the reader rather than to a document
// measured after the fact, so the input is bounded before the JSON decoder is
// handed any of it and no part of it is ever held whole.
//
// What it returns has passed the same budget checkHuntResultBudget holds a
// hunt result to before writing one, so this command accepts only documents
// this package could have produced. It is not a semantic check: whether the
// cases are the ones deterministic generation produces is still
// MergeHuntResults and ValidateMergedHuntResult's question.
func DecodeHuntResult(r io.Reader) (*HuntResult, error) {
	bounded := &huntBoundedReader{r: r, limit: HuntMaxResultBytes}
	decoder := json.NewDecoder(bounded)
	result, err := huntWalkResult(decoder, bounded)
	if err != nil {
		return nil, huntInputError(bounded, err)
	}
	// Trailing input, scanned rather than parsed. Whitespace after a JSON
	// document is legal and may run to the document's whole remaining
	// allowance, so the trailing check cannot be given a small ceiling; and a
	// second top-level value cannot be handed to the decoder either, because a
	// decoder has to buffer a value before it can report that there was one,
	// and a second value of four hundred megabytes would be buffered and
	// decoded in full to be refused. Looking for the first byte that is not
	// whitespace answers both without holding either.
	if err := huntCheckTrailing(io.MultiReader(decoder.Buffered(), bounded)); err != nil {
		return nil, huntInputError(bounded, err)
	}
	if bounded.n > HuntMaxResultBytes {
		return nil, huntOversizeError()
	}
	if err := checkHuntResultBudget(result); err != nil {
		return nil, err
	}
	return result, nil
}

// huntCheckTrailing reads what follows the document and accepts only
// whitespace, in fixed-size bites, so what comes after a complete hunt result
// costs nothing to refuse however much of it there is.
func huntCheckTrailing(r io.Reader) error {
	var window [512]byte
	for {
		n, err := r.Read(window[:])
		for _, b := range window[:n] {
			switch b {
			case ' ', '\t', '\r', '\n':
			default:
				return errors.New("multiple JSON values")
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func huntOversizeError() error {
	return fmt.Errorf("hunt result exceeds the supported maximum of %d bytes", HuntMaxResultBytes)
}

// huntInputError names the document's own ceiling for a refusal no section
// claimed, and reports a document already past that ceiling as too large
// whatever the decoder was complaining about when it stopped.
//
// It also puts back the one answer walking the document token by token changed.
// json.Decoder.Decode reports a document that ends mid-value as
// io.ErrUnexpectedEOF and json.Decoder.Token reports the same document as the
// syntax error below, so a truncated input would otherwise start saying
// something new about itself for no reason that concerns a reader. The
// comparison is against the message rather than a sentinel because
// encoding/json does not export one, and the test that pins "unexpected EOF"
// is what would notice if that message ever moved.
const huntTruncatedDocument = "unexpected end of JSON input"

func huntInputError(bounded *huntBoundedReader, err error) error {
	if errors.Is(err, errHuntOverLimit) || bounded.n > HuntMaxResultBytes {
		return huntOversizeError()
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) && syntax.Error() == huntTruncatedDocument {
		return io.ErrUnexpectedEOF
	}
	return err
}

// huntWalkResult reads the top-level object one member at a time.
//
// The three lists that can grow are streamed into the result as they are read.
// Everything else that HuntResult declares is collected as raw bytes under the
// run summary's ceiling and decoded in one stock pass at the end, which is what
// keeps duplicate keys, absent keys, null keys and type mismatches answering
// exactly the way a stock struct decode answers for them. A key HuntResult does
// not declare is skipped a token at a time, so an unknown array costs its
// element count in time and nothing in memory.
func huntWalkResult(dec *json.Decoder, bounded *huntBoundedReader) (*HuntResult, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		// A null document decodes to the zero result, the way a stock decode of
		// it always has.
		return &HuntResult{}, nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil, &json.UnmarshalTypeError{Value: huntTokenKind(token),
			Type: reflect.TypeOf(HuntResult{})}
	}
	result, summary := &HuntResult{}, &huntSummary{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := key.(string)
		switch name {
		case "findings":
			result.Findings, err = huntStreamList[HuntFinding](dec, bounded,
				huntMaxAggregateFindingsBytes, name, "hunt findings")
		case "suggestions":
			result.Suggestions, err = huntStreamList[HuntSuggestion](dec, bounded,
				huntMaxAggregateSuggestionsBytes, name, "hunt suggestions")
		case "case_results":
			// Dropped before the next one is read rather than after, so a
			// document that names the section twice holds one decoded case
			// list at a time and the last one still wins.
			result.Cases = nil
			result.Cases, err = huntStreamCases(dec, bounded)
		default:
			if huntSummaryFields[name] {
				err = summary.take(dec, bounded, name)
			} else {
				err = huntSkipValue(dec, bounded, name)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if err := summary.apply(result); err != nil {
		return nil, err
	}
	return result, nil
}

// huntSummaryFields is every member of HuntResult that is not one of the three
// streamed lists, taken from the struct rather than listed here so a field
// added to the model is carried by the reader without being named twice.
var huntSummaryFields = huntSummaryFieldNames()

func huntSummaryFieldNames() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeOf(HuntResult{})
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		switch name {
		case "", "-", "findings", "suggestions", "case_results":
			continue
		}
		out[name] = true
	}
	return out
}

// huntSummary collects the members outside the three streamed lists, as the
// bytes the document spells them with, and decodes them in one pass.
//
// Reassembling an object out of raw members rather than decoding each one into
// its field is what preserves the stock contract: the members are in the order
// the document gave them, so the last of two duplicates still wins, and the one
// decode that happens is an ordinary struct decode with ordinary struct errors.
// The cost is bounded by huntMaxRunSummaryBytes, the ceiling the writer already
// holds this part of the document to, which is also what stops a single scalar
// member from carrying hundreds of megabytes into a Go string.
type huntSummary struct {
	buf bytes.Buffer
}

func (s *huntSummary) take(dec *json.Decoder, bounded *huntBoundedReader, name string) error {
	over := fmt.Errorf("hunt %s exceeds the supported encoded maximum of %d bytes",
		name, huntMaxRunSummaryBytes)
	room := huntMaxRunSummaryBytes - s.buf.Len() - len(`,"":`) - len(name)
	restore := bounded.section(dec, room)
	var raw json.RawMessage
	err := dec.Decode(&raw)
	bounded.limit = restore
	if errors.Is(err, errHuntOverLimit) {
		return over
	}
	if err != nil {
		return err
	}
	if len(raw) > room {
		return over
	}
	if s.buf.Len() > 0 {
		s.buf.WriteByte(',')
	}
	s.buf.WriteString(`"` + name + `":`)
	s.buf.Write(raw)
	return nil
}

func (s *huntSummary) apply(r *HuntResult) error {
	if s.buf.Len() == 0 {
		return nil
	}
	return json.Unmarshal([]byte("{"+s.buf.String()+"}"), r)
}

// huntStreamList reads one top-level list element by element, holding the
// running total against the same accounting boundEncodedList bounds the section
// by on the way out. Stopping on the element that crosses the ceiling is what
// keeps the typed slice proportional to the ceiling instead of to the number of
// elements the document offers, and lowering the reader's ceiling to the
// section's for the length of each element is what keeps one enormous element
// from being buffered before it can be refused.
func huntStreamList[T any](dec *json.Decoder, bounded *huntBoundedReader, max int, field, name string) ([]T, error) {
	over := fmt.Errorf("%s exceed the supported encoded maximum of %d bytes", name, max)
	out, total := []T{}, len("[]")
	array, err := huntStreamArray[T](dec, bounded, field, max, over, func(element json.RawMessage) error {
		var item T
		if err := json.Unmarshal(element, &item); err != nil {
			return err
		}
		total += huntEncodedElementSize(item)
		if total > max {
			return over
		}
		out = append(out, item)
		return nil
	})
	if !array || err != nil {
		return nil, err
	}
	return out, nil
}

// huntStreamCases is the list the whole boundary exists for. Three ceilings
// decide a case before it becomes a Go value, in the order that keeps the cost
// of refusing it low: the count, so the five hundred and first element is
// refused without the five hundred and first struct; the encoded bytes of the
// element, so no case is decoded out of more input than one case is allowed to
// weigh; and the encoded bytes of what came back, so a case cannot spend its
// allowance on elements the decoder reserves a struct for and then discards.
func huntStreamCases(dec *json.Decoder, bounded *huntBoundedReader) ([]HuntCaseResult, error) {
	out := []HuntCaseResult{}
	over := func(index int) error {
		return fmt.Errorf("hunt case result %d exceeds the supported encoded maximum of %d bytes",
			index, HuntMaxCaseResultBytes)
	}
	array, err := huntStreamArray[HuntCaseResult](dec, bounded, "case_results", HuntMaxCaseResultBytes, over(0),
		func(element json.RawMessage) error {
			if len(out) == HuntMaxCases {
				return fmt.Errorf("hunt result has more than %d case results", HuntMaxCases)
			}
			if len(element) > HuntMaxCaseResultBytes {
				return over(len(out))
			}
			var item HuntCaseResult
			if err := json.Unmarshal(element, &item); err != nil {
				return err
			}
			if err := checkHuntCaseCardinality(&item); err != nil {
				return err
			}
			if size := huntEncodedElementSize(item); size > HuntMaxCaseResultBytes {
				return fmt.Errorf("hunt case result %d is %d bytes, over the maximum of %d",
					len(out), size, HuntMaxCaseResultBytes)
			}
			out = append(out, item)
			return nil
		})
	if !array || err != nil {
		return nil, err
	}
	return out, nil
}

// huntStreamArray hands visit one element of a JSON array at a time, each read
// under a ceiling of element bytes, so the memory a section costs to inspect is
// one element rather than all of them. It reports whether the value was an
// array at all, and answers a value that is not one the way the stock decoder
// answers for it: an absent or null section leaves the field alone, and
// anything else is the type mismatch a slice field draws.
func huntStreamArray[T any](dec *json.Decoder, bounded *huntBoundedReader, field string,
	element int, over error, visit func(json.RawMessage) error) (bool, error) {
	token, err := dec.Token()
	if err != nil {
		return false, err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '[' {
		if token == nil {
			return false, nil
		}
		return false, &json.UnmarshalTypeError{Value: huntTokenKind(token),
			Type: reflect.TypeOf([]T(nil)), Struct: "HuntResult", Field: field}
	}
	for dec.More() {
		var raw json.RawMessage
		restore := bounded.section(dec, element)
		err := dec.Decode(&raw)
		bounded.limit = restore
		if errors.Is(err, errHuntOverLimit) {
			return true, over
		}
		if err != nil {
			return true, err
		}
		if err := visit(raw); err != nil {
			return true, err
		}
	}
	_, err = dec.Token()
	return true, err
}

// huntSkipValue walks one value the model does not declare and keeps nothing.
// Tracking the nesting depth rather than decoding the value is what makes an
// unknown array cost the same memory whether it holds one element or ten
// million.
//
// Each token is read under the run summary's ceiling, which is the one thing
// depth tracking does not bound on its own: a container costs a delimiter
// whatever it holds, but a single scalar token is as large as the document lets
// it be, and json.Decoder.Token hands back a decoded copy of it. A member this
// version of the model does not know is still ignored; a single unknown value
// larger than the whole run summary a hunt is allowed to write is not
// compatibility, it is a shape, and it is refused before it is held.
func huntSkipValue(dec *json.Decoder, bounded *huntBoundedReader, name string) error {
	for depth := 0; ; {
		restore := bounded.section(dec, huntMaxRunSummaryBytes)
		token, err := dec.Token()
		bounded.limit = restore
		if errors.Is(err, errHuntOverLimit) {
			return fmt.Errorf("hunt %s exceeds the supported encoded maximum of %d bytes",
				name, huntMaxRunSummaryBytes)
		}
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			if delim == '[' || delim == '{' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// huntTokenKind names a token the way encoding/json names it in a type
// mismatch, so a value of the wrong shape draws the complaint it has always
// drawn.
func huntTokenKind(token json.Token) string {
	switch value := token.(type) {
	case json.Delim:
		if value == '[' {
			return "array"
		}
		return "object"
	case string:
		return "string"
	case float64, json.Number:
		return "number"
	case bool:
		return "bool"
	}
	return "null"
}
