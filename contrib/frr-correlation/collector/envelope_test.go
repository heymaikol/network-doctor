package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func exampleEnvelope() Envelope {
	return Envelope{
		Schema:    SchemaVersion,
		CohortID:  "11111111-1111-1111-1111-111111111111",
		BootID:    "22222222-2222-2222-2222-222222222222",
		Namespace: Namespace{Device: 5, Inode: 4026533000},
		BuildID:   strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64),
		BundleSHA256: strings.Repeat("c", 64),
		Producers: Producers{
			BGPD:  Producer{PID: 100, StartTimeTicks: 9007199254740993, Epoch: "33333333-3333-3333-3333-333333333333", CaptureSHA256: strings.Repeat("d", 64), CaptureBytes: 4096},
			Zebra: Producer{PID: 101, StartTimeTicks: math.MaxUint64, Epoch: "44444444-4444-4444-4444-444444444444", CaptureSHA256: strings.Repeat("e", 64), CaptureBytes: 8192},
		},
	}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func requireCode(t *testing.T, err error, code RefusalCode) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code() != code {
		t.Fatalf("got %v, want refusal %s", err, code)
	}
	if len(r.Error()) > MaxDiagnosticBytes {
		t.Fatal("unbounded diagnostic")
	}
}

func TestExactIntegersAndImmutableClaims(t *testing.T) {
	want := exampleEnvelope()
	want.Namespace.Inode = math.MaxUint64
	u, err := Decode(bytes.NewReader(encode(t, want)))
	if err != nil {
		t.Fatal(err)
	}
	if u.Claims() != want {
		t.Fatal("lost integer precision or identity")
	}
	copy := u.Claims()
	copy.Producers.BGPD.PID = 999
	if u.Claims() != want {
		t.Fatal("mutable envelope alias")
	}
}

func TestMalformedJSON(t *testing.T) {
	valid := string(encode(t, exampleEnvelope()))
	cases := map[string]string{
		"empty": "", "truncated": valid[:len(valid)-1], "second_object": valid + "{}",
		"trailing_scalar": valid + "true", "trailing_garbage": valid + "secret",
		"duplicate_root":      strings.Replace(valid, `"schema":`, `"cohort_id":"other","schema":`, 1),
		"escaped_duplicate":   strings.Replace(valid, `"schema":`, `"\u0063ohort_id":"other","schema":`, 1),
		"duplicate_namespace": strings.Replace(valid, `"device":5`, `"device":5,"device":6`, 1),
		"duplicate_producer":  strings.Replace(valid, `"pid":100`, `"pid":100,"pid":200`, 1),
		"invalid_utf8":        strings.Replace(valid, "cohort_id", "\xff", 1),
		"trailing_comma":      valid[:len(valid)-1] + ",}",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			u, err := Decode(strings.NewReader(raw))
			requireCode(t, err, MalformedJSON)
			if u.envelope != nil {
				t.Fatal("failed parse returned data")
			}
		})
	}
}

func TestSchemaRefusals(t *testing.T) {
	valid := string(encode(t, exampleEnvelope()))
	cases := map[string]string{
		"array": "[]", "null": "null", "scalar": "42",
		"unknown":           strings.Replace(valid, `"schema":`, `"authenticated":true,"schema":`, 1),
		"case_variant":      strings.Replace(valid, `"boot_id":`, `"Boot_id":`, 1),
		"unknown_namespace": strings.Replace(valid, `"device":5`, `"device":5,"lifetime_verified":true`, 1),
		"unknown_producer":  strings.Replace(valid, `"pid":100`, `"pid":100,"pidfd_verified":true`, 1),
		"schema_version":    strings.Replace(valid, SchemaVersion, "netdoc-frr-cohort/v2", 1),
		"selected_fib":      strings.Replace(valid, `"selected_fib_verified":false`, `"selected_fib_verified":true`, 1),
		"bad_uuid":          strings.Replace(valid, "11111111-1111-1111-1111-111111111111", "not-a-uuid", 1),
		"bad_hash":          strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("g", 64), 1),
		"zero_pid":          strings.Replace(valid, `"pid":100`, `"pid":0`, 1),
		"pid_overflow":      strings.Replace(valid, `"pid":100`, `"pid":2147483648`, 1),
		"same_pid":          strings.Replace(valid, `"pid":101`, `"pid":100`, 1),
		"same_epoch":        strings.Replace(valid, "44444444-4444-4444-4444-444444444444", "33333333-3333-3333-3333-333333333333", 1),
		"capture_limit":     strings.Replace(valid, `"capture_bytes":4096`, `"capture_bytes":67108865`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			u, err := Decode(strings.NewReader(raw))
			requireCode(t, err, InvalidEnvelope)
			if u.envelope != nil {
				t.Fatal("failed parse returned data")
			}
		})
	}
}

func TestEveryFieldRequiredAndNonNull(t *testing.T) {
	var doc map[string]any
	d := json.NewDecoder(bytes.NewReader(encode(t, exampleEnvelope())))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	var walk func(map[string]any, string)
	walk = func(obj map[string]any, path string) {
		for key, value := range obj {
			t.Run(path+key, func(t *testing.T) {
				delete(obj, key)
				_, err := Decode(bytes.NewReader(encode(t, doc)))
				requireCode(t, err, InvalidEnvelope)
				for _, invalid := range []any{nil, []any{}, map[string]any{"unknown": true}, "invalid", true} {
					obj[key] = invalid
					_, err = Decode(bytes.NewReader(encode(t, doc)))
					requireCode(t, err, InvalidEnvelope)
				}
				obj[key] = value
			})
			if nested, ok := value.(map[string]any); ok {
				walk(nested, path+key+"/")
			}
		}
	}
	walk(doc, "")
}

func TestIntegerLexicalBoundaries(t *testing.T) {
	valid := string(encode(t, exampleEnvelope()))
	for _, field := range []string{`"device":5`, `"inode":4026533000`, `"pid":100`, `"start_time_ticks":9007199254740993`, `"capture_bytes":4096`} {
		for _, bad := range []string{"-1", "0", "1.0", "1e0", "1e1000000000", "0e1000000000", "18446744073709551616", `"1"`, "true", "null"} {
			t.Run(field+"/"+bad, func(t *testing.T) {
				key, _, _ := strings.Cut(field, ":")
				_, err := Decode(strings.NewReader(strings.Replace(valid, field, key+":"+bad, 1)))
				requireCode(t, err, InvalidEnvelope)
			})
		}
	}
}

func TestResourceLimits(t *testing.T) {
	valid := string(encode(t, exampleEnvelope()))
	cases := map[string]string{
		"bytes":  strings.Repeat(" ", MaxEnvelopeBytes+1),
		"depth":  strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1),
		"tokens": "[" + strings.Repeat("0,", MaxTokens) + "0]",
		"string": `{"x":"` + strings.Repeat("x", MaxStringBytes+1) + `"}`,
		"key":    `{"` + strings.Repeat("x", MaxStringBytes+1) + `":0}`,
		"number": strings.Repeat("9", MaxNumberBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(raw))
			requireCode(t, err, ResourceLimit)
		})
	}
	_, err := Decode(strings.NewReader(valid + strings.Repeat(" ", MaxEnvelopeBytes-len(valid))))
	if err != nil {
		t.Fatalf("exact byte limit refused: %v", err)
	}
	r := &countingReader{}
	_, err = Decode(r)
	requireCode(t, err, ResourceLimit)
	if r.read != MaxEnvelopeBytes+1 {
		t.Fatalf("read %d bytes", r.read)
	}
}

type countingReader struct{ read int }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.read += len(p)
	return len(p), nil
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, fmt.Errorf("secret\x1b[31m") }

func TestDiagnosticsDoNotExposeInput(t *testing.T) {
	_, err := Decode(brokenReader{})
	requireCode(t, err, ReadFailure)
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\x1b") {
		t.Fatal("reader diagnostic leaked")
	}
	_, err = Decode(nil)
	requireCode(t, err, MalformedJSON)
	for _, code := range []RefusalCode{MalformedJSON, ResourceLimit, InvalidEnvelope, ReadFailure, ContractFailure, Unauthenticated, InvalidTransition, Incomplete, Replay, Aborted, "secret\x1b"} {
		err := refusal(code)
		if len(err.Error()) > MaxDiagnosticBytes || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsafe diagnostic")
		}
	}
}

func TestSchemaAndDecoderAgreement(t *testing.T) {
	sch, err := compiledSchema()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint64{1, 9007199254740993, math.MaxUint64} {
		v := exampleEnvelope()
		v.Namespace.Device, v.Namespace.Inode = n, n
		v.Producers.BGPD.StartTimeTicks, v.Producers.Zebra.StartTimeTicks = n, n
		raw := encode(t, v)
		doc, err := jsonschemaDocument(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(doc); err != nil {
			t.Fatal(err)
		}
		u, err := Decode(bytes.NewReader(raw))
		if err != nil || u.Claims() != v {
			t.Fatalf("integer %d: %v", n, err)
		}
	}
}

func TestExactResourceBoundaries(t *testing.T) {
	for _, raw := range []string{
		strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth),
		"[" + strings.Repeat("0,", MaxTokens-3) + "0]",
		`"` + strings.Repeat("x", MaxStringBytes) + `"`,
		"1" + strings.Repeat("0", MaxNumberBytes-1),
	} {
		_, err := Decode(strings.NewReader(raw))
		// These violate the envelope schema, but do not exceed a resource bound.
		requireCode(t, err, InvalidEnvelope)
	}
	v := exampleEnvelope()
	v.Producers.BGPD.CaptureBytes = 67108864
	v.Producers.Zebra.CaptureBytes = 1
	if _, err := Decode(bytes.NewReader(encode(t, v))); err != nil {
		t.Fatal(err)
	}
}

func jsonschemaDocument(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var doc any
	err := d.Decode(&doc)
	return doc, err
}

func FuzzDecode(f *testing.F) {
	valid, err := json.Marshal(exampleEnvelope())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"schema":"netdoc-frr-cohort/v1"}`))
	f.Add([]byte(`{"x":0,"x":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		u, err := Decode(bytes.NewReader(raw))
		if err != nil {
			var r *Refusal
			if !errors.As(err, &r) || len(err.Error()) > MaxDiagnosticBytes || u.envelope != nil {
				t.Fatal("unsafe refusal")
			}
			return
		}
		if u.Claims().SelectedFIBVerified {
			t.Fatal("selected FIB claim")
		}
	})
}
