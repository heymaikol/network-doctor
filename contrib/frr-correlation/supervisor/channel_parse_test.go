package supervisor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// refChanTokenNames returns the member names of one top-level object in wire order, or nil. It is the oracle's name
// pass. It does not share code with chanMembers.
func refChanTokenNames(b []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var names []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil
		}
		name, ok := t.(string)
		if !ok {
			return nil
		}
		names = append(names, name)
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return nil
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil
	}
	return names
}

// refChanParse is the oracle grammar (3.2, R5, R6). It is a port of the harness reference (fuzz_test.go refParse),
// written apart from parseChanRecord.
func refChanParse(b []byte) chanParse {
	var out chanParse
	if !utf8.Valid(b) {
		return out
	}
	names := refChanTokenNames(b)
	if names == nil {
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return out
	}
	typeN := 0
	for _, n := range names {
		if n == "type" {
			typeN++
		}
	}
	if typeN == 1 {
		var s string
		if json.Unmarshal(m["type"], &s) == nil && s == "status" {
			out.Cand = true
		}
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			return out
		}
		seen[n] = true
	}
	if typeN != 1 {
		return out
	}
	var typ string
	if refChanNull(m["type"]) || json.Unmarshal(m["type"], &typ) != nil {
		return out
	}
	want := map[string][]string{
		"init":     {"v", "type"},
		"producer": {"v", "type"},
		"status":   {"v", "type", "kind", "value"},
	}[typ]
	if want == nil || len(m) != len(want) {
		return out
	}
	for k := range m {
		found := false
		for _, w := range want {
			if k == w {
				found = true
			}
		}
		if !found {
			return out
		}
	}
	var v int
	if refChanNull(m["v"]) || refChanNegZero(m["v"]) || json.Unmarshal(m["v"], &v) != nil {
		return out
	}
	out.W = chanWire{V: v, Type: typ}
	if typ == "status" {
		var kind string
		var val int
		if refChanNull(m["kind"]) || json.Unmarshal(m["kind"], &kind) != nil {
			return out
		}
		if refChanNull(m["value"]) || refChanNegZero(m["value"]) || json.Unmarshal(m["value"], &val) != nil {
			return out
		}
		out.W.Kind, out.W.Value = kind, val
	}
	out.OK = true
	return out
}

func refChanNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

func refChanNegZero(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "-0"
}

func TestChanRecordGrammar(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
		cand bool
	}{
		{"init", `{"v":1,"type":"init"}`, true, false},
		{"producer", `{"v":1,"type":"producer"}`, true, false},
		{"status exit", `{"v":1,"type":"status","kind":"exit","value":0}`, true, true},
		{"status signal", `{"v":1,"type":"status","kind":"signal","value":9}`, true, true},
		{"status unknown kind is grammatical", `{"v":1,"type":"status","kind":"bogus","value":0}`, true, true},
		{"surrounding whitespace", " {\"v\":1,\"type\":\"init\"}\n", true, false},
		{"escaped name decodes to type", `{"v":1,"type":"init"}`, true, false},
		{"escaped value decodes", `{"v":1,"type":"init"}`, true, false},
		{"escaped kind and value on status", `{"v":1,"type":"status","kind":"exit","value":0}`, true, true},
		{"escaped duplicate type", `{"v":1,"type":"init","type":"init"}`, false, false},
		{"escaped duplicate v", `{"v":1,"v":1,"type":"init"}`, false, false},
		{"escaped unknown member", `{"v":1,"x":1,"type":"init"}`, false, false},
		{"invalid escape in name", `{"v":1,"\x":1,"type":"init"}`, false, false},
		{"short unicode escape in name", `{"v":1,"\u00":1,"type":"init"}`, false, false},
		{"lone surrogate name is an unknown member", `{"v":1,"\ud800":1,"type":"init"}`, false, false},
		{"duplicate type status", `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`, false, false},
		{"uppercase name", `{"v":1,"TYPE":"status","kind":"exit","value":0}`, false, false},
		{"extra member on init", `{"v":1,"type":"init","x":1}`, false, false},
		{"extra member on status", `{"v":1,"type":"status","kind":"exit","value":0,"x":1}`, false, true},
		{"status missing kind", `{"v":1,"type":"status","value":0}`, false, true},
		{"status null kind", `{"v":1,"type":"status","kind":null,"value":0}`, false, true},
		{"unknown type", `{"v":1,"type":"hello"}`, false, false},
		{"capitalized type value", `{"v":1,"type":"Status","kind":"exit","value":0}`, false, false},
		{"string v", `{"v":"1","type":"status"}`, false, true},
		{"null v", `{"v":null,"type":"init"}`, false, false},
		{"fraction v", `{"v":1.0,"type":"init"}`, false, false},
		{"exponent v", `{"v":1e0,"type":"init"}`, false, false},
		{"negative zero v", `{"v":-0,"type":"init"}`, false, false},
		{"leading zero v", `{"v":01,"type":"init"}`, false, false},
		{"trailing content", `{"v":1,"type":"init"} x`, false, false},
		{"two objects", `{"v":1,"type":"init"}{"v":1,"type":"init"}`, false, false},
		{"array", `[]`, false, false},
		{"null", `null`, false, false},
		{"scalar", `1`, false, false},
		{"empty", ``, false, false},
		{"invalid utf-8 in string", "{\"v\":1,\"type\":\"init\",\"k\":\"\xff\"}", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseChanRecord([]byte(c.in))
			if got.OK != c.ok || got.Cand != c.cand {
				t.Fatalf("parseChanRecord(%q) ok=%v cand=%v, want ok=%v cand=%v", c.in, got.OK, got.Cand, c.ok, c.cand)
			}
			ref := refChanParse([]byte(c.in))
			if ref.OK != c.ok || ref.Cand != c.cand {
				t.Fatalf("refChanParse(%q) ok=%v cand=%v, want ok=%v cand=%v", c.in, ref.OK, ref.Cand, c.ok, c.cand)
			}
		})
	}
}

func TestChanRecordStatusFields(t *testing.T) {
	got := parseChanRecord([]byte(`{"v":1,"type":"status","kind":"signal","value":9}`))
	want := chanWire{V: 1, Type: "status", Kind: "signal", Value: 9}
	if !got.OK || got.W != want {
		t.Fatalf("got %+v, want OK with %+v", got, want)
	}
}

// TestR6IntegerGrammarMatchesRefParse checks the integer rule of 3.2 against the oracle. Both parsers must accept
// or reject each token the same way and decode the same value. The range rule follows the Go int of the build
// target, so 2147483648 is accepted only where int is 64 bits.
func TestR6IntegerGrammarMatchesRefParse(t *testing.T) {
	cases := []struct {
		tok    string
		accept bool
		want   int64
	}{
		{"0", true, 0},
		{"1", true, 1},
		{"-1", true, -1},
		{"2147483648", strconv.IntSize == 64, 2147483648},
		{"9223372036854775807", strconv.IntSize == 64, 9223372036854775807},
		{"-9223372036854775808", strconv.IntSize == 64, -9223372036854775808},
		{"-0", false, 0},
		{"01", false, 0},
		{"1.0", false, 0},
		{"1e2", false, 0},
		{"1E2", false, 0},
		{"1.5", false, 0},
		{"+1", false, 0},
		{"null", false, 0},
		{`"1"`, false, 0},
		{"true", false, 0},
		{"9223372036854775808", false, 0},
		{"-9223372036854775809", false, 0},
	}
	shapes := []string{
		`{"v":%s,"type":"init"}`,
		`{"v":1,"type":"status","kind":"exit","value":%s}`,
	}
	for _, c := range cases {
		for _, shape := range shapes {
			payload := []byte(fmt.Sprintf(shape, c.tok))
			got := parseChanRecord(payload)
			ref := refChanParse(payload)
			if got.OK != ref.OK || got.Cand != ref.Cand || (got.OK && got.W != ref.W) {
				t.Fatalf("%s: parser ok=%v cand=%v w=%+v, oracle ok=%v cand=%v w=%+v",
					payload, got.OK, got.Cand, got.W, ref.OK, ref.Cand, ref.W)
			}
			if got.OK != c.accept {
				t.Fatalf("%s: accepted=%v, want %v", payload, got.OK, c.accept)
			}
			if !c.accept {
				continue
			}
			value := int64(got.W.V)
			if strings.Contains(shape, "value") {
				value = int64(got.W.Value)
			}
			if value != c.want {
				t.Fatalf("%s: decoded %d, want %d", payload, value, c.want)
			}
		}
	}
}

// FuzzParseWireAgreement compares parseChanRecord with the oracle. The seeds are the harness seeds
// (FuzzParseWireAgreement, fuzz_test.go). Run the seeds with go test. Run the fuzzer with
// go test -fuzz=FuzzParseWireAgreement -fuzztime=10s.
func FuzzParseWireAgreement(f *testing.F) {
	f.Add([]byte(`{"v":1,"type":"init"}`))
	f.Add([]byte(`{"v":1,"type":"producer"}`))
	f.Add([]byte(`{"v":1,"type":"status","kind":"exit","value":1.5}`))
	f.Add([]byte(`{"v":1,"type":"status","kind":"exit","value":null}`))
	f.Add([]byte(`{"v":1,"type":"init"}`))
	f.Add([]byte(`{"v":1,"type":"init","type":"init"}`))
	f.Add([]byte(`{"v":1,"TYPE":"status","kind":"exit","value":0}`))
	f.Add([]byte(`{"v":1,"type":"status","Kind":"exit","value":0}`))
	f.Add([]byte(`{"v":1,"type":"status","kind":"exit","value":0,"x":1}`))
	f.Add([]byte(`{"v":"1","type":"status"}`))
	f.Add([]byte("{\"v\":1,\"type\":\"status\",\"kind\":\"exit\",\"value\":0,\"x\":\"\xff\"}"))
	f.Add([]byte(`{"v":1,"type":"init"} x`))
	f.Add([]byte(`{"v":1,"type":"init"}{"v":1,"type":"init"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))
	f.Add([]byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add([]byte(`{"v":1,"type":"status","type":"status","kind":"exit","value":0}`))
	f.Add([]byte(`{"v":1,"type":"init"}`))
	f.Add([]byte(`{"v":1,"TYPE":"init"}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		got := parseChanRecord(payload)
		want := refChanParse(payload)
		if got.OK != want.OK || got.Cand != want.Cand {
			t.Fatalf("payload %q: parser ok=%v cand=%v, oracle ok=%v cand=%v", payload, got.OK, got.Cand, want.OK, want.Cand)
		}
		if got.OK && got.W != want.W {
			t.Fatalf("payload %q: fields differ: parser %+v, oracle %+v", payload, got.W, want.W)
		}
	})
}

// The 150-seed oracle below is new in this slice. The generator is not ported from the harness: the harness had no
// generator for the R6 grammar. A seed fixes one payload, so the run is deterministic.
var (
	chanOracleNumbers = []string{"0", "1", "-1", "-0", "01", "1.0", "1e2", "null", `"1"`, "true",
		"2147483648", "9223372036854775808"}
	chanOracleTypes = []string{"init", "producer", "status", "status", "bogus", "Status"}
	chanOracleKinds = []string{"exit", "signal", "bogus", ""}
)

// chanOraclePayload builds one payload from seed. Most payloads use v=1 so that the status and admission rules are
// reached, and the rest carry a grammar break picked from the tables above.
func chanOraclePayload(seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, 0x6368616e6f726163)) //nolint:gosec // G404: seeded oracle generator, not a security value
	pick := func(list []string) string { return list[r.IntN(len(list))] }

	v := "1"
	if r.IntN(4) == 0 {
		v = pick(chanOracleNumbers)
	}
	typ := pick(chanOracleTypes)
	members := []string{`"v":` + v, `"type":"` + typ + `"`}
	if typ == "status" || r.IntN(5) == 0 {
		kind := pick(chanOracleKinds)
		if r.IntN(16) == 0 {
			kind = string([]byte{0xff})
		}
		members = append(members, `"kind":"`+kind+`"`)
		value := "0"
		if r.IntN(3) == 0 {
			value = pick(chanOracleNumbers)
		}
		members = append(members, `"value":`+value)
	}
	if r.IntN(8) == 0 {
		members = append(members, `"x":1`)
	}
	if r.IntN(8) == 0 {
		members = append(members, members[r.IntN(len(members))])
	}
	r.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
	payload := "{" + strings.Join(members, ",") + "}"
	if r.IntN(10) == 0 {
		payload += " x"
	}
	return []byte(payload)
}

func TestChanParseOracleSeeds(t *testing.T) {
	accepted, rejected := 0, 0
	for seed := uint64(0); seed < 150; seed++ {
		payload := chanOraclePayload(seed)
		got := parseChanRecord(payload)
		want := refChanParse(payload)
		if got.OK != want.OK || got.Cand != want.Cand || (got.OK && got.W != want.W) {
			t.Fatalf("seed %d payload %q: parser ok=%v cand=%v w=%+v, oracle ok=%v cand=%v w=%+v",
				seed, payload, got.OK, got.Cand, got.W, want.OK, want.Cand, want.W)
		}
		if got.OK {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("generator degenerate: %d accepted, %d rejected", accepted, rejected)
	}
}

// chanStubIdent answers chanDecide's identity question. err wins over pid and ppid.
type chanStubIdent struct {
	pid, ppid int
	err       error
}

func (s chanStubIdent) pidInfo(int) (int, int, error) { return s.pid, s.ppid, s.err }

// TestChanDecideIdentityRules covers the identity branches of chanDecide (3.3 checks 2, 4 and 7). The real identity
// is slice 2, so the real-socket tests never reach these branches.
func TestChanDecideIdentityRules(t *testing.T) {
	initRec := chanParse{W: chanWire{V: 1, Type: "init"}, OK: true}
	prodRec := chanParse{W: chanWire{V: 1, Type: "producer"}, OK: true}
	creds := func(pid int) chanFacts { return chanFacts{N: 20, HasCreds: true, CredsPid: pid} }
	cases := []struct {
		name  string
		st    chanState
		f     chanFacts
		p     chanParse
		fds   []int
		id    chanIdentity
		want  string
		stage int
	}{
		{"init_nil_identity_refused", chanState{}, creds(42), initRec, []int{5}, nil, "CLOSE:pidfd_info", 4},
		{"init_identity_error", chanState{}, creds(42), initRec, []int{5}, chanStubIdent{err: ErrObservation}, "CLOSE:pidfd_info", 4},
		{"init_pidfd_pid_mismatch", chanState{}, creds(42), initRec, []int{5}, chanStubIdent{pid: 7, ppid: 1}, "CLOSE:creds_pidfd", 4},
		{"init_accepted", chanState{}, creds(42), initRec, []int{5}, chanStubIdent{pid: 42, ppid: 1}, "ACCEPT_INIT", 1},
		{"init_two_fds_count_first", chanState{}, creds(42), initRec, []int{5, 6}, nil, "CLOSE:count", 4},
		{"producer_nil_identity_refused", chanState{stage: 1, pidI: 42}, creds(42), prodRec, []int{6}, nil, "CLOSE:pidfd_info", 4},
		{"producer_ppid_mismatch", chanState{stage: 1, pidI: 42}, creds(42), prodRec, []int{6}, chanStubIdent{pid: 9, ppid: 7}, "CLOSE:ppid", 4},
		{"producer_creds_mismatch", chanState{stage: 1, pidI: 42}, creds(43), prodRec, []int{6}, chanStubIdent{pid: 9, ppid: 42}, "CLOSE:creds", 4},
		{"producer_accepted", chanState{stage: 1, pidI: 42}, creds(42), prodRec, []int{6}, chanStubIdent{pid: 9, ppid: 42}, "ACCEPT_PRODUCER", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := c.st
			if got := chanDecide(&st, c.f, c.p, c.fds, c.id); got != c.want {
				t.Fatalf("decided %q, want %q", got, c.want)
			}
			if st.stage != c.stage {
				t.Errorf("stage %d, want %d", st.stage, c.stage)
			}
		})
	}
}
