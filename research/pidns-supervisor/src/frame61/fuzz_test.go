package main

// Bounded fuzz targets for R5 (scratch, test only).
//
// FuzzDecideOracle: decide (harness) against refDecide (an independent reading of contract 3.3 and 3.4, R5).
// The identity function is injected as a parameter, so the ACCEPT paths are reachable. Injection is local to the
// fuzz body. It does not touch the global seam, so evidence runs keep the real ioctl.
//
// FuzzParseWireAgreement: parseWire (harness) against refParse (map decoding plus a token pass for names).
//
// Excluded inputs: FuzzDecideOracle skips payloads longer than dataBuf (1024). The kernel truncates them, and
// MSG_TRUNC decides the outcome before any payload parsing (decidePost and decide check flags first). The number
// of skipped inputs is NOT recorded: go test -fuzz reports no per-filter count. Deterministic coverage of this
// path: the E10 rows init_oversize_1500 and known_then_status_truncated, and TestZeroByteBufferTruncIsRecordAndConsumes.

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"
)

const fuzzPidI = 1000

// tokenNames returns the decoded member names of one top-level object, in order, or nil if the bytes do not
// start with an object. It is the oracle's name pass, separate from objectMembers.
func tokenNames(b []byte) []string {
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

// negZeroRaw reports the token -0. The R6 grammar rejects it (3.2), as decodeInt does.
func negZeroRaw(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("-0"))
}
func rawIsNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// refParse is the oracle grammar (3.2 R5). It is written independently of parseWire.
func refParse(b []byte) rec {
	var out rec
	if !utf8.Valid(b) {
		return out
	}
	names := tokenNames(b)
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
			out.cand = true
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
	if rawIsNull(m["type"]) || json.Unmarshal(m["type"], &typ) != nil {
		return out
	}
	want := map[string][]string{
		"init":     {"v", "type"},
		"producer": {"v", "type"},
		"status":   {"v", "type", "kind", "value"},
	}[typ]
	if want == nil {
		return out
	}
	if len(m) != len(want) {
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
	if rawIsNull(m["v"]) || negZeroRaw(m["v"]) || json.Unmarshal(m["v"], &v) != nil {
		return out
	}
	out.w = wire{V: v, Type: typ}
	if typ == "status" {
		var kind string
		var val int
		if rawIsNull(m["kind"]) || json.Unmarshal(m["kind"], &kind) != nil {
			return out
		}
		if rawIsNull(m["value"]) || negZeroRaw(m["value"]) || json.Unmarshal(m["value"], &val) != nil {
			return out
		}
		out.w.Kind, out.w.Value = kind, val
	}
	out.ok = true
	return out
}

// refFacts are the kernel and parse facts the oracle reads for one record.
type refFacts struct {
	stage    int
	pidI     int
	trunc    bool
	ctrunc   bool
	n        int
	credsPid int // -1: no SCM_CREDENTIALS
	nfds     int
	infoOK   bool
	infoPid  uint32
	infoPpid uint32
	rec      rec
}

// refDecide is the contract reading (3.3 admission, 3.4 post-admission). One step, no state beyond stage.
func refDecide(f refFacts) string {
	if f.stage == 4 {
		return "DISCARD"
	}
	if f.stage >= 2 {
		switch {
		case f.trunc:
			return "CLOSE:trunc"
		case f.ctrunc:
			return "CLOSE:ctrunc"
		case f.n == 0:
			return "CLOSE:empty"
		case !f.rec.cand && !f.rec.ok:
			return "CLOSE:malformed"
		case !f.rec.cand:
			return "CLOSE:late_record"
		case f.credsPid != f.pidI:
			return "CLOSE:creds"
		case f.nfds > 0:
			return "CLOSE:status_fd"
		case f.stage == 3:
			return "UNKNOWN:after_terminal"
		case !f.rec.ok:
			return "UNKNOWN:malformed"
		case f.rec.w.V == 1 && (f.rec.w.Kind == "exit" || f.rec.w.Kind == "signal"):
			return "KNOWN"
		default:
			return "UNKNOWN:status_shape"
		}
	}
	want := map[int]string{0: "init", 1: "producer"}[f.stage]
	switch {
	case f.trunc:
		return "CLOSE:trunc"
	case f.ctrunc:
		return "CLOSE:ctrunc"
	case f.credsPid < 0:
		return "CLOSE:nocreds"
	case f.n == 0:
		return "CLOSE:empty"
	case f.rec.cand:
		return "CLOSE:early_status"
	case !f.rec.ok || f.rec.w.Type != want || f.rec.w.V != 1:
		return "CLOSE:order"
	case f.nfds != 1:
		return "CLOSE:count"
	case !f.infoOK:
		return "CLOSE:pidfd_info"
	case f.stage == 0 && int64(f.infoPid) != int64(f.credsPid):
		return "CLOSE:creds_pidfd"
	case f.stage == 0:
		return "ACCEPT_INIT"
	case f.credsPid != f.pidI:
		return "CLOSE:creds"
	case int64(f.infoPpid) != int64(f.pidI):
		return "CLOSE:ppid"
	default:
		return "ACCEPT_PRODUCER"
	}
}

func FuzzDecideOracle(f *testing.F) {
	// Seed bits: stage, flags (1 TRUNC, 2 CTRUNC), creds (0 none, 1 sender, 2 other), nfds, identBits (1 pid is
	// creds pid, 2 ppid is pidI, 4 mask ok), payload.
	f.Add(uint8(0), uint8(0), uint8(1), uint8(1), uint8(7), []byte(initRec))
	f.Add(uint8(1), uint8(0), uint8(1), uint8(1), uint8(7), []byte(prodRec))
	f.Add(uint8(2), uint8(0), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add(uint8(3), uint8(0), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add(uint8(2), uint8(1), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add(uint8(2), uint8(0), uint8(1), uint8(1), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add(uint8(2), uint8(0), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status"}`))
	f.Add(uint8(2), uint8(0), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":null}`))
	f.Add(uint8(2), uint8(0), uint8(1), uint8(0), uint8(7), []byte(`{"v":1,"type":"status","kind":"exit","value":0}`))
	f.Add(uint8(2), uint8(0), uint8(0), uint8(0), uint8(7), []byte(``))
	f.Add(uint8(0), uint8(0), uint8(1), uint8(1), uint8(7), []byte(``))
	f.Add(uint8(0), uint8(0), uint8(1), uint8(1), uint8(7), []byte(`{"v":1,"type":"init","type":"init"}`))
	f.Add(uint8(3), uint8(0), uint8(2), uint8(0), uint8(7), []byte(`null`))
	f.Add(uint8(1), uint8(0), uint8(1), uint8(1), uint8(3), []byte(prodRec))
	f.Add(uint8(0), uint8(0), uint8(1), uint8(1), uint8(5), []byte(initRec))
	f.Fuzz(func(t *testing.T, stage, flags, credsMode, nfds, identBits uint8, payload []byte) {
		if len(payload) > dataBuf {
			return // excluded: kernel truncation, decided by flags (see file comment)
		}
		st := &state{stage: int(stage % 5), pidI: fuzzPidI}
		fl := 0
		if flags&1 != 0 {
			fl |= syscall.MSG_TRUNC
		}
		if flags&2 != 0 {
			fl |= syscall.MSG_CTRUNC
		}
		k := int(nfds % 4)
		credsPid := -1
		r := recvd{data: payload, flags: fl, n: len(payload)}
		switch credsMode % 3 {
		case 1:
			credsPid = fuzzPidI
			r.creds = &syscall.Ucred{Pid: fuzzPidI}
		case 2:
			credsPid = fuzzPidI + 1
			r.creds = &syscall.Ucred{Pid: fuzzPidI + 1}
		}
		for i := 0; i < k; i++ {
			r.fds = append(r.fds, 100+i)
		}
		r.nfds = k
		infoOK := identBits&4 != 0
		infoPid := uint32(credsPid)
		if identBits&1 == 0 {
			infoPid = uint32(credsPid) + 1
		}
		if credsPid < 0 {
			infoPid = 0
		}
		infoPpid := uint32(fuzzPidI)
		if identBits&2 == 0 {
			infoPpid = uint32(fuzzPidI) + 1
		}
		ident := func(fd int) (pidfdInfo, error) {
			mask := uint64(1)
			if infoOK {
				mask = 3
			}
			return pidfdInfo{Mask: mask, Pid: infoPid, Ppid: infoPpid}, nil
		}
		p := parseWire(payload)
		ref := refParse(payload)
		if p.ok != ref.ok || p.cand != ref.cand {
			t.Fatalf("grammar disagreement on %q: harness ok=%v cand=%v, oracle ok=%v cand=%v",
				payload, p.ok, p.cand, ref.ok, ref.cand)
		}
		startStage := st.stage
		got := decide(st, &r, p, ident)
		want := refDecide(refFacts{
			stage: startStage, pidI: fuzzPidI, trunc: fl&syscall.MSG_TRUNC != 0, ctrunc: fl&syscall.MSG_CTRUNC != 0,
			n: len(payload), credsPid: credsPid, nfds: k, infoOK: infoOK, infoPid: infoPid, infoPpid: infoPpid,
			rec: ref,
		})
		if got != want {
			t.Fatalf("stage=%d flags=%#x creds=%d nfds=%d ident=%#x payload=%q: oracle %s, harness %s",
				startStage, fl, credsMode%3, k, identBits, payload, want, got)
		}
		if strings.HasPrefix(got, "ACCEPT_") && k != 1 {
			t.Fatalf("ACCEPT with %d fds", k)
		}
		if (startStage == 2 || startStage == 3) && !ref.cand && !strings.HasPrefix(got, "CLOSE:") {
			t.Fatalf("non-candidate after admission not closed: %q gave %s", payload, got)
		}
	})
}

func FuzzParseWireAgreement(f *testing.F) {
	f.Add([]byte(initRec))
	f.Add([]byte(prodRec))
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
		h := parseWire(payload)
		o := refParse(payload)
		if h.ok != o.ok || h.cand != o.cand {
			t.Fatalf("payload %q: harness ok=%v cand=%v, oracle ok=%v cand=%v", payload, h.ok, h.cand, o.ok, o.cand)
		}
		if h.ok && (h.w != o.w) {
			t.Fatalf("payload %q: fields differ: harness %+v oracle %+v", payload, h.w, o.w)
		}
	})
}

// TestAcceptPathsWithInjectedIdentity proves the ACCEPT and KNOWN branches are reachable with the identity
// function injected as a parameter, and that refDecide agrees on each row. Fuzzing alone does not show this.
func TestAcceptPathsWithInjectedIdentity(t *testing.T) {
	type row struct {
		name     string
		stage    int
		payload  string
		credsPid int
		infoPid  uint32
		infoPpid uint32
		want     string
	}
	rows := []row{
		{"init_accept", 0, initRec, 1000, 1000, 0, "ACCEPT_INIT"},
		{"init_pid_mismatch", 0, initRec, 1000, 1001, 0, "CLOSE:creds_pidfd"},
		{"producer_accept", 1, prodRec, fuzzPidI, 0, fuzzPidI, "ACCEPT_PRODUCER"},
		{"producer_ppid_mismatch", 1, prodRec, fuzzPidI, 0, fuzzPidI + 1, "CLOSE:ppid"},
		{"producer_creds_mismatch", 1, prodRec, fuzzPidI + 1, 0, fuzzPidI, "CLOSE:creds"},
		{"known_after_admission", 2, `{"v":1,"type":"status","kind":"exit","value":0}`, fuzzPidI, 0, 0, "KNOWN"},
		{"known_signal", 2, `{"v":1,"type":"status","kind":"signal","value":9}`, fuzzPidI, 0, 0, "KNOWN"},
	}
	for _, rw := range rows {
		st := &state{stage: rw.stage, pidI: fuzzPidI}
		r := recvd{data: []byte(rw.payload), n: len(rw.payload), creds: &syscall.Ucred{Pid: int32(rw.credsPid)}}
		if rw.stage < 2 {
			r.fds = []int{100}
		}
		ident := func(fd int) (pidfdInfo, error) {
			return pidfdInfo{Mask: 3, Pid: rw.infoPid, Ppid: rw.infoPpid}, nil
		}
		got := decide(st, &r, parseWire(r.data), ident)
		want := refDecide(refFacts{stage: rw.stage, pidI: fuzzPidI, n: len(rw.payload), credsPid: rw.credsPid,
			nfds: len(r.fds), infoOK: true, infoPid: rw.infoPid, infoPpid: rw.infoPpid, rec: refParse(r.data)})
		if got != rw.want || want != rw.want {
			t.Errorf("%s: harness %s, oracle %s, want %s", rw.name, got, want, rw.want)
		}
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// TestParseWireEscapedNames checks that member names are compared after unescaping (3.2). The E10 row
// init_escaped_type_name does not contain an escape; this test and the escaped seeds in FuzzParseWireAgreement
// are the escape coverage.
func TestParseWireEscapedNames(t *testing.T) {
	rows := []struct {
		name string
		in   string
		ok   bool
		cand bool
	}{
		{"escaped_type_init", `{"v":1,"type":"init"}`, true, false},
		{"escaped_type_status", `{"v":1,"type":"status","kind":"exit","value":0}`, true, true},
		{"duplicate_after_unescape", `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`, false, false},
		{"escaped_uppercase_name", `{"v":1,"TYPE":"status","kind":"exit","value":0}`, false, false},
	}
	for _, rw := range rows {
		p := parseWire([]byte(rw.in))
		if p.ok != rw.ok || p.cand != rw.cand {
			t.Errorf("%s: ok=%v cand=%v, want ok=%v cand=%v", rw.name, p.ok, p.cand, rw.ok, rw.cand)
		}
	}
}
