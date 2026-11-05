package main

// Deterministic R6 tests that open no socket (contract 3.2, 3.4, 6.3): one status gate for decidePost and T2, and the
// integer grammar against refParse. The socket tests of R6 are in r6_integration_test.go, which carries the integration
// tag (AGENTS.md).

import (
	"syscall"
	"testing"
)

// TestR6StatusGateSameForDecideAndT2: for each record, the T2 Known rule and decidePost agree, and both give the
// expected answer. The table covers every gate in statusGate.
func TestR6StatusGateSameForDecideAndT2(t *testing.T) {
	const pid = fuzzPidI
	status := `{"v":1,"type":"status","kind":"exit","value":0}`
	rows := []struct {
		name    string
		payload string
		flags   int
		creds   int // -1: no SCM_CREDENTIALS
		nfds    int
		want    bool
	}{
		{"valid_exit", status, 0, pid, 0, true},
		{"valid_signal", `{"v":1,"type":"status","kind":"signal","value":9}`, 0, pid, 0, true},
		{"status_with_fd", status, 0, pid, 1, false},
		{"trunc", status, syscall.MSG_TRUNC, pid, 0, false},
		{"ctrunc", status, syscall.MSG_CTRUNC, pid, 0, false},
		{"foreign_creds", status, 0, pid + 1, 0, false},
		{"no_creds", status, 0, -1, 0, false},
		{"zero_length", "", 0, pid, 0, false},
		{"bad_kind", `{"v":1,"type":"status","kind":"bogus","value":0}`, 0, pid, 0, false},
		{"v_two", `{"v":2,"type":"status","kind":"exit","value":0}`, 0, pid, 0, false},
		{"missing_kind", `{"v":1,"type":"status","value":0}`, 0, pid, 0, false},
		{"producer_record", prodRec, 0, pid, 0, false},
		{"negative_zero_value", `{"v":1,"type":"status","kind":"exit","value":-0}`, 0, pid, 0, false},
		{"duplicate_type", `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`, 0, pid, 0, false},
	}
	for _, rw := range rows {
		r := recvd{data: []byte(rw.payload), flags: rw.flags, n: len(rw.payload), nfds: rw.nfds}
		if rw.creds >= 0 {
			r.creds = &syscall.Ucred{Pid: int32(rw.creds)}
		}
		gotT2 := t2Known(drainOut{Recs: []recvd{r}, End: "EAGAIN"}, pid)
		dr := r
		gotDecide := decidePost(&state{stage: 2, pidI: pid}, &dr, parseWire(dr.data)) == "KNOWN"
		if gotT2 != rw.want || gotDecide != rw.want {
			t.Errorf("%s: t2Known=%v decidePost=%v, want %v", rw.name, gotT2, gotDecide, rw.want)
		}
	}
}

// TestR6IntegerGrammarMatchesRefParse pins the canonical integer rule (3.2, R6) on parseWire and on the oracle.
func TestR6IntegerGrammarMatchesRefParse(t *testing.T) {
	rows := []struct {
		name string
		in   string
		ok   bool
		cand bool
	}{
		{"int_plain", `{"v":1,"type":"status","kind":"exit","value":0}`, true, true},
		{"negative_zero_value", `{"v":1,"type":"status","kind":"exit","value":-0}`, false, true},
		{"negative_zero_v", `{"v":-0,"type":"status","kind":"exit","value":0}`, false, true},
		{"negative_zero_init", `{"v":-0,"type":"init"}`, false, false},
		{"leading_zero_value", `{"v":1,"type":"status","kind":"exit","value":01}`, false, false},
		{"fraction_value", `{"v":1,"type":"status","kind":"exit","value":1.0}`, false, true},
		{"exponent_value", `{"v":1,"type":"status","kind":"exit","value":1e0}`, false, true},
		{"fraction_v", `{"v":1.0,"type":"status","kind":"exit","value":0}`, false, true},
		{"string_v", `{"v":"1","type":"status","kind":"exit","value":0}`, false, true},
		{"int64_max", `{"v":1,"type":"status","kind":"exit","value":9223372036854775807}`, true, true},
		{"int64_max_plus_one", `{"v":1,"type":"status","kind":"exit","value":9223372036854775808}`, false, true},
		{"int64_min", `{"v":1,"type":"status","kind":"exit","value":-9223372036854775808}`, true, true},
		{"int64_min_minus_one", `{"v":1,"type":"status","kind":"exit","value":-9223372036854775809}`, false, true},
		{"escaped_v_name", `{"\u0076":1,"type":"status","kind":"exit","value":0}`, true, true},
		{"escaped_type_value", `{"v":1,"type":"\u0073tatus","kind":"exit","value":0}`, true, true},
		{"duplicate_after_unescape", `{"v":1,"type":"status","type":"status","kind":"exit","value":0}`, false, false},
		{"uppercase_name", `{"v":1,"TYPE":"status","kind":"exit","value":0}`, false, false},
	}
	for _, rw := range rows {
		p := parseWire([]byte(rw.in))
		ref := refParse([]byte(rw.in))
		if p.ok != rw.ok || p.cand != rw.cand {
			t.Errorf("%s: parseWire ok=%v cand=%v, want ok=%v cand=%v", rw.name, p.ok, p.cand, rw.ok, rw.cand)
		}
		if ref.ok != p.ok || ref.cand != p.cand {
			t.Errorf("%s: refParse ok=%v cand=%v disagrees with parseWire ok=%v cand=%v",
				rw.name, ref.ok, ref.cand, p.ok, p.cand)
		}
		if p.ok && p.w != ref.w {
			t.Errorf("%s: parseWire %+v, refParse %+v", rw.name, p.w, ref.w)
		}
	}
}

// t2Known is the one-drain T2 rule: commitExit on a fresh handle whose poison is the drain's own error (R6-1).
// Production code calls commitExit with the handle. The drain sets st.poison to the same error it returns in o.Err,
// so this form cannot differ from the handle.
func t2Known(o drainOut, pidI int) bool {
	return commitExit(&state{poison: o.Err}, o, pidI, false) == "KNOWN"
}
