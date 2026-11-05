package main

// Deterministic R6 tests (contract 3.2, 3.4, 6.3): metadata preservation, sticky poison, one gate for decidePost
// and T2, and the integer grammar against refParse. Real SOCK_SEQPACKET pairs; seams only where a specific kernel
// return is needed. Every seam is restored, and seamsArmed is checked at the end.

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestR6DrainKeepsMetadataAndClosesFds(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	var pp [2]int
	must(syscall.Pipe2(pp[:], syscall.O_CLOEXEC))
	err := syscall.Sendmsg(wr, statusPayload(), syscall.UnixRights(pp[1]), nil, 0)
	closeBoth(pp[0], pp[1]) // the in-flight reference keeps the descriptor for the receiver
	if err != nil {
		t.Fatal(err)
	}
	base := countFds()
	o := drain(rd, bufV61, true, &state{})
	if o.End != "EAGAIN" || len(o.Recs) != 1 {
		t.Fatalf("End=%s records=%d, want EAGAIN and one record", o.End, len(o.Recs))
	}
	r := o.Recs[0]
	if r.nfds != 1 {
		t.Errorf("nfds=%d, want 1: the descriptor count is lost", r.nfds)
	}
	if r.fds != nil {
		t.Errorf("fds=%v kept after close: closed numbers must not be reused", r.fds)
	}
	if r.flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		t.Errorf("flags=%#x, want no truncation", r.flags)
	}
	if r.creds == nil || r.n != len(statusPayload()) {
		t.Errorf("creds=%v n=%d, want creds and n=%d", r.creds, r.n, len(statusPayload()))
	}
	if !o.CloexecOK {
		t.Error("received descriptor without FD_CLOEXEC")
	}
	if got := countFds(); got != base {
		t.Errorf("drain left a received descriptor open: %d, want %d", got, base)
	}
}

func TestR6OverflowPoisonsLaterStatus(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	for i := 0; i < maxRecords+1; i++ {
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	}
	st := &state{stage: 2, pidI: os.Getpid()}
	o1 := drain(rd, bufV61, true, st)
	if o1.End != "OVERFLOW_RECORD" || len(o1.Recs) != maxRecords {
		t.Fatalf("setup: End=%s records=%d, want OVERFLOW_RECORD and %d records", o1.End, len(o1.Recs), maxRecords)
	}
	if !errors.Is(o1.Err, ErrProtocolViolation) {
		t.Fatalf("overflow error %v does not wrap ErrProtocolViolation", o1.Err)
	}
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	o2 := drain(rd, bufV61, true, st)
	if o2.End != "POISONED" || len(o2.Recs) != 0 || t2Known(o2, os.Getpid()) {
		t.Fatalf("drain after overflow: End=%s records=%d, want POISONED and no record", o2.End, len(o2.Recs))
	}
	if o2.Calls != 0 {
		t.Fatalf("poisoned drain made %d recvmsg calls, want 0", o2.Calls)
	}
	r := recvd{data: statusPayload(), n: len(statusPayload()), creds: &syscall.Ucred{Pid: int32(os.Getpid())}}
	if got := decide(st, &r, parseWire(r.data), nil); got != "UNKNOWN:observed" {
		t.Fatalf("decide after overflow = %s, want UNKNOWN:observed", got)
	}
}

func TestR6ObservationErrorWrapsAndPoisons(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	st := &state{stage: 2, pidI: os.Getpid()}
	restore := armSeam(econnresetOnce(), nil, nil)
	o := drain(rd, bufV61, true, st)
	restore()
	if o.End != "ERR" || !errors.Is(o.Err, ErrObservation) || st.poison == nil {
		t.Fatalf("End=%s err=%v poison=%v, want ERR wrapping ErrObservation and poisoned", o.End, o.Err, st.poison)
	}
	if errors.Is(o.Err, ErrProtocolViolation) {
		t.Fatal("observation error must not wrap ErrProtocolViolation")
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

func TestR6EINTROverflowIsProtocolViolation(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	st := &state{stage: 2, pidI: os.Getpid()}
	restore := armSeam(eintrRecv(maxEINTR+1), nil, nil)
	o := drain(rd, bufV61, true, st)
	restore()
	if o.End != "OVERFLOW_EINTR" || !errors.Is(o.Err, ErrProtocolViolation) || st.poison == nil {
		t.Fatalf("End=%s err=%v, want OVERFLOW_EINTR wrapping ErrProtocolViolation", o.End, o.Err)
	}
	if len(o.Recs) != 0 {
		t.Fatalf("records=%d after EINTR overflow, want 0 (the record is not read)", len(o.Recs))
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// TestR6PostStatusErrorIsNotKnown: a valid status is read, then the next receive fails. The drain ends in ERR, so
// the record is not a clean T2 Known, and the error is kept.
func TestR6PostStatusErrorIsNotKnown(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	restore := armSeam(econnresetAt(2), nil, nil)
	o := drain(rd, bufV61, true, &state{})
	restore()
	if len(o.Recs) != 1 || o.End != "ERR" || !errors.Is(o.Err, ErrObservation) {
		t.Fatalf("records=%d End=%s err=%v, want one record then ERR wrapping ErrObservation", len(o.Recs), o.End, o.Err)
	}
	if t2Known(o, os.Getpid()) {
		t.Fatal("status followed by an observation error classed Known")
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

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
