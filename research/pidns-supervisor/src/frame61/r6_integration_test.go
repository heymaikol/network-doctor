//go:build integration

package main

// Deterministic R6 tests that open real SOCK_SEQPACKET pairs (contract 3.2, 3.4, 6.3): metadata preservation, sticky
// poison, and the overflow and observation-error rules. Seams only where a specific kernel return is needed. Every seam
// is restored, and seamsArmed is checked at the end. Real-socket tests carry the integration tag (AGENTS.md).

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
