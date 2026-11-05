//go:build integration

package main

// Reproductions for the two R6 bugs (contract 3.2, 3.4, 6.3, 6.4). Each failed on the R5 sources before the R6 fix; the
// red record is held outside this branch. The R5 variant differs only in call forms: drain takes no state argument and
// t2Known takes no pid argument. Real socket pairs, so the integration tag applies (AGENTS.md).

import (
	"os"
	"syscall"
	"testing"
)

// econnresetAt fails the nth recvmsg call with ECONNRESET, once, without consuming a record. Other calls are real.
func econnresetAt(n int) recvFn {
	calls := 0
	return func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		calls++
		if calls == n {
			return 0, 0, 0, nil, syscall.ECONNRESET
		}
		return syscall.Recvmsg(fd, p, oob, flags)
	}
}

func econnresetOnce() recvFn { return econnresetAt(1) }

func TestR6ReproDrainStatusWithFdIsNotKnown(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	var pp [2]int
	if err := syscall.Pipe2(pp[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer closeBoth(pp[0], pp[1])
	if err := syscall.Sendmsg(wr, statusPayload(), syscall.UnixRights(pp[1]), nil, 0); err != nil {
		t.Fatal(err)
	}
	o := drain(rd, bufV61, true, &state{})
	if t2Known(o, os.Getpid()) {
		t.Fatalf("status with a descriptor classed Known (End=%s, records=%d)", o.End, len(o.Recs))
	}
}

func TestR6ReproDrainTruncatedStatusIsNotKnown(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	// A valid status padded with spaces past the 1024-byte data buffer: the JSON survives, MSG_TRUNC is set.
	payload := []byte(statusRec("exit", 0))
	for len(payload) < 1100 {
		payload = append(payload, ' ')
	}
	if err := syscall.Sendmsg(wr, payload, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	o := drain(rd, bufV61, true, &state{})
	if len(o.Recs) != 1 || o.Recs[0].flags&syscall.MSG_TRUNC == 0 {
		t.Fatalf("setup: want one record with MSG_TRUNC, got End=%s records=%d", o.End, len(o.Recs))
	}
	if t2Known(o, os.Getpid()) {
		t.Fatalf("truncated status classed Known (flags=%#x)", o.Recs[0].flags)
	}
}

func TestR6ReproObservationNotRestoredByLaterStatus(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	st := &state{}
	restore := armSeam(econnresetOnce(), nil, nil)
	o1 := drain(rd, bufV61, true, st)
	restore()
	if o1.End != "ERR" {
		t.Fatalf("setup: want observation error (End=ERR), got %s", o1.End)
	}
	o2 := drain(rd, bufV61, true, st)
	if t2Known(o2, os.Getpid()) {
		t.Fatalf("status read after an observation error classed Known (End=%s)", o2.End)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// TestR6ReproReadContinuesAfterObservation is the runCase form of bug 2. The first post-admission receive fails
// with ECONNRESET. R5 then breaks only the inner step loop and goes on to read the next step, so a later record is
// still classified. The channel must stop at the observation error. Each step is a new sender process, so the
// later status fails the creds gate here (CLOSE:creds); Known restoration is reproduced at drain level by
// TestR6ReproObservationNotRestoredByLaterStatus.
func TestR6ReproReadContinuesAfterObservation(t *testing.T) {
	sc := scenario{
		name:     "r6_repro_econnreset_then_status",
		passcred: true,
		buf:      bufV61,
		steps: [][]msg{
			{{Payload: initRec, Fds: []string{"pidfd_self"}}, {Payload: prodRec, Fds: []string{"pidfd_child"}}},
			{{Payload: statusRec("exit", 0)}},
			{{Payload: statusRec("exit", 0)}},
		},
	}
	restore := armSeam(econnresetAt(3), nil, nil)
	res := runCase(sc)
	restore()
	want := []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "OBSERVE:recv_error"}
	if !equal(res.Actual, want) {
		t.Fatalf("actual %v, want %v: no record may be classified after an observation error", res.Actual, want)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}
