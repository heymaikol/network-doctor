//go:build integration

package main

// Deterministic R6 final tests (contract 3.2, 3.4, 6.3, 6.4). The receive-call ceiling is an observation error, not a
// protocol violation. ExitStatus is committed once across T2 and CL0a. pollRaw waits on a real socket pair. Seams are
// used only where a specific kernel return is needed, and each one is restored.

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// errRecv returns EIO on every call: an observation error from recvmsg (A40).
func errRecv() recvFn {
	return func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		return 0, 0, 0, nil, syscall.EIO
	}
}

func TestR6CallCeilingIsObservation(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(eagainRecv(1000), pollAlwaysReadable, nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kErr || err == nil {
		t.Fatalf("kind %v err %v, want kErr with an error", kind, err)
	}
	st := &state{stage: 2}
	observe(st, kind, err)
	if !errors.Is(st.poison, ErrObservation) {
		t.Fatalf("call ceiling poisoned with %v, want ErrObservation", st.poison)
	}
	if errors.Is(st.poison, ErrProtocolViolation) {
		t.Fatal("call ceiling must not wrap ErrProtocolViolation")
	}
	ninth := &state{stage: 2}
	observe(ninth, kErr, errBudget)
	if !errors.Is(ninth.poison, ErrProtocolViolation) {
		t.Fatalf("ninth EINTR poisoned with %v, want ErrProtocolViolation", ninth.poison)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

func TestR6PollRawOnSocketPair(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if rev, err := pollRaw(rd, 1); err != nil || rev != 0 {
		t.Fatalf("idle: revents %#x err %v, want 0 and no error", rev, err)
	}
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	if rev, err := pollRaw(rd, 1000); err != nil || rev&pollIn == 0 {
		t.Fatalf("readable: revents %#x err %v, want POLLIN", rev, err)
	}
	// A closed descriptor reports POLLNVAL in revents, not as an error.
	a, b := sockpairCreds(t, true)
	defer closeBoth(b)
	must(syscall.Close(a))
	if rev, err := pollRaw(a, 0); err != nil || rev&pollNval == 0 {
		t.Fatalf("closed: revents %#x err %v, want POLLNVAL", rev, err)
	}
}

// TestR6FinalExitCommit checks the commit points of ExitStatus: T2 gives a provisional value, and CL0a gives the final
// one. Each subtest runs on one handle, drain by drain, as T2 and CL0a do.
func TestR6FinalExitCommit(t *testing.T) {
	pid := os.Getpid()

	t.Run("clean_cl0a_keeps_known", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "KNOWN" {
			t.Fatalf("T2 commit %s, want KNOWN", got)
		}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "KNOWN" {
			t.Fatalf("CL0a commit %s, want KNOWN", got)
		}
	})

	t.Run("observation_error_at_cl0a_is_final_unknown", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "KNOWN" {
			t.Fatalf("T2 commit %s, want provisional KNOWN", got)
		}
		restore := armSeam(errRecv(), nil, nil)
		o := drain(rd, bufV61, true, st)
		restore()
		if o.End != "ERR" || !errors.Is(st.poison, ErrObservation) {
			t.Fatalf("CL0a End %q poison %v, want ERR and ErrObservation", o.End, st.poison)
		}
		if got := commitExit(st, o, pid, true); got != "UNKNOWN" {
			t.Fatalf("CL0a commit %s, want final UNKNOWN", got)
		}
		// Sticky: a later drain reads nothing, makes no receive call, and the value stays UNKNOWN.
		later := drain(rd, bufV61, true, st)
		if later.End != "POISONED" || later.Calls != 0 || commitExit(st, later, pid, true) != "UNKNOWN" {
			t.Fatalf("later drain End %q calls %d, want POISONED with zero calls and UNKNOWN", later.End, later.Calls)
		}
		if seamsArmed != 0 {
			t.Fatalf("seams still armed: %d", seamsArmed)
		}
	})

	t.Run("second_record_at_cl0a_is_unknown", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "KNOWN" {
			t.Fatalf("T2 commit %s, want provisional KNOWN", got)
		}
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "UNKNOWN" {
			t.Fatalf("CL0a commit %s, want UNKNOWN (two records)", got)
		}
	})

	t.Run("poisoned_handle_is_never_known", func(t *testing.T) {
		// A valid status on a poisoned handle is UNKNOWN: commitExit reads st.poison, not only the drain result.
		r := recvd{data: statusPayload(), n: len(statusPayload()), creds: &syscall.Ucred{Pid: int32(pid)}}
		st := &state{poison: ErrObservation}
		o := drainOut{Recs: []recvd{r}, End: "EAGAIN"}
		if got := commitExit(st, o, pid, true); got != "UNKNOWN" {
			t.Fatalf("poisoned handle commit %s, want UNKNOWN", got)
		}
	})
}
