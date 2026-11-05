//go:build integration

package main

// Regression for the final ExitStatus commit (R6 final; A52 (11)). CL0a is the commit point: the value it returns is
// stored and frozen, and no later status on the same handle changes it. Before this correction, a clean CL0a drain with
// no record returned UNKNOWN without storing it, and a later valid status made the value KNOWN. The subtests named
// cl0a_no_record_then_status_stays_unknown and final_known_is_frozen fail on that R6 behavior. The other subtests pin
// behavior that must not change: a provisional T2 value stays open for CL0a, and poison stays sticky.

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestR6FinalUnknownIsFrozen(t *testing.T) {
	pid := os.Getpid()

	t.Run("cl0a_no_record_then_status_stays_unknown", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "UNKNOWN" {
			t.Fatalf("T2 commit %s, want provisional UNKNOWN", got)
		}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "UNKNOWN" {
			t.Fatalf("CL0a commit %s, want final UNKNOWN", got)
		}
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "UNKNOWN" {
			t.Fatalf("status after the final commit: %s, want UNKNOWN", got)
		}
	})

	t.Run("t2_no_record_then_cl0a_status_is_known", func(t *testing.T) {
		// The T2 value is provisional and stores nothing, so a status read at CL0a still decides the value.
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "UNKNOWN" {
			t.Fatalf("T2 commit %s, want provisional UNKNOWN", got)
		}
		if st.exit != "" {
			t.Fatalf("provisional T2 value stored as %q, want nothing stored", st.exit)
		}
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "KNOWN" {
			t.Fatalf("CL0a commit %s, want KNOWN", got)
		}
	})

	t.Run("final_known_is_frozen", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		st := &state{}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, false); got != "KNOWN" {
			t.Fatalf("T2 commit %s, want provisional KNOWN", got)
		}
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "KNOWN" {
			t.Fatalf("CL0a commit %s, want final KNOWN", got)
		}
		// A second record after the commit point must not change the frozen value.
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "KNOWN" {
			t.Fatalf("after the final commit: %s, want frozen KNOWN", got)
		}
	})

	t.Run("protocol_violation_then_status_stays_unknown", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		st := &state{}
		o := poisonDrain(drainOut{}, st, "OVERFLOW_RECORD", fmt.Errorf("%w: record cap", ErrProtocolViolation))
		if got := commitExit(st, o, pid, false); got != "UNKNOWN" {
			t.Fatalf("T2 commit %s, want UNKNOWN", got)
		}
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "UNKNOWN" {
			t.Fatalf("CL0a commit %s, want UNKNOWN after protocol violation", got)
		}
	})

	t.Run("observation_error_then_status_stays_unknown", func(t *testing.T) {
		rd, wr := sockpairCreds(t, true)
		defer closeBoth(rd, wr)
		st := &state{}
		restore := armSeam(errRecv(), nil, nil)
		o := drain(rd, bufV61, true, st)
		restore()
		if got := commitExit(st, o, pid, false); got != "UNKNOWN" {
			t.Fatalf("T2 commit %s, want UNKNOWN", got)
		}
		must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
		if got := commitExit(st, drain(rd, bufV61, true, st), pid, true); got != "UNKNOWN" {
			t.Fatalf("CL0a commit %s, want UNKNOWN after observation error", got)
		}
		if seamsArmed != 0 {
			t.Fatalf("seams still armed: %d", seamsArmed)
		}
	})
}
