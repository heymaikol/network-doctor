package supervisor

import (
	"errors"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// chanRecvLabel names the close reason of an admission receive that ended the channel.
func chanRecvLabel(k chanKind, err error) string {
	switch {
	case k == chanEOF:
		return "CLOSE:eof"
	case errors.Is(err, errChanDeadline):
		return "CLOSE:timeout"
	case errors.Is(err, errChanBudget), errors.Is(err, errChanCallBound):
		return "CLOSE:budget"
	}
	return "CLOSE:recv_error"
}

// seamCalls counts the system calls a seamEnd makes.
type seamCalls struct{ recvs, polls int }

// errSeamPoll is the poll error past the receive call ceiling. A correct receive never polls after the 17th recvmsg.
var errSeamPoll = errors.New("seam: poll past the receive call ceiling")

// seamEnd returns a channel end with scripted system calls and no kernel access. Each recvmsg takes the next step: an
// errno, or nil for one record of one byte. Every poll reports readable, and poll 18 fails with errSeamPoll.
func seamEnd(t *testing.T, steps ...error) (chanEnd, *seamCalls) {
	t.Helper()
	c := &seamCalls{}
	sys := chanSys{
		recvmsg: func(int, []byte, []byte, int) (int, int, int, error) {
			if c.recvs == len(steps) {
				t.Fatalf("recvmsg call %d, script has %d steps", c.recvs+1, len(steps))
			}
			step := steps[c.recvs]
			c.recvs++
			if step != nil {
				return 0, 0, 0, step
			}
			return 1, 0, 0, nil
		},
		poll: func(int, int) (int16, error) {
			c.polls++
			if c.polls > 17 {
				return 0, errSeamPoll
			}
			return unix.POLLIN, nil
		},
	}
	return chanEnd{sys: sys}, c
}

// TestRecvOneCallCeiling pins the admission receive budgets (contract 3.4): at most 17 recvmsg calls, EAGAIN included,
// and at most 8 EINTR returns. The ceiling is checked before the readiness wait, so no poll follows the 17th call.
func TestRecvOneCallCeiling(t *testing.T) {
	far := time.Now().Add(time.Hour)
	eagain := func(n int) []error { return slices.Repeat([]error{unix.EAGAIN}, n) }
	eintr := func(n int) []error { return slices.Repeat([]error{unix.EINTR}, n) }
	cases := []struct {
		name      string
		steps     []error
		kind      chanKind
		wantErr   error
		sentinel  error
		wantLabel string
		recvs     int
		polls     int
	}{
		{"17_eagain_hits_ceiling", eagain(17), chanErr, errChanCallBound, ErrObservation, "CLOSE:budget", 17, 17},
		{"16_eagain_then_record_on_call_17", append(eagain(16), nil), chanRecord, nil, nil, "", 17, 17},
		{"8_eintr_then_9_eagain_hits_ceiling", append(eintr(8), eagain(9)...), chanErr, errChanCallBound, ErrObservation, "CLOSE:budget", 17, 17},
		{"9_eintr_hits_eintr_budget", eintr(9), chanErr, errChanBudget, ErrProtocolViolation, "CLOSE:budget", 9, 9},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			end, calls := seamEnd(t, c.steps...)
			k, r, err := end.recvOne(far)
			if k != c.kind {
				t.Fatalf("kind %d, want %d (err %v)", k, c.kind, err)
			}
			if c.wantErr == nil && err != nil || c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("err %v, want %v", err, c.wantErr)
			}
			if c.sentinel != nil && !errors.Is(err, c.sentinel) {
				t.Fatalf("err %v does not wrap %v", err, c.sentinel)
			}
			if c.wantLabel != "" {
				if got := chanRecvLabel(k, err); got != c.wantLabel {
					t.Fatalf("label %s, want %s", got, c.wantLabel)
				}
			}
			if k == chanRecord && r.n != 1 {
				t.Fatalf("record length %d, want 1", r.n)
			}
			if calls.recvs != c.recvs || calls.polls != c.polls {
				t.Fatalf("recvmsg %d polls %d, want recvmsg %d polls %d", calls.recvs, calls.polls, c.recvs, c.polls)
			}
		})
	}
}
