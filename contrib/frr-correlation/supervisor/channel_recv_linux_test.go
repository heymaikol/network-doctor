package supervisor

import (
	"encoding/binary"
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

// seamLen converts a small non-negative length to the native size_t word.
func seamLen(n int) uint64 {
	return uint64(n) //nolint:gosec // G115: test lengths are small and non-negative
}

// seamCmsg returns one control message. The length word is written as given, so a test can make it disagree with the
// body. The message is padded to the next size_t boundary, as the kernel pads it.
func seamCmsg(length uint64, lvl, typ int, body []byte) []byte {
	buf := make([]byte, unix.CmsgLen(0)+len(body))
	if unix.SizeofPtr == 8 {
		binary.NativeEndian.PutUint64(buf, length)
	} else {
		binary.NativeEndian.PutUint32(buf, uint32(length)) //nolint:gosec // G115: a 32-bit size_t keeps its low word
	}
	binary.NativeEndian.PutUint32(buf[unix.SizeofPtr:], uint32(lvl))   //nolint:gosec // G115: SOL_SOCKET and SCM_* are small constants
	binary.NativeEndian.PutUint32(buf[unix.SizeofPtr+4:], uint32(typ)) //nolint:gosec // G115: SOL_SOCKET and SCM_* are small constants
	copy(buf[unix.CmsgLen(0):], body)
	for len(buf)%unix.SizeofPtr != 0 {
		buf = append(buf, 0)
	}
	return buf
}

// TestWalkChanCmsgs pins the cmsg walk on malformed control buffers (contract 3.4, A8). The walk stops at a header it
// cannot trust and keeps the descriptors of the complete messages before it. The descriptor numbers are synthetic, and
// the walk never closes them. The padding case relies on a 64-bit size_t, where the last message ends at a boundary.
func TestWalkChanCmsgs(t *testing.T) {
	word32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.NativeEndian.PutUint32(b, v)
		return b
	}
	// partial is a rights message whose length covers one descriptor and two stray bytes.
	partial := func() []byte {
		body := append(word32(7), 0xaa, 0xbb)
		return seamCmsg(seamLen(unix.CmsgLen(6)), unix.SOL_SOCKET, unix.SCM_RIGHTS, body)
	}
	// short is a credentials message whose body is n bytes. The walk accepts credentials only from 12 bytes.
	short := func(n int) []byte {
		body := make([]byte, n)
		binary.NativeEndian.PutUint32(body, 42)
		return seamCmsg(seamLen(unix.CmsgLen(n)), unix.SOL_SOCKET, unix.SCM_CREDENTIALS, body)
	}
	cases := []struct {
		name    string
		oob     []byte
		fds     []int
		wantPid int32 // zero means no credentials
	}{
		{"empty", nil, nil, 0},
		{"shorter_than_a_header", []byte{1, 2, 3}, nil, 0},
		{"length_zero", seamCmsg(0, unix.SOL_SOCKET, unix.SCM_RIGHTS, nil), nil, 0},
		{"length_past_end_keeps_earlier_fds", append(unix.UnixRights(7), seamCmsg(1<<20, unix.SOL_SOCKET, unix.SCM_RIGHTS, nil)...), []int{7}, 0},
		{"length_wraps_negative_keeps_earlier_fds", append(unix.UnixRights(7), seamCmsg(^uint64(0), unix.SOL_SOCKET, unix.SCM_RIGHTS, nil)...), []int{7}, 0},
		{"partial_descriptor_is_ignored", partial(), []int{7}, 0},
		{"credentials_body_8_bytes_is_not_accepted", short(8), nil, 0},
		{"credentials_body_11_bytes_is_not_accepted", short(11), nil, 0},
		{"credentials_body_12_bytes_is_accepted", unix.UnixCredentials(&unix.Ucred{Pid: 42, Uid: 1000, Gid: 1000}), nil, 42},
		{"rights_then_truncated_header_keeps_fds", append(unix.UnixRights(7, 8), 1, 2, 3, 4), []int{7, 8}, 0},
		{"three_descriptors", unix.UnixRights(7, 8, 9), []int{7, 8, 9}, 0},
		{"last_message_padding_past_end_keeps_its_fd", seamCmsg(seamLen(unix.CmsgLen(4)), unix.SOL_SOCKET, unix.SCM_RIGHTS, word32(7))[:unix.CmsgLen(4)], []int{7}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fds, creds := walkChanCmsgs(c.oob)
			if !slices.Equal(fds, c.fds) {
				t.Fatalf("fds %v, want %v", fds, c.fds)
			}
			if (creds != nil) != (c.wantPid != 0) {
				t.Fatalf("credentials %v, want pid %d or none", creds, c.wantPid)
			}
			if creds != nil && creds.Pid != c.wantPid {
				t.Fatalf("pid %d, want %d", creds.Pid, c.wantPid)
			}
		})
	}
}
