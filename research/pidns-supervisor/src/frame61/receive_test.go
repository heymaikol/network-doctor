package main

// Receive-path tests for R5 (contract 3.2, A40, A50). Real SOCK_SEQPACKET pairs; seams only where a test needs
// a specific kernel return. Each test restores every seam it arms, and checks seamsArmed == 0 at the end.

import (
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func sockpairCreds(t *testing.T, creds bool) (rd, wr int) {
	t.Helper()
	p, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if creds {
		if err := syscall.SetsockoptInt(p[0], syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1); err != nil {
			t.Fatal(err)
		}
	}
	return p[0], p[1]
}

func closeBoth(fds ...int) {
	for _, f := range fds {
		_ = syscall.Close(f)
	}
}

// eintrRecv returns EINTR for the first k calls, then calls the real recvmsg.
func eintrRecv(k int) recvFn {
	n := 0
	return func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		if n < k {
			n++
			return 0, 0, 0, nil, syscall.EINTR
		}
		return syscall.Recvmsg(fd, p, oob, flags)
	}
}

// eagainRecv returns EAGAIN for the first k calls, then calls the real recvmsg.
func eagainRecv(k int) recvFn {
	n := 0
	return func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		if n < k {
			n++
			return 0, 0, 0, nil, syscall.EAGAIN
		}
		return syscall.Recvmsg(fd, p, oob, flags)
	}
}

// pollEINTR returns EINTR for the first k polls, then calls the real poll.
func pollEINTR(k int) func(int, int) (int16, error) {
	n := 0
	return func(fd, ms int) (int16, error) {
		if n < k {
			n++
			return 0, syscall.EINTR
		}
		return pollRaw(fd, ms)
	}
}

func pollAlwaysReadable(fd, ms int) (int16, error) { return pollIn, nil }

func pollEINTRForever(fd, ms int) (int16, error) { return 0, syscall.EINTR }

func pollNvalSeam(fd, ms int) (int16, error) { return pollNval, nil }

func statusPayload() []byte { return []byte(statusRec("exit", 0)) }

func TestRecvNBNeverBlocks(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	start := time.Now()
	k, _, err := recvNB(rd, bufV61, true)
	if k != kAgain || err != syscall.EAGAIN {
		t.Fatalf("empty socket: kind %v err %v, want kAgain EAGAIN", k, err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("MSG_DONTWAIT receive took %v", el)
	}
}

func TestReceiveDeadlineIsBounded(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	var c counters
	start := time.Now()
	k, _, err := receiveOne(rd, bufV61, true, time.Now().Add(80*time.Millisecond), &c)
	if k != kErr || err != errDeadline {
		t.Fatalf("kind %v err %v, want kErr errDeadline", k, err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("deadline overrun %v", el)
	}
}

func TestRecvEINTRBudget(t *testing.T) {
	for k := 0; k <= maxEINTR+1; k++ {
		rd, wr := sockpairCreds(t, true)
		if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		restore := armSeam(eintrRecv(k), nil, nil)
		var c counters
		kind, r, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
		restore()
		if k <= maxEINTR {
			if kind != kRecord || err != nil {
				t.Fatalf("k=%d: kind %v err %v, want record", k, kind, err)
			}
			if c.RecvEINTR != k {
				t.Fatalf("k=%d: RecvEINTR %d", k, c.RecvEINTR)
			}
			if string(r.data) != statusRec("exit", 0) {
				t.Fatalf("k=%d: payload %q", k, r.data)
			}
		} else {
			if kind != kErr || err != errBudget {
				t.Fatalf("k=%d: kind %v err %v, want errBudget", k, kind, err)
			}
		}
		closeBoth(rd, wr)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

func TestPollEINTRRetriedInsideDeadline(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	restore := armSeam(nil, pollEINTR(50), nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kRecord || err != nil {
		t.Fatalf("kind %v err %v, want record after poll EINTR", kind, err)
	}
	if c.PollEINTR != 50 || c.RecvEINTR != 0 {
		t.Fatalf("counters %+v, want PollEINTR 50 RecvEINTR 0", c)
	}
}

func TestPollEINTRForeverStopsAtDeadline(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(nil, pollEINTRForever, nil)
	var c counters
	start := time.Now()
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(80*time.Millisecond), &c)
	restore()
	if kind != kErr || err != errDeadline {
		t.Fatalf("kind %v err %v, want errDeadline", kind, err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("poll EINTR loop overran deadline: %v", el)
	}
	if c.PollEINTR == 0 {
		t.Fatalf("no poll EINTR counted")
	}
}

func TestPollInvalidDescriptorFailsClosed(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(nil, pollNvalSeam, nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kErr || err != errPollNval {
		t.Fatalf("kind %v err %v, want errPollNval", kind, err)
	}
}

func TestEAGAINAfterReadablePollRepolls(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	restore := armSeam(eagainRecv(3), nil, nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kRecord || err != nil {
		t.Fatalf("kind %v err %v, want record", kind, err)
	}
	if c.RecvAgain != 3 || c.RecvCalls != 4 {
		t.Fatalf("counters %+v, want RecvAgain 3 RecvCalls 4", c)
	}
}

func TestReceiveCallCapIsSeventeen(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(eagainRecv(1000), pollAlwaysReadable, nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kErr || err != errCallBound {
		t.Fatalf("kind %v err %v, want errCallBound", kind, err)
	}
	if c.RecvCalls != maxCalls {
		t.Fatalf("RecvCalls %d, want %d", c.RecvCalls, maxCalls)
	}
}

// Any recvmsg failure other than EAGAIN or EINTR is an observation error, never EOF (R5 decision 8).
func TestRecvErrorIsNeverEOF(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		return 0, 0, 0, nil, syscall.ECONNRESET
	}, pollAlwaysReadable, nil)
	var c counters
	kind, _, err := receiveOne(rd, bufV61, true, time.Now().Add(admissionDeadline), &c)
	restore()
	if kind != kErr || err != syscall.ECONNRESET {
		t.Fatalf("kind %v err %v, want kErr ECONNRESET", kind, err)
	}
	if got := recvLabel(kind, err, 2); got != "OBSERVE:recv_error" {
		t.Fatalf("post-admission label %q", got)
	}
	if got := recvLabel(kind, err, 0); got != "CLOSE:recv_error" {
		t.Fatalf("pre-admission label %q", got)
	}
	if got := recvLabel(kEOF, nil, 2); got != "EOF" {
		t.Fatalf("EOF label %q", got)
	}
}

func TestDrainEOFNeedsCreds(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd)
	_ = syscall.Close(wr)
	o := drain(rd, bufV61, true, &state{})
	if o.End != "EOF" || len(o.Recs) != 0 || o.Calls != 1 {
		t.Fatalf("closed peer with creds: %+v", o)
	}
}

// Without verified SO_PASSCRED a zero-length read is a record, never EOF. The drain then ends at the record cap
// (fail closed). Admission refuses this case before launch, so this shows the consequence only.
func TestDrainZeroLengthIsRecordWithoutCreds(t *testing.T) {
	rd, wr := sockpairCreds(t, false)
	defer closeBoth(rd)
	_ = syscall.Close(wr)
	o := drain(rd, bufV61, false, &state{})
	if o.End != "OVERFLOW_RECORD" || len(o.Recs) != maxRecords {
		t.Fatalf("no creds, closed peer: %+v", o)
	}
}

func TestDrainZeroLengthWithCreds(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd)
	if err := syscall.Sendmsg(wr, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	_ = syscall.Close(wr)
	o := drain(rd, bufV61, true, &state{})
	if o.End != "EOF" || len(o.Recs) != 1 || len(o.Recs[0].data) != 0 {
		t.Fatalf("zero-length then close: %+v", o)
	}
}

// Z4 shape: a valid status, then a zero-length record. Two records are counted and the result is not Known.
func TestDrainStatusThenZeroLengthIsNotKnown(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Sendmsg(wr, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	o := drain(rd, bufV61, true, &state{})
	if len(o.Recs) != 2 {
		t.Fatalf("records %d, want 2: %+v", len(o.Recs), o)
	}
	if len(o.Recs[1].data) != 0 {
		t.Fatalf("second record not zero-length")
	}
	if t2Known(o, os.Getpid()) {
		t.Fatalf("status then zero-length gave Known")
	}
}

// Z12: zero-length record with MSG_CTRUNC (creds do not fit a 24-byte control buffer) is a record, not EOF.
func TestDrainZeroLengthWithCtruncIsRecord(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	k, r, err := recvNB(rd, bufV6, true)
	if k != kRecord || err != nil {
		t.Fatalf("kind %v err %v, want record", k, err)
	}
	if r.flags&syscall.MSG_CTRUNC == 0 || r.n != 0 {
		t.Fatalf("flags %#x n %d, want CTRUNC and n 0", r.flags, r.n)
	}
}

// rawRecvZeroIov is SYS_RECVMSG with a zero-length iovec and no dummy byte. syscall.Recvmsg adds one dummy
// byte when the data buffer is empty and control is attached (syscall_linux.go recvmsgRaw), so it cannot
// express a true zero-byte read. Test use only, for Z8.
func rawRecvZeroIov(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
	var iov syscall.Iovec
	var msg syscall.Msghdr
	msg.Iov = &iov
	msg.Iovlen = 1
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	r, _, e := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), uintptr(flags))
	if e != 0 {
		return 0, 0, 0, nil, e
	}
	return int(r), int(msg.Controllen), int(msg.Flags), nil, nil
}

// Z8: a zero-byte data buffer on a 10-byte message sets MSG_TRUNC, n is 0, and the message is consumed.
func TestZeroByteBufferTruncIsRecordAndConsumes(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, []byte("0123456789"), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	restore := armSeam(rawRecvZeroIov, nil, nil)
	k, r, err := recvNBBuf(rd, []byte{}, bufV61, true)
	restore()
	if k != kRecord || err != nil {
		t.Fatalf("kind %v err %v, want record", k, err)
	}
	if r.flags&syscall.MSG_TRUNC == 0 || r.n != 0 {
		t.Fatalf("flags %#x n %d, want TRUNC and n 0", r.flags, r.n)
	}
	k2, _, _ := recvNB(rd, bufV61, true)
	if k2 != kAgain {
		t.Fatalf("message not consumed: next kind %v", k2)
	}
}

// Zero-length records count toward the eight-record cap. Eight zero-length records: the ninth overflows.
func TestRecordCapCountsZeroLength(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	for i := 0; i < maxRecords+1; i++ {
		if err := syscall.Sendmsg(wr, nil, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	o := drain(rd, bufV61, true, &state{})
	if o.End != "OVERFLOW_RECORD" || len(o.Recs) != maxRecords {
		t.Fatalf("nine zero-length: %+v", o)
	}
}

func TestRecordCapSevenStatusPlusZeroLength(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	for i := 0; i < maxRecords-1; i++ {
		if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Sendmsg(wr, nil, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	o := drain(rd, bufV61, true, &state{})
	if o.End != "EAGAIN" || len(o.Recs) != maxRecords {
		t.Fatalf("seven status plus zero-length: %+v", o)
	}
}

// Drain EINTR budget: eight EINTR then EAGAIN ends clean; the ninth EINTR overflows.
func TestDrainEINTRBudget(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(eintrRecv(maxEINTR), nil, nil)
	o := drain(rd, bufV61, true, &state{})
	restore()
	if o.End != "EAGAIN" || o.EINTR != maxEINTR || o.Calls != maxEINTR+1 {
		t.Fatalf("8 EINTR: %+v", o)
	}
	restore = armSeam(eintrRecv(maxEINTR+1), nil, nil)
	o = drain(rd, bufV61, true, &state{})
	restore()
	if o.End != "OVERFLOW_EINTR" || o.EINTR != maxEINTR || o.Calls != maxEINTR+1 {
		t.Fatalf("9 EINTR: %+v", o)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// Seventeen calls is the ceiling. Eight EINTR and eight records are sixteen non-terminal calls, so the
// seventeenth call is the last one allowed and must be terminal (EAGAIN here).
func TestDrainCallCeiling(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	for i := 0; i < maxRecords; i++ {
		if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	restore := armSeam(eintrRecv(maxEINTR), nil, nil)
	o := drain(rd, bufV61, true, &state{})
	restore()
	if o.End != "EAGAIN" || o.Calls != maxCalls || len(o.Recs) != maxRecords || o.EINTR != maxEINTR {
		t.Fatalf("ceiling: %+v", o)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// t2Known is the one-drain T2 rule: commitExit on a fresh handle whose poison is the drain's own error (R6-1).
// Production code calls commitExit with the handle. The drain sets st.poison to the same error it returns in o.Err,
// so this form cannot differ from the handle.
func t2Known(o drainOut, pidI int) bool {
	return commitExit(&state{poison: o.Err}, o, pidI, false) == "KNOWN"
}

func TestT2KnownOnlyForOneCleanStatus(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	if err := syscall.Sendmsg(wr, statusPayload(), nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	o := drain(rd, bufV61, true, &state{})
	if !t2Known(o, os.Getpid()) {
		t.Fatalf("one clean exit status not Known: %+v", o)
	}
}
