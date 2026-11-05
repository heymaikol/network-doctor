//go:build integration

package main

// Per-receive and per-drain call budgets (R6 final; D control-flow review, item 2). Each budget applies to the operation
// it belongs to. receiveOne's ceiling restarts for every receive (3.4). drain's ceiling spans one whole drain, across
// records and EINTR returns (TestDrainCallCeiling in receive_test.go), and an EAGAIN ends a drain without a repoll.
// The per-receive ceiling of 17 is TestReceiveCallCapIsSeventeen in receive_test.go.

import (
	"syscall"
	"testing"
	"time"
)

// TestR6BudgetPerReceiveRestarts: each receive has its own 17 calls. Sixteen EAGAIN returns and then one datagram use
// all 17 calls and the datagram is accepted (the 17th call is allowed). The second receive starts at call 1 again, so
// its sixteen EAGAIN returns and its datagram also fit. A budget shared across receives would fail the second receive.
func TestR6BudgetPerReceiveRestarts(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	must(syscall.Sendmsg(wr, statusPayload(), nil, nil, 0))
	n := 0
	recv := func(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
		n++
		if (n-1)%maxCalls < maxCalls-1 {
			return 0, 0, 0, nil, syscall.EAGAIN
		}
		return syscall.Recvmsg(fd, p, oob, flags)
	}
	restore := armSeam(recv, pollAlwaysReadable, nil)
	var c counters
	deadline := time.Now().Add(admissionDeadline)
	for i := 1; i <= 2; i++ {
		kind, _, err := receiveOne(rd, bufV61, true, deadline, &c)
		if kind != kRecord || err != nil {
			restore()
			t.Fatalf("receive %d: kind %v err %v, want kRecord and no error", i, kind, err)
		}
	}
	restore()
	if c.RecvCalls != 2*maxCalls {
		t.Fatalf("RecvCalls %d, want %d", c.RecvCalls, 2*maxCalls)
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}

// TestR6BudgetDrainEndsOnFirstEAGAIN: a drain never repolls. One EAGAIN ends it at call 1, so the per-receive EAGAIN
// loop of receiveOne does not apply to drain, and EAGAIN does not consume the per-drain budget.
func TestR6BudgetDrainEndsOnFirstEAGAIN(t *testing.T) {
	rd, wr := sockpairCreds(t, true)
	defer closeBoth(rd, wr)
	restore := armSeam(eagainRecv(1000), nil, nil)
	o := drain(rd, bufV61, true, &state{})
	restore()
	if o.End != "EAGAIN" || o.Calls != 1 || o.Err != nil || len(o.Recs) != 0 {
		t.Fatalf("drain End %q calls %d err %v recs %d, want EAGAIN after one call", o.End, o.Calls, o.Err, len(o.Recs))
	}
	if seamsArmed != 0 {
		t.Fatalf("seams still armed: %d", seamsArmed)
	}
}
