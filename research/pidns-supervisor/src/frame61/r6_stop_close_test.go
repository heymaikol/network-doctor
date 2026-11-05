package main

// Regression for CLOSE as the terminal decision of runCase (R6 final; D control-flow review, item 1). A CLOSE decision
// ends the channel: no later step is launched, no later receive is made, and no later record is decided. The probe
// case in stop_test.go only logs this; this test asserts it. It uses the seams of stop_test.go (stpHarness, launchFn,
// self) and armSeam from receive_test.go.

import "testing"

func TestR6CloseIsTerminalInRunCase(t *testing.T) {
	h := &stpHarness{}
	prevLaunch, prevSelf := launchFn, self
	launchFn, self = h.launch, "stp-fake-sender-not-executed"
	defer func() { launchFn, self = prevLaunch, prevSelf }()
	restore := armSeam(h.recv, nil, h.ident)
	defer restore()

	// Step 0 is a status before init: CLOSE:early_status. Step 1 is a valid admission that must never run.
	steps := [][]msg{{stpStatus()}, {stpInit(), stpProducer(), stpStatus()}}
	res := runCase(scenario{name: "close_terminal", passcred: true, buf: 64, steps: steps,
		expect: []string{"CLOSE:early_status"}})
	if h.launches != 1 {
		t.Fatalf("senders launched %d, want 1: CLOSE must stop later steps", h.launches)
	}
	if h.recvCalls != 1 {
		t.Fatalf("recvmsg calls %d, want 1: CLOSE must stop later receives", h.recvCalls)
	}
	if !stpSame(res.Actual, []string{"CLOSE:early_status"}) {
		t.Fatalf("decisions %q, want [CLOSE:early_status]", res.Actual)
	}
	if res.FdAfter != res.FdBefore {
		t.Fatalf("descriptors before %d after %d", res.FdBefore, res.FdAfter)
	}
}
