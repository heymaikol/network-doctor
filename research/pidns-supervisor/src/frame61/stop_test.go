//go:build integration

package main

// Scratch regression tests for runCase stopping (issue 390). Test only; identical in every harness copy.
//
// The sender seam (launchFn) writes each step's messages to the child socket in process. No child process
// starts. The receive seam (recvmsgFn, via armSeam) scripts the error or EINTR at each recvmsg call. Every
// datagram that the script does not consume stays queued. Each queued datagram after an error is a valid
// exit status with no descriptors, so a path that keeps reading decides KNOWN and the test sees it.
//
// Oracles are literal wire strings and literal decision labels from the contract (3.2, 3.4, A40) and from the
// stop rule under test. No harness fixture (statusRec, initRec) is used.

import (
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

type stpHarness struct {
	launches  int
	recvCalls int
	script    string // one byte per recvmsg call: R real, E EINTR, A EAGAIN, X EBADF; past the end: R
}

// launch replaces cmd.Start. It sends the step's messages on the child socket in order and starts nothing.
func (h *stpHarness) launch(c *exec.Cmd) error {
	h.launches++
	var raw string
	for _, kv := range c.Env {
		if strings.HasPrefix(kv, "FRAME61_MSGS=") {
			raw = strings.TrimPrefix(kv, "FRAME61_MSGS=")
		}
	}
	var step []msg
	if err := json.Unmarshal([]byte(raw), &step); err != nil {
		return err
	}
	sock := int(c.ExtraFiles[0].Fd()) // the child socket dup that runCase passes as fd 3
	for _, m := range step {
		var fds, locals []int
		for range m.Fds {
			var p [2]int
			if err := syscall.Pipe2(p[:], syscall.O_CLOEXEC); err != nil {
				return err
			}
			fds = append(fds, p[0])
			locals = append(locals, p[0], p[1])
		}
		var oob []byte
		if len(fds) > 0 {
			oob = syscall.UnixRights(fds...)
		}
		err := syscall.Sendmsg(sock, []byte(m.Payload), oob, nil, 0)
		for _, f := range locals {
			_ = syscall.Close(f)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// recv is the scripted recvmsg seam. Only the scripted calls differ from the kernel.
func (h *stpHarness) recv(fd int, p, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
	h.recvCalls++
	step := byte('R')
	if h.recvCalls <= len(h.script) {
		step = h.script[h.recvCalls-1]
	}
	switch step {
	case 'E':
		return -1, 0, 0, nil, syscall.EINTR
	case 'A':
		return -1, 0, 0, nil, syscall.EAGAIN
	case 'X':
		return -1, 0, 0, nil, syscall.EBADF
	case 'Z':
		return 0, 0, 0, nil, nil
	}
	return syscall.Recvmsg(fd, p, oob, flags)
}

// ident is the pidfd_info seam. Pid and Ppid are this test process, the sender of every record.
func (h *stpHarness) ident(fd int) (pidfdInfo, error) {
	pid := uint32(syscall.Getpid())
	return pidfdInfo{Mask: 3, Pid: pid, Tgid: pid, Ppid: pid}, nil
}

func stpInit() msg { return msg{Payload: `{"v":1,"type":"init"}`, Fds: []string{"pidfd_self"}} }
func stpProducer() msg {
	return msg{Payload: `{"v":1,"type":"producer"}`, Fds: []string{"pidfd_child"}}
}
func stpStatus() msg { return msg{Payload: `{"v":1,"type":"status","kind":"exit","value":0}`} }

type stpCase struct {
	name         string
	steps        [][]msg
	script       string
	want         []string // exact decision sequence (only when not probe)
	wantLaunches int
	wantCalls    int
	errAt        int  // index in want of the first error label; -1 when none
	probe        bool // gap probe: assert only the no-accept property after errAt; log the rest
}

const (
	stpLabelRecv   = "OBSERVE:recv_error"
	stpLabelBudget = "OBSERVE:budget"
)

var stpCases = []stpCase{
	{
		name:         "control_one_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus()}},
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"},
		wantLaunches: 1, wantCalls: 3, errAt: -1,
	},
	{
		name:         "control_two_steps",
		steps:        [][]msg{{stpInit(), stpProducer()}, {stpStatus()}},
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "KNOWN"},
		wantLaunches: 2, wantCalls: 3, errAt: -1,
	},
	{
		// Inner stop only: the error ends step 0. The queued status in the same step is never read.
		name:         "observation_error_same_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus(), stpStatus()}},
		script:       "RRX",
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", stpLabelRecv},
		wantLaunches: 1, wantCalls: 3, errAt: 2,
	},
	{
		// Inner and outer stop: the error ends step 0. Step 1 must not start, and its status is never read.
		name:         "observation_error_later_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus(), stpStatus()}, {stpStatus()}},
		script:       "RRX",
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", stpLabelRecv},
		wantLaunches: 1, wantCalls: 3, errAt: 2,
	},
	{
		// Protocol violation: nine EINTR returns make errBudget, which poisons with ErrProtocolViolation.
		name:         "protocol_violation_later_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus(), stpStatus()}, {stpStatus()}},
		script:       "RR" + strings.Repeat("E", 9),
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", stpLabelBudget},
		wantLaunches: 1, wantCalls: 11, errAt: 2,
	},
	{
		// Call ceiling: seventeen EAGAIN returns for one receive make errCallBound (the ceiling is per receive). Label is "budget" in recvLabel.
		name:         "call_ceiling_later_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus(), stpStatus()}, {stpStatus()}},
		script:       "RR" + strings.Repeat("A", 17),
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", stpLabelBudget},
		wantLaunches: 1, wantCalls: 19, errAt: 2,
	},
	{
		name:         "eof_later_step",
		steps:        [][]msg{{stpInit(), stpProducer(), stpStatus(), stpStatus()}, {stpStatus()}},
		script:       "RRZ",
		want:         []string{"ACCEPT_INIT", "ACCEPT_PRODUCER", "EOF"},
		wantLaunches: 1, wantCalls: 3, errAt: 2,
	},
	{
		// Gap probe, not a contract row. A CLOSE at admission does not stop later steps in runCase. Assert only
		// that nothing after the CLOSE is accepted or Known. Log the launch count for the report.
		name:         "close_then_later_step_probe",
		steps:        [][]msg{{stpStatus()}, {stpInit(), stpProducer(), stpStatus()}},
		wantLaunches: 2, wantCalls: 4, errAt: 0, probe: true,
	},
}

func stpSame(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stpRun(t *testing.T, c stpCase) {
	h := &stpHarness{script: c.script}
	prevLaunch, prevSelf := launchFn, self
	launchFn, self = h.launch, "stp-fake-sender-not-executed"
	defer func() { launchFn, self = prevLaunch, prevSelf }()
	restore := armSeam(h.recv, nil, h.ident)
	defer restore()

	res := runCase(scenario{name: c.name, passcred: true, buf: 64, steps: c.steps, expect: c.want})

	if c.probe {
		t.Logf("probe: launches=%d recvmsg=%d decisions=%q", h.launches, h.recvCalls, res.Actual)
	} else {
		if h.launches != c.wantLaunches {
			t.Errorf("senders launched %d, want %d", h.launches, c.wantLaunches)
		}
		if h.recvCalls != c.wantCalls {
			t.Errorf("recvmsg calls %d, want %d", h.recvCalls, c.wantCalls)
		}
		if !stpSame(res.Actual, c.want) {
			t.Errorf("decisions %q, want %q", res.Actual, c.want)
		}
	}
	if c.errAt >= 0 && len(res.Actual) > c.errAt {
		for _, a := range res.Actual[c.errAt+1:] {
			if a == "KNOWN" || strings.HasPrefix(a, "ACCEPT_") {
				t.Errorf("decision %q after the error at index %d", a, c.errAt)
			}
		}
	}
	if res.FdAfter != res.FdBefore {
		t.Errorf("descriptors before %d after %d", res.FdBefore, res.FdAfter)
	}
}

func TestStopRunCase(t *testing.T) {
	for _, c := range stpCases {
		t.Run(c.name, func(t *testing.T) { stpRun(t, c) })
	}
}
