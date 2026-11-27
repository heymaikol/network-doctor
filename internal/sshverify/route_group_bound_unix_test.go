//go:build unix

package sshverify

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// groupGoneCeiling is the longest a read may hold its process group, in the wait after a kill. It is
// twice the bound in use, so a bound that grows past twice its size fails, while a few hundred
// milliseconds of load noise does not.
const groupGoneCeiling = 2 * time.Second

// The bound is a promise to the caller: a read never holds its group past it. The tests below do not
// depend on how the operating system reaps orphans, or on the scheduler's exact timing. The member the
// wait sees is a live sleep in its own group, so the group cannot empty while the wait runs, and the
// wait must end at its bound and leave the member running.

// TestGroupGoneBoundStaysWithinItsCeiling pins the constant. A change to the bound fails here first.
func TestGroupGoneBoundStaysWithinItsCeiling(t *testing.T) {
	if groupGoneBound > groupGoneCeiling {
		t.Fatalf("groupGoneBound is %v; a read may hold its process group for at most %v", groupGoneBound, groupGoneCeiling)
	}
}

// TestGroupWaitEndsAtItsBoundWhileAMemberRuns times the wait itself. It fails if the wait takes longer
// than the ceiling, even when the constant still reads as one second.
func TestGroupWaitEndsAtItsBoundWhileAMemberRuns(t *testing.T) {
	sleep := exec.Command("sleep", "30")
	sleep.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := sleep.Start(); err != nil {
		t.Skipf("no sleep to start: %v", err)
	}
	pid := sleep.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = sleep.Wait()
	})
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		waitGroupGone(pid, groupGoneBound)
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		if elapsed > groupGoneCeiling {
			t.Fatalf("the group wait held a live group for %v, past the %v ceiling", elapsed, groupGoneCeiling)
		}
		if syscall.Kill(pid, 0) != nil {
			t.Fatalf("the group wait ended the member it was waiting on; it may only return")
		}
	case <-time.After(3 * groupGoneCeiling):
		t.Fatalf("the group wait did not return within %v", 3*groupGoneCeiling)
	}
}
