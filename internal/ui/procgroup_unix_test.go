//go:build unix

package ui

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestKillGroupNilProcess(t *testing.T) {
	if err := killGroup(exec.Command("true")); err != nil {
		t.Fatalf("nil Process: %v", err)
	}
}

func TestKillGroupReapedLeaderFallsBack(t *testing.T) {
	cmd := exec.Command("true")
	setProcGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	// Leader reaped, so Getpgid fails; the fallback Process.Kill on a waited
	// process reports ErrProcessDone rather than signalling a stale pgid.
	if err := killGroup(cmd); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("want ErrProcessDone from fallback, got %v", err)
	}
}

// The exit path has to reach a tool's descendants, not just the process we
// spawned: mtr leaves an mtr-packet behind, and it would outlive netdoc.
func TestCleanupKillsGrandchild(t *testing.T) {
	var m model
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.cur.active = startHelper(t, m.ctx, "grandchild")
	pid := grandchildPID(t, m.cur.active.ch)

	Cleanup(m)

	// The grandchild is reparented to init once the leader dies, so it is gone
	// a moment after the signal rather than the instant Cleanup returns.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if exited(pid) {
			return
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL) // don't leak it into the next test
			t.Fatalf("grandchild %d survived Cleanup", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// exited reports whether pid has exited. Once its reaper collects it the pid is gone. Until then it
// is a zombie: it cannot run and holds nothing but its pid, so it has exited too. Init normally reaps
// orphans at once, but a sandbox whose PID 1 never calls wait leaves the zombie, and kill(pid, 0)
// still succeeds on one.
func exited(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false // no procfs here (macOS): only a reaped pid reads as gone
	}
	// The state follows the command name, which is in parentheses and may hold spaces or parentheses.
	i := bytes.LastIndexByte(stat, ')')
	return i >= 0 && i+2 < len(stat) && stat[i+2] == 'Z'
}

// Negative control: a live descendant is not exited, and a child that exited but was not waited for
// is. The first half keeps the cleanup assertion honest: a grandchild that survives reads as running.
func TestExitedTellsALiveDescendantFromAZombie(t *testing.T) {
	live := exec.Command("sleep", "30")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = live.Process.Kill()
		_ = live.Wait()
	}()
	if exited(live.Process.Pid) {
		t.Fatal("a live descendant reads as exited, so a surviving grandchild would pass Cleanup")
	}
	if runtime.GOOS != "linux" {
		t.Skip("a zombie is read from procfs, which only Linux has here")
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for !exited(cmd.Process.Pid) {
		if time.Now().After(deadline) {
			t.Fatal("a child that exited was never read as exited")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
