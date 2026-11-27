//go:build unix

package sshverify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// D's ADV L1: a background child that a Match exec starts is in the group the ssh client leads, and
// the route read kills that group when the client exits. The read must not return while that child is
// still running. The check follows the verifier's rule that a zombie has exited, and it asks at the
// moment the read returns, with no wait, because the kill is delivered asynchronously.
//
// The script stands for the configuration read: readConfig runs the same client-kill code as the route
// read, and a shell is the rootless client. The child writes its pid, and readConfig must not return
// while that pid is still running.

// startsBackgroundChild is a client that backgrounds one child, records its pid in pidFile, and exits.
func startsBackgroundChild(pidFile string) string {
	return "sleep 37 </dev/null >/dev/null 2>&1 & echo $! > " + pidFile
}

// processIDs returns the process group and session of pid from procfs, or false where there is none.
func processIDs(pid int) (pgid, sid int, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- a process this test started
	if err != nil {
		return 0, 0, false
	}
	closing := strings.LastIndex(string(data), ")")
	fields := strings.Fields(string(data[closing+1:]))
	if closing < 0 || len(fields) < 4 {
		return 0, 0, false
	}
	pgid, _ = strconv.Atoi(fields[2])
	sid, _ = strconv.Atoi(fields[3])
	return pgid, sid, true
}

// readPID reads the pid the client wrote, which the client has written before it exits.
func readPID(t *testing.T, pidFile string) int {
	t.Helper()
	data, err := os.ReadFile(pidFile) // #nosec G304 -- a file this test wrote in its own directory
	if err != nil {
		t.Fatalf("the client did not record its child's pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("the recorded pid %q is not a pid", data)
	}
	return pid
}

// killIfRunning stops a child a test left behind, so a failing test does not leak a sleep.
func killIfRunning(pid int) {
	if !processEnded(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// TestRouteReadLeavesNoBackgroundChildRunning is L1. Each run is a fresh client and child. The read
// must not return while the child runs, in every run.
func TestRouteReadLeavesNoBackgroundChildRunning(t *testing.T) {
	const runs = 10
	for run := 1; run <= runs; run++ {
		pidFile := filepath.Join(t.TempDir(), "child.pid")
		_, _, err := readConfig(context.Background(), "/bin/sh", []string{"-c", startsBackgroundChild(pidFile)}, nil)
		if err != nil {
			t.Fatalf("run %d: the client read failed: %v", run, err)
		}
		pid := readPID(t, pidFile)
		if !processEnded(pid) {
			pgid, sid, _ := processIDs(pid)
			killIfRunning(pid)
			t.Fatalf("run %d: the read returned while its background child was still running: pid %d, pgid %d, sid %d", run, pid, pgid, sid)
		}
	}
}

// TestRouteReadEndsItsChildOnTimeoutAndCancellation keeps the cleanup bounded and complete on the two
// other ends of a read: its deadline, and a cancellation once the child is running.
func TestRouteReadEndsItsChildOnTimeoutAndCancellation(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "child.pid")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, _, err := readConfig(ctx, "/bin/sh", []string{"-c", startsBackgroundChild(pidFile) + "; sleep 30"}, nil)
		elapsed := time.Since(start)
		pid := readPID(t, pidFile)
		defer killIfRunning(pid)
		if err == nil {
			t.Fatal("a read that hit its deadline returned no error")
		}
		if elapsed > 5*time.Second {
			t.Fatalf("a read at its deadline took %v; the cleanup is not bounded", elapsed)
		}
		if !processEnded(pid) {
			t.Fatalf("the read at its deadline returned while its background child was still running: pid %d", pid)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "child.pid")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			for start := time.Now(); time.Since(start) < 5*time.Second; time.Sleep(5 * time.Millisecond) {
				if b, err := os.ReadFile(pidFile); err == nil && len(b) > 0 { // #nosec G304 -- a file this test wrote
					cancel()
					return
				}
			}
			cancel()
		}()
		start := time.Now()
		_, _, err := readConfig(ctx, "/bin/sh", []string{"-c", startsBackgroundChild(pidFile) + "; sleep 30"}, nil)
		elapsed := time.Since(start)
		pid := readPID(t, pidFile)
		defer killIfRunning(pid)
		if err == nil {
			t.Fatal("a cancelled read returned no error")
		}
		if elapsed > 5*time.Second {
			t.Fatalf("a cancelled read took %v; the cleanup is not bounded", elapsed)
		}
		if !processEnded(pid) {
			t.Fatalf("the cancelled read returned while its background child was still running: pid %d", pid)
		}
	})
}

// TestRouteReadLeavesASetsidChildAsTheDocumentedLimit pins the limit the docs state: a child that calls
// setsid leaves the client's group and session, and the read cannot reach it. The test asserts that the
// child is outside the group, so a change that starts killing it is noticed and reviewed.
func TestRouteReadLeavesASetsidChildAsTheDocumentedLimit(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("no setsid command on this host")
	}
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	// The child writes its own pid from inside the session it starts, so the recorded pid is the
	// process that escaped, not the setsid wrapper, which may fork and exit.
	script := "setsid sh -c 'echo $$ > " + pidFile + "; sleep 37' </dev/null >/dev/null 2>&1 & while [ ! -s " + pidFile + " ]; do :; done; true"
	_, _, err := readConfig(context.Background(), "/bin/sh", []string{"-c", script}, nil)
	if err != nil {
		t.Fatalf("the client read failed: %v", err)
	}
	pid := readPID(t, pidFile)
	defer killIfRunning(pid)
	pgid, sid, ok := processIDs(pid)
	if !ok {
		t.Skip("procfs is not available to show the child's session")
	}
	if processEnded(pid) {
		t.Fatalf("the documented limit no longer holds: the setsid child ended with the read (pid %d)", pid)
	}
	if sid != pid || pgid != pid {
		t.Fatalf("the setsid child is not its own session and group leader: pid %d, pgid %d, sid %d", pid, pgid, sid)
	}
}
