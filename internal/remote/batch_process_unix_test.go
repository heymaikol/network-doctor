//go:build unix

package remote

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// heartbeats counts the lines a descendant has appended to the file. A missing file counts
// as none.
func heartbeats(path string) int {
	b, _ := os.ReadFile(path) // #nosec G304 -- a file the test wrote in its own temporary directory
	return bytes.Count(b, []byte("\n"))
}

// A cancelled batch run must not leave the processes its ssh started running. The
// stand-in ssh starts a descendant that appends a heartbeat every 50 ms, then stalls. The
// run is cancelled once the descendant is beating. Killing only the stand-in would leave the
// descendant beating; killing its process group stops it.
func TestCancelledBatchRunKillsItsDescendants(t *testing.T) {
	dir := t.TempDir()
	beat := filepath.Join(dir, "beat")
	subPID := filepath.Join(dir, "sub.pid")
	stallPID := filepath.Join(dir, "stall.pid")
	script := filepath.Join(dir, "ssh")
	// The descendant and the stall record their pids, so a failing run can still kill them.
	body := "#!/bin/sh\n" +
		"( echo $$ > '" + subPID + "'; while :; do echo beat >> '" + beat + "'; sleep 0.05; done ) &\n" +
		"sleep 30 &\n" +
		"echo $! > '" + stallPID + "'\n" +
		"wait\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- an executable stand-in ssh the test writes for itself
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range []string{subPID, stallPID} {
			if b, err := os.ReadFile(f); err == nil { // #nosec G304 -- a pid file the test wrote in its own temporary directory
				if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	})
	savedProgram := sshProgram
	sshProgram = script
	t.Cleanup(func() { sshProgram = savedProgram })
	savedTerminal := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return true }
	t.Cleanup(func() { sshverify.TerminalAvailable = savedTerminal })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RunBatch(ctx, "lab", "", Request{TimeoutMs: 20000})
	}()

	deadline := time.Now().Add(10 * time.Second)
	for heartbeats(beat) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the descendant never started beating")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(cancelGrace + 10*time.Second):
		t.Fatal("the run did not return after it was cancelled")
	}

	// The descendant beats every 50 ms, so a live one adds several lines in this window.
	before := heartbeats(beat)
	time.Sleep(500 * time.Millisecond)
	if after := heartbeats(beat); after != before {
		t.Fatalf("a process started by the batch ssh kept running after the run was cancelled: %d more heartbeats", after-before)
	}
}
