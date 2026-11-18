//go:build unix

package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
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

// installStandIn makes the batch ssh a stand-in that starts a descendant appending a heartbeat
// every 50 ms, then stalls. It returns the heartbeat file. The stand-in records its pids, so a
// failing test still kills them.
func installStandIn(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	beat := filepath.Join(dir, "beat")
	subPID := filepath.Join(dir, "sub.pid")
	stallPID := filepath.Join(dir, "stall.pid")
	script := filepath.Join(dir, "ssh")
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
	return beat
}

// requireStopped checks that the descendant was beating when the run returned, and that it
// stopped then. The heartbeat is every 50 ms, so a live descendant adds several lines in the
// window; a stopped one adds none.
func requireStopped(t *testing.T, beat string) {
	t.Helper()
	before := heartbeats(beat)
	if before == 0 {
		t.Fatal("the descendant never beat, so the test proves nothing")
	}
	time.Sleep(500 * time.Millisecond)
	if after := heartbeats(beat); after != before {
		t.Fatalf("a process started by the batch ssh kept running after the run returned: %d more heartbeats", after-before)
	}
}

// A cancelled batch run must not leave the processes its ssh started running. The run is
// cancelled once the descendant is beating. Killing only the stand-in would leave the
// descendant beating; killing its process group stops it.
func TestCancelledBatchRunKillsItsDescendants(t *testing.T) {
	beat := installStandIn(t)
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
	requireStopped(t, beat)
}

// A batch run whose request write fails kills its processes too. The write is failed through
// the writeRequest seam, so the run takes the write-failure path: it waits for a response that
// never comes, then stops ssh. The descendant must be beating when the run returns, and stopped
// after it.
func TestWriteFailureKillsBatchDescendants(t *testing.T) {
	beat := installStandIn(t)
	savedWrite := writeRequest
	writeRequest = func(io.Writer, []byte) (int, error) { return 0, errors.New("broken pipe") }
	t.Cleanup(func() { writeRequest = savedWrite })

	_, err := RunBatch(context.Background(), "lab", "", Request{TimeoutMs: 20000})
	if err == nil {
		t.Fatal("a run whose request write failed returned no error")
	}
	requireStopped(t, beat)
}
