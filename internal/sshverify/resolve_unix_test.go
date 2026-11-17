//go:build unix

package sshverify

import (
	"context"
	"errors"
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

// fakeClient writes an executable stand-in for the ssh client. The script can
// record its own PID and a background child's PID in files, so a test can check
// that every process it started has ended.
func fakeClient(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil { // #nosec G306 -- the test writes an executable fake ssh client on purpose
		t.Fatal(err)
	}
	return path
}

// useFakeClient points the configuration read at client for one test.
func useFakeClient(t *testing.T, client string, timeout time.Duration) {
	t.Helper()
	savedBinary, savedTimeout, savedGrace := sshBinary, resolveTimeout, outputGrace
	sshBinary, resolveTimeout = client, timeout
	t.Cleanup(func() { sshBinary, resolveTimeout, outputGrace = savedBinary, savedTimeout, savedGrace })
}

// waitForPID returns the PID a script wrote to file, once it has been written.
func waitForPID(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(file) // #nosec G304 -- a file this test's script wrote
		if err == nil && strings.TrimSpace(string(data)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("%s holds %q, not a PID", file, data)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fake client never wrote %s", file)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// processEnded reports whether pid has exited. A zombie has exited too, though
// kill(0) still finds it until it is reaped, so /proc is checked for one.
func processEnded(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- a process this test started
	if err != nil {
		return false
	}
	closing := strings.LastIndex(string(data), ")")
	return closing >= 0 && len(data) > closing+2 && data[closing+2] == 'Z'
}

func requireEnded(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !processEnded(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("%s (pid %d) is still running after the read ended", what, pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A hung client that holds the output pipe open must not hold the read open.
func TestResolveIsBoundedWhenTheClientHangs(t *testing.T) {
	client := fakeClient(t, "sleep 60 &\nsleep 60\n")
	useFakeClient(t, client, 300*time.Millisecond)
	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now()
		_, err := Resolve(context.Background(), "host", 0, "")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("attempt %d: a hung configuration read returned no error", attempt)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("attempt %d: a hung configuration read took %v; want it bounded by its deadline", attempt, elapsed)
		}
	}
}

// Cancellation ends the client and the child it started, and nothing else.
func TestCancellationEndsTheClientAndItsChildren(t *testing.T) {
	dir := t.TempDir()
	self, child := filepath.Join(dir, "self.pid"), filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("echo $$ > %s\nsleep 300 &\necho $! > %s\nwait\n", self, child))
	useFakeClient(t, client, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitForPID(t, child)
		cancel()
	}()

	if _, err := Resolve(ctx, "host", 0, ""); err == nil {
		t.Fatal("a cancelled configuration read returned no error")
	}
	requireEnded(t, waitForPID(t, self), "the ssh client")
	requireEnded(t, waitForPID(t, child), "the child the client started")
}

// The deadline ends the client and the child it started in the same way.
func TestTimeoutEndsTheClientAndItsChildren(t *testing.T) {
	dir := t.TempDir()
	self, child := filepath.Join(dir, "self.pid"), filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("echo $$ > %s\nsleep 300 &\necho $! > %s\nwait\n", self, child))
	useFakeClient(t, client, 500*time.Millisecond)

	if _, err := Resolve(context.Background(), "host", 0, ""); err == nil {
		t.Fatal("a timed-out configuration read returned no error")
	}
	requireEnded(t, waitForPID(t, self), "the ssh client")
	requireEnded(t, waitForPID(t, child), "the child the client started")
}

// A client that exits normally must not leave the child it started running.
func TestSuccessfulReadLeavesNoBackgroundChild(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("sleep 300 &\necho $! > %s\nprintf 'hostname h\\nport 22\\nuser u\\n'\nexit 0\n", child))
	useFakeClient(t, client, time.Minute)

	target, err := Resolve(context.Background(), "host", 0, "")
	if err != nil {
		t.Fatalf("a successful read returned an error: %v", err)
	}
	if target.Host != "h" {
		t.Fatalf("host = %q, want the complete listing", target.Host)
	}
	requireEnded(t, waitForPID(t, child), "the child the client left behind")
}

// A listing that ends without its last newline is incomplete, and it is refused
// rather than parsed as if it were whole.
func TestIncompleteOutputIsRefused(t *testing.T) {
	client := fakeClient(t, "printf 'hostname h\\nport 22\\nuser u'\nexit 0\n")
	useFakeClient(t, client, time.Minute)

	_, err := Resolve(context.Background(), "host", 0, "")
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("an incomplete listing was accepted: %v", err)
	}
}

// A child that leaves the process group and keeps the output open makes the
// listing incomplete for certain, so it is an error. The child is killed by the
// test, since the read does not reach it.
func TestChildOutsideTheGroupIsAnError(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not available to start a child in a session of its own")
	}
	dir := t.TempDir()
	child := filepath.Join(dir, "child.pid")
	// The pause lets the child leave the group before the client exits, so the
	// group kill does not reach it: the test is about a child that escaped.
	client := fakeClient(t, fmt.Sprintf("setsid sleep 300 &\necho $! > %s\nsleep 0.5\nprintf 'hostname h\\nport 22\\nuser u\\n'\nexit 0\n", child))
	useFakeClient(t, client, time.Minute)
	savedGrace := outputGrace
	outputGrace = 300 * time.Millisecond
	t.Cleanup(func() { outputGrace = savedGrace })

	done := make(chan error, 1)
	go func() {
		_, err := Resolve(context.Background(), "host", 0, "")
		done <- err
	}()
	pid := waitForPID(t, child)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "kept it open") {
		t.Fatalf("a read held open by a child outside the group was accepted: %v", err)
	}
}
