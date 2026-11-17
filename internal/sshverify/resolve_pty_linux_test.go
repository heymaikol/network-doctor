//go:build linux

package sshverify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The configuration read starts its client in a session of its own, with no
// controlling terminal. A Match exec command that needs the terminal therefore
// fails at once, and its reason is reported. These tests run the read in a child
// that has a pseudo-terminal as its controlling terminal, which is the situation
// a read would otherwise share.

// TestResolveHelper runs one read in the child the terminal tests start. It is
// skipped unless the parent sets NETDOC_RESOLVE_HELPER.
func TestResolveHelper(t *testing.T) {
	if os.Getenv("NETDOC_RESOLVE_HELPER") == "" {
		t.Skip("runs only as the child of the terminal tests")
	}
	sshBinary = os.Getenv("NETDOC_FAKE_CLIENT")
	resolveTimeout = 3 * time.Second
	target, err := Resolve(context.Background(), "host", 0, "")
	if err != nil {
		fmt.Printf("RESULT error: %s\n", err)
	} else {
		fmt.Printf("RESULT ok: %s\n", target.Host)
	}
	os.Exit(0)
}

func openPseudoTerminal(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(m)
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(m, unix.TIOCGPTN)
	if err != nil {
		_ = unix.Close(m)
		t.Fatal(err)
	}
	s, err := unix.Open(fmt.Sprintf("/dev/pts/%d", n), unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = unix.Close(m)
		t.Fatal(err)
	}
	return os.NewFile(uintptr(m), "ptmx"), os.NewFile(uintptr(s), "pts")
}

// readOnTerminal runs the read in a child whose controlling terminal is a
// pseudo-terminal, and returns the child's result line and how long it took.
func readOnTerminal(t *testing.T, client string) (string, time.Duration) {
	t.Helper()
	master, slave := openPseudoTerminal(t)
	defer master.Close()
	defer slave.Close()

	var mu sync.Mutex
	var output bytes.Buffer
	go func() {
		chunk := make([]byte, 256)
		for {
			n, err := master.Read(chunk)
			if n > 0 {
				mu.Lock()
				output.Write(chunk[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	resultLine := func() string {
		mu.Lock()
		defer mu.Unlock()
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "RESULT ") {
				return strings.TrimSpace(line)
			}
		}
		return ""
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestResolveHelper$") // #nosec G204 -- the test runs its own binary as the helper process
	cmd.Env = append(os.Environ(), "NETDOC_RESOLVE_HELPER=1", "NETDOC_FAKE_CLIENT="+client)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(20 * time.Second)
	for resultLine() == "" {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("the helper printed no result; output so far: %q", output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	took := time.Since(start)
	if err := <-done; err != nil {
		t.Fatalf("the helper failed: %v", err)
	}
	return resultLine(), took
}

// An interactive Match exec command, one that needs the terminal, fails at once
// with the reason, and it does not wait out the read's deadline.
func TestTerminalMatchExecFailsAtOnceWithItsReason(t *testing.T) {
	client := fakeClient(t, "cat /dev/tty >/dev/null || exit 255\nprintf 'hostname h\\nport 22\\nuser u\\n'\n")

	line, took := readOnTerminal(t, client)

	if !strings.HasPrefix(line, "RESULT error:") {
		t.Fatalf("an interactive Match exec was not refused: %q", line)
	}
	if !strings.Contains(line, "/dev/tty") {
		t.Errorf("the error does not say what the command needed: %q", line)
	}
	if strings.Contains(line, "did not finish") {
		t.Errorf("the read timed out instead of reporting the failure: %q", line)
	}
	if took > 2*time.Second {
		t.Errorf("the refusal took %v; want it immediate, not the read's deadline", took)
	}
}

// A Match exec command that does not need the terminal still resolves, on the
// same terminal.
func TestTerminalNoninteractiveReadStillResolves(t *testing.T) {
	client := fakeClient(t, "printf 'hostname h\\nport 22\\nuser u\\n'\n")

	line, _ := readOnTerminal(t, client)

	if line != "RESULT ok: h" {
		t.Fatalf("a noninteractive read on a terminal = %q, want the resolved host", line)
	}
}
