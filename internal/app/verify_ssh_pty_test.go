//go:build linux

package app

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests run the secret prompt in a child process attached to a
// pseudo-terminal. The interrupt is Ctrl-C written to the terminal, so it reaches
// the child as a real SIGINT, and the terminal's echo state is read back from the
// terminal itself after the child exits.

// TestPasswordPromptHelper is the child process. It is skipped unless the
// parent starts it with NETDOC_PROMPT_HELPER set.
func TestPasswordPromptHelper(t *testing.T) {
	if os.Getenv("NETDOC_PROMPT_HELPER") != "1" {
		t.Skip("runs only as the child of the terminal tests")
	}
	value, err := readVerifySecret(os.Stderr, "Password: ", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "helper read %d bytes\n", len(value))
	os.Exit(0)
}

func openTerminal(t *testing.T) (master, slave *os.File) {
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

func echoOn(t *testing.T, slave *os.File) bool {
	t.Helper()
	termios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return termios.Lflag&unix.ECHO != 0
}

// runSecretPrompt starts the helper on a terminal, waits until it has turned
// echo off, sends input, and returns how it exited and whether echo is on after.
func runSecretPrompt(t *testing.T, input []byte) (exitErr error, echoAfter bool) {
	t.Helper()
	master, slave := openTerminal(t)
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

	// #nosec G702 G204 -- the test runs its own binary as the helper process, with a fixed argument
	cmd := exec.Command(os.Args[0], "-test.run=^TestPasswordPromptHelper$")
	cmd.Env = append(os.Environ(), "NETDOC_PROMPT_HELPER=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Echo goes off once the helper is inside the read, which is when an
	// interrupt matters. Waiting for that keeps the interrupt from arriving
	// before the state under test exists.
	waitUntil(t, "the helper to turn echo off", func() bool {
		termios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		return err == nil && termios.Lflag&unix.ECHO == 0
	})
	if _, err := master.Write(input); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case exitErr = <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the secret prompt did not end")
	}
	return exitErr, echoOn(t, slave)
}

func waitUntil(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Ctrl-C during the prompt ends the command, and the terminal must still echo
// what is typed afterwards. Without the handler the terminal was left with echo
// off.
func TestInterruptDuringPasswordPromptRestoresEcho(t *testing.T) {
	exitErr, echo := runSecretPrompt(t, []byte{3}) // ETX, the Ctrl-C character
	if exitErr == nil {
		t.Fatal("the interrupted prompt reported success")
	}
	if !echo {
		t.Fatal("echo is still off on the terminal after Ctrl-C at the password prompt")
	}
}

// The normal path reads a line and restores echo, as before.
func TestPasswordPromptRestoresEchoAfterInput(t *testing.T) {
	exitErr, echo := runSecretPrompt(t, []byte("demo-password\n"))
	if exitErr != nil {
		t.Fatalf("the prompt failed after input: %v", exitErr)
	}
	if !echo {
		t.Fatal("echo is off on the terminal after a password was entered")
	}
}
