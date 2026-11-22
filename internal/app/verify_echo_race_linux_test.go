//go:build linux

package app

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/unix"
)

// TestPromptRaceHelper is the child of the interrupt sweep. It announces itself, then
// reads a secret. NETDOC_PROMPT_RACE_CONFLICT=1 reads with term.ReadPassword instead,
// which writes the terminal state a second time after echo is off. That is the write
// the reader must not make, so the flag is the negative control.
func TestPromptRaceHelper(t *testing.T) {
	if os.Getenv("NETDOC_PROMPT_RACE") != "1" {
		t.Skip("runs only as the child of the interrupt sweep")
	}
	if os.Getenv("NETDOC_PROMPT_RACE_CONFLICT") == "1" {
		verifyReadPass = func() ([]byte, error) { return term.ReadPassword(os.Stdin.Fd()) }
	}
	fmt.Fprintln(os.Stderr, "READY")
	if _, err := readVerifySecret(context.Background(), os.Stderr, "Password: ", false); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(2)
	}
	os.Exit(0)
}

// interruptRace runs the helper on a terminal, sends Ctrl-C after delay, and reports
// whether echo is on once the helper has ended.
func interruptRace(t *testing.T, delay time.Duration, conflict bool) bool {
	t.Helper()
	master, slave := openTerminal(t)
	defer master.Close()
	defer slave.Close()

	var mu sync.Mutex
	var output bytes.Buffer
	ready := make(chan struct{})
	var readyOnce sync.Once
	go func() {
		chunk := make([]byte, 256)
		for {
			n, err := master.Read(chunk)
			if n > 0 {
				mu.Lock()
				output.Write(chunk[:n])
				if strings.Contains(output.String(), "READY") {
					readyOnce.Do(func() { close(ready) })
				}
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	flag := "0"
	if conflict {
		flag = "1"
	}
	// #nosec G702 G204 -- the test runs its own binary as the helper process, with a fixed argument
	cmd := exec.Command(os.Args[0], "-test.run=^TestPromptRaceHelper$")
	cmd.Env = append(os.Environ(), "NETDOC_PROMPT_RACE=1", "NETDOC_PROMPT_RACE_CONFLICT="+flag)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the helper did not announce itself")
	}
	time.Sleep(delay)
	if _, err := master.Write([]byte{3}); err != nil { // ETX, Ctrl-C
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the interrupted helper did not end")
	}
	return echoOn(t, slave)
}

// countEchoLeaks interrupts runs prompts at delays drawn from a fixed seed, so a run
// is repeatable, and counts the runs that end with echo off.
func countEchoLeaks(t *testing.T, runs int, conflict bool) (leaks int, firstDelay time.Duration) {
	t.Helper()
	// #nosec G404 -- a fixed seed makes the sweep repeatable; the delays need no secrecy
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < runs; i++ {
		delay := time.Duration(rng.Intn(400)) * time.Microsecond
		if !interruptRace(t, delay, conflict) {
			if leaks == 0 {
				firstDelay = delay
			}
			leaks++
		}
	}
	return leaks, firstDelay
}

// Ctrl-C at varied points around the echo change must never leave echo off.
// NETDOC_ECHO_SWEEP_RUNS sets the number of runs.
func TestInterruptRaceLeavesEchoOn(t *testing.T) {
	runs := envInt("NETDOC_ECHO_SWEEP_RUNS", 40)
	if leaks, delay := countEchoLeaks(t, runs, false); leaks > 0 {
		t.Fatalf("%d of %d interrupted prompts left echo off (first at %v)", leaks, runs, delay)
	}
}

// Negative control, run with NETDOC_ECHO_NEGATIVE=1: the conflicting second write must
// reproduce the leak, or the sweep above could not have caught it.
func TestInterruptRaceConflictingWriteIsDetected(t *testing.T) {
	if os.Getenv("NETDOC_ECHO_NEGATIVE") != "1" {
		t.Skip("the negative control runs only with NETDOC_ECHO_NEGATIVE=1")
	}
	runs := envInt("NETDOC_ECHO_SWEEP_RUNS", 400)
	leaks, delay := countEchoLeaks(t, runs, true)
	t.Logf("conflicting second write: %d of %d interrupted prompts left echo off (first at %v)", leaks, runs, delay)
	if leaks == 0 {
		t.Fatalf("the conflicting second write did not reproduce the leak in %d runs", runs)
	}
}

// A restore that has run is final: a later echo-off is refused, and echo stays on.
func TestSecretEchoOffIsRefusedAfterRestore(t *testing.T) {
	master, slave := openTerminal(t)
	defer master.Close()
	defer slave.Close()
	echo, err := newSecretEcho(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	echo.restore()
	if err := echo.off(); err == nil {
		t.Fatal("echo was turned off after the terminal was restored")
	}
	if !echoOn(t, slave) {
		t.Fatal("echo is off after a restore and a late echo-off")
	}
}

// An interrupt's restore and the reader's echo-off run from separate goroutines. Whichever
// runs last, echo must end on. Each run uses its own terminal. NETDOC_ECHO_RACE_RUNS sets
// the run count.
func TestRestoreRacingEchoOffLeavesEchoOn(t *testing.T) {
	runs := envInt("NETDOC_ECHO_RACE_RUNS", 4000)
	for i := 0; i < runs; i++ {
		master, slave := openTerminal(t)
		echo, err := newSecretEcho(slave.Fd())
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = echo.off()
		}()
		go func() {
			defer wg.Done()
			<-start
			echo.restore()
		}()
		close(start)
		wg.Wait()
		on := echoOn(t, slave)
		_ = master.Close()
		_ = slave.Close()
		if !on {
			t.Fatalf("run %d: echo is off after a restore raced an echo-off", i)
		}
	}
}

// promptWriter runs fn at the first write, which is the prompt.
type promptWriter struct {
	first func()
	done  bool
}

func (p *promptWriter) Write(b []byte) (int, error) {
	if !p.done {
		p.done = true
		p.first()
	}
	return len(b), nil
}

// The read keeps the modes it needs, with echo off: canonical line mode, signals, and
// CR-to-NL mapping, so Ctrl-C still interrupts and a line ending in CR is returned. The
// terminal ends with the state it started in.
func TestSecretReadKeepsLineModesAndRestoresTheTerminal(t *testing.T) {
	master, slave := openTerminal(t)
	defer master.Close()
	defer slave.Close()
	// Start from a state without the modes the read needs, so the read has to set them.
	orig, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	orig.Lflag &^= unix.ICANON | unix.ISIG | unix.ECHO
	orig.Iflag &^= unix.ICRNL
	if err := setTermios(slave.Fd(), &orig); err != nil {
		t.Fatal(err)
	}
	oldStdin, oldRead := os.Stdin, verifyReadPass
	os.Stdin = slave
	verifyReadPass = readTerminalLine
	t.Cleanup(func() { os.Stdin, verifyReadPass = oldStdin, oldRead })

	var atPrompt unix.Termios
	probe := &promptWriter{first: func() {
		atPrompt, _ = getTermios(slave.Fd())
		// Typed while echo is off: the line discipline keeps it, and nothing is echoed.
		_, _ = master.Write([]byte("typed-secret\r"))
	}}
	type read struct {
		value []byte
		err   error
	}
	done := make(chan read, 1)
	go func() {
		value, err := readTerminalSecret(probe, "Password: ")
		done <- read{value, err}
	}()
	var got read
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the read did not end: the line ending in CR was not returned as a line")
	}
	if got.err != nil {
		t.Fatalf("the secret was not read: %v", got.err)
	}
	if string(got.value) != "typed-secret" {
		t.Fatalf("the line read was %q, want the typed secret", got.value)
	}
	if atPrompt.Lflag&unix.ECHO != 0 {
		t.Error("echo was on at the prompt")
	}
	if atPrompt.Lflag&unix.ICANON == 0 || atPrompt.Lflag&unix.ISIG == 0 || atPrompt.Iflag&unix.ICRNL == 0 {
		t.Errorf("the read lost a required mode: lflag=%#x iflag=%#x", atPrompt.Lflag, atPrompt.Iflag)
	}
	after, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if after != orig {
		t.Errorf("the terminal did not end in its original state: before %+v, after %+v", orig, after)
	}
}

// envInt reads a positive run count from the environment, or returns def.
func envInt(name string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(name)); err == nil && n > 0 {
		return n
	}
	return def
}
