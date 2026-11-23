//go:build linux

package sshverify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests run the real OpenSSH client against a configuration with a Match
// exec command, on a pseudo-terminal, through the same resolver netdoc uses. The
// resolver runs in a child process, so the terminal it sees is one the test
// chose: a controlling terminal for the terminal tests, none for the headless one.

// TestResolveHelper is the child that runs one read. It is skipped unless the
// parent sets NETDOC_SSH_CONFIG to the configuration to read.
func TestResolveHelper(t *testing.T) {
	cfg := os.Getenv("NETDOC_SSH_CONFIG")
	if cfg == "" {
		t.Skip("runs only as the child of the terminal tests")
	}
	resolveTimeout = 3 * time.Second
	// Resolve applies the deadline; the helper calls the runner directly, so it
	// applies the same deadline itself.
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	out, err := resolveOutput(ctx, []string{"-G", "-F", cfg, "--", "target"})
	if err != nil {
		fmt.Printf("RESULT error: %s\n", err)
		os.Exit(0)
	}
	target, err := parseConfig(out, testHomeDir())
	if err != nil {
		fmt.Printf("RESULT error: %s\n", err)
		os.Exit(0)
	}
	fmt.Printf("RESULT ok: %s\n", target.Host)
	os.Exit(0)
}

// openPTYPair returns the master and slave of a new pseudo-terminal.
func openPTYPair(t *testing.T) (master, slave *os.File) {
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

// runResolveChild runs TestResolveHelper against config, with a controlling
// terminal when terminal is true and with no terminal at all when it is false.
// It returns the child's result line and how long the child took.
func runResolveChild(t *testing.T, config string, terminal bool) (string, time.Duration) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestResolveHelper$") // #nosec G702 G204 -- the test runs its own test binary (os.Args[0]) with a fixed -test.run argument, and no shell
	cmd.Env = append(os.Environ(), "NETDOC_SSH_CONFIG="+config)
	var master *os.File
	var slave *os.File
	if terminal {
		m, s := openPTYPair(t)
		master, slave = m, s
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	var output lockedBuffer
	copied := make(chan struct{})
	if master != nil {
		defer master.Close()
		go func() {
			output.copyFrom(master)
			close(copied)
		}()
	} else {
		close(copied)
	}
	start := time.Now()
	if master == nil {
		cmd.Stdout = &output
		cmd.Stderr = &output
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The child holds the terminal's slave side now. Closing this one lets the
	// reader see end of file once the child has exited, after every byte is read.
	if slave != nil {
		_ = slave.Close()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the child failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the child did not end; output so far: %q", output.text())
	}
	select {
	case <-copied:
	case <-time.After(10 * time.Second):
		t.Fatalf("the child's output did not end; output so far: %q", output.text())
	}
	took := time.Since(start)
	line := output.resultLine()
	if line == "" {
		t.Fatalf("the child printed no result; output: %q", output.text())
	}
	return line, took
}

// interactiveHostname is what the user's own ssh resolves: the same command on a
// controlling terminal, with the answer typed into it. It returns the resolved host.
func interactiveHostname(t *testing.T, config, typed string) string {
	t.Helper()
	requireOpenSSH(t)
	master, slave := openPTYPair(t)
	defer master.Close()
	cmd := exec.Command("ssh", "-G", "-F", config, "--", "target") // #nosec G204 -- a fixed argument list
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	var output lockedBuffer
	copied := make(chan struct{})
	go func() {
		output.copyFrom(master)
		close(copied)
	}()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = slave.Close()
	if typed != "" {
		time.Sleep(500 * time.Millisecond)
		if _, err := master.Write([]byte(typed)); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the interactive ssh did not finish")
	}
	select {
	case <-copied:
	case <-time.After(10 * time.Second):
		t.Fatal("the interactive ssh output did not end")
	}
	target, err := parseConfig([]byte(output.stdoutText()), testHomeDir())
	if err != nil {
		t.Fatalf("interactive ssh printed no usable configuration: %v; output %q", err, output.text())
	}
	return target.Host
}

// lockedBuffer collects a child's output, which another goroutine reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) copyFrom(r *os.File) {
	chunk := make([]byte, 256)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			_, _ = b.Write(chunk[:n])
		}
		if err != nil {
			return
		}
	}
}

func (b *lockedBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// stdoutText is the child's output without the RESULT line, for the interactive
// listing that ssh -G printed.
func (b *lockedBuffer) stdoutText() string {
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(b.text(), "\r", ""), "\n") {
		if !strings.HasPrefix(line, "RESULT ") {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

func (b *lockedBuffer) resultLine() string {
	for _, line := range strings.Split(strings.ReplaceAll(b.text(), "\r", ""), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return line
		}
	}
	return ""
}

// A command that reads the terminal is stopped, not answered, so the read is
// refused at its deadline. The user's own ssh, typing "y", resolves to the other
// host, so accepting the silent answer would send the credential to a host the
// user's ssh would not reach.
func TestTerminalReadIsRefusedNotSilent(t *testing.T) {
	requireOpenSSH(t)
	// POSIX sh only: /bin/sh is dash on some systems, and dash has no read -t.
	ask := writeScript(t, "ask.sh", "IFS= read -r answer </dev/tty || exit 1\n[ \"$answer\" = y ]\n")
	config := writeMatchConfig(t, "ask.config", ask)

	if got := interactiveHostname(t, config, "y\n"); got != "10.9.9.9" {
		t.Fatalf("the interactive baseline resolves %q, want 10.9.9.9", got)
	}
	line, took := runResolveChild(t, config, true)

	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "did not finish") {
		t.Fatalf("a terminal read was not refused: %q", line)
	}
	if took > 10*time.Second {
		t.Errorf("the refusal took %v; want it at the deadline, not longer", took)
	}
}

// A terminal probe is a Match exec test. It is refused even on a terminal, because
// its answer is then the one this terminal gives, not one netdoc can reproduce for
// the user's own ssh in every other place.
func TestTerminalProbeIsRefused(t *testing.T) {
	requireOpenSSH(t)
	config := writeMatchConfig(t, "probe.config", ": </dev/tty")
	line, _ := runResolveChild(t, config, true)
	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "Match exec") {
		t.Fatalf("a terminal probe was not refused: %q", line)
	}
}

// A noninteractive Match exec is refused on a terminal too: the rule is the same
// whether or not netdoc has a terminal, so a result never depends on where it ran.
func TestTerminalNoninteractiveMatchExecIsRefused(t *testing.T) {
	requireOpenSSH(t)
	config := writeMatchConfig(t, "true.config", "true")
	line, _ := runResolveChild(t, config, true)
	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "Match exec") {
		t.Fatalf("a noninteractive Match exec was not refused on a terminal: %q", line)
	}
}

// On a real terminal the read runs, and any Match exec command it evaluates is
// refused. A timed terminal read is refused as well, because its answer would be
// the command's own timeout.
func TestTerminalTimedReadIsRefused(t *testing.T) {
	requireOpenSSH(t)
	script := writeScript(t, "timed.sh", "read -t 2 answer </dev/tty\n[ \"$answer\" = y ]\n")
	line, _ := runResolveChild(t, writeMatchConfig(t, "timed.config", script), true)
	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "Match exec") {
		t.Fatalf("a timed terminal read was not refused on a terminal: %q", line)
	}
}

// A command that asks the terminal its size is a Match exec test, refused on a
// terminal like any other.
func TestTerminalSizeIsRefused(t *testing.T) {
	requireOpenSSH(t)
	script := writeScript(t, "size.sh", "rows=$(stty size </dev/tty 2>/dev/null | cut -d' ' -f1)\n[ \"${rows:-0}\" -gt 20 ]\n")
	line, _ := runResolveChild(t, writeMatchConfig(t, "size.config", script), true)
	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "Match exec") {
		t.Fatalf("a terminal-size test was not refused on a terminal: %q", line)
	}
}

// A Match exec in a file pulled in by Include is refused the same way.
func TestTerminalNestedIncludeIsRefused(t *testing.T) {
	requireOpenSSH(t)
	dir := t.TempDir()
	script := writeScript(t, "nested.sh", "exit 0\n")
	inc := filepath.Join(dir, "inc.conf")
	if err := os.WriteFile(inc, []byte("Match host target exec \""+script+"\"\n  ProxyJump bastion.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "main.config")
	if err := os.WriteFile(cfg, []byte("Include "+inc+"\nHost target\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line, _ := runResolveChild(t, cfg, true)
	if !strings.HasPrefix(line, "RESULT error:") || !strings.Contains(line, "Match exec") {
		t.Fatalf("a Match exec in an included file was not refused on a terminal: %q", line)
	}
}

// The positive control on a terminal: a configuration with no Match exec resolves,
// so terminal use keeps working where the configuration is plain.
func TestTerminalPlainConfigResolves(t *testing.T) {
	requireOpenSSH(t)
	cfg := filepath.Join(t.TempDir(), "plain.config")
	if err := os.WriteFile(cfg, []byte("Host target\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	line, _ := runResolveChild(t, cfg, true)
	if line != "RESULT ok: 127.0.0.1" {
		t.Fatalf("a plain configuration on a terminal resolved %q, want 127.0.0.1", line)
	}
}
