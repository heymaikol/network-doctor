//go:build unix

package sshverify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A configuration read is refused without a terminal, before any command in the
// configuration runs: a run with no terminal can differ from the user's own ssh in
// its environment, which netdoc cannot reproduce. These tests run the read in a
// child with no controlling terminal and check that nothing in the configuration
// ran. The classifier's own cases run on a real terminal in the terminal tests.

// writeMatchConfig writes a configuration whose Match exec command is command.
// Matched, the command sets the host to 10.9.9.9; otherwise the host is 127.0.0.1.
func writeMatchConfig(t *testing.T, name, command string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	body := fmt.Sprintf("Match host target exec %q\n  HostName 10.9.9.9\nHost target\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n", command)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeScript writes an executable Match exec command.
func writeScript(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil { // #nosec G306 -- an executable test command on purpose
		t.Fatal(err)
	}
	return path
}

// TestHeadlessHelper is the child for the headless tests. It reads the configuration
// with the same read Resolve makes, and then asks Discover to connect, counting the
// dials. It is skipped unless the parent sets NETDOC_HEADLESS_CONFIG.
func TestHeadlessHelper(t *testing.T) {
	cfg := os.Getenv("NETDOC_HEADLESS_CONFIG")
	if cfg == "" {
		t.Skip("runs only as the child of the headless tests")
	}
	resolveTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	out, err := resolveOutput(ctx, []string{"-G", "-F", cfg, "--", "target"})
	cancel()
	if err != nil {
		fmt.Printf("RESULT resolve-error: %s\n", err)
		os.Exit(0)
	}
	target, err := parseConfig(out, "")
	if err != nil {
		fmt.Printf("RESULT resolve-error: %s\n", err)
		os.Exit(0)
	}
	var dials atomic.Int32
	opts := Options{Timeout: 2 * time.Second, Dial: func(context.Context, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("the test does not connect")
	}}
	r := Discover(context.Background(), target, opts)
	fmt.Printf("RESULT unsupported=%q dials=%d outcome=%s\n", target.Unsupported, dials.Load(), r.Outcome)
	os.Exit(0)
}

// runHeadless runs the headless child on config and returns its result line.
// The child starts a new session with no controlling terminal.
func runHeadless(t *testing.T, config string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHeadlessHelper$") // #nosec G702 G204 -- the test runs its own test binary (os.Args[0]) with a fixed -test.run argument, and no shell
	cmd.Env = append(os.Environ(), "NETDOC_HEADLESS_CONFIG="+config)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the headless child failed: %v; output %q", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return line
		}
	}
	t.Fatalf("the headless child printed no result: %q", out)
	return ""
}

// A headless run is refused before any command in the configuration runs. The
// command here would leave a file behind if it ran, and the file must not exist.
func TestHeadlessReadIsRefusedBeforeAnythingRuns(t *testing.T) {
	requireOpenSSH(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "ran")
	script := writeScript(t, "touch.sh", "touch "+sentinel+"\nexit 0\n")
	line := runHeadless(t, writeMatchConfig(t, "touch.config", script))
	if !strings.Contains(line, "RESULT resolve-error:") || !strings.Contains(line, "run netdoc from a terminal") {
		t.Fatalf("a headless read was not refused for its missing terminal: %q", line)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("a Match exec command ran in a headless read")
	}
}

// Without a terminal the read is refused even when the configuration would be read
// the same everywhere, because netdoc cannot tell that it would be.
func TestHeadlessPlainConfigIsRefused(t *testing.T) {
	requireOpenSSH(t)
	cfg := filepath.Join(t.TempDir(), "plain.config")
	body := "Host target\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	line := runHeadless(t, cfg)
	if !strings.Contains(line, "run netdoc from a terminal") || strings.Contains(line, "dials=") {
		t.Fatalf("a headless read of a plain configuration was not refused: %q", line)
	}
}
