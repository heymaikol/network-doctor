//go:build integration && unix

package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// A proxy chosen by Match command depends on the remote command. The route read runs
// ssh -G with no command, so it never sees that proxy, and the batch transport forces
// ProxyJump=none. Without a fix, that connects straight to the host the user's own ssh
// reaches through its jump host.
const matchCommandConfig = `Match command "netdoc*"
  ProxyJump 127.0.0.3
Host probe
  HostName 127.0.0.1
  Port %d
  User demo
`

// countingListener accepts and drops every connection, and counts them. It binds only
// to loopback, and the test uses it as the host the configuration names.
func countingListener(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &accepts
}

// realSSHWithConfig makes the remote package's ssh use the given configuration, by
// putting it on the command line first. Every other argument is OpenSSH's own.
func realSSHWithConfig(t *testing.T, cfg string) {
	t.Helper()
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}
	wrapper := filepath.Join(t.TempDir(), "ssh")
	script := "#!/bin/sh\nexec '" + ssh + "' -F '" + cfg + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test wrapper in a directory this test created
		t.Fatal(err)
	}
	previous := sshProgram
	sshProgram = wrapper
	t.Cleanup(func() { sshProgram = previous })
}

func matchCommandConfigFile(t *testing.T, port int) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "match-command.config")
	if err := os.WriteFile(cfg, []byte(sprintfPort(matchCommandConfig, port)), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// A headless run connects by a known direct route only. A route whose proxy depends on
// the command is not one, so no connection reaches the host around its jump.
func TestHeadlessRunDoesNotConnectAroundAMatchCommandProxy(t *testing.T) {
	port, accepts := countingListener(t)
	realSSHWithConfig(t, matchCommandConfigFile(t, port))
	saved := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return false }
	t.Cleanup(func() { sshverify.TerminalAvailable = saved })

	_, err := Run(context.Background(), "probe", "", Request{TimeoutMs: 5000})
	if n := accepts.Load(); n != 0 {
		t.Fatalf("a headless run connected %d time(s) straight to the host, around the jump host its command selects (err %v)", n, err)
	}
	if err == nil {
		t.Fatal("a headless run of a command-dependent proxy route returned no error")
	}
}

// On a terminal the batch transport is chosen by the same decision, so a route whose
// proxy depends on the command must not be read as direct there either.
func TestTerminalDirectDoesNotRouteAroundAMatchCommandProxy(t *testing.T) {
	port, _ := countingListener(t)
	realSSHWithConfig(t, matchCommandConfigFile(t, port))
	saved := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return true }
	t.Cleanup(func() { sshverify.TerminalAvailable = saved })

	if Direct(context.Background(), "probe") {
		t.Fatal("a terminal run chose the batch transport for a route whose proxy depends on the remote command, and the batch transport turns that proxy off")
	}
}

// sprintfPort fills the one %d of a configuration with a port.
func sprintfPort(format string, port int) string {
	return fmt.Sprintf(format, port)
}
