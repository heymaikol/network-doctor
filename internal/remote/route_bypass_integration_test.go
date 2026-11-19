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

// The carriage-return spelling of the same directive. OpenSSH splits a line on a carriage return,
// so this is a Match command to ssh, and it must be refused headless and on a terminal, with no
// connection made around the jump host.
const matchCommandCRConfig = "Match\rcommand \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n  Port %d\n  User demo\n"

// The same host with CRLF line endings and no directive that depends on the connection. It is a
// direct route, and it must still connect, so the refusals above are not refusals of everything.
const directCRLFConfig = "Host probe\r\n  HostName 127.0.0.1\r\n  Port %d\r\n  User demo\r\n"

func writeRouteConfig(t *testing.T, format string, port int) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "route.config")
	if err := os.WriteFile(cfg, []byte(sprintfPort(format, port)), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Headless, a carriage-return Match command is refused before any connection: no accept on the
// host's port, and the run returns an error.
func TestHeadlessRunDoesNotConnectAroundACarriageReturnMatchCommand(t *testing.T) {
	port, accepts := countingListener(t)
	realSSHWithConfig(t, writeRouteConfig(t, matchCommandCRConfig, port))
	saved := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return false }
	t.Cleanup(func() { sshverify.TerminalAvailable = saved })

	_, err := Run(context.Background(), "probe", "", Request{TimeoutMs: 5000})
	if n := accepts.Load(); n != 0 {
		t.Fatalf("a headless run connected %d time(s) straight to the host, around the jump host its carriage-return Match command selects (err %v)", n, err)
	}
	if err == nil {
		t.Fatal("a headless run of a carriage-return Match command returned no error")
	}
}

// On a terminal the batch transport is chosen by the same read, so a carriage-return Match command
// must not be read as a direct route there either.
func TestTerminalDirectRefusesACarriageReturnMatchCommand(t *testing.T) {
	port, _ := countingListener(t)
	realSSHWithConfig(t, writeRouteConfig(t, matchCommandCRConfig, port))
	saved := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return true }
	t.Cleanup(func() { sshverify.TerminalAvailable = saved })

	if Direct(context.Background(), "probe") {
		t.Fatal("a terminal run read a carriage-return Match command as a direct route, and the batch transport turns its proxy off")
	}
}

// Control: a CRLF configuration with a plain direct route is still direct, and a headless run still
// connects to it. Refusing the carriage-return form does not refuse CRLF files.
func TestHeadlessRunStillConnectsByACRLFDirectRoute(t *testing.T) {
	port, accepts := countingListener(t)
	realSSHWithConfig(t, writeRouteConfig(t, directCRLFConfig, port))
	saved := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return false }
	t.Cleanup(func() { sshverify.TerminalAvailable = saved })

	if !Direct(context.Background(), "probe") {
		t.Fatal("a CRLF configuration with a plain direct route was not read as direct")
	}
	_, _ = Run(context.Background(), "probe", "", Request{TimeoutMs: 5000})
	if accepts.Load() == 0 {
		t.Fatal("a headless run of a direct CRLF route made no connection")
	}
}

// The quoted spellings of the same directive. ssh removes quotes from a keyword by a rule that joins
// the text around them, so each of these is a Match command to ssh. Each is refused headless and on a
// terminal, with no connection made around the jump host.
func TestQuotedMatchCommandIsNotRoutedAroundItsProxy(t *testing.T) {
	for _, spelling := range []string{`"Match" command "netdoc*"`, `=Match command "netdoc*"`, `= "Match" command "netdoc*"`} {
		t.Run(spelling, func(t *testing.T) {
			port, accepts := countingListener(t)
			realSSHWithConfig(t, writeRouteConfig(t, spelling+"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n  Port %d\n  User demo\n", port))
			saved := sshverify.TerminalAvailable
			t.Cleanup(func() { sshverify.TerminalAvailable = saved })

			sshverify.TerminalAvailable = func() bool { return false }
			_, err := Run(context.Background(), "probe", "", Request{TimeoutMs: 5000})
			if n := accepts.Load(); n != 0 {
				t.Errorf("a headless run connected %d time(s) straight to the host, around the jump host", n)
			}
			if err == nil {
				t.Error("a headless run of a quoted Match command returned no error")
			}

			sshverify.TerminalAvailable = func() bool { return true }
			if Direct(context.Background(), "probe") {
				t.Error("a terminal run read a quoted Match command as a direct route, and the batch transport turns its proxy off")
			}
		})
	}
}
