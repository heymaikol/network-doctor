//go:build integration && unix

package sshverify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// oshStartPasswordEndpoint starts a second sshd on loopback that presents the lab's host key, accepts
// the lab's client key, and also accepts passwords, so a password attempt reaches it and is logged.
// It returns the port.
func oshStartPasswordEndpoint(t *testing.T, l *oshLab) int {
	t.Helper()
	port := oshFreePort(t)
	cfg := filepath.Join(l.dir, "sshd_endpoint_b.config")
	body := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PerSourcePenalties no
PidFile %s
LogLevel VERBOSE
`, port, l.hostKeys[0], filepath.Join(l.dir, "authorized_keys"), filepath.Join(l.dir, "sshd_endpoint_b.pid"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(l.dir, "sshd_endpoint_b.log"))
	if err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command(l.sshd, "-D", "-e", "-f", cfg) // #nosec G204 -- the test's own sshd and configuration
	daemon.Stdout, daemon.Stderr = logFile, logFile
	if err := daemon.Start(); err != nil {
		t.Fatalf("start the second sshd: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
		_ = logFile.Close()
	})
	oshWaitForPort(t, port)
	return port
}

// oshCountInLog counts the lines of an sshd log that contain needle.
func oshCountInLog(t *testing.T, path, needle string) int {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a log the test wrote in its own directory
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), needle)
}

// D's ADV M1 against real OpenSSH and the library API. One host key is trusted at two loopback
// endpoints. Discovery of the first endpoint returns an identity, and a credential sent to the second
// endpoint with that identity must not reach it. The second sshd logs each password it is sent.
func TestOpenSSHDiscoveredIdentityDoesNotAuthorizeAnotherEndpoint(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	portA := l.port
	portB := oshStartPasswordEndpoint(t, l)
	logB := filepath.Join(l.dir, "sshd_endpoint_b.log")
	hostKey := l.hostKeys[0]

	// Both endpoints are trusted with the same key.
	l.writeKnown(t,
		l.record(hostKey, "", "[127.0.0.1]:"+strconv.Itoa(portA)),
		l.record(hostKey, "", "[127.0.0.1]:"+strconv.Itoa(portB)),
	)
	l.useConfig(t, l.baseConfig(l.known, ""))

	ctx := context.Background()
	tgA, err := Resolve(ctx, "127.0.0.1", portA, l.login)
	if err != nil {
		t.Fatalf("resolve endpoint A: %v", err)
	}
	tgB, err := Resolve(ctx, "127.0.0.1", portB, l.login)
	if err != nil {
		t.Fatalf("resolve endpoint B: %v", err)
	}

	d := Discover(ctx, tgA, oshOptions())
	if d.Outcome != Discovered || !d.Identity.Valid() {
		t.Fatalf("discovery of endpoint A: outcome %q, identity %+v (%s)", d.Outcome, d.Identity, d.Detail)
	}

	before := oshCountInLog(t, logB, "Failed password")
	r := Verify(ctx, tgB, Attempt{Method: MethodPassword, Password: []byte("netdoc-not-the-password"), Identity: d.Identity}, oshOptions())
	sent := oshCountInLog(t, logB, "Failed password") - before
	if sent != 0 || r.Outcome != HostKeyChanged {
		t.Fatalf("a discovery of endpoint A authorized a credential to endpoint B: outcome %q, passwords that reached B %d", r.Outcome, sent)
	}

	// The endpoint the discovery reached still verifies with its own identity.
	ok := Verify(ctx, tgA, Attempt{Method: MethodKey, KeyPath: l.clientKey, Identity: d.Identity}, oshOptions())
	if ok.Outcome != Verified {
		t.Fatalf("verification at endpoint A with its own discovery: outcome %q (%s), want verified", ok.Outcome, ok.Detail)
	}

	// Host aliases name the same endpoint when they resolve to the same host and port. An alias that
	// resolves to another port is another endpoint, so the discovery does not reach it.
	t.Run("aliases", func(t *testing.T) {
		cfg := filepath.Join(l.dir, "ssh_config_aliases")
		body := fmt.Sprintf("Host endpoint-a\n  HostName 127.0.0.1\n  Port %d\n  User %s\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile none\n"+
			"Host endpoint-b\n  HostName 127.0.0.1\n  Port %d\n  User %s\n  UserKnownHostsFile %s\n  GlobalKnownHostsFile none\n",
			portA, l.login, l.known, portB, l.login, l.known)
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		saved := sshTestArgs
		sshTestArgs = []string{"-F", cfg}
		t.Cleanup(func() { sshTestArgs = saved })

		aliasA, err := Resolve(ctx, "endpoint-a", 0, l.login)
		if err != nil {
			t.Fatalf("resolve endpoint-a: %v", err)
		}
		aliasB, err := Resolve(ctx, "endpoint-b", 0, l.login)
		if err != nil {
			t.Fatalf("resolve endpoint-b: %v", err)
		}
		discovered := Discover(ctx, aliasA, oshOptions())
		if discovered.Outcome != Discovered || !discovered.Identity.Valid() {
			t.Fatalf("discovery through endpoint-a: outcome %q (%s)", discovered.Outcome, discovered.Detail)
		}

		same := Verify(ctx, tgA, Attempt{Method: MethodKey, KeyPath: l.clientKey, Identity: discovered.Identity}, oshOptions())
		if same.Outcome != Verified {
			t.Fatalf("the same endpoint under its address (%s) refused the identity: outcome %q (%s)", aliasA.Host, same.Outcome, same.Detail)
		}

		before := oshCountInLog(t, logB, "Accepted publickey")
		other := Verify(ctx, aliasB, Attempt{Method: MethodKey, KeyPath: l.clientKey, Identity: discovered.Identity}, oshOptions())
		accepted := oshCountInLog(t, logB, "Accepted publickey") - before
		if other.Outcome != HostKeyChanged || accepted != 0 {
			t.Fatalf("an identity discovered through endpoint-a authorized endpoint-b: outcome %q, keys accepted at endpoint-b %d", other.Outcome, accepted)
		}
	})
}
