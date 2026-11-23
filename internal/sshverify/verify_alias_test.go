package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testAlias is a HostKeyAlias, the name a configuration gives a server so that
// known_hosts can be keyed on it.
const testAlias = "sshverify-alias.test"

// aliasTarget is a target reached through testAlias on the given port.
func aliasTarget(port int, known ...string) Target {
	return Target{Host: testHost, Port: port, User: testUser, KnownHosts: known, HostKeyAlias: testAlias}
}

// knownHostsNamed writes a known_hosts file with one entry under name.
func knownHostsNamed(t *testing.T, name string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{name}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// OpenSSH looks an alias up verbatim, whatever the port. The entry under the alias
// is the one that decides, so a known key verifies on a non-default port too.
func TestAliasKnownKeyVerifiesOnANonDefaultPort(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsNamed(t, testAlias, host.PublicKey())

	r := Verify(context.Background(), aliasTarget(testPort, known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
}

// A changed key recorded under the alias is a change, on the default and on a
// non-default port. It must never be read as unknown, because an unknown key is
// offered a one-check trust override and a changed one is not.
func TestAliasChangedKeyIsChangedNotUnknown(t *testing.T) {
	for _, port := range []int{testPort, 22} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			host, _ := newEd25519(t)
			other, _ := newEd25519(t)
			s := passwordServer(host)
			known := knownHostsNamed(t, testAlias, other.PublicKey())

			r := Verify(context.Background(), aliasTarget(port, known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
			if r.Outcome != HostKeyChanged {
				t.Fatalf("outcome = %q, want host key changed; detail %q", r.Outcome, r.Detail)
			}
			if got := s.password.Load(); got != 0 {
				t.Errorf("a credential was sent to a host whose key changed: %d attempts", got)
			}

			// The fingerprint shown for a changed key must not work as a trust override.
			opts := s.options()
			opts.TrustHostKey = r.HostKey
			again := Verify(context.Background(), aliasTarget(port, known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)
			if again.Outcome != HostKeyChanged {
				t.Fatalf("with the presented fingerprint confirmed, outcome = %q, want host key changed", again.Outcome)
			}
			if got := s.password.Load(); got != 0 {
				t.Errorf("a credential was sent after a trust override for a changed key: %d attempts", got)
			}
		})
	}
}

// The name under an alias is the alias alone. An entry bracketed with the alias and
// the port is a different name, so OpenSSH does not find it, and the key is unknown.
func TestAliasDoesNotMatchTheBracketedPortName(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsNamed(t, "["+testAlias+"]:"+strconv.Itoa(testPort), host.PublicKey())

	r := Verify(context.Background(), aliasTarget(testPort, known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q, want host key unknown; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to an unknown host: %d attempts", got)
	}
}
