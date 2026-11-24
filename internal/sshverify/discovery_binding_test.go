package sshverify

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Discovery showed host key A. OpenSSH now trusts host key B, and the server presents B. The
// check must refuse B before it connects for the credential, so no password reaches the server.
func TestVerifyRefusesAKeyOtherThanTheDiscoveredOne(t *testing.T) {
	shown, _ := newEd25519(t)
	changed, _ := newEd25519(t)
	s := passwordServer(changed)
	trustOpenSSH(t, changed.PublicKey())

	a := Attempt{Method: MethodPassword, Password: []byte(testPassword), HostKey: ssh.FingerprintSHA256(shown.PublicKey())}
	r := Verify(context.Background(), target(), a, s.options())

	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want host key changed; detail %q", r.Outcome, r.Detail)
	}
	if got := s.dials.Load(); got != 0 {
		t.Errorf("netdoc connected %d time(s) for the credential after the host key changed", got)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a key other than the one discovery showed: %d attempts", got)
	}
	if want := ssh.FingerprintSHA256(changed.PublicKey()); r.HostKey != want {
		t.Errorf("the key reported = %q, want the key the server presented %q", r.HostKey, want)
	}
}

// Discovery showed the key that OpenSSH trusts and the server presents, so the check proceeds.
func TestVerifyAcceptsTheDiscoveredHostKey(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	a := Attempt{Method: MethodPassword, Password: []byte(testPassword), HostKey: ssh.FingerprintSHA256(host.PublicKey())}
	r := Verify(context.Background(), target(), a, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("password attempts = %d, want 1", got)
	}
}

// Without a discovery there is no key to bind to. OpenSSH's decision alone governs the check, as
// it does for a direct verification, so the trusted key verifies.
func TestVerifyWithoutDiscoveryTrustsOpenSSHAlone(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("password attempts = %d, want 1", got)
	}
}

// A discovery reports the fingerprint of the key it trusted, which is the value a later check binds.
func TestDiscoverReportsTheHostKeyItTrusted(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	r := Discover(context.Background(), target(), s.options())

	if r.Outcome != Discovered {
		t.Fatalf("outcome = %q, want discovered; detail %q", r.Outcome, r.Detail)
	}
	if want := ssh.FingerprintSHA256(host.PublicKey()); r.HostKey != want {
		t.Errorf("host key = %q, want %q", r.HostKey, want)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a discovery sent %d credential attempt(s)", got)
	}
}
