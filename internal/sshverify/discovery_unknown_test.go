package sshverify

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Discovery sends no credential, and a host key OpenSSH does not know must stop it before any
// connection. Verify's unknown-key test covers the credential path; this covers discovery.
func TestDiscoverUnknownKeyStopsBeforeAnyConnection(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	refuseOpenSSH(t, Result{Outcome: HostKeyUnknown, HostKey: ssh.FingerprintSHA256(host.PublicKey()), Detail: "OpenSSH has no record of this host key; establish trust with your normal SSH client first"})

	r := Discover(context.Background(), target(), s.options())

	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q (%s), want host key unknown", r.Outcome, r.Detail)
	}
	if got := s.dials.Load(); got != 0 {
		t.Errorf("discovery connected %d time(s) after OpenSSH did not trust the key", got)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to an unknown host: %d attempts", got)
	}
}
