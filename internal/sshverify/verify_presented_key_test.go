package sshverify

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A changed key is refused before any credential is sent, and the result names the key the
// server presented. That fingerprint is the only one the user can compare against known_hosts.
func TestChangedKeyReportsThePresentedFingerprint(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	path := dir + "/known_hosts"
	recordChanged(t, path, target())

	r := Verify(context.Background(), target(path), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want a changed key; detail %q", r.Outcome, r.Detail)
	}
	if want := ssh.FingerprintSHA256(host.PublicKey()); r.HostKey != want {
		t.Fatalf("presented fingerprint = %q, want the server's own key %q", r.HostKey, want)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a changed key: %d attempts", got)
	}
}
