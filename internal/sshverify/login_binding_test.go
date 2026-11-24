package sshverify

import (
	"context"
	"testing"
)

// The host key was checked for the login in the target: its configuration, its known_hosts and
// its trust all belong to that login. A credential for another login would authenticate a user
// whose configuration and trust were never checked, so it is refused before anything is sent.
func TestVerifyRefusesALoginOtherThanTheCheckedOne(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	other := Attempt{User: "eve", Method: MethodPassword, Password: []byte(testPassword)}
	r := VerifyDirect(context.Background(), target(), other, s.options())

	if r.Outcome == Verified || s.password.Load() != 0 {
		t.Fatalf("a credential for another login was sent: outcome %q, attempts %d", r.Outcome, s.password.Load())
	}
	if r.Outcome != LocalFailure {
		t.Errorf("outcome = %q (%s), want a local failure that says the login differs", r.Outcome, r.Detail)
	}

	// Control: the checked login verifies with one credential.
	same := Attempt{User: testUser, Method: MethodPassword, Password: []byte(testPassword)}
	if r := VerifyDirect(context.Background(), target(), same, s.options()); r.Outcome != Verified {
		t.Fatalf("the checked login did not verify: %+v", r)
	}
}
