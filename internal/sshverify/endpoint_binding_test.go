package sshverify

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A discovery names the endpoint it reached, and the identity it returns is bound to that endpoint.
// The same key can be trusted at a second endpoint, and a credential for that endpoint must not be
// authorized by the first discovery. This is D's ADV M1: discovery of a.example, then a credential
// to b.example that presents the same trusted key.
func TestVerifyRefusesADiscoveredIdentityAtAnotherEndpoint(t *testing.T) {
	host, _ := newEd25519(t)
	fp := ssh.FingerprintSHA256(host.PublicKey())
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: "ssh-ed25519", fingerprint: fp}, true, Result{}
	})
	a := Target{Host: "a.example", Port: 22, User: testUser}
	b := Target{Host: "b.example", Port: 22, User: testUser}
	sA, sB := passwordServer(host), passwordServer(host)

	d := Discover(context.Background(), a, sA.options())
	if d.Outcome != Discovered || !d.Identity.Valid() {
		t.Fatalf("discovery of a.example: outcome %q, identity %+v (%s)", d.Outcome, d.Identity, d.Detail)
	}

	r := Verify(context.Background(), b, Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: d.Identity}, sB.options())
	if r.Outcome == Verified || sB.password.Load() != 0 {
		t.Fatalf("a discovery of a.example authorized a credential to b.example: outcome %q, passwords sent to b.example %d",
			r.Outcome, sB.password.Load())
	}

	// The endpoint the discovery reached still verifies with the same identity.
	ok := Verify(context.Background(), a, Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: d.Identity}, sA.options())
	if ok.Outcome != Verified || sA.password.Load() != 1 {
		t.Fatalf("verification at a.example with its own discovery: outcome %q (%s), passwords %d; want verified with one password",
			ok.Outcome, ok.Detail, sA.password.Load())
	}
}

// The endpoint is the dialed host and port, so a different port on the same host is another endpoint,
// and so is a different host name for the same address. Both are refused with nothing sent.
func TestVerifyRefusesADiscoveredIdentityOnAnotherPortOrName(t *testing.T) {
	host, _ := newEd25519(t)
	fp := ssh.FingerprintSHA256(host.PublicKey())
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: "ssh-ed25519", fingerprint: fp}, true, Result{}
	})
	s := passwordServer(host)
	a := Target{Host: "a.example", Port: 22, User: testUser}
	d := Discover(context.Background(), a, s.options())
	if d.Outcome != Discovered {
		t.Fatalf("discovery: outcome %q (%s)", d.Outcome, d.Detail)
	}
	for _, other := range []Target{
		{Host: "a.example", Port: 2222, User: testUser},
		{Host: "A.example", Port: 22, User: testUser},
	} {
		before := s.password.Load()
		r := Verify(context.Background(), other, Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: d.Identity}, s.options())
		if r.Outcome == Verified || s.password.Load() != before {
			t.Fatalf("a discovery of a.example:22 authorized %s:%d: outcome %q, passwords sent %d",
				other.Host, other.Port, r.Outcome, s.password.Load()-before)
		}
	}
}
