package sshverify

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

// discoverTrusting runs a real discovery of the host that the probe trusts as trusted and the server
// presents as presented, and returns the identity the discovery reported.
func discoverTrusting(t *testing.T, trusted hostTrust, presented ssh.Signer) (HostIdentity, *server) {
	t.Helper()
	s := passwordServer(presented)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) { return trusted, true, Result{} })
	d := Discover(context.Background(), target(), s.options())
	if d.Outcome != Discovered || !d.Identity.Valid() {
		t.Fatalf("discovery: outcome %q, identity %+v (%s)", d.Outcome, d.Identity, d.Detail)
	}
	return d.Identity, s
}

// Discovery showed host key A. OpenSSH now trusts host key B, and the server presents B. The check
// is bound to A, so it must refuse B before it connects for the credential.
func TestVerifyRefusesAKeyOtherThanTheDiscoveredOne(t *testing.T) {
	shown, _ := newEd25519(t)
	changed, _ := newEd25519(t)
	id, _ := discoverTrusting(t, hostTrust{algorithm: "ssh-ed25519", fingerprint: ssh.FingerprintSHA256(shown.PublicKey())}, shown)

	s := passwordServer(changed)
	trustOpenSSH(t, changed.PublicKey())
	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: id}, s.options())

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
	id, _ := discoverTrusting(t, hostTrust{algorithm: "ssh-ed25519", fingerprint: ssh.FingerprintSHA256(host.PublicKey())}, host)

	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())
	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: id}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("password attempts = %d, want 1", got)
	}
}

// Without a discovery there is no identity to bind to, and Verify refuses before anything runs. The
// same check made directly, with VerifyDirect, lets OpenSSH's decision alone govern it.
func TestVerifyRefusesAnUnboundCheckAndVerifyDirectTrustsOpenSSH(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	probes := 0
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		probes++
		return hostTrust{algorithm: "ssh-ed25519", fingerprint: ssh.FingerprintSHA256(host.PublicKey())}, true, Result{}
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != LocalFailure || probes != 0 || s.dials.Load() != 0 || s.password.Load() != 0 {
		t.Fatalf("an unbound check: outcome %q, probes %d, dials %d, passwords %d; want refused before anything ran",
			r.Outcome, probes, s.dials.Load(), s.password.Load())
	}

	d := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if d.Outcome != Verified || s.password.Load() != 1 {
		t.Fatalf("VerifyDirect: outcome %q (%s), passwords %d; want verified with one password", d.Outcome, d.Detail, s.password.Load())
	}
}

// VerifyDirect does not bind. An attempt that carries an identity meant to bind, so it is refused.
func TestVerifyDirectRefusesAnAttemptThatCarriesAnIdentity(t *testing.T) {
	host, _ := newEd25519(t)
	id, _ := discoverTrusting(t, hostTrust{algorithm: "ssh-ed25519", fingerprint: ssh.FingerprintSHA256(host.PublicKey())}, host)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	r := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: id}, s.options())
	if r.Outcome != LocalFailure || s.dials.Load() != 0 || s.password.Load() != 0 {
		t.Fatalf("VerifyDirect with an identity: outcome %q, dials %d, passwords %d; want refused with nothing sent", r.Outcome, s.dials.Load(), s.password.Load())
	}
}

// A malformed identity is refused before anything runs, however the trusted host looks.
func TestVerifyRefusesAMalformedIdentityBeforeAnythingRuns(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	probes := 0
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		probes++
		return hostTrust{algorithm: "ssh-ed25519", fingerprint: ssh.FingerprintSHA256(host.PublicKey())}, true, Result{}
	})
	bad := HostIdentity{Fingerprint: "SHA256:short", Algorithm: "ssh-ed25519"}

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: bad}, s.options())
	if r.Outcome != LocalFailure || probes != 0 || s.password.Load() != 0 {
		t.Fatalf("a malformed identity: outcome %q, probes %d, passwords %d; want refused before anything ran", r.Outcome, probes, s.password.Load())
	}
}

// A plain key and a certificate for the same subject key are different identities. A discovery of
// the plain key does not admit the certificate.
func TestIdentityDistinguishesPlainKeyFromCertificateForTheSameSubject(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())
	plainID, _ := discoverTrusting(t, hostTrust{algorithm: "ssh-ed25519", fingerprint: subject}, host)

	certSigner := certifiedSigner(t, ca, host, "hostcert")
	certTrust := hostTrust{algorithm: certSigner.PublicKey().Type(), fingerprint: subject, certificate: true, keyID: "hostcert", serial: "0", authority: ssh.FingerprintSHA256(ca.PublicKey())}
	s := passwordServer(certSigner)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) { return certTrust, true, Result{} })

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: plainID}, s.options())
	if r.Outcome != HostKeyChanged || s.password.Load() != 0 {
		t.Fatalf("plain-discovered identity admitted a certificate: outcome %q, passwords %d", r.Outcome, s.password.Load())
	}
}

// Two certificates for one subject key with different key IDs are different identities.
func TestIdentityDistinguishesCertificatesByKeyID(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())
	authority := ssh.FingerprintSHA256(ca.PublicKey())
	discovered := hostTrust{algorithm: "ssh-ed25519-cert-v01@openssh.com", fingerprint: subject, certificate: true, keyID: "id-a", serial: "0", authority: authority}
	id, _ := discoverTrusting(t, discovered, certifiedSigner(t, ca, host, "id-a"))

	rotated := discovered
	rotated.keyID = "id-b"
	s := passwordServer(certifiedSigner(t, ca, host, "id-b"))
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) { return rotated, true, Result{} })
	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword), Identity: id}, s.options())
	if r.Outcome != HostKeyChanged || s.password.Load() != 0 {
		t.Fatalf("a certificate with another key ID was admitted: outcome %q, passwords %d", r.Outcome, s.password.Load())
	}
}

// A discovery reports the identity of the key it trusted, and sends no credential.
func TestDiscoverReportsTheHostKeyItTrusted(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	trustOpenSSH(t, host.PublicKey())

	r := Discover(context.Background(), target(), s.options())

	if r.Outcome != Discovered {
		t.Fatalf("outcome = %q, want discovered; detail %q", r.Outcome, r.Detail)
	}
	if want := ssh.FingerprintSHA256(host.PublicKey()); r.HostKey != want || r.Identity.Fingerprint != want {
		t.Errorf("host key = %q, identity fingerprint = %q, want %q", r.HostKey, r.Identity.Fingerprint, want)
	}
	if !r.Identity.Valid() {
		t.Errorf("the discovered identity is not valid: %+v", r.Identity)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a discovery sent %d credential attempt(s)", got)
	}
}
