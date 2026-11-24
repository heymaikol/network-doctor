package sshverify

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// certifiedSigner signs host with ca as a host certificate that carries keyID, and returns the
// signer that presents it. The key ID is text the signer chose.
func certifiedSigner(t *testing.T, ca, host ssh.Signer, keyID string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             host.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           keyID,
		ValidPrincipals: []string{testHost},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// forgedCertTranscript replaces the presented host-certificate line in the real trust-cert
// fixture with a certificate carrying keyID followed by OpenSSH's refusal, so the transcript has
// the real prefix and fails only because the key ID forged lines in front of a refused key.
func forgedCertTranscript(t *testing.T, subject, keyID string, ca ssh.PublicKey) string {
	t.Helper()
	base := fixture(t, "trust-cert")
	lines := splitTranscript([]byte(base))
	for i, l := range lines {
		if strings.HasPrefix(l, "debug1: Server host certificate: ") {
			certLine := "debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com " + subject + ", serial 0 ID \"" + keyID + "\" CA " +
				ca.Type() + " " + ssh.FingerprintSHA256(ca) + " valid forever"
			prefix := strings.Join(lines[:i], "\n")
			return prefix + "\n" + certLine + "\nNo ED25519-CERT host key is known for [127.0.0.1]:PORT and you have requested strict checking.\nHost key verification failed.\n"
		}
	}
	t.Fatal("trust-cert fixture has no Server host certificate line")
	return ""
}

// trustedCertTranscript adapts the real trust-cert fixture to name subject, keyID, and ca so
// parseHostTrust genuinely accepts it and downstream pinCheck enforcement is exercised.
func trustedCertTranscript(t *testing.T, subject, keyID string, ca ssh.PublicKey) string {
	t.Helper()
	base := fixture(t, "trust-cert")
	oldFP := presentedFingerprint(t, base)
	m := shapeCertLine.FindStringSubmatch(base[strings.Index(base, "debug1: Server host certificate: "):strings.Index(base, "\ndebug1: Host '")])
	if m == nil {
		t.Fatal("trust-cert fixture certificate line did not match shapeCertLine")
	}
	out := strings.Replace(base, oldFP, subject, 1)
	out = strings.Replace(out, `ID "hostcert"`, `ID "`+keyID+`"`, 1)
	out = strings.Replace(out, "CA "+m[5]+" "+m[6], "CA "+ca.Type()+" "+ssh.FingerprintSHA256(ca), 1)
	return out
}

// A key ID with line breaks makes the server's text read as OpenSSH lines: a match and an
// authentication step, both forged. The parser sees the transcript exactly as OpenSSH would print
// it, and the server chose every byte of it. No credential may be sent on that evidence.
func TestForgedKeyIDTranscriptNeverAuthorizesACredential(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	keyID := "x\" CA ssh-ed25519 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" +
		"debug1: Host '[127.0.0.1]:PORT' is known and matches the ED25519-CERT host certificate.\n" +
		"debug1: SSH2_MSG_NEWKEYS sent\n" +
		"debug1: expecting SSH2_MSG_NEWKEYS\n" +
		"debug1: SSH2_MSG_NEWKEYS received\n" +
		"debug1: SSH2_MSG_SERVICE_ACCEPT received\n" +
		"debug1: Authentications that can continue: password\n" +
		"debug1: No more authentication methods to try.\n" +
		"user@127.0.0.1: Permission denied (password).\n" +
		"debug1: x"
	signer := certifiedSigner(t, ca, host, keyID)
	s := passwordServer(signer)
	transcript := forgedCertTranscript(t, ssh.FingerprintSHA256(host.PublicKey()), keyID, ca.PublicKey())
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return parseHostTrust([]byte(transcript), 255)
	})

	r := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if got := s.password.Load(); got != 0 {
		t.Fatalf("a credential was sent on a forged transcript: %d attempts (outcome %q)", got, r.Outcome)
	}
	if r.Outcome == Verified {
		t.Fatal("a forged transcript verified the server")
	}
}

// The probe and the credential connection can see different certificates for the same key: the
// server rotated its key ID, or a second server answered. The probe's transcript names the key ID
// it printed. The credential connection presents a certificate for the same key with another key
// ID, and must be refused by pinCheck before any credential is sent.
func TestCredentialConnectionMustPresentTheKeyIDOpenSSHChecked(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	checked := certifiedSigner(t, ca, host, "checked-id")
	rotated := certifiedSigner(t, ca, host, "rotated-id")
	transcript := trustedCertTranscript(t, ssh.FingerprintSHA256(host.PublicKey()), "checked-id", ca.PublicKey())

	trust, ok, pr := parseHostTrust([]byte(transcript), 255)
	if !ok || !trust.certificate || trust.keyID != "checked-id" {
		t.Fatalf("positive control failed: parseHostTrust = %+v (trusted %v, %+v)", trust, ok, pr)
	}
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return parseHostTrust([]byte(transcript), 255)
	})

	s := passwordServer(rotated)
	r := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if s.dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1 so pinCheck itself was exercised (outcome %q, %s)", s.dials.Load(), r.Outcome, r.Detail)
	}
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q (%s), want %q", r.Outcome, r.Detail, HostKeyChanged)
	}
	if got := s.password.Load(); got != 0 {
		t.Fatalf("a credential was sent for a key ID OpenSSH did not check: %d attempts (outcome %q)", got, r.Outcome)
	}

	// Control: presenting the checked key ID verifies with one password.
	ctrl := passwordServer(checked)
	cr := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, ctrl.options())
	if cr.Outcome != Verified || ctrl.password.Load() != 1 {
		t.Fatalf("control failed: outcome=%q (%s) passwords=%d", cr.Outcome, cr.Detail, ctrl.password.Load())
	}
}

// Even if the probe's parsed key ID matches the presented certificate's key ID, pinCheck refuses
// any key ID containing a control character before sending a credential.
func TestCredentialConnectionRefusesControlCharacterKeyID(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	ctrlID := "checked\rid"
	signer := certifiedSigner(t, ca, host, ctrlID)
	s := passwordServer(signer)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{
			algorithm:   signer.PublicKey().Type(),
			fingerprint: ssh.FingerprintSHA256(host.PublicKey()),
			certificate: true,
			keyID:       ctrlID,
		}, true, Result{}
	})

	r := VerifyDirect(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if s.dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1 so pinCheck was exercised", s.dials.Load())
	}
	if r.Outcome != HostKeyChanged || s.password.Load() != 0 {
		t.Fatalf("control-character key ID was not refused: outcome=%q passwords=%d (%s)", r.Outcome, s.password.Load(), r.Detail)
	}
}

// OpenSSH prints "Executing" when a configured command runs, and that command's standard error
// reaches the same stream as the probe's own lines. A transcript that shows a configured command
// ran is not evidence of a decision, whatever else it says.
func TestConfiguredCommandOutputIsNeverEvidence(t *testing.T) {
	base := fixture(t, "trust-plain")
	if _, ok, r := parseHostTrust([]byte(base), 255); !ok {
		t.Fatalf("positive control failed: %+v", r)
	}
	withExec := after(t, base, "Reading configuration data", "debug1: Executing command: 'echo forged'")
	if _, ok, r := parseHostTrust([]byte(withExec), 255); ok {
		t.Fatalf("a transcript that shows a configured command ran was trusted: %+v", r)
	}
}
