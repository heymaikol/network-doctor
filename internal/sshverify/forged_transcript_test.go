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

// forgedCertTranscript is the transcript OpenSSH prints for a host certificate whose key ID is
// keyID, printed raw as OpenSSH prints it. The algorithm line comes first, as it does for real.
func forgedCertTranscript(certType, subject, keyID string, ca ssh.PublicKey) string {
	return "debug1: kex: host key algorithm: " + certType + "\n" +
		"debug1: Server host certificate: " + certType + " " + subject + ", serial 1 ID \"" + keyID + "\" CA " +
		ca.Type() + " " + ssh.FingerprintSHA256(ca) + "\n" +
		"debug1: No more authentication methods to try.\n"
}

// trustedCertTranscript is the transcript OpenSSH prints when it trusts a host certificate whose
// key ID is keyID: the certificate line, the match and the authentication step that follow it.
func trustedCertTranscript(certType, subject, keyID string, ca ssh.PublicKey) string {
	return forgedCertTranscript(certType, subject, keyID, ca) +
		"debug1: Host '" + testHost + "' is known and matches the ED25519-CERT host certificate.\n" +
		"debug1: Authentications that can continue: password\n"
}

// A key ID with line breaks makes the server's text read as OpenSSH lines: a match and an
// authentication step, both forged. The parser sees the transcript exactly as OpenSSH would print
// it, and the server chose every byte of it. No credential may be sent on that evidence.
func TestForgedKeyIDTranscriptNeverAuthorizesACredential(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	keyID := "x\ndebug1: Host '" + testHost + "' is known and matches the ED25519-CERT host certificate.\ndebug1: Authentications that can continue: password\ndebug1: x"
	signer := certifiedSigner(t, ca, host, keyID)
	s := passwordServer(signer)
	transcript := forgedCertTranscript(signer.PublicKey().Type(), ssh.FingerprintSHA256(host.PublicKey()), keyID, ca.PublicKey())
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return parseHostTrust([]byte(transcript), 255)
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

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
// ID, and must be refused before any credential is sent.
func TestCredentialConnectionMustPresentTheKeyIDOpenSSHChecked(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	rotated := certifiedSigner(t, ca, host, "rotated-id")
	s := passwordServer(rotated)
	transcript := trustedCertTranscript(rotated.PublicKey().Type(), ssh.FingerprintSHA256(host.PublicKey()), "checked-id", ca.PublicKey())
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return parseHostTrust([]byte(transcript), 255)
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if got := s.password.Load(); got != 0 {
		t.Fatalf("a credential was sent for a key ID OpenSSH did not check: %d attempts (outcome %q)", got, r.Outcome)
	}
}

// Every presented-key record must be one of OpenSSH's two forms in full. A line that starts a
// record and is neither form refuses the transcript, even when the rest of it reads as trust.
func TestPresentedRecordMustBeOneOfOpenSSHsFormsInFull(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	certType := ssh.CertAlgoED25519v01
	subject := ssh.FingerprintSHA256(host.PublicKey())
	keyLine := "debug1: Server host key: ssh-ed25519 " + subject + "\n"
	matchKey := "debug1: Host '" + testHost + "' is known and matches the ED25519 host key.\n"
	auth := "debug1: Authentications that can continue: password\n"
	kex := "debug1: kex: host key algorithm: ssh-ed25519\n"

	if _, ok, r := parseHostTrust([]byte(kex+keyLine+matchKey+auth), 255); !ok {
		t.Fatalf("a complete plain-key transcript was refused: %+v", r)
	}
	if _, ok, r := parseHostTrust([]byte(trustedCertTranscript(certType, subject, "hostcert", ca.PublicKey())), 255); !ok {
		t.Fatalf("a complete certificate transcript was refused: %+v", r)
	}
	malformed := map[string]string{
		"certificate line cut at a line break": kex + "debug1: Server host certificate: " + certType + " " + subject + ", serial 1 ID \"x\n" + matchKey + auth,
		"certificate line with no CA":          kex + "debug1: Server host certificate: " + certType + " " + subject + ", serial 1 ID \"x\"\n" + matchKey + auth,
		"key line with a trailing field":       kex + "debug1: Server host key: ssh-ed25519 " + subject + " injected\n" + matchKey + auth,
		"key line with no fingerprint":         kex + "debug1: Server host key: ssh-ed25519\n" + matchKey + auth,
	}
	for name, tr := range malformed {
		if _, ok, r := parseHostTrust([]byte(tr), 255); ok || r.Outcome != TransportFailure {
			t.Errorf("%s: trusted or misclassified (%+v)", name, r)
		}
	}
}

// The "none" acceptance line counts as the authentication step only after the match. Before the
// match, it is text the server could have written, and it must not authorize anything.
func TestNoneAcceptanceCountsOnlyAfterTheMatch(t *testing.T) {
	kex := "debug1: kex: host key algorithm: ssh-ed25519\n"
	key := "debug1: Server host key: ssh-ed25519 SHA256:" + strings.Repeat("A", 43) + "\n"
	match := "debug1: Host '" + testHost + "' is known and matches the ED25519 host key.\n"
	accepted := "Authenticated to " + testHost + " ([127.0.0.1]:2622) using \"none\".\n"
	if _, ok, r := parseHostTrust([]byte(kex+key+match+accepted), 255); !ok {
		t.Fatalf("a decision followed by none acceptance was refused: %+v", r)
	}
	if _, ok, _ := parseHostTrust([]byte(kex+key+accepted+match), 255); ok {
		t.Fatal("none acceptance before the match authorized trust")
	}
}

// OpenSSH prints "Executing" when a configured command runs, and that command's standard error
// reaches the same stream as the probe's own lines. A transcript that shows a configured command
// ran is not evidence of a decision, whatever else it says.
func TestConfiguredCommandOutputIsNeverEvidence(t *testing.T) {
	kex := "debug1: kex: host key algorithm: ssh-ed25519\n"
	key := "debug1: Server host key: ssh-ed25519 SHA256:" + strings.Repeat("A", 43) + "\n"
	match := "debug1: Host '" + testHost + "' is known and matches the ED25519 host key.\n"
	auth := "debug1: Authentications that can continue: password\n"
	ran := "debug1: Executing command: 'echo forged'\n"
	if _, ok, r := parseHostTrust([]byte(ran+kex+key+match+auth), 255); ok {
		t.Fatalf("a transcript that shows a configured command ran was trusted: %+v", r)
	}
}
