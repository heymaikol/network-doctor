package sshverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// mustECDSAKey returns a P-256 host key, for a server whose second key has another algorithm.
func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// passwordServerWith is passwordServer for a server that holds several host keys.
func passwordServerWith(keys ...ssh.Signer) *server {
	s := newServer(keys...)
	s.cfg.PasswordCallback = func(conn ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		s.password.Add(1)
		if string(pw) == testPassword {
			return nil, nil
		}
		return nil, errors.New("denied")
	}
	return s
}

// OpenSSH trusted key A. The server presents key B, so the credential connection refuses B
// before any credential is sent, and the result names B.
func TestPinRefusesAKeyThatMovedAfterOpenSSHTrustedIt(t *testing.T) {
	keyA, _ := newEd25519(t)
	keyB, _ := newEd25519(t)
	moved := passwordServer(keyB)
	trustOpenSSH(t, keyA.PublicKey())

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, moved.options())

	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want host key changed; detail %q", r.Outcome, r.Detail)
	}
	if got := moved.password.Load(); got != 0 {
		t.Fatalf("a credential reached a host key OpenSSH did not trust: %d attempts", got)
	}
	if r.HostKey != ssh.FingerprintSHA256(keyB.PublicKey()) {
		t.Errorf("the result should name the key presented, got %q", r.HostKey)
	}
}

// OpenSSH trusted the key the server presents: the credential is sent once and accepted.
func TestPinAcceptsTheKeyOpenSSHTrusted(t *testing.T) {
	key, _ := newEd25519(t)
	s := passwordServer(key)
	trustOpenSSH(t, key.PublicKey())

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("password attempts = %d, want 1", got)
	}
}

// A server with two host keys negotiates the algorithm OpenSSH negotiated. The credential
// connection offers that one algorithm, so each of the two keys verifies in turn.
func TestPinFollowsTheAlgorithmOpenSSHNegotiated(t *testing.T) {
	ed, _ := newEd25519(t)
	ec := mustSigner(t, mustECDSAKey(t))
	for _, trusted := range []ssh.Signer{ed, ec} {
		s := passwordServerWith(ed, ec)
		trustOpenSSH(t, trusted.PublicKey())
		r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
		if r.Outcome != Verified {
			t.Fatalf("trusting %s: outcome = %q, want verified; detail %q", trusted.PublicKey().Type(), r.Outcome, r.Detail)
		}
	}
}

// A host certificate is pinned by the key it certifies. The probe names that subject key, and
// the credential connection accepts the certificate that carries it.
func TestPinAcceptsACertificateBySubjectKey(t *testing.T) {
	ca, _ := newEd25519(t)
	hostSigner, _ := newEd25519(t)
	cert := signedHostCertificate(t, ca, hostSigner.PublicKey())
	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	s := passwordServer(certSigner)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: cert.Type(), fingerprint: ssh.FingerprintSHA256(hostSigner.PublicKey())}, true, Result{}
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
}

// The certificate blob is not the key it certifies. A pin on the blob's fingerprint is refused.
func TestPinRefusesACertificateBlobFingerprint(t *testing.T) {
	ca, _ := newEd25519(t)
	hostSigner, _ := newEd25519(t)
	cert := signedHostCertificate(t, ca, hostSigner.PublicKey())
	certSigner, err := ssh.NewCertSigner(cert, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	s := passwordServer(certSigner)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: cert.Type(), fingerprint: ssh.FingerprintSHA256(cert)}, true, Result{}
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want host key changed for a blob fingerprint; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent under a blob fingerprint: %d attempts", got)
	}
}

// signedHostCertificate issues a host certificate for the test host, signed by ca.
func signedHostCertificate(t *testing.T, ca ssh.Signer, key ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             key,
		CertType:        ssh.HostCert,
		KeyId:           "hostcert",
		ValidPrincipals: []string{testHost},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestValidFingerprint(t *testing.T) {
	key, _ := newEd25519(t)
	valid := ssh.FingerprintSHA256(key.PublicKey())
	if !ValidFingerprint(valid) {
		t.Fatalf("a fingerprint ssh prints must be valid: %q", valid)
	}
	zeros := "SHA256:" + strings.Repeat("A", 43) // 43 characters decode to 32 zero bytes
	cases := map[string]bool{
		"":                               false,
		valid + " ":                      false,
		"sha256" + valid[len("SHA256"):]: false,
		valid[len("SHA256:"):]:           false,
		"SHA256:":                        false,
		"SHA256:short":                   false,
		valid + "=":                      false,
		valid[:len(valid)-1] + "B":       false, // non-zero bits past the 256-bit digest
		valid[:len(valid)-1] + "!":       false,
		zeros:                            true,
	}
	for fp, want := range cases {
		if got := ValidFingerprint(fp); got != want {
			t.Errorf("ValidFingerprint(%q) = %v, want %v", fp, got, want)
		}
	}
}

func TestKeyNeedsPassphraseNamesTheProblem(t *testing.T) {
	dir := t.TempDir()
	plain, _ := writeKey(t, dir, "plain", "")
	locked, _ := writeKey(t, dir, "locked", testPassphrase)
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if needs, err := KeyNeedsPassphrase(plain); needs || err != nil {
		t.Errorf("plain key: needs %v, err %v", needs, err)
	}
	if needs, err := KeyNeedsPassphrase(locked); !needs || err != nil {
		t.Errorf("encrypted key: needs %v, err %v; want a passphrase", needs, err)
	}
	if _, err := KeyNeedsPassphrase(filepath.Join(dir, "absent")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err %v, want not exist", err)
	}
	if _, err := KeyNeedsPassphrase(dir); !errors.Is(err, ErrKeyNotRegular) {
		t.Errorf("a directory: err %v, want not a regular file", err)
	}
	if _, err := KeyNeedsPassphrase(garbage); !errors.Is(err, ErrKeyNotPrivate) {
		t.Errorf("a non-key file: err %v, want not a private key", err)
	}
}

// OpenSSH's decision can name a host key algorithm the SSH library cannot negotiate. The
// credential connection then fails before any credential is sent, and never verifies.
func TestPinRefusesAnAlgorithmTheLibraryCannotNegotiate(t *testing.T) {
	key, _ := newEd25519(t)
	s := passwordServer(key)
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: "ssh-mldsa-65", fingerprint: ssh.FingerprintSHA256(key.PublicKey())}, true, Result{}
	})

	r := Verify(context.Background(), target(), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome == Verified {
		t.Fatal("a host key algorithm the library cannot negotiate verified")
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent over an algorithm the library cannot negotiate: %d attempts", got)
	}
}
