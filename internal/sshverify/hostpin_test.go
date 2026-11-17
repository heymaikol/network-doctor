package sshverify

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsForAll is a known_hosts file that trusts every key given for the
// test host, as a user who has connected with more than one key would have.
func knownHostsForAll(t *testing.T, keys ...ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	var body []byte
	for _, k := range keys {
		body = append(body, knownhosts.Line([]string{"[" + testHost + "]:" + strconv.Itoa(testPort)}, k)...)
		body = append(body, '\n')
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The discovery saw host key A. Between that and the credential, the server
// presents key B, which known_hosts also trusts. Without a pin the credential
// goes to B; with the pin it is refused before auth and nothing is sent.
func TestPinnedHostKeyRefusesAKeyThatMovedBeforeAuth(t *testing.T) {
	keyA, _ := newEd25519(t)
	keyB, _ := newEd25519(t)
	known := knownHostsForAll(t, keyA.PublicKey(), keyB.PublicKey())
	moved := passwordServer(keyB)
	opts := moved.options()
	opts.PinHostKey = ssh.FingerprintSHA256(keyA.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)

	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want host key changed; detail %q", r.Outcome, r.Detail)
	}
	if got := moved.password.Load(); got != 0 {
		t.Fatalf("a credential reached a host key that moved after discovery: %d attempts", got)
	}
	if r.HostKey != ssh.FingerprintSHA256(keyB.PublicKey()) {
		t.Errorf("the result should name the key presented, got %q", r.HostKey)
	}
}

// The same server and the same known_hosts file, with no pin: this is the case
// the pin exists for. If it did not reach auth, the pin test above would prove
// nothing.
func TestWithoutAPinTheTrustedSecondKeyIsUsed(t *testing.T) {
	keyA, _ := newEd25519(t)
	keyB, _ := newEd25519(t)
	known := knownHostsForAll(t, keyA.PublicKey(), keyB.PublicKey())
	moved := passwordServer(keyB)

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, moved.options())

	if r.Outcome != Verified || moved.password.Load() != 1 {
		t.Fatalf("outcome = %q with %d attempts; the control should reach auth", r.Outcome, moved.password.Load())
	}
}

func TestPinnedHostKeyAcceptsTheSameKey(t *testing.T) {
	keyA, _ := newEd25519(t)
	s := passwordServer(keyA)
	known := knownHostsFor(t, keyA.PublicKey())
	opts := s.options()
	opts.PinHostKey = ssh.FingerprintSHA256(keyA.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)

	if r.Outcome != Verified || s.password.Load() != 1 {
		t.Fatalf("outcome = %q with %d attempts, want verified once", r.Outcome, s.password.Load())
	}
}

// An unknown key the user confirmed is the other accept path. The pin must hold
// there too, so a key the user did not confirm cannot take its place.
func TestPinAppliesToAKeyTrustedForOneCheck(t *testing.T) {
	keyA, _ := newEd25519(t)
	keyB, _ := newEd25519(t)
	fpA := ssh.FingerprintSHA256(keyA.PublicKey())
	fpB := ssh.FingerprintSHA256(keyB.PublicKey())

	cases := []struct {
		name    string
		serve   ssh.Signer
		pin     string
		outcome Outcome
		sent    int32
	}{
		{"same key as the pin", keyA, fpA, Verified, 1},
		{"a different key than the pin", keyB, fpA, HostKeyChanged, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := passwordServer(c.serve)
			opts := s.options()
			opts.TrustHostKey = fpB
			if c.serve == keyA {
				opts.TrustHostKey = fpA
			}
			opts.PinHostKey = c.pin

			r := Verify(context.Background(), target(emptyKnownHosts(t)), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)

			if r.Outcome != c.outcome || s.password.Load() != c.sent {
				t.Fatalf("outcome = %q with %d attempts, want %q with %d", r.Outcome, s.password.Load(), c.outcome, c.sent)
			}
		})
	}
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
