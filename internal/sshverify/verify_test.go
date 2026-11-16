package sshverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// The secret values below exist only inside these tests, and only as the
// credential a test server accepts or refuses.
const (
	testPassword   = "test-password-correct"
	testWrongPass  = "test-password-wrong"
	testPassphrase = "test-passphrase"
	testHost       = "sshverify.test"
	testPort       = 2222
	testUser       = "tester"
)

// server is an in-memory SSH server behind net.Pipe. It counts every
// connection, every authentication callback, and every channel the client
// opens, so a test can assert what was sent rather than what was returned.
type server struct {
	cfg      *ssh.ServerConfig
	dials    atomic.Int32
	password atomic.Int32
	pubkey   atomic.Int32
	kbd      atomic.Int32
	opens    atomic.Int32
}

func newServer(hostKeys ...ssh.Signer) *server {
	cfg := &ssh.ServerConfig{}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	return &server{cfg: cfg}
}

// serve runs the server side of one connection. It refuses every channel and
// counts it, because the check is supposed to open none.
func (s *server) serve(conn net.Conn) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for ch := range chans {
		s.opens.Add(1)
		_ = ch.Reject(ssh.Prohibited, "test server opens no channels")
	}
}

// options returns check options whose dial reaches this server in memory.
func (s *server) options() Options {
	return Options{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			s.dials.Add(1)
			client, srv := bufferedPipe()
			go s.serve(srv)
			return client, nil
		},
	}
}

// passwordServer accepts exactly testPassword and counts each attempt.
func passwordServer(hostKey ssh.Signer) *server {
	s := newServer(hostKey)
	s.cfg.PasswordCallback = func(conn ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		s.password.Add(1)
		if string(pw) == testPassword {
			return nil, nil
		}
		return nil, errors.New("denied")
	}
	return s
}

func newEd25519(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return mustSigner(t, priv), priv
}

func mustSigner(t *testing.T, key any) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// knownHostsFor writes a known_hosts file that trusts key for the test host,
// and returns its path.
func knownHostsFor(t *testing.T, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"[" + testHost + "]:" + strconv.Itoa(testPort)}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// emptyKnownHosts is a known_hosts file that lists no host.
func emptyKnownHosts(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// target returns the test destination, trusting the given known_hosts files.
func target(known ...string) Target {
	return Target{Host: testHost, Port: testPort, User: testUser, KnownHosts: known}
}

func TestVerifyPasswordAcceptedOnce(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsFor(t, host.PublicKey())
	pw := []byte(testPassword)

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: pw}, s.options())

	if r.Outcome != Verified || r.Method != MethodPassword {
		t.Fatalf("outcome = %q method = %q, want verified by password; detail %q", r.Outcome, r.Method, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("server saw %d password attempts, want exactly 1", got)
	}
	if got := s.opens.Load(); got != 0 {
		t.Errorf("server saw %d channel opens, want none: verification must not open a session", got)
	}
	if !bytes.Equal(pw, make([]byte, len(pw))) {
		t.Error("the caller's password slice was not cleared after the check")
	}
}

func TestVerifyPasswordRefusedWithoutRetry(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testWrongPass)}, s.options())

	if r.Outcome != Refused {
		t.Fatalf("outcome = %q, want refused; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("server saw %d password attempts, want exactly 1: netdoc must never guess", got)
	}
}

func TestDiscoverListsMethodsWithoutSendingACredential(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsFor(t, host.PublicKey())

	r := Discover(context.Background(), target(known), s.options())

	if r.Outcome != Discovered {
		t.Fatalf("outcome = %q, want discovered; detail %q", r.Outcome, r.Detail)
	}
	if len(r.Methods) != 1 || r.Methods[0] != "password" {
		t.Errorf("methods = %q, want the server's advertised [password]", r.Methods)
	}
	if got := s.password.Load() + s.pubkey.Load() + s.kbd.Load(); got != 0 {
		t.Errorf("server saw %d credential attempts during discovery, want none", got)
	}
}

func TestVerifyMethodNotOfferedSendsNothing(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		return nil, errors.New("denied")
	}
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != NotOffered {
		t.Fatalf("outcome = %q, want not offered; detail %q", r.Outcome, r.Detail)
	}
	if len(r.Methods) != 1 || r.Methods[0] != "publickey" {
		t.Errorf("methods = %q, want the server's [publickey]", r.Methods)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("server saw %d password attempts for a method it does not offer", got)
	}
}

func TestVerifyHostKeyChangedStopsBeforeAuth(t *testing.T) {
	host, _ := newEd25519(t)
	other, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsFor(t, other.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want host key changed; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a host whose key changed: %d attempts", got)
	}
	if r.HostKey == "" {
		t.Error("a changed host key should report the fingerprint presented")
	}
}

func TestVerifyHostKeyUnknownSendsNothingUnlessTrusted(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := emptyKnownHosts(t)

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q, want host key unknown; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to an unknown host: %d attempts", got)
	}
	if data, _ := os.ReadFile(known); len(data) != 0 { // #nosec G304 -- a temporary file this test created
		t.Error("an unknown host key was written to known_hosts")
	}

	opts := s.options()
	opts.TrustHostKey = r.HostKey
	trusted := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)
	if trusted.Outcome != Verified {
		t.Fatalf("with the confirmed fingerprint, outcome = %q, want verified; detail %q", trusted.Outcome, trusted.Detail)
	}
	if data, _ := os.ReadFile(known); len(data) != 0 { // #nosec G304 -- a temporary file this test created
		t.Error("a confirmed host key was written to known_hosts; it must be trusted for this check only")
	}
}

func TestVerifyTrustFingerprintMustMatchExactly(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	opts := s.options()
	opts.TrustHostKey = "SHA256:not-the-key"

	r := Verify(context.Background(), target(emptyKnownHosts(t)), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)

	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q, want host key unknown for a wrong fingerprint; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a wrong fingerprint still sent %d credential attempts", got)
	}
}

// A server that holds two host keys can negotiate the one known_hosts lacks.
// That must not read as a changed key: the check retries with the key types
// the file does record.
func TestVerifyRetriesNegotiatedHostKeyTypeWithoutFalseChange(t *testing.T) {
	ed, _ := newEd25519(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := passwordServer(ed)
	s.cfg.AddHostKey(mustSigner(t, ecKey))
	known := knownHostsFor(t, ed.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified: a second host key type is not a change; detail %q", r.Outcome, r.Detail)
	}
	// Two connections prove the retry ran: the first negotiated the ECDSA key
	// that known_hosts lacks, and the second was restricted to the recorded
	// type. Only the second sent a credential.
	if got := s.dials.Load(); got != 2 {
		t.Errorf("dials = %d, want 2: the first handshake must negotiate the unrecorded type and retry", got)
	}
	if got := s.password.Load(); got != 1 {
		t.Errorf("server saw %d password attempts, want exactly 1", got)
	}
}

func TestVerifyLocalFailuresSendNothing(t *testing.T) {
	host, _ := newEd25519(t)
	known := knownHostsFor(t, host.PublicKey())
	dir := t.TempDir()
	encrypted, _ := writeKey(t, dir, "enc", testPassphrase)

	cases := map[string]Attempt{
		"no password":      {Method: MethodPassword},
		"no key file":      {Method: MethodKey},
		"missing key file": {Method: MethodKey, KeyPath: filepath.Join(dir, "absent")},
		"encrypted, no pw": {Method: MethodKey, KeyPath: encrypted},
		"encrypted, wrong": {Method: MethodKey, KeyPath: encrypted, Passphrase: []byte("nope")},
		"agent, no fp":     {Method: MethodAgent},
		"unknown method":   {Method: Method("keyboard")},
		"key with a token": {Method: MethodKey, KeyPath: filepath.Join(dir, "%h-key")},
		"agent, no key":    {Method: MethodAgent, AgentFingerprint: "SHA256:none"},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) {
			s := passwordServer(host)
			opts := s.options()
			opts.Agent = func() (io.ReadWriteCloser, error) { return nil, errors.New("no agent in this test") }
			r := Verify(context.Background(), target(known), a, opts)
			if r.Outcome != LocalFailure {
				t.Fatalf("outcome = %q, want local failure; detail %q", r.Outcome, r.Detail)
			}
			if got := s.dials.Load(); got != 0 {
				t.Errorf("a local failure still dialled the server %d times", got)
			}
		})
	}
}

func TestVerifyKeyFileAccepted(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	keyPath, pub := writeKey(t, t.TempDir(), "id", "")
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		if bytes.Equal(key.Marshal(), pub.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("not authorised")
	}
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodKey, KeyPath: keyPath}, s.options())

	if r.Outcome != Verified || r.Method != MethodKey {
		t.Fatalf("outcome = %q, want verified by key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.pubkey.Load(); got != 1 {
		t.Errorf("server saw %d key attempts, want exactly 1", got)
	}
}

func TestVerifyEncryptedKeyWithPassphrase(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		return nil, nil
	}
	known := knownHostsFor(t, host.PublicKey())
	keyPath, _ := writeKey(t, t.TempDir(), "enc", testPassphrase)

	r := Verify(context.Background(), target(known), Attempt{Method: MethodKey, KeyPath: keyPath, Passphrase: []byte(testPassphrase)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
}

func TestVerifyAgentKeyChosenByFingerprint(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	_, priv := newEd25519(t)
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		return nil, nil
	}
	known := knownHostsFor(t, host.PublicKey())
	opts := s.options()
	opts.Agent = fakeAgent(t, priv)

	keys, err := ListAgentKeys(target(known), opts)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListAgentKeys = %v, %v; want one key", keys, err)
	}
	if got := s.pubkey.Load(); got != 0 {
		t.Fatalf("listing agent keys contacted the server: %d attempts", got)
	}

	r := Verify(context.Background(), target(known), Attempt{Method: MethodAgent, AgentFingerprint: keys[0].Fingerprint}, opts)
	if r.Outcome != Verified || r.Method != MethodAgent {
		t.Fatalf("outcome = %q, want verified by agent; detail %q", r.Outcome, r.Detail)
	}
	if got := s.pubkey.Load(); got != 1 {
		t.Errorf("server saw %d key attempts, want exactly 1: the agent must offer one signer", got)
	}
}

func TestVerifyPasswordOverKeyboardInteractive(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		s.kbd.Add(1)
		answers, err := challenge("", "", []string{"Password: "}, []bool{false})
		if err != nil || len(answers) != 1 || answers[0] != testPassword {
			return nil, errors.New("denied")
		}
		return nil, nil
	}
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified via keyboard-interactive; detail %q", r.Outcome, r.Detail)
	}
}

// A keyboard-interactive server that asks for more than a password is not
// answered, so a second factor never receives the password.
func TestVerifyDeclinesMultiplePrompts(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		s.kbd.Add(1)
		_, err := challenge("", "", []string{"Password: ", "Verification code: "}, []bool{false, true})
		return nil, err
	}
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Unsupported {
		t.Fatalf("outcome = %q, want unsupported; detail %q", r.Outcome, r.Detail)
	}
}

func TestVerifyPartialSuccessReportsWhatRemains(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		s.pubkey.Add(1)
		return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
			PasswordCallback: func(conn ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
				return nil, errors.New("denied")
			},
		}}
	}
	known := knownHostsFor(t, host.PublicKey())
	_, priv := newEd25519(t)
	opts := s.options()
	opts.Agent = fakeAgent(t, priv)
	keys, err := ListAgentKeys(target(known), opts)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListAgentKeys = %v, %v", keys, err)
	}

	r := Verify(context.Background(), target(known), Attempt{Method: MethodAgent, AgentFingerprint: keys[0].Fingerprint}, opts)

	if r.Outcome != Partial {
		t.Fatalf("outcome = %q, want partial; detail %q", r.Outcome, r.Detail)
	}
	if len(r.Remaining) != 1 || r.Remaining[0] != "password" {
		t.Errorf("remaining = %q, want [password]", r.Remaining)
	}
}

func TestVerifyNoCredentialAcceptedIsAFinding(t *testing.T) {
	host, _ := newEd25519(t)
	s := newServer(host)
	s.cfg.NoClientAuth = true
	known := knownHostsFor(t, host.PublicKey())

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != NoCredentialAccepted {
		t.Fatalf("outcome = %q, want no credential accepted; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a password was sent to a server that needed none: %d attempts", got)
	}
}

func TestProxiedTargetIsRefusedWithoutDialing(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	tg := target()
	tg.Unsupported = "proxyjump"

	r := Verify(context.Background(), tg, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != Unsupported {
		t.Fatalf("outcome = %q, want unsupported; detail %q", r.Outcome, r.Detail)
	}
	if got := s.dials.Load(); got != 0 {
		t.Errorf("a proxied target was dialled directly %d times", got)
	}
}

func TestCancelledCheckReportsCancellation(t *testing.T) {
	host, _ := newEd25519(t)
	s := passwordServer(host)
	known := knownHostsFor(t, host.PublicKey())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := Verify(ctx, target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())

	if r.Outcome != TransportFailure || !strings.Contains(r.Detail, "cancelled") {
		t.Fatalf("outcome = %q detail %q, want a transport failure that says cancelled", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a cancelled check still sent %d credential attempts", got)
	}
}

func TestSilentServerTimesOut(t *testing.T) {
	host, _ := newEd25519(t)
	known := knownHostsFor(t, host.PublicKey())
	opts := Options{
		Timeout: 100 * time.Millisecond,
		Dial: func(ctx context.Context, addr string) (net.Conn, error) {
			client, _ := bufferedPipe() // the far end never speaks SSH
			return client, nil
		},
	}

	r := Verify(context.Background(), target(known), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, opts)

	if r.Outcome != TransportFailure || !strings.Contains(r.Detail, "timed out") {
		t.Fatalf("outcome = %q detail %q, want a transport failure that says timed out", r.Outcome, r.Detail)
	}
}

// Every result is serialised for the report and the screen, so none of them
// may carry the secret, whatever the outcome.
func TestResultsNeverCarryTheSecret(t *testing.T) {
	host, _ := newEd25519(t)
	const secret = "never-in-a-result-value" // #nosec G101 -- a marker string the test looks for, not a credential
	s := passwordServer(host)
	known := knownHostsFor(t, host.PublicKey())
	attempts := []Attempt{
		{Method: MethodPassword, Password: []byte(testWrongPass + secret)},
		{Method: MethodKey, KeyPath: filepath.Join(t.TempDir(), secret)},
	}
	for _, a := range attempts {
		r := Verify(context.Background(), target(known), a, s.options())
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), secret) {
			t.Errorf("result %s carries the secret", raw)
		}
	}
}

// fakeAgent serves one in-memory ssh-agent that holds the given private key.
func fakeAgent(t *testing.T, priv ed25519.PrivateKey) func() (io.ReadWriteCloser, error) {
	t.Helper()
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: "test identity"}); err != nil {
		t.Fatal(err)
	}
	return func() (io.ReadWriteCloser, error) {
		client, srv := net.Pipe()
		go func() {
			_ = agent.ServeAgent(keyring, srv)
			_ = srv.Close()
		}()
		return client, nil
	}
}

// writeKey writes a new ed25519 private key in OpenSSH format, encrypted with
// passphrase when it is not empty. It returns the path and the public key.
func writeKey(t *testing.T, dir, name, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, mustSigner(t, priv).PublicKey()
}
