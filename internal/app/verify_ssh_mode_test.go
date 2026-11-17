package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// stubHostKey is the fingerprint the stub server presents when a test does not
// set one. A password or key check discovers it before any secret is asked for.
const stubHostKey = "SHA256:stubhostkeystubhostkeystubhostkeystub0"

// stubVerify replaces the verification seams for one test and restores them.
type stubVerify struct {
	attempt   sshverify.Attempt
	attempted bool
	discover  bool
	resolved  bool
	result    sshverify.Result
	// preflight is what discovery returns before a secret; nil means the host
	// key is trusted and the server lists methods.
	preflight *sshverify.Result
	pin       string // the PinHostKey the credential check was given
	listed    []sshverify.AgentKey
	listErr   error
	needsPass bool
	needsErr  error
}

func installVerifyStubs(t *testing.T, s *stubVerify) {
	t.Helper()
	savedResolve, savedDiscover, savedVerify := verifyResolve, verifyDiscover, verifyVerify
	savedList, savedNeeds, savedStdin := verifyListAgent, verifyNeedsPass, verifyStdin
	savedTTY, savedPass := verifyIsTTY, verifyReadPass
	t.Cleanup(func() {
		verifyResolve, verifyDiscover, verifyVerify = savedResolve, savedDiscover, savedVerify
		verifyListAgent, verifyNeedsPass, verifyStdin = savedList, savedNeeds, savedStdin
		verifyIsTTY, verifyReadPass = savedTTY, savedPass
	})
	verifyResolve = func(_ context.Context, host string, port int, login string) (sshverify.Target, error) {
		s.resolved = true
		if login == "" {
			login = "defaultuser"
		}
		p := port
		if p == 0 {
			p = 22
		}
		return sshverify.Target{Host: host, Port: p, User: login}, nil
	}
	verifyDiscover = func(_ context.Context, _ sshverify.Target, _ sshverify.Options) sshverify.Result {
		s.discover = true
		switch {
		case s.preflight != nil:
			return *s.preflight
		case s.result.Outcome == sshverify.Discovered:
			return s.result
		}
		return sshverify.Result{Outcome: sshverify.Discovered, HostKey: stubHostKey, Methods: []string{"password", "publickey"}}
	}
	verifyVerify = func(_ context.Context, _ sshverify.Target, a sshverify.Attempt, o sshverify.Options) sshverify.Result {
		s.attempted = true
		s.attempt = a
		s.pin = o.PinHostKey
		return s.result
	}
	verifyListAgent = func(sshverify.Target, sshverify.Options) ([]sshverify.AgentKey, error) {
		return s.listed, s.listErr
	}
	verifyNeedsPass = func(string) (bool, error) { return s.needsPass, s.needsErr }
	verifyIsTTY = func() bool { return false }
}

func runVerify(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	verifyStdin = strings.NewReader(stdin)
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVerifyFlagsNeedVerifySSH(t *testing.T) {
	code, _, errOut := runVerify(t, "", "-verify-auth", "password", "host.example")
	if code != 2 || !strings.Contains(errOut, "-verify-auth requires -verify-ssh") {
		t.Fatalf("code = %d stderr %q, want exit 2 naming the missing -verify-ssh", code, errOut)
	}
}

func TestVerifySSHRefusesOtherModes(t *testing.T) {
	installVerifyStubs(t, &stubVerify{})
	for _, extra := range []string{"-explain", "-compare", "-via", "-watch", "-timeout"} {
		args := []string{"-verify-ssh", extra}
		if extra == "-via" || extra == "-timeout" {
			args = append(args, "1s")
		}
		args = append(args, "host.example")
		if extra == "-explain" || extra == "-compare" {
			args = append(args, "x.json")
		}
		code, _, errOut := runVerify(t, "", args...)
		if code != 2 || !strings.Contains(errOut, "cannot be combined") {
			t.Errorf("%s: code = %d stderr %q, want exit 2 refusing the combination", extra, code, errOut)
		}
	}
}

func TestVerifySSHNeedsOneTarget(t *testing.T) {
	installVerifyStubs(t, &stubVerify{})
	if code, _, _ := runVerify(t, "", "-verify-ssh"); code != 2 {
		t.Errorf("no target: code = %d, want 2", code)
	}
}

func TestVerifyDiscoveryListsMethodsAndSendsNothing(t *testing.T) {
	s := &stubVerify{result: sshverify.Result{Outcome: sshverify.Discovered, Methods: []string{"publickey", "password"}}}
	installVerifyStubs(t, s)

	code, out, _ := runVerify(t, "", "-verify-ssh", "tester@host.example:2222")

	if code != 0 || !s.discover || s.attempted {
		t.Fatalf("code = %d discover=%v attempted=%v, want a listing only", code, s.discover, s.attempted)
	}
	if !strings.Contains(out, "methods:   publickey, password") || !strings.Contains(out, "tester@host.example:2222") {
		t.Errorf("output %q does not list the methods for the target", out)
	}
}

func TestVerifyPasswordFromStdinNeverPrintsIt(t *testing.T) {
	const secret = "stdin-only-test-secret" // #nosec G101 -- a marker string the test looks for, not a credential
	s := &stubVerify{result: sshverify.Result{Outcome: sshverify.Verified, Method: sshverify.MethodPassword}}
	installVerifyStubs(t, s)

	code, out, errOut := runVerify(t, secret+"\n", "-verify-ssh", "-verify-auth", "password", "-password-stdin", "host.example")

	if code != 0 {
		t.Fatalf("code = %d, want 0 for a verified credential; stderr %q", code, errOut)
	}
	if string(s.attempt.Password) != secret {
		t.Errorf("the attempt carried %q, want the stdin line", s.attempt.Password)
	}
	if strings.Contains(out, secret) || strings.Contains(errOut, secret) {
		t.Error("the secret was printed")
	}
}

func TestVerifyPasswordWithoutTerminalOrStdinIsRefused(t *testing.T) {
	s := &stubVerify{}
	installVerifyStubs(t, s)

	code, _, errOut := runVerify(t, "", "-verify-ssh", "-verify-auth", "password", "host.example")

	if code != 2 || !strings.Contains(errOut, "needs a terminal, or -password-stdin") {
		t.Fatalf("code = %d stderr %q, want exit 2 asking for a terminal or -password-stdin", code, errOut)
	}
	if s.attempted {
		t.Error("a password was attempted without a secret source")
	}
}

func TestVerifyKeyNeedsItsPassphraseOnlyWhenEncrypted(t *testing.T) {
	s := &stubVerify{needsPass: true, result: sshverify.Result{Outcome: sshverify.Refused}}
	installVerifyStubs(t, s)
	code, _, _ := runVerify(t, "phrase\n", "-verify-ssh", "-verify-auth", "key", "-verify-key", "/k/id", "-password-stdin", "host.example")
	if code != 1 || string(s.attempt.Passphrase) != "phrase" || s.attempt.KeyPath != "/k/id" {
		t.Fatalf("code = %d passphrase = %q key = %q, want the passphrase read and exit 1 for a refusal", code, s.attempt.Passphrase, s.attempt.KeyPath)
	}

	plain := &stubVerify{needsPass: false, result: sshverify.Result{Outcome: sshverify.Verified}}
	installVerifyStubs(t, plain)
	if code, _, _ := runVerify(t, "", "-verify-ssh", "-verify-auth", "key", "-verify-key", "/k/id", "host.example"); code != 0 || len(plain.attempt.Passphrase) != 0 {
		t.Errorf("an unencrypted key asked for a passphrase: code %d", code)
	}
}

func TestVerifyAgentListsKeysWhenNoFingerprintIsGiven(t *testing.T) {
	s := &stubVerify{listed: []sshverify.AgentKey{{Fingerprint: "SHA256:abc", Type: "ssh-ed25519", Comment: "work"}}}
	installVerifyStubs(t, s)

	code, out, _ := runVerify(t, "", "-verify-ssh", "-verify-auth", "agent", "host.example")

	if code != 2 || s.attempted {
		t.Fatalf("code = %d attempted = %v, want no attempt and exit 2", code, s.attempted)
	}
	if !strings.Contains(out, "SHA256:abc") || !strings.Contains(out, "-verify-agent-key") {
		t.Errorf("output %q should list the agent keys and name the flag", out)
	}
}

func TestVerifyExitCodesMatchTheDocumentedMapping(t *testing.T) {
	want := map[sshverify.Outcome]int{
		sshverify.Discovered: 0, sshverify.Verified: 0,
		sshverify.Refused: 1, sshverify.Partial: 1, sshverify.NotOffered: 1, sshverify.NoCredentialAccepted: 1,
		sshverify.HostKeyUnknown: 2, sshverify.HostKeyChanged: 2, sshverify.Unsupported: 2,
		sshverify.LocalFailure: 2, sshverify.TransportFailure: 2,
	}
	for outcome, code := range want {
		if got := verifyExitCode(outcome); got != code {
			t.Errorf("%s: exit %d, want %d", outcome, got, code)
		}
	}
}

func TestVerifyJSONCarriesNoSecret(t *testing.T) {
	const secret = "json-test-secret-value"
	s := &stubVerify{result: sshverify.Result{Outcome: sshverify.Refused, Detail: "the server refused this credential"}}
	installVerifyStubs(t, s)

	_, out, _ := runVerify(t, secret+"\n", "-verify-ssh", "-verify-auth", "password", "-password-stdin", "-json", "host.example")

	if strings.Contains(out, secret) {
		t.Errorf("the JSON report carries the secret: %s", out)
	}
	if !strings.Contains(out, `"outcome": "refused"`) {
		t.Errorf("JSON output %s lacks the outcome", out)
	}
}

// refusedBeforeAnything runs args with input on stdin and asserts the flags were
// refused with exit 2 and the reason, before the target was read, the host was
// contacted, or any stdin was consumed.
func refusedBeforeAnything(t *testing.T, args []string, reason string) {
	t.Helper()
	s := &stubVerify{}
	installVerifyStubs(t, s)
	input := strings.NewReader("never-read-secret\n")
	verifyStdin = input
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), reason) {
		t.Fatalf("%v: code = %d stderr %q, want exit 2 with %q", args, code, errOut.String(), reason)
	}
	if s.resolved || s.discover || s.attempted {
		t.Errorf("%v: refused flags still resolved=%v discovered=%v attempted=%v", args, s.resolved, s.discover, s.attempted)
	}
	if input.Len() == 0 {
		t.Errorf("%v: the secret source was read before the flags were checked", args)
	}
}

// Each credential flag the chosen method would never read is refused, and so is
// a malformed trust value. Nothing is read or contacted first.
func TestUnusedCredentialFlagsAreRefusedBeforeAnything(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		reason string
	}{
		{"password-stdin without auth", []string{"-verify-ssh", "-password-stdin", "host.example"}, "-password-stdin needs -verify-auth password or key"},
		{"password-stdin with agent", []string{"-verify-ssh", "-verify-auth", "agent", "-password-stdin", "host.example"}, "-password-stdin needs -verify-auth password or key"},
		{"agent key without auth", []string{"-verify-ssh", "-verify-agent-key", "SHA256:abc", "host.example"}, "-verify-agent-key needs -verify-auth agent"},
		{"agent key with password", []string{"-verify-ssh", "-verify-auth", "password", "-verify-agent-key", "SHA256:abc", "-password-stdin", "host.example"}, "-verify-agent-key needs -verify-auth agent"},
		{"key file with password", []string{"-verify-ssh", "-verify-auth", "password", "-verify-key", "/k/id", "-password-stdin", "host.example"}, "-verify-key needs -verify-auth key"},
		{"password-stdin with an unencrypted key", []string{"-verify-ssh", "-verify-auth", "key", "-verify-key", "/k/id", "-password-stdin", "host.example"}, "-password-stdin needs an encrypted key"},
		{"key auth without a key file", []string{"-verify-ssh", "-verify-auth", "key", "host.example"}, "-verify-auth key needs -verify-key FILE"},
		{"unknown auth method", []string{"-verify-ssh", "-verify-auth", "bogus", "host.example"}, "-verify-auth must be password, key, or agent"},
		{"trust value without a prefix", []string{"-verify-ssh", "-trust-host-key", "abc", "host.example"}, "-trust-host-key needs a SHA256 host key fingerprint"},
		{"trust value in lower case", []string{"-verify-ssh", "-trust-host-key", "sha256:" + strings.Repeat("A", 43), "host.example"}, "-trust-host-key needs a SHA256 host key fingerprint"},
		{"empty trust value", []string{"-verify-ssh", "-trust-host-key", "", "host.example"}, "-trust-host-key needs a SHA256 host key fingerprint"},
		{"trust value with a short digest", []string{"-verify-ssh", "-verify-auth", "password", "-password-stdin", "-trust-host-key", "SHA256:short", "host.example"}, "-trust-host-key needs a SHA256 host key fingerprint"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { refusedBeforeAnything(t, c.args, c.reason) })
	}
}

// An unknown or changed host key is an outcome, and the secret is never asked
// for: the terminal is not read and stdin is left alone.
func TestUntrustedHostKeyAsksForNothing(t *testing.T) {
	for _, outcome := range []sshverify.Outcome{sshverify.HostKeyUnknown, sshverify.HostKeyChanged} {
		t.Run(string(outcome), func(t *testing.T) {
			s := &stubVerify{preflight: &sshverify.Result{Outcome: outcome, HostKey: stubHostKey}}
			installVerifyStubs(t, s)
			prompted := false
			verifyIsTTY = func() bool { return true }
			verifyReadPass = func() ([]byte, error) { prompted = true; return []byte("typed"), nil }
			input := strings.NewReader("never-read-secret\n")
			verifyStdin = input
			var out, errOut bytes.Buffer

			code := run([]string{"-verify-ssh", "-verify-auth", "password", "host.example"}, &out, &errOut)

			if code != 2 || s.attempted || prompted || input.Len() == 0 {
				t.Fatalf("code = %d attempted=%v prompted=%v unread=%v; want exit 2 with nothing asked for or sent", code, s.attempted, prompted, input.Len() > 0)
			}
			if !strings.Contains(out.String(), string(outcome)) && !strings.Contains(out.String(), "host key") {
				t.Errorf("the output %q does not report the host key", out.String())
			}
		})
	}
}

// The secret is asked for only after the host key is trusted, and the check
// is given the key that discovery saw, so a credential cannot follow a key that
// changed in between.
func TestTrustedHostKeyIsPinnedForTheCheck(t *testing.T) {
	s := &stubVerify{result: sshverify.Result{Outcome: sshverify.Verified}}
	installVerifyStubs(t, s)

	code, _, errOut := runVerify(t, "a-secret\n", "-verify-ssh", "-verify-auth", "password", "-password-stdin", "host.example")

	if code != 0 || !s.attempted {
		t.Fatalf("code = %d attempted = %v stderr %q, want the credential sent once", code, s.attempted, errOut)
	}
	if s.pin != stubHostKey {
		t.Errorf("the check was given pin %q, want the discovered key %q", s.pin, stubHostKey)
	}
}

// A key file that cannot be verified is named, and nothing else runs first.
func TestKeyFileProblemsAreNamedBeforeAnything(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		reason string
	}{
		{"missing", fmt.Errorf("open: %w", fs.ErrNotExist), "does not exist"},
		{"unreadable", fmt.Errorf("open: %w", fs.ErrPermission), "permission denied"},
		{"a directory", sshverify.ErrKeyNotRegular, "is not a regular file"},
		{"not a key", sshverify.ErrKeyNotPrivate, "is not a private key netdoc can read"},
		{"other read error", errors.New("io failure"), "could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &stubVerify{needsErr: c.err}
			installVerifyStubs(t, s)
			var out, errOut bytes.Buffer

			code := run([]string{"-verify-ssh", "-verify-auth", "key", "-verify-key", "/k/id", "host.example"}, &out, &errOut)

			if code != 2 || !strings.Contains(errOut.String(), c.reason) || !strings.Contains(errOut.String(), "/k/id") {
				t.Fatalf("code = %d stderr %q, want exit 2 naming the file and %q", code, errOut.String(), c.reason)
			}
			if s.resolved || s.discover || s.attempted {
				t.Errorf("a broken key file still resolved=%v discovered=%v attempted=%v", s.resolved, s.discover, s.attempted)
			}
		})
	}
}
