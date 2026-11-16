package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// stubVerify replaces the verification seams for one test and restores them.
type stubVerify struct {
	attempt   sshverify.Attempt
	attempted bool
	discover  bool
	result    sshverify.Result
	listed    []sshverify.AgentKey
	listErr   error
	needsPass bool
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
		return s.result
	}
	verifyVerify = func(_ context.Context, _ sshverify.Target, a sshverify.Attempt, _ sshverify.Options) sshverify.Result {
		s.attempted = true
		s.attempt = a
		return s.result
	}
	verifyListAgent = func(sshverify.Target, sshverify.Options) ([]sshverify.AgentKey, error) {
		return s.listed, s.listErr
	}
	verifyNeedsPass = func(string) (bool, error) { return s.needsPass, nil }
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
