//go:build unix

package sshverify

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// shellQuery runs script under sh, so the query's output and exit status are real.
func shellQuery(script string) func() ([]byte, error) {
	return func() ([]byte, error) {
		return exec.Command("sh", "-c", script).CombinedOutput() // #nosec G204 -- fixed test scripts
	}
}

// A client without GSSAPI prints one diagnostic for the probe's GSSAPIAuthentication=no override, as
// the transcript's first line. The line is removed only when the query for GSSAPI key exchange gives
// exactly the unsupported answer, with a nonzero exit. Every other answer refuses the check.
func TestGSSAPIUnsupportedDiagnosticIsAcceptedOnlyWithTheExactQueryAnswer(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	exact := `printf 'Unsupported query "kex-gss"\n'; exit 255`
	noTop := strings.Replace(alpine, gssapiUnsupportedLine+"\n", "", 1)

	cases := []struct {
		name     string
		in       string
		kex      func() ([]byte, error)
		accepted bool // whether the diagnostic is removed, or the transcript is returned unchanged
		trusted  bool // whether the judged transcript is trusted
	}{
		{"exact answer, nonzero exit", alpine, shellQuery(exact), true, true},
		{"exact answer, CRLF line endings", strings.ReplaceAll(alpine, "\n", "\r\n"), shellQuery(exact), true, true},
		{"client lists GSSAPI key exchange", alpine, shellQuery(`printf 'gss-group14-sha1-\n'; exit 255`), false, false},
		{"unrelated failure output", alpine, shellQuery(`printf 'ssh: permission denied\n'; exit 255`), false, false},
		{"empty failure", alpine, shellQuery(`exit 255`), false, false},
		{"exact answer and a second line", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\nextra\n'; exit 255`), false, false},
		{"exact answer with exit 0", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\n'; exit 0`), false, false},
		{"exact answer, then killed by a signal", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\n'; kill -9 $$`), false, false},
		{"query cannot start", alpine, func() ([]byte, error) { return nil, errors.New("exec: not found") }, false, false},
		{"single misplaced diagnostic, after the banner", strings.Replace(noTop, "\n", "\n"+gssapiUnsupportedLine+"\n", 1), shellQuery(exact), true, false},
		{"diagnostic twice at the top", gssapiUnsupportedLine + "\n" + alpine, shellQuery(exact), true, false},
		{"other option named", strings.Replace(alpine, "gssapiauthentication", "gssapikeyexchange", 1), shellQuery(exact), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := withoutGSSAPIUnsupported([]byte(tc.in), tc.kex)
			if ok != tc.accepted {
				t.Fatalf("accepted = %v, want %v", ok, tc.accepted)
			}
			if !ok {
				return
			}
			trust, trusted, _ := parseHostTrust(got, 255)
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
			if trusted && trust.fingerprint != presentedFingerprint(t, alpine) {
				t.Fatalf("trusted fingerprint %q, want the one OpenSSH presented", trust.fingerprint)
			}
		})
	}
}

// A query that outlives its deadline is killed, and the check is refused, not accepted.
func TestGSSAPIUnsupportedQueryTimeoutRefusesTheCheck(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	slow := func() ([]byte, error) {
		return exec.CommandContext(ctx, "sh", "-c", `printf 'Unsupported query "kex-gss"\n'; exec sleep 5`).CombinedOutput() // #nosec G204 -- fixed test script
	}
	if _, ok := withoutGSSAPIUnsupported([]byte(alpine), slow); ok {
		t.Fatal("a query that timed out was accepted")
	}
}

// Only the diagnostic line is removed: no other line of the transcript changes.
func TestGSSAPIUnsupportedRemovalChangesNothingElse(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	got, ok := withoutGSSAPIUnsupported([]byte(alpine), shellQuery(`printf 'Unsupported query "kex-gss"\n'; exit 255`))
	if !ok {
		t.Fatal("the diagnostic was not removed")
	}
	want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n")
	if string(got) != want {
		t.Fatalf("removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}
