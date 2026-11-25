package sshverify

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// A client without GSSAPI prints one diagnostic for the probe's GSSAPIAuthentication=no override.
// The line is removed only when the client lists no GSSAPI key exchange, and then the rest of the
// transcript is judged as before.
func TestGSSAPIUnsupportedDiagnosticIsAcceptedOnlyWithoutGSSAPIKeyExchange(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	noGSS := func() ([]byte, error) {
		return []byte("Unsupported query \"kex-gss\"\n"), &exec.ExitError{}
	}
	withGSS := func() ([]byte, error) { return []byte("gss-group14-sha1-\ngss-gex-sha1-\n"), nil }
	unrunnable := func() ([]byte, error) { return nil, errors.New("exec: not found") }
	crlf := strings.ReplaceAll(alpine, "\n", "\r\n")
	twice := gssapiUnsupportedLine + "\n" + alpine
	elsewhere := strings.Replace(alpine, "debug1: OpenSSH_", gssapiUnsupportedLine+"\ndebug1: OpenSSH_", 1)
	otherOption := strings.Replace(alpine, "gssapiauthentication", "gssapikeyexchange", 1)

	cases := []struct {
		name     string
		in       string
		kex      func() ([]byte, error)
		accepted bool // whether the diagnostic is removed or the transcript is left as it was
		trusted  bool // whether the judged transcript is trusted
	}{
		{"alpine, no GSSAPI kex", alpine, noGSS, true, true},
		{"alpine, CRLF line endings", crlf, noGSS, true, true},
		{"client lists GSSAPI kex", alpine, withGSS, false, false},
		{"kex query cannot run", alpine, unrunnable, false, false},
		{"diagnostic not first", elsewhere, noGSS, true, false},
		{"diagnostic twice", twice, noGSS, true, false},
		{"other option named", otherOption, noGSS, true, false},
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

// Only the diagnostic line differs: removing it must not change any other line.
func TestGSSAPIUnsupportedRemovalChangesNothingElse(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	got, ok := withoutGSSAPIUnsupported([]byte(alpine), func() ([]byte, error) {
		return []byte("Unsupported query \"kex-gss\"\n"), &exec.ExitError{}
	})
	if !ok {
		t.Fatal("the diagnostic was not removed")
	}
	want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n")
	if string(got) != want {
		t.Fatalf("removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}
