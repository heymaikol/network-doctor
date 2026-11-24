package sshverify

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixture returns a transcript OpenSSH printed for a real probe, from testdata/openssh. The files
// are captured from OpenSSH 10.5p1, with local paths and ports replaced. Every negative case below
// edits one of them, so each refusal is about one changed line.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "openssh", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var presentedRe = regexp.MustCompile(`(?m)^debug1: Server host (?:key|certificate): \S+ (SHA256:[^,\s]+)`)

// presentedFingerprint is the fingerprint the fixture's own host-key record names.
func presentedFingerprint(t *testing.T, transcript string) string {
	t.Helper()
	m := presentedRe.FindStringSubmatch(transcript)
	if m == nil {
		t.Fatal("the fixture names no host key")
	}
	return m[1]
}

// without removes the first line that contains sub, and fails the test when there is none.
func without(t *testing.T, transcript, sub string) string {
	t.Helper()
	lines := strings.Split(transcript, "\n")
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return strings.Join(append(lines[:i:i], lines[i+1:]...), "\n")
		}
	}
	t.Fatalf("the fixture has no line with %q", sub)
	return ""
}

// after inserts text after the first line that contains sub.
func after(t *testing.T, transcript, sub, text string) string {
	t.Helper()
	lines := strings.Split(transcript, "\n")
	for i, l := range lines {
		if strings.Contains(l, sub) {
			out := append([]string{}, lines[:i+1]...)
			out = append(out, strings.Split(strings.TrimSuffix(text, "\n"), "\n")...)
			return strings.Join(append(out, lines[i+1:]...), "\n")
		}
	}
	t.Fatalf("the fixture has no line with %q", sub)
	return ""
}

// The genuine transcripts are trusted, with the fingerprint and algorithm OpenSSH named.
func TestGenuineTranscriptsAreTrusted(t *testing.T) {
	plain := fixture(t, "trust-plain")
	got, ok, r := parseHostTrust([]byte(plain), 255)
	if !ok || got.algorithm != "ssh-ed25519" || got.fingerprint != presentedFingerprint(t, plain) || got.certificate {
		t.Fatalf("plain key: trust = %+v (trusted %v, %+v)", got, ok, r)
	}

	cert := fixture(t, "trust-cert")
	got, ok, r = parseHostTrust([]byte(cert), 255)
	if !ok || got.algorithm != "ssh-ed25519-cert-v01@openssh.com" || got.fingerprint != presentedFingerprint(t, cert) || !got.certificate || got.keyID != "hostcert" {
		t.Fatalf("certificate: trust = %+v (trusted %v, %+v)", got, ok, r)
	}
}

// OpenSSH's genuine refusals and the failures of its own commands are refused.
func TestGenuineRefusalsAreRefused(t *testing.T) {
	cases := map[string]struct {
		name    string
		outcome Outcome
	}{
		"unknown-plain":   {"unknown-plain", HostKeyUnknown},
		"changed-plain":   {"changed-plain", HostKeyChanged},
		"kh-command-run":  {"kh-command-run", TransportFailure},
		"matchexec-trust": {"matchexec-trust", TransportFailure},
		"padded":          {"padded", TransportFailure},
		"forged-newline":  {"forged-newline", HostKeyUnknown},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok, r := parseHostTrust([]byte(fixture(t, c.name)), 255)
			if ok || r.Outcome != c.outcome {
				t.Fatalf("%s = %q (trusted %v, %s), want %q", c.name, r.Outcome, ok, r.Detail, c.outcome)
			}
		})
	}
}

// Every change to the genuine transcript that the shape does not allow is refused, whether it is
// added before the host-key record, after it, or at the end.
func TestWholePrefixAndEndAreBothChecked(t *testing.T) {
	base := fixture(t, "trust-plain")
	cases := map[string]string{
		"forged NEWKEYS before the host-key record":   after(t, base, "debug1: expecting SSH2_MSG_KEX_ECDH_REPLY", "debug1: SSH2_MSG_NEWKEYS sent"),
		"forged KEXINIT line after the final refusal": base + "debug1: SSH2_MSG_KEXINIT received\n",
		"duplicate host-key match":                    after(t, base, "is known and matches", "debug1: Host '[127.0.0.1]:PORT' is known and matches the ED25519 host key."),
		"method list that differs from the refusal":   strings.Replace(base, "Permission denied (publickey,keyboard-interactive)", "Permission denied (password)", 1),
		"text after the final refusal":                base + "something else the server wrote\n",
		"no NEWKEYS received":                         without(t, base, "SSH2_MSG_NEWKEYS received"),
		"acceptance of none after the match":          after(t, base, "is known and matches", "Authenticated to 127.0.0.1 ([127.0.0.1]:PORT) using \"none\"."),
		"configuration line that is not OpenSSH's":    after(t, base, "Reading configuration data", "debug1: Host forged matches the ED25519 host key."),
	}
	for name, edited := range cases {
		t.Run(name, func(t *testing.T) {
			if _, ok, r := parseHostTrust([]byte(edited), 255); ok {
				t.Fatalf("the edited transcript was trusted: %+v", r)
			}
		})
	}
}

// A certificate line that is cut, or a host-key record with an extra field, is refused.
func TestPresentedRecordMustBeOneOfOpenSSHsFormsInFull(t *testing.T) {
	plain := fixture(t, "trust-plain")
	if _, ok, r := parseHostTrust([]byte(plain), 255); !ok {
		t.Fatalf("a genuine plain-key transcript was refused: %+v", r)
	}
	extra := strings.Replace(plain, "SHA256:", "injected SHA256:", 1)
	if _, ok, _ := parseHostTrust([]byte(extra), 255); ok {
		t.Fatal("a host-key record with an extra field was trusted")
	}
	cert := fixture(t, "trust-cert")
	cut := strings.Replace(cert, " CA ", "", 1)
	if _, ok, _ := parseHostTrust([]byte(cut), 255); ok {
		t.Fatal("a certificate line without its authority was trusted")
	}
}

// The positive rule decides alone: the same transcript with every failure text removed is still
// refused, because the shape does not contain it.
func TestPositiveEvidenceRefusesWithoutAnyFailureText(t *testing.T) {
	unknown := fixture(t, "unknown-plain")
	stripped := without(t, without(t, unknown, "Host key verification failed."), "No ED25519 host key is known")
	if _, ok, r := parseHostTrust([]byte(stripped), 255); ok {
		t.Fatalf("a refusal with no failure text was trusted: %+v", r)
	}
	changed := fixture(t, "changed-plain")
	stripped = without(t, changed, "REMOTE HOST IDENTIFICATION HAS CHANGED")
	if _, ok, r := parseHostTrust([]byte(stripped), 255); ok {
		t.Fatalf("a changed key with no warning text was trusted: %+v", r)
	}
}

// A transcript whose status is not the one OpenSSH ends with is refused, even when its shape is right.
func TestUnexpectedStatusIsRefused(t *testing.T) {
	if _, ok, _ := parseHostTrust([]byte(fixture(t, "trust-plain")), 0); ok {
		t.Fatal("a probe that exited 0 was trusted")
	}
}
