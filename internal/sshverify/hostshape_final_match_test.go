package sshverify

import (
	"strings"
	"testing"
)

// This fixture is a real Fedora OpenSSH 10.5p1 transcript against a Debian
// OpenSSH 10.0p2 host, with paths, host names, and fingerprints replaced.
// The client accepted the host key and refused to authenticate with no method.
func TestFedoraRecordedFinalMatchTranscriptIsTrusted(t *testing.T) {
	tr := fixture(t, "fedora-openssh-10.5p1-final-match")
	trust, ok, result := parseHostTrust([]byte(tr), 255)
	if !ok || trust.algorithm != "ssh-ed25519" || trust.fingerprint != presentedFingerprint(t, tr) || trust.certificate {
		t.Fatalf("the recorded Fedora transcript was refused: trust=%+v ok=%v result=%+v", trust, ok, result)
	}
}

// The synthetic variant isolates the second configuration pass from other
// platform differences, so each negative control changes only one rule.
func fedoraFinalMatchTranscript(t *testing.T) string {
	t.Helper()
	return after(t, fixture(t, "trust-plain"), "cfg line 1: Applying options", strings.Join([]string{
		"debug1: Reading configuration data /etc/ssh/ssh_config",
		"debug1: configuration requests final Match pass",
		"debug1: re-parsing configuration",
		"debug1: Reading configuration data cfg",
		"debug1: Reading configuration data /etc/ssh/ssh_config",
	}, "\n"))
}

func TestFedoraFinalMatchTranscriptIsTrusted(t *testing.T) {
	tr := fedoraFinalMatchTranscript(t)
	trust, ok, result := parseHostTrust([]byte(tr), 255)
	if !ok || trust.algorithm != "ssh-ed25519" || trust.fingerprint != presentedFingerprint(t, tr) || trust.certificate {
		t.Fatalf("the Fedora final Match pass was refused: trust=%+v ok=%v result=%+v", trust, ok, result)
	}
}

func TestFinalMatchPassRequiresOrderedCompleteConfiguration(t *testing.T) {
	base := fixture(t, "trust-plain")
	good := fedoraFinalMatchTranscript(t)
	const (
		request = "debug1: configuration requests final Match pass"
		reparse = "debug1: re-parsing configuration"
		read    = "debug1: Reading configuration data cfg"
	)

	cases := map[string]string{
		"request without reparse":     without(t, good, reparse),
		"reparse without request":     without(t, good, request),
		"reversed markers":            strings.Replace(good, request+"\n"+reparse, reparse+"\n"+request, 1),
		"duplicate request":           strings.Replace(good, request, request+"\n"+request, 1),
		"duplicate reparse":           strings.Replace(good, reparse, reparse+"\n"+reparse, 1),
		"read between markers":        strings.Replace(good, request+"\n"+reparse, request+"\n"+read+"\n"+reparse, 1),
		"no read after reparse":       strings.Replace(good, reparse+"\n"+read+"\n"+"debug1: Reading configuration data /etc/ssh/ssh_config", reparse, 1),
		"markers before first read":   after(t, base, "debug1: OpenSSH_10.5p1", request+"\n"+reparse+"\n"+read),
		"markers after connection":    after(t, base, "Connection established.", request+"\n"+reparse+"\n"+read),
		"markers after host key":      after(t, base, "Server host key:", request+"\n"+reparse+"\n"+read),
		"misspelled marker":           strings.Replace(good, request, "debug1: configuration requests final match pass", 1),
		"configured command executed": after(t, good, reparse, "debug1: Executing command: 'echo forged'"),
		"forged authentication list":  strings.Replace(good, "Permission denied (publickey,keyboard-interactive)", "Permission denied (password)", 1),
	}
	for name, tr := range cases {
		t.Run(name, func(t *testing.T) {
			if trust, ok, result := parseHostTrust([]byte(tr), 255); ok {
				t.Fatalf("malformed final Match transcript was trusted: %+v (%+v)", trust, result)
			}
		})
	}
}
