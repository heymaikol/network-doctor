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
func withFinalMatchPass(t *testing.T, base string) string {
	t.Helper()
	return after(t, base, "cfg line 1: Applying options", strings.Join([]string{
		"debug1: Reading configuration data /etc/ssh/ssh_config",
		"debug1: configuration requests final Match pass",
		"debug1: re-parsing configuration",
		"debug1: Reading configuration data cfg",
		"debug1: Reading configuration data /etc/ssh/ssh_config",
	}, "\n"))
}

func fedoraFinalMatchTranscript(t *testing.T) string {
	t.Helper()
	return withFinalMatchPass(t, fixture(t, "trust-plain"))
}

func TestFedoraFinalMatchTranscriptIsTrusted(t *testing.T) {
	tr := fedoraFinalMatchTranscript(t)
	trust, ok, result := parseHostTrust([]byte(tr), 255)
	if !ok || trust.algorithm != "ssh-ed25519" || trust.fingerprint != presentedFingerprint(t, tr) || trust.certificate {
		t.Fatalf("the final Match pass was refused: trust=%+v ok=%v result=%+v", trust, ok, result)
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

// OpenSSH finishes its final configuration pass before connecting. Moving
// the connection-established line ahead of the markers must not establish
// host trust or expose a fingerprint through refusal reporting.
func TestFinalMatchPassRefusesEarlyConnectionEstablished(t *testing.T) {
	good := fedoraFinalMatchTranscript(t)
	bad := strings.Replace(good, "debug1: Connection established.\n", "", 1)
	bad = strings.Replace(bad,
		"debug1: configuration requests final Match pass",
		"debug1: Connection established.\n"+"debug1: configuration requests final Match pass", 1)

	_, ok, result := parseHostTrust([]byte(bad), 255)
	if ok || result.Outcome != TransportFailure || result.HostKey != "" {
		t.Fatalf("early connection established: trusted=%v outcome=%q hostKey=%q", ok, result.Outcome, result.HostKey)
	}
}

// A malformed configuration prefix cannot name a trusted host key, including
// in refusal reporting. The same validation must guard presentedKeyAtPrefix
// and acceptShape; a check applied only to acceptShape would miss this case.
func TestFinalMatchMalformedPrefixDoesNotReportHostFingerprint(t *testing.T) {
	good := fedoraFinalMatchTranscript(t)
	bad := strings.Replace(good,
		"debug1: configuration requests final Match pass\n"+"debug1: re-parsing configuration",
		"debug1: re-parsing configuration\n"+"debug1: configuration requests final Match pass", 1)
	_, ok, result := parseHostTrust([]byte(bad), 255)
	if ok || result.Outcome != TransportFailure || result.HostKey != "" {
		t.Fatalf("malformed prefix: trusted=%v outcome=%q hostKey=%q", ok, result.Outcome, result.HostKey)
	}
}

// A complete final Match pass must not hide the key that OpenSSH actually
// presented when it refuses an unknown host key. No trust is granted.
func TestFinalMatchUnknownHostKeyStillReportsPresentedFingerprint(t *testing.T) {
	tr := withFinalMatchPass(t, fixture(t, "unknown-plain"))
	_, ok, result := parseHostTrust([]byte(tr), 255)
	if ok || result.Outcome != HostKeyUnknown || result.HostKey != presentedFingerprint(t, tr) {
		t.Fatalf("unknown key: trusted=%v outcome=%q hostKey=%q", ok, result.Outcome, result.HostKey)
	}
}
