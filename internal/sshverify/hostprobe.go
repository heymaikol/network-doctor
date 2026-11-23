package sshverify

import (
	"regexp"
	"strings"
)

// OpenSSH decides which host key to trust. netdoc asks it once, without a credential, and
// reads the verbose record of that decision. netdoc reads no known_hosts file itself, so the
// file list, the names, the aliases and the certificate authorities are OpenSSH's to resolve.
//
// A server controls some of the text that OpenSSH prints before it checks the host key:
//   - a disconnect message, printed on a "Received disconnect" line, which is not a debug line;
//   - a debug message, printed as "debug1: Remote: ...";
//   - the name list of a failed negotiation, printed on an "Unable to negotiate" line;
//   - the key ID and principals of a host certificate, printed on the presented-key line.
//
// Injected text can carry trust lines of its own, so the parser accepts trust only when the
// evidence is unique, when every line before it is a plain debug line, and when the
// authentication phase followed it. The probe also forces LogLevel DEBUG1, which hides the
// debug2 lines that print the server's own algorithm lists. probeArgs documents the rest.

// hostTrust is OpenSSH's decision about the host key, as its own record states it.
type hostTrust struct {
	// algorithm is the host key algorithm OpenSSH negotiated. The credential connection
	// offers only this one, so the algorithm checked here is the one that is used.
	algorithm string
	// fingerprint is the SHA256 fingerprint of the subject key OpenSSH checked. For a host
	// certificate it is the key the certificate certifies, not the certificate blob.
	fingerprint string
}

var (
	probePresentedLine = regexp.MustCompile(`^debug1: Server host (?:key|certificate): \S+ (SHA256:\S+?)(?:, |$)`)
	probeAlgorithmLine = regexp.MustCompile(`^debug1: kex: host key algorithm: ([A-Za-z0-9@.+_-]+)$`)
	probeMatchedLine   = regexp.MustCompile(`^debug1: Host '.*' is known and matches the .* host (?:key|certificate)\.$`)
	probeAuthLine      = regexp.MustCompile(`^debug1: Authentications that can continue: `)
)

// probeArgs is the argument vector for the probe: the options that decide what the client
// prints and what it may do, followed by the destination ssh -G read. Nothing here overrides a
// known-hosts setting, CheckHostIP, or a revocation list; OpenSSH applies those from the user's
// configuration. The options that stop a probe from doing more than the handshake are:
// no session (-N), no credential method, no agent, no control connection, no forwarding, no
// local command, and no proxy.
func probeArgs(dest []string) []string {
	return append([]string{
		"-N", "-n", "-T",
		"-o", "LogLevel=DEBUG1",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PreferredAuthentications=none",
		"-o", "PubkeyAuthentication=no",
		"-o", "IdentityAgent=none",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ClearAllForwardings=yes",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "Tunnel=no",
		"-o", "PermitLocalCommand=no",
		"-o", "ProxyCommand=none",
		"-o", "ProxyJump=none",
		"-o", "UpdateHostKeys=no",
	}, dest...)
}

// parseHostTrust reads one probe transcript and returns OpenSSH's trust decision. When the
// evidence is missing, ambiguous or not in order, it returns the reason to refuse, and nothing
// is sent. The returned Result is set only when trusted is false.
func parseHostTrust(transcript []byte, exitStatus int) (hostTrust, bool, Result) {
	lines := strings.Split(strings.ReplaceAll(string(transcript), "\r\n", "\n"), "\n")
	var presented, algorithms, matched, auth []int
	failed := ""
	for i, l := range lines {
		switch {
		case probePresentedLine.MatchString(l):
			presented = append(presented, i)
		case probeAlgorithmLine.MatchString(l):
			algorithms = append(algorithms, i)
		case probeMatchedLine.MatchString(l):
			matched = append(matched, i)
		case probeAuthLine.MatchString(l):
			auth = append(auth, i)
		}
		if failed == "" {
			failed = failureLine(l)
		}
	}
	fingerprint := ""
	if len(presented) == 1 {
		fingerprint = probePresentedLine.FindStringSubmatch(lines[presented[0]])[1]
	}
	refuse := func(outcome Outcome, detail string) (hostTrust, bool, Result) {
		return hostTrust{}, false, Result{Outcome: outcome, HostKey: fingerprint, Detail: detail + "; nothing was sent"}
	}
	if failed != "" {
		switch {
		case strings.Contains(failed, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
			return refuse(HostKeyChanged, "OpenSSH reports that the host key has changed")
		case strings.Contains(failed, "revoked"):
			return refuse(HostKeyChanged, "OpenSSH reports that the host key is revoked")
		case strings.Contains(failed, "host key is known for"):
			return refuse(HostKeyUnknown, "OpenSSH has no record of this host key; establish trust with your normal SSH client first")
		}
		return refuse(TransportFailure, "OpenSSH refused the host key for a reason netdoc does not recognise")
	}
	if exitStatus != 255 {
		return refuse(TransportFailure, "OpenSSH's probe ended with an unexpected status")
	}
	if len(presented) != 1 || len(algorithms) != 1 || len(matched) != 1 || !probeEvidenceInOrder(lines, presented[0], algorithms[0], matched[0], auth) {
		return refuse(TransportFailure, "OpenSSH's output did not show a trusted host key in the order and form netdoc needs")
	}
	if !ValidFingerprint(fingerprint) {
		return refuse(TransportFailure, "OpenSSH's host key fingerprint is malformed")
	}
	return hostTrust{algorithm: probeAlgorithmLine.FindStringSubmatch(lines[algorithms[0]])[1], fingerprint: fingerprint}, true, Result{}
}

// probeEvidenceInOrder checks the order of the evidence and the guard on injected text. The
// algorithm line and the presented-key line come before the match, and an authentication line
// comes after it. Every line before the match must be a plain debug line, and none may be a
// debug message from the server.
func probeEvidenceInOrder(lines []string, presented, algorithm, matched int, auth []int) bool {
	if algorithm >= presented || presented >= matched {
		return false
	}
	afterMatch := false
	for _, a := range auth {
		if a > matched {
			afterMatch = true
		}
	}
	if !afterMatch {
		return false
	}
	for _, l := range lines[:matched] {
		if !strings.HasPrefix(l, "debug1: ") || strings.HasPrefix(l, "debug1: Remote:") {
			return false
		}
	}
	return true
}

// failureLine returns l when OpenSSH printed a refusal on it, and "" otherwise.
func failureLine(l string) string {
	switch {
	case l == "Host key verification failed.",
		strings.Contains(l, "REMOTE HOST IDENTIFICATION HAS CHANGED"),
		strings.Contains(l, "revoked"),
		strings.Contains(l, "host key is known for"):
		return l
	}
	return ""
}
