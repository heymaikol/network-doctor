package sshverify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
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
		case failed == "Host key verification failed." && len(presented) == 1:
			// With strict checking, OpenSSH ends with this line when it does not trust the key it
			// presented. A global known-hosts setting often prints no line that says which case it is.
			return refuse(HostKeyUnknown, "OpenSSH does not trust this host key; establish trust with your normal SSH client first")
		}
		return refuse(TransportFailure, "OpenSSH refused the host key for a reason netdoc does not recognise")
	}
	if len(presented) == 0 {
		if reason := unreachable(lines); reason != "" {
			return hostTrust{}, false, Result{Outcome: TransportFailure, Detail: reason + "; nothing was sent"}
		}
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

// unreachable names why OpenSSH read no host key, from the client's own lines. The client prints
// these lines itself, so the server cannot write them. It returns "" when none of them is there.
func unreachable(lines []string) string {
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "ssh: Could not resolve hostname "):
			return "the host name could not be resolved"
		case strings.HasPrefix(l, "ssh: connect to host "):
			return "the server could not be reached, so it named no host key"
		case strings.HasPrefix(l, "Unable to negotiate with "):
			// The client prints this line when the two sides share no algorithm. The server's own
			// list follows it on the same line, which the prefix does not depend on.
			return "OpenSSH could not agree a key exchange or host key algorithm with the server, so it named no host key"
		case strings.HasPrefix(l, "Connection reset by "), strings.HasPrefix(l, "Connection closed by "):
			// sshd refuses an address with recent failed logins at the identification stage, so the
			// client's own reset line is all the output there is.
			return "the server closed the connection before it named its host key, as sshd does to an address with recent failed logins"
		}
	}
	return ""
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

// openSSHProbe is the host-key decision a check asks for. The product uses probeHostKey; tests
// replace it with a fixed decision, and the integration tests run the real client.
var openSSHProbe = probeHostKey

// sshTestArgs are options that ssh -G and the probe both read before the destination. Only the
// integration tests set them, to point the client at a test configuration.
var sshTestArgs []string

// probeOutputLimit bounds what the probe keeps of OpenSSH's output.
const probeOutputLimit = 1 << 20

// probeHostKey runs the probe for the target and returns OpenSSH's trust decision. It runs the
// installed client, the one ssh -G read the configuration with, and sends no credential.
func probeHostKey(ctx context.Context, t Target, opts Options) (hostTrust, bool, Result) {
	program, err := sshExecutable(sshBinary)
	if err != nil {
		return hostTrust{}, false, Result{Outcome: LocalFailure, Detail: textsafe.Clean(err.Error()) + "; nothing was sent"}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dest := t.dest
	if dest == nil {
		dest = append(slices.Clone(sshTestArgs), "-p", strconv.Itoa(t.Port), "-l", t.User, "--", t.Host)
	}
	transcript, status, err := runHostKeyProbe(ctx, program, probeArgs(dest))
	if ctx.Err() != nil {
		return hostTrust{}, false, transport(ctx, "the OpenSSH host-key check did not finish")
	}
	if err != nil {
		return hostTrust{}, false, Result{Outcome: TransportFailure, Detail: textsafe.Clean(err.Error()) + "; nothing was sent"}
	}
	return parseHostTrust(transcript, status)
}

// errProbeOutput refuses a probe that wrote to standard output or ran past the output limit.
var errProbeOutput = errors.New("the OpenSSH host-key check wrote unexpected output")

// runHostKeyProbe runs program with args and returns its diagnostic output and exit status. The
// argument vector is passed as a slice, with no shell. The probe may write nothing to standard
// output, and its diagnostic output is held to probeOutputLimit.
func runHostKeyProbe(ctx context.Context, program string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 -- a fixed option vector and the destination ssh -G read; no shell
	cmd.Env = append(os.Environ(), "SSH_ASKPASS_REQUIRE=never")
	var stdout, stderr bytes.Buffer
	out := &limitedBuffer{buf: &stdout, limit: 0}
	diag := &limitedBuffer{buf: &stderr, limit: probeOutputLimit}
	cmd.Stdout = out
	cmd.Stderr = diag
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		return nil, 0, err
	}
	if out.over || diag.over {
		return nil, 0, errProbeOutput
	}
	status := 0
	if exit != nil {
		status = exit.ExitCode()
	}
	return stderr.Bytes(), status, nil
}

// limitedBuffer keeps at most limit bytes and records that it was asked for more, so an
// oversized transcript is refused and never held in memory.
type limitedBuffer struct {
	buf   *bytes.Buffer
	limit int
	over  bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := l.limit - l.buf.Len()
	if room < len(p) {
		l.over = true
		if room > 0 {
			l.buf.Write(p[:room])
		}
		return len(p), nil
	}
	l.buf.Write(p)
	return len(p), nil
}
