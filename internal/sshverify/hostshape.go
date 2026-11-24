package sshverify

import (
	"regexp"
	"strings"
)

// A probe transcript is trusted only when all of it has OpenSSH's shape. The shape is a whole
// transcript grammar: the configuration lines, the key exchange, exactly one host-key record, and
// the markers and the authentication refusal that follow it, ending exactly at the end of the
// output. It is checked line by line from the first line, so text the server or a command chose can
// not sit between two genuine lines and pass. A prefix check alone would accept a forged tail, and
// an end-of-output check alone would accept a forged middle; the rule needs both.
//
// The rule is positive: a line that is not in the grammar refuses the transcript, whatever it
// says. The failure messages below are used only to explain a refusal to the user. They never
// decide it.

// shapeRule says how many consecutive lines of one kind the transcript holds at a point. The
// walk takes as many matching lines as max allows, and fails when it takes fewer than min.
type shapeRule struct {
	re       *regexp.Regexp
	min, max int // max < 0 means no limit
}

// The configuration section: the lines OpenSSH prints while it reads the configuration and
// connects, before the key exchange. Command output is not among them, so a Match exec line fails.
var shapeConfig = []shapeRule{{regexp.MustCompile(`^debug1: (?:OpenSSH_\S+, OpenSSL .*|Reading configuration data .*|(?:[^"\x00-\x1f\x7f:]+ )?line \d+: Applying options for [^"\x00-\x1f\x7f]*|Applying options for [^"]*|(?:no pubkey loaded from|identity file|no identity pubkey loaded from) [^"]*|loaded pubkey from [^\x00-\x1f\x7f]+: [A-Za-z0-9@._-]+ SHA256:[A-Za-z0-9+/]+|Connecting to [^"]*|Connection established\.|Local version string SSH-2\.0-[^"]*|Remote protocol version 2\.0, remote software version [^"]*|compat_banner: [^"]*|Authenticating to [^"]*|using hostkeyalias: [^"]*)$`), 0, -1}}

// The key exchange, from the first KEXINIT line to the line before the host-key record. The host
// key algorithm is the one line that is taken for the decision, so it appears exactly once.
var (
	shapeKexInitSent   = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEXINIT sent$`), 1, 1}
	shapeKexInitRecv   = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEXINIT received$`), 1, 1}
	shapeKexAlgorithm  = shapeRule{regexp.MustCompile(`^debug1: kex: algorithm: [A-Za-z0-9@._+-]+$`), 1, 1}
	shapeKexHostKeyAlg = shapeRule{regexp.MustCompile(`^debug1: kex: host key algorithm: ([A-Za-z0-9@._+-]+)$`), 1, 1}
	shapeKexS2C        = shapeRule{regexp.MustCompile(`^debug1: kex: server->client cipher: \S+ MAC: .*compression: \S+$`), 1, 1}
	shapeKexC2S        = shapeRule{regexp.MustCompile(`^debug1: kex: client->server cipher: \S+ MAC: .*compression: \S+$`), 1, 1}
	shapeKexNeed       = shapeRule{regexp.MustCompile(`^debug1: kex: \S+ need=\d+ dh_need=\d+$`), 0, 2}
	shapeKexExpect     = shapeRule{regexp.MustCompile(`^debug1: expecting SSH2_MSG_KEX[A-Z0-9_]*_REPLY$`), 1, 1}
	shapeKexReply      = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEX[A-Z0-9_]*_REPLY received$`), 1, 1}
)

var shapeKexRules = []shapeRule{shapeKexInitSent, shapeKexInitRecv, shapeKexAlgorithm, shapeKexHostKeyAlg, shapeKexS2C, shapeKexC2S, shapeKexNeed, shapeKexExpect, shapeKexReply}

// The host-key record: exactly one, in one of OpenSSH's two forms, matched in full. A certificate's
// line carries its key ID, which the server chose, and ends with the authority and validity text.
var (
	shapeKeyLine  = regexp.MustCompile(`^debug1: Server host key: (\S+) (SHA256:\S+)$`)
	shapeCertLine = regexp.MustCompile(`^debug1: Server host certificate: (\S+) (SHA256:\S+), serial \d+ ID "(.*)" CA (\S+) (SHA256:\S+)(?: valid .*)?$`)
	// shapeCertPrefix matches the client-written head of a certificate record before the server's
	// key ID begins, so refusal reporting extracts the presented key even if the key ID spans lines.
	shapeCertPrefix = regexp.MustCompile(`^debug1: Server host certificate: \S+ (SHA256:\S+), serial \d+ ID "`)
)

// The section after the host-key record, to the end of the output. Each marker that decides the
// connection appears exactly once: the match, the NEWKEYS markers, SERVICE_ACCEPT, the method list
// and the final refusal. The extension lines and the rekey notices may appear where OpenSSH prints
// them. The last two lines are the authentication step and the refusal, and their method lists
// must agree.
var (
	// The lookup lines OpenSSH prints while it finds the key: the name it tries without the port, a
	// fallback to the plain key when the certificate authority is not known, and the alias it uses.
	shapeLookup        = shapeRule{regexp.MustCompile(`^debug1: (?:checking without port identifier|No matching CA found\. Retry with plain key|using hostkeyalias: [^"]*)$`), 0, -1}
	shapeMatched       = shapeRule{regexp.MustCompile(`^debug1: Host '[^']*' is known and matches the [A-Z0-9-]+ host (?:key|certificate)\.$`), 1, 1}
	shapeFoundKey      = shapeRule{regexp.MustCompile(`^debug1: Found (?:CA )?key in [^"]*:\d+$`), 0, 1}
	shapeSeqnrSend     = shapeRule{regexp.MustCompile(`^debug1: ssh_packet_send2_wrapped: resetting send seqnr \d+$`), 0, 1}
	shapeRekeyOut      = shapeRule{regexp.MustCompile(`^debug1: rekey out after \d+ blocks$`), 0, 1}
	shapeNewkeysSent   = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_NEWKEYS sent$`), 1, 1}
	shapeExtSend       = shapeRule{regexp.MustCompile(`^debug1: Sending SSH2_MSG_EXT_INFO$`), 0, 1}
	shapeExpectNewkeys = shapeRule{regexp.MustCompile(`^debug1: expecting SSH2_MSG_NEWKEYS$`), 1, 1}
	shapeSeqnrRead     = shapeRule{regexp.MustCompile(`^debug1: ssh_packet_read_poll2: resetting read seqnr \d+$`), 0, 1}
	shapeNewkeysRecv   = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_NEWKEYS received$`), 1, 1}
	shapeRekeyIn       = shapeRule{regexp.MustCompile(`^debug1: rekey in after \d+ blocks$`), 0, 1}
	shapeExt           = shapeRule{regexp.MustCompile(`^debug1: (?:SSH2_MSG_EXT_INFO received|kex_ext_info_[a-z_]+: [^"]*)$`), 0, -1}
	shapeServiceAccept = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_SERVICE_ACCEPT received$`), 1, 1}
	shapeAuthMethods   = shapeRule{regexp.MustCompile(`^debug1: Authentications that can continue: ([a-z0-9-]+(?:,[a-z0-9-]+)*)$`), 1, 1}
	shapeNoMore        = shapeRule{regexp.MustCompile(`^debug1: No more authentication methods to try\.$`), 1, 1}
	shapePermission    = shapeRule{regexp.MustCompile(`^[^"\s]+@\S+: Permission denied \(([a-z0-9-]+(?:,[a-z0-9-]+)*)\)\.$`), 1, 1}
)

// shapeAfterKey is the list of rules after the host-key record, in the order OpenSSH prints them.
// The extension lines are allowed on both sides of SERVICE_ACCEPT, so they are listed twice.
var shapeAfterKey = []shapeRule{
	shapeLookup, shapeMatched, shapeFoundKey, shapeSeqnrSend, shapeRekeyOut, shapeNewkeysSent, shapeExtSend,
	shapeExpectNewkeys, shapeSeqnrRead, shapeNewkeysRecv, shapeRekeyIn, shapeExt,
	shapeServiceAccept, shapeExt, shapeAuthMethods, shapeNoMore, shapePermission,
}

// indexOfRule is the position of r in rules. The walk reports positions, so a rule is found by its
// identity rather than by a fixed number.
func indexOfRule(rules []shapeRule, r shapeRule) int {
	for i := range rules {
		if rules[i].re == r.re {
			return i
		}
	}
	panic("sshverify: shape rule not in its list")
}

// walkShape takes the lines from start under rules, in order. Each rule takes as many consecutive
// matching lines as its limits allow, and the walk fails when a rule takes fewer than its minimum.
// It returns the index after the last line taken, and the index of the first line each rule took
// (-1 for a rule that took none).
func walkShape(lines []string, start int, rules []shapeRule) (int, []int, bool) {
	pos := start
	first := make([]int, len(rules))
	for i, r := range rules {
		first[i] = -1
		n := 0
		for pos < len(lines) && (r.max < 0 || n < r.max) && r.re.MatchString(lines[pos]) {
			if n == 0 {
				first[i] = pos
			}
			pos++
			n++
		}
		if n < r.min {
			return 0, nil, false
		}
	}
	return pos, first, true
}

// splitTranscript splits the probe's output into lines, without the empty line at the end.
func splitTranscript(transcript []byte) []string {
	lines := strings.Split(strings.ReplaceAll(string(transcript), "\r\n", "\n"), "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// acceptShape decides a transcript from its shape alone. It returns the trust it establishes and
// an empty reason, or no trust and the reason the shape failed.
func acceptShape(lines []string) (hostTrust, string) {
	for _, l := range lines {
		if strings.HasPrefix(l, "debug1: Executing ") {
			return hostTrust{}, "OpenSSH ran a configured command during the check"
		}
	}
	pos, _, ok := walkShape(lines, 0, shapeConfig)
	if !ok {
		return hostTrust{}, "the configuration section has a line OpenSSH does not print there"
	}
	pos, kex, ok := walkShape(lines, pos, shapeKexRules)
	if !ok {
		return hostTrust{}, "the key exchange does not have OpenSSH's shape"
	}
	if pos >= len(lines) {
		return hostTrust{}, "the output ends before the host key is named"
	}
	var key hostTrust
	var presentedType string
	switch {
	case shapeKeyLine.MatchString(lines[pos]):
		m := shapeKeyLine.FindStringSubmatch(lines[pos])
		presentedType, key.fingerprint = m[1], m[2]
	case shapeCertLine.MatchString(lines[pos]):
		m := shapeCertLine.FindStringSubmatch(lines[pos])
		presentedType, key.fingerprint, key.certificate, key.keyID = m[1], m[2], true, m[3]
	default:
		return hostTrust{}, "the host key record is not one of OpenSSH's two forms, in full"
	}
	pos, after, ok := walkShape(lines, pos+1, shapeAfterKey)
	if !ok {
		return hostTrust{}, "the output after the host key does not have OpenSSH's shape"
	}
	if pos != len(lines) {
		return hostTrust{}, "the output continues after the final refusal"
	}
	algorithm := shapeKexHostKeyAlg.re.FindStringSubmatch(lines[kex[3]])[1]
	// An RSA key is presented as ssh-rsa, and negotiated with one of its signature algorithms.
	if presentedType != algorithm && (presentedType != "ssh-rsa" || !strings.HasPrefix(algorithm, "rsa-sha2-")) {
		return hostTrust{}, "the host key record and the negotiated algorithm name different keys"
	}
	methods := shapeAuthMethods.re.FindStringSubmatch(lines[after[indexOfRule(shapeAfterKey, shapeAuthMethods)]])[1]
	refused := shapePermission.re.FindStringSubmatch(lines[after[indexOfRule(shapeAfterKey, shapePermission)]])[1]
	if methods != refused {
		return hostTrust{}, "the authentication methods and the final refusal name different methods"
	}
	if !ValidFingerprint(key.fingerprint) {
		return hostTrust{}, "the host key fingerprint is malformed"
	}
	key.algorithm = algorithm
	return key, ""
}

// parseHostTrust decides a probe transcript. Trust comes only from acceptShape. Any other
// transcript is refused, and the refusal names what the output showed, for the user.
func parseHostTrust(transcript []byte, exitStatus int) (hostTrust, bool, Result) {
	lines := splitTranscript(transcript)
	if exitStatus == 255 {
		if trust, reason := acceptShape(lines); reason == "" {
			return trust, true, Result{}
		}
	}
	return hostTrust{}, false, refusal(lines, exitStatus)
}

// presentedKeyAtPrefix returns the validated host-key fingerprint OpenSSH printed immediately
// after a clean configuration and key-exchange prefix, so server-injected lines cannot spoof it.
func presentedKeyAtPrefix(lines []string) string {
	pos, _, ok := walkShape(lines, 0, shapeConfig)
	if !ok {
		return ""
	}
	pos, _, ok = walkShape(lines, pos, shapeKexRules)
	if !ok || pos >= len(lines) {
		return ""
	}
	var fp string
	if m := shapeKeyLine.FindStringSubmatch(lines[pos]); m != nil {
		fp = m[2]
	} else if m := shapeCertPrefix.FindStringSubmatch(lines[pos]); m != nil {
		fp = m[1]
	}
	if !ValidFingerprint(fp) {
		return ""
	}
	return fp
}

// refusal names why a transcript was refused. It chooses the message only: the shape has already
// refused, and nothing here can make a transcript trusted.
func refusal(lines []string, exitStatus int) Result {
	fingerprint := presentedKeyAtPrefix(lines)
	out := func(outcome Outcome, detail string) Result {
		return Result{Outcome: outcome, HostKey: fingerprint, Detail: detail + "; nothing was sent"}
	}
	var hasChanged, hasRevoked, hasUnknown, hasExecBeforeKex, hasAuth bool
	beforeKex := true
	for _, l := range lines {
		if shapeKexInitSent.re.MatchString(l) {
			beforeKex = false
		}
		if beforeKex && strings.HasPrefix(l, "debug1: Executing ") {
			hasExecBeforeKex = true
		}
		if strings.HasPrefix(l, "Authenticated to ") {
			hasAuth = true
		}
		if failed := failureLine(l); failed != "" {
			switch {
			case strings.Contains(failed, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
				hasChanged = true
			case strings.Contains(failed, "revoked"):
				hasRevoked = true
			case strings.Contains(failed, "host key is known for"), failed == "Host key verification failed.":
				hasUnknown = true
			}
		}
	}
	switch {
	case hasChanged:
		return out(HostKeyChanged, "OpenSSH reports that the host key has changed")
	case hasRevoked:
		return out(HostKeyRevoked, "OpenSSH reports that the host key is revoked")
	case hasUnknown:
		return out(HostKeyUnknown, "OpenSSH has no record of this host key; establish trust with your normal SSH client first")
	case hasExecBeforeKex:
		return out(TransportFailure, "OpenSSH ran a configured command during the check, so its output is not evidence")
	case hasAuth:
		return out(TransportFailure, "the server accepted the connection without authentication; netdoc does not verify such a server")
	}
	if reason := unreachable(lines); reason != "" {
		return out(TransportFailure, reason)
	}
	if exitStatus != 255 {
		return out(TransportFailure, "OpenSSH's probe ended with an unexpected status")
	}
	return out(TransportFailure, "OpenSSH's output did not have the shape netdoc verifies")
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

// failureLine returns l when OpenSSH printed a refusal on it, and "" otherwise.
func failureLine(l string) string {
	if strings.HasPrefix(l, "debug1: ") {
		return ""
	}
	switch {
	case l == "Host key verification failed.",
		strings.Contains(l, "REMOTE HOST IDENTIFICATION HAS CHANGED"),
		strings.Contains(l, "revoked"),
		strings.Contains(l, "host key is known for"):
		return l
	}
	return ""
}
