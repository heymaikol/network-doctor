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
var shapeConfig = []shapeRule{{regexp.MustCompile(`^debug1: (?:OpenSSH_\S+(?: [A-Za-z]+-[A-Za-z0-9._+~]+)?(?:, (?:OpenSSL|LibreSSL) [^\x00-\x1f\x7f]+)?|Reading configuration data .*|configuration requests final Match pass|re-parsing configuration|(?:[^"\x00-\x1f\x7f:]+ )?line \d+: Applying options for [^"\x00-\x1f\x7f]*|Applying options for [^"]*|(?:no pubkey loaded from|identity file|no identity pubkey loaded from) [^"]*|loaded (?:identity )?pubkey from [^\x00-\x1f\x7f]+: [A-Za-z0-9@._-]+ SHA256:[A-Za-z0-9+/]+|load_hostkeys: fopen [^\x00-\x1f\x7f]+: [^\x00-\x1f\x7f]+|Connecting to [^"]*|Connection established\.|Local version string SSH-2\.0-[^"]*|Remote protocol version 2\.0, remote software version [^"]*|compat_banner: [^"]*|Authenticating to [^"]*|using hostkeyalias: [^"]*)$`), 0, -1}}

// Fedora's OpenSSH can read configuration twice for Match final. Accept the
// two exact diagnostic lines only as one ordered pair, between an initial
// configuration read and a second one, before any connection starts. The rest
// of the transcript must still match the entire host-key and refusal grammar.
func validFinalMatchPass(lines []string) bool {
	const request = "debug1: configuration requests final Match pass"
	const reparse = "debug1: re-parsing configuration"
	requested, reparsed := -1, -1
	for i, line := range lines {
		switch line {
		case request:
			if requested != -1 {
				return false
			}
			requested = i
		case reparse:
			if reparsed != -1 {
				return false
			}
			reparsed = i
		}
	}
	if requested == -1 {
		return reparsed == -1
	}
	if reparsed != requested+1 || reparsed+1 >= len(lines) ||
		!strings.HasPrefix(lines[reparsed+1], "debug1: Reading configuration data ") {
		return false
	}
	initialRead := false
	for _, line := range lines[:requested] {
		if strings.HasPrefix(line, "debug1: Connecting to ") {
			return false
		}
		if strings.HasPrefix(line, "debug1: Reading configuration data ") {
			initialRead = true
		}
	}
	return initialRead
}

// The key exchange, from the first KEXINIT line to the line before the host-key record. The host
// key algorithm is the one line that is taken for the decision, so it appears exactly once.
var (
	shapeKexInitSent    = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEXINIT sent$`), 1, 1}
	shapeKexInitRecv    = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEXINIT received$`), 1, 1}
	shapeKexAlgorithm   = shapeRule{regexp.MustCompile(`^debug1: kex: algorithm: [A-Za-z0-9@._+-]+$`), 1, 1}
	shapeKexHostKeyAlg  = shapeRule{regexp.MustCompile(`^debug1: kex: host key algorithm: ([A-Za-z0-9@._+-]+)$`), 1, 1}
	shapeKexS2C         = shapeRule{regexp.MustCompile(`^debug1: kex: server->client cipher: \S+ MAC: .*compression: \S+$`), 1, 1}
	shapeKexC2S         = shapeRule{regexp.MustCompile(`^debug1: kex: client->server cipher: \S+ MAC: .*compression: \S+$`), 1, 1}
	shapeKexNeed        = shapeRule{regexp.MustCompile(`^debug1: kex: \S+ need=\d+ dh_need=\d+$`), 0, 2}
	shapeKexGexRequest  = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEX_DH_GEX_REQUEST\(\d+<\d+<\d+\) sent$`), 0, 1}
	shapeKexGexExpGroup = shapeRule{regexp.MustCompile(`^debug1: expecting SSH2_MSG_KEX_DH_GEX_GROUP$`), 0, 1}
	shapeKexGexGotGroup = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEX_DH_GEX_GROUP received$`), 0, 1}
	shapeKexGexInit     = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEX_DH_GEX_INIT sent$`), 0, 1}
	shapeKexExpect      = shapeRule{regexp.MustCompile(`^debug1: expecting SSH2_MSG_KEX[A-Z0-9_]*_REPLY$`), 1, 1}
	shapeKexReply       = shapeRule{regexp.MustCompile(`^debug1: SSH2_MSG_KEX[A-Z0-9_]*_REPLY received$`), 1, 1}
)

var shapeKexRules = []shapeRule{
	shapeKexInitSent, shapeKexInitRecv, shapeKexAlgorithm, shapeKexHostKeyAlg,
	shapeKexS2C, shapeKexC2S, shapeKexNeed,
	shapeKexGexRequest, shapeKexGexExpGroup, shapeKexGexGotGroup, shapeKexGexInit,
	shapeKexExpect, shapeKexReply,
}

// The host-key record: exactly one, in one of OpenSSH's two forms, matched in full. A certificate's
// line carries its key ID, which the server chose, and ends with the authority and validity text.
var (
	shapeKeyLine  = regexp.MustCompile(`^debug1: Server host key: (\S+) (SHA256:\S+)$`)
	shapeCertLine = regexp.MustCompile(`^debug1: Server host certificate: (\S+) (SHA256:\S+), serial (\d+) ID "([^"\x00-\x1f\x7f]*)" CA (\S+) (SHA256:\S+) valid (?:forever|after \S+|before \S+|from \S+ to \S+)$`)
	// shapeCertPrefix matches the client-written head of a certificate record before the server's
	// key ID begins, so refusal reporting extracts the presented key even if the key ID spans lines.
	shapeCertPrefix = regexp.MustCompile(`^debug1: Server host certificate: \S+ (SHA256:\S+), serial \d+ ID "`)
)

// certRecordLimit is the length from which a host certificate record may have been cut. OpenSSH
// prints records up to 1021 bytes, and a real record is far shorter than this.
const certRecordLimit = 1000

// The section after the host-key record, to the end of the output. Each marker that decides the
// connection appears exactly once: the match, the NEWKEYS markers, SERVICE_ACCEPT, the method list
// and the final refusal. The extension lines and the rekey notices may appear where OpenSSH prints
// them. The last two lines are the authentication step and the refusal, and their method lists
// must agree.
var (
	// The lookup lines OpenSSH prints while it finds the key: optional missing known_hosts files,
	// the name it tries without the port, a fallback to the plain key when the CA is not known,
	// and the alias it uses.
	shapeLookup        = shapeRule{regexp.MustCompile(`^debug1: (?:load_hostkeys: fopen [^\x00-\x1f\x7f]+: [^\x00-\x1f\x7f]+|checking without port identifier|No matching CA found\. Retry with plain key|using hostkeyalias: [^"]*)$`), 0, -1}
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
	shapePQWarn1       = shapeRule{regexp.MustCompile(`^\*\* WARNING: connection is not using a post-quantum key exchange algorithm\.$`), 0, 1}
	shapePQWarn2       = shapeRule{regexp.MustCompile(`^\*\* This session may be vulnerable to "store now, decrypt later" attacks\.$`), 0, 1}
	shapePQWarn3       = shapeRule{regexp.MustCompile(`^\*\* The server may need to be upgraded\. See https://openssh\.com/pq\.html$`), 0, 1}
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
	shapeExpectNewkeys, shapeSeqnrRead, shapeNewkeysRecv, shapeRekeyIn,
	shapePQWarn1, shapePQWarn2, shapePQWarn3, shapeExt,
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

func walkConfig(lines []string) (int, bool) {
	pos, _, ok := walkShape(lines, 0, shapeConfig)
	return pos, ok && validFinalMatchPass(lines[:pos])
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
	pos, ok := walkConfig(lines)
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
		// OpenSSH cuts a record that is too long to print and prints nothing to say so, so a
		// record near the limit may be truncated. Its tail would then be text the server chose.
		if len(lines[pos]) >= certRecordLimit {
			return hostTrust{}, "the host certificate record is at the length OpenSSH cuts, so it may be truncated"
		}
		m := shapeCertLine.FindStringSubmatch(lines[pos])
		presentedType, key.fingerprint, key.certificate, key.keyID = m[1], m[2], true, m[4]
		key.serial, key.authority = m[3], m[6]
		if !ValidFingerprint(key.authority) {
			return hostTrust{}, "the certificate's authority fingerprint is malformed"
		}
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
	algorithm := shapeKexHostKeyAlg.re.FindStringSubmatch(lines[kex[indexOfRule(shapeKexRules, shapeKexHostKeyAlg)]])[1]
	// An RSA key or certificate is presented under its ssh-rsa key type and negotiated with an RSA SHA-2 signature algorithm.
	if !presentedMatchesAlgorithm(presentedType, algorithm) {
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

// presentedMatchesAlgorithm reports whether OpenSSH's presented key type matches the negotiated
// host-key algorithm. RSA plain keys and RSA host certificates present under ssh-rsa types while
// negotiating rsa-sha2-256 or rsa-sha2-512.
func presentedMatchesAlgorithm(presentedType, algorithm string) bool {
	if presentedType == algorithm {
		return true
	}
	switch presentedType {
	case "ssh-rsa":
		return algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512"
	case "ssh-rsa-cert-v01@openssh.com":
		return algorithm == "rsa-sha2-256-cert-v01@openssh.com" || algorithm == "rsa-sha2-512-cert-v01@openssh.com"
	}
	return false
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
	pos, ok := walkConfig(lines)
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
//
// OpenSSH names a refused host key on the line just before its final line, "Host key verification
// failed.", and the client prints the two together, so the server cannot write between them. Server
// text, banners, disconnect messages and key IDs can contain any of the same words anywhere else, so
// only that position decides which refusal is named.
func refusal(lines []string, exitStatus int) Result {
	fingerprint := presentedKeyAtPrefix(lines)
	out := func(outcome Outcome, detail string) Result {
		return Result{Outcome: outcome, HostKey: fingerprint, Detail: detail + "; nothing was sent"}
	}
	if n := len(lines); exitStatus == 255 && n >= 2 && lines[n-1] == hostKeyVerificationFailed {
		switch decision := lines[n-2]; {
		case shapeChangedDecision.MatchString(decision):
			return out(HostKeyChanged, "OpenSSH reports that the host key has changed")
		case shapeRevokedDecision.MatchString(decision), shapeRevokedFileDecision.MatchString(decision):
			return out(HostKeyRevoked, "OpenSSH reports that the host key is revoked")
		case shapeUnknownDecision.MatchString(decision):
			return out(HostKeyUnknown, "OpenSSH has no record of this host key; establish trust with your normal SSH client first")
		}
	}
	if n := len(lines); exitStatus == 255 && n >= 1 && lines[n-1] == hostKeyVerificationFailed && fingerprint != "" {
		// OpenSSH refused the key without naming why, as a global known-hosts setting can cause.
		return out(HostKeyUnknown, "OpenSSH does not trust this host key; establish trust with your normal SSH client first")
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "debug1: Executing ") {
			return out(TransportFailure, "OpenSSH ran a configured command during the check, so its output is not evidence")
		}
	}
	if reason := unreachable(lines); reason != "" {
		return out(TransportFailure, reason)
	}
	if exitStatus != 255 {
		return out(TransportFailure, "OpenSSH's probe ended with an unexpected status")
	}
	return out(TransportFailure, "OpenSSH's output did not have the shape netdoc verifies")
}

// hostKeyVerificationFailed is OpenSSH's final line when it refuses a host key.
const hostKeyVerificationFailed = "Host key verification failed."

// The decision lines OpenSSH prints for a refused host key, as the client prints them.
var (
	shapeChangedDecision     = regexp.MustCompile(`^Host key for \S+ has changed and you have requested strict checking\.$`)
	shapeRevokedDecision     = regexp.MustCompile(`^[A-Z0-9-]+ host key for \S+ was revoked and you have requested strict checking\.$`)
	shapeRevokedFileDecision = regexp.MustCompile(`^Host key [A-Z0-9-]+ SHA256:\S+ revoked by file .+$`)
	shapeUnknownDecision     = regexp.MustCompile(`^No [A-Z0-9-]+ host key is known for \S+ and you have requested strict checking\.$`)
)

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
			// sshd closes a connection before it sends its identification string when the address has
			// recent failed logins, and when it has no key exchange algorithm or host key type to offer.
			// The client's own reset line is all the output there is, so the two cannot be told apart.
			return "the server closed the connection before it named its host key; sshd does this for an address with recent failed logins, and when it has no key exchange algorithm or host key type to offer"
		}
	}
	return ""
}
