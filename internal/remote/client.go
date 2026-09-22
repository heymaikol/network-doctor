package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// cancelGrace is how long Wait tolerates a killed ssh's pipes staying open.
// Without a delay, Wait blocks until every inherited pipe closes, and after a
// cancellation those belong to a process that was just killed for not
// finishing.
const cancelGrace = 2 * time.Second

// responseEOFGrace bounds how long a completed response waits for SSH stdout
// to finish naturally. During this window the existing framing check can still
// observe trailing protocol data. Afterward Run ends SSH so an inherited remote
// stdout cannot withhold an already-complete diagnosis indefinitely.
const responseEOFGrace = 2 * time.Second

// maxDiagnosisStages is how many probe budgets one remote diagnosis can spend
// one after another. Both executors start every ready probe at once, so a pass
// costs the probe graph's deepest dependency chain rather than the sum over
// every probe, and that chain is five rungs deep for the richest target shape
// netdoc builds. internal/diagnostic's TestProbeGraphStagesAndWorstCaseBudget
// pins that number, so a sixth rung fails there before it can silently make a
// legitimate remote run outlast this bound.
const maxDiagnosisStages = 5

// transportAllowance is what one exchange may spend on everything that is not
// probing: opening the SSH connection, authenticating (a passphrase, a hardware
// key, an MFA approval), starting the remote worker, the request and response
// on the wire, and teardown. It is a var only so tests can shrink it; nothing
// at runtime changes it.
var transportAllowance = time.Minute

// operationTimeout is the whole acquisition's ceiling, derived from the probe
// budget the request carries rather than fixed, so a deliberately long
// --timeout still gets a proportionally long remote run.
//
// It is not Request.TimeoutMs itself: that is one probe's budget, and a
// diagnosis legitimately spends several of them in sequence. It is the deepest
// chain of probe budgets a remote pass can spend, plus the transport allowance,
// which is by construction longer than any run the far end can honestly still
// be working on and finite for one that is not.
//
// The arithmetic stays in milliseconds so a probe budget near the top of the
// range cannot wrap; a request that large saturates instead.
func operationTimeout(probeTimeoutMs int64) time.Duration {
	if probeTimeoutMs <= 0 {
		// No usable budget in the request. The far end refuses such a request
		// outright, so only the transport still has to be bounded here.
		return transportAllowance
	}
	allowanceMs := int64(transportAllowance / time.Millisecond)
	const maxMs = int64(math.MaxInt64) / int64(time.Millisecond)
	if probeTimeoutMs > (maxMs-allowanceMs)/maxDiagnosisStages {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(probeTimeoutMs*maxDiagnosisStages)*time.Millisecond + transportAllowance
}

// maxStderrBytes keeps the first of ssh's stderr. The first bytes are the
// useful ones: ssh says why a login failed up front, and a remote shell says
// why a command did not start in its first line.
const maxStderrBytes = 8 << 10

// sshFailedStatus is the status ssh reserves for its own failures, as opposed
// to passing back the remote command's.
const sshFailedStatus = 255

// sshProgram is the client, resolved on PATH the way any other invocation of it
// would be. Tests point it at a stand-in so the transport can be exercised
// without an SSH server; nothing else ever changes it.
var sshProgram = "ssh"

// writeRequest is the one request write. Tests replace it to exercise a write
// failure deterministically without depending on process scheduling.
var writeRequest = func(w io.Writer, p []byte) (int, error) {
	return w.Write(p)
}

// Run performs one diagnosis on dest by starting a netdoc worker there through
// the system SSH client, and returns what that worker answered.
//
// The user's own OpenSSH does everything OpenSSH already does: dest is handed
// over exactly as typed, so a ~/.ssh/config alias, a user@host, a ProxyJump, an
// IdentityFile, a port, and agent authentication all behave the way they do for
// `ssh dest`. Nothing here parses ssh_config, and nothing here re-implements a
// line of it.
//
// command is the remote program, empty for DefaultCommand.
//
// A returned error is a transport or protocol failure, or a remote netdoc that
// refused the request: in every one of those the diagnosis did not happen. A
// diagnosis that happened and went badly is not an error here; it comes back
// inside the Response, because "the remote network is broken" and "the SSH
// connection is broken" are different answers and must not share a code path.
func Run(ctx context.Context, dest, command string, req Request) (Response, error) {
	return run(ctx, dest, command, req, false)
}

// batchOptions is the fixed set of ssh options that makes one acquisition
// incapable of asking the user anything. Every value is a literal, and a
// command-line -o is the first value ssh obtains for a keyword, so an
// ssh_config saying otherwise cannot put any of them back.
//
// BatchMode alone is not enough, which is the whole reason this is a list. It
// turns the questions ssh asks itself into refusals: a password, a
// keyboard-interactive or MFA challenge, an encrypted key's passphrase, and the
// unknown-host-key confirmation. It does not cover the questions something else
// asks on ssh's behalf, and there are three of those here:
//
//   - A FIDO authenticator's PIN is read by the security-key signing path,
//     which retries a refused signature by asking for a PIN, and that retry is
//     not under BatchMode. Removing every security-key signature algorithm
//     means such a key is skipped before it is ever offered, so the signing
//     path is not reached. Both families have to be named: OpenSSH's
//     webauthn-sk-ecdsa-sha2-nistp256@openssh.com and its certificate form are
//     security-key algorithms that do not begin with "sk-", so "sk-*" by
//     itself does not remove them. They are one list and it carries one
//     operator: the leading "-" of "-sk-*,webauthn-sk-*" applies to every
//     pattern after it. Spelling the second one "-webauthn-sk-*" would not be
//     a second removal, it would be a pattern beginning with a hyphen that
//     matches no algorithm, and that family would stay offered.
//   - An agent decides for itself what to ask. A key added with `ssh-add -c`
//     confirms through the agent's own askpass, an agent can hold FIDO keys,
//     and a third-party agent can show whatever interface it likes. None of
//     that is ours to bound, so the concurrent path uses no agent at all.
//   - A PKCS#11 provider is a library loaded into ssh that may ask for a smart
//     card's PIN.
//
// GSSAPI is off for the same reason, one step further out: the exchange itself
// does not prompt, but which mechanism library answers it is not ours to say.
// Hostbased authentication is left alone: ssh-keysign signs with an unencrypted
// host key and has nothing to ask.
//
// A ProxyJump child and a ProxyCommand are the remaining prompting programs.
// Neither inherits a word of the above: each is a separate program, a jump
// child is an ordinary interactive ssh that can ask for the bastion's own
// password or host-key confirmation, and a ProxyCommand is whatever the user
// named. Both are pinned off here, and that pin is only sound because of the
// order it happens in.
//
// Direct reads the user's ordinary configuration first. A destination it
// reports as proxied never reaches this transport at all: the profile stays
// sequential over Run, with the configured proxy used exactly as written. Only
// a destination that configuration already said to reach directly is acquired
// here, and the pin then holds that answer for the whole pass. It is not a way
// to reach a proxied host without its proxy; it is what stops a second
// evaluation of the same config, through a Match exec whose result moved, from
// producing a prompting child this list cannot bound. A batch acquisition that
// fails for any reason falls back to Run, which evaluates and honors the
// configuration as it stands at that moment, proxy included.
//
// AddKeysToAgent is off because an ssh_config asking for "ask" turns a used
// software key into an askpass prompt. PreferredAuthentications names the one
// method this transport can complete, so an acquisition is public-key or
// nothing, rather than a password method selected and then refused.
//
// What remains eligible is a plain software key on disk, and nothing else. An
// unencrypted one connects; an encrypted one is refused rather than asked
// about. Everything refused here falls back to the ordinary transport, one
// acquisition at a time.
var batchOptions = []string{
	"BatchMode=yes",
	"PreferredAuthentications=publickey",
	"ProxyJump=none",
	"ProxyCommand=none",
	"PubkeyAcceptedAlgorithms=-sk-*,webauthn-sk-*",
	"IdentityAgent=none",
	"AddKeysToAgent=no",
	"PKCS11Provider=none",
	"GSSAPIAuthentication=no",
}

// RunBatch is Run over a transport that cannot ask the user anything itself;
// see batchOptions for what that costs and why each part of it is there.
//
// It exists so that several acquisitions can be in flight at once without their
// prompts landing on one terminal together. It is not a faster Run and not a
// default: a caller that has a user to ask wants Run, and one that cannot
// afford a question wants this and has to be ready for the refusal.
//
// It bounds this ssh process and every program it would start, but it does so
// by pinning ProxyJump and ProxyCommand off, so a caller must first establish
// with Direct that the user's configuration reaches this destination directly
// anyway. Calling it on a destination Direct has not cleared would connect
// around a configured proxy, which is not netdoc's decision to make.
//
// It fails closed. An ssh too old to know one of these options rejects the
// whole invocation, which is a refusal like any other and sends the caller back
// to Run.
func RunBatch(ctx context.Context, dest, command string, req Request) (Response, error) {
	return run(ctx, dest, command, req, true)
}

// sshConfigTimeout bounds reading the effective configuration. That read is
// local and normally instant, but ssh_config can contain a Match exec whose
// command is an arbitrary local program, so it still needs an end.
const sshConfigTimeout = 10 * time.Second

// Direct reports whether dest reaches its host without a ProxyJump or a
// ProxyCommand, by asking ssh for the destination's effective configuration.
//
// It is the precondition for running several RunBatch acquisitions at once. A
// proxied destination is excluded rather than un-proxied: the configured path
// may be the only route, or the audited one, and netdoc connecting around it
// would be both a different connection and a policy decision it has no standing
// to make. A jump child is also an ordinary interactive ssh that would ask for
// the bastion's own password or host-key confirmation, which is the prompt
// collision this whole path exists to prevent.
//
// It answers false for anything it could not establish: an ssh that failed, one
// that is not there, output it did not understand, or a read that outlasted its
// bound. Every one of those means the caller acquires one component at a time,
// which is what netdoc has always done.
//
// It costs one extra evaluation of the user's ssh_config per profile pass, on
// top of the one each acquisition performs. A Match exec or a KnownHostsCommand
// therefore runs once more than it otherwise would. That is the deliberate
// price of not silently bypassing a configured proxy.
//
// Its answer is what RunBatch then freezes. A Match exec is an arbitrary local
// program and may decide differently on the next evaluation, so a later
// acquisition could otherwise start a proxy child that no batch option reaches.
// Pinning the proxy off for accelerated acquisitions holds this reading for the
// pass; a destination read as proxied here is never acquired that way, and a
// batch acquisition that fails hands the work back to Run and its unpinned
// configuration.
func Direct(ctx context.Context, dest string) bool {
	if err := validateDestination(dest); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, sshConfigTimeout)
	defer cancel()
	// -G prints the configuration ssh would use for this destination without
	// connecting to anything.
	// #nosec G204 -- sshProgram is fixed and dest is validated against argv
	// option injection, and both stay separate arguments, never shell text.
	cmd := exec.CommandContext(ctx, sshProgram, "-G", dest)
	cmd.WaitDelay = cancelGrace
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	understood := false
	for _, line := range strings.Split(string(out), "\n") {
		keyword, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch strings.ToLower(keyword) {
		case "hostname":
			// Every ssh that knows -G prints this one. Requiring it is what
			// makes silence an unanswered question rather than a yes.
			understood = true
		case "proxyjump", "proxycommand":
			// ssh omits either keyword when it is unset or set to none, so
			// reaching here is a configured proxy. The value is checked anyway
			// rather than trusting that omission to stay true.
			if !strings.EqualFold(strings.TrimSpace(value), "none") {
				return false
			}
		}
	}
	return understood
}

func run(ctx context.Context, dest, command string, req Request, batch bool) (Response, error) {
	if err := validateDestination(dest); err != nil {
		return Response{}, err
	}
	if command == "" {
		command = DefaultCommand
	} else if err := validateCommand(command); err != nil {
		return Response{}, err
	}
	req.Protocol = Protocol
	body, err := marshalRequest(req)
	if err != nil {
		return Response{}, err
	}

	// The whole acquisition is bounded here, before ssh is started, because
	// every part of it can stall: the connection, the worker's startup, the
	// request write, and the wait for a first response. The caller's context is
	// an interruption channel with no deadline of its own, so without this a
	// peer that simply never answers strands the run for as long as it likes.
	//
	// It is a separate context from the caller's rather than a deadline placed
	// on it, so the two remain distinguishable afterwards: one is the user
	// stopping the run, the other is netdoc giving up on the transport.
	limit := operationTimeout(req.TimeoutMs)
	opCtx, endOperation := context.WithTimeout(ctx, limit)
	defer endOperation()

	// No shell, anywhere. exec starts the ssh binary with these as separate
	// argv elements, and the remote command is two fixed ASCII words, so the
	// remote shell (POSIX sh, cmd.exe, or PowerShell alike) has nothing to
	// expand, split, or interpret.
	//
	// -T because this is a byte protocol on a pipe: a pseudo-terminal would be
	// free to translate line endings and echo what is written through it.
	// Password, passphrase, and host-key prompts are unaffected; ssh reads
	// those from the terminal directly, not from the stdin used here.
	args := []string{"-T"}
	if batch {
		// Ahead of the destination, because ssh reads options before it.
		for _, option := range batchOptions {
			args = append(args, "-o", option)
		}
	}
	args = append(args, dest, command, WorkerFlag)
	// #nosec G204 -- sshProgram is fixed, dest is validated against argv option
	// injection, and every element stays a separate argument, never shell text.
	cmd := exec.CommandContext(opCtx, sshProgram, args...)
	cmd.WaitDelay = cancelGrace
	errBuf := &capped{limit: maxStderrBytes}
	cmd.Stderr = errBuf

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Response{}, fmt.Errorf("could not start ssh: %s", clean(err.Error()))
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Response{}, fmt.Errorf("could not start ssh: %s", clean(err.Error()))
	}
	if err := cmd.Start(); err != nil {
		return Response{}, fmt.Errorf("could not run ssh: %s", clean(err.Error()))
	}

	// The request is written, and the pipe is then deliberately left open. The
	// worker reads one JSON object and treats the rest of the stream as the
	// local side's liveness signal: while this pipe is open the run is still
	// wanted, and when ssh goes away the remote sees EOF and stops probing
	// instead of finishing a diagnosis nobody will read.
	var resp Response
	var dec *json.Decoder
	var limited *io.LimitedReader
	var decodeErr error
	stopSSH := false
	if _, err := writeRequest(stdin, body); err != nil {
		// A write that fails means ssh is already gone. Its own stderr and exit
		// status say why far better than a broken-pipe error would, and this is
		// the same "nothing came back" outcome from the caller's side.
		decodeErr = ErrNoResponse
		stopSSH = true
	} else {
		resp, dec, limited, decodeErr = decodeResponse(stdout)
		stopSSH = decodeErr != nil
	}
	// Close the worker's liveness input once its response is decoded. This lets
	// a normal worker and SSH session finish naturally before the bounded stdout
	// teardown below has to intervene.
	_ = stdin.Close()

	if stopSSH {
		// A peer that already failed decoding or framing gets no teardown
		// grace. Stop ssh so the failed exchange cannot strand its writer.
		_ = cmd.Process.Kill()
		_ = stdout.Close()
	} else {
		// Check the remainder on the exact decoder and LimitedReader that read
		// the first response. This is the only reader of stdout.
		trailing := make(chan error, 1)
		go func() {
			trailing <- confirmNoTrailingData(dec, limited)
		}()

		timer := time.NewTimer(responseEOFGrace)
		var framingErr error
		select {
		case framingErr = <-trailing:
			_ = timer.Stop()
		case <-timer.C:
			// A complete valid response is already in hand. If stdout still
			// has no end after the bounded teardown window, stop the local SSH
			// transport. Killing ssh closes its stdout writer after bytes
			// already delivered through the pipe, letting the framing check
			// finish without treating remote EOF as an unbounded requirement.
			_ = cmd.Process.Kill()
			framingErr = <-trailing
		}

		if framingErr != nil {
			_ = cmd.Process.Kill()
			_ = stdout.Close()
			decodeErr = framingErr
		} else {
			// Drain what is left so ssh is never blocked writing into a full
			// pipe while we wait. Bounded, for the same reason the decode was.
			_, _ = io.Copy(io.Discard, io.LimitReader(stdout, MaxResponseBytes))
		}
	}
	waitErr := cmd.Wait()

	if decodeErr != nil {
		return Response{}, transportError(ctx, opCtx, limit, dest, exitStatus(cmd, waitErr), errBuf.String(), decodeErr)
	}
	// A response decoded, so the exchange succeeded and ssh's exit status is
	// not consulted for the verdict. The worker exits 0 for a failed diagnosis
	// on purpose; anything nonzero here is teardown noise after an answer we
	// already hold, and reading it as a failure would make an unhealthy remote
	// network indistinguishable from a broken connection.
	if resp.Error != "" {
		return resp, fmt.Errorf("%s: %s", cleanDest(dest), clean(resp.Error))
	}
	return resp, nil
}

// transportError words the failures where no diagnosis came back at all, which
// are the ones a user has to be able to act on without reading this file.
//
// It is handed both contexts on purpose. opCtx is derived from ctx, so a
// deadline netdoc set for itself and a cancellation the user asked for both
// leave opCtx.Err() non-nil, and only the caller's own context can say which
// happened. Reading the derived one first would report every remote timeout as
// an interruption nobody performed.
func transportError(ctx, opCtx context.Context, limit time.Duration, dest string, status int, stderrText string, cause error) error {
	detail := indentLines(clean(stderrText))
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("%s: the run was interrupted", cleanDest(dest))
	case errors.Is(opCtx.Err(), context.DeadlineExceeded):
		return withDetail(fmt.Sprintf("%s: the remote run timed out after %s", cleanDest(dest), limit),
			join(detail,
				"That is the time one diagnosis over SSH is allowed end to end, not a",
				"verdict about the remote network: the connection, the remote netdoc, or",
				"the path between them stopped making progress. Retry, or raise -timeout",
				"if the remote run legitimately needs longer."))
	case status == sshFailedStatus:
		return withDetail(fmt.Sprintf("%s: ssh could not open the connection", cleanDest(dest)), detail)
	case errors.Is(cause, ErrNoResponse):
		return withDetail(fmt.Sprintf("%s: netdoc did not run on the SSH host%s", cleanDest(dest), statusPhrase(status)),
			join(detail,
				"Install netdoc on the SSH host and make sure it is on the PATH of a",
				"non-interactive SSH session, or set "+CommandEnv+" to its full path.",
				"The netdoc there also has to be new enough to know "+WorkerFlag+"."))
	default:
		return withDetail(fmt.Sprintf("%s: %s%s", cleanDest(dest), clean(cause.Error()), statusPhrase(status)), detail)
	}
}

func join(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "\n")
}

func statusPhrase(status int) string {
	if status <= 0 {
		return ""
	}
	return fmt.Sprintf(" (ssh exited %d)", status)
}

// exitStatus is ssh's status, or -1 when it never got far enough to have one.
func exitStatus(cmd *exec.Cmd, waitErr error) int {
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		return exit.ExitCode()
	}
	if waitErr != nil || cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.ExitCode()
}

func withDetail(head, detail string) error {
	if strings.TrimSpace(detail) == "" {
		return errors.New(head)
	}
	return errors.New(head + "\n" + detail)
}

// indentLines sets remote text off from netdoc's own words. Text that arrived
// over the wire should never be mistakable for something netdoc said.
func indentLines(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}

// validateDestination refuses what OpenSSH's own argument parsing would
// misread. A destination is user input that lands in argv, and one starting
// with "-" would become an ssh option: -oProxyCommand=... is arbitrary local
// command execution, which is the whole reason this check exists. Whitespace
// goes for the same reason: one argument must not be able to become two.
//
// Nothing else is rejected. No local shell is ever involved, so a semicolon or
// a backtick in a destination is only a hostname that will not resolve, and
// inventing a hostname grammar here would start rejecting the ProxyJump and
// ssh:// forms OpenSSH itself accepts.
func validateDestination(dest string) error {
	if dest == "" {
		return errors.New("needs an SSH destination, for example --via server")
	}
	if strings.HasPrefix(dest, "-") {
		return fmt.Errorf("%q is not a usable SSH destination: it would be read as an ssh option", cleanDest(dest))
	}
	for _, r := range dest {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%q is not a usable SSH destination: it contains whitespace or a control character", cleanDest(dest))
		}
	}
	return nil
}

// validateCommand guards the one piece of this invocation the remote shell
// does see as text. It is an allowlist rather than a denylist: these runes mean
// the same thing to POSIX sh, cmd.exe, and PowerShell, which is the only way
// one value can be correct on every host netdoc supports.
//
// Whitespace is excluded, which rules out a path containing a space. That is
// the deliberate trade: a value the remote shell would split is a value whose
// meaning depends on which remote shell it met, and a wrong guess there starts
// something other than netdoc.
func validateCommand(command string) error {
	if strings.HasPrefix(command, "-") {
		return fmt.Errorf("%s=%q is not usable: it would be read as an ssh option", CommandEnv, textsafe.Clean(command))
	}
	for _, r := range command {
		if !commandRune(r) {
			return fmt.Errorf("%s=%q is not usable: it has to be a plain path with no spaces or shell punctuation, so that it means the same thing to every remote shell", CommandEnv, textsafe.Clean(command))
		}
	}
	return nil
}

func commandRune(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	return strings.ContainsRune(`._-/\:+@~`, r)
}

// cleanDest is single-line on purpose, unlike clean. A destination is quoted
// back inside error messages that are themselves multi-line, and one carrying a
// newline could otherwise forge a line of netdoc's own output.
func cleanDest(dest string) string { return textsafe.Clean(dest) }

// marshalRequest serializes the request and refuses one that outgrew the cap
// the far side will read, so an over-long target fails here with a clear
// message rather than as a truncated object the worker cannot parse.
func marshalRequest(req Request) ([]byte, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("could not encode the remote request: %s", clean(err.Error()))
	}
	if len(body) > MaxRequestBytes {
		return nil, errors.New("the remote request is too large to send")
	}
	// The newline is not a framing rule; the far side decodes one JSON value
	// and stops. It is so that a human watching the stream sees a line.
	return append(body, '\n'), nil
}

// capped keeps the first limit bytes it is given and counts the rest away.
type capped struct {
	b       []byte
	limit   int
	dropped int
}

func (c *capped) Write(p []byte) (int, error) {
	kept := min(max(c.limit-len(c.b), 0), len(p))
	c.b = append(c.b, p[:kept]...)
	c.dropped += len(p) - kept
	return len(p), nil
}

func (c *capped) String() string {
	s := string(bytes.TrimRight(c.b, "\r\n"))
	if c.dropped > 0 {
		s += "\n[" + strconv.Itoa(c.dropped) + " more bytes discarded]"
	}
	return s
}
