package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// No shell, anywhere. exec starts the ssh binary with these as separate
	// argv elements, and the remote command is two fixed ASCII words, so the
	// remote shell (POSIX sh, cmd.exe, or PowerShell alike) has nothing to
	// expand, split, or interpret.
	//
	// -T because this is a byte protocol on a pipe: a pseudo-terminal would be
	// free to translate line endings and echo what is written through it.
	// Password, passphrase, and host-key prompts are unaffected; ssh reads
	// those from the terminal directly, not from the stdin used here.
	// #nosec G204 -- sshProgram is fixed, dest is validated against argv option
	// injection, and every element stays a separate argument, never shell text.
	cmd := exec.CommandContext(ctx, sshProgram, "-T", dest, command, WorkerFlag)
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
		return Response{}, transportError(ctx, dest, exitStatus(cmd, waitErr), errBuf.String(), decodeErr)
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
func transportError(ctx context.Context, dest string, status int, stderrText string, cause error) error {
	detail := indentLines(clean(stderrText))
	switch {
	case ctx.Err() != nil:
		return fmt.Errorf("%s: the run was interrupted", cleanDest(dest))
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
