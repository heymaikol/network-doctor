package sshverify

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

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
// whole transcript has OpenSSH's shape, from the configuration lines to the end of the output
// (hostshape.go). A matching line alone is not enough, and neither is a clean end alone. The probe
// also forces LogLevel DEBUG1, which hides the debug2 lines that print the server's own algorithm
// lists. probeArgs documents the rest.

// hostTrust is OpenSSH's decision about the host key, as its own record states it.
type hostTrust struct {
	// algorithm is the host key algorithm OpenSSH negotiated. The credential connection
	// offers only this one, so the algorithm checked here is the one that is used.
	algorithm string
	// fingerprint is the SHA256 fingerprint of the subject key OpenSSH checked. For a host
	// certificate it is the key the certificate certifies, not the certificate blob.
	fingerprint string
	// certificate says OpenSSH printed a host certificate, and keyID is the key ID it printed
	// for it. The key ID is text the signer chose, so the credential connection must present
	// the same one; see pinCheck.
	certificate bool
	keyID       string
	// serial and authority are the certificate's serial number and the SHA256 fingerprint of
	// the key that signed it, as OpenSSH printed them. The credential connection must present
	// the same ones, so two certificates for one subject key are told apart; see pinCheck.
	serial    string
	authority string
}

// probeArgs is the argument vector for the probe: the options that decide what the client
// prints and what it may do, followed by the destination ssh -G read. It overrides no known-hosts
// file, CheckHostIP, or revocation list: OpenSSH applies those from the user's configuration. It
// does override KnownHostsCommand, to none, so a command written after the route read cannot change
// the decision. The options that stop a probe from doing more than the handshake are: no session
// (-N), no credential method, no agent, no control connection, no forwarding, no local command,
// no proxy, no provider, and no background process. A Match exec in the configuration can run
// whenever OpenSSH reads the configuration, including the probe's own read, and no option turns
// that off. The route read refuses a configuration with a Match exec before the probe starts, and
// the probe refuses a transcript that shows a configured command ran. Neither stops the command
// from running. VisualHostKey and HostbasedAuthentication are off, because their output is not part
// of the shape and they change nothing about the trust decision.
func probeArgs(dest []string) []string {
	return append([]string{
		"-N", "-n", "-T",
		"-o", "LogLevel=DEBUG1",
		"-o", "VisualHostKey=no",
		"-o", "HostbasedAuthentication=no",
		"-o", "LogVerbose=none",
		"-o", "FingerprintHash=sha256",
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
		// Each of these lets the configuration run a program or load a provider during the check.
		// "none" only removes keys from OpenSSH's decision, so it can make the decision stricter,
		// never looser. GSSAPI and ForkAfterAuthentication would start a credential exchange or a
		// background process, which this check never wants.
		"-o", "KnownHostsCommand=none",
		"-o", "PKCS11Provider=none",
		"-o", "SecurityKeyProvider=none",
		"-o", "GSSAPIAuthentication=no",
		"-o", "ForkAfterAuthentication=no",
	}, dest...)
}

// openSSHProbe is the host-key decision a check asks for. The product uses probeHostKey; tests
// replace it with a fixed decision, and the integration tests run the real client.
var openSSHProbe = probeHostKey

// sshTestArgs are options that ssh -G and the probe both read before the destination. Only the
// integration tests set them, to point the client at a test configuration.
var sshTestArgs []string

// probeOutputLimit bounds what the probe keeps of OpenSSH's output.
const probeOutputLimit = 1 << 20

// probeWaitDelay bounds the wait for the probe's output once the client has ended or been killed.
const probeWaitDelay = 2 * time.Second

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
	if r, ok := confirmRoute(ctx, program, t, dest); !ok {
		return hostTrust{}, false, r
	}
	transcript, status, err := runHostKeyProbe(ctx, program, probeArgs(dest))
	if ctx.Err() != nil {
		return hostTrust{}, false, transport(ctx, "the OpenSSH host-key check did not finish")
	}
	if err != nil {
		return hostTrust{}, false, Result{Outcome: TransportFailure, Detail: textsafe.Clean(err.Error()) + "; nothing was sent"}
	}
	transcript, ok := transcriptWithoutGSSAPI(ctx, transcript, func() ([]byte, error) {
		return kexGSSQuery(ctx, program)
	})
	if !ok {
		if ctx.Err() != nil {
			return hostTrust{}, false, transport(ctx, "the OpenSSH host-key check did not finish")
		}
		return hostTrust{}, false, Result{Outcome: TransportFailure, Detail: "OpenSSH printed a GSSAPI diagnostic, and netdoc could not confirm that the client has no GSSAPI key exchange; nothing was sent"}
	}
	return parseHostTrust(transcript, status)
}

// gssapiUnsupportedLine is the diagnostic a client without GSSAPI prints for the probe's own
// GSSAPIAuthentication=no override. It is removed only as the first line, and only when the same
// client lists no GSSAPI key exchange. Then the override has nothing to disable, and no other line
// of the transcript is relaxed.
const gssapiUnsupportedLine = `command-line line 0: Unsupported option "gssapiauthentication"`

// gssapiQueryAnswer is the whole answer a client without GSSAPI gives to ssh -Q kex-gss: one line,
// with a nonzero exit status.
const gssapiQueryAnswer = `Unsupported query "kex-gss"`

// withoutGSSAPIUnsupported returns the transcript without its first line when that line is the
// GSSAPI diagnostic and the query for GSSAPI key exchange gives exactly gssapiQueryAnswer, with a
// nonzero exit. Any other answer refuses the check: a successful exit, empty or unrelated output,
// more than one line, a process ended by a signal (including a timeout), or a query that cannot run.
// A transcript without the diagnostic first is returned unchanged, so a diagnostic anywhere else
// still refuses it in the shape check.
func withoutGSSAPIUnsupported(transcript []byte, kexList func() ([]byte, error)) ([]byte, bool) {
	lines := splitTranscript(transcript)
	if len(lines) == 0 || lines[0] != gssapiUnsupportedLine {
		return transcript, true
	}
	out, err := kexList()
	var exit *exec.ExitError
	if err == nil || !errors.As(err, &exit) || exit.ExitCode() < 1 {
		return nil, false
	}
	answer := splitTranscript(out)
	if len(answer) != 1 || answer[0] != gssapiQueryAnswer {
		return nil, false
	}
	return []byte(strings.Join(lines[1:], "\n") + "\n"), true
}

// transcriptWithoutGSSAPI is the GSSAPI step of probeHostKey. The exception is part of the check, so it
// holds only while the check's context is live. A query that answers exactly and exits nonzero is
// still refused when the context has ended by the time its answer is judged.
func transcriptWithoutGSSAPI(ctx context.Context, transcript []byte, kexList func() ([]byte, error)) ([]byte, bool) {
	transcript, ok := withoutGSSAPIUnsupported(transcript, kexList)
	return transcript, ok && ctx.Err() == nil
}

// kexGSSQuery runs the client's GSSAPI key exchange query under the rules runHostKeyProbe uses. The
// query gets its own process group, so cancellation and the cleanup after it exit reach any child it
// started. Its standard output and standard error share one pipe, read to the probe's output limit.
// The wait for that pipe is bounded by probeWaitDelay, and output still open after the bound is
// refused as incomplete. WaitDelay is not used: exec applies it only to copy goroutines, which a file
// pipe does not have, and after a nonzero exit it reports nothing, so it could not tell a complete
// answer from an open one.
func kexGSSQuery(ctx context.Context, program string) ([]byte, error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer outR.Close()
	cmd := exec.CommandContext(ctx, program, "-Q", "kex-gss") // #nosec G204 -- fixed arguments
	configureProcess(cmd)
	cmd.Stdout = outW
	cmd.Stderr = outW
	err = cmd.Start()
	_ = outW.Close()
	if err != nil {
		return nil, err
	}
	out := captureProbeStream(outR, probeOutputLimit)
	waitErr := cmd.Wait()
	killProcessGroup(cmd.Process.Pid)
	data, complete := out.finish(outR, probeWaitDelay)
	if out.over || !complete {
		return nil, errProbeOutput
	}
	return data, waitErr
}

// errProbeOutput refuses a probe that wrote to standard output or ran past the output limit.
var errProbeOutput = errors.New("the OpenSSH host-key check wrote unexpected output")

// runHostKeyProbe runs program with args and returns its diagnostic output and exit status. The
// argument vector is passed as a slice, with no shell. The probe may write nothing to standard
// output, and its diagnostic output is held to probeOutputLimit. Its whole process group ends with
// it on both cancellation and normal exit, and its wait for output is bounded.
func runHostKeyProbe(ctx context.Context, program string, args []string) ([]byte, int, error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, 0, err
	}
	defer outR.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outW.Close()
		return nil, 0, err
	}
	defer errR.Close()

	cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 -- a fixed option vector and the destination ssh -G read; no shell
	configureProcess(cmd)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS_REQUIRE=never")
	cmd.Stdout = outW
	cmd.Stderr = errW
	err = cmd.Start()
	_ = outW.Close()
	_ = errW.Close()
	if err != nil {
		return nil, 0, err
	}

	out := captureProbeStream(outR, 0)
	diag := captureProbeStream(errR, probeOutputLimit)

	waitErr := cmd.Wait()
	// Kill any descendant still in the probe's process group, even after a normal exit, so a
	// helper holding stderr open cannot outlive the probe or stall output collection.
	killProcessGroup(cmd.Process.Pid)
	_, outComplete := out.finish(outR, probeWaitDelay)
	stderr, diagComplete := diag.finish(errR, probeWaitDelay)

	var exit *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exit) {
		return nil, 0, waitErr
	}
	if out.over || diag.over || !outComplete || !diagComplete {
		return nil, 0, errProbeOutput
	}
	status := 0
	if exit != nil {
		status = exit.ExitCode()
	}
	return stderr, status, nil
}

// probeStream captures one pipe up to limit bytes and drains any overflow so the child cannot block.
type probeStream struct {
	data []byte
	over bool
	done chan struct{}
}

func captureProbeStream(r *os.File, limit int) *probeStream {
	s := &probeStream{done: make(chan struct{})}
	go func() {
		defer close(s.done)
		data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
		s.data = data
		s.over = err == nil && len(data) > limit
		if s.over {
			_, _ = io.Copy(io.Discard, r)
		}
	}()
	return s
}

func (s *probeStream) finish(r *os.File, grace time.Duration) ([]byte, bool) {
	select {
	case <-s.done:
		return s.data, true
	case <-time.After(grace):
		_ = r.Close()
		<-s.done
		return s.data, false
	}
}

// confirmRoute reads the configuration again, under the rules the first read applied, immediately
// before the probe. The probe reads the configuration itself, and it overrides KnownHostsCommand
// and the providers, so a configuration that changed since the first read would otherwise be
// trusted without anyone seeing the change. A configuration that is no longer one netdoc verifies,
// or that now names another host, port or login, is refused before any credential is sent.
func confirmRoute(ctx context.Context, program string, t Target, dest []string) (Result, bool) {
	route, err := readRoute(ctx, program, append([]string{"-G"}, dest...), true)
	if err != nil {
		return Result{Outcome: LocalFailure, Detail: "the SSH configuration could not be read again before the check: " + textsafe.Clean(err.Error()) + "; nothing was sent"}, false
	}
	if route.Kind != RouteDirect {
		return Result{Outcome: LocalFailure, Detail: "the SSH configuration changed after it was read, and the new one is not one netdoc verifies: " + route.Reason + "; nothing was sent"}, false
	}
	sameLower := func(key, want string) bool {
		got, set := listingValue(route.Listing, key)
		return set && got == strings.ToLower(want)
	}
	gotUser, userSet := listingRawValue(route.Listing, "user")
	if !sameLower("hostname", t.Host) || !sameLower("port", strconv.Itoa(t.Port)) || !userSet || gotUser != t.User {
		return Result{Outcome: LocalFailure, Detail: "the SSH configuration now names another host, port or login than the one checked; nothing was sent"}, false
	}
	return Result{}, true
}
