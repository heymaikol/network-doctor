package sshverify

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strconv"
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
	// certificate says OpenSSH printed a host certificate, and keyID is the key ID it printed
	// for it. The key ID is text the signer chose, so the credential connection must present
	// the same one; see pinCheck.
	certificate bool
	keyID       string
}

// probeArgs is the argument vector for the probe: the options that decide what the client
// prints and what it may do, followed by the destination ssh -G read. It overrides no known-hosts
// file, CheckHostIP, or revocation list: OpenSSH applies those from the user's configuration. It
// does override KnownHostsCommand, to none, so a command written after the route read cannot change
// the decision. The options that stop a probe from doing more than the handshake are: no session
// (-N), no credential method, no agent, no control connection, no forwarding, no local command,
// no proxy, no provider, and no background process. Match exec in the configuration still runs
// when OpenSSH reads it; the route read refuses that, and no option can turn it off.
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
	return parseHostTrust(transcript, status)
}

// errProbeOutput refuses a probe that wrote to standard output or ran past the output limit.
var errProbeOutput = errors.New("the OpenSSH host-key check wrote unexpected output")

// runHostKeyProbe runs program with args and returns its diagnostic output and exit status. The
// argument vector is passed as a slice, with no shell. The probe may write nothing to standard
// output, and its diagnostic output is held to probeOutputLimit. Its whole process group ends with
// it, and its wait for output is bounded.
func runHostKeyProbe(ctx context.Context, program string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 -- a fixed option vector and the destination ssh -G read; no shell
	// The probe's group is killed with it, so no descendant outlives the deadline, and the wait
	// for its output is bounded, so a descendant that holds the output cannot hold the check.
	configureProcess(cmd)
	cmd.WaitDelay = probeWaitDelay
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
	same := func(key, want string) bool {
		got, set := listingValue(route.Listing, key)
		return set && got == want
	}
	if !same("hostname", t.Host) || !same("port", strconv.Itoa(t.Port)) || !same("user", t.User) {
		return Result{Outcome: LocalFailure, Detail: "the SSH configuration now names another host, port or login than the one checked; nothing was sent"}, false
	}
	return Result{}, true
}
