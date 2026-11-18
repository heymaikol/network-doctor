// Package sshverify checks SSH credentials against a server without opening a
// shell. Discovery reports which authentication methods a server offers and
// sends no credential. Verification sends exactly one credential, once, and
// reports whether the server accepted it. Host keys are checked against the
// user's known_hosts files before any credential is sent, and a host key that
// does not match is refused.
package sshverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// resolveTimeout bounds one configuration read, including any Match exec
// command ssh runs while reading it. A hung command must not hold a check open.
var resolveTimeout = 15 * time.Second

// configPlatformSupported says whether the configuration read is safe here. It is
// true only where the read can be made to see the terminal an interactive ssh
// would see; Windows and FreeBSD are refused until that is validated. It is a
// variable so a test can exercise the refusal.
var configPlatformSupported = runtime.GOOS == "linux" || runtime.GOOS == "darwin"

// sshBinary is the OpenSSH client used only to read configuration. Tests
// replace resolveOutput; nothing here connects to the target.
var sshBinary = "ssh"

// Target is the SSH configuration of one destination, as OpenSSH resolves it.
type Target struct {
	Host         string // the host name ssh would dial
	Port         int
	User         string   // the login name ssh would use
	HostKeyAlias string   // the name known_hosts is keyed on, when set
	IdentityFile []string // configured key paths, with ~ expanded
	AgentSocket  string   // the agent socket from IdentityAgent, "" when none
	AgentOff     bool     // IdentityAgent none: ssh uses no agent, so neither does netdoc
	KnownHosts   []string // user known_hosts files, in ssh's order
	GlobalHosts  []string // system-wide known_hosts files, in ssh's order
	// Unsupported names the directive that routes the connection through a
	// proxy. The native client does not run proxies, so a non-empty value
	// means no verification is attempted.
	Unsupported string
}

// Resolve reads the configuration for host, as ssh would resolve it. It runs
// one `ssh -G` with a fixed argument vector. That reads configuration files
// and connects to nothing.
func Resolve(ctx context.Context, host string, port int, login string) (Target, error) {
	if host == "" {
		return Target{}, errors.New("no host given")
	}
	args := []string{"-G"}
	if port > 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if login != "" {
		args = append(args, "-l", login)
	}
	args = append(args, "--", host)
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	out, err := resolveOutput(ctx, args)
	if err != nil {
		return Target{}, fmt.Errorf("could not read the SSH configuration: %w", err)
	}
	home, _ := os.UserHomeDir()
	return parseConfig(out, home)
}

// resolveOutput runs ssh with args and returns its standard output. Standard
// error is returned as part of the error, so a configuration mistake reads
// the same way it does on a terminal.
var resolveOutput = func(ctx context.Context, args []string) ([]byte, error) {
	program, err := sshExecutable(sshBinary)
	if err != nil {
		return nil, err
	}
	return ReadConfig(ctx, program, args)
}

// TerminalAvailable reports whether netdoc has the terminal it was started from. A
// configuration can depend on the environment, and a run with a terminal has the
// environment the user's own ssh has; a run without one, as under cron or in CI,
// does not. It is a variable so tests that stand in for a client can replace it.
var TerminalAvailable = hasControllingTerminal

// errNoTerminal refuses a configuration read that netdoc cannot make equivalent to
// the user's own ssh. Nothing is run or sent.
var errNoTerminal = errors.New("netdoc has no terminal of its own, and a configuration can depend on the environment, which a run without one cannot reproduce for your own ssh; run netdoc from a terminal. Nothing was run or sent")

// hasControllingTerminal reports whether this process can open its terminal.
func hasControllingTerminal() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) // #nosec G304 -- the controlling terminal, opened only to test for it
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

// ReadConfig is the one way netdoc reads a configuration listing for verification. It
// returns the complete listing when the route is known, with or without a proxy, and
// an error otherwise: a route netdoc cannot match to the user's own ssh is refused
// here, so verification never sends a credential by a route it could not establish.
// The platform gate, the terminal check, the canary and the route classification all
// run inside ReadRoute, so no caller can skip them.
func ReadConfig(ctx context.Context, program string, args []string) ([]byte, error) {
	if !configPlatformSupported {
		return nil, unsupportedPlatform()
	}
	if !TerminalAvailable() {
		return nil, errNoTerminal
	}
	route, err := ReadRoute(ctx, program, args)
	if err != nil {
		return nil, err
	}
	if route.Kind == RouteUnknown {
		return nil, errors.New(route.Reason)
	}
	return route.Listing, nil
}

// maxConfigBytes bounds the configuration listing. A real listing is a few
// kilobytes, so anything this large is refused rather than parsed.
const maxConfigBytes = 1 << 20

// outputGrace bounds how long a finished read waits for output that a child the
// client left behind still holds open.
var outputGrace = 2 * time.Second

// Diagnostic markers. OpenSSH prints these at debug level while it reads the
// configuration with -v: the first for each configuration file it reads, the
// second for each command a Match exec test runs, in a file pulled in by Include
// or not. The canary checks that the installed client prints them.
const (
	readingMarker = "debug1: Reading configuration data"
	execMarker    = "debug1: Executing command:"
)

// canaryCheck verifies the installed client before any read is trusted. It is a
// variable so tests that run a fake client can replace it.
var canaryCheck = ensureCanary

// canaries keeps the canary result for each client path, so the check runs once
// per process. A result cut short by a cancellation is not kept.
var canaries sync.Map

// hostBlock is the destination the canary reads. Its address is loopback and it
// names no real host, so nothing the canary does reaches the network.
const hostBlock = "Host canary\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"

const (
	canaryExecConfig  = "Match host canary exec \"true\"\n" + hostBlock
	canaryPlainConfig = hostBlock
)

// Canary probe names. A refusal names the probe that failed, so a difference in the
// installed OpenSSH can be told apart from a real risk.
const (
	probeMarkerExec        = "marker-exec"
	probeMarkerPlain       = "marker-plain"
	probeCanonicalExec     = "canonical-exec"
	probeProxyJumpNone     = "proxyjump-none"
	probeKnownHostsCommand = "knownhostscommand"
)

// ensureCanary runs the fixed probes against the client once per process. A client
// that fails any of them is refused: the configuration rules depend on how it reads
// a configuration, and a client that reads differently cannot be trusted with one.
// A result cut short by a cancellation is not kept.
func ensureCanary(ctx context.Context, program string) error {
	if v, ok := canaries.Load(program); ok {
		err, _ := v.(error)
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	err := runCanary(cctx, program)
	if ctx.Err() == nil {
		canaries.Store(program, err)
	}
	return err
}

// runCanary runs five probes. Each one is a configuration netdoc writes itself, read
// with the same bounded runner every read uses.
func runCanary(ctx context.Context, program string) error {
	dir, err := os.MkdirTemp("", "netdoc-canary-")
	if err != nil {
		return canaryFail("setup", "no temporary directory for the check")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if strings.ContainsAny(dir, " \t'\"") {
		return canaryFail("setup", "the temporary directory name has spaces or quotes, which the KnownHostsCommand probe cannot carry")
	}
	sentinel := filepath.Join(dir, "ran")

	out, diag, err := runProbe(ctx, program, dir, probeMarkerExec, canaryExecConfig)
	if err != nil {
		return err
	}
	if !bytes.Contains(diag, []byte(readingMarker)) || !bytes.Contains(diag, []byte(execMarker)) || !hasLine(out, "hostname 127.0.0.1") {
		return canaryFail(probeMarkerExec, "the client did not report the Match exec test that the check runs")
	}

	out, diag, err = runProbe(ctx, program, dir, probeMarkerPlain, canaryPlainConfig)
	if err != nil {
		return err
	}
	if !bytes.Contains(diag, []byte(readingMarker)) || bytes.Contains(diag, []byte(execMarker)) || !hasLine(out, "hostname 127.0.0.1") {
		return canaryFail(probeMarkerPlain, "the client reported a Match exec test in a configuration that has none")
	}

	// Canonical is false here, because netdoc does not canonicalize hostnames, so an
	// exec test behind it must not run.
	out, diag, err = runProbe(ctx, program, dir, probeCanonicalExec, "Match canonical exec \"true\"\n"+hostBlock)
	if err != nil {
		return err
	}
	if bytes.Contains(diag, []byte(execMarker)) || !hasLine(out, "hostname 127.0.0.1") {
		return canaryFail(probeCanonicalExec, "an exec test behind canonical ran although canonical did not match")
	}

	out, _, err = runProbe(ctx, program, dir, probeProxyJumpNone, hostBlock+"  ProxyJump none\n")
	if err != nil {
		return err
	}
	if !hasLine(out, "hostname 127.0.0.1") || listingKey(out, "proxyjump") || listingKey(out, "proxycommand") {
		return canaryFail(probeProxyJumpNone, "ProxyJump none did not leave the route direct in the listing")
	}

	// -G prints KnownHostsCommand and must not run it: the command would otherwise
	// run during every configuration read, before any route is known.
	out, _, err = runProbe(ctx, program, dir, probeKnownHostsCommand, hostBlock+"  KnownHostsCommand touch "+sentinel+"\n")
	if err != nil {
		return err
	}
	if !listingKey(out, "knownhostscommand") {
		return canaryFail(probeKnownHostsCommand, "the listing does not show the KnownHostsCommand the check set")
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		return canaryFail(probeKnownHostsCommand, "KnownHostsCommand ran during the configuration read")
	}
	return nil
}

// runProbe writes one probe configuration and reads it. A read that fails is reported
// with the probe's name.
func runProbe(ctx context.Context, program, dir, name, body string) ([]byte, []byte, error) {
	path := filepath.Join(dir, name+".config")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return nil, nil, canaryFail(name, "the check could not write its configuration")
	}
	out, diag, err := readConfig(ctx, program, []string{"-v", "-G", "-F", path, "--", "canary"})
	if err != nil {
		return nil, nil, canaryFail(name, err.Error())
	}
	return out, diag, nil
}

// canaryFail is the refusal for one named probe. Nothing is sent when it is returned.
func canaryFail(probe, detail string) error {
	return fmt.Errorf("the installed ssh client failed canary probe %q: %s; netdoc refuses to read the SSH configuration with it, so nothing was sent", probe, textsafe.Clean(detail))
}

// hasLine reports whether the listing has exactly this line.
func hasLine(out []byte, want string) bool {
	for _, line := range bytes.Split(out, []byte("\n")) {
		if string(bytes.TrimRight(line, "\r")) == want {
			return true
		}
	}
	return false
}

// listingKey reports whether the listing has a line for this keyword, with any value.
func listingKey(out []byte, key string) bool {
	for _, line := range bytes.Split(out, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(key+" ")) {
			return true
		}
	}
	return false
}

// readConfig runs the client once, in its own process group, and returns its
// complete standard output and complete diagnostic output. It fails when the run
// was cut short, when either stream was not read to its end or was larger than
// netdoc reads, or when the client exited non-zero.
func readConfig(ctx context.Context, program string, args []string) ([]byte, []byte, error) {
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, nil, errors.New("no pipe for the client's output")
	}
	defer outR.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		_ = outR.Close()
		_ = outW.Close()
		return nil, nil, errors.New("no pipe for the client's output")
	}
	defer errR.Close()
	cmd := exec.CommandContext(ctx, program, args...) // #nosec G702 G204 -- program is the ssh client sshExecutable resolved and permission-checked; args are fixed option flags, the login and port from the parsed target, and the host after "--", each passed as its own argv entry with no shell
	configureProcess(cmd)
	cmd.Stdout = outW
	cmd.Stderr = errW
	err = cmd.Start()
	// The child holds its own copies of the write ends; ours must close so the
	// readers see end of file once every process that holds them has exited.
	_ = outW.Close()
	_ = errW.Close()
	if err != nil {
		_ = outR.Close()
		_ = errR.Close()
		return nil, nil, errors.New("could not start ssh: " + textsafe.Clean(err.Error()))
	}
	stdout := captureOutput(outR)
	stderr := captureOutput(errR)

	// cmd.Wait reaps the client and records its state. A client that exits non-zero
	// is an *exec.ExitError, which is a result to report, not a failure to wait.
	waitErr := cmd.Wait()
	state := cmd.ProcessState
	var exitErr *exec.ExitError
	waited := waitErr == nil || errors.As(waitErr, &exitErr)
	// The client has exited. Anything it left running in its group is killed now,
	// so a read does not leave a helper process behind.
	killProcessGroup(cmd.Process.Pid)
	out, outComplete := stdout.finish(outR)
	diag, diagComplete := stderr.finish(errR)

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return nil, nil, fmt.Errorf("the read did not finish within %s; a Match exec command may be waiting for input, which netdoc cannot give it", resolveTimeout)
	case ctx.Err() != nil:
		return nil, nil, errors.New("the read was cancelled")
	case !waited:
		return nil, nil, errors.New("could not wait for ssh: " + textsafe.Clean(waitErr.Error()))
	case stdout.tooLarge:
		return nil, nil, errors.New("the listing is larger than netdoc reads")
	case !outComplete:
		return nil, nil, errors.New("the output was not complete, because a process the read started kept it open")
	case !state.Success():
		if text := strings.TrimSpace(textsafe.Clean(string(withoutDebugLines(diag)))); text != "" {
			return nil, nil, errors.New(text)
		}
		return nil, nil, fmt.Errorf("ssh exited with %s", state)
	case stderr.tooLarge:
		return nil, nil, errors.New("the SSH client's diagnostic output is larger than netdoc reads, so it cannot check which configuration rules ran; nothing was sent")
	case !diagComplete:
		return nil, nil, errors.New("the SSH client's diagnostic output was not complete, because a process the read started kept it open, so it cannot check which configuration rules ran; nothing was sent")
	}
	return out, diag, nil
}

// withoutDebugLines drops the debug lines OpenSSH prints at -v, so a failure is
// reported as the message the user would see without that flag.
func withoutDebugLines(msg []byte) []byte {
	var keep [][]byte
	for _, line := range bytes.Split(msg, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("debug")) {
			continue
		}
		keep = append(keep, line)
	}
	return bytes.Join(keep, []byte("\n"))
}

// capturedOutput is one stream read to its end in the background.
type capturedOutput struct {
	data     []byte
	tooLarge bool
	done     chan struct{}
}

func captureOutput(r *os.File) *capturedOutput {
	c := &capturedOutput{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
		c.data = data
		c.tooLarge = err == nil && len(data) > maxConfigBytes
		// Past the limit the client may still be writing. Keep draining so it can
		// finish and exit; the bytes are discarded, so memory stays at the limit.
		if c.tooLarge {
			_, _ = io.Copy(io.Discard, r)
		}
	}()
	return c
}

// finish waits for the stream to end. It reports false when the stream did not
// end within outputGrace, in which case the read is closed and its partial data
// is not a complete listing.
func (c *capturedOutput) finish(r *os.File) ([]byte, bool) {
	select {
	case <-c.done:
		return c.data, true
	case <-time.After(outputGrace):
		_ = r.Close()
		<-c.done
		return c.data, false
	}
}

// sshExecutable finds the OpenSSH client on PATH and refuses it when the file
// or its directory can be written by anyone but the owner. The client reads the
// user's configuration and is trusted with it, so a writable copy on PATH would
// be a way to run other code with the user's configuration in hand.
func sshExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("the ssh client was not found on PATH")
	}
	if err := checkClientPermissions(path); err != nil {
		return "", err
	}
	return path, nil
}

// parseConfig reads the key-value listing `ssh -G` prints. Most keywords
// appear once; identityfile repeats, and the known-hosts files are one line of
// space-separated paths. home expands the ~ that ssh leaves in identity paths.
func parseConfig(out []byte, home string) (Target, error) {
	var t Target
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			t.Host = value
		case "port":
			p, err := strconv.Atoi(value)
			if err != nil {
				return Target{}, errors.New("the SSH configuration gave an unreadable port")
			}
			t.Port = p
		case "user":
			t.User = value
		case "hostkeyalias":
			t.HostKeyAlias = value
		case "identityfile":
			t.IdentityFile = append(t.IdentityFile, expandHome(value, home))
		case "identityagent":
			if value == "none" {
				t.AgentOff = true
			} else {
				t.AgentSocket = expandHome(value, home)
			}
		case "userknownhostsfile":
			t.KnownHosts = append(t.KnownHosts, splitPaths(value, home)...)
		case "globalknownhostsfile":
			t.GlobalHosts = append(t.GlobalHosts, splitPaths(value, home)...)
		case "proxyjump", "proxycommand":
			if value != "none" && t.Unsupported == "" {
				t.Unsupported = key
			}
		}
	}
	if t.Host == "" || t.Port == 0 || t.User == "" {
		return Target{}, errors.New("the SSH configuration did not name a host, port and user")
	}
	return t, nil
}

func splitPaths(value, home string) []string {
	var paths []string
	for _, p := range strings.Fields(value) {
		paths = append(paths, expandHome(p, home))
	}
	return paths
}

// expandHome replaces a leading ~/ with the home directory. A path that still
// holds a %-token is returned as written; the caller refuses to open it.
func expandHome(p, home string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

// ExistingIdentityFiles returns the configured key files that exist as regular
// files, in ssh's order. A path holding a %-token is left out: it names a key
// ssh would expand per connection, and netdoc does not guess at the expansion.
func ExistingIdentityFiles(t Target) []string {
	var out []string
	for _, p := range t.IdentityFile {
		if strings.Contains(p, "%") {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			out = append(out, p)
		}
	}
	return out
}
