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

// ReadConfig is the one way netdoc reads a configuration listing. Every caller
// that routes a connection by its configuration uses it, so none can skip the
// canary, the diagnostic check or the completeness checks. args select a listing,
// such as "-G" and the destination. It returns the complete standard output only
// when the installed client has passed the canary and its diagnostic output shows
// that no Match exec test ran.
func ReadConfig(ctx context.Context, program string, args []string) ([]byte, error) {
	// The platform gate is here, not in one caller, so every path that reads a route
	// is refused on a platform the read has not been validated on.
	if !configPlatformSupported {
		return nil, fmt.Errorf("SSH credential verification is not supported on %s in this build: netdoc cannot yet read the SSH configuration there safely; nothing was sent", runtime.GOOS)
	}
	if !TerminalAvailable() {
		return nil, errNoTerminal
	}
	if err := canaryCheck(ctx, program); err != nil {
		return nil, err
	}
	return runSSHClient(ctx, program, args)
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

const (
	canaryExecConfig  = "Match host canary exec \"true\"\nHost canary\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"
	canaryPlainConfig = "Host canary\n  HostName 127.0.0.1\n  Port 2260\n  User demo\n"
)

// ensureCanary runs the client on two configurations netdoc writes itself. The one
// with a Match exec test must report that the command ran; the one without must
// report none. A client that does not report both is refused.
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

func runCanary(ctx context.Context, program string) error {
	dir, err := os.MkdirTemp("", "netdoc-canary-")
	if err != nil {
		return canaryFailure("no temporary directory for the check")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	withExec := filepath.Join(dir, "exec.config")
	plain := filepath.Join(dir, "plain.config")
	if err := os.WriteFile(withExec, []byte(canaryExecConfig), 0o600); err != nil {
		return canaryFailure("the check could not write its configuration")
	}
	if err := os.WriteFile(plain, []byte(canaryPlainConfig), 0o600); err != nil {
		return canaryFailure("the check could not write its configuration")
	}

	out, diag, err := readConfig(ctx, program, []string{"-v", "-G", "-F", withExec, "--", "canary"})
	if err != nil {
		return canaryFailure(err.Error())
	}
	if !bytes.Contains(diag, []byte(readingMarker)) || !bytes.Contains(diag, []byte(execMarker)) || !bytes.Contains(out, []byte("hostname 127.0.0.1")) {
		return canaryFailure("the client did not report the Match exec test that the check runs")
	}

	out, diag, err = readConfig(ctx, program, []string{"-v", "-G", "-F", plain, "--", "canary"})
	if err != nil {
		return canaryFailure(err.Error())
	}
	if !bytes.Contains(diag, []byte(readingMarker)) || bytes.Contains(diag, []byte(execMarker)) || !bytes.Contains(out, []byte("hostname 127.0.0.1")) {
		return canaryFailure("the client reported a Match exec test in a configuration that has none")
	}
	return nil
}

func canaryFailure(detail string) error {
	return fmt.Errorf("the installed ssh client does not report its configuration reads in the form netdoc checks (%s), so netdoc refuses to read the SSH configuration with it; nothing was sent", textsafe.Clean(detail))
}

// runSSHClient reads the configuration with -v and returns its complete standard
// output, but only when the diagnostic output shows that the client reported its
// reads and that no Match exec test ran.
func runSSHClient(ctx context.Context, program string, args []string) ([]byte, error) {
	out, diag, err := readConfig(ctx, program, append([]string{"-v"}, args...))
	if err != nil {
		return nil, err
	}
	if err := checkDiagnostics(diag); err != nil {
		return nil, err
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		return nil, errors.New("the output was incomplete")
	}
	return out, nil
}

// checkDiagnostics refuses a read whose diagnostic output does not show the client
// reporting its configuration reads, or shows that a Match exec test ran. Such a
// test's answer depends on the terminal and environment netdoc cannot reproduce, so
// the read is refused rather than used.
func checkDiagnostics(diag []byte) error {
	if !bytes.Contains(diag, []byte(readingMarker)) {
		return errors.New("the SSH client's diagnostic output is not in a form netdoc recognizes, so it cannot check which configuration rules ran; nothing was sent")
	}
	if bytes.Contains(diag, []byte(execMarker)) {
		return errors.New("a Match exec command runs in it, whose answer netdoc cannot reproduce; the read is refused and nothing was sent")
	}
	return nil
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
