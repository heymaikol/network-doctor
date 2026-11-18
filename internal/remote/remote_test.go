// The SSH transport and the worker protocol, exercised against a stand-in ssh
// rather than a live server: the failures worth testing here are the ones a
// real host would be an unreliable way to produce.

package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/report"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

// The stand-in ssh is this test binary, re-executed. TestMain answers before
// the testing package parses flags, which is what lets the process be started
// with ssh's argv instead of a test binary's.
const (
	fakeSSHEnv     = "NETDOC_TEST_FAKE_SSH"
	fakeSSHArgv    = "NETDOC_TEST_FAKE_SSH_ARGV"
	fakeSSHRequest = "NETDOC_TEST_FAKE_SSH_REQUEST"
	// fakeSSHAlive names a file a stalling stand-in appends to while it is
	// still running, which is how a test proves the process was really stopped
	// rather than left behind writing into a pipe nobody reads.
	fakeSSHAlive = "NETDOC_TEST_FAKE_SSH_ALIVE"
	// fakeSSHGrandchild names a file the grandchild-holding stand-in writes its
	// pid to, so the test can stop the grandchild when it is done.
	fakeSSHGrandchild = "NETDOC_TEST_FAKE_SSH_GRANDCHILD"
	// fakeSSHGrandchildStop names the file whose removal ends the grandchild. The
	// file exists for the whole test, and once it is gone it stays gone, so the
	// grandchild cannot miss the signal.
	fakeSSHGrandchildStop = "NETDOC_TEST_FAKE_SSH_GRANDCHILD_STOP"
	// fakeSSHConfig names the real configuration file a listing reports reading.
	fakeSSHConfig = "NETDOC_TEST_FAKE_SSH_CONFIG"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeSSHEnv); mode != "" {
		os.Exit(fakeSSH(mode))
	}
	os.Exit(m.Run())
}

// fakeSSH behaves like the ssh client for one exchange. Every mode is a real
// thing OpenSSH or a remote shell does: a command that is not there, a
// connection that never opened, a peer that says something other than the
// protocol.
func fakeSSH(mode string) int {
	if path := os.Getenv(fakeSSHArgv); path != "" {
		// #nosec G703 -- path comes from this test binary's own environment,
		// set by useFakeSSH to a directory the test just created.
		_ = os.WriteFile(path, []byte(strings.Join(os.Args[1:], "\n")), 0o600)
	}
	switch mode {
	case "missing":
		// What a remote shell says when the program is not on its PATH. The
		// status is the POSIX one: an exit status is eight bits by the time
		// the local ssh process spends it, so cmd.exe's 9009 arrives smaller.
		fmt.Fprintln(os.Stderr, "'netdoc' is not recognized as an internal or external command,")
		return 127
	case "sshfail":
		fmt.Fprintln(os.Stderr, "ssh: Could not resolve hostname nope: Name or service not known")
		return sshFailedStatus
	case "silent":
		return 0
	case "garbage":
		fmt.Fprintln(os.Stdout, "Welcome to the machine.")
		return 0
	case "config", "configproxy", "configproxycommand", "confignoneproxy", "configexec":
		// `ssh -G`: the effective configuration, one lowercased keyword per
		// line, printed without connecting to anything. ssh leaves a proxy
		// keyword out entirely when it is unset or set to none, and
		// confignoneproxy prints it anyway to pin that the value is read too.
		if hasArg(os.Args[1:], "-v") {
			// At -v a real client reports each configuration file it reads, and
			// each Match exec command it runs.
			fmt.Fprintln(os.Stderr, "debug1: Reading configuration data "+os.Getenv(fakeSSHConfig))
			if mode == "configexec" {
				fmt.Fprintln(os.Stderr, "debug1: Executing command: 'proxy-decider'")
			}
		}
		fmt.Fprintln(os.Stdout, "user maikol")
		fmt.Fprintln(os.Stdout, "canonicalizehostname false")
		fmt.Fprintln(os.Stdout, "hostname 10.0.0.5")
		switch mode {
		case "configproxy":
			fmt.Fprintln(os.Stdout, "proxyjump bastion.example.com")
		case "configproxycommand":
			fmt.Fprintln(os.Stdout, "proxycommand /usr/bin/corp-connect --host --port")
		case "confignoneproxy":
			fmt.Fprintln(os.Stdout, "proxycommand none")
		}
		fmt.Fprintln(os.Stdout, "port 22")
		return 0
	case "answered-unread", "error-unread":
		// A worker that writes its answer and exits without reading the
		// request. The answer is complete, but it cannot be this request's.
		resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
		if mode == "error-unread" {
			resp.Error = "could not read the remote request: unexpected EOF"
		} else {
			rep, snap := diagnosedPair(resp.Tool, true)
			resp.Report, resp.Snapshot = &rep, &snap
		}
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		return 0
	case "extra-unread", "twice-unread", "answer-closed-stall", "answer-open-stall", "extra-stall":
		// Stand-ins that never read their request. Each writes a complete answer
		// first. The variants then add extra output, or close stdin and stall
		// with stdout still open.
		resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
		rep, snap := diagnosedPair(resp.Tool, true)
		resp.Report, resp.Snapshot = &rep, &snap
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(resp)
		switch mode {
		case "extra-unread":
			fmt.Fprintln(os.Stdout, "Welcome to the machine.")
		case "twice-unread":
			_ = enc.Encode(resp)
		case "answer-closed-stall":
			_ = os.Stdin.Close()
			stall()
		case "extra-stall":
			fmt.Fprintln(os.Stdout, "Welcome to the machine.")
			_ = os.Stdin.Close()
			stall()
		case "answer-open-stall":
			stall()
		}
		return 0
	case "answer-grandchild", "silent-grandchild":
		// A stand-in that starts a grandchild sharing its stdout, then exits
		// without reading its request. The grandchild keeps the pipe open after
		// the stand-in is gone, which is the stuck pipe the client must not wait on.
		if mode == "answer-grandchild" {
			resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
			rep, snap := diagnosedPair(resp.Tool, true)
			resp.Report, resp.Snapshot = &rep, &snap
			_ = json.NewEncoder(os.Stdout).Encode(resp)
		}
		return startGrandchild()
	case "read-silent-grandchild", "read-answer-grandchild", "read-extra-grandchild", "read-garbage-grandchild",
		"read-buffered-partial-grandchild", "read-buffered-space-grandchild":
		// The normal path: the request write succeeds because this stand-in reads
		// the whole request before it exits. What it writes first varies, and a
		// grandchild holds stdout open in every variant.
		var req Request
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, "fake ssh:", err)
			return 1
		}
		switch mode {
		case "read-answer-grandchild", "read-extra-grandchild":
			resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
			rep, snap := diagnosedPair(resp.Tool, true)
			resp.Report, resp.Snapshot = &rep, &snap
			_ = json.NewEncoder(os.Stdout).Encode(resp)
			if mode == "read-extra-grandchild" {
				fmt.Fprintln(os.Stdout, "Welcome to the machine.")
			}
		case "read-garbage-grandchild":
			fmt.Fprintln(os.Stdout, "Welcome to the machine.")
		case "read-buffered-partial-grandchild", "read-buffered-space-grandchild":
			// The response and the bytes after it go out in one write, so the first
			// decode reads them together and the bytes after it are left in the
			// decoder's buffer. The unfinished-object test checks the "{" against the
			// trailing hook; the whitespace test checks only the verdict.
			tail := "\n{"
			if mode == "read-buffered-space-grandchild" {
				tail = "\n\n"
			}
			_, _ = os.Stdout.Write(append(bufferedAnswer(), tail...))
		}
		return startGrandchild()
	case "read-eof-linger", "read-stderr-grandchild", "read-partial-grandchild", "read-space-grandchild":
		// A complete answer, then whatever the mode does next. read-eof-linger closes
		// stdout and keeps running, so the operation context ends it. read-stderr-grandchild
		// closes stdout and exits while a grandchild holds stderr, so the wait is inside
		// cmd.Wait. The last two keep stdout open with a grandchild holding it: the start
		// of a second object, and whitespace only.
		var req Request
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, "fake ssh:", err)
			return 1
		}
		resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
		rep, snap := diagnosedPair(resp.Tool, true)
		resp.Report, resp.Snapshot = &rep, &snap
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		switch mode {
		case "read-eof-linger":
			_ = os.Stdout.Close()
			stall()
			return 0
		case "read-stderr-grandchild":
			_ = os.Stdout.Close()
			return startHolder(false)
		case "read-partial-grandchild":
			// The second object starts only after the parent closes stdin, which it does
			// once the response is decoded. So the bytes reach the trailing reader, and
			// never the decoder's read-ahead, however late the parent reads.
			_, _ = io.Copy(io.Discard, os.Stdin)
			fmt.Fprint(os.Stdout, "\n{")
		default:
			fmt.Fprint(os.Stdout, "\n\n")
		}
		return startGrandchild()
	case "hold":
		// A grandchild that holds an inherited stdout until the test removes its
		// stop file. The backstop keeps an orphan from running for long.
		stop := os.Getenv(fakeSSHGrandchildStop)
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(stop); errors.Is(err, os.ErrNotExist) { //nolint:gosec // G703: the stop path is a file this test just created.
				return 0
			}
		}
		return 0
	case "hang":
		// An ssh that never gets as far as reading the request: a connection
		// that is opening, authenticating, or waiting on a prompt forever.
		stall()
		return 0
	}

	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "fake ssh:", err)
		return 1
	}
	if path := os.Getenv(fakeSSHRequest); path != "" {
		body, _ := json.Marshal(req)
		// #nosec G703 -- as above: the path is the test harness's own.
		_ = os.WriteFile(path, body, 0o600)
	}
	resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}}
	switch mode {
	case "ok", "unhealthy":
		rep, snap := diagnosedPair(resp.Tool, mode == "ok")
		resp.Report, resp.Snapshot = &rep, &snap
	case "openstdout":
		// The worker has completed and written a valid response, but the SSH
		// stdout channel remains open independently of stdin.
		rep, snap := diagnosedPair(resp.Tool, true)
		resp.Report, resp.Snapshot = &rep, &snap
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		time.Sleep(30 * time.Second)
		return 0
	case "refuse":
		resp.Error = "-public-dns: \"nope\" is not an IP address"
	case "protocol2":
		resp.Protocol = 2
	case "twice":
		rep, snap := diagnosedPair(resp.Tool, true)
		resp.Report, resp.Snapshot = &rep, &snap
		enc := json.NewEncoder(os.Stdout)
		_ = enc.Encode(resp)
		_ = enc.Encode(resp)
		return 0
	case "noresponse":
		// The request was read and the peer then says nothing at all, which is
		// a worker that started and never answered.
		stall()
		return 0
	case "stdineof":
		// A peer that waits for its stdin to end before answering. The local
		// side deliberately holds that pipe open as the worker's liveness
		// channel, so this is a protocol deadlock rather than a slow run.
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "slow":
		// A legitimately slow exchange that still finishes inside the bound.
		time.Sleep(300 * time.Millisecond)
		rep, snap := diagnosedPair(resp.Tool, true)
		resp.Report, resp.Snapshot = &rep, &snap
	case "oversize":
		// The oversize sits inside the first value, not after a complete one.
		// The decoder reaches the cap synchronously, so the outcome does not
		// depend on how fast the trailing check drains stdout before
		// responseEOFGrace expires. Spaces are legal inside the string.
		fmt.Fprint(os.Stdout, `{"protocol":1,"tool":{},"padding":"`)
		_, _ = io.CopyN(os.Stdout, endless{}, 3*MaxResponseBytes)
		return 0
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	return 0
}

// startGrandchild starts the process that keeps the stand-in's stdout open after
// the stand-in exits, and records its pid for the test cleanup.
func startGrandchild() int { return startHolder(true) }

// startHolder starts the hold process with either the stand-in's stdout or its
// stderr. Holding stderr is what keeps cmd.Wait waiting after ssh has exited, since
// exec waits for every pipe it created to end. Both use the stop file for cleanup.
func startHolder(holdStdout bool) int {
	grandchild := exec.Command(os.Args[0]) //nolint:gosec // G204: re-runs this test binary with a fixed helper mode.
	grandchild.Env = append(os.Environ(), fakeSSHEnv+"=hold")
	if holdStdout {
		grandchild.Stdout = os.Stdout
	} else {
		grandchild.Stderr = os.Stderr
	}
	if err := grandchild.Start(); err != nil {
		return 1
	}
	if path := os.Getenv(fakeSSHGrandchild); path != "" {
		_ = os.WriteFile(path, []byte(strconv.Itoa(grandchild.Process.Pid)), 0o600) //nolint:gosec // G703: a path this test just created.
	}
	return 0
}

// stall keeps the stand-in running without answering, appending to the liveness
// file so a test can tell a killed process from one still going. The ceiling is
// only a backstop: the transport is what has to end this.
func stall() {
	path := os.Getenv(fakeSSHAlive)
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if path != "" {
			// #nosec G304 G703 -- the path is this test harness's own temporary file.
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.Write([]byte("."))
				_ = f.Close()
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// useFakeSSH points the transport at the stand-in and returns the files it
// records the invocation in.
func useFakeSSH(t *testing.T, mode string) (argvPath, requestPath string) {
	t.Helper()
	previous := sshProgram
	sshProgram = fakeSSHProgram(t)
	// The stand-in is read as if netdoc had its terminal, which the configuration
	// read requires; the refusal without one has its own test.
	previousTerminal := sshverify.TerminalAvailable
	sshverify.TerminalAvailable = func() bool { return true }
	t.Cleanup(func() {
		sshProgram = previous
		sshverify.TerminalAvailable = previousTerminal
	})
	argvPath = t.TempDir() + string(os.PathSeparator) + "argv"
	requestPath = t.TempDir() + string(os.PathSeparator) + "request"
	t.Setenv(fakeSSHEnv, mode)
	t.Setenv(fakeSSHArgv, argvPath)
	t.Setenv(fakeSSHRequest, requestPath)
	t.Setenv(fakeSSHAlive, "")
	// A listing names a configuration file that exists, as a real client's does, so
	// netdoc can read the file it reports.
	cfg := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeSSHConfig, cfg)
	return argvPath, requestPath
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a path this test just created.
	if err != nil {
		t.Fatalf("the stand-in ssh recorded nothing: %v", err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func TestRunPassesTheDestinationThroughUntouchedWithAFixedRemoteCommand(t *testing.T) {
	argvPath, requestPath := useFakeSSH(t, "ok")
	// An alias out of ~/.ssh/config, which only resolves because ssh is handed
	// it exactly as typed. Anything netdoc did to it here would break it.
	resp, err := Run(context.Background(), "ideapad", "", Request{Target: "example.com", TimeoutMs: 3000})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Report == nil || !resp.Report.OK {
		t.Fatalf("response did not carry a healthy report: %+v", resp)
	}
	want := []string{"-T", "ideapad", DefaultCommand, WorkerFlag}
	got := readLines(t, argvPath)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("ssh argv = %q, want %q", got, want)
	}
	// The target travels as data on stdin, never as a word in the remote
	// command line, so no remote shell ever has a chance to read it.
	var req Request
	data, err := os.ReadFile(requestPath) // #nosec G304 -- a path this test just created.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Target != "example.com" || req.Protocol != Protocol || req.TimeoutMs != 3000 {
		t.Errorf("the worker received %+v", req)
	}
}

func TestRunKeepsAHostileTargetOutOfTheRemoteCommandLine(t *testing.T) {
	argvPath, requestPath := useFakeSSH(t, "ok")
	hostile := `a" & calc.exe & "b`
	if _, err := Run(context.Background(), "server", "", Request{Target: hostile}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, arg := range readLines(t, argvPath) {
		if strings.Contains(arg, "calc.exe") {
			t.Fatalf("a target reached the remote command line: %q", arg)
		}
	}
	data, err := os.ReadFile(requestPath) // #nosec G304 -- a path this test just created.
	if err != nil {
		t.Fatal(err)
	}
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		t.Fatal(err)
	}
	if req.Target != hostile {
		t.Errorf("target = %q, want it delivered verbatim as data", req.Target)
	}
}

func TestRunBatchTellsSSHToRefuseEveryInteractiveAuthentication(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "ok")
	if _, err := RunBatch(context.Background(), "ideapad", "", Request{TimeoutMs: 3000}); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	// Ahead of the destination, because ssh reads its options before it, and
	// otherwise exactly the invocation Run makes. Spelled out rather than built
	// from batchOptions: this list is the safety property, and a test that
	// derived it from the code under test would agree with any change to it.
	want := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "ProxyJump=none",
		"-o", "ProxyCommand=none",
		"-o", "PubkeyAcceptedAlgorithms=-sk-*,webauthn-sk-*",
		"-o", "IdentityAgent=none",
		"-o", "AddKeysToAgent=no",
		"-o", "PKCS11Provider=none",
		"-o", "GSSAPIAuthentication=no",
		"ideapad", DefaultCommand, WorkerFlag,
	}
	if got := readLines(t, argvPath); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("ssh argv = %q, want %q", got, want)
	}
	// Ordinary Run is untouched: it has a user in front of it and may ask.
	if _, err := Run(context.Background(), "ideapad", "", Request{TimeoutMs: 3000}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	want = []string{"-T", "ideapad", DefaultCommand, WorkerFlag}
	got := readLines(t, argvPath)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("ordinary ssh argv = %q, want %q", got, want)
	}
	// Said again on its own, because this is the half of the proxy rule that a
	// changed option list could break quietly: the ordinary transport carries a
	// user's ProxyJump and ProxyCommand exactly as configured, and pins
	// neither.
	for _, arg := range got {
		if strings.HasPrefix(arg, "Proxy") {
			t.Errorf("ordinary ssh argv overrides the configured proxy with %q", arg)
		}
	}
}

// The concurrent path may only be taken for a destination Direct has already
// read as unproxied, and it then holds that reading for the whole pass. ssh
// evaluates ssh_config once per invocation, so without this pin a Match exec
// that decided differently on a later acquisition could start a jump child or a
// ProxyCommand, and neither inherits anything from the options above.
func TestRunBatchPinsTheProxyOffForThePassItWasClearedFor(t *testing.T) {
	pinned := map[string]bool{"ProxyJump": false, "ProxyCommand": false}
	for _, option := range batchOptions {
		name, value, _ := strings.Cut(option, "=")
		if _, ok := pinned[name]; !ok {
			continue
		}
		if !strings.EqualFold(value, "none") {
			t.Errorf("%s = %q, want none", name, value)
		}
		pinned[name] = true
	}
	for name, found := range pinned {
		if !found {
			t.Errorf("the batch options do not pin %s", name)
		}
	}
}

// Direct is the gate that keeps a proxied destination off the concurrent path.
// A ProxyJump child and a ProxyCommand are separate programs that the batch
// options do not reach, and netdoc must not connect around either one.
func TestDirectReadsTheEffectiveConfiguration(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"config", true},
		{"confignoneproxy", true},
		{"configproxy", false},
		{"configproxycommand", false},
		// A Match exec test ran. Its answer depends on a terminal and environment
		// netdoc cannot reproduce, so the listing is refused, which is not direct.
		{"configexec", false},
		// ssh itself failed, so nothing was established. Anything unestablished
		// is treated as proxied, which costs an overlap and never a prompt.
		{"sshfail", false},
		{"silent", false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			argvPath, _ := useFakeSSH(t, tc.mode)
			if got := Direct(context.Background(), "ideapad"); got != tc.want {
				t.Errorf("Direct = %t, want %t", got, tc.want)
			}
			if got := readLines(t, argvPath); strings.Join(got, " ") != "-v -G ideapad" {
				t.Errorf("ssh argv = %q, want the verbose configuration of ideapad and no connection", got)
			}
		})
	}
}

// The destination reaches argv here too, so the same refusal has to apply.
func TestDirectRefusesADestinationSSHWouldReadAsAnOption(t *testing.T) {
	useFakeSSH(t, "config")
	if Direct(context.Background(), "-oProxyCommand=calc.exe") {
		t.Error("Direct accepted a destination that would become an ssh option")
	}
}

// OpenSSH's security-key algorithms are two families, and only one of them is
// spelled with an "sk-" prefix: webauthn-sk-ecdsa-sha2-nistp256@openssh.com and
// its certificate form are security keys too. Removing one family and not the
// other would leave the signing path that asks for a PIN reachable, so both
// patterns are pinned here rather than left to whichever names one installed
// OpenSSH happens to list.
//
// The two are one list with one operator. Written out rather than derived from
// batchOptions, because this is the value ssh has to receive: the leading "-"
// makes the whole list a removal, and a second "-" would be read as part of the
// pattern instead of as a second removal.
func TestRunBatchRemovesBothSecurityKeyAlgorithmFamilies(t *testing.T) {
	var filter string
	for _, option := range batchOptions {
		if name, value, _ := strings.Cut(option, "="); name == "PubkeyAcceptedAlgorithms" {
			filter = value
		}
	}
	patterns := strings.Split(filter, ",")
	want := []string{"-sk-*", "webauthn-sk-*"}
	if len(patterns) != len(want) {
		t.Fatalf("PubkeyAcceptedAlgorithms = %q, want the two patterns %q", filter, strings.Join(want, ","))
	}
	for i, pattern := range patterns {
		if pattern != want[i] {
			t.Errorf("PubkeyAcceptedAlgorithms pattern %d = %q, want %q", i, pattern, want[i])
		}
	}
}

// The mistake the value above is one character away from: "-sk-*,-webauthn-sk-*"
// looks like two removals and is one removal plus a pattern beginning with a
// hyphen, which matches nothing and leaves the webauthn family offered. Only the
// first pattern may carry a list operator.
func TestRunBatchGivesTheAlgorithmListExactlyOneRemovalOperator(t *testing.T) {
	var filter string
	for _, option := range batchOptions {
		if name, value, _ := strings.Cut(option, "="); name == "PubkeyAcceptedAlgorithms" {
			filter = value
		}
	}
	patterns := strings.Split(filter, ",")
	if len(patterns) == 0 || !strings.HasPrefix(patterns[0], "-") {
		t.Fatalf("PubkeyAcceptedAlgorithms = %q, want the list to begin with the removal operator", filter)
	}
	for i, pattern := range patterns[1:] {
		if strings.HasPrefix(pattern, "-") || strings.HasPrefix(pattern, "+") || strings.HasPrefix(pattern, "^") {
			t.Errorf("PubkeyAcceptedAlgorithms pattern %d = %q in %q, want a bare pattern: only the first one carries the operator",
				i+1, pattern, filter)
		}
	}
}

// A destination is user input that reaches argv, and RunBatch puts options
// there too. The refusal has to come before either is spent.
func TestRunBatchRefusesADestinationSSHWouldReadAsAnOption(t *testing.T) {
	useFakeSSH(t, "ok")
	if _, err := RunBatch(context.Background(), "-oProxyCommand=calc.exe", "", Request{}); err == nil {
		t.Error("RunBatch accepted a destination that would become an ssh option")
	}
}

func TestRunUsesTheCommandOverrideForThePrograms(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "ok")
	if _, err := Run(context.Background(), "server", `C:\tmp\netdoc.exe`, Request{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := readLines(t, argvPath)
	if len(got) != 4 || got[2] != `C:\tmp\netdoc.exe` {
		t.Errorf("ssh argv = %q, want the override as the remote program", got)
	}
}

func TestRunReportsAFailedDiagnosisAsASuccessfulExchange(t *testing.T) {
	useFakeSSH(t, "unhealthy")
	resp, err := Run(context.Background(), "server", "", Request{})
	if err != nil {
		t.Fatalf("a remote network that fails checks is not a transport error: %v", err)
	}
	if resp.Report == nil || resp.Report.OK {
		t.Fatalf("response = %+v, want an unhealthy report", resp)
	}
}

func TestRunHandlesARequestWriteFailureWithoutPanicking(t *testing.T) {
	useFakeSSH(t, "hang")

	previous := writeRequest
	writeRequest = func(io.Writer, []byte) (int, error) {
		return 0, io.ErrClosedPipe
	}
	t.Cleanup(func() { writeRequest = previous })

	_, err := Run(context.Background(), "server", "", Request{})
	if err == nil {
		t.Fatal("want a transport error, got none")
	}
	if !strings.Contains(err.Error(), "netdoc did not run on the SSH host") {
		t.Fatalf("Run error = %q, want the no-response transport error", err)
	}
}

func TestRunDistinguishesTheTransportFailures(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"missing", []string{"netdoc did not run on the SSH host", "ssh exited 127", "is not recognized", CommandEnv, WorkerFlag}},
		{"sshfail", []string{"ssh could not open the connection", "Could not resolve hostname"}},
		{"silent", []string{"netdoc did not run on the SSH host"}},
		{"garbage", []string{"could not read the remote response"}},
		{"twice", []string{"more than one response"}},
		{"protocol2", []string{"remote protocol 2, not 1", "9.9.9"}},
		{"refuse", []string{"is not an IP address"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useFakeSSH(t, tc.mode)
			_, err := Run(context.Background(), "server", "", Request{})
			if err == nil {
				t.Fatal("want an error, got none")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// writeUntilRefused returns a request write that keeps writing until the stand-in
// refuses it, which happens only once the stand-in has closed its stdin. It is
// bounded: a stand-in that reads its stdin never refuses the write, and an
// unbounded loop would hang the test instead of failing it.
func writeUntilRefused(t *testing.T) func(io.Writer, []byte) (int, error) {
	return func(w io.Writer, p []byte) (int, error) {
		for written := 0; written < 1<<24; written += len(p) {
			if _, err := w.Write(p); err != nil {
				return 0, err
			}
		}
		t.Fatal("the request write was never refused")
		return 0, nil
	}
}

// A write into a stand-in that exits without reading its stdin fails only after
// the stand-in has closed that stdin, and it closes stdin on exit, after writing
// its output. Writing in a loop reaches that failure: once the pipe is full the
// write blocks until the stand-in is gone, and then it errors. Each expected
// verdict is the same whether the reader sees the stand-in's exit or the grace
// window ends first, and the output it depends on is already in the pipe.
func TestRunReadsWhatAWorkerWroteBeforeItExited(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"garbage", []string{"could not read the remote response"}},
		{"silent", []string{"netdoc did not run on the SSH host"}},
		{"missing", []string{"netdoc did not run on the SSH host", "ssh exited 127"}},
		{"sshfail", []string{"ssh could not open the connection"}},
		{"answered-unread", []string{"the request did not reach it whole"}},
		{"error-unread", []string{"the request did not reach it whole", "could not read the remote request"}},
		{"extra-unread", []string{"the request did not reach it whole", "the remote sent more than one response"}},
		{"twice-unread", []string{"the request did not reach it whole", "the remote sent more than one response"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useFakeSSH(t, tc.mode)
			previous := writeRequest
			writeRequest = writeUntilRefused(t)
			t.Cleanup(func() { writeRequest = previous })
			_, err := Run(context.Background(), "server", "", Request{})
			if err == nil {
				t.Fatal("want an error, got none")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// A request write that blocks, because the stand-in never reads its stdin and
// the pipe fills, must still end on the operation deadline or on cancellation.
// The write error it then sees must not change which of the two is reported.
func TestRunEndsABlockedRequestWriteOnTheDeadlineOrCancellation(t *testing.T) {
	blockingWrite := func(w io.Writer, p []byte) (int, error) {
		for {
			if _, err := w.Write(p); err != nil {
				return 0, err
			}
		}
	}
	useWriter := func(t *testing.T) {
		previous := writeRequest
		writeRequest = blockingWrite
		t.Cleanup(func() { writeRequest = previous })
	}
	t.Run("deadline", func(t *testing.T) {
		useFakeSSH(t, "hang")
		useShortOperationBound(t, 300*time.Millisecond)
		useWriter(t)
		start := time.Now()
		_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("Run error = %v, want the remote run timed out", err)
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("Run took %s to give up on a blocked write", elapsed)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		useFakeSSH(t, "hang")
		useWriter(t)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := Run(ctx, "server", "", Request{})
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Fatalf("Run error = %v, want the run interrupted", err)
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("Run took %s to notice the cancellation", elapsed)
		}
	})
}

// An answer that arrives before the request write is refused is not this
// request's diagnosis. A stand-in that then keeps stdout open must not turn that
// into "did not run": the window ends and the answer is reported as it stands.
func TestRunReportsAnAnswerWhoseStdoutStaysOpen(t *testing.T) {
	useFakeSSH(t, "answer-closed-stall")
	previous := writeRequest
	writeRequest = writeUntilRefused(t)
	t.Cleanup(func() { writeRequest = previous })
	start := time.Now()
	_, err := Run(context.Background(), "server", "", Request{})
	if err == nil || !strings.Contains(err.Error(), "the request did not reach it whole") || strings.Contains(err.Error(), "did not run") {
		t.Fatalf("Run error = %v, want the answer reported as not delivered", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Run took %s to stop waiting on stdout", elapsed)
	}
}

// Trailing output after a complete answer is reported even while stdout stays
// open. A check that waited for end of stdout would run out the window and lose
// the message, so the message is the assertion.
func TestRunReportsTrailingOutputWhileStdoutStaysOpen(t *testing.T) {
	useFakeSSH(t, "extra-stall")
	previous := writeRequest
	writeRequest = writeUntilRefused(t)
	t.Cleanup(func() { writeRequest = previous })
	_, err := Run(context.Background(), "server", "", Request{})
	if err == nil || !strings.Contains(err.Error(), "the remote sent more than one response") {
		t.Fatalf("Run error = %v, want the trailing output reported", err)
	}
}

// The same stalled answer, with stdin still open, must still end on the operation
// deadline or on cancellation, and the deadline or cancellation is what is reported.
func TestRunEndsAStalledAnswerOnTheDeadlineOrCancellation(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		useFakeSSH(t, "answer-open-stall")
		useShortOperationBound(t, 300*time.Millisecond)
		previous := writeRequest
		writeRequest = writeUntilRefused(t)
		t.Cleanup(func() { writeRequest = previous })
		_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20})
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("Run error = %v, want the remote run timed out", err)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		useFakeSSH(t, "answer-open-stall")
		previous := writeRequest
		writeRequest = writeUntilRefused(t)
		t.Cleanup(func() { writeRequest = previous })
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := Run(ctx, "server", "", Request{})
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Fatalf("Run error = %v, want the run interrupted", err)
		}
	})
}

// useGrandchildFakeSSH runs a stand-in whose grandchild keeps its stdout open,
// and stops that grandchild when the test ends. The stop file exists for the whole
// test and is removed at cleanup, which reaches the grandchild even when the
// stand-in was killed before it recorded the pid. It returns the path the pid is
// recorded at, which appears only after the stand-in has written its answer.
func useGrandchildFakeSSH(t *testing.T, mode string) (pidPath string) {
	t.Helper()
	useFakeSSH(t, mode)
	dir := t.TempDir()
	pidPath = filepath.Join(dir, "grandchild")
	stopPath := filepath.Join(dir, "stop")
	if err := os.WriteFile(stopPath, nil, 0o600); err != nil { //nolint:gosec // G703: a path this test just created.
		t.Fatal(err)
	}
	t.Setenv(fakeSSHGrandchild, pidPath)
	t.Setenv(fakeSSHGrandchildStop, stopPath)
	t.Cleanup(func() {
		_ = os.Remove(stopPath)           //nolint:gosec // G703: a path this test just created.
		data, err := os.ReadFile(pidPath) // #nosec G304 -- a path this test just created.
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(string(data)); err == nil {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})
	return pidPath
}

// A grandchild that inherits the stand-in's stdout keeps the pipe open after the
// stand-in is gone. Cancellation and the operation deadline must still end the run
// promptly, rather than after the grace window, whether or not an answer arrived.
func TestRunEndsPromptlyWhileAGrandchildHoldsStdout(t *testing.T) {
	for _, mode := range []string{"answer-grandchild", "silent-grandchild"} {
		t.Run(mode+"/cancellation", func(t *testing.T) {
			useGrandchildFakeSSH(t, mode)
			previous := writeRequest
			writeRequest = writeUntilRefused(t)
			t.Cleanup(func() { writeRequest = previous })
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := Run(ctx, "server", "", Request{})
			if err == nil || !strings.Contains(err.Error(), "interrupted") {
				t.Fatalf("Run error = %v, want the run interrupted", err)
			}
			if elapsed := time.Since(start); elapsed >= responseEOFGrace {
				t.Errorf("Run took %s to notice the cancellation, so it waited out the grace window", elapsed)
			}
		})
		t.Run(mode+"/deadline", func(t *testing.T) {
			useGrandchildFakeSSH(t, mode)
			useShortOperationBound(t, 300*time.Millisecond)
			previous := writeRequest
			writeRequest = writeUntilRefused(t)
			t.Cleanup(func() { writeRequest = previous })
			start := time.Now()
			_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20})
			if err == nil || !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("Run error = %v, want the remote run timed out", err)
			}
			if elapsed := time.Since(start); elapsed >= responseEOFGrace {
				t.Errorf("Run took %s to give up on the deadline, so it waited out the grace window", elapsed)
			}
		})
	}
	// With no deadline and no cancellation, the trailing window ends and the run
	// tears the pipe down itself. The grandchild still holds stdout, so Run must
	// release it rather than wait on it.
	t.Run("answer-grandchild/no deadline", func(t *testing.T) {
		useGrandchildFakeSSH(t, "answer-grandchild")
		previous := writeRequest
		writeRequest = writeUntilRefused(t)
		t.Cleanup(func() { writeRequest = previous })
		done := make(chan error, 1)
		go func() {
			_, err := Run(context.Background(), "server", "", Request{})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "the request did not reach it whole") {
				t.Fatalf("Run error = %v, want the answer reported as not delivered", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Run waited on a grandchild that held stdout")
		}
	})
}

// On the normal path the request write succeeds, so the answer is read in full,
// and the first decode and the trailing check both wait on stdout. A grandchild
// that keeps stdout open must not hold either wait past the end of the operation,
// and must not turn a complete answer into a timeout or a hang.
func TestRunEndsOnTheNormalPathWhileAGrandchildHoldsStdout(t *testing.T) {
	t.Run("cancelled before the first response", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-silent-grandchild")
		got := runGuarded(t, cancelledAfter(200*time.Millisecond), Request{})
		requireFailure(t, got, "interrupted")
	})
	t.Run("deadline before the first response", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-silent-grandchild")
		useShortOperationBound(t, 300*time.Millisecond)
		got := runGuarded(t, context.Background(), Request{TimeoutMs: 20})
		requireFailure(t, got, "timed out")
	})
	t.Run("cancelled during trailing-data validation", func(t *testing.T) {
		pidPath := useGrandchildFakeSSH(t, "read-answer-grandchild")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// The pid is recorded after the answer is written, so once it exists the
		// answer is in the pipe and the run is in its trailing window.
		cancelWhenFileExists(pidPath, cancel)
		got := runGuarded(t, ctx, Request{})
		requireFailure(t, got, "interrupted")
	})
	t.Run("deadline during trailing-data validation", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-answer-grandchild")
		// A deadline cannot be triggered by an event, so this is a timed row: the
		// answer normally arrives well inside the bound, and the deadline then falls
		// inside the two-second trailing window. Under heavy load it can fall
		// elsewhere, and the message is the same, so this row then proves the
		// message and not the window.
		useShortOperationBound(t, time.Second)
		got := runGuarded(t, context.Background(), Request{TimeoutMs: 20})
		requireFailure(t, got, "timed out")
	})
	t.Run("deadline in the teardown wait after a complete answer", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-answer-grandchild")
		// The deadline is meant to land after the two-second trailing window, while the
		// bounded wait after the kill is still running. It is timed, not an event, so
		// under heavy load it can land earlier, and the message is then the same. The
		// verdict is due at the deadline, about 3.0 s in. Without the operation check
		// in that wait, it would come only after cancelGrace, at about 4 s, so the
		// bound is set between the two.
		useShortOperationBound(t, 2900*time.Millisecond)
		got := runGuarded(t, context.Background(), Request{TimeoutMs: 20})
		requireVerdict(t, got, "timed out", 3500*time.Millisecond)
	})
	t.Run("a complete answer stands while a grandchild holds stdout", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-answer-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		if got.err != nil {
			t.Fatalf("Run: %v", got.err)
		}
		if got.resp.Report == nil || !got.resp.Report.OK {
			t.Fatalf("response did not carry the completed diagnosis: %+v", got.resp)
		}
	})
	t.Run("extra output after the answer is rejected promptly", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-extra-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		requireFailure(t, got, "more than one response")
	})
	t.Run("malformed output before the answer is rejected promptly", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-garbage-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		requireFailure(t, got, "could not read the remote response")
	})
}

// cancelledAfter returns a context the test cancels after d. It is a cancellation,
// not a deadline: the context has no deadline of its own, so the run reports an
// interruption because the caller cancelled it. A context with a deadline is the
// caller-owned case, covered separately.
func cancelledAfter(d time.Duration) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(d, cancel)
	return ctx
}

// cancelWhenFileExists calls cancel once path exists. It polls for at most
// guardLimit, and calls cancel then regardless, so a file that never appears
// cannot leave the run waiting forever.
func cancelWhenFileExists(path string, cancel context.CancelFunc) {
	go func() {
		defer cancel()
		for deadline := time.Now().Add(guardLimit); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			if _, err := os.Stat(path); err == nil { //nolint:gosec // G703: a path this test just created.
				return
			}
		}
	}()
}

// A grandchild that holds stdout must not leave a stdout reader running once Run
// has returned: every path that leaves a reader blocked has to release it. The
// check reads the goroutine stacks for the reader frames rather than counting
// goroutines, so a goroutine from another subtest cannot offset a leaked reader.
func TestRunLeavesNoStdoutReaderBehindWhileAGrandchildHoldsStdout(t *testing.T) {
	t.Run("the answer stands", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-answer-grandchild")
		runGuarded(t, context.Background(), Request{})
		requireNoReaderLeft(t)
	})
	t.Run("cancelled before the first response", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-silent-grandchild")
		runGuarded(t, cancelledAfter(200*time.Millisecond), Request{})
		requireNoReaderLeft(t)
	})
}

// requireNoReaderLeft fails if a goroutine is still inside decodeResponse or
// confirmNoTrailingData once the run has returned. It polls, because a reader that
// was released a moment ago may still be on its way out.
func requireNoReaderLeft(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(guardLimit)
	for {
		stacks := allStacks()
		if !strings.Contains(stacks, "internal/remote.decodeResponse(") && !strings.Contains(stacks, "internal/remote.confirmNoTrailingData(") {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("a stdout reader is still blocked after the run returned")
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// allStacks returns the stacks of every goroutine in the process.
func allStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// guardLimit is how long a run may take before the test calls it a hang. It is
// only a backstop that turns a hang into a failure: the grandchild is stopped by
// the test cleanup either way, which ends the held pipe and lets the run return.
const guardLimit = 10 * time.Second

type runOutcome struct {
	resp    Response
	err     error
	elapsed time.Duration
}

// runGuarded runs Run and returns its outcome, or fails the test if it has not
// returned within guardLimit.
func runGuarded(t *testing.T, ctx context.Context, req Request) runOutcome {
	t.Helper()
	return awaitRun(t, startRun(ctx, req))
}

// startRun runs Run on its own goroutine. The outcome arrives on the returned channel,
// so a test can act on the run's events while it is still in progress.
func startRun(ctx context.Context, req Request) <-chan runOutcome {
	done := make(chan runOutcome, 1)
	start := time.Now()
	go func() {
		resp, err := Run(ctx, "server", "", req)
		done <- runOutcome{resp, err, time.Since(start)}
	}()
	return done
}

// awaitRun returns the outcome of a started run, or fails the test if it has not
// arrived within guardLimit.
func awaitRun(t *testing.T, done <-chan runOutcome) runOutcome {
	t.Helper()
	select {
	case got := <-done:
		return got
	case <-time.After(guardLimit):
		t.Fatalf("Run had not returned after %s, so it waited on a grandchild that held stdout", guardLimit)
		return runOutcome{}
	}
}

// requireFailure checks that a run failed with want in its message, and that it
// gave up well inside responseEOFGrace: a held pipe must not stretch a failure
// past the operation's end.
func requireFailure(t *testing.T, got runOutcome, want string) {
	t.Helper()
	if got.err == nil || !strings.Contains(got.err.Error(), want) {
		t.Fatalf("Run error = %v, want it to say %q", got.err, want)
	}
	if got.elapsed >= responseEOFGrace {
		t.Errorf("Run took %s to fail, so a grandchild holding stdout held it past the end of the operation", got.elapsed)
	}
}

// A complete answer does not decide the run by itself. The operation context is
// checked again after teardown, and a deadline that has passed by then is a timeout,
// never a success, even when the answer was whole and the pipes ended on their own.
func TestRunTimesOutWhenTeardownOutlastsTheDeadline(t *testing.T) {
	t.Run("ssh closes stdout and keeps running", func(t *testing.T) {
		useFakeSSH(t, "read-eof-linger")
		useShortOperationBound(t, 300*time.Millisecond)
		got := runGuarded(t, context.Background(), Request{TimeoutMs: 20})
		requireVerdict(t, got, "timed out", 2*cancelGrace)
	})
	t.Run("a grandchild holds stderr open", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-stderr-grandchild")
		useShortOperationBound(t, 300*time.Millisecond)
		got := runGuarded(t, context.Background(), Request{TimeoutMs: 20})
		requireVerdict(t, got, "timed out", 2*cancelGrace)
	})
}

// The same check for a caller cancellation: a cancellation that lands during
// teardown is an interruption, not a success.
func TestRunIsInterruptedWhenTeardownOutlastsTheCancellation(t *testing.T) {
	t.Run("ssh closes stdout and keeps running", func(t *testing.T) {
		useFakeSSH(t, "read-eof-linger")
		got := runGuarded(t, cancelledAfter(200*time.Millisecond), Request{})
		requireVerdict(t, got, "interrupted", 2*cancelGrace)
	})
	t.Run("a grandchild holds stderr open", func(t *testing.T) {
		pidPath := useGrandchildFakeSSH(t, "read-stderr-grandchild")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// The pid is recorded when the grandchild starts, after the answer is written
		// and stdout is closed, so the cancellation lands while the run is in its
		// teardown wait, which holds for cancelGrace.
		cancelWhenFileExists(pidPath, cancel)
		got := runGuarded(t, ctx, Request{})
		requireVerdict(t, got, "interrupted", 2*cancelGrace)
	})
	// A deadline the caller set on its own context is the caller's, not the
	// operation's. The run reports it as an interruption, because transportError
	// reads the caller's context before the operation's.
	t.Run("caller-owned deadline ends teardown", func(t *testing.T) {
		useFakeSSH(t, "read-eof-linger")
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		got := runGuarded(t, ctx, Request{})
		requireVerdict(t, got, "interrupted", 2*cancelGrace)
	})
}

// The check must not turn a healthy run into a failure: a complete answer, with
// the context still active through a held stderr, is still a success.
func TestRunSucceedsWhenTeardownFinishesInsideTheContext(t *testing.T) {
	useGrandchildFakeSSH(t, "read-stderr-grandchild")
	got := runGuarded(t, context.Background(), Request{})
	if got.err != nil {
		t.Fatalf("Run: %v", got.err)
	}
	if got.resp.Report == nil || !got.resp.Report.OK {
		t.Fatalf("response did not carry the completed diagnosis: %+v", got.resp)
	}
}

// trailingHold holds the trailing reader between a byte's delivery and its record,
// and reports two events to the test. entered closes when a reader reaches the hold,
// which is how a test tells the reader path from the decoder's read-ahead path.
// waiting closes when the teardown begins waiting for the reader after stdout is
// closed. Each event closes once, and a test waits on it with waitFor.
type trailingHold struct {
	ch          chan struct{}
	releaseOnce sync.Once
	entered     chan struct{}
	enterOnce   sync.Once
	waiting     chan struct{}
	waitOnce    sync.Once
}

func (h *trailingHold) release() { h.releaseOnce.Do(func() { close(h.ch) }) }

// trailingHoldActive is the hold in force, or nil. init installs the hooks once,
// before any goroutine exists, and each hook reads this atomically, so no test
// writes a package variable while a reader or the teardown may still read it.
var trailingHoldActive atomic.Pointer[trailingHold]

func init() {
	trailingReadHook = func() {
		if h := trailingHoldActive.Load(); h != nil {
			h.enterOnce.Do(func() { close(h.entered) })
			<-h.ch
		}
	}
	readerWaitHook = func() {
		if h := trailingHoldActive.Load(); h != nil {
			h.waitOnce.Do(func() { close(h.waiting) })
		}
	}
}

// holdTrailingReads holds the trailing reader until the returned hold is released.
// The hold ends when the test does, and it is released then too, so a failing test
// cannot leave a reader blocked.
func holdTrailingReads(t *testing.T) *trailingHold {
	t.Helper()
	h := &trailingHold{
		ch:      make(chan struct{}),
		entered: make(chan struct{}),
		waiting: make(chan struct{}),
	}
	trailingHoldActive.Store(h)
	t.Cleanup(func() {
		h.release()
		trailingHoldActive.Store(nil)
	})
	return h
}

// A complete answer followed by the start of a second object, with a grandchild
// holding stdout open, is two responses, and the held pipe does not make it one.
// The answer may stand only when nothing but whitespace followed it.
func TestRunRejectsUnfinishedTrailingOutputWhileAGrandchildHoldsStdout(t *testing.T) {
	t.Run("an unfinished second object is a violation", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-partial-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		requireVerdict(t, got, "more than one response", responseEOFGrace+cancelGrace+time.Second)
	})
	// A byte can be delivered while the teardown waits for the reader, and the reader
	// has not recorded it yet. The check must still see it. The reader is held until
	// the teardown is waiting, and the run must stay pending while it is held, so a
	// check that does not wait for the reader returns early and the test fails. The
	// two events are awaited. The timed assertions are the 200 ms pending window and
	// the return within 1 s of the release. Setup latency is varied, and the overall
	// bound allows for it.
	t.Run("a byte delivered as the teardown wait ends is still counted", func(t *testing.T) {
		for _, setup := range []time.Duration{0, 1500 * time.Millisecond, 3 * time.Second} {
			t.Run(fmt.Sprintf("setup %s", setup), func(t *testing.T) {
				useGrandchildFakeSSH(t, "read-partial-grandchild")
				// The setup latency is the time between the request write and the first
				// decode, the same seam the held-reader subtest below uses.
				previous := writeRequest
				writeRequest = func(w io.Writer, p []byte) (int, error) {
					n, err := previous(w, p)
					time.Sleep(setup)
					return n, err
				}
				t.Cleanup(func() { writeRequest = previous })
				hold := holdTrailingReads(t)
				done := startRun(context.Background(), Request{})
				waitFor(t, hold.entered, "the trailing bytes to reach the held reader")
				waitFor(t, hold.waiting, "the teardown to begin waiting for the reader after stdout closed")
				select {
				case got := <-done:
					t.Fatalf("Run returned while the reader was still held: %+v", got)
				case <-time.After(200 * time.Millisecond):
				}
				released := time.Now()
				hold.release()
				got := awaitRun(t, done)
				if d := time.Since(released); d > time.Second {
					t.Errorf("Run returned %s after the reader was released, want at most 1s", d)
				}
				// The overall bound is a guard, not the teardown's own length. The elapsed time
				// includes the setup latency, the 2 s trailing window and the 2 s teardown wait,
				// so a bound near 6 s fails at the 3 s setup, and the bound was raised to guardLimit
				// for that reason. The 1 s return above is the timed assertion.
				requireVerdict(t, got, "more than one response", guardLimit)
			})
		}
	})
	// The reader can hold a byte it has received but not yet recorded, and stay
	// there past the teardown wait. Nothing then shows whether that byte was a
	// second response, so the answer must not stand while the reader is unfinished.
	t.Run("a reader still held after stdout is closed is not accepted", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-partial-grandchild")
		// The parent reads its response late. The trailing bytes still follow the parent's
		// stdin close, which comes after the decode, so a late read cannot merge them into
		// the response's read, and they must reach the held reader.
		previous := writeRequest
		writeRequest = func(w io.Writer, p []byte) (int, error) {
			n, err := previous(w, p)
			time.Sleep(500 * time.Millisecond)
			return n, err
		}
		t.Cleanup(func() { writeRequest = previous })
		hold := holdTrailingReads(t)
		done := startRun(context.Background(), Request{})
		waitFor(t, hold.entered, "the trailing bytes to reach the held reader")
		got := awaitRun(t, done)
		requireVerdict(t, got, "could not be verified", 8*time.Second)
		hold.release()
		requireNoReaderLeft(t)
	})
	t.Run("whitespace after the answer still stands", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-space-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		if got.err != nil {
			t.Fatalf("Run: %v", got.err)
		}
		if got.resp.Report == nil || !got.resp.Report.OK {
			t.Fatalf("response did not carry the completed diagnosis: %+v", got.resp)
		}
	})
}

// bufferedRefusal is the error the buffered stand-ins answer with. It is a complete
// response, and a small one, so the first decode takes it and the bytes after it in
// one read.
const bufferedRefusal = "the remote refused this request"

// firstDecodeRead is the size of encoding/json's first read into an empty decoder,
// which is its minimum read size. The buffered stand-ins keep the response and the
// bytes after it within it, so both arrive in that first read.
const firstDecodeRead = 512

// bufferedAnswer is the complete response the buffered stand-ins write first.
func bufferedAnswer() []byte {
	body, err := json.Marshal(Response{
		Protocol: Protocol,
		Tool:     snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"},
		Error:    bufferedRefusal,
	})
	if err != nil {
		panic(err)
	}
	return body
}

// The check reads what the decoder took past the first response. The stand-in writes a
// complete response and then the start of a second object in one write, so the first
// decode takes both. The trailing reader's hook runs only for non-whitespace reads, so
// a hook that never fires shows that no non-whitespace byte came through the trailing
// reader. A second object that never finishes can then be caught only from the
// decoder's buffer, while a grandchild holds stdout open. Dropping that read makes the
// run accept the answer.
func TestRunRejectsBufferedTrailingOutputWhileAGrandchildHoldsStdout(t *testing.T) {
	if n := len(bufferedAnswer()) + len("\n{"); n > firstDecodeRead {
		t.Fatalf("the buffered answer is %d bytes, more than the %d-byte first read it must fit in", n, firstDecodeRead)
	}
	t.Run("an unfinished second object already in the decoder's buffer is a violation", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-buffered-partial-grandchild")
		hold := holdTrailingReads(t)
		got := runGuarded(t, context.Background(), Request{})
		requireBufferedOnly(t, hold)
		requireVerdict(t, got, "more than one response", responseEOFGrace+cancelGrace+time.Second)
		requireNoReaderLeft(t)
	})
	// The verdict only. The trailing hook cannot see whitespace reads, so this subtest
	// does not show where the whitespace was read, and it makes no claim about that.
	t.Run("whitespace after the response still stands", func(t *testing.T) {
		useGrandchildFakeSSH(t, "read-buffered-space-grandchild")
		got := runGuarded(t, context.Background(), Request{})
		requireVerdict(t, got, bufferedRefusal, responseEOFGrace+cancelGrace+time.Second)
		requireNoReaderLeft(t)
	})
}

// requireBufferedOnly checks that the trailing reader never took a non-whitespace byte
// past the response. The hook runs only for non-whitespace reads, so this covers the
// unfinished object's "{" and says nothing about whitespace. The stand-in writes the
// response and the tail in one write, so a "{" the hook never saw was in the decoder's
// buffer.
func requireBufferedOnly(t *testing.T, hold *trailingHold) {
	t.Helper()
	select {
	case <-hold.entered:
		t.Fatal("a non-whitespace byte after the response reached the trailing reader, not the decoder's buffer")
	default:
	}
}

// requireVerdict checks that a run did not succeed, and that it failed with want in
// its message within bound. The bound is for the teardown wait a held pipe can cause.
func requireVerdict(t *testing.T, got runOutcome, want string, bound time.Duration) {
	t.Helper()
	if got.err == nil || !strings.Contains(got.err.Error(), want) {
		t.Fatalf("Run error = %v, want it to say %q", got.err, want)
	}
	if got.elapsed > bound {
		t.Errorf("Run took %s to give up, want at most %s", got.elapsed, bound)
	}
}

// stalledReader hands out prefix, then blocks every further read until the test
// releases it. entered is closed when the first blocked read starts, so a test
// can act while the helper is waiting. returned is closed when that read ends.
type stalledReader struct {
	prefix   *bytes.Reader
	reads    atomic.Int32
	entered  chan struct{}
	release  chan struct{}
	returned chan struct{}
	enterOne sync.Once
	letGoOne sync.Once
	backOne  sync.Once
}

func newStalledReader(prefix []byte) *stalledReader {
	return &stalledReader{
		prefix:   bytes.NewReader(prefix),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		returned: make(chan struct{}),
	}
}

func (r *stalledReader) Read(p []byte) (int, error) {
	r.reads.Add(1)
	if r.prefix.Len() > 0 {
		return r.prefix.Read(p)
	}
	r.enterOne.Do(func() { close(r.entered) })
	defer r.backOne.Do(func() { close(r.returned) })
	<-r.release
	return 0, io.ErrClosedPipe
}

func (r *stalledReader) letGo() { r.letGoOne.Do(func() { close(r.release) }) }

// answerJSON is one complete answer, as a worker writes it.
func answerJSON(t *testing.T) []byte {
	t.Helper()
	tool := snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}
	rep, snap := diagnosedPair(tool, true)
	body, err := json.Marshal(Response{Protocol: Protocol, Tool: tool, Report: &rep, Snapshot: &snap})
	if err != nil {
		t.Fatal(err)
	}
	return append(body, '\n')
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// The helper waits in two windows, the answer window and the trailing window. A
// cancellation in either must end the wait at once with the context's own error,
// not after the grace window, and the reader must not be waited on.
func TestReadAfterWriteFailureEndsOnCancellationInEitherWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix []byte
	}{
		{"answer window", nil},
		{"trailing window", answerJSON(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStalledReader(tc.prefix)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stops atomic.Int32
			type result struct {
				resp Response
				err  error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := readAfterWriteFailure(ctx, r, func() { stops.Add(1) })
				done <- result{resp, err}
			}()
			waitFor(t, r.entered, "the read to block")
			cancel()
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("readAfterWriteFailure kept waiting after its context was cancelled")
			}
			if !errors.Is(got.err, context.Canceled) {
				t.Errorf("readAfterWriteFailure = %v, want the cancellation itself", got.err)
			}
			if n := stops.Load(); n != 1 {
				t.Errorf("ssh was stopped %d times, want 1", n)
			}
			r.letGo()
			waitFor(t, r.returned, "the blocked read to end once released")
		})
	}
}

// A deadline ends the wait the same way cancellation does, and is reported as the
// deadline rather than as the grace window running out.
func TestReadAfterWriteFailureEndsOnDeadlineInEitherWindow(t *testing.T) {
	for _, prefix := range [][]byte{nil, answerJSON(t)} {
		r := newStalledReader(prefix)
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(20*time.Millisecond))
		defer cancel()
		var stops atomic.Int32
		_, err := readAfterWriteFailure(ctx, r, func() { stops.Add(1) })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("readAfterWriteFailure with prefix %d bytes = %v, want the deadline itself", len(prefix), err)
		}
		if n := stops.Load(); n != 1 {
			t.Errorf("ssh was stopped %d times, want 1", n)
		}
		r.letGo()
	}
}

// A context that has already ended must not start a read at all.
func TestReadAfterWriteFailureDoesNotReadOnAnEndedContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"cancelled", cancelled, context.Canceled},
		{"expired", expired, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newStalledReader(answerJSON(t))
			var stops atomic.Int32
			_, err := readAfterWriteFailure(tc.ctx, r, func() { stops.Add(1) })
			if !errors.Is(err, tc.want) {
				t.Errorf("readAfterWriteFailure = %v, want %v", err, tc.want)
			}
			if n := r.reads.Load(); n != 0 {
				t.Errorf("the reader was read %d times after the context ended, want none", n)
			}
			if n := stops.Load(); n != 1 {
				t.Errorf("ssh was stopped %d times, want 1", n)
			}
		})
	}
}

// After the grace window a write-failure read gives up on stdout. A pipe that
// never ends, which a process other than ssh can keep open after ssh is killed,
// must not hold the run.
func TestReadAfterWriteFailureDoesNotWaitForAPipeThatNeverEnds(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	defer func() { _ = r.Close() }()

	stopped := 0
	done := make(chan error, 1)
	go func() {
		_, err := readAfterWriteFailure(context.Background(), r, func() { stopped++ })
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNoResponse) {
			t.Fatalf("readAfterWriteFailure = %v, want no response", err)
		}
		if stopped != 1 {
			t.Errorf("ssh was stopped %d times, want 1", stopped)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("readAfterWriteFailure waited on a pipe that never ends")
	}
}

func TestRunEndsWhenTheContextIsCancelled(t *testing.T) {
	useFakeSSH(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Run(ctx, "server", "", Request{})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error = %q, want it to say the run was interrupted", err)
	}
	// The stand-in sleeps for 30 seconds; returning anywhere near that would
	// mean the cancellation never reached the ssh process.
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Run took %s to notice the cancellation", elapsed)
	}
}

// useShortOperationBound shrinks the transport half of the operation ceiling so
// a stalled stand-in is bounded in test time. What is under test is that the
// ceiling exists and is enforced, not the size of the shipped allowance, which
// TestOperationTimeoutDerivesTheCeilingFromTheProbeBudget covers on its own.
func useShortOperationBound(t *testing.T, d time.Duration) {
	t.Helper()
	previous := transportAllowance
	transportAllowance = d
	t.Cleanup(func() { transportAllowance = previous })
}

// Every way an SSH exchange can stop making progress without anybody
// cancelling it. The caller's context here has no deadline, which is what an
// ordinary --via run passes: an interruption channel and nothing more.
func TestRunBoundsAStalledRemoteOperation(t *testing.T) {
	for _, tc := range []struct{ name, mode string }{
		// ssh starts and the peer never writes a response.
		{"no response", "noresponse"},
		// The peer waits for its stdin to end first. The local side holds that
		// pipe open on purpose as the worker's liveness channel, so waiting for
		// EOF before answering deadlocks the protocol rather than delaying it.
		{"waits for stdin EOF", "stdineof"},
		// A connection or worker startup that hangs before the request is read.
		{"stalls before reading the request", "hang"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useFakeSSH(t, tc.mode)
			useShortOperationBound(t, 300*time.Millisecond)
			start := time.Now()
			_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20})
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(err.Error(), "timed out") {
				t.Errorf("error = %q, want it to say the remote run timed out", err)
			}
			// The same failure must not read as the user having stopped the
			// run: nobody interrupted anything here, and --via spends a
			// different exit code for each.
			if strings.Contains(err.Error(), "interrupted") {
				t.Errorf("error = %q, want the operation deadline, not an interruption", err)
			}
			if !strings.Contains(err.Error(), "server") {
				t.Errorf("error = %q, want it to name the SSH destination", err)
			}
			// The stand-in stalls for 30 seconds. Anywhere near that means the
			// deadline never reached it.
			if elapsed := time.Since(start); elapsed > 10*time.Second {
				t.Errorf("Run took %s to give up on a stalled exchange", elapsed)
			}
		})
	}
}

// A remote run that takes its time is not a stalled one, and the ceiling must
// be well clear of an exchange that is still making progress.
func TestRunCompletesASlowExchangeInsideTheOperationBound(t *testing.T) {
	useFakeSSH(t, "slow")
	useShortOperationBound(t, 2*time.Second)
	resp, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Report == nil || !resp.Report.OK {
		t.Fatalf("response did not carry the completed diagnosis: %+v", resp)
	}
}

// The deadline has to end the local ssh process, not merely stop waiting for
// it. The stand-in appends to a file while it is alive, so a process left
// behind keeps writing after Run has returned.
func TestRunStopsTheSSHProcessItGaveUpOn(t *testing.T) {
	useFakeSSH(t, "noresponse")
	useShortOperationBound(t, 300*time.Millisecond)
	alive := t.TempDir() + string(os.PathSeparator) + "alive"
	t.Setenv(fakeSSHAlive, alive)

	if _, err := Run(context.Background(), "server", "", Request{TimeoutMs: 20}); err == nil {
		t.Fatal("want the operation deadline error, got none")
	}
	if aliveFor(t, alive) == 0 {
		t.Fatal("the stand-in ssh never recorded that it ran")
	}
	settled := aliveFor(t, alive)
	time.Sleep(200 * time.Millisecond)
	if grew := aliveFor(t, alive); grew != settled {
		t.Errorf("the stand-in ssh kept running after Run returned: %d bytes, was %d", grew, settled)
	}
}

func aliveFor(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return int(info.Size())
}

// The ceiling is derived, not picked: the probe budget the request carries,
// times the deepest chain of probes one pass can spend, plus the transport
// allowance. A larger --timeout therefore always buys a larger remote bound,
// and no user-selected probe budget can be cut short by it.
func TestOperationTimeoutDerivesTheCeilingFromTheProbeBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		ms   int64
		want time.Duration
	}{
		{"default probe budget", 4000, 5*4*time.Second + time.Minute},
		{"a deliberately long probe budget", 30000, 5*30*time.Second + time.Minute},
		{"a short probe budget", 250, 5*250*time.Millisecond + time.Minute},
		// The far end refuses a request with no budget, so only the transport
		// is left to bound.
		{"no budget in the request", 0, time.Minute},
		{"a negative budget", -1, time.Minute},
		// A value this large is refused before it is ever run, but the
		// arithmetic here must saturate rather than wrap into a short deadline.
		{"a budget that would overflow", math.MaxInt64 / int64(time.Millisecond), time.Duration(math.MaxInt64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := operationTimeout(tc.ms); got != tc.want {
				t.Errorf("operationTimeout(%d) = %v, want %v", tc.ms, got, tc.want)
			}
		})
	}
	// Whatever the request asks for, the bound never falls below the probe
	// budget a user chose, which is the one way it could turn a legitimate run
	// into a failure.
	for _, ms := range []int64{1, 250, 4000, 30000, 600000} {
		if got := operationTimeout(ms); got <= time.Duration(ms)*time.Millisecond {
			t.Errorf("operationTimeout(%d) = %v, which is inside one probe budget", ms, got)
		}
	}
}

func TestRunReturnsACompleteResponseWhenStdoutStaysOpen(t *testing.T) {
	useFakeSSH(t, "openstdout")

	// This deadline bounds the regression and cleans up the fake SSH process.
	// It is not the behavior under test: Run must return before it expires.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := Run(ctx, "server", "", Request{})
	if ctx.Err() != nil {
		t.Fatalf("Run withheld a complete response until cancellation: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Report == nil || !resp.Report.OK {
		t.Fatalf("response did not carry the completed diagnosis: %+v", resp)
	}
}

func TestRunStopsAnOversizedProducer(t *testing.T) {
	useFakeSSH(t, "oversize")
	// The deadline is a hang backstop, not a timing assertion. Pushing the cap
	// through the decoder is CPU work whose speed depends on the machine, and
	// -race on a loaded runner can take more than a few seconds.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := Run(ctx, "server", "", Request{})
	if ctx.Err() != nil {
		t.Fatal("Run waited for context cancellation after the oversized response")
	}
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("Run error = %v, want oversized response error", err)
	}
}

func TestValidateDestinationRefusesArgvOptionInjection(t *testing.T) {
	for _, dest := range []string{
		"-oProxyCommand=touch /tmp/pwned",
		"-i/tmp/key",
		"--",
		"server -oProxyCommand=x",
		"serv\ner",
		"serv er",
		"",
	} {
		if err := validateDestination(dest); err == nil {
			t.Errorf("validateDestination(%q) accepted it", dest)
		}
	}
	// Everything OpenSSH itself accepts as a destination still has to work.
	for _, dest := range []string{"ideapad", "user@host", "ssh://user@host:2222", "10.0.0.4", "[fe80::1]", "host.example.com"} {
		if err := validateDestination(dest); err != nil {
			t.Errorf("validateDestination(%q) = %v, want it accepted", dest, err)
		}
	}
}

func TestValidateCommandRefusesAnythingARemoteShellWouldReinterpret(t *testing.T) {
	for _, command := range []string{
		"netdoc; rm -rf /",
		"netdoc & calc.exe",
		"netdoc $(id)",
		"netdoc `id`",
		`C:\Program Files\netdoc.exe`,
		"%COMSPEC%",
		"-oProxyCommand=x",
		"netdoc|tee",
	} {
		if err := validateCommand(command); err == nil {
			t.Errorf("validateCommand(%q) accepted it", command)
		}
	}
	for _, command := range []string{"netdoc", "/usr/local/bin/netdoc", `C:\Users\me\bin\netdoc.exe`, "~/bin/netdoc"} {
		if err := validateCommand(command); err != nil {
			t.Errorf("validateCommand(%q) = %v, want it accepted", command, err)
		}
	}
}

func TestServeAnswersOneRequestWithOneObjectAndNothingElse(t *testing.T) {
	var out strings.Builder
	tool := snapshot.Tool{Version: "1.2.3", OS: "windows", Arch: "amd64"}
	var seen Request
	err := Serve(context.Background(), liveStdin(t, `{"protocol":1,"target":"example.com","timeout_ms":2000}`), &out, tool,
		func(_ context.Context, req Request) (*report.Report, *snapshot.Snapshot, error) {
			seen = req
			return &report.Report{OK: true}, &snapshot.Snapshot{Schema: snapshot.Schema}, nil
		})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if seen.Target != "example.com" || seen.TimeoutMs != 2000 {
		t.Errorf("the worker was handed %+v", seen)
	}
	// Exactly one JSON value and no trailing prose: this stream is the protocol.
	dec := json.NewDecoder(strings.NewReader(out.String()))
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("worker stdout is not one JSON object: %v", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		t.Errorf("worker stdout carried more than the response: %q", out.String())
	}
	if resp.Protocol != Protocol || resp.Tool != tool || resp.Report == nil || resp.Snapshot == nil {
		t.Errorf("response = %+v", resp)
	}
}

func TestServeRefusesWhatItCannotRun(t *testing.T) {
	ran := func(context.Context, Request) (*report.Report, *snapshot.Snapshot, error) {
		t.Error("the diagnosis ran for a request that should have been refused")
		return nil, nil, nil
	}
	for _, tc := range []struct {
		name, in, want string
	}{
		{"another protocol", `{"protocol":7}`, "protocol 1, not 7"},
		{"not json", "hello", "could not read the remote request"},
		{"empty stream", "", "could not read the remote request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			if err := Serve(context.Background(), strings.NewReader(tc.in), &out, snapshot.Tool{}, ran); err != nil {
				t.Fatalf("Serve: %v", err)
			}
			var resp Response
			if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Protocol != Protocol {
				t.Errorf("a refusal has to stay readable to the version that asked: %+v", resp)
			}
			if !strings.Contains(resp.Error, tc.want) {
				t.Errorf("error = %q, want it to mention %q", resp.Error, tc.want)
			}
		})
	}
}

func TestServeReportsARejectedRequestInsteadOfFailingTheExchange(t *testing.T) {
	var out strings.Builder
	err := Serve(context.Background(), liveStdin(t, `{"protocol":1}`), &out, snapshot.Tool{},
		func(context.Context, Request) (*report.Report, *snapshot.Snapshot, error) {
			return nil, nil, errors.New("-timeout must be positive")
		})
	if err != nil {
		t.Fatalf("a refused request is still a completed exchange: %v", err)
	}
	var resp Response
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != "-timeout must be positive" || resp.Report != nil {
		t.Errorf("response = %+v", resp)
	}
}

func TestServeStripsEscapeSequencesFromWhatItSaysBack(t *testing.T) {
	var out strings.Builder
	_ = Serve(context.Background(), liveStdin(t, `{"protocol":1}`), &out, snapshot.Tool{},
		func(context.Context, Request) (*report.Report, *snapshot.Snapshot, error) {
			return nil, nil, errors.New("bad target \x1b[31mred\x1b]0;title\x07")
		})
	var resp Response
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(resp.Error, 0x1b) {
		t.Errorf("an escape sequence survived into the response: %q", resp.Error)
	}
}

func TestServeStopsProbingWhenTheCallerGoesAway(t *testing.T) {
	// Stdin at EOF after the request is what a dropped SSH channel looks like
	// from the worker's side, and it has to reach the running diagnosis.
	var out strings.Builder
	stopped := make(chan struct{})
	err := Serve(context.Background(), strings.NewReader(`{"protocol":1}`), &out, snapshot.Tool{},
		func(ctx context.Context, _ Request) (*report.Report, *snapshot.Snapshot, error) {
			select {
			case <-ctx.Done():
				close(stopped)
				return nil, nil, errors.New("the run was interrupted before it finished")
			case <-time.After(10 * time.Second):
				return nil, nil, errors.New("the cancellation never arrived")
			}
		})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("the diagnosis was not cancelled when the caller's stream ended")
	}
}

func TestServeRefusesARequestThatNeverEnds(t *testing.T) {
	var out strings.Builder
	err := Serve(context.Background(), endless{}, &out, snapshot.Tool{},
		func(context.Context, Request) (*report.Report, *snapshot.Snapshot, error) {
			t.Error("an unbounded request reached the diagnosis")
			return nil, nil, nil
		})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if !strings.Contains(out.String(), "could not read the remote request") {
		t.Errorf("response = %q", out.String())
	}
}

func TestDecodeResponseRefusesAnUnboundedStream(t *testing.T) {
	if _, _, _, err := decodeResponse(endless{}); err == nil {
		t.Fatal("an unbounded response was accepted")
	}
}

func TestDecodeResponseEnforcesFramingBoundary(t *testing.T) {
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(diagnosedResponse(t)); err != nil {
		t.Fatal(err)
	}
	response := encoded.Bytes()
	for _, tc := range []struct {
		name string
		in   io.Reader
		want string
	}{
		{"normal", bytes.NewReader(response), ""},
		{"exactly at limit", bytes.NewReader(paddedResponse(t, MaxResponseBytes)), ""},
		{"one byte over limit", bytes.NewReader(paddedResponse(t, MaxResponseBytes+1)), "too large"},
		{"second JSON value", io.MultiReader(bytes.NewReader(response), strings.NewReader("{}\n")), "more than one response"},
		{"trailing prose", io.MultiReader(bytes.NewReader(response), strings.NewReader("hello")), "more than one response"},
		{"trailing data crosses limit", io.MultiReader(bytes.NewReader(paddedResponse(t, MaxResponseBytes)), strings.NewReader("x")), "too large"},
		{"trailing whitespace", io.MultiReader(bytes.NewReader(response), strings.NewReader(" \r\n\t")), ""},
		{"continuing past limit", io.MultiReader(bytes.NewReader(response), endless{}), "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// decodeResponse reports the first response's own problems; this
			// second phase, on the same decoder and LimitedReader, reports
			// anything past it. The two are never checked apart.
			_, dec, limited, err := decodeResponse(tc.in)
			if err == nil {
				err = confirmNoTrailingData(dec, limited)
			}
			if tc.want == "" && err != nil {
				t.Fatalf("framing: %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("framing error = %v, want %q", err, tc.want)
			}
		})
	}
}

// openAfterReader stands in for a live SSH stdout that stays open after the
// response: its first Read hands back one complete response, and the next Read
// proves decodeResponse kept reading past it instead of returning. It never
// yields EOF on its own, so a decodeResponse that waits for EOF blocks here.
type openAfterReader struct {
	first     []byte
	attempted chan struct{}
	release   chan struct{}
}

func (r *openAfterReader) Read(p []byte) (int, error) {
	if len(r.first) > 0 {
		n := copy(p, r.first)
		r.first = r.first[n:]
		return n, nil
	}
	// A read past the complete response is the bug: signal it, then block on
	// release so the decode goroutine cannot leak.
	select {
	case r.attempted <- struct{}{}:
	default:
	}
	<-r.release
	return 0, io.EOF
}

// TestDecodeResponseReturnsAfterCompleteResponseWithoutWaitingForEOF pins #157:
// once decodeResponse has one complete valid Response it must return, not read
// past it for an EOF that a live SSH stdout will not send while the local stdin
// stays open. A deterministic signal fires when decodeResponse attempts that
// unwanted post-response read, so the test never relies on timing.
func TestDecodeResponseReturnsAfterCompleteResponseWithoutWaitingForEOF(t *testing.T) {
	data, err := json.Marshal(diagnosedResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	attempted := make(chan struct{}, 1)
	release := make(chan struct{})
	r := &openAfterReader{first: data, attempted: attempted, release: release}

	type decoded struct {
		resp Response
		err  error
	}
	result := make(chan decoded, 1)
	go func() {
		resp, _, _, err := decodeResponse(r)
		result <- decoded{resp, err}
	}()

	select {
	case <-attempted:
		// decodeResponse read past the already-complete response. Let the
		// goroutine finish, then fail for it.
		close(release)
		got := <-result
		t.Fatalf("decodeResponse read past the complete response (resp=%+v, err=%v); it must return once the response is complete", got.resp, got.err)
	case got := <-result:
		if got.err != nil {
			t.Fatalf("decodeResponse returned an error on a complete response: %v", got.err)
		}
		if got.resp.Protocol != Protocol || got.resp.Report == nil || got.resp.Snapshot == nil {
			t.Fatalf("decodeResponse did not return the complete valid response: %+v", got.resp)
		}
	}
}

func paddedResponse(t *testing.T, size int) []byte {
	t.Helper()
	const prefix = `{"protocol":1,"tool":{},"error":"remote failure","padding":"`
	// Encoder newline is part of the complete response representation and
	// therefore counts toward MaxResponseBytes.
	const suffix = `"}` + "\n"
	if size < len(prefix)+len(suffix) {
		t.Fatalf("response size %d is too small", size)
	}
	return []byte(prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix)
}

func TestDecodeResponseNamesWhatIsMissing(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"nothing at all", "", "no response"},
		{"cut short", `{"protocol":1,"report":`, "could not read the remote response"},
		{"neither answer nor error", `{"protocol":1}`, "carried no diagnosis and no error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := decodeResponse(strings.NewReader(tc.in))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("decodeResponse = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// liveStdin is a request followed by a stream that stays open, which is what
// the local side holds while it waits for an answer. A reader that ends at the
// request would be a caller that hung up, and the worker treats that as one.
func liveStdin(t *testing.T, request string) io.Reader {
	t.Helper()
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	return io.MultiReader(strings.NewReader(request), blockUntil{held})
}

type blockUntil struct{ done <-chan struct{} }

func (b blockUntil) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

// endless never stops producing plausible-looking bytes, the shape of a peer
// that answers a request with an unbounded stream.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

// Both halves of the second-opinion setting cross protocol 1 without moving it.
// public_dns keeps carrying an address or the empty opt-out, which is all a
// netdoc from before this feature has ever accepted there, and the bit beside
// it is additive: absent on the wire when false, ignored by a remote that has
// never heard of it, and read as false when a remote that knows it receives a
// request from one that does not.
func TestPublicDNSAutoCrossesProtocolOneAsAnAdditiveField(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"default", Request{Protocol: Protocol, PublicDNS: "8.8.8.8", PublicDNSAuto: true, TimeoutMs: 4000}},
		{"resolver the user named", Request{Protocol: Protocol, PublicDNS: "8.8.8.8", TimeoutMs: 4000}},
		{"switched off", Request{Protocol: Protocol, PublicDNS: "", TimeoutMs: 4000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.req)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			// The worker netdoc used to be: protocol 1, and public_dns is the
			// only thing it knows about the second opinion.
			var legacy struct {
				Protocol  int    `json:"protocol"`
				PublicDNS string `json:"public_dns"`
				TimeoutMs int64  `json:"timeout_ms"`
			}
			if err := json.Unmarshal(data, &legacy); err != nil {
				t.Fatalf("legacy decode: %v", err)
			}
			if legacy.Protocol != Protocol {
				t.Errorf("protocol = %d, want %d: an added field is not a new protocol", legacy.Protocol, Protocol)
			}
			if legacy.PublicDNS != tc.req.PublicDNS || legacy.TimeoutMs != tc.req.TimeoutMs {
				t.Errorf("legacy request = %+v, want the run it was given", legacy)
			}
			var keys map[string]json.RawMessage
			if err := json.Unmarshal(data, &keys); err != nil {
				t.Fatalf("read keys: %v", err)
			}
			if _, present := keys["public_dns_auto"]; present != tc.req.PublicDNSAuto {
				t.Errorf("public_dns_auto present = %v, want %v", present, tc.req.PublicDNSAuto)
			}
			var back Request
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if back.PublicDNS != tc.req.PublicDNS || back.PublicDNSAuto != tc.req.PublicDNSAuto {
				t.Errorf("request = %+v, want %+v", back, tc.req)
			}
		})
	}

	// The other direction: a request from a netdoc that predates the field.
	var legacy Request
	if err := json.Unmarshal([]byte(`{"protocol":1,"public_dns":"8.8.8.8","timeout_ms":4000}`), &legacy); err != nil {
		t.Fatalf("decode legacy request: %v", err)
	}
	if legacy.PublicDNS != "8.8.8.8" || legacy.PublicDNSAuto {
		t.Errorf("legacy request = %+v, want 8.8.8.8 with auto=false", legacy)
	}
	// And an unknown field from a newer one is ignored rather than fatal, which
	// is the same promise in the other direction.
	var newer Request
	if err := json.Unmarshal([]byte(`{"protocol":1,"public_dns":"8.8.8.8","public_dns_auto":true,"nonesuch":{"a":1}}`), &newer); err != nil {
		t.Fatalf("decode newer request: %v", err)
	}
	if newer.PublicDNS != "8.8.8.8" || !newer.PublicDNSAuto {
		t.Errorf("newer request = %+v, want 8.8.8.8 with auto=true", newer)
	}
}

// diagnosedPair is one run spelled in both formats, which is the only shape a
// successful response is allowed to carry. It is written once here so that a
// test about the transport is not quietly also a test that two hand-written
// artifacts happened to match.
func diagnosedPair(tool snapshot.Tool, ok bool) (report.Report, snapshot.Snapshot) {
	status, verdict, failed := "PASS", "ok", ""
	if !ok {
		status, verdict, failed = "FAIL", "network", "internet"
	}
	rep := report.Report{
		Version: tool.Version, OK: ok, Verdict: verdict, FailedStage: failed,
		Target: &report.Target{Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []report.Check{{ID: "internet", Name: "Internet", Status: status, Ms: 4}},
	}
	snap := snapshot.Snapshot{
		Schema: snapshot.Schema, Tool: tool, CreatedAt: "2026-01-02T03:04:05Z", OK: ok,
		Target:    &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks:    []snapshot.Check{{ID: "internet", Name: "Internet", Status: status, Ran: true, DurationMs: 4}},
		Diagnosis: snapshot.Diagnosis{Verdict: verdict, FailedStage: failed},
	}
	return rep, snap
}

// fakeCanaryConfig reports whether argv is the configuration check sshverify runs
// against the client: a verbose listing of the host "canary" from a file it wrote.

// fakeCanary answers the check the way OpenSSH does: it reports the file it reads,
// reports the Match exec test only in the file that has one, and lists the host.

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// Headless, a direct route is read as direct, and a proxied one is not. A route the
// run cannot establish is never direct, so the batch transport is not offered for it.
func TestDirectOnlyAcceptsAKnownDirectRouteHeadless(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "config")
	withoutTerminal(t)
	if !Direct(context.Background(), "ideapad") {
		t.Error("a headless run did not read a known direct route as direct")
	}
	_ = argvPath
	useFakeSSH(t, "configproxy")
	withoutTerminal(t)
	if Direct(context.Background(), "ideapad") {
		t.Error("a headless run read a proxied route as direct")
	}
}

// fakeCanaryShell is the canary's probe client, answering as OpenSSH does. A race-built
// test binary takes about a second to start, and the canary runs fourteen probes, which
// would not finish inside a read's budget under -race. The probes are answered here, by
// a shell script, and every other call still runs the test binary.
const fakeCanaryShell = `#!/bin/sh
BROKEN=""
cfg=""
prev=""
last=""
for a in "$@"; do
  if [ "$prev" = "-F" ]; then cfg="$a"; fi
  prev="$a"
  last="$a"
done
# Every file read is announced, and each Include is followed to its own includes. A
# client that stops following at the first level is the include-announcement break.
walk() {
  echo "debug1: Reading configuration data $1" >&2
  for i in $(sed -n 's/^Include //p' "$1"); do
    if [ "$BROKEN" = include-announcement ] && [ "$2" -ge 1 ]; then continue; fi
    walk "$i" $(( $2 + 1 ))
  done
}
walk "$cfg" 0
case "$(cat "$cfg")" in
  *"Match !canonical exec"*) [ "$BROKEN" = canonical-positive ] || echo "debug1: Executing command: 'true'" >&2 ;;
  *"Match canonical exec"*) [ "$BROKEN" = canonical-exec ] && echo "debug1: Executing command: 'true'" >&2 ;;
  *"Match host canary exec"*) echo "debug1: Executing command: 'true'" >&2 ;;
esac
case "$(cat "$cfg")" in
  *"ProxyJump 127.0.0.2"*) [ "$BROKEN" = proxyjump-positive ] || echo "proxyjump [127.0.0.2]" ;;
  *"ProxyJump none"*) [ "$BROKEN" = proxyjump ] && echo "proxyjump bastion" ;;
esac
case "$(cat "$cfg")" in
  *"KnownHostsCommand touch"*)
    echo "knownhostscommand touch x"
    if [ "$BROKEN" = knownhostscommand ]; then
      sentinel=$(sed -n 's/.*KnownHostsCommand touch //p' "$cfg"); touch "$sentinel"
    fi ;;
  *"KnownHostsCommand none"*) echo "knownhostscommand none" ;;
esac
case "$(cat "$cfg")" in
  *'User ${NETDOC_CANARY_VAR}u'*)
    if [ "$BROKEN" = environment ]; then echo 'user ${netdoc_canary_var}u'; else echo "user alphau"; fi ;;
esac
hn="127.0.0.1"
case "$(cat "$cfg")" in
  *'HostName ${NETDOC_CANARY_VAR}.example'*)
    hn='${netdoc_canary_var}.example'
    if [ "$BROKEN" = environment-literal ]; then echo "identityfile alpha/k"; else echo 'identityfile ${NETDOC_CANARY_VAR}/k'; fi ;;
  *'Host ${NETDOC_CANARY_VAR}'*)
    if [ "$BROKEN" = environment-host ]; then hn="127.0.0.9"; else hn="$last"; fi ;;
esac
case "$(cat "$cfg")" in
  *"CanonicalizeHostname yes"*)
    if [ "$BROKEN" = canonicalizehostname ] || [ "$BROKEN" = canonicalizehostname-positive ]; then echo "canonicalizehostname false"; else echo "canonicalizehostname true"; fi ;;
  *)
    if [ "$BROKEN" = canonicalizehostname ]; then echo "canonicalizehostname true"; else echo "canonicalizehostname false"; fi ;;
esac
echo "hostname $hn"
exit 0
`

// fakeSSHProgram is the program a stand-in test uses as ssh. It sends the canary's
// verbose configuration reads to fakeCanaryShell, and every other call to this test
// binary in fake mode.
func fakeSSHProgram(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	canary := filepath.Join(dir, "canary.sh")
	if err := os.WriteFile(canary, []byte(fakeCanaryShell), 0o700); err != nil { // #nosec G306 -- an executable test script on purpose
		t.Fatal(err)
	}
	wrapper := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  -v) case \" $* \" in *\" -F \"*) exec /bin/sh '" + canary + "' \"$@\" ;; esac ;;\n" +
		"esac\n" +
		"exec '" + os.Args[0] + "' \"$@\"\n"
	// #nosec G306 G703 -- an executable test script in a directory this test created
	if err := os.WriteFile(wrapper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return wrapper
}
