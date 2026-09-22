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
	"io"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
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
	case "config", "configproxy", "configproxycommand", "confignoneproxy":
		// `ssh -G`: the effective configuration, one lowercased keyword per
		// line, printed without connecting to anything. ssh leaves a proxy
		// keyword out entirely when it is unset or set to none, and
		// confignoneproxy prints it anyway to pin that the value is read too.
		fmt.Fprintln(os.Stdout, "user maikol")
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
		fmt.Fprint(os.Stdout, `{"protocol":1,"tool":{},"error":"remote failure"}`+"\n")
		_, _ = io.CopyN(os.Stdout, endless{}, 3*MaxResponseBytes)
		return 0
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
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
	sshProgram = os.Args[0]
	t.Cleanup(func() { sshProgram = previous })
	argvPath = t.TempDir() + string(os.PathSeparator) + "argv"
	requestPath = t.TempDir() + string(os.PathSeparator) + "request"
	t.Setenv(fakeSSHEnv, mode)
	t.Setenv(fakeSSHArgv, argvPath)
	t.Setenv(fakeSSHRequest, requestPath)
	t.Setenv(fakeSSHAlive, "")
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
			if got := readLines(t, argvPath); strings.Join(got, " ") != "-G ideapad" {
				t.Errorf("ssh argv = %q, want the configuration of ideapad and no connection", got)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
