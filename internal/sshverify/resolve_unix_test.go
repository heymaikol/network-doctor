//go:build unix

package sshverify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeClient writes an executable stand-in for the ssh client. The script can
// record its own PID and a background child's PID in files, so a test can check
// that every process it started has ended.
func fakeClient(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	// A real client reports each configuration file it reads at -v, and netdoc reads the
	// file the report names, so the fake names a real, harmless configuration file.
	cfg := filepath.Join(filepath.Dir(path), "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\necho 'debug1: Reading configuration data " + cfg + "' >&2\necho 'canonicalizehostname false'\n" + script
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { // #nosec G306 -- the test writes an executable fake ssh client on purpose
		t.Fatal(err)
	}
	return path
}

// requireConfigRead skips a test that reads configuration on a platform that refuses the
// read. ReadConfig refuses before any client starts, so a fake client or a headless child
// would only report that refusal.
func requireConfigRead(t *testing.T) {
	t.Helper()
	if !configPlatformSupported {
		t.Skip("the configuration read is refused on this platform, so no client is started")
	}
}

// useFakeClient points the configuration read at client for one test.
func useFakeClient(t *testing.T, client string, timeout time.Duration) {
	t.Helper()
	requireConfigRead(t)
	savedBinary, savedTimeout, savedGrace, savedCanary, savedTerminal := sshBinary, resolveTimeout, outputGrace, canaryCheck, TerminalAvailable
	sshBinary, resolveTimeout = client, timeout
	// A fake client cannot pass the canary, which checks the real client; the canary
	// has its own tests against the installed OpenSSH. The fake runs as if netdoc had
	// its terminal, so the reads it stands in for are reached.
	canaryCheck = func(context.Context, string) error { return nil }
	TerminalAvailable = func() bool { return true }
	t.Cleanup(func() {
		sshBinary, resolveTimeout, outputGrace, canaryCheck, TerminalAvailable = savedBinary, savedTimeout, savedGrace, savedCanary, savedTerminal
	})
}

// waitForPID returns the PID a script wrote to file, once it has been written.
func waitForPID(t *testing.T, file string) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(file) // #nosec G304 -- a file this test's script wrote
		if err == nil && strings.TrimSpace(string(data)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("%s holds %q, not a PID", file, data)
			}
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fake client never wrote %s", file)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// processEnded reports whether pid has exited. A zombie has exited too, though
// kill(0) still finds it until it is reaped, so /proc is checked for one.
func processEnded(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)) // #nosec G304 -- a process this test started
	if err != nil {
		return false
	}
	closing := strings.LastIndex(string(data), ")")
	return closing >= 0 && len(data) > closing+2 && data[closing+2] == 'Z'
}

func requireEnded(t *testing.T, pid int, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !processEnded(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("%s (pid %d) is still running after the read ended", what, pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A hung client that holds the output pipe open must not hold the read open.
func TestResolveIsBoundedWhenTheClientHangs(t *testing.T) {
	client := fakeClient(t, "sleep 60 &\nsleep 60\n")
	useFakeClient(t, client, 300*time.Millisecond)
	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now()
		_, err := Resolve(context.Background(), "host", 0, "")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("attempt %d: a hung configuration read returned no error", attempt)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("attempt %d: a hung configuration read took %v; want it bounded by its deadline", attempt, elapsed)
		}
	}
}

// Cancellation ends the client and the child it started, and nothing else.
func TestCancellationEndsTheClientAndItsChildren(t *testing.T) {
	dir := t.TempDir()
	self, child := filepath.Join(dir, "self.pid"), filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("echo $$ > %s\nsleep 300 &\necho $! > %s\nwait\n", self, child))
	useFakeClient(t, client, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		waitForPID(t, child)
		cancel()
	}()

	if _, err := Resolve(ctx, "host", 0, ""); err == nil {
		t.Fatal("a cancelled configuration read returned no error")
	}
	requireEnded(t, waitForPID(t, self), "the ssh client")
	requireEnded(t, waitForPID(t, child), "the child the client started")
}

// The deadline ends the client and the child it started in the same way.
func TestTimeoutEndsTheClientAndItsChildren(t *testing.T) {
	dir := t.TempDir()
	self, child := filepath.Join(dir, "self.pid"), filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("echo $$ > %s\nsleep 300 &\necho $! > %s\nwait\n", self, child))
	useFakeClient(t, client, 500*time.Millisecond)

	if _, err := Resolve(context.Background(), "host", 0, ""); err == nil {
		t.Fatal("a timed-out configuration read returned no error")
	}
	requireEnded(t, waitForPID(t, self), "the ssh client")
	requireEnded(t, waitForPID(t, child), "the child the client started")
}

// A client that exits normally must not leave the child it started running.
func TestSuccessfulReadLeavesNoBackgroundChild(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "child.pid")
	client := fakeClient(t, fmt.Sprintf("sleep 300 &\necho $! > %s\nprintf 'hostname h\\nport 22\\nuser u\\nrevokedhostkeys none\\n'\nexit 0\n", child))
	useFakeClient(t, client, time.Minute)

	target, err := Resolve(context.Background(), "host", 0, "")
	if err != nil {
		t.Fatalf("a successful read returned an error: %v", err)
	}
	if target.Host != "h" {
		t.Fatalf("host = %q, want the complete listing", target.Host)
	}
	requireEnded(t, waitForPID(t, child), "the child the client left behind")
}

// A listing that ends without its last newline is incomplete, and it is refused
// rather than parsed as if it were whole.
func TestIncompleteOutputIsRefused(t *testing.T) {
	client := fakeClient(t, "printf 'hostname h\\nport 22\\nuser u'\nexit 0\n")
	useFakeClient(t, client, time.Minute)

	_, err := Resolve(context.Background(), "host", 0, "")
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("an incomplete listing was accepted: %v", err)
	}
}

// A child that leaves the process group and keeps the output open makes the
// listing incomplete for certain, so it is an error. The child is killed by the
// test, since the read does not reach it.
func TestChildOutsideTheGroupIsAnError(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	t.Cleanup(func() { killRecorded(pidFile) })
	// The holder is TestHoldDiagnosticPipe, started with its stdout left as the listing pipe and its
	// stderr sent to /dev/null, so the listing is the only stream it holds open. It leaves the client's session with Setsid, so the client's group
	// kill does not reach it: the test is about a child that escaped. No external setsid is run.
	client := fakeClient(t, fmt.Sprintf(
		"%s='%s' '%s' -test.run='^TestHoldDiagnosticPipe$' 2>/dev/null &\n"+
			"while [ ! -e '%s' ]; do sleep 0.05; done\n"+
			"printf 'hostname h\\nport 22\\nuser u\\nrevokedhostkeys none\\n'\nexit 0\n",
		holdEnv, pidFile, self, pidFile))
	useFakeClient(t, client, 10*time.Second)
	outputGrace = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), holderStartBound+holderOutputBudget)
	defer cancel()
	_, err = Resolve(ctx, "host", 0, "")
	expired := ctx.Err() != nil
	pid := holderPID(t, pidFile, ctx, err)
	if expired {
		t.Fatalf("the read reached its %v deadline before the listing closed, so the listing was not checked", holderStartBound+holderOutputBudget)
	}
	if processEnded(pid) {
		t.Fatalf("the holder (pid %d) ended before the read did, so the listing was not held open", pid)
	}
	if err == nil || !strings.Contains(err.Error(), "kept it open") {
		t.Fatalf("a read held open by a child outside the group was accepted: %v", err)
	}
}

// Each read opens pipes for the client's output. They must be closed when the
// read ends, or every read leaks descriptors for the life of the process.
func TestRepeatedReadsDoNotLeakDescriptors(t *testing.T) {
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		t.Skip("descriptor counts are read from /proc, which this platform does not have")
	}
	client := fakeClient(t, "printf 'hostname h\\nport 22\\nuser u\\nrevokedhostkeys none\\n'\n")
	useFakeClient(t, client, time.Minute)
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	if _, err := Resolve(context.Background(), "host", 0, ""); err != nil {
		t.Fatal(err)
	}
	before := count()
	for i := 0; i < 20; i++ {
		if _, err := Resolve(context.Background(), "host", 0, ""); err != nil {
			t.Fatal(err)
		}
	}
	if after := count(); after > before {
		t.Fatalf("20 reads left %d descriptors open; want no growth from %d", after-before, before)
	}
}

// An oversized listing is refused as oversized, promptly. The client keeps
// writing after the limit, so the output must still be drained: a client blocked
// on a full pipe would otherwise run until the deadline and report a hang.
func TestOversizedListingIsRefusedAsOversized(t *testing.T) {
	client := fakeClient(t, "head -c 2097152 /dev/zero | tr '\\0' 'a'\nexit 0\n")
	useFakeClient(t, client, 10*time.Second)

	start := time.Now()
	_, err := Resolve(context.Background(), "host", 0, "")
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "larger than netdoc reads") {
		t.Fatalf("an oversized listing returned %v; want the size refusal", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the size refusal took %v; a client blocked on the pipe was left to the deadline", elapsed)
	}
}

// settledGoroutines returns the goroutine count once it stops changing, so a
// reader that is still exiting does not count as growth.
func settledGoroutines() int {
	last := -1
	for i := 0; i < 50; i++ {
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == last {
			return n
		}
		last = n
		time.Sleep(10 * time.Millisecond)
	}
	return last
}

// Repeated reads start output readers and a wait each time. If any of them outlives
// its read, the goroutine count grows with every read.
func TestRepeatedReadsDoNotLeakGoroutines(t *testing.T) {
	client := fakeClient(t, "printf 'hostname 127.0.0.1\\nport 22\\nuser demo\\nrevokedhostkeys none\\n'\nexit 0\n")
	useFakeClient(t, client, 5*time.Second)
	read := func() {
		t.Helper()
		if _, err := Resolve(context.Background(), "host", 0, ""); err != nil {
			t.Fatalf("a read failed: %v", err)
		}
	}
	read()
	before := settledGoroutines()
	for i := 0; i < 40; i++ {
		read()
	}
	after := settledGoroutines()
	if growth := after - before; growth > 3 {
		t.Fatalf("goroutines grew from %d to %d over 40 reads; a read leaves a goroutine behind", before, after)
	}
}

// Diagnostics larger than netdoc reads are not a prefix to classify. A Match exec
// reported after the limit would be missed, so the read is refused.
func TestTruncatedDiagnosticsAreRefused(t *testing.T) {
	client := fakeClient(t, "yes 'debug2: filler line' | head -c 2097152 >&2\nprintf 'debug1: Executing command: x\\n' >&2\nprintf 'hostname 127.0.0.1\\nport 22\\nuser demo\\nrevokedhostkeys none\\n'\nexit 0\n")
	useFakeClient(t, client, 10*time.Second)
	_, err := Resolve(context.Background(), "host", 0, "")
	if err == nil || !strings.Contains(err.Error(), "larger than netdoc reads") {
		t.Fatalf("a read with truncated diagnostics returned %v; want the refusal", err)
	}
}

// A diagnostic stream a process left open is not complete, so it is refused rather
// than classified: the command may still be writing.
func TestIncompleteDiagnosticsAreRefused(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "holder.pid")
	t.Cleanup(func() { killRecorded(pidFile) })
	// The client starts the holder, waits for the holder to record its pid, and only then prints
	// its listing and exits. The holder keeps the stderr it inherited, which is the diagnostic
	// stream, open after the client is gone. It leaves the client's session, so the client's
	// group cleanup does not reach it.
	client := fakeClient(t, fmt.Sprintf(
		"%s='%s' '%s' -test.run='^TestHoldDiagnosticPipe$' >/dev/null &\n"+
			"while [ ! -e '%s' ]; do sleep 0.05; done\n"+
			"printf 'hostname 127.0.0.1\\nport 22\\nuser demo\\nrevokedhostkeys none\\n'\nexit 0\n",
		holdEnv, pidFile, self, pidFile))
	useFakeClient(t, client, 10*time.Second)
	outputGrace = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), holderStartBound+holderOutputBudget)
	defer cancel()
	_, err = Resolve(ctx, "host", 0, "")
	expired := ctx.Err() != nil
	pid := holderPID(t, pidFile, ctx, err)
	if expired {
		t.Fatalf("the read reached its %v deadline before the diagnostic stream closed, so the diagnostic stream was not checked", holderStartBound+holderOutputBudget)
	}
	if processEnded(pid) {
		t.Fatalf("the holder (pid %d) ended before the read did, so the stream was not held open", pid)
	}
	if err == nil || !strings.Contains(err.Error(), "diagnostic output was not complete") {
		t.Fatalf("a read with an open diagnostic stream returned %v; want the refusal", err)
	}
}

// holdEnv names the file the holder writes its pid to. The two tests that start a holder set it.
const holdEnv = "NETDOC_TEST_HOLD_PID"

// holderStartBound is how long a holder has to record its pid. One that records within this bound normally
// completes before the read's deadline, a wall-clock timer that kills the client's group. Heavy load can slow
// the client's exit past the tail, so this is an expectation, not a guarantee.
const holderStartBound = 9 * time.Second

// holderOutputBudget is the time after the bound for the listing to close: the next 50 ms poll, the client's
// exit, and an outputGrace wait per stream (0.2 s at the tests' 100 ms). The deadline is the bound plus this,
// half a second inside the 10 s read budget.
const holderOutputBudget = 500 * time.Millisecond

// TestHoldDiagnosticPipe is the holder the tests that hold a pipe open start: a second run of this test
// binary, selected by name. It does nothing unless holdEnv names a file. It leaves the client's session,
// records its pid in a file it renames into place, and sleeps. The sleep is bounded, so a holder whose
// pid was never read still ends on its own.
func TestHoldDiagnosticPipe(t *testing.T) {
	pidFile := os.Getenv(holdEnv)
	if pidFile == "" {
		t.Skip("a helper that TestChildOutsideTheGroupIsAnError and TestIncompleteDiagnosticsAreRefused start")
	}
	if _, err := syscall.Setsid(); err != nil {
		t.Fatal(err)
	}
	tmp := pidFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil { // #nosec G306 G703 -- a file in a directory the test created
		t.Fatal(err)
	}
	if err := os.Rename(tmp, pidFile); err != nil { // #nosec G703 -- a file in a directory the test created
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

// holderPID returns the pid the holder recorded. A missing file means the holder did not start: the test's
// deadline names the bound, and any other end is named by the read's error.
func holderPID(t *testing.T, pidFile string, ctx context.Context, readErr error) int {
	t.Helper()
	data, err := os.ReadFile(pidFile) // #nosec G304 -- a path this test just created.
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
	if err == nil && convErr == nil {
		return pid
	}
	if ctx.Err() != nil {
		t.Fatalf("the holder did not record its pid within %v, so it did not start", holderStartBound)
	}
	t.Fatalf("the holder did not record its pid, so it did not start: the read ended with %v", readErr)
	return 0
}

// killRecorded ends the recorded holder when the test returns, including after a failure. A binary killed by
// -timeout or a signal runs no cleanup, and the holder then ends after its bounded sleep.
func killRecorded(pidFile string) {
	data, err := os.ReadFile(pidFile) // #nosec G304 -- a path this test just created.
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// A client that does not report its Match exec test fails the canary, so no read
// with it is trusted.
func TestCanaryRefusesAClientThatReportsNoExec(t *testing.T) {
	client := fakeClient(t, "exit 0\n")
	err := ensureCanary(context.Background(), client)
	if err == nil || !strings.Contains(err.Error(), `failed canary probe "marker-exec"`) {
		t.Fatalf("a client without exec reports passed the canary: %v", err)
	}
}

// The canary against the installed OpenSSH is the real check that the marker text
// netdoc relies on is what this client prints.
func TestCanaryPassesWithTheInstalledOpenSSH(t *testing.T) {
	requireOpenSSH(t)
	program, err := sshExecutable("ssh")
	if err != nil {
		t.Skip(err)
	}
	if err := ensureCanary(context.Background(), program); err != nil {
		t.Fatalf("the installed OpenSSH failed the canary: %v", err)
	}
}

// The read itself runs the canary first, so a client that fails it is refused before
// the target's configuration is read.
func TestResolveRunsTheCanaryFirst(t *testing.T) {
	client := fakeClient(t, "printf 'hostname 127.0.0.1\\nport 22\\nuser demo\\nrevokedhostkeys none\\n'\nexit 0\n")
	useFakeClient(t, client, 10*time.Second)
	canaryCheck = ensureCanary
	_, err := Resolve(context.Background(), "host", 0, "")
	if err == nil || !strings.Contains(err.Error(), `failed canary probe "marker-exec"`) {
		t.Fatalf("a read with a client that fails the canary returned %v; want the canary refusal", err)
	}
}

// The verification read refuses a configured revocation list before anything is sent,
// through the same client path a real read uses.
func TestVerificationReadRefusesARevocationList(t *testing.T) {
	client := fakeClient(t, "printf 'hostname h\\nport 22\\nuser u\\nrevokedhostkeys /etc/ssh/revoked\\n'\nexit 0\n")
	useFakeClient(t, client, time.Minute)
	if _, err := Resolve(context.Background(), "host", 0, ""); err == nil || !strings.Contains(err.Error(), "RevokedHostKeys is set") {
		t.Fatalf("a configured revocation list was not refused by the verification read: %v", err)
	}
}
