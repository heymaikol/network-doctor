//go:build linux

package frrospf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The lab driver lab/run5.sh runs real FRR inside namespaces. These tests run it with
// a shim for every external command it calls, so no mount, namespace, or daemon is
// touched and nothing needs root. Each shim appends its argv to a log, so a test can
// read what the driver would have run. A fault is set by one MOCK_ variable.

// labShims are the command shims, by name. Each body runs under /bin/sh.
var labShims = map[string]string{
	"mount": `echo "mount $*" >>"$MOCK_LOG"
if [ -n "$MOCK_MOUNT_FAIL" ]; then exit 32; fi
exit 0
`,
	// mkdir for /run and /var/lib is a no-op, since the shim mounts nothing there.
	"mkdir": `p=$1
if [ "$p" = -p ]; then p=$2; fi
case $p in
/run|/run/*|/var/lib|/var/lib/*)
	echo "mkdir $*" >>"$MOCK_LOG"
	if [ -n "$MOCK_MKDIR_FAIL" ]; then exit 1; fi
	exit 0 ;;
esac
exec "$REAL_MKDIR" "$@"
`,
	"ip": `echo "ip $*" >>"$MOCK_LOG"
if [ -n "$MOCK_IP_FAIL" ]; then
	case "$*" in *"$MOCK_IP_FAIL"*) exit 1 ;; esac
fi
if [ "$1" = -o ]; then echo "2: e2: <BROADCAST,UP> mtu 1500 qdisc noqueue"; fi
exit 0
`,
	// nsenter drops its namespace flags and runs the command where it stands.
	"nsenter": `echo "nsenter $*" >>"$MOCK_LOG"
if [ "$1" = -t ]; then shift 2; fi
if [ "$1" = -n ]; then shift; fi
exec "$@"
`,
	// unshare starts the namespace holder as a plain sleep.
	"unshare": `echo "unshare $*" >>"$MOCK_LOG"
if [ -n "$MOCK_UNSHARE_FAIL" ]; then exit 1; fi
exec "$REAL_SLEEP" 3600 </dev/null >/dev/null 2>&1
`,
	"sleep": `exit 0
`,
	"timeout": `echo "timeout $*" >>"$MOCK_LOG"
if [ -n "$MOCK_TIMEOUT" ]; then exit 124; fi
shift
exec "$@"
`,
	// python3 -I tcpvty2.py PORT COMMAND answers with the command echoed and a body.
	"python3": `cmd=$4
echo "vty [$cmd]" >>"$MOCK_LOG"
if [ -n "$MOCK_VTY_FAIL" ]; then
	case "$cmd" in *"$MOCK_VTY_FAIL"*) echo refused >&2; exit 1 ;; esac
fi
printf '%s\r\n{}\r\nr1# ' "$cmd"
`,
}

// fakeDaemon stands in for zebra and ospfd. It logs its argv, answers --version, and
// starts a sleeping child whose pid goes in the -i file, as a daemon does.
const fakeDaemon = `name=$(basename "$0")
line=$name
for a in "$@"; do line="$line [$a]"; done
echo "$line" >>"$MOCK_LOG"
if [ "$1" = --version ]; then echo "$name (FRR) 10.7.0 mock"; exit 0; fi
if [ "$MOCK_DAEMON_FAIL" = "$name" ]; then exit 1; fi
pid=
while [ $# -gt 0 ]; do
	if [ "$1" = -i ]; then pid=$2; fi
	shift
done
if [ -z "$pid" ]; then exit 1; fi
"$REAL_SLEEP" 3600 >/dev/null 2>&1 &
echo $! >"$pid"
`

// labDriver returns the path of the lab driver script.
func labDriver(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "frr", "10.7.0", "lab", "run5.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// newLabScratch makes a SCRATCH directory named name, holding the fake FRR root. The
// name may hold spaces and shell metacharacters, and the directory lies in its own
// temporary parent.
func newLabScratch(t *testing.T, name string) string {
	t.Helper()
	s := filepath.Join(t.TempDir(), name)
	frr := filepath.Join(s, "frr-root", "usr", "libexec", "frr")
	if err := os.MkdirAll(frr, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"zebra", "ospfd"} {
		if err := os.WriteFile(filepath.Join(frr, d), []byte("#!/bin/sh\n"+fakeDaemon), 0o755); err != nil { //nolint:gosec // G306: the shim must be executable to run; it lives in t.TempDir.
			t.Fatal(err)
		}
	}
	return s
}

// labRun is one run of the driver under the shims.
type labRun struct {
	stdout, stderr string
	code           int
	mock           []string // every shim call, one per line, in order
}

// runLab runs the driver for mode in scratch, with the shims first on PATH and the
// faults given as MOCK_ settings. Any daemon the run starts is killed at cleanup.
func runLab(t *testing.T, scratch, mode string, faults ...string) labRun {
	t.Helper()
	return runScript(t, labDriver(t), scratch, mode, faults...)
}

// runScript is runLab for the driver at script.
func runScript(t *testing.T, script, scratch, mode string, faults ...string) labRun {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range labShims {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil { //nolint:gosec // G306: the shim must be executable to run; it lives in t.TempDir.
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(t.TempDir(), "mock.log")
	env := append([]string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"SCRATCH=" + scratch,
		"MOCK_LOG=" + logPath,
		"REAL_SLEEP=" + lookPath(t, "sleep"),
		"REAL_MKDIR=" + lookPath(t, "mkdir"),
	}, faults...)
	t.Cleanup(func() { killRecordedPIDs(scratch, logPath) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", script, mode) //nolint:gosec // G204: script is the lab driver the test located, and mode is a fixed test value.
	cmd.Dir = filepath.Dir(scratch)
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 10 * time.Second
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run driver: %v", err)
		}
		code = ee.ExitCode()
	}
	raw, _ := os.ReadFile(logPath) //nolint:gosec // G304: logPath is a file this test created under t.TempDir.
	return labRun{stdout: out.String(), stderr: errb.String(), code: code, mock: strings.Split(strings.TrimSpace(string(raw)), "\n")}
}

// lookPath returns the path of a real command, so a shim can call it.
func lookPath(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// killRecordedPIDs kills the daemons and sleeps a run left under scratch, so no fake
// daemon outlives its test. A pid is killed only while its process still carries this
// run's MOCK_LOG, since a pid that was reused belongs to something else. Failures are
// ignored, since most pids are already gone.
func killRecordedPIDs(scratch, logPath string) {
	_ = filepath.WalkDir(scratch, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".pid" {
			return nil
		}
		if pid, ok := pidOf(p); ok && ownedByRun(pid, logPath) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		return nil
	})
}

// ownedByRun reports whether pid runs with this run's MOCK_LOG in its environment. The
// fake daemons and their sleeps inherit it, and a process from anywhere else does not.
func ownedByRun(pid int, logPath string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return false
	}
	return slices.Contains(strings.Split(string(b), "\x00"), "MOCK_LOG="+logPath)
}

// pidOf reads the pid a daemon wrote to path.
func pidOf(path string) (int, bool) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is a pid file the test wrote under its scratch dir.
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid, err == nil && pid > 0
}

// reaped reports whether pid no longer runs. A zombie counts as gone.
func reaped(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	i := bytes.LastIndexByte(b, ')')
	return i >= 0 && len(b) > i+2 && b[i+2] == 'Z'
}

// startSacrificial starts a process the driver must never signal. env, when given,
// is added to this process's environment. It returns the pid and a channel that closes
// once the process is reaped.
func startSacrificial(t *testing.T, env ...string) (int, <-chan struct{}) {
	t.Helper()
	cmd := exec.Command(lookPath(t, "sleep"), "600") //nolint:gosec // G204: a fixed sleep binary and argument, the sacrificial process under test.
	cmd.Env = append(os.Environ(), env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	return cmd.Process.Pid, done
}

// alive reports whether a sacrificial process still runs, after a short grace.
func alive(done <-chan struct{}) bool {
	select {
	case <-done:
		return false
	case <-time.After(300 * time.Millisecond):
		return true
	}
}

// nonBlankLines returns the lines of b that hold text, trimmed.
func nonBlankLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// hasCall reports whether a shim log line starts with prefix.
func hasCall(calls []string, prefix string) bool {
	return slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, prefix) })
}

// countCalls counts the shim log lines that start with prefix.
func countCalls(calls []string, prefix string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// mustNotFinish requires a failed run: nonzero, no DONE marker, and the error named.
func mustNotFinish(t *testing.T, r labRun, why string) {
	t.Helper()
	if r.code == 0 {
		t.Errorf("%s: exit 0, want nonzero", why)
	}
	if strings.Contains(r.stdout, "DONE") {
		t.Errorf("%s: printed DONE after a failure", why)
	}
}

// TestLabDriverRejectsModeBeforeTouchingFiles gives the driver modes outside its
// allowlist, one of them a path that would escape the run directory. Each must exit 2
// before any mount, copy, or removal, so a directory the traversal names survives.
func TestLabDriverRejectsModeBeforeTouchingFiles(t *testing.T) {
	for _, mode := range []string{"", "../victim", "bcast/../victim", "bcast;touch x", "nosuch", "bcast "} {
		t.Run(fmt.Sprintf("%q", mode), func(t *testing.T) {
			s := newLabScratch(t, "scratch")
			victim := filepath.Join(s, "victim")
			if err := os.MkdirAll(victim, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := runLab(t, s, mode)
			if r.code != 2 {
				t.Errorf("exit %d, want 2; stderr %q", r.code, r.stderr)
			}
			if len(r.mock) != 1 || r.mock[0] != "" {
				t.Errorf("shims ran for a rejected mode: %q", r.mock)
			}
			if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
				t.Errorf("file outside the run directory was removed: %v", err)
			}
			if _, err := os.Stat(filepath.Join(s, "run")); err == nil {
				t.Errorf("run directory was created for a rejected mode")
			}
		})
	}
}

// TestLabDriverScratchMetacharactersAreData puts a command substitution in the SCRATCH
// path. The path is data, so the substitution must not run. The run itself succeeds.
func TestLabDriverScratchMetacharactersAreData(t *testing.T) {
	s := newLabScratch(t, "with space $(touch MARK)")
	r := runLab(t, s, "bcast")
	if _, err := os.Stat(filepath.Join(filepath.Dir(s), "MARK")); err == nil {
		t.Errorf("a command substitution in SCRATCH ran")
	}
	if r.code != 0 || !strings.Contains(r.stdout, "DONE") {
		t.Errorf("exit %d, want a finished run; stderr %q", r.code, r.stderr)
	}
}

// TestLabDriverFailedMountStartsNothing fails the first mount. The driver must stop
// before it starts any daemon or runs any capture.
func TestLabDriverFailedMountStartsNothing(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLab(t, s, "bcast", "MOCK_MOUNT_FAIL=1")
	mustNotFinish(t, r, "failed mount")
	if hasCall(r.mock, "zebra ") || hasCall(r.mock, "ospfd ") || hasCall(r.mock, "vty ") {
		t.Errorf("daemons or captures ran after a failed mount: %q", r.mock)
	}
}

// TestLabDriverFailedClearLeavesStalePIDAlone makes the clear of the old run fail,
// with a stale pid file from that run left behind. The driver must fail before it
// signals anything, so the sacrificial process named by the stale file survives.
func TestLabDriverFailedClearLeavesStalePIDAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the clear cannot fail")
	}
	s := newLabScratch(t, "scratch")
	pid, done := startSacrificial(t)
	r1 := filepath.Join(s, "run", "bcast", "r1")
	if err := os.MkdirAll(r1, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r1, "stale.pid"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r1, 0o500); err != nil { //nolint:gosec // G302: the test makes this directory unwritable so the driver clear fails; it is under t.TempDir.
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r1, 0o700) }) //nolint:gosec // G302: restores write access so t.TempDir cleanup succeeds.
	r := runLab(t, s, "bcast")
	mustNotFinish(t, r, "failed clear")
	if !alive(done) {
		t.Errorf("a failed clear signaled the stale pid %d", pid)
	}
}

// TestLabDriverFailedCaptureIsNotMarked fails the route capture of r1. The driver must
// keep the output as .raw.failed, write no .collected_at for it, and stop.
func TestLabDriverFailedCaptureIsNotMarked(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLab(t, s, "bcast", "MOCK_VTY_FAIL=route json")
	mustNotFinish(t, r, "failed capture")
	meta := filepath.Join(s, "run", "bcast", "meta")
	if _, err := os.Stat(filepath.Join(meta, "r1-show_ip_ospf_route_json.collected_at")); err == nil {
		t.Errorf("failed capture left a .collected_at marker")
	}
	if _, err := os.Stat(filepath.Join(s, "run", "bcast", "r1-show_ip_ospf_route_json.raw.failed")); err != nil {
		t.Errorf("failed capture kept no .raw.failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(meta, "r1-show_ip_ospf_neighbor_detail_json.collected_at")); err != nil {
		t.Errorf("an earlier good capture lost its marker: %v", err)
	}
}

// TestLabDriverTimeoutFailsTheCapture makes every vty call time out. The first capture
// must fail, leave no marker, and stop the run.
func TestLabDriverTimeoutFailsTheCapture(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLab(t, s, "bcast", "MOCK_TIMEOUT=1")
	mustNotFinish(t, r, "timeout")
	if _, err := os.Stat(filepath.Join(s, "run", "bcast", "meta", "r1-show_ip_ospf_neighbor_detail_json.collected_at")); err == nil {
		t.Errorf("timed out capture left a .collected_at marker")
	}
	if n := countCalls(r.mock, "timeout "); n != 1 {
		t.Errorf("%d capture attempts after a timeout, want the run to stop at 1", n)
	}
}

// TestLabDriverDaemonStartupFailureStopsAndCleansUp makes ospfd fail to start after
// zebra started. The driver must stop, name the failure, and kill the zebra it started.
func TestLabDriverDaemonStartupFailureStopsAndCleansUp(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLab(t, s, "bcast", "MOCK_DAEMON_FAIL=ospfd")
	mustNotFinish(t, r, "daemon startup failure")
	if !strings.Contains(r.stderr, "daemons did not start") {
		t.Errorf("stderr %q does not name the daemon failure", r.stderr)
	}
	if hasCall(r.mock, "vty ") {
		t.Errorf("captures ran after a daemon failed to start")
	}
	pid, ok := pidOf(filepath.Join(s, "run", "bcast", "r1", "zebra.pid"))
	if !ok {
		t.Fatalf("zebra started no pid file")
	}
	// The driver kills zebra before it exits, but the signal lands asynchronously, so
	// wait a bounded time for the process to be reaped before calling it still running.
	for deadline := time.Now().Add(2 * time.Second); !reaped(pid) && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	if !reaped(pid) {
		t.Errorf("zebra pid %d still runs after the failed start", pid)
	}
}

// TestLabDriverHappyPathKeepsTheLabConfig runs every mode with no fault. Each run must
// finish, and each generated ospfd.conf must hold the same non-blank lines as the one
// committed beside the capture. The generator writes blank lines that the committed
// files do not hold, so blank lines are not compared.
func TestLabDriverHappyPathKeepsTheLabConfig(t *testing.T) {
	modes := []string{"bcast", "p2p", "mtu", "empty", "nbma", "noinst", "area", "secondary", "secp1", "secp2", "passive1", "cost50", "mixp2p", "down1"}
	lab := filepath.Join("..", "..", "testdata", "frr", "10.7.0")
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			s := newLabScratch(t, "scratch")
			r := runLab(t, s, mode)
			if r.code != 0 || !strings.Contains(r.stdout, "DONE") {
				t.Fatalf("exit %d, want a finished run; stderr %q", r.code, r.stderr)
			}
			for _, node := range []string{"r1", "r2"} {
				committed, err := os.ReadFile(filepath.Join(lab, mode, node+"-ospfd.conf")) //nolint:gosec // G304: a committed fixture path built from fixed mode and node names.
				if err != nil {
					continue
				}
				got, err := os.ReadFile(filepath.Join(s, "run", mode, node, "ospfd.conf")) //nolint:gosec // G304: the scratch path this test created for the driver run.
				if err != nil {
					t.Fatalf("%s ospfd.conf not written: %v", node, err)
				}
				if g, c := nonBlankLines(got), nonBlankLines(committed); !slices.Equal(g, c) {
					t.Errorf("%s ospfd.conf differs from the committed lab config:\n%q\n--- committed\n%q", node, g, c)
				}
			}
		})
	}
}

// TestLabDriverDaemonArgvIsUnchanged checks the argv each daemon gets on the first
// node, which is what the lab has always run zebra and ospfd with.
func TestLabDriverDaemonArgvIsUnchanged(t *testing.T) {
	s := newLabScratch(t, "scratch")
	r := runLab(t, s, "bcast")
	d := filepath.Join(s, "run", "bcast", "r1")
	sock := "/run/frr/r1"
	wantZebra := fmt.Sprintf("zebra [-d] [-f] [%s/zebra.conf] [-i] [%s/zebra.pid] [-z] [%s/zserv.api] [--vty_socket] [%s] [-u] [root] [-g] [root]", d, d, sock, sock)
	wantOSPFD := fmt.Sprintf("ospfd [-d] [-f] [%s/ospfd.conf] [-i] [%s/ospfd.pid] [-z] [%s/zserv.api] [--vty_socket] [%s] [-u] [root] [-g] [root]", d, d, sock, sock)
	for _, want := range []string{wantZebra, wantOSPFD} {
		if !slices.Contains(r.mock, want) {
			t.Errorf("no daemon call %q in the log", want)
		}
	}
}

// TestKillRecordedPIDsSparesAForeignProcess writes two pid files. One names a process
// that carries this run's MOCK_LOG, and the other a process that does not, as a reused
// pid would. Cleanup must kill the first and leave the second running.
func TestKillRecordedPIDsSparesAForeignProcess(t *testing.T) {
	scratch := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "mock.log")
	owned, ownedDone := startSacrificial(t, "MOCK_LOG="+logPath)
	foreign, foreignDone := startSacrificial(t, "MOCK_LOG="+filepath.Join(t.TempDir(), "other.log"))
	for name, pid := range map[string]int{"owned": owned, "foreign": foreign} {
		dir := filepath.Join(scratch, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "zebra.pid"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	killRecordedPIDs(scratch, logPath)
	select {
	case <-ownedDone:
	case <-time.After(2 * time.Second):
		t.Errorf("the run's own pid %d survived cleanup", owned)
	}
	if !alive(foreignDone) {
		t.Errorf("cleanup killed pid %d, which does not carry this run's MOCK_LOG", foreign)
	}
}
