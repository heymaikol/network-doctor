//go:build linux && netns_integration

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// killShim is loaded into the script through BASH_ENV. It wraps the kill builtin
// to log every call, and to drop SIGKILL aimed at the process whose PID is in
// SURVIVOR_PIDFILE. That simulates a process that survives SIGKILL, which a test
// cannot make for real: the kernel ends a process in uninterruptible sleep only
// when the sleep ends. The script's own check of /proc is untouched, except where
// a test asks the shim to break procfs, which is the one way to make the script's
// reads of /proc fail on demand:
//   - FAULT_ALL_PROC covers /proc with an empty tmpfs once the vtysh query has run.
//   - FAULT_PIDFILE names the daemon whose /proc/PID is covered with an empty tmpfs at the
//     first SIGTERM sent to it. FAULT_KIND=directory also makes stat a directory, so reading
//     it fails with EISDIR instead of ENOENT.
//
// The mount is real and the daemon is untouched, so the script sees a running daemon whose
// /proc entry cannot be read.
const killShim = `timeout() {
  command timeout "$@"
  local rc=$?
  [[ -z ${FAULT_ALL_PROC:-} ]] || mount -t tmpfs tmpfs /proc
  return $rc
}
break_proc() {
  mount -t tmpfs tmpfs "/proc/$1" || return
  [[ ${FAULT_KIND:-} != directory ]] || mkdir "/proc/$1/stat"
}
kill() {
  local a
  [[ -z ${KILL_LOG:-} ]] || echo "kill $*" >> "$KILL_LOG"
  if [[ $1 == -TERM && -n ${FAULT_PIDFILE:-} ]]; then
    for a in "${@:2}"; do [[ $a == "$(< "$FAULT_PIDFILE")" ]] && break_proc "$a"; done
  fi
  if [[ $1 == -KILL && -n ${SURVIVOR_PIDFILE:-} ]]; then
    for a in "${@:2}"; do [[ $a == "$(< "$SURVIVOR_PIDFILE")" ]] && return 0; done
  fi
  builtin kill "$@"
}
`

// shimEnv writes killShim and returns the environment that loads it, plus the
// log of every kill the script makes. A non-empty survivor names the daemon whose
// SIGKILL is dropped.
func shimEnv(t *testing.T, out, survivor string) (env []string, killLog string) {
	t.Helper()
	dir := t.TempDir()
	shim, killLog := filepath.Join(dir, "shim.sh"), filepath.Join(dir, "kills")
	if err := os.WriteFile(shim, []byte(killShim), 0o600); err != nil {
		t.Fatal(err)
	}
	env = []string{"BASH_ENV=" + shim, "KILL_LOG=" + killLog}
	if survivor != "" {
		env = append(env, "SURVIVOR_PIDFILE="+filepath.Join(out, survivor+".pid"))
	}
	return env, killLog
}

func pidOf(t *testing.T, out, name string) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, name+".pid")) //nolint:gosec // G304: a file in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// A daemon that is still running after SIGKILL cannot be stopped by a script. The
// script must say so on stderr and exit 10 instead of claiming a clean stop, keep
// the daemon's PID so the exit trap tries once more, and still stop the other one.
func TestLaunchPolicyReportsADaemonItCannotStop(t *testing.T) {
	stage, out := newMockStage(t, "term", "ignore-term", vtyshAttached)
	env, _ := shimEnv(t, out, "bgpd")
	text, code := startLaunchPolicy(t, stage, out, env...).wait(t)
	pid := pidOf(t, out, "bgpd")
	if code != 10 {
		t.Fatalf("exit %d, want 10:\n%s", code, text)
	}
	requireLines(t, text,
		"  bgpd stop: still running after SIGKILL, not waited for",
		"  zebra exit: 143",
		fmt.Sprintf("launch-policy: bgpd (pid %d) may still be running", pid))
	if strings.Contains(text, "launch-policy: zebra") {
		t.Errorf("zebra was stopped but is reported as running:\n%s", text)
	}
	// The normal stop and the exit trap each give bgpd SIGTERM, the grace period and SIGKILL.
	if n := strings.Count(text, "  bgpd stop: SIGKILL after 1s\n"); n != 2 {
		t.Errorf("bgpd was stopped %d times, want 2 (the stop and one retry by the exit trap):\n%s", n, text)
	}
	if !alive(pid) {
		t.Errorf("bgpd (pid %d) is gone, so the report is not about a survivor:\n%s", pid, text)
	}
	zebra := pidOf(t, out, "zebra")
	for i := 0; alive(zebra) && i < 50; i++ {
		time.Sleep(40 * time.Millisecond)
	}
	if alive(zebra) {
		t.Errorf("zebra (pid %d) is still running", zebra)
	}
}

// An interrupt ends with the status of the failed cleanup, not the signal's: 10
// is the only status that tells the caller a daemon may still be running.
func TestLaunchPolicyReportsAnUnstoppableDaemonAfterAnInterrupt(t *testing.T) {
	stage, out := newMockStage(t, "term", "ignore-term", vtyshAttached)
	env, _ := shimEnv(t, out, "bgpd")
	run := startLaunchPolicy(t, stage, out, env...)
	waitFile(t, filepath.Join(out, "zebra.pid"))
	waitFile(t, filepath.Join(out, "bgpd.pid"))
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	text, code := run.wait(t)
	if code != 10 {
		t.Fatalf("exit %d, want 10:\n%s", code, text)
	}
	requireLines(t, text, "  zebra exit: 143", fmt.Sprintf("launch-policy: bgpd (pid %d) may still be running", pidOf(t, out, "bgpd")))
}

// A daemon that ended on its own and was reaped is no longer the script's: its PID
// may belong to someone else by now. The script must not signal it.
func TestLaunchPolicyDoesNotSignalADaemonThatAlreadyExited(t *testing.T) {
	stage, out := newMockStage(t, "term", "exit-soon", vtyshAttached)
	env, killLog := shimEnv(t, out, "")
	text, code := startLaunchPolicy(t, stage, out, env...).wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text, "  alive: zebra", "  bgpd exit: 7", "  zebra exit: 143")
	log, err := os.ReadFile(killLog) //nolint:gosec // G304: a file in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(pidOf(t, out, "bgpd"))
	for _, l := range strings.Split(string(log), "\n") {
		if f := strings.Fields(l); len(f) > 2 && (f[1] == "-TERM" || f[1] == "-KILL") && strings.Contains(l, " "+pid) {
			t.Errorf("the script signalled pid %s after it had exited: %q", pid, l)
		}
	}
}

// signalled reports whether the script's kill log holds a call that sends sig to pid.
func signalled(t *testing.T, killLog, sig string, pid int) bool {
	t.Helper()
	log, err := os.ReadFile(killLog) //nolint:gosec // G304: a file in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(log), "\n") {
		if f := strings.Fields(l); len(f) > 2 && f[1] == sig && slices.Contains(f[2:], strconv.Itoa(pid)) {
			return true
		}
	}
	return false
}

// Without /proc the script cannot tell a running daemon from a gone one. Treating
// the daemon as gone skips both signals and then blocks in wait on a daemon that is
// still running. The script must signal nothing, wait for nothing, and report both
// daemons as possibly running. bgpd ignores SIGTERM, so a wrong wait never returns.
func TestLaunchPolicyDoesNotAssumeAnUnreadableDaemonIsGone(t *testing.T) {
	stage, out := newMockStage(t, "term", "ignore-term", vtyshAttached)
	env, killLog := shimEnv(t, out, "")
	text, code := startLaunchPolicy(t, stage, out, append(env, "FAULT_ALL_PROC=1")...).wait(t)
	zebra, bgpd := pidOf(t, out, "zebra"), pidOf(t, out, "bgpd")
	if code != 10 {
		t.Fatalf("exit %d, want 10:\n%s", code, text)
	}
	requireLines(t, text,
		fmt.Sprintf("  zebra stop: cannot read the state of pid %d, not signalled and not waited for", zebra),
		fmt.Sprintf("  bgpd stop: cannot read the state of pid %d, not signalled and not waited for", bgpd),
		fmt.Sprintf("launch-policy: zebra (pid %d) may still be running", zebra),
		fmt.Sprintf("launch-policy: bgpd (pid %d) may still be running", bgpd))
	for _, pid := range []int{zebra, bgpd} {
		for _, sig := range []string{"-TERM", "-KILL"} {
			if signalled(t, killLog, sig, pid) {
				t.Errorf("the script sent %s to pid %d although it could not read its state:\n%s", sig, pid, text)
			}
		}
		if !alive(pid) {
			t.Errorf("pid %d is gone, so the report is not about a running daemon", pid)
		}
	}
}

// A daemon that was running when SIGTERM went out and whose state can no longer be
// read has not been shown to ignore it. The script must not escalate to SIGKILL, must
// not wait for it, and must report it as possibly running while the other daemon stops
// as usual. The retry by the exit trap sends nothing either.
func TestLaunchPolicyDoesNotKillADaemonItCannotObserveAfterTerm(t *testing.T) {
	stage, out := newMockStage(t, "term", "ignore-term", vtyshAttached)
	env, killLog := shimEnv(t, out, "")
	env = append(env, "FAULT_PIDFILE="+filepath.Join(out, "bgpd.pid"), "FAULT_KIND=directory")
	text, code := startLaunchPolicy(t, stage, out, env...).wait(t)
	bgpd := pidOf(t, out, "bgpd")
	if code != 10 {
		t.Fatalf("exit %d, want 10:\n%s", code, text)
	}
	requireLines(t, text,
		fmt.Sprintf("  bgpd stop: cannot read the state of pid %d after SIGTERM, not killed and not waited for", bgpd),
		fmt.Sprintf("  bgpd stop: cannot read the state of pid %d, not signalled and not waited for", bgpd),
		"  zebra exit: 143",
		fmt.Sprintf("launch-policy: bgpd (pid %d) may still be running", bgpd))
	if !signalled(t, killLog, "-TERM", bgpd) {
		t.Errorf("bgpd never received SIGTERM, so the fault was not injected after it:\n%s", text)
	}
	if signalled(t, killLog, "-KILL", bgpd) {
		t.Errorf("the script killed bgpd although it could not read its state:\n%s", text)
	}
	if !alive(bgpd) {
		t.Errorf("bgpd (pid %d) is gone, so the report is not about a running daemon", bgpd)
	}
}

// Losing the /proc entry does not hide a daemon that exited. kill -0 finds no process
// under the number, so the script waits for the exit status it already holds and prints
// the same line as when /proc works.
func TestLaunchPolicyStillReapsADaemonWhoseProcEntryDisappears(t *testing.T) {
	stage, out := newMockStage(t, "term", "term", vtyshAttached)
	env, killLog := shimEnv(t, out, "")
	env = append(env, "FAULT_PIDFILE="+filepath.Join(out, "bgpd.pid"), "FAULT_KIND=missing")
	text, code := startLaunchPolicy(t, stage, out, env...).wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text, "  bgpd exit: 143", "  zebra exit: 143")
	if signalled(t, killLog, "-KILL", pidOf(t, out, "bgpd")) {
		t.Errorf("the script killed a daemon that had already exited:\n%s", text)
	}
	noneAlive(t, out)
}
