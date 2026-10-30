//go:build linux && netns_integration

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
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
// when the sleep ends. The script's own check of /proc is untouched.
const killShim = `kill() {
  local a
  [[ -z ${KILL_LOG:-} ]] || echo "kill $*" >> "$KILL_LOG"
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
