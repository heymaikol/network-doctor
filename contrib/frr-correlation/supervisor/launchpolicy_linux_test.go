//go:build linux && netns_integration

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests run testdata/launch-policy.sh against harmless stand-ins. They
// never touch FRR, a certified artifact or an evidence archive: the stage they
// build holds symlinks to this test binary and a shell script.
//
// The script starts "$STAGE/usr/libexec/frr/zebra" and ".../bgpd" under an
// empty environment, so the test binary cannot be told what to do through
// SUPERVISOR_HELPER. TestMain instead recognises the name in argv[0] and calls
// mockDaemon, which reads its mode from a file in HOME, the one variable the
// script passes through (it is the script's OUT directory).

const launchPolicyScript = "testdata/launch-policy.sh"

// launchPolicyHostNeeds is the part of the script that depends on the host: the
// three tmpfs mounts, made in the private mount namespace the probe runs in.
const launchPolicyHostNeeds = "mount -t tmpfs tmpfs /run && mount -t tmpfs tmpfs /var/lib && mount -t tmpfs tmpfs /var/tmp"

// mockDaemon never returns. It fails closed: without its mode file it exits at
// once, so a run that reaches it by mistake cannot start the whole test suite.
func mockDaemon(name string) {
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, name+": "+format+"\n", args...)
		os.Exit(2)
	}
	home := os.Getenv("HOME")
	mode, err := os.ReadFile(filepath.Join(home, name+".mode")) //nolint:gosec // G304: HOME is the script's OUT directory inside this test's TempDir.
	if err != nil {
		fail("no mode file, refusing to run: %v", err)
	}
	switch strings.TrimSpace(string(mode)) {
	case "term": // the default action for SIGTERM ends the process
	case "exit-soon": // ends by itself, as a daemon that crashed would, before the script stops it
		go func() {
			time.Sleep(500 * time.Millisecond)
			os.Exit(7)
		}()
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
	case "note-term": // survives SIGTERM and says it arrived, so a test can act on the script's stop phase
		got := make(chan os.Signal, 1)
		signal.Notify(got, syscall.SIGTERM)
		go func() {
			for range got {
				_ = os.WriteFile(filepath.Join(home, name+".termed"), []byte("termed"), 0o600) //nolint:gosec // G703: HOME is the script's OUT directory inside this test's TempDir.
			}
		}()
	default:
		fail("unknown mode %q", mode)
	}
	var ln net.Listener
	if name == "zebra" { // the script waits for zebra's API socket, whose path follows -z
		for i, a := range os.Args {
			if a == "-z" && i+1 < len(os.Args) {
				if ln, err = net.Listen("unix", os.Args[i+1]); err != nil {
					fail("listen: %v", err)
				}
			}
		}
	}
	// The pid file comes last: once it exists, the mode and the socket are in place.
	_ = os.WriteFile(filepath.Join(home, name+".pid"), []byte(strconv.Itoa(os.Getpid())), 0o600) //nolint:gosec // G703: HOME is the script's OUT directory inside this test's TempDir.
	time.Sleep(time.Minute)                                                                      // a mock nobody stopped ends by itself
	runtime.KeepAlive(ln)
	os.Exit(3)
}

// newMockStage lays out what the script expects under STAGE and returns that
// directory and the OUT directory.
func newMockStage(t *testing.T, zebraMode, bgpdMode, vtysh string) (stage, out string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	stage, out = filepath.Join(root, "stage"), filepath.Join(root, "out")
	frr, bin := filepath.Join(stage, "usr", "libexec", "frr"), filepath.Join(stage, "usr", "bin")
	for _, d := range []string{frr, bin, out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, mode := range map[string]string{"zebra": zebraMode, "bgpd": bgpdMode} {
		if err := os.Symlink(self, filepath.Join(frr, name)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name+".mode"), []byte(mode), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "vtysh"), []byte("#!/bin/sh\n"+vtysh+"\n"), 0o700); err != nil { //nolint:gosec // G306: the stand-in vtysh must be executable.
		t.Fatal(err)
	}
	t.Cleanup(func() { killMocks(out, self) })
	return stage, out
}

// killMocks ends any stand-in a failed test left behind. It signals a PID only
// while that PID is still this test binary, so a reused PID is never hit.
func killMocks(out, self string) {
	for _, name := range []string{"zebra", "bgpd"} {
		b, err := os.ReadFile(filepath.Join(out, name+".pid")) //nolint:gosec // G304: a file in this test's own TempDir.
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(string(b))
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && exe == self {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// vtyshAttached answers the way zebra does when bgpd has attached.
const vtyshAttached = `echo "Client: bgp"`

// vtyshHangs never answers. The stand-in is bounded by exec'ing sleep with an
// absolute path (the script clears PATH) and a short life of its own.
func vtyshHangs(t *testing.T) string {
	return execLine(lookPath(t, "sleep"), "30")
}

// execLine is a shell line that replaces the shell with the program at path. The
// path is quoted, so it stays one word whatever characters it holds.
func execLine(path, arg string) string {
	return "exec " + shellQuote(path) + " " + arg
}

// shellQuote is path as one shell word, whatever characters it holds.
func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

type policyRun struct {
	cmd *exec.Cmd
	ctx context.Context
	out *bytes.Buffer
}

// startLaunchPolicy runs the script as its header documents, under unshare
// -Urnm, with short bounds so that a run takes seconds. The run is itself
// bounded: past the deadline its process group is killed and the test fails, so
// a script that hangs cannot hang the suite.
func startLaunchPolicy(t *testing.T, stage, out string, extraEnv ...string) policyRun {
	t.Helper()
	unshare, bash := lookPath(t, "unshare"), lookPath(t, "bash")
	lookPath(t, "setpriv")
	lookPath(t, "timeout")
	lookPath(t, "mount")
	// The script needs rootless user, network and mount namespaces and the three
	// tmpfs mounts. A host that refuses them ends the test through unavailable,
	// which is a skip, or a failure where NETDOC_SIM_REQUIRE_NETNS demands the
	// namespace tests. A probe that fails any other way is a failure.
	probeCtx, stopProbe := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopProbe()
	refusal, err := hostRefusal(probeCtx, unshare, "-Urnm", bash, "-c", launchPolicyHostNeeds)
	if err != nil {
		t.Fatal(err)
	}
	if refusal != "" {
		unavailable(t, "launch-policy.sh needs user, network and mount namespaces with tmpfs: %s", refusal)
	}
	script, err := filepath.Abs(launchPolicyScript)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, unshare, "-Urnm", bash, script, "policy") //nolint:gosec // G204: the binaries come from LookPath and the script is this package's own testdata.
	cmd.Env = append(os.Environ(), "STAGE="+stage, "OUT="+out, "STOP_GRACE=1", "QUERY_TIMEOUT=1")
	for _, e := range extraEnv { // "-NAME" removes NAME, so a test can leave a setting unset
		if name, drop := strings.CutPrefix(e, "-"); drop {
			cmd.Env = slices.DeleteFunc(cmd.Env, func(v string) bool { return strings.HasPrefix(v, name+"=") })
		} else {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return policyRun{cmd: cmd, ctx: ctx, out: &buf}
}

// wait returns the script's output and exit code once it has ended.
func (r policyRun) wait(t *testing.T) (string, int) {
	t.Helper()
	err := r.cmd.Wait()
	if r.ctx.Err() != nil {
		t.Fatalf("the script did not finish in time and was killed:\n%s", r.out)
	}
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return r.out.String(), r.cmd.ProcessState.ExitCode()
}

func requireLines(t *testing.T, text string, want ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, l := range strings.Split(text, "\n") {
		have[l] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("no line %q in the output:\n%s", w, text)
		}
	}
}

// noneAlive requires that no stand-in daemon is left running once the script is gone.
func noneAlive(t *testing.T, out string) {
	t.Helper()
	for _, name := range []string{"zebra", "bgpd"} {
		b, err := os.ReadFile(filepath.Join(out, name+".pid")) //nolint:gosec // G304: a file in this test's own TempDir.
		if err != nil {
			t.Errorf("%s never started: %v", name, err)
			continue
		}
		pid, _ := strconv.Atoi(string(b))
		for i := 0; alive(pid) && i < 50; i++ {
			time.Sleep(40 * time.Millisecond)
		}
		if alive(pid) {
			t.Errorf("%s (pid %d) is still running after the script ended", name, pid)
		}
	}
}

// The control: nothing is stuck, so the output keeps the shape it had before the
// script was bounded, and both daemons are stopped by SIGTERM alone.
// Only an unset setting takes its default. An empty one is refused (see the table below).
func TestLaunchPolicyUnsetSettingsTakeTheirDefaults(t *testing.T) {
	stage, out := newMockStage(t, "term", "term", vtyshAttached)
	text, code := startLaunchPolicy(t, stage, out, "-STOP_GRACE", "-QUERY_TIMEOUT").wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text, "  alive: zebra bgpd", "  bgpd attached to zebra: yes", "  bgpd exit: 143", "  zebra exit: 143")
	noneAlive(t, out)
}

func TestLaunchPolicyControlStopsBothDaemonsWithSIGTERM(t *testing.T) {
	stage, out := newMockStage(t, "term", "term", vtyshAttached)
	text, code := startLaunchPolicy(t, stage, out).wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text, "  alive: zebra bgpd", "  bgpd attached to zebra: yes", "  bgpd exit: 143", "  zebra exit: 143")
	if strings.Contains(text, "timed out") || strings.Contains(text, "SIGKILL") {
		t.Errorf("the control reported a timeout or an escalation:\n%s", text)
	}
	noneAlive(t, out)
}

// A vtysh that never answers must not hold the script, and a daemon that ignores
// SIGTERM must be killed after the grace period instead of waited for forever.
func TestLaunchPolicyBoundsAStuckQueryAndAnIgnoredSIGTERM(t *testing.T) {
	stage, out := newMockStage(t, "term", "ignore-term", vtyshHangs(t))
	text, code := startLaunchPolicy(t, stage, out).wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text,
		"  bgpd attached to zebra: no",
		"  vtysh query: timed out after 1s",
		"  bgpd exit: 137",
		"  bgpd stop: SIGKILL after 1s",
		"  zebra exit: 143")
	noneAlive(t, out)
}

// timeout reports 124 when its own deadline ended the command, and 137 when the
// command died of SIGKILL. A 137 does not say who sent the signal: the OOM killer
// and a person look the same, and so does timeout's own escalation after a command
// that ignored SIGTERM. The script reports it as SIGKILL with the cause open, and
// never as a timeout.
func TestLaunchPolicyReportsAKilledQueryApartFromATimeout(t *testing.T) {
	sleep := lookPath(t, "sleep")
	for _, tc := range []struct{ name, vtysh string }{
		{"killed from outside", "kill -KILL $$"},
		{"ignored SIGTERM until timeout escalated", "trap '' TERM; " + execLine(sleep, "30")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, out := newMockStage(t, "term", "term", tc.vtysh)
			text, code := startLaunchPolicy(t, stage, out).wait(t)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, text)
			}
			requireLines(t, text, "  bgpd attached to zebra: no", "  vtysh query: ended by SIGKILL (status 137), cause not confirmed", "  bgpd exit: 143", "  zebra exit: 143")
			if strings.Contains(text, "timed out") {
				t.Errorf("a SIGKILL was reported as a timeout:\n%s", text)
			}
			noneAlive(t, out)
		})
	}
}

// An interrupt while the daemons run must stop both of them, including one that
// survives SIGTERM, and must not leave either behind. A second interrupt that
// arrives while the script is already stopping them, as a user pressing Ctrl-C
// twice would send, must not cut that work short.
func TestLaunchPolicyStopsBothDaemonsWhenInterrupted(t *testing.T) {
	stage, out := newMockStage(t, "term", "note-term", vtyshAttached)
	run := startLaunchPolicy(t, stage, out)
	waitFile(t, filepath.Join(out, "zebra.pid"))
	waitFile(t, filepath.Join(out, "bgpd.pid"))
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitFile(t, filepath.Join(out, "bgpd.termed")) // the script is now waiting out bgpd's grace period
	if err := run.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	text, code := run.wait(t)
	if code != 143 {
		t.Fatalf("exit %d, want 143:\n%s", code, text)
	}
	requireLines(t, text, "  bgpd exit: 137", "  bgpd stop: SIGKILL after 1s", "  zebra exit: 143")
	noneAlive(t, out)
}

// The script mounts tmpfs over /run, /var/lib and /var/tmp, which hides anything
// there, and its waits are whole seconds from 1 to 60: a larger number is not an
// operational bound, and one past 18 digits overflows the shell's arithmetic.
// It refuses all of these before it mounts or starts anything.
func TestLaunchPolicyRefusesUnusableSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  func(out string) []string
		want string
	}{
		{"output under /var/tmp", func(string) []string { return []string{"OUT=/var/tmp/launch-policy-test"} }, "hidden"},
		{"stage under /run", func(string) []string { return []string{"STAGE=/run/launch-policy-test"} }, "hidden"},
		{"grace is not a number", func(string) []string { return []string{"STOP_GRACE=soon"} }, "STOP_GRACE"},
		{"query bound is not a number", func(string) []string { return []string{"QUERY_TIMEOUT=-1"} }, "QUERY_TIMEOUT"},
		{"grace is empty", func(string) []string { return []string{"STOP_GRACE="} }, "STOP_GRACE"},
		{"query bound is empty", func(string) []string { return []string{"QUERY_TIMEOUT="} }, "QUERY_TIMEOUT"},
		{"grace is zero", func(string) []string { return []string{"STOP_GRACE=0"} }, "STOP_GRACE"},
		{"grace is one past the limit", func(string) []string { return []string{"STOP_GRACE=61"} }, "STOP_GRACE"},
		{"grace has three digits", func(string) []string { return []string{"STOP_GRACE=100"} }, "STOP_GRACE"},
		{"grace overflows the arithmetic", func(string) []string { return []string{"STOP_GRACE=1000000000000000000"} }, "STOP_GRACE"},
		{"grace has twenty digits", func(string) []string { return []string{"STOP_GRACE=99999999999999999999"} }, "STOP_GRACE"},
		{"grace has a leading zero", func(string) []string { return []string{"STOP_GRACE=05"} }, "STOP_GRACE"},
		{"grace has a fraction", func(string) []string { return []string{"STOP_GRACE=1.5"} }, "STOP_GRACE"},
		{"grace has a space", func(string) []string { return []string{"STOP_GRACE= 5"} }, "STOP_GRACE"},
		{"grace has a trailing newline", func(string) []string { return []string{"STOP_GRACE=5\n"} }, "STOP_GRACE"},
		{"query bound is zero", func(string) []string { return []string{"QUERY_TIMEOUT=0"} }, "QUERY_TIMEOUT"},
		{"query bound is one past the limit", func(string) []string { return []string{"QUERY_TIMEOUT=61"} }, "QUERY_TIMEOUT"},
		{"query bound overflows the arithmetic", func(string) []string { return []string{"QUERY_TIMEOUT=1000000000000000000"} }, "QUERY_TIMEOUT"},
		{"query bound has twenty digits", func(string) []string { return []string{"QUERY_TIMEOUT=99999999999999999999"} }, "QUERY_TIMEOUT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage, out := newMockStage(t, "term", "term", vtyshAttached)
			text, code := startLaunchPolicy(t, stage, out, tc.env(out)...).wait(t)
			if code != 9 || !strings.Contains(text, tc.want) {
				t.Fatalf("exit %d, want 9 and a message naming %q:\n%s", code, tc.want, text)
			}
			if _, err := os.Stat(filepath.Join(out, "zebra.pid")); err == nil {
				t.Fatal("a daemon started although the settings were refused")
			}
		})
	}
}

// The limit itself is allowed, so the bound is not off by one.
func TestLaunchPolicyAcceptsTheLargestSettings(t *testing.T) {
	stage, out := newMockStage(t, "term", "term", vtyshAttached)
	text, code := startLaunchPolicy(t, stage, out, "STOP_GRACE=60", "QUERY_TIMEOUT=60").wait(t)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, text)
	}
	requireLines(t, text, "  bgpd exit: 143", "  zebra exit: 143")
	noneAlive(t, out)
}
