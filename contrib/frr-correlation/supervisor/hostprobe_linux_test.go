//go:build linux && netns_integration

package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// refusedByHost reports whether the output of a failed namespace or mount
// command names one of the errors that mean this host does not allow it. The
// command must have run with LC_ALL=C: util-linux and the C library translate
// these messages. Matching text is the only evidence a shell command gives, so
// anything it does not recognise is not a refusal.
func refusedByHost(output string) bool {
	low := strings.ToLower(output)
	for _, e := range capabilityErrnos {
		if strings.Contains(low, strings.ToLower(e.Error())) {
			return true
		}
	}
	return false
}

// hostRefusal runs a command a test needs to know the host can run, and tells a
// host that refuses it from a probe that failed some other way. refusal is the
// command's output when it ended with a recognised refusal. err covers every
// other failure (a command that would not start, a deadline, an exit with
// unrecognised or no output), and a caller must fail on it: it says nothing
// about the host, so it must never turn into a skip.
func hostRefusal(ctx context.Context, argv ...string) (refusal string, err error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: the callers pass binaries from LookPath and constant arguments.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	// The probe gets its own process group, and ending it ends the whole group. Killing only
	// the shell would leave a child holding the output pipe, and Wait would block on the pipe.
	// WaitDelay bounds the wait for a process that left the group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = hostProbeWaitDelay
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	runErr := cmd.Start()
	if runErr == nil {
		pgid := cmd.Process.Pid
		runErr = cmd.Wait()
		_ = syscall.Kill(-pgid, syscall.SIGKILL) // whatever the probe left behind
	}
	text := strings.TrimSpace(out.String())
	var exit *exec.ExitError
	switch {
	case runErr == nil:
		return "", nil
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s did not finish: %w: %s", filepath.Base(argv[0]), ctx.Err(), text)
	case errors.As(runErr, &exit) && refusedByHost(text):
		return text, nil
	default:
		return "", fmt.Errorf("%s failed in a way that is not a host refusal: %w: %s", filepath.Base(argv[0]), runErr, text)
	}
}

// A probe that never finishes must end at the context deadline, and only that proves
// the deadline worked. The test checks that the shell reached the sleep, that the
// error wraps context.DeadlineExceeded, and that a shell which failed at once, as an
// unquoted path with a space does, is told apart from a timeout.
func TestHostRefusalEndsAProbeAtTheDeadline(t *testing.T) {
	dir := t.TempDir()
	spaced := filepath.Join(dir, "a b'c", "sleep")
	if err := os.MkdirAll(filepath.Dir(spaced), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lookPath(t, "sleep"), spaced); err != nil {
		t.Fatal(err)
	}
	// started records that the shell ran far enough to reach the sleep line.
	started := func(body string) string { return "echo started > \"$1\"\n" + body }
	for _, tc := range []struct {
		name         string
		body         string
		wantStarted  bool
		wantDeadline bool
	}{
		{"sleep on the search path", started(execLine(lookPath(t, "sleep"), "30")), true, true},
		{"sleep path with a space and a quote", started(execLine(spaced, "30")), true, true},
		{"the same path unquoted fails at once", started("exec " + spaced + " 30"), true, false},
		{"sleep that does not exist fails at once", started(execLine(filepath.Join(dir, "absent", "sleep"), "30")), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "started")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			refusal, err := hostRefusal(ctx, probeScript(t, dir, strings.ReplaceAll(tc.name, " ", "-"), tc.body), marker)
			if refusal != "" || err == nil {
				t.Fatalf("refusal %q, error %v; want an error", refusal, err)
			}
			if got := errors.Is(err, context.DeadlineExceeded); got != tc.wantDeadline {
				t.Errorf("error %v wraps DeadlineExceeded = %v, want %v", err, got, tc.wantDeadline)
			}
			if _, statErr := os.Stat(marker); (statErr == nil) != tc.wantStarted {
				t.Errorf("the shell started = %v, want %v", statErr == nil, tc.wantStarted)
			}
		})
	}
}

// hostProbeWaitDelay is how long hostRefusal waits for a probe's output pipe after
// the probe's own process is gone, before it closes the pipe and reports an error.
const hostProbeWaitDelay = 2 * time.Second

func TestRefusedByHostRecognisesOnlyCapabilityErrors(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"unshare: unshare failed: Operation not permitted", true},
		{"unshare: write failed /proc/self/uid_map: Operation not permitted", true},
		{"mount: /run: permission denied.", true},
		{"unshare: unshare failed: Invalid argument", true},
		{"unshare: unshare failed: No space left on device", true},
		{"unshare: unshare failed: Function not implemented", true},
		{"unshare: unshare failed: Resource temporarily unavailable", false},
		{"unshare: unshare failed: Cannot allocate memory", false},
		{"unshare: unshare failed: Too many open files", false},
		{"mount: /var/lib: mount point does not exist.", false},
		{"unshare: unrecognized option '-Urnm'", false},
		{"", false},
	} {
		if got := refusedByHost(tc.out); got != tc.want {
			t.Errorf("refusedByHost(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// A refusal may skip a test. Every other way a probe can fail must stay a
// failure, or a broken probe would hide a host that could have run the test.
func TestHostRefusalSeparatesARefusalFromAFailedProbe(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string { return probeScript(t, dir, name, body) }
	for _, tc := range []struct {
		name        string
		body        string
		timeout     time.Duration
		wantRefusal bool
		wantErr     bool
	}{
		{"succeeds", "exit 0", time.Second, false, false},
		{"namespace refused", `echo "unshare: unshare failed: Operation not permitted" >&2; exit 1`, time.Second, true, false},
		{"mount refused", `echo "mount: /run: permission denied." >&2; exit 32`, time.Second, true, false},
		{"unrecognised failure", `echo "unshare: unrecognized option '-Urnm'" >&2; exit 1`, time.Second, false, true},
		{"fails without saying why", "exit 1", time.Second, false, true},
		{"resource limit", `echo "unshare: unshare failed: Resource temporarily unavailable" >&2; exit 1`, time.Second, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			refusal, err := hostRefusal(ctx, script(strings.ReplaceAll(tc.name, " ", "-"), tc.body))
			if (refusal != "") != tc.wantRefusal || (err != nil) != tc.wantErr {
				t.Fatalf("refusal %q, error %v; want refusal %v, error %v", refusal, err, tc.wantRefusal, tc.wantErr)
			}
		})
	}
	t.Run("command that does not exist", func(t *testing.T) {
		refusal, err := hostRefusal(context.Background(), filepath.Join(dir, "absent"))
		if refusal != "" || err == nil {
			t.Fatalf("refusal %q, error %v; want an error", refusal, err)
		}
	})
}

// probeScript writes an executable stand-in for a probe command.
func probeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // G306: the stand-in must be executable.
		t.Fatal(err)
	}
	return p
}

// probeBound is the longest a bounded probe may take: the wait for its output pipe
// plus time to kill and reap it. It comes from the constant, not from a clock.
const probeBound = hostProbeWaitDelay + 5*time.Second

// holdsFor is how long the fixture's child keeps the probe's output pipe open. It is
// far above probeBound, so an unbounded wait cannot pass by finishing on its own.
const holdsFor = "60"

// fixtureChildGone fails the test unless the fixture child recorded in pidfile is gone soon.
func fixtureChildGone(t *testing.T, pidfile string) {
	t.Helper()
	b, err := os.ReadFile(pidfile) //nolint:gosec // G304: a file in this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	for range 100 {
		if !alive(pid) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("fixture child %d is still running after the probe returned", pid)
}

// A probe shell that has started a child holding the output pipe open is the case
// CombinedOutput alone cannot bound: killing the shell leaves the pipe open.
func TestHostRefusalIsBoundedWhenAChildHoldsTheOutputPipe(t *testing.T) {
	dir := t.TempDir()
	sleep := lookPath(t, "sleep")
	hold := shellQuote(sleep) + " " + holdsFor + " &\necho $! > \"$1\"\n"

	t.Run("the shell exits and leaves the child", func(t *testing.T) {
		pidfile := filepath.Join(t.TempDir(), "pid")
		start := time.Now()
		refusal, err := hostRefusal(context.Background(), probeScript(t, dir, "leaves", hold+"exit 0"), pidfile)
		if took := time.Since(start); took > probeBound {
			t.Errorf("hostRefusal took %v, want at most %v", took, probeBound)
		}
		if refusal != "" || err == nil {
			t.Errorf("refusal %q, error %v; a probe that leaves a process on its output pipe is an error", refusal, err)
		}
		fixtureChildGone(t, pidfile)
	})

	t.Run("the context ends while the shell waits for the child", func(t *testing.T) {
		pidfile := filepath.Join(t.TempDir(), "pid")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { // end the probe only once the child exists, so the test does not race the shell
			for range 500 {
				if b, err := os.ReadFile(pidfile); err == nil && len(b) > 0 { //nolint:gosec // G304: a file in this test's own TempDir.
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
		}()
		start := time.Now()
		refusal, err := hostRefusal(ctx, probeScript(t, dir, "waits", hold+"wait"), pidfile)
		if took := time.Since(start); took > probeBound {
			t.Errorf("hostRefusal took %v, want at most %v", took, probeBound)
		}
		if refusal != "" || !errors.Is(err, context.Canceled) {
			t.Errorf("refusal %q, error %v; want an error that wraps context.Canceled", refusal, err)
		}
		fixtureChildGone(t, pidfile)
	})
}
