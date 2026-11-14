package remote

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cancellation that lands before ssh starts is still the caller stopping the
// run. cmd.Start refuses a context that has already ended, and that refusal used
// to surface as "could not run ssh: context canceled" rather than as an
// interruption.
func TestRunReportsACancellationBeforeSSHStartsAsInterrupted(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "ok")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, "server", "", Request{TimeoutMs: 3000})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error = %q, want it to say the run was interrupted", err)
	}
	if strings.Contains(err.Error(), "could not run ssh") || strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error = %q leaks the start refusal or the raw context error", err)
	}
	if !strings.Contains(err.Error(), "server") {
		t.Errorf("error = %q, want it to name the SSH destination", err)
	}
	// The refusal comes before the fork, so the stand-in never ran.
	if _, statErr := os.Stat(argvPath); statErr == nil {
		t.Error("ssh was started although the run was cancelled before it could start")
	}
}

// An operation deadline that has already passed when ssh would start is the
// same timeout a deadline during the exchange would be, not a failure to run
// ssh and not an interruption.
func TestRunReportsAnExpiredDeadlineBeforeSSHStartsAsTimedOut(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "ok")
	useShortOperationBound(t, 0)
	_, err := Run(context.Background(), "server", "", Request{})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want it to say the remote run timed out", err)
	}
	if strings.Contains(err.Error(), "could not run ssh") || strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error = %q leaks the start refusal or the raw context error", err)
	}
	if strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error = %q, want the operation deadline, not an interruption", err)
	}
	if _, statErr := os.Stat(argvPath); statErr == nil {
		t.Error("ssh was started although its operation deadline had already passed")
	}
}

// A start failure with no cancellation involved keeps its own message, because
// the caller needs the cause to fix it: here, the ssh that cannot be run.
func TestRunKeepsTheCauseOfAnSSHThatCannotStart(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-ssh")
	previous := sshProgram
	sshProgram = missing
	t.Cleanup(func() { sshProgram = previous })
	_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 3000})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.HasPrefix(err.Error(), "could not run ssh: ") {
		t.Errorf("error = %q, want the could-not-run-ssh message", err)
	}
	if !strings.Contains(err.Error(), "no-such-ssh") {
		t.Errorf("error = %q, want the cause to name the ssh that cannot run", err)
	}
	if strings.Contains(err.Error(), "interrupted") || strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, a start failure is not an interruption or a timeout", err)
	}
}

// The usual failure is an ssh that is not installed, which exec reports as a
// lookup on PATH rather than as a failed fork. It keeps its message too, and a
// cancelled run reports it as well: the missing program is the cause a user can
// act on, and the lookup happens before the context is ever consulted.
func TestRunKeepsTheCauseOfAnSSHNotOnPATH(t *testing.T) {
	previous := sshProgram
	sshProgram = "netdoc-ssh-not-installed-for-test"
	t.Cleanup(func() { sshProgram = previous })
	_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 3000})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.HasPrefix(err.Error(), "could not run ssh: ") || !strings.Contains(err.Error(), "netdoc-ssh-not-installed-for-test") {
		t.Errorf("error = %q, want the could-not-run-ssh message naming the missing program", err)
	}
}

// stoppedCaller reports the caller as cancelled and never closes Done. A zero
// operation bound then expires the derived context by itself, so the caller's
// stop and the passed deadline both stand when ssh would start.
type stoppedCaller struct{ context.Context }

func (stoppedCaller) Err() error { return context.Canceled }

// When the caller has stopped the run and its operation deadline has also
// passed, the stop is what happened: the caller's context decides the verdict,
// so this is an interruption, not a timeout.
func TestRunReportsACancellationAheadOfAnExpiredDeadlineAsInterrupted(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "ok")
	useShortOperationBound(t, 0)
	_, err := Run(stoppedCaller{context.Background()}, "server", "", Request{})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error = %q, want it to say the run was interrupted", err)
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, the caller stopped the run before any deadline mattered", err)
	}
	if _, statErr := os.Stat(argvPath); statErr == nil {
		t.Error("ssh was started although the run was already cancelled")
	}
}
