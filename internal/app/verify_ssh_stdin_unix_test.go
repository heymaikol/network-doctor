//go:build unix

package app

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// blockingStdin reports that its read has begun, then waits for a line that never comes.
type blockingStdin struct{}

func (blockingStdin) Read([]byte) (int, error) {
	fmt.Fprintln(os.Stdout, "reading")
	time.Sleep(time.Hour)
	return 0, io.EOF
}

// TestHelperVerifyStdinChild is the child of the tests below. It runs the headless check
// with -password-stdin and the network stubbed, so only the read can block.
func TestHelperVerifyStdinChild(t *testing.T) {
	if os.Getenv("GO_HELPER") != "1" {
		return
	}
	verifyResolve = func(context.Context, string, int, string) (sshverify.Target, error) {
		return sshverify.Target{Host: "127.0.0.1", Port: 22, User: "tester"}, nil
	}
	verifyDiscover = func(context.Context, sshverify.Target, sshverify.Options) sshverify.Result {
		return sshverify.Result{Outcome: sshverify.Discovered, HostKey: "SHA256:seen"}
	}
	verifyVerify = func(context.Context, sshverify.Target, sshverify.Attempt, sshverify.Options) sshverify.Result {
		return sshverify.Result{Outcome: sshverify.Verified}
	}
	if os.Getenv("GO_HELPER_MODE") == "line" {
		verifyStdin = strings.NewReader("the-password\n")
	} else {
		verifyStdin = blockingStdin{}
	}
	code := runVerifySSH([]string{"tester@127.0.0.1:22"}, map[string]bool{"verify-auth": true, "password-stdin": true},
		verifySSHFlags{auth: "password", passwordStdin: true}, os.Stdout, os.Stderr)
	os.Exit(code)
}

func helperCommand(t *testing.T, mode string) *exec.Cmd {
	t.Helper()
	// #nosec G204 G702 -- os.Args[0] deliberately re-executes this test binary as the child.
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperVerifyStdinChild$")
	cmd.Env = append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE="+mode)
	return cmd
}

// A -password-stdin read that is waiting for a line ends on SIGINT or SIGTERM, with
// exit status 2 and no line. The child reports that its read has begun before the
// signal is sent, so the signal cannot land before the handler is registered.
func TestVerifyPasswordStdinEndsOnAnInterrupt(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := helperCommand(t, "block")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			guard := time.AfterFunc(10*time.Second, func() { _ = cmd.Process.Kill() })
			defer guard.Stop()
			ready, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || !strings.Contains(ready, "reading") {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("the child never began its read: %q, %v", ready, err)
			}

			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Fatal("the process kept waiting for a line after the signal")
			}
			if cmd.ProcessState.ExitCode() != 2 {
				t.Fatalf("exit status = %d (signaled %v), want 2 after an interrupt; stderr %q", cmd.ProcessState.ExitCode(), cmd.ProcessState.Sys(), stderr.String())
			}
			if !strings.Contains(stderr.String(), "interrupted before the secret was read") {
				t.Errorf("stderr = %q, want the interrupt reported", stderr.String())
			}
		})
	}
}

// Control: when a line is supplied, the same read proceeds and the check runs.
func TestVerifyPasswordStdinWithALineProceeds(t *testing.T) {
	cmd := helperCommand(t, "line")
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 0 {
			t.Fatalf("a supplied line did not complete the check: %v", err)
		}
	}
}
