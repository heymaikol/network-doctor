package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// withoutTerminal makes the run a headless one for the rest of the test. useFakeSSH
// restores the terminal check when the test ends.
func withoutTerminal(t *testing.T) {
	t.Helper()
	sshverify.TerminalAvailable = func() bool { return false }
}

// I2, headless: a destination whose route is not known as direct starts no ssh that
// connects. The connection is the only call that passes -T, and none does here.
func TestHeadlessRunStartsNoConnectionForAnUnknownRoute(t *testing.T) {
	for _, mode := range []string{"configproxy", "configproxycommand", "configexec"} {
		t.Run(mode, func(t *testing.T) {
			argvPath, _ := useFakeSSH(t, mode)
			withoutTerminal(t)
			_, err := Run(context.Background(), "ideapad", "", Request{})
			if err == nil || !strings.Contains(err.Error(), "run it from a terminal") {
				t.Fatalf("a headless run of a %s route returned %v; want the refusal", mode, err)
			}
			// The connection is the only call that passes -T; the configuration read never does.
			for _, line := range readLines(t, argvPath) {
				if line == "-T" {
					t.Fatalf("a headless run started a connection for a %s route: argv %q", mode, readLines(t, argvPath))
				}
			}
		})
	}
}

// I2, headless: a direct route connects only with the batch options, so no password,
// keyboard-interactive or passphrase prompt can be answered, and no host-key question.
func TestHeadlessRunConnectsOnlyWithBatchOptions(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "config")
	withoutTerminal(t)
	_, _ = Run(context.Background(), "ideapad", "", Request{})
	argv := strings.Join(readLines(t, argvPath), " ")
	for _, want := range []string{"BatchMode=yes", "PreferredAuthentications=publickey", "ProxyJump=none", "KnownHostsCommand=none"} {
		if !strings.Contains(argv, want) {
			t.Errorf("a headless connection lacks %q: argv %q", want, argv)
		}
	}
}

// A headless connection pins the host and port its configuration read classified, so the
// connection goes where the read said it goes. The fake reports 10.0.0.5 on port 22.
func TestHeadlessConnectionPinsTheClassifiedEndpoint(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "config")
	withoutTerminal(t)
	_, _ = Run(context.Background(), "ideapad", "", Request{})
	argv := strings.Join(readLines(t, argvPath), " ")
	for _, want := range []string{"HostName=10.0.0.5", "Port=22"} {
		if !strings.Contains(argv, want) {
			t.Errorf("a headless connection is not pinned to %q: argv %q", want, argv)
		}
	}
}

// The positive control on a terminal: the same direct route runs without the batch
// options, so the user can answer what ssh asks, as before.
func TestTerminalRunKeepsTheInteractiveTransport(t *testing.T) {
	argvPath, _ := useFakeSSH(t, "config")
	_, _ = Run(context.Background(), "ideapad", "", Request{})
	argv := strings.Join(readLines(t, argvPath), " ")
	if strings.Contains(argv, "BatchMode=yes") {
		t.Errorf("a terminal run was made batch: argv %q", argv)
	}
}

// A missing ssh is reported headless too, and the cause is named: the route cannot be
// read, so nothing is connected, and the user can see which program was missing.
func TestHeadlessRunNamesAMissingSSH(t *testing.T) {
	previous := sshProgram
	sshProgram = "netdoc-ssh-not-installed-for-test"
	t.Cleanup(func() { sshProgram = previous })
	withoutTerminal(t)
	_, err := Run(context.Background(), "server", "", Request{TimeoutMs: 3000})
	if err == nil || !strings.Contains(err.Error(), "netdoc-ssh-not-installed-for-test") {
		t.Fatalf("a headless run with no ssh returned %v; want the missing program named", err)
	}
}

// A headless batch run whose connection stalls after the route was established is the
// transport's own deadline, so it is marked as a run timeout. The route read answers, and the
// worker never does.
func TestHeadlessBatchDeadlineIsMarkedAsARunTimeout(t *testing.T) {
	useFakeSSH(t, "configthenhang")
	withoutTerminal(t)
	savedAllowance := transportAllowance
	transportAllowance = 300 * time.Millisecond
	t.Cleanup(func() { transportAllowance = savedAllowance })
	_, err := Run(context.Background(), "ideapad", "", Request{})
	if err == nil || !errors.Is(err, ErrRunTimedOut) {
		t.Fatalf("a stalled headless batch run returned %v; want a run timeout", err)
	}
}

// Negative control, headless: a route read that stalls is a gate, not the run's deadline. It
// refuses the run, and the refusal does not carry the run-timeout mark, so the profile pass ends
// on it as it does on any refusal. The read stops after its own budget, which takes about ten
// seconds.
func TestHeadlessRouteReadTimeoutIsNotARunTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("the route read waits out its own budget")
	}
	useFakeSSH(t, "hang")
	withoutTerminal(t)
	_, err := Run(context.Background(), "ideapad", "", Request{})
	if err == nil {
		t.Fatal("a headless run whose route read stalled returned no error")
	}
	if errors.Is(err, ErrRunTimedOut) {
		t.Fatalf("a stalled route read is marked as a run timeout: %v", err)
	}
}
