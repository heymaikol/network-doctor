package ui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// A check started after a discovery carries the host key that discovery showed, so Verify can
// refuse a different key. The panel passes that key and nothing else of the discovery's.
func TestCheckCarriesTheHostKeyDiscoveryShowed(t *testing.T) {
	var got sshverify.Attempt
	saved := verifyCheck
	verifyCheck = func(_ context.Context, _ sshverify.Target, a sshverify.Attempt, _ sshverify.Options) sshverify.Result {
		got = a
		return sshverify.Result{Outcome: sshverify.Refused}
	}
	t.Cleanup(func() { verifyCheck = saved })

	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered, HostKey: "SHA256:shown"}})
	m.verify.secret.SetValue("secret")

	_, cmd := m.startVerifyAction(true)
	// A single command runs as the check itself. A batch holds the check first, and the spinner
	// after it, which is not run here.
	if batch, ok := cmd().(tea.BatchMsg); ok && len(batch) > 0 {
		batch[0]()
	}

	if got.HostKey != "SHA256:shown" {
		t.Fatalf("the check's host key = %q, want the one discovery showed", got.HostKey)
	}
}

// A discovery that names no host key trusts nothing for the check, so the check cannot start.
func TestDiscoveryWithoutAHostKeyDoesNotArmTheCheck(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered}})
	if m.verify.trusted || m.verify.hostKey != "" {
		t.Fatalf("a discovery with no host key armed the check: trusted=%v hostKey=%q", m.verify.trusted, m.verify.hostKey)
	}
}

// The panel shows the host key a discovery trusted, so the user can compare it with the key they expect.
func TestDiscoveryShowsTheTrustedHostKey(t *testing.T) {
	m := resolved(t, sshModel(t))
	r := sshverify.Result{Outcome: sshverify.Discovered, HostKey: "SHA256:shown"}
	if !strings.Contains(resultLines(m, r), "trusted host key: SHA256:shown") {
		t.Fatalf("the discovery result does not show its host key:\n%s", resultLines(m, r))
	}
}
