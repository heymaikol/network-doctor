package ui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// sshModel is a model whose run target answered the SSH banner probe, which is
// what offers the credential check.
func sshModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:22"), false)
	m.width, m.height = 100, 40
	if m.results == nil {
		m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	}
	m.results[diagnostic.ProbeSSH] = diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	return m
}

// resolved returns the panel as it looks once its configuration read landed.
func resolved(t *testing.T, m model) model {
	t.Helper()
	next, _, _ := m.handleVerifyMsg(verifyResolvedMsg{id: m.verify.id, target: sshverify.Target{Host: "example.com", Port: 22, User: "tester"}})
	return next
}

func TestVerifyKeyIsOfferedOnlyWhereSSHAnswered(t *testing.T) {
	m := newModel(mustTarget(t, "example.com:22"), false)
	if m.actionAvailable(actVerifySSH) {
		t.Fatal("the credential check is offered without an SSH banner")
	}
	m = pressed(t, m, keyPress("S"))
	if m.verifying {
		t.Fatal("S opened the panel although the menu does not offer it")
	}

	m = sshModel(t)
	if !m.actionAvailable(actVerifySSH) {
		t.Fatal("the credential check is not offered after the SSH banner passed")
	}
	m = pressed(t, m, keyPress("S"))
	if !m.verifying || m.verify.id == 0 {
		t.Fatalf("S did not open the panel: verifying=%v", m.verifying)
	}
}

func TestVerifyRowsFollowTheMethod(t *testing.T) {
	p := verifyPanel{}
	p.method = 0 // password
	if rows := p.visibleRows(); !containsVerifyRow(rows, vrSecret) || containsVerifyRow(rows, vrKey) {
		t.Errorf("password rows = %v", rows)
	}
	p.method = 1 // key file
	if rows := p.visibleRows(); !containsVerifyRow(rows, vrKey) || !containsVerifyRow(rows, vrSecret) {
		t.Errorf("key rows = %v", rows)
	}
	p.method = 2 // agent
	if rows := p.visibleRows(); !containsVerifyRow(rows, vrAgent) || containsVerifyRow(rows, vrSecret) {
		t.Errorf("agent rows = %v", rows)
	}
}

func TestVerifyCheckNeedsASecretAndSendsNothingWithout(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.focus(vrCheck)

	u, cmd := m.startVerifyAction(true)
	m = asModel(t, u)
	if cmd != nil || m.verify.busy {
		t.Fatalf("a check started with no password: busy=%v", m.verify.busy)
	}
	if !strings.Contains(m.verify.note, "Password") {
		t.Errorf("note = %q, want the reason the check did not start", m.verify.note)
	}
}

func TestVerifySecretIsClearedAfterTheAttempt(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.secret.SetValue("the-typed-secret")
	m.verify.focus(vrCheck)
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered, HostKey: "SHA256:seen"}})

	u, cmd := m.startVerifyAction(true)
	m = asModel(t, u)
	if cmd == nil || !m.verify.busy {
		t.Fatal("a check with a password did not start")
	}
	if got := m.verify.secret.Value(); got != "" {
		t.Errorf("the secret input still holds %d characters after the attempt", len(got))
	}
	if strings.Contains(ansi.Strip(m.verifyView()), "the-typed-secret") {
		t.Error("the panel shows the secret")
	}
}

func TestVerifyStaleResultIsDropped(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.busy = true

	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id + 7, result: sshverify.Result{Outcome: sshverify.Verified}})
	if m.verify.result != nil || !m.verify.busy {
		t.Error("a result for another panel was applied")
	}
}

func TestVerifyEscClosesAndCancelsInFlight(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	cancelled := false
	m.verify.cancel = func() { cancelled = true }
	m.verify.busy = true
	m.verify.secret.SetValue("left-behind")

	// Keys reach the panel through Update, as they do in the running program.
	u, _ := m.Update(keyPress("esc"))
	m = asModel(t, u)

	if m.verifying || !cancelled {
		t.Errorf("esc: verifying=%v cancelled=%v, want the panel closed and the check cancelled", m.verifying, cancelled)
	}
	if m.verify.secret.Value() != "" {
		t.Error("the secret survived closing the panel")
	}
}

// An unknown host key is confirmed for exactly one check, and the confirmation
// is written nowhere: the next check consumes it, and nothing persists.
func TestVerifyUnknownHostKeyIsTrustedOnceOnly(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.result = &sshverify.Result{Outcome: sshverify.HostKeyUnknown, HostKey: "SHA256:example"}
	if !containsVerifyRow(m.verify.visibleRows(), vrTrust) {
		t.Fatal("the trust row is not offered after an unknown host key")
	}
	m.verify.focus(vrTrust)

	u, _ := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if m.verify.trust != "SHA256:example" || m.verify.result != nil {
		t.Fatalf("trust = %q result = %v, want the fingerprint confirmed and the result cleared", m.verify.trust, m.verify.result)
	}
	if opts := m.verify.verifyOptions(true); opts.TrustHostKey != "SHA256:example" || opts.PinHostKey != "SHA256:example" {
		t.Errorf("the next check carried trust %q and pin %q, want the confirmed key for both", opts.TrustHostKey, opts.PinHostKey)
	}
	if again := m.verify.verifyOptions(true); again.TrustHostKey != "" || again.PinHostKey != "" {
		t.Errorf("trust or pin survived the check that used it: %q %q", again.TrustHostKey, again.PinHostKey)
	}
}

// A check sends its secret only after a discovery trusted the host. Without
// one there is no key to present, so nothing starts.
func TestVerifyCheckWaitsForATrustedDiscovery(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.secret.SetValue("typed-secret")
	m.verify.focus(vrCheck)

	u, cmd := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if cmd != nil || m.verify.busy {
		t.Fatal("a check started without a trusted discovery")
	}
	if !strings.Contains(m.verify.note, "Discover methods first") {
		t.Errorf("note %q does not say why nothing was sent", m.verify.note)
	}
}

// The check presents the key the trusted discovery saw, and a discovery that
// does not trust the host leaves nothing to present.
func TestVerifyCheckPinsTheDiscoveredKey(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)

	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered, HostKey: "SHA256:seen"}})
	if opts := m.verify.verifyOptions(true); opts.PinHostKey != "SHA256:seen" {
		t.Fatalf("the check was pinned to %q, want the discovered key", opts.PinHostKey)
	}

	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.HostKeyChanged, HostKey: "SHA256:moved"}})
	if opts := m.verify.verifyOptions(true); opts.PinHostKey != "" {
		t.Errorf("a changed-key result left the pin %q in place", opts.PinHostKey)
	}
}

func containsVerifyRow(rows []verifyRow, r verifyRow) bool {
	for _, x := range rows {
		if x == r {
			return true
		}
	}
	return false
}

// Closing the panel cancels the configuration read it started, however many
// times the panel is opened. Each read runs until its context ends, as a hung
// ssh -G would, so a read that outlives its panel shows up as a missed cancel.
func TestClosingThePanelCancelsItsConfigurationRead(t *testing.T) {
	saved := resolveTarget
	t.Cleanup(func() { resolveTarget = saved })
	started := make(chan context.Context, 1)
	resolveTarget = func(ctx context.Context, host string, port int, login string) (sshverify.Target, error) {
		started <- ctx
		<-ctx.Done()
		return sshverify.Target{}, ctx.Err()
	}

	m := sshModel(t)
	for i := 0; i < 25; i++ {
		var cmd tea.Cmd
		m, cmd = m.openVerifySSH()
		if cmd == nil {
			t.Fatalf("opening %d returned no configuration read", i)
		}
		go cmd()
		read := <-started
		u, _ := m.Update(keyPress("esc"))
		m = asModel(t, u)
		select {
		case <-read.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("opening %d: closing the panel did not cancel its configuration read", i)
		}
		if m.verifying {
			t.Fatalf("opening %d: the panel is still open after esc", i)
		}
	}
}

// Only the esc key closes the panel. Ticks, a configuration read that resolves,
// and a check result, including one for an earlier panel, leave it open.
func TestAsynchronousEventsNeverCloseThePanel(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	id := m.verify.id

	events := []tea.Msg{
		spinner.TickMsg{},
		verifyResolvedMsg{id: id, target: sshverify.Target{Host: "example.com", Port: 22, User: "tester"}},
		verifyResultMsg{id: id, result: sshverify.Result{Outcome: sshverify.Verified}},
		verifyResultMsg{id: id + 9, result: sshverify.Result{Outcome: sshverify.Refused}},
		verifyResolvedMsg{id: id + 9, err: errors.New("late")},
	}
	for _, msg := range events {
		u, _ := m.Update(msg)
		m = asModel(t, u)
		if !m.verifying {
			t.Fatalf("%T closed the panel", msg)
		}
	}
}

// Discovery sends no secret, so typed input survives it. The check clears the
// input once it starts, as before.
func TestDiscoveryKeepsTheTypedSecret(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.secret.SetValue("typed-secret")
	m.verify.focus(vrDiscover)

	u, _ := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if got := m.verify.secret.Value(); got != "typed-secret" {
		t.Fatalf("discovery cleared the typed secret: %q", got)
	}
}

// Switching to another target closes the SSH panel, so a late result from it
// cannot land on the new target. Retesting the same target keeps the panel.
func TestSwitchingTargetClosesTheSSHPanel(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	id := m.verify.id
	m.verify.secret.SetValue("typed-secret")

	m.applyTarget(mustTarget(t, "other.example:22"), true)

	if m.verifying || m.verify.secret.Value() != "" || m.verify.id != 0 {
		t.Fatalf("the panel survived a target switch: verifying=%v secret=%q id=%d", m.verifying, m.verify.secret.Value(), m.verify.id)
	}
	m, _, _ = m.handleVerifyMsg(verifyResolvedMsg{id: id, target: sshverify.Target{Host: "example.com", Port: 22, User: "u"}})
	if m.verifying || m.verify.resolved {
		t.Fatal("a late configuration read for the previous target reopened the panel")
	}
}

func TestRetestOfTheSameTargetKeepsTheSSHPanel(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)

	m.applyTarget(mustTarget(t, "example.com:22"), false)

	if !m.verifying || !m.verify.resolved {
		t.Fatal("a retest of the same target closed the SSH panel")
	}
}

// A deferred restart waits for the running job. The SSH panel stays until that
// restart applies its new target, and then it is closed with the previous target.
func TestDeferredRestartClosesTheSSHPanelForTheOldTarget(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.secret.SetValue("typed-secret")

	u, _ := m.runPending(&pendingAction{kind: pendRestart, target: mustTarget(t, "other.example:22"), newQuestion: true})
	m = asModel(t, u)

	if m.verifying || m.verify.secret.Value() != "" {
		t.Fatalf("the deferred restart left the SSH panel for the previous target: verifying=%v secret=%q", m.verifying, m.verify.secret.Value())
	}
}
