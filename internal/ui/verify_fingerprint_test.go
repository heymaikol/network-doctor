package ui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// A changed host key is refused, and the panel must show the key the server presented, so the
// user can compare it with the key they expect. Unknown keys already show theirs.
func TestChangedHostKeyFingerprintIsShownInThePanel(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	const presented = "SHA256:presentedkeyfixture"
	m.verify.result = &sshverify.Result{
		Outcome: sshverify.HostKeyChanged,
		HostKey: presented,
		Detail:  "the host key differs from the one in known_hosts; nothing was sent",
	}

	view := ansi.Strip(m.View())
	if !strings.Contains(view, "presented host key: "+presented) {
		t.Fatalf("the changed key's fingerprint is not in the panel:\n%s", view)
	}
}

// Control: a result without a presented key shows no fingerprint line.
func TestChangedHostKeyWithoutAFingerprintShowsNoLine(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.result = &sshverify.Result{Outcome: sshverify.HostKeyChanged, Detail: "x"}

	if view := ansi.Strip(m.View()); strings.Contains(view, "presented host key") {
		t.Fatalf("a fingerprint line was drawn with no key:\n%s", view)
	}
}

// A revoked key is refused like a changed one, and the panel shows the key it presented too.
func TestRevokedHostKeyFingerprintIsShownInThePanel(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	const presented = "SHA256:revokedkeyfixture"
	m.verify.result = &sshverify.Result{Outcome: sshverify.HostKeyRevoked, HostKey: presented, Detail: "x"}

	if view := ansi.Strip(m.View()); !strings.Contains(view, "presented host key: "+presented) {
		t.Fatalf("the revoked key's fingerprint is not in the panel:\n%s", view)
	}
}

// An unknown key shows its fingerprint, so the user can compare it before establishing trust with their
// normal SSH client. The panel offers no trust override, and showing the key trusts nothing: the result
// arms no check, so a secret typed after it cannot start one.
func TestUnknownHostKeyFingerprintIsShownWithoutATrustOverride(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	const presented = "SHA256:unknownkeyfixture"
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{
		Outcome: sshverify.HostKeyUnknown,
		HostKey: presented,
		Detail:  "OpenSSH has no record of this host key; nothing was sent",
	}})

	view := ansi.Strip(m.View())
	if !strings.Contains(view, "presented host key: "+presented) {
		t.Fatalf("the unknown key's fingerprint is not in the panel:\n%s", view)
	}
	lower := strings.ToLower(view)
	for _, offer := range []string{"trust this host", "trust host", "trust the host", "accept this key", "override"} {
		if strings.Contains(lower, offer) {
			t.Fatalf("the panel offers a trust override (%q):\n%s", offer, view)
		}
	}
	if m.verify.trusted || m.verify.identity.Valid() {
		t.Fatal("an unknown key was treated as trusted because its fingerprint is shown")
	}

	started := false
	saved := verifyCheck
	verifyCheck = func(context.Context, sshverify.Target, sshverify.Attempt, sshverify.Options) sshverify.Result {
		started = true
		return sshverify.Result{Outcome: sshverify.Refused}
	}
	t.Cleanup(func() { verifyCheck = saved })
	m.verify.secret.SetValue("secret")
	_, cmd := m.startVerifyAction(true)
	if cmd != nil {
		if batch, ok := cmd().(tea.BatchMsg); ok && len(batch) > 0 {
			batch[0]()
		}
	}
	if started {
		t.Fatal("a check started after an unknown key was displayed, with no discovery to trust it")
	}
}

// The presented key comes from the server, so it is sanitized like every other server string: a control
// sequence in it never reaches the terminal.
func TestUnknownHostKeyFingerprintIsSanitized(t *testing.T) {
	const presented = "SHA256:abc\x1b]0;evil\x07tail"
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{
		Outcome: sshverify.HostKeyUnknown,
		HostKey: presented,
		Detail:  "x",
	}})

	raw := m.View()
	if strings.Contains(raw, "\x1b]0;evil") || strings.Contains(raw, "\x07") {
		t.Fatal("a control sequence from the presented key reached the terminal")
	}
	want := "presented host key: " + textsafe.Clean(presented)
	if !strings.Contains(ansi.Strip(raw), want) {
		t.Fatalf("the sanitized fingerprint is not in the panel:\n%s", ansi.Strip(raw))
	}
}
