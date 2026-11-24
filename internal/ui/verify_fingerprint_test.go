package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
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
