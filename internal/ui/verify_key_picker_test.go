package ui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

func TestVerifyRouteReadListsLocalPrivateKeysNotConfiguredIdentityFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "custom_key")
	if err := os.WriteFile(keyPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nprivate material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := resolveTarget
	t.Cleanup(func() { resolveTarget = saved })
	resolveTarget = func(_ context.Context, host string, port int, login string) (sshverify.Target, error) {
		return sshverify.Target{Host: host, Port: port, User: login, IdentityFile: []string{"/other/configured-key"}}, nil
	}
	m, cmd := sshModel(t).openVerifySSH()
	m = deliverReads(t, m, cmd)
	if !m.verify.resolved || len(m.verify.keys) != 1 || m.verify.keys[0] != keyPath || m.verify.keyChosen {
		t.Fatalf("route read: resolved=%v keys=%q chosen=%v", m.verify.resolved, m.verify.keys, m.verify.keyChosen)
	}
}

func TestVerifyKeyPickerDoesNotChooseConfiguredIdentityAutomatically(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	configured := "/outside/configured-identity"
	manual := []string{"/keys/custom_ed25519", "/keys/git/account"}
	m, _, _ = m.handleVerifyMsg(verifyResolvedMsg{
		id: m.verify.id, seq: m.verify.resolveSeq,
		target: sshverify.Target{Host: "192.0.2.18", Port: 22, User: "sample", IdentityFile: []string{configured}},
		keys:   manual,
	})
	m.verify.method = 1
	if len(m.verify.keys) != 2 || m.verify.keys[0] != manual[0] {
		t.Fatalf("picker keys %q did not come from the manual list", m.verify.keys)
	}
	if a, reason := m.verify.attempt(); a.KeyPath != "" || reason == "" {
		t.Fatalf("a key was selected without consent: %+v, %q", a, reason)
	}
	m.verify.focus(vrKey)
	u, _ := m.handleVerifyKey(keyPress("down"))
	m = asModel(t, u)
	if m.verify.row != vrKey || m.verify.keyIdx != 1 || m.verify.keyChosen {
		t.Fatalf("down: row=%v index=%d chosen=%v", m.verify.row, m.verify.keyIdx, m.verify.keyChosen)
	}
	u, _ = m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if !m.verify.keyChosen || m.verify.row != vrSecret {
		t.Fatalf("enter: row=%v chosen=%v", m.verify.row, m.verify.keyChosen)
	}
	if a, reason := m.verify.attempt(); reason != "" || a.KeyPath != manual[1] {
		t.Fatalf("manual selection = %+v, reason %q", a, reason)
	}
}

func TestVerifyChangingKeyClearsSelectionAndPassphrase(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.keys = []string{"/keys/one", "/keys/two"}
	m.verify.keyChosen = true
	m.verify.secret.SetValue("secret-passphrase")
	m.verify.result = &sshverify.Result{Outcome: sshverify.Verified}
	m.verify.focus(vrKey)
	u, _ := m.handleVerifyKey(keyPress("up"))
	m = asModel(t, u)
	if m.verify.keyIdx != 1 || m.verify.keyChosen || m.verify.secret.Value() != "" || m.verify.result != nil {
		t.Fatalf("key change: index=%d chosen=%v passphrase length=%d result=%v", m.verify.keyIdx, m.verify.keyChosen, len(m.verify.secret.Value()), m.verify.result)
	}
	if a, reason := m.verify.attempt(); a.KeyPath != "" || reason == "" {
		t.Fatalf("key change used stale selection: %+v, %q", a, reason)
	}
}

func TestVerifyKeyPickerShowsAWindowOfKeysAndKeepsTabNavigation(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.syncSecretPrompt()
	m.width = 66
	for i := 0; i < 8; i++ {
		m.verify.keys = append(m.verify.keys, filepath.Join("/keys", string(rune('a'+i))))
	}
	m.verify.focus(vrKey)
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "showing 1-5 of 8 private keys") || !strings.Contains(text, "/keys/a") {
		t.Fatalf("picker did not display the first page: %q", text)
	}
	t.Logf("sanitized key picker sample:\n%s", ansi.Strip(m.verifyView()))
	for i := 0; i < 6; i++ {
		u, _ := m.handleVerifyKey(keyPress("down"))
		m = asModel(t, u)
	}
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "/keys/g") || !strings.Contains(text, "showing 4-8 of 8 private keys") {
		t.Fatalf("picker did not scroll with down: %q", text)
	}
	u, _ := m.handleVerifyKey(keyPress("tab"))
	m = asModel(t, u)
	if m.verify.row != vrSecret {
		t.Fatalf("tab left focus at %v, want passphrase", m.verify.row)
	}
	if m.verify.keyChosen {
		t.Fatal("tab automatically selected a key")
	}
}

func TestVerifyKeyPickerDoesNotAcceptAnEmptyList(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.focus(vrKey)
	u, _ := m.handleVerifyKey(keyPress("enter"))
	m = asModel(t, u)
	if m.verify.keyChosen || !strings.Contains(m.verify.note, "no private keys found") {
		t.Fatalf("empty picker: chosen=%v note=%q", m.verify.keyChosen, m.verify.note)
	}
}
