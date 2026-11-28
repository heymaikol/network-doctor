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
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "✓ "+shortSSHKeyPath(manual[1])) {
		t.Fatalf("chosen key is not marked in the list: %q", text)
	}
}

func TestVerifyChangingKeyClearsSelectionAndPassphrase(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.keys = []string{"/keys/one", "/keys/two"}
	m.verify.keyIdx = 1
	m.verify.keyChosen = true
	m.verify.secret.SetValue("secret-passphrase")
	m.verify.result = &sshverify.Result{Outcome: sshverify.Verified}
	m.verify.focus(vrKey)
	u, _ := m.handleVerifyKey(keyPress("up"))
	m = asModel(t, u)
	if m.verify.keyIdx != 0 || m.verify.keyChosen || m.verify.secret.Value() != "" || m.verify.result != nil {
		t.Fatalf("key change: index=%d chosen=%v passphrase length=%d result=%v", m.verify.keyIdx, m.verify.keyChosen, len(m.verify.secret.Value()), m.verify.result)
	}
	if a, reason := m.verify.attempt(); a.KeyPath != "" || reason == "" {
		t.Fatalf("key change used stale selection: %+v, %q", a, reason)
	}
}

func TestVerifyArrowKeysNavigateFieldsAndLeaveKeyListAtItsEnds(t *testing.T) {
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.keys = []string{"/keys/one", "/keys/two"}
	m.verify.focus(vrUser)
	pressArrow := func(key string, row verifyRow, idx int) {
		t.Helper()
		u, _ := m.handleVerifyKey(keyPress(key))
		m = asModel(t, u)
		if m.verify.row != row || m.verify.keyIdx != idx {
			t.Fatalf("%s: row=%v keyIdx=%d, want row=%v keyIdx=%d", key, m.verify.row, m.verify.keyIdx, row, idx)
		}
	}
	pressArrow("up", vrUser, 0) // no wrap at the start
	pressArrow("down", vrMethod, 0)
	pressArrow("down", vrKey, 0)
	pressArrow("down", vrKey, 1)
	pressArrow("down", vrSecret, 1)
	pressArrow("down", vrDiscover, 1)
	pressArrow("down", vrCheck, 1)
	pressArrow("down", vrCheck, 1) // no wrap at the end
	pressArrow("up", vrDiscover, 1)
	pressArrow("up", vrSecret, 1)
	pressArrow("up", vrKey, 1)
	pressArrow("up", vrKey, 0)
	pressArrow("up", vrMethod, 0)
	pressArrow("up", vrUser, 0)
	if m.verify.keyChosen {
		t.Fatal("arrow navigation chose a private key without Enter")
	}
}

func TestVerifyArrowKeysNavigatePasswordAndAgentRows(t *testing.T) {
	for _, method := range []int{0, 2} {
		m := pressed(t, sshModel(t), keyPress("S"))
		m = resolved(t, m)
		m.verify.method = method
		m.verify.focus(vrUser)
		rows := m.verify.visibleRows()
		for _, want := range rows[1:] {
			u, _ := m.handleVerifyKey(keyPress("down"))
			m = asModel(t, u)
			if m.verify.row != want {
				t.Fatalf("method %d: down reached %v, want %v", method, m.verify.row, want)
			}
		}
		for i := len(rows) - 2; i >= 0; i-- {
			u, _ := m.handleVerifyKey(keyPress("up"))
			m = asModel(t, u)
			if m.verify.row != rows[i] {
				t.Fatalf("method %d: up reached %v, want %v", method, m.verify.row, rows[i])
			}
		}
	}
}

func TestVerifyKeyPickerShowsAWindowOfKeysAndKeepsTabNavigation(t *testing.T) {
	assertHintGap := func(text string) {
		t.Helper()
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			if strings.Contains(line, "choose with arrows, press enter to select") {
				if i == 0 || strings.TrimSpace(strings.Trim(lines[i-1], "│")) != "" {
					t.Fatalf("picker hint must follow a blank line: %q", text)
				}
				return
			}
		}
		t.Fatalf("picker hint missing: %q", text)
	}
	m := pressed(t, sshModel(t), keyPress("S"))
	m = resolved(t, m)
	m.verify.method = 1
	m.verify.syncSecretPrompt()
	m.width = 66
	for i := 0; i < 8; i++ {
		m.verify.keys = append(m.verify.keys, filepath.Join("/keys", string(rune('a'+i))))
	}
	m.verify.focus(vrKey)
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "▸ "+filepath.Join("/keys", "a")) || !strings.Contains(text, "▹ "+filepath.Join("/keys", "b")) || !strings.Contains(text, filepath.Join("/keys", "e")) || strings.Contains(text, filepath.Join("/keys", "f")) || strings.Contains(text, "showing ") {
		t.Fatalf("picker did not display the first page: %q", text)
	} else {
		if strings.Contains(text, "Key file  ") || strings.Contains(text, "No Key File") {
			t.Fatalf("picker added a redundant key file status row: %q", text)
		}
		if !strings.Contains(text, "[ Verify credential ]  sends one credential") || strings.Contains(text, "sends one credential, once") {
			t.Fatalf("verification action has outdated helper text: %q", text)
		}
		keysEnd := strings.Index(text, filepath.Join("/keys", "e"))
		hint := strings.Index(text, "choose with arrows, press enter to select")
		passphrase := strings.Index(text, "Passphrase type here")
		if keysEnd < 0 || hint <= keysEnd || passphrase <= hint {
			t.Fatalf("picker guidance must follow the list and precede Passphrase: %q", text)
		}
		assertHintGap(text)
	}
	t.Logf("sanitized key picker sample:\n%s", ansi.Strip(m.verifyView()))
	for i := 0; i < 6; i++ {
		u, _ := m.handleVerifyKey(keyPress("down"))
		m = asModel(t, u)
	}
	if text := ansi.Strip(m.verifyView()); !strings.Contains(text, "▸ "+filepath.Join("/keys", "g")) || !strings.Contains(text, "▹ "+filepath.Join("/keys", "h")) || strings.Contains(text, filepath.Join("/keys", "c")) || strings.Contains(text, "showing ") {
		t.Fatalf("picker did not scroll with down: %q", text)
	} else {
		assertHintGap(text)
	}
	u, _ := m.handleVerifyKey(keyPress("tab"))
	m = asModel(t, u)
	if m.verify.row != vrSecret {
		t.Fatalf("tab left focus at %v, want passphrase", m.verify.row)
	}
	if m.verify.keyChosen {
		t.Fatal("tab automatically selected a key")
	}
	m.verify.keys = m.verify.keys[:5]
	m.verify.keyIdx = 0
	assertHintGap(ansi.Strip(m.verifyView()))
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

func TestVerifyKeyPickerKeepsDistinctFileNamesVisible(t *testing.T) {
	m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
	m.verify.method = 1
	m.width = 76
	m.verify.keys = []string{
		filepath.Join("/keys", strings.Repeat("shared-directory/", 10), "custom-key_ed25519"),
		filepath.Join("/keys", strings.Repeat("shared-directory/", 10), "custom-key-backup"),
	}
	m.verify.focus(vrKey)
	view := ansi.Strip(m.verifyView())
	for _, name := range []string{"custom-key_ed25519", "custom-key-backup"} {
		if !strings.Contains(view, name) {
			t.Fatalf("long path hid %q in the chooser: %q", name, view)
		}
	}
	if !strings.Contains(view, "…") {
		t.Fatalf("long key paths were not visibly shortened: %q", view)
	}
}

func TestVerifyPickerButtonsRemainVisibleOnShortTerminals(t *testing.T) {
	for _, method := range []int{1, 2} {
		for _, height := range []int{24, 16} {
			m := resolved(t, pressed(t, sshModel(t), keyPress("S")))
			m.width, m.height = 80, height
			m.verify.method = method
			m.verify.keys = []string{"/keys/a", "/keys/b", "/keys/c", "/keys/d", "/keys/e"}
			for i := 0; i < 5; i++ {
				m.verify.agentKeys = append(m.verify.agentKeys, sshverify.AgentKey{Comment: string(rune('a' + i)), Fingerprint: "SHA256:test"})
			}
			view := ansi.Strip(m.View())
			if !strings.Contains(view, "[ Discover methods ]") || !strings.Contains(view, "[ Verify credential ]") {
				t.Fatalf("method %d at 80x%d hid verification controls:\n%s", method, height, view)
			}
			if !strings.Contains(view, "esc") {
				t.Fatalf("method %d at 80x%d hid the exit instructions:\n%s", method, height, view)
			}
			if height == 16 {
				if method == 1 {
					m.verify.focus(vrKey)
				} else {
					m.verify.focus(vrAgent)
				}
				u, _ := m.handleVerifyKey(keyPress("down"))
				m = asModel(t, u)
				view = ansi.Strip(m.View())
				want := "▸ /keys/b"
				if method == 2 {
					want = "▸ b  SHA256:test"
				}
				if !strings.Contains(view, want) || !strings.Contains(view, "[ Verify credential ]") {
					t.Fatalf("method %d at 80x16 did not scroll the compact list:\n%s", method, view)
				}
			}
		}
	}
}
