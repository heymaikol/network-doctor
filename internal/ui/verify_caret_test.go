package ui

import "testing"

// Left and Right move the caret inside the login and secret fields. The panel uses
// them to cycle the method and the key on their own rows, so on a text row they must
// reach the field, and typing lands at the caret.
func TestVerifyLeftAndRightMoveTheCaretInTextFields(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	// The password field takes text only after a trusted discovery.
	m.verify.trusted = true

	m.verify.user.SetValue("")
	m.verify.focus(vrUser)
	m = typeInPanel(t, m, "abc")
	m = typeInPanel(t, m, "left")
	m = typeInPanel(t, m, "X")
	if got := m.verify.user.Value(); got != "abXc" {
		t.Fatalf("login = %q, want %q: left did not move the caret before typing", got, "abXc")
	}
	m = typeInPanel(t, m, "left")
	m = typeInPanel(t, m, "left")
	if got := m.verify.user.Position(); got != 1 {
		t.Fatalf("login caret after two lefts = %d, want 1", got)
	}
	m = typeInPanel(t, m, "right")
	if got := m.verify.user.Position(); got != 2 {
		t.Fatalf("login caret after a right = %d, want 2", got)
	}

	m.verify.secret.SetValue("")
	// Editing the login dropped the trusted discovery, so the secret needs one again.
	m.verify.trusted = true
	m.verify.focus(vrSecret)
	m = typeInPanel(t, m, "abc")
	m = typeInPanel(t, m, "left")
	m = typeInPanel(t, m, "X")
	if got := m.verify.secret.Value(); got != "abXc" {
		t.Fatalf("secret = %q, want %q: left did not move the caret before typing", got, "abXc")
	}
}

// typeInPanel sends one key, by name or as typed text, to the open panel.
func typeInPanel(t *testing.T, m model, key string) model {
	t.Helper()
	u, _ := m.handleVerifyKey(keyPress(key))
	return asModel(t, u)
}
