package ui

import "testing"

// The secret is typed for the login it was typed under. Changing the login clears it
// at the first change, so a password typed for one login cannot reach another.
func TestVerifyLoginChangeClearsTheTypedSecret(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m.verify.focus(vrSecret)
	u, _ := m.handleVerifyKey(keyPress("alice-password"))
	m = asModel(t, u)
	if got := m.verify.secret.Value(); got != "alice-password" {
		t.Fatalf("setup: the secret was not typed: %q", got)
	}

	m.verify.focus(vrUser)
	u, _ = m.handleVerifyKey(keyPress("b"))
	m = asModel(t, u)
	if got := m.verify.secret.Value(); got != "" {
		t.Fatalf("changing the login kept the secret typed for the previous login: %d characters", len(got))
	}
	if a, _ := m.verify.attempt(); len(a.Password) != 0 {
		t.Fatal("a password attempt for the new login carried the previous login's secret")
	}
}
