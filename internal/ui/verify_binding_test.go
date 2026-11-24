package ui

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/ssh"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// shownIdentity is the identity a test discovery trusts: a fixed key, as OpenSSH would record it.
var shownIdentity = func() sshverify.HostIdentity {
	seed := make([]byte, ed25519.SeedSize)
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		panic(err)
	}
	return sshverify.HostIdentity{Endpoint: "example.com:22", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Algorithm: "ssh-ed25519"}
}()

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
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered, HostKey: shownIdentity.Fingerprint, Identity: shownIdentity}})
	m.verify.secret.SetValue("secret")

	_, cmd := m.startVerifyAction(true)
	// A single command runs as the check itself. A batch holds the check first, and the spinner
	// after it, which is not run here.
	if batch, ok := cmd().(tea.BatchMsg); ok && len(batch) > 0 {
		batch[0]()
	}

	if got.Identity != shownIdentity {
		t.Fatalf("the check's identity = %+v, want the one discovery showed %+v", got.Identity, shownIdentity)
	}
}

// A discovery that names no identity trusts nothing for the check, so the check cannot start.
func TestDiscoveryWithoutAHostKeyDoesNotArmTheCheck(t *testing.T) {
	m := resolved(t, sshModel(t))
	m = pressed(t, m, keyPress("S"))
	m = resolved(t, m)
	m, _, _ = m.handleVerifyMsg(verifyResultMsg{id: m.verify.id, result: sshverify.Result{Outcome: sshverify.Discovered}})
	if m.verify.trusted || m.verify.identity.Valid() {
		t.Fatalf("a discovery with no identity armed the check: trusted=%v identity=%+v", m.verify.trusted, m.verify.identity)
	}
}

// The panel shows the host key a discovery trusted, so the user can compare it with the key they expect.
func TestDiscoveryShowsTheTrustedHostKey(t *testing.T) {
	m := resolved(t, sshModel(t))
	r := sshverify.Result{Outcome: sshverify.Discovered, HostKey: shownIdentity.Fingerprint, Identity: shownIdentity}
	if !strings.Contains(resultLines(m, r), "trusted host key: "+shownIdentity.Fingerprint) {
		t.Fatalf("the discovery result does not show its host key:\n%s", resultLines(m, r))
	}
}
