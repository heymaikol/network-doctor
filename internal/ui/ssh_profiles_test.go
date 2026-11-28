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

func TestSSHProfileSuggestionsAreLiteralAndNeverEvaluated(t *testing.T) {
	config := `
Host witness git *.example.com !danger
  HostName witness.local
Match exec "touch /tmp/never-run"
Host other
Include /tmp/not-read
Host WITNESS
Host -bad "quoted" question? single'quote
`
	got := parseSSHHostProfiles(config)
	if strings.Join(got, ",") != "witness,git,other" {
		t.Fatalf("suggested profiles = %q", got)
	}
}

func TestMapDeviceCanChooseSSHProfileWithoutChoosingPrivateKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host witness\n  HostName witness.local\n  User witness\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "bridge-witness_ed25519")
	if err := os.WriteFile(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\ntest material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := resolveTarget
	t.Cleanup(func() { resolveTarget = saved })
	resolveTarget = func(_ context.Context, host string, port int, login string) (sshverify.Target, error) {
		target := sshverify.Target{Host: host, Port: port, User: login, IdentityFile: []string{"/automatically-configured"}}
		if host == "witness" {
			target.Host = "witness.local"
			target.User = "witness"
		}
		return target, nil
	}
	m := newModel(mustTarget(t, "192.0.2.151:22"), false)
	m.width, m.height = 100, 40
	m, cmd := m.openVerifySSH()
	m = deliverReads(t, m, cmd)
	if m.verify.row != vrHost || m.verify.sshHost.Value() != "192.0.2.151" || m.verify.scannedIP != "192.0.2.151" {
		t.Fatalf("map device did not open at its IP: %+v", m.verify)
	}
	if len(m.verify.profiles) != 1 || m.verify.profiles[0] != "witness" {
		t.Fatalf("SSH profile options = %q", m.verify.profiles)
	}
	u, cmd := m.handleVerifyKey(keyPress("down"))
	m = asModel(t, u)
	if cmd != nil || m.verify.profileIdx != 0 || m.verify.sshHost.Value() != "192.0.2.151" {
		t.Fatal("moving the SSH profile cursor changed the connection before selection")
	}
	u, cmd = m.handleVerifyKey(keyPress("enter"))
	m = deliverReads(t, asModel(t, u), cmd)
	if !m.verify.resolved || m.verify.sshHost.Value() != "witness" || m.verify.target.Host != "witness.local" {
		t.Fatalf("selected profile was not resolved: %+v", m.verify)
	}
	if m.verify.keyChosen || len(m.verify.keys) != 1 || m.verify.keys[0] != key {
		t.Fatal("choosing an SSH profile implicitly chose or lost the manual private-key list")
	}
	view := ansi.Strip(m.verifyView())
	for _, want := range []string{"Original target: 192.0.2.151:22", "SSH host", "witness", "OpenSSH destination: witness.local"} {
		if !strings.Contains(view, want) {
			t.Fatalf("selected profile view does not show %q: %s", want, view)
		}
	}
	if m.verify.trusted {
		t.Fatal("choosing an SSH profile silently trusted its host key")
	}
}

func TestChangingSSHProfileClearsDiscoveredHostTrust(t *testing.T) {
	m := newModel(mustTarget(t, "192.0.2.151:22"), false)
	m.width, m.height = 100, 40
	m, _ = m.openVerifySSH()
	m.verify.resolved = true
	m.verify.trusted = true
	m.verify.identity = shownIdentity
	m.verify.sshHost.SetValue("witness")
	m.verify.dropRoute()
	if m.verify.resolved || m.verify.trusted || m.verify.identity.Valid() {
		t.Fatal("editing the SSH destination retained the previous host's trust")
	}
	if got := m.verify.sshHost.Value(); got != "witness" {
		t.Fatalf("destination edit lost the typed name: %q", got)
	}
}
