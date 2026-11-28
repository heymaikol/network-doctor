package ui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSSHPrivateKeyPickerFindsPrivateKeysWithoutSSHConfiguration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.MkdirAll(filepath.Join(dir, "git"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	custom := write("custom_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate material is never shown\n")
	git := write(filepath.Join("git", "account"), "-----BEGIN ENCRYPTED PRIVATE KEY-----\nprivate material\n")
	rsa := write("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nprivate material\n")
	write("custom_ed25519.pub", "ssh-ed25519 AAAAB3Nza...\n")
	write("authorized_keys", "ssh-ed25519 AAAAB3Nza...\n")
	write("config", "Host sample\n  IdentityFile ~/.ssh/custom_ed25519\n")
	write("known_hosts", "sample ssh-ed25519 AAAAB3Nza...\n")
	write("not-a-key", "some other text\n")
	other := filepath.Join(t.TempDir(), "outside-key")
	if err := os.WriteFile(other, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "linked-key")); err != nil {
		t.Logf("symlink check unavailable: %v", err)
	}

	got, err := scanSSHPrivateKeys(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{custom, git, rsa}
	if !slices.Equal(got, want) {
		t.Fatalf("listed private keys = %q, want %q", got, want)
	}
}

func TestSSHPrivateKeyPickerMissingDirectoryAndCancellation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	keys, err := scanSSHPrivateKeys(context.Background(), dir)
	if err != nil || len(keys) != 0 {
		t.Fatalf("missing .ssh directory: keys=%q err=%v", keys, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanSSHPrivateKeys(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan returned %v, want context canceled", err)
	}
}

func TestSSHPrivateKeyPickerDisplaysHomeRelativePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	path := filepath.Join(home, ".ssh", "subdir", "my_key")
	if got := shortSSHKeyPath(path); got != "~/.ssh/subdir/my_key" {
		t.Fatalf("short key path = %q", got)
	}
	outside := filepath.Join(t.TempDir(), "outside-key")
	if got := shortSSHKeyPath(outside); got != outside {
		t.Fatalf("outside path = %q, want unchanged", got)
	}
}
