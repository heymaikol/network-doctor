//go:build unix

package ui

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSSHProfileConfigNamedPipeDoesNotBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(sshDir, "config"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan []string, 1)
	go func() { done <- listSSHHostProfiles(context.Background()) }()
	select {
	case profiles := <-done:
		if len(profiles) != 0 {
			t.Fatalf("named pipe suggested profiles: %q", profiles)
		}
	case <-time.After(time.Second):
		t.Fatal("named pipe blocked SSH profile suggestions")
	}
}

func TestSSHProfileConfigSymlinkToRegularFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, "ssh-aliases")
	if err := os.WriteFile(config, []byte("Host witness\n  HostName witness.local\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(config, filepath.Join(sshDir, "config")); err != nil {
		t.Fatal(err)
	}
	profiles := listSSHHostProfiles(context.Background())
	if len(profiles) != 1 || profiles[0] != "witness" {
		t.Fatalf("symlinked SSH config suggested profiles: %q", profiles)
	}
}
