//go:build unix

package sshverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The configuration reader trusts the ssh client it runs, so a client that
// another user can write is refused before it is run.
func TestSSHExecutableRefusesAWritableClient(t *testing.T) {
	dir := t.TempDir()
	client := filepath.Join(dir, "ssh")
	if err := os.WriteFile(client, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(client, 0o777); err != nil { // #nosec G302 -- the test makes a writable client on purpose
		t.Fatal(err)
	}
	if _, err := sshExecutable(client); err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Fatalf("a group- or world-writable client was accepted: %v", err)
	}

	owned := filepath.Join(dir, "owned-ssh")
	if err := os.WriteFile(owned, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(owned, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := sshExecutable(owned); err != nil || got != owned {
		t.Fatalf("a client only its owner can write was refused: %q %v", got, err)
	}
}
