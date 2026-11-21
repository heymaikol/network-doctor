package sshverify

import (
	"os/exec"
	"testing"
)

// requireOpenSSH skips a test that needs the OpenSSH client when none is installed.
func requireOpenSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH is not installed")
	}
}
