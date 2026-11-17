//go:build !unix

package sshverify

import "os/exec"

// configureProcess has no process group to use on this platform. The client is
// still killed when the read is cancelled, but a child it started can outlive it.
func configureProcess(*exec.Cmd) {}

// killProcessGroup has nothing to kill beyond the client itself on this platform.
func killProcessGroup(int) {}
