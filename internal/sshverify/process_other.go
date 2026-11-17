//go:build !unix

package sshverify

import "os/exec"

// configureProcess has no process group to use on this platform. The client is
// still killed when the read is cancelled, but a child it started can outlive it.
func configureProcess(*exec.Cmd) {}

// killProcessGroup has nothing to kill beyond the client itself on this platform.
func killProcessGroup(int) {}

// requireTerminal is not checked on this platform. How a Match exec command sees
// the console here is not verified, so configuration reads are not guaranteed to
// match an interactive ssh.
var requireTerminal = func() error { return nil }
