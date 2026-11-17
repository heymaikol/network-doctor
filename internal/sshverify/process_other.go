//go:build !unix

package sshverify

import "os/exec"

// configureProcess has no process group to use on this platform. The read is
// still bounded by its deadline and by WaitDelay, but a command started by ssh
// can outlive a cancelled read.
func configureProcess(*exec.Cmd) {}
