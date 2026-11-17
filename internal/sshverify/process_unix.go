//go:build unix

package sshverify

import (
	"os/exec"
	"syscall"
)

// configureProcess starts the ssh client in a new session and process group.
// The new session has no controlling terminal, so a Match exec command that
// needs the terminal fails at once instead of being stopped while it waits. The
// group is what netdoc kills to end the client together with its children.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The client itself is always killed, so a cancelled read ends even if
		// the group kill fails. The group kill then reaches the client's children.
		killProcessGroup(cmd.Process.Pid)
		_ = cmd.Process.Kill()
		return nil
	}
}

// killProcessGroup kills every process still in the group the client led. It
// is a no-op once the group is empty.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
