//go:build unix

package sshverify

import (
	"os/exec"
	"syscall"
)

// configureProcess puts the ssh client in its own process group, so a command it
// starts is killed with it, and sets how the client is cancelled. The group is
// also what a command that reads the terminal is stopped for: it is not the
// terminal's foreground group.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
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
