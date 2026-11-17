//go:build unix

package sshverify

import (
	"os/exec"
	"syscall"
)

// configureProcess runs the ssh client in its own process group. When the read
// is cancelled, the group is killed, which takes down a hung Match exec command
// that ssh started, not only ssh itself.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
}
