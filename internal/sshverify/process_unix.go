//go:build unix

package sshverify

import (
	"os/exec"
	"syscall"
	"time"
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

// waitGroupGone waits, for at most bound, until no process is left in the group the client led.
// SIGKILL is delivered asynchronously, so a process the kill has reached can still be running when
// the kill returns. A member that is a zombie stays in the group until it is reaped, so the wait ends
// at the bound in a sandbox whose PID 1 never reaps; the caller then treats the zombie as exited.
func waitGroupGone(pid int, bound time.Duration) {
	deadline := time.Now().Add(bound)
	for syscall.Kill(-pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}
