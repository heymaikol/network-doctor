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

// killProcessGroup sends SIGKILL once to the group the client led. It is the
// cancellation path's signal. The client may still be an unreaped zombie there,
// and a zombie leader keeps the group visible, so a retry would signal the whole
// window every time.
func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// groupRetryWindow bounds how long terminateProcessGroup keeps signalling after
// the client is reaped. A healthy probe leaves no group, so its first kill
// returns at once and the window is never used.
const groupRetryWindow = 100 * time.Millisecond

// groupRetryInterval is the pause between kills while the group still has members.
const groupRetryInterval = 5 * time.Millisecond

// terminateProcessGroup ends every process left in the group the client led. Call
// it only after the client has been reaped. Each kill that finds a member is
// followed by a short pause and another kill. The loop stops when a kill finds the
// group empty, when a kill is refused with EPERM (no member can be signalled, so
// another kill cannot succeed), or when groupRetryWindow has passed. A descendant
// forked while the first kill was in progress is caught by a later one.
//
// A pid of 0 or 1 is refused before any kill. Negated, those name the caller's own
// group and every process the caller may signal. A started client always has a
// larger PID, so the guard only stops a bad value from reaching kill.
//
// The group ID is the client's PID, which the reaped client no longer holds. A
// kill is sent only after the previous kill found the group occupied, so an empty
// group is never signalled again. Linux does not reuse a PID while a process group
// still uses it, so an occupied group keeps its ID. Reuse of an emptied group's ID
// inside the window would need the PID space to wrap within about 100 ms. That is
// not ruled out on every platform. A zombie member stays in the group until it is
// reaped, so where PID 1 never reaps, the loop runs the whole window and stops.
func terminateProcessGroup(pid int) {
	if pid <= 1 {
		return
	}
	deadline := time.Now().Add(groupRetryWindow)
	for {
		err := syscall.Kill(-pid, syscall.SIGKILL)
		if err == syscall.ESRCH || err == syscall.EPERM || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(groupRetryInterval)
	}
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
