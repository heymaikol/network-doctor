//go:build unix

package sshverify

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// configureProcess starts the ssh client in its own process group, inside the
// terminal of the netdoc process. The client keeps the controlling terminal, so a
// Match exec command that tests for a terminal gets the same answer it gets from
// an interactive ssh. Because the group is not the terminal's foreground group,
// a command that reads the terminal is stopped by SIGTTIN and never receives an
// answer; the read then fails at its deadline instead of choosing a branch.
//
// The group is also what netdoc kills to end the client together with any child
// it started.
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

// requireTerminal refuses a configuration read that has no controlling terminal.
// Without one, a Match exec command that tests for a terminal gets a different
// answer from the one an interactive ssh gives, and the difference is silent.
var requireTerminal = func() error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) // #nosec G304 -- the controlling terminal, opened only to test for it
	if err != nil {
		return fmt.Errorf("the SSH configuration needs a terminal, because a Match exec command could otherwise choose a different host without saying so; run netdoc from a terminal")
	}
	_ = tty.Close()
	return nil
}
