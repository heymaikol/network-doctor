//go:build unix

package remote

import (
	"os/exec"
	"syscall"
)

// configureBatchProcess puts a batch ssh client in its own process group, and makes a
// cancelled run kill the whole group. Cancelling kills only the client otherwise, and a
// process it started keeps running. The batch pins stop the usual helpers from starting;
// the group kill covers what they miss. The group is not the terminal's foreground group,
// which costs nothing here: a batch client reads no terminal.
func configureBatchProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		killBatchProcess(cmd)
		return nil
	}
}

// killBatchProcess kills a batch ssh client and every process in the group it leads.
func killBatchProcess(cmd *exec.Cmd) {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
