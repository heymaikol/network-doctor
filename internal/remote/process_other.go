//go:build !unix

package remote

import "os/exec"

// configureBatchProcess does nothing on this platform. A cancelled batch run kills the ssh
// client only, so a process the client started is not killed here.
func configureBatchProcess(*exec.Cmd) {}

// killBatchProcess stops the batch ssh client alone: there is no group to stop here.
func killBatchProcess(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
