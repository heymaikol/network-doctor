//go:build !unix

package remote

import "os/exec"

// configureBatchProcess does nothing on this platform. A cancelled batch run kills the ssh
// client only, so a process the client started is not killed here.
func configureBatchProcess(*exec.Cmd) {}
