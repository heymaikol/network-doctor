//go:build !windows

package diagnostic

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestConnectionResetMatchesUnixErrnos(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ECONNRESET, syscall.EPIPE} {
		err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)}
		if !isConnectionReset(err) {
			t.Errorf("%v not classed as a reset", errno)
		}
	}
}
