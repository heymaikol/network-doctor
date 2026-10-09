//go:build windows

package diagnostic

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// connectionResetErrno is this platform's reset errno, for tests that simulate one.
var connectionResetErrno error = windows.WSAECONNRESET

func TestConnectionResetMatchesWinsockErrors(t *testing.T) {
	for _, errno := range []error{windows.WSAECONNRESET, windows.WSAECONNABORTED} {
		err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", errno)}
		if !isConnectionReset(err) {
			t.Errorf("%v not classed as a reset", errno)
		}
	}
}
