//go:build windows

package diagnostic

import (
	"errors"

	"golang.org/x/sys/windows"
)

const connectionRefusedErrno = windows.WSAECONNREFUSED

func isConnectionRefused(err error) bool { return errors.Is(err, connectionRefusedErrno) }

// isConnectionReset reports a reset or abort on a socket that was already open.
// Windows reports both as WSA errors. Go's syscall.ECONNRESET is a value of its
// own there, so the Unix constants never match.
func isConnectionReset(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED)
}
