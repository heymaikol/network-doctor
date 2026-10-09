//go:build !windows

package diagnostic

import (
	"errors"
	"syscall"
)

const connectionRefusedErrno = syscall.ECONNREFUSED

func isConnectionRefused(err error) bool { return errors.Is(err, connectionRefusedErrno) }

// isConnectionReset reports a reset, or a write to a socket the peer already
// closed, on a socket that was already open.
func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}
