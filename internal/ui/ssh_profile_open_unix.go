//go:build unix

package ui

import (
	"os"
	"syscall"
)

// A configuration path can be a FIFO or replaced with one between checks.
// Opening it nonblocking keeps profile suggestions from delaying the route.
func openSSHProfileConfig(path string) (*os.File, error) {
	// #nosec G304 -- caller constructs only the current user's ~/.ssh/config path;
	// following its symlink matches OpenSSH, and O_NONBLOCK prevents FIFO hangs.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
