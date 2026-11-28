//go:build unix

package ui

import (
	"os"
	"syscall"
)

// A configuration path can be a FIFO or replaced with one between checks.
// Opening it nonblocking keeps profile suggestions from delaying the route.
func openSSHProfileConfig(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
