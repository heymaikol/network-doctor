//go:build unix

package ui

import (
	"os"
	"syscall"
)

// The nonblocking flag prevents an entry replaced with a FIFO from holding
// the key scan indefinitely while waiting for a writer.
func openSSHKeyCandidate(root *os.Root, path string) (*os.File, error) {
	return root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
