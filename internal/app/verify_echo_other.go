//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package app

import (
	"os"

	"github.com/charmbracelet/x/term"
)

// secretEcho is the Windows path, unchanged: term.ReadPassword turns echo off inside
// its own read, and restore puts back the console state saved before the read.
// There is no termios interface here, so off does nothing.
type secretEcho struct {
	fd    uintptr
	state *term.State
}

func newSecretEcho(fd uintptr) (*secretEcho, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	return &secretEcho{fd: fd, state: state}, nil
}

func (e *secretEcho) off() error { return nil }

func (e *secretEcho) restore() { _ = term.Restore(e.fd, e.state) }

func readTerminalLine() ([]byte, error) {
	return term.ReadPassword(os.Stdin.Fd())
}
