//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package app

// setEchoOff does nothing where netdoc has no termios interface. The prompt is
// then written before the platform's own read turns echo off, as it was before.
func setEchoOff(uintptr) error {
	return nil
}
