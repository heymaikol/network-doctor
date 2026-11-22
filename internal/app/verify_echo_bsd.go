//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package app

import "golang.org/x/sys/unix"

// setEchoOff turns local echo off and leaves the other modes alone, so Ctrl-C and
// Ctrl-\ still reach the prompt as signals.
func setEchoOff(fd uintptr) error {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	if err != nil {
		return err
	}
	termios.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(int(fd), unix.TIOCSETA, termios)
}
