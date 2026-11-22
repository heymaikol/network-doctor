//go:build linux

package app

import "golang.org/x/sys/unix"

// setEchoOff turns local echo off and leaves the other modes alone, so Ctrl-C and
// Ctrl-\ still reach the prompt as signals.
func setEchoOff(fd uintptr) error {
	termios, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return err
	}
	termios.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(int(fd), unix.TCSETS, termios)
}
