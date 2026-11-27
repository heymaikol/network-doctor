//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package app

import "golang.org/x/sys/unix"

func getTermios(fd uintptr) (unix.Termios, error) {
	t, err := unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
	if err != nil {
		return unix.Termios{}, err
	}
	return *t, nil
}

func setTermios(fd uintptr, t *unix.Termios) error {
	return unix.IoctlSetTermios(int(fd), unix.TIOCSETA, t)
}
