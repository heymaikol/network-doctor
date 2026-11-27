//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package app

import (
	"bytes"
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// errSecretInterrupted is returned when an interrupt has already restored the
// terminal, so the read must not turn echo off again.
var errSecretInterrupted = errors.New("the terminal was restored by an interrupt")

// secretEcho is the only writer of the terminal's state while a secret is read.
// An interrupt restores the terminal from its signal handler, in another goroutine,
// so restore and echo-off are serialized here. Once restore has run, no later write
// may turn echo off again. A second write from a line reader that saved the state
// after echo was off is what left echo off after Ctrl-C.
type secretEcho struct {
	mu      sync.Mutex
	fd      uintptr
	orig    unix.Termios
	stopped bool
}

func newSecretEcho(fd uintptr) (*secretEcho, error) {
	orig, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	return &secretEcho{fd: fd, orig: orig}, nil
}

// off turns echo off. It keeps the canonical line mode, signals and CR-to-NL mapping
// that the read needs, so a line is still returned and Ctrl-C still sends SIGINT.
func (e *secretEcho) off() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return errSecretInterrupted
	}
	t := e.orig
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	t.Iflag |= unix.ICRNL
	return setTermios(e.fd, &t)
}

// restore puts the terminal back as it was before the read. It runs once.
func (e *secretEcho) restore() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.stopped = true
	_ = setTermios(e.fd, &e.orig)
}

// readTerminalLine reads one line from standard input. It writes no terminal state:
// secretEcho has already set the modes the line needs.
func readTerminalLine() ([]byte, error) {
	var line []byte
	one := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(one)
		if n > 0 {
			if one[0] == '\n' {
				return bytes.TrimRight(line, "\r"), nil
			}
			if len(line) <= maxSecretLen {
				line = append(line, one[0])
			}
		}
		if err != nil {
			return nil, err
		}
	}
}
