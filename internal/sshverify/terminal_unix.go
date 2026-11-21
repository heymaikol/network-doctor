//go:build unix

package sshverify

import "os"

// hasControllingTerminal reports whether this process can open its terminal. The
// controlling terminal is /dev/tty on every unix netdoc supports.
func hasControllingTerminal() bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0) // #nosec G304 -- the controlling terminal, opened only to test for it
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}
