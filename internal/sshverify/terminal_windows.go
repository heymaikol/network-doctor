//go:build windows

package sshverify

import "os"

// hasControllingTerminal reports whether this process has a console. CONIN$ is the
// console input device on Windows, the counterpart of /dev/tty on unix. It is opened only
// to test for it, and nothing is read. Untested on Windows in this change: it is checked
// by cross-compiling only.
func hasControllingTerminal() bool {
	con, err := os.OpenFile("CONIN$", os.O_RDWR, 0) // #nosec G304 -- the console input device, opened only to test for it
	if err != nil {
		return false
	}
	_ = con.Close()
	return true
}
