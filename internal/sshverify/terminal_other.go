//go:build !unix && !windows

package sshverify

// hasControllingTerminal reports false here: this platform has no terminal device that
// netdoc tests, so a run on it is treated as headless.
func hasControllingTerminal() bool { return false }
