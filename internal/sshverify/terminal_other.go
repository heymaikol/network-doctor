//go:build !unix

package sshverify

// hasControllingTerminal reports false here: there is no /dev/tty to test, and netdoc
// does not yet detect a console. A run on this platform is therefore treated as headless.
func hasControllingTerminal() bool { return false }
