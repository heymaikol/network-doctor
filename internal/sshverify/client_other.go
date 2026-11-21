//go:build !unix

package sshverify

// checkClientPermissions has nothing to check here: the permission bits that
// Unix reports are not meaningful on this platform.
func checkClientPermissions(string) error { return nil }
