//go:build !unix

package ui

import "os"

func openSSHProfileConfig(path string) (*os.File, error) {
	// Reject non-files where the platform has no nonblocking file flag.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return os.Open(path)
}
