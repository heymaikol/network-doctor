//go:build !unix

package ui

import "os"

func openSSHKeyCandidate(root *os.Root, path string) (*os.File, error) {
	return root.Open(path)
}
