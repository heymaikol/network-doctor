//go:build !unix

package sshverify

import (
	"errors"
	"io"
)

// dialAgent reports that ssh-agent access is not built for this platform. The
// Windows OpenSSH agent listens on a named pipe, which this build does not
// reach; keys can still be verified with a key file or a password.
func dialAgent(string) (io.ReadWriteCloser, error) {
	return nil, errors.New("ssh-agent access is not built for this platform")
}
