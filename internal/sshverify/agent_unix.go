//go:build unix

package sshverify

import (
	"errors"
	"io"
	"net"
)

// dialAgent connects to the ssh-agent socket at path.
func dialAgent(path string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("unix", path) // #nosec G704 -- a local Unix socket named by the SSH configuration, not a network address
	if err != nil {
		return nil, errAgentUnreachable
	}
	return conn, nil
}

var errAgentUnreachable = errors.New("the ssh-agent socket could not be reached")
