//go:build !linux && !darwin && !windows

package diagnostic

import (
	"errors"
	"net"
	"runtime"
)

// socketSendBuffer and socketMSS have no reading here. SO_SNDBUF and TCP_MAXSEG
// do exist on the Unixes this constraint covers, but netdoc ships linux, darwin
// and windows binaries only, so a getsockopt written for one of them could not
// be exercised by any test or release in this repository. A guess at a socket
// option level that nothing here can run is how a probe comes to report a
// confident wrong number. These keep the package compiling for another GOOS and
// name the limitation, the way socketQueued already does for Windows.
//
// Both callers already handle the error. The path-MTU probe reports StatusNA
// when the effective send buffer cannot be read, since a completed write would
// then only prove local buffering, and an unreadable MSS drops the byte count
// from the detail line without changing any verdict.
func socketSendBuffer(net.Conn) (int, error) {
	return 0, errors.New("no TCP send-buffer reading on " + runtime.GOOS)
}

func socketMSS(net.Conn) (int, error) {
	return 0, errors.New("no TCP MSS reading on " + runtime.GOOS)
}
