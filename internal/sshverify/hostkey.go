package sshverify

import (
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
)

// errHostMoved stops a handshake whose host key is not the one OpenSSH trusted.
var errHostMoved = errors.New("host key differs from the one OpenSSH trusted")

// pinCheck admits only the host key OpenSSH trusted. The probe names its fingerprint. The
// credential connection offers only OpenSSH's negotiated algorithm, so the key it presents is
// the one OpenSSH checked. A certificate is checked by the key it certifies, not by its blob.
// netdoc reads no known_hosts file: the decision is OpenSSH's, and this check enforces it.
type pinCheck struct {
	fingerprint string // SHA256 of the subject key OpenSSH checked
	presented   string // SHA256 of the subject key the server presented, once it has
}

// callback is the ssh.HostKeyCallback. It returns an error to stop the handshake before any
// credential is sent.
func (p *pinCheck) callback(_ string, _ net.Addr, key ssh.PublicKey) error {
	subject := key
	if cert, ok := key.(*ssh.Certificate); ok {
		subject = cert.Key
	}
	p.presented = ssh.FingerprintSHA256(subject)
	if p.presented != p.fingerprint {
		return errHostMoved
	}
	return nil
}
