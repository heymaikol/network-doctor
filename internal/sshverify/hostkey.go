package sshverify

import (
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// errHostMoved stops a handshake whose host key is not the one OpenSSH trusted.
var errHostMoved = errors.New("host key differs from the one OpenSSH trusted")

// pinCheck admits only the host key OpenSSH trusted. The probe names its fingerprint, and for a
// host certificate the key ID OpenSSH printed. The credential connection offers only OpenSSH's
// negotiated algorithm, so the key it presents is the one OpenSSH checked. A certificate is
// checked by the key it certifies, not by its blob, and by its key ID. The key ID is text the
// signer chose, so the presented one must equal the printed one and hold no control character.
// netdoc reads no known_hosts file: the decision is OpenSSH's, and this check enforces it.
type pinCheck struct {
	fingerprint string // SHA256 of the subject key OpenSSH checked
	certificate bool   // OpenSSH checked a host certificate, not a plain key
	keyID       string // the key ID OpenSSH printed for the certificate
	presented   string // SHA256 of the subject key the server presented, once it has
	refused     bool   // the server presented something this check does not admit
}

// callback is the ssh.HostKeyCallback. It returns an error to stop the handshake before any
// credential is sent.
func (p *pinCheck) callback(_ string, _ net.Addr, key ssh.PublicKey) error {
	subject := key
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		subject = cert.Key
	}
	p.presented = ssh.FingerprintSHA256(subject)
	if p.presented != p.fingerprint || isCert != p.certificate {
		p.refused = true
		return errHostMoved
	}
	if isCert && (cert.KeyId != p.keyID || hasControlCharacter(cert.KeyId)) {
		p.refused = true
		return errHostMoved
	}
	return nil
}

// hasControlCharacter reports whether s holds a control character, such as a line break, which
// OpenSSH's output would show as the start of a line of its own.
func hasControlCharacter(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}
