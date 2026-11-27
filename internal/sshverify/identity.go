package sshverify

import (
	"net"
	"strconv"
)

// HostIdentity is the host identity a discovery trusted, as OpenSSH recorded it: the endpoint the
// discovery dialed, the SHA256 fingerprint of the subject key, the negotiated host key algorithm,
// and for a host certificate its key ID, serial number and authority. Two certificates for one
// subject key are different identities, and so is a plain key for the same subject key. So is one
// key trusted at two endpoints: a discovery authorizes a credential only at the endpoint it reached.
//
// Discover returns the identity it trusted. Verify binds a credential to an identity: a trusted
// key that differs in any field, or a target at another endpoint, is refused before any credential
// is sent. A caller that builds an identity by hand can only make a check refuse, never admit a key
// OpenSSH did not trust, because OpenSSH's decision still has to pass. The zero value names no
// identity, and Verify refuses it.
type HostIdentity struct {
	Endpoint    string // the host and port the discovery dialed, as net.JoinHostPort writes them
	Fingerprint string // SHA256 of the subject key
	Algorithm   string // the negotiated host key algorithm
	Certificate bool   // the host presented a certificate
	KeyID       string // the certificate's key ID
	Serial      string // the certificate's serial number, in decimal
	Authority   string // SHA256 of the key that signed the certificate
}

// Valid reports whether the identity is well formed: an endpoint, a SHA256 fingerprint and an
// algorithm, and for a certificate a decimal serial and a SHA256 authority fingerprint.
func (h HostIdentity) Valid() bool {
	if !validEndpoint(h.Endpoint) || !ValidFingerprint(h.Fingerprint) || h.Algorithm == "" {
		return false
	}
	if !h.Certificate {
		return h.Serial == "" && h.Authority == "" && h.KeyID == ""
	}
	if _, err := strconv.ParseUint(h.Serial, 10, 64); err != nil {
		return false
	}
	return ValidFingerprint(h.Authority)
}

// validEndpoint reports whether e is a host and a non-zero port, as endpointOf writes them.
func validEndpoint(e string) bool {
	host, port, err := net.SplitHostPort(e)
	if err != nil || host == "" {
		return false
	}
	p, err := strconv.ParseUint(port, 10, 16)
	return err == nil && p != 0
}

// endpointOf is the endpoint the probe and the credential connection both dial for a target. It is
// the only place the endpoint is written, so the binding and the dial cannot disagree.
func endpointOf(t Target) string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// identityOf is the identity OpenSSH's trust decision names, on the endpoint it was asked about.
func identityOf(t hostTrust, endpoint string) HostIdentity {
	return HostIdentity{
		Endpoint:    endpoint,
		Fingerprint: t.fingerprint,
		Algorithm:   t.algorithm,
		Certificate: t.certificate,
		KeyID:       t.keyID,
		Serial:      t.serial,
		Authority:   t.authority,
	}
}
