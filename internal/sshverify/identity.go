package sshverify

import "strconv"

// HostIdentity is the host identity a discovery trusted, as OpenSSH recorded it: the SHA256
// fingerprint of the subject key, the negotiated host key algorithm, and for a host certificate its
// key ID, serial number and authority. Two certificates for one subject key are different
// identities, and so is a plain key for the same subject key.
//
// Discover returns the identity it trusted. Verify binds a credential to an identity: a trusted
// key that differs in any field is refused before any credential is sent. A caller that builds an
// identity by hand can only make a check refuse, never admit a key OpenSSH did not trust, because
// OpenSSH's decision still has to pass. The zero value names no identity, and Verify refuses it.
type HostIdentity struct {
	Fingerprint string // SHA256 of the subject key
	Algorithm   string // the negotiated host key algorithm
	Certificate bool   // the host presented a certificate
	KeyID       string // the certificate's key ID
	Serial      string // the certificate's serial number, in decimal
	Authority   string // SHA256 of the key that signed the certificate
}

// Valid reports whether the identity is well formed: a SHA256 fingerprint and an algorithm, and for
// a certificate a decimal serial and a SHA256 authority fingerprint.
func (h HostIdentity) Valid() bool {
	if !ValidFingerprint(h.Fingerprint) || h.Algorithm == "" {
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

// identityOf is the identity OpenSSH's trust decision names.
func identityOf(t hostTrust) HostIdentity {
	return HostIdentity{
		Fingerprint: t.fingerprint,
		Algorithm:   t.algorithm,
		Certificate: t.certificate,
		KeyID:       t.keyID,
		Serial:      t.serial,
		Authority:   t.authority,
	}
}
