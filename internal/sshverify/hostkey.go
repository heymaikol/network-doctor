package sshverify

import (
	"errors"
	"net"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostState is what the host-key check concluded for the key the server
// presented. Every state other than hostTrusted and hostTrustedForCheck stops
// the attempt before any credential is sent.
type hostState int

const (
	hostNotChecked      hostState = iota // the handshake never reached the host key
	hostTrusted                          // the key matched known_hosts
	hostTrustedForCheck                  // unknown key, confirmed by the user for this check only
	hostUnknown
	hostChanged
	hostRevoked
	hostFailed // known_hosts could not be used at all
)

// hostCheck decides whether the presented host key may be used. It records
// the outcome in the callback, so the caller never has to recognise the
// knownhosts error after the library has wrapped it.
type hostCheck struct {
	verify    ssh.HostKeyCallback // nil when no known_hosts file exists
	trust     string              // SHA256 fingerprint the user confirmed, or ""
	presented ssh.PublicKey
	state     hostState
	// wants is the set of key types known for this host, when the key did
	// not match. It drives one retry with host-key algorithms restricted to
	// those types, so a server that offers several keys is not mistaken for
	// one whose key changed.
	wants []string
	err   error
}

// newHostCheck loads the known_hosts files that exist. A file that exists but
// cannot be parsed is an error, not an empty list, so a broken file cannot
// quietly turn every host into an unknown one.
func newHostCheck(files []string, trust string) (*hostCheck, error) {
	var present []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			present = append(present, f)
		}
	}
	h := &hostCheck{trust: trust}
	if len(present) == 0 {
		return h, nil
	}
	verify, err := knownhosts.New(present...)
	if err != nil {
		return nil, errKnownHostsUnreadable
	}
	h.verify = verify
	return h, nil
}

var errKnownHostsUnreadable = errors.New("a known_hosts file could not be read")

// callback is the ssh.HostKeyCallback. It returns an error to stop the
// handshake; nothing after it runs.
func (h *hostCheck) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	h.presented = key
	if h.verify == nil {
		return h.unknown(key)
	}
	err := h.verify(hostname, remote, key)
	if err == nil {
		h.state = hostTrusted
		return nil
	}
	var revoked *knownhosts.RevokedError
	var mismatch *knownhosts.KeyError
	switch {
	case errors.As(err, &revoked):
		h.state, h.err = hostRevoked, err
	case errors.As(err, &mismatch) && len(mismatch.Want) == 0:
		return h.unknown(key)
	case errors.As(err, &mismatch):
		h.state, h.err = hostChanged, err
		h.wants = knownTypes(mismatch)
	default:
		h.state, h.err = hostFailed, err
	}
	return err
}

// unknown handles a key with no entry in any known_hosts file. The key is
// accepted for this check only when the user confirmed its exact fingerprint;
// nothing is written to a file.
func (h *hostCheck) unknown(key ssh.PublicKey) error {
	if h.trust != "" && ssh.FingerprintSHA256(key) == h.trust {
		h.state = hostTrustedForCheck
		return nil
	}
	h.state = hostUnknown
	h.err = errHostUnknown
	return h.err
}

var errHostUnknown = errors.New("host key is not in known_hosts")

// knownTypes lists the key types recorded for the host.
func knownTypes(mismatch *knownhosts.KeyError) []string {
	var types []string
	for _, k := range mismatch.Want {
		types = append(types, k.Key.Type())
	}
	return slices.Compact(slices.Sorted(slices.Values(types)))
}

// hostKeyAlgorithms turns recorded key types into the names the handshake
// negotiates. An ssh-rsa key is negotiated as rsa-sha2-512 or rsa-sha2-256.
func hostKeyAlgorithms(types []string) []string {
	var algos []string
	for _, t := range types {
		if t == ssh.KeyAlgoRSA {
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
			continue
		}
		algos = append(algos, t)
	}
	return slices.Compact(slices.Sorted(slices.Values(algos)))
}

// needsRetry reports whether a mismatch can be a negotiation artifact: the
// host has known keys, and the presented key is of a type it does not have.
// Only the first handshake retries; a second mismatch is a real change.
func (h *hostCheck) needsRetry(restricted bool) bool {
	if restricted || h.state != hostChanged || len(h.wants) == 0 || h.presented == nil {
		return false
	}
	return !slices.Contains(h.wants, h.presented.Type())
}
