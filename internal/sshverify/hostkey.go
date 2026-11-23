package sshverify

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
	hostMoved  // the key differs from the one an earlier check of this host presented
)

// errHostMoved stops a handshake whose host key is not the pinned one.
var errHostMoved = errors.New("host key differs from the one checked before the credential was requested")

// hostCheck decides whether the presented host key may be used. It records
// the outcome in the callback, so the caller never has to recognise the
// knownhosts error after the library has wrapped it.
type hostCheck struct {
	verify    ssh.HostKeyCallback // nil when no known_hosts file exists
	trust     string              // SHA256 fingerprint the user confirmed, or ""
	presented ssh.PublicKey
	state     hostState
	// pin is the SHA256 fingerprint the presented key must also match, or "".
	pin string
	// wants is the set of key types known for this host, when the key did
	// not match. It drives one retry with host-key algorithms restricted to
	// those types, so a server that offers several keys is not mistaken for
	// one whose key changed.
	wants []string
	err   error
}

// newHostCheck loads the known_hosts files that exist. Only a file that does not
// exist is skipped. A file that cannot be stat'd, or cannot be parsed, is an error,
// not an empty list, so a broken file cannot quietly turn every host into an unknown
// one, and a changed key cannot then be shown as unknown and trusted.
func newHostCheck(files []string, trust string) (*hostCheck, error) {
	if ambiguousPaths(files) {
		return nil, errKnownHostsAmbiguous
	}
	var present []string
	for _, f := range files {
		_, err := os.Stat(f)
		if err == nil {
			present = append(present, f)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errKnownHostsUnreadable
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

// errKnownHostsAmbiguous is returned when a listed path may be one path split at a space.
// ssh -G prints the list space-separated, so a path with a space arrives as two entries,
// and neither names a file. The listing cannot show where the path ends, so netdoc does
// not guess which files hold the recorded keys.
var errKnownHostsAmbiguous = errors.New("a known_hosts path has a space in it, and the SSH configuration listing does not show where it ends, so netdoc cannot tell which files hold recorded host keys; nothing was sent")

// ambiguousPaths reports whether the listed paths may be one path split at a space. Two
// cases are checked. A run of listed paths joined by single spaces that names an existing
// file is one. A file in the directory of an entry, whose name has the same words under
// any spacing, is another, which covers a name with two spaces in it. An unreadable
// directory that exists is refused too, since its files cannot be ruled out.
// siblingSplits reports whether a directory entry is a path that the listing split at a
// space. Such an entry starts with the token's name, then whitespace, then the start of the
// next token. A name that merely has a space after it, such as "known_hosts copy", does not
// match, because the next token does not begin with "copy". An entry that is the name
// plus spaces only continues with the next token, which must then start a new path.
func siblingSplits(base, next string, entries []os.DirEntry) bool {
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), base)
		if !ok {
			continue
		}
		tail := strings.TrimLeft(rest, " \t")
		if tail == rest {
			continue
		}
		if tail == "" {
			if strings.HasPrefix(next, "/") {
				return true
			}
			continue
		}
		if strings.HasPrefix(next, strings.Fields(tail)[0]) {
			return true
		}
	}
	return false
}

func ambiguousPaths(files []string) bool {
	norm := func(p string) string { return strings.Join(strings.Fields(p), " ") }
	for i := range files {
		if i+1 == len(files) {
			break
		}
		dir := filepath.Dir(files[i])
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return true
		}
		if siblingSplits(filepath.Base(files[i]), files[i+1], entries) {
			return true
		}
		for j := i + 1; j < len(files); j++ {
			run := strings.Join(files[i:j+1], " ")
			if _, err := os.Stat(run); err == nil {
				return true
			}
			for _, e := range entries {
				name := filepath.Join(dir, e.Name())
				if strings.ContainsAny(e.Name(), " \t") && norm(name) == norm(run) {
					return true
				}
			}
		}
	}
	return false
}

// callback is the ssh.HostKeyCallback. It returns an error to stop the
// handshake; nothing after it runs.
func (h *hostCheck) callback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	h.presented = key
	if err := h.decide(hostname, remote, key); err != nil {
		return err
	}
	// The pin is checked after known_hosts, so a server with several host keys
	// still gets the key-type retry; a key that was accepted but is not the one
	// pinned is refused here.
	if h.pin != "" && ssh.FingerprintSHA256(key) != h.pin {
		h.state, h.err = hostMoved, errHostMoved
		return h.err
	}
	return nil
}

// decide is the known_hosts decision for a presented key.
func (h *hostCheck) decide(hostname string, remote net.Addr, key ssh.PublicKey) error {
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
