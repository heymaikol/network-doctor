package sshverify

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// A key ID with a tab or a carriage return is not text OpenSSH prints on one line, so the record is
// refused by the parser rather than handed on to the pin check.
func TestCertificateRecordWithControlCharacterInKeyIDIsRefused(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())
	for _, keyID := range []string{"prod\ttab", "prod\rcr"} {
		transcript := trustedCertTranscript(t, subject, keyID, ca.PublicKey())
		if _, ok, _ := parseHostTrust([]byte(transcript), 255); ok {
			t.Fatalf("a key ID with a control character (%q) was accepted as trust evidence", keyID)
		}
	}
}

// OpenSSH cuts a record that is too long to print. A key ID whose record reaches the cut can end in
// a validity phrase the server chose, so the record is refused. A short record of the same shape is
// the control.
func TestTruncatedCertificateRecordIsRefused(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())

	long := strings.Repeat("a", 990) + " valid forever"
	transcript := trustedCertTranscript(t, subject, long, ca.PublicKey())
	if _, ok, _ := parseHostTrust([]byte(transcript), 255); ok {
		t.Fatal("a certificate record at the length OpenSSH cuts was accepted as trust evidence")
	}

	short := trustedCertTranscript(t, subject, "hostcert-short", ca.PublicKey())
	if _, ok, r := parseHostTrust([]byte(short), 255); !ok {
		t.Fatalf("the control record of ordinary length was refused: %+v", r)
	}
}

// The authority fingerprint is a SHA256 fingerprint. A record that names anything else is malformed.
func TestCertificateRecordWithMalformedAuthorityIsRefused(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	base := trustedCertTranscript(t, ssh.FingerprintSHA256(host.PublicKey()), "hostcert-x", ca.PublicKey())
	bad := strings.Replace(base, ssh.FingerprintSHA256(ca.PublicKey()), "SHA256:short", 1)
	if bad == base {
		t.Fatal("the test did not change the authority fingerprint")
	}
	if _, ok, _ := parseHostTrust([]byte(bad), 255); ok {
		t.Fatal("a certificate record with a malformed authority fingerprint was accepted")
	}
}

// The credential connection must present the certificate OpenSSH checked: the same serial, and the
// same authority. Two certificates for one subject key are different identities.
func TestPinRefusesACertificateWithAnotherSerialOrAuthority(t *testing.T) {
	ca, _ := newEd25519(t)
	otherCA, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())
	pin := pinCheck{fingerprint: subject, certificate: true, keyID: "hostcert", serial: "0", authority: ssh.FingerprintSHA256(ca.PublicKey())}

	cert := func(serial uint64, signer ssh.PublicKey) *ssh.Certificate {
		return &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, KeyId: "hostcert", Serial: serial, SignatureKey: signer}
	}
	control := pin
	if err := control.callback("", nil, cert(0, ca.PublicKey())); err != nil {
		t.Fatalf("the checked certificate was refused: %v", err)
	}
	another := pin
	if err := another.callback("", nil, cert(7, ca.PublicKey())); err == nil {
		t.Fatal("a certificate with another serial was admitted")
	}
	foreign := pin
	if err := foreign.callback("", nil, cert(0, otherCA.PublicKey())); err == nil {
		t.Fatal("a certificate from another authority was admitted")
	}
}
