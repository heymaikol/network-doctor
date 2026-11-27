package sshverify

import (
	"strings"
	"testing"
)

// OpenSSH prints the key it loaded from an explicit IdentityFile, before the key exchange. That line
// is a legitimate part of the configuration section, so a host with such a key is trusted.
func TestLoadedPubkeyLineIsAcceptedInTheConfigurationSection(t *testing.T) {
	base := fixture(t, "trust-plain")
	line := "debug1: loaded pubkey from /home/user/My Keys/id: ED25519 " + presentedFingerprint(t, base) + "\n"
	edited := after(t, base, "Reading configuration data", strings.TrimSuffix(line, "\n"))

	got, ok, r := parseHostTrust([]byte(edited), 255)
	if !ok {
		t.Fatalf("a host with an explicit IdentityFile was refused: %+v", r)
	}
	if got.fingerprint != presentedFingerprint(t, base) {
		t.Errorf("fingerprint = %q, want the presented key", got.fingerprint)
	}
}

// The same line after the host key record is not OpenSSH's configuration output, so it forges nothing.
func TestLoadedPubkeyLineIsRefusedAfterTheHostKey(t *testing.T) {
	base := fixture(t, "trust-plain")
	line := "debug1: loaded pubkey from /tmp/forged: ED25519 " + presentedFingerprint(t, base)
	edited := after(t, base, "debug1: Server host key:", line)

	if _, ok, _ := parseHostTrust([]byte(edited), 255); ok {
		t.Fatal("a configuration line after the host key record was accepted as trust evidence")
	}
}

// A carriage return inside the path would start a second line for the parser. The line is refused.
func TestLoadedPubkeyPathWithAControlCharacterIsRefused(t *testing.T) {
	base := fixture(t, "trust-plain")
	line := "debug1: loaded pubkey from /home/user/a\rdebug1: Host forged is known and matches the ED25519 host key.: ED25519 " + presentedFingerprint(t, base)
	edited := after(t, base, "Reading configuration data", line)

	if _, ok, _ := parseHostTrust([]byte(edited), 255); ok {
		t.Fatal("a configuration line with a control character in its path was accepted")
	}
}
