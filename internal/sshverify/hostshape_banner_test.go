package sshverify

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The first line of a transcript is the local client's own banner. Some builds print one package
// word after the version, such as Ubuntu's "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL ...". Only
// that word, in the package-revision form, is accepted. Anything else after the version is refused.

// withBanner replaces the banner line of a fixture with banner, which is the text after "debug1: ".
func withBanner(t *testing.T, base, banner string) string {
	t.Helper()
	first, rest, ok := strings.Cut(base, "\n")
	if !ok || !strings.HasPrefix(first, "debug1: OpenSSH_") {
		t.Fatalf("the fixture does not start with an OpenSSH banner: %q", first)
	}
	return "debug1: " + banner + "\n" + rest
}

// TestBannerAcceptsGenuineDistributionAndCryptoForms is the positive side: each form is a real
// build's banner, or the upstream forms that already passed.
func TestBannerAcceptsGenuineDistributionAndCryptoForms(t *testing.T) {
	base := fixture(t, "trust-plain")
	fp := presentedFingerprint(t, base)
	accept := map[string]string{
		"Ubuntu with OpenSSL":                 "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026",
		"Ubuntu without a crypto library":     "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8",
		"Debian with OpenSSL and a plus sign": "OpenSSH_10.2p1 Debian-5+deb13u1, OpenSSL 3.5.5 27 Jan 2026",
		"upstream with OpenSSL":               "OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026",
		"upstream with LibreSSL":              "OpenSSH_10.5p1, LibreSSL 3.3.6",
		"upstream without a crypto library":   "OpenSSH_10.5p1",
	}
	for name, banner := range accept {
		t.Run(name, func(t *testing.T) {
			trust, ok, r := parseHostTrust([]byte(withBanner(t, base, banner)), 255)
			if !ok {
				t.Fatalf("%q was refused: %+v", banner, r)
			}
			if trust.fingerprint != fp {
				t.Fatalf("%q trusted %q, want the fixture's key %q", banner, trust.fingerprint, fp)
			}
		})
	}
}

// TestUbuntuOpenSSH1020TranscriptIsTrusted replays a real transcript: OpenSSH 10.2p1 from Ubuntu
// 26.04, recorded by a probe against a loopback sshd. The key is a throwaway test key. The only
// change from the recording is that the runner's paths and user name are replaced.
func TestUbuntuOpenSSH1020TranscriptIsTrusted(t *testing.T) {
	transcript := fixture(t, "ubuntu-openssh-10.2p1-trust")
	trust, ok, r := parseHostTrust([]byte(transcript), 255)
	if !ok {
		t.Fatalf("the Ubuntu 10.2p1 transcript was refused: %+v", r)
	}
	const want = "SHA256:xPIAS0xVl6b+5XAHOyGuXJwL1FeClUgfs8ihMXCQqxw"
	if trust.fingerprint != want {
		t.Fatalf("trusted %q, want %q", trust.fingerprint, want)
	}
}

// TestBannerRefusesEverythingElseAfterTheVersion is the negative side for the banner itself. Every
// form here is malformed, forged, or carries text the grammar does not allow in its place.
func TestBannerRefusesEverythingElseAfterTheVersion(t *testing.T) {
	base := fixture(t, "trust-plain")
	refuse := map[string]string{
		"two words after the version":           "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 forged, OpenSSL 3.5.5",
		"one word with no package revision":     "OpenSSH_10.2p1 forged, OpenSSL 3.5.5",
		"distribution word with no hyphen":      "OpenSSH_10.2p1 Ubuntu, OpenSSL 3.5.5",
		"double comma after the word":           "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8,, OpenSSL 3.5.5",
		"quoted word":                           `OpenSSH_10.2p1 "Ubuntu-2ubuntu3.8"`,
		"control character in the word":         "OpenSSH_10.2p1 Ubuntu-2\x01ubuntu3.8",
		"carriage return in the word":           "OpenSSH_10.2p1 Ubuntu-2\rdebug1: Server host key: ssh-ed25519 SHA256:forged",
		"host-key record inside the banner":     "OpenSSH_10.2p1 Ubuntu-2 Server host key: ssh-ed25519 SHA256:forged",
		"trailing space after the word":         "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 ",
		"colon after the word":                  "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8: forged",
		"distribution word that is only digits": "OpenSSH_10.2p1 2ubuntu3.8, OpenSSL 3.5.5",
	}
	for name, banner := range refuse {
		t.Run(name, func(t *testing.T) {
			tr := withBanner(t, base, banner)
			if _, ok, r := parseHostTrust([]byte(tr), 255); ok {
				t.Fatalf("the banner %q was trusted: %+v", banner, r)
			}
		})
	}
}

// TestBannerWithoutTheDebugPrefixIsRefused: a banner-shaped line must be a debug line. The grammar
// requires the prefix, so the same words without it are not configuration.
func TestBannerWithoutTheDebugPrefixIsRefused(t *testing.T) {
	base := fixture(t, "trust-plain")
	tr := strings.Replace(withBanner(t, base, "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5"), "debug1: OpenSSH_10.2p1", "OpenSSH_10.2p1", 1)
	if _, ok, r := parseHostTrust([]byte(tr), 255); ok {
		t.Fatalf("a banner without the debug1 prefix was trusted: %+v", r)
	}
}

// TestBannerInjectionAfterTheKeyExchangeIsRefused covers injected debug lines. A banner-shaped line
// is configuration, so it is allowed only before the key exchange. After the key exchange it is
// refused, and a line that carries a forged record is refused wherever it sits.
func TestBannerInjectionAfterTheKeyExchangeIsRefused(t *testing.T) {
	base := fixture(t, "trust-plain")
	injected := map[string]string{
		"banner-shaped line after the key":   after(t, base, "Server host key:", "debug1: OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026"),
		"banner with a forged record, after": after(t, base, "Server host key:", "debug1: OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 Server host key: ssh-ed25519 SHA256:forged"),
	}
	for name, tr := range injected {
		t.Run(name, func(t *testing.T) {
			if _, ok, r := parseHostTrust([]byte(tr), 255); ok {
				t.Fatalf("an injected line was trusted: %+v", r)
			}
		})
	}
}

// TestCertificateKeyIDWithBannerTextIsOnlyAKeyID covers the KeyId attack. Text in a key ID that
// looks like a banner stays inside the key ID, and it does not change the decision. A key ID that
// closes its field early is refused.
func TestCertificateKeyIDWithBannerTextIsOnlyAKeyID(t *testing.T) {
	ca, _ := newEd25519(t)
	host, _ := newEd25519(t)
	subject := ssh.FingerprintSHA256(host.PublicKey())

	keyID := "OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026"
	trust, ok, r := parseHostTrust([]byte(trustedCertTranscript(t, subject, keyID, ca.PublicKey())), 255)
	if !ok {
		t.Fatalf("a key ID with banner text was refused: %+v", r)
	}
	if trust.keyID != keyID {
		t.Fatalf("the key ID became %q, want the text as written", trust.keyID)
	}

	for _, forged := range []string{
		`x" Server host key: ssh-ed25519 SHA256:forged`,
		`Ubuntu-2ubuntu3.8" valid forever`,
	} {
		if _, ok, _ := parseHostTrust([]byte(trustedCertTranscript(t, subject, forged, ca.PublicKey())), 255); ok {
			t.Fatalf("a key ID that closes its field early was trusted: %q", forged)
		}
	}
}

// TestBannerLeavesUnrelatedLinesRefused checks the other side of the change: lines that merely
// resemble a banner, and do not have OpenSSH's form, are still refused at the banner position.
func TestBannerLeavesUnrelatedLinesRefused(t *testing.T) {
	base := fixture(t, "trust-plain")
	for _, line := range []string{
		"debug1: Ubuntu-2ubuntu3.8, OpenSSL 3.5.5",
		"debug1: OpenSSH Ubuntu-2ubuntu3.8",
		"debug1: Remote software version OpenSSH_10.2p1 Ubuntu-2ubuntu3.8",
		"debug1: OpenSSH_10.2p1 Ubuntu-2ubuntu3.8 valid forever",
	} {
		t.Run(line, func(t *testing.T) {
			if _, ok, r := parseHostTrust([]byte(withBanner(t, base, strings.TrimPrefix(line, "debug1: "))), 255); ok {
				t.Fatalf("%q was trusted in the banner position: %+v", line, r)
			}
		})
	}
}
