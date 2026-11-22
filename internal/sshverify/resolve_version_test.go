package sshverify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestAtLeastRevocationFloor asserts the version-comparison policy only. The rows for
// 10.1p1 and 11.0p1 show what the comparison accepts. netdoc's tests do not run those
// releases, so the rows say nothing about runtime compatibility.
func TestAtLeastRevocationFloor(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026", true},
		{"OpenSSH_10.2p1, OpenSSL 3.0.13", true},
		{"OpenSSH_10.1p1, OpenSSL 3.0.13", true},
		{"OpenSSH_10.0p2, OpenSSL 3.0.13", true},
		{"OpenSSH_10.0p1, OpenSSL 3.0.13", false},
		{"OpenSSH_10.0, OpenSSL 3.0.13", false},
		{"OpenSSH_9.9p1 Debian-3", false},
		{"OpenSSH_11.0p1, OpenSSL 3.0.13", true},
		{"", false},
		{"not an ssh version line", false},
	}
	for _, c := range cases {
		if got := atLeastRevocationFloor(c.line); got != c.want {
			t.Errorf("atLeastRevocationFloor(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// fixedListing runs Resolve against a listing and a client version, and returns the error.
func fixedListing(t *testing.T, listing, version string, versionErr error) error {
	t.Helper()
	oldOutput, oldVersion := resolveOutput, clientVersion
	t.Cleanup(func() { resolveOutput, clientVersion = oldOutput, oldVersion })
	resolveOutput = func(context.Context, []string) ([]byte, error) { return []byte(listing), nil }
	clientVersion = func(context.Context) (string, error) { return version, versionErr }
	_, err := Resolve(context.Background(), "target", 0, "")
	return err
}

// The listing an unset RevokedHostKeys produces, with no line for it, is accepted from
// OpenSSH 10.0p2 up by policy. The version strings are stubbed, so these rows assert the
// comparison and the listing rule, not a run of each release. Direct netdoc runs are
// listed in docs/reference.md. Below the floor the line is refused, and the refusal
// names the release it found.
func TestOmittedRevocationLineListingByVersion(t *testing.T) {
	const omitted = "user demo\nhostname 127.0.0.1\nport 2260\n"
	accepted := []string{"OpenSSH_10.0p2, OpenSSL 3.0.13", "OpenSSH_10.2p1, OpenSSL 3.0.13", "OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026"}
	for _, v := range accepted {
		if err := fixedListing(t, omitted, v, nil); err != nil {
			t.Errorf("an omitted RevokedHostKeys line from %q was refused: %v", v, err)
		}
	}
	refused := []string{"OpenSSH_10.0p1, OpenSSL 3.0.13", "OpenSSH_9.9p1 Debian-3"}
	for _, v := range refused {
		err := fixedListing(t, omitted, v, nil)
		if err == nil || !strings.Contains(err.Error(), "older than OpenSSH 10.0p2") {
			t.Errorf("an omitted RevokedHostKeys line from %q: got %v, want a refusal naming the older release", v, err)
		}
	}
	err := fixedListing(t, omitted, "", errors.New("no version"))
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("an omitted RevokedHostKeys line with an unreadable version: got %v, want a refusal that says the version could not be read", err)
	}
	// The refusal describes the version. It must not claim the client never reports the setting.
	for _, err := range []error{
		fixedListing(t, omitted, "OpenSSH_9.9p1 Debian-3", nil),
		fixedListing(t, omitted, "", errors.New("no version")),
	} {
		if err != nil && strings.Contains(err.Error(), "does not report") {
			t.Errorf("the refusal still claims the client does not report RevokedHostKeys: %v", err)
		}
	}
}

// A listing that prints the setting needs no version. A printed none is unset, and a
// printed path is refused whatever the version, so no configured revocation list passes.
func TestPrintedRevocationSettingByVersion(t *testing.T) {
	versions := []string{"OpenSSH_9.9p1 Debian-3", "OpenSSH_10.0p2, OpenSSL 3.0.13", "OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026"}
	host := "user demo\nhostname 127.0.0.1\nport 2260\n"
	for _, v := range versions {
		if err := fixedListing(t, host+"revokedhostkeys none\n", v, errors.New("version must not be asked")); err != nil {
			t.Errorf("a printed RevokedHostKeys none from %q was refused: %v", v, err)
		}
		for _, path := range []string{"/etc/ssh/revoked", "/etc/ssh/a /etc/ssh/b", "./none"} {
			err := fixedListing(t, host+"revokedhostkeys "+path+"\n", v, nil)
			if err == nil || !strings.Contains(err.Error(), "RevokedHostKeys is set") {
				t.Errorf("a configured revocation list %q under %q was not refused: %v", path, v, err)
			}
		}
	}
}

// The installed client's version line must parse, or an omitted line is always refused.
// The floor is not required here, so a system client older than it still passes.
func TestClientVersionReadsTheInstalledRelease(t *testing.T) {
	requireOpenSSH(t)
	line, err := clientVersion(context.Background())
	if err != nil {
		t.Fatalf("the installed client's version was not read: %v", err)
	}
	if !openSSHRelease.MatchString(line) {
		t.Fatalf("the installed client's version line %q names no OpenSSH release", line)
	}
}
