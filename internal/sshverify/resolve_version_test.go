package sshverify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAtLeastRevocationFloor(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026", true},
		{"OpenSSH_10.2p1, OpenSSL 3.0.13", true},
		{"OpenSSH_11.0p1, OpenSSL 3.0.13", true},
		{"OpenSSH_10.1p1, OpenSSL 3.0.13", false},
		{"OpenSSH_9.9p1 Debian-3", false},
		{"", false},
		{"not an ssh version line", false},
	}
	for _, c := range cases {
		if got := atLeastRevocationFloor(c.line); got != c.want {
			t.Errorf("atLeastRevocationFloor(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// Only a listing that leaves RevokedHostKeys out depends on the client's version. From
// the floor up it is unset; below it, or with no known version, the read is refused.
func TestResolveOmittedRevocationLineNeedsTheFloor(t *testing.T) {
	oldOutput, oldVersion := resolveOutput, clientVersion
	t.Cleanup(func() { resolveOutput, clientVersion = oldOutput, oldVersion })
	listing := []byte("user demo\nhostname 127.0.0.1\nport 2260\n")
	resolveOutput = func(context.Context, []string) ([]byte, error) { return listing, nil }
	refused := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "does not report RevokedHostKeys")
	}

	clientVersion = func(context.Context) (string, error) { return "OpenSSH_10.1p1, OpenSSL 3.0.13", nil }
	if _, err := Resolve(context.Background(), "target", 0, ""); !refused(err) {
		t.Fatalf("an omitted RevokedHostKeys line from OpenSSH 10.1p1 was not refused: %v", err)
	}

	clientVersion = func(context.Context) (string, error) { return "", errors.New("no version") }
	if _, err := Resolve(context.Background(), "target", 0, ""); !refused(err) {
		t.Fatalf("an omitted RevokedHostKeys line with an unknown client version was not refused: %v", err)
	}

	// The positive control: the floor itself accepts the omitted line.
	clientVersion = func(context.Context) (string, error) { return "OpenSSH_10.2p1, OpenSSL 3.0.13", nil }
	if _, err := Resolve(context.Background(), "target", 0, ""); err != nil {
		t.Fatalf("an omitted RevokedHostKeys line from OpenSSH 10.2p1 was refused: %v", err)
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

// A listing that prints the setting, as none, needs no version: it is set, and not refused.
func TestResolvePrintedNoneNeedsNoVersion(t *testing.T) {
	oldOutput, oldVersion := resolveOutput, clientVersion
	t.Cleanup(func() { resolveOutput, clientVersion = oldOutput, oldVersion })
	resolveOutput = func(context.Context, []string) ([]byte, error) {
		return []byte("user demo\nhostname 127.0.0.1\nport 2260\nrevokedhostkeys none\n"), nil
	}
	clientVersion = func(context.Context) (string, error) {
		t.Fatal("the client version was asked for a listing that prints the setting")
		return "", nil
	}
	if _, err := Resolve(context.Background(), "target", 0, ""); err != nil {
		t.Fatalf("a printed RevokedHostKeys none was refused: %v", err)
	}
}
