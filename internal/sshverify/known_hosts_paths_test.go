package sshverify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// recordChanged writes a known_hosts file that records a different key for the test host,
// so the server's real key is a change.
func recordChanged(t *testing.T, path string, other Target) {
	t.Helper()
	key, _ := newEd25519(t)
	line := knownhosts.Line([]string{"[" + other.Host + "]:" + strconv.Itoa(other.Port)}, key.PublicKey())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A path with a space arrives in the listing as two entries. Neither names the file, and
// the recorded change in that file must not be read as an unknown key.
func TestSpacedKnownHostsPathIsRefusedNotReadAsUnknown(t *testing.T) {
	for _, tc := range []struct{ name, value, file string }{
		{"one space", "%s/my hosts", "my hosts"},
		{"two spaces", "%s/my  hosts", "my  hosts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			host, _ := newEd25519(t)
			s := passwordServer(host)
			recordChanged(t, filepath.Join(dir, tc.file), target())
			tokens := splitPaths(fmt.Sprintf(tc.value, dir), "")

			r := Verify(context.Background(), target(tokens...), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
			if r.Outcome == HostKeyUnknown {
				t.Fatalf("a changed key in a spaced file was read as unknown; detail %q", r.Detail)
			}
			if r.Outcome != LocalFailure {
				t.Fatalf("outcome = %q, want the path refused; detail %q", r.Outcome, r.Detail)
			}
			if got := s.password.Load(); got != 0 {
				t.Errorf("a credential was sent with an ambiguous known_hosts list: %d attempts", got)
			}
		})
	}
}

// Ordinary paths are read as before: a changed key in a readable file is a change, and a
// missing file is not an error.
func TestOrdinaryKnownHostsPathsAreRead(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	ordinary := filepath.Join(dir, "known_hosts")
	recordChanged(t, ordinary, target())

	tokens := []string{filepath.Join(dir, "missing"), ordinary}
	r := Verify(context.Background(), target(tokens...), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want a changed key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a changed key: %d attempts", got)
	}
}

// With several files, one spaced path among ordinary ones still refuses the list. The
// ordinary file is not read on its own, because the list cannot be trusted as a whole.
func TestSpacedPathAmongSeveralFilesRefusesTheList(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordChanged(t, filepath.Join(dir, "known_hosts"), target())
	recordChanged(t, filepath.Join(dir, "my hosts"), target())

	tokens := splitPaths(filepath.Join(dir, "known_hosts")+" "+filepath.Join(dir, "my hosts"), "")
	r := Verify(context.Background(), target(tokens...), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != LocalFailure {
		t.Fatalf("outcome = %q, want the list refused; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with an ambiguous known_hosts list: %d attempts", got)
	}
}

// A listing without UserKnownHostsFile or GlobalKnownHostsFile cannot say which files hold
// recorded keys, so it is refused. A listing that names both is read.
func TestListingWithoutAKnownHostsKeywordIsRefused(t *testing.T) {
	base := "user u\nhostname h\nport 22\nrevokedhostkeys none\n"
	for _, tc := range []struct {
		name, extra string
		refused     bool
	}{
		{"both keywords", "userknownhostsfile none\nglobalknownhostsfile none\n", false},
		{"user keyword omitted", "globalknownhostsfile none\n", true},
		{"global keyword omitted", "userknownhostsfile none\n", true},
		{"both omitted", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig([]byte(base+tc.extra), "")
			if tc.refused && err == nil {
				t.Fatal("a listing without a known-hosts keyword was accepted")
			}
			if !tc.refused && err != nil {
				t.Fatalf("a complete listing was refused: %v", err)
			}
		})
	}
}

// A directory whose name has two spaces splits the listing into a token that names no file.
// The changed key inside it must not be read as unknown.
func TestSpacedDirectoryWithTwoSpacesIsRefused(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	nested := filepath.Join(dir, "a  b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	recordChanged(t, filepath.Join(nested, "known_hosts"), target())
	tokens := splitPaths(filepath.Join(nested, "known_hosts"), "")

	r := Verify(context.Background(), target(tokens...), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome == HostKeyUnknown {
		t.Fatalf("a changed key under a two-space directory was read as unknown; detail %q", r.Detail)
	}
	if r.Outcome != LocalFailure {
		t.Fatalf("outcome = %q, want the list refused; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with an ambiguous known_hosts list: %d attempts", got)
	}
}

// A file that exists but cannot be read is refused. Its recorded key is not read as unknown,
// and no credential is sent. File modes do not restrict reads on Windows, and root reads any file.
func TestUnreadableKnownHostsFileIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not restrict reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its mode")
	}
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	path := filepath.Join(dir, "known_hosts")
	recordChanged(t, path, target())
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	r := Verify(context.Background(), target(path), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome == HostKeyUnknown {
		t.Fatalf("a changed key in an unreadable file was read as unknown; detail %q", r.Detail)
	}
	if r.Outcome != LocalFailure {
		t.Fatalf("outcome = %q, want the file refused; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with an unreadable known_hosts file: %d attempts", got)
	}
}

// A file named like a listed token, with a suffix that is not a split path, is an ordinary
// file. The listing of two ordinary files is read, and the changed key in it is reported.
func TestSpacedCopyBesideOrdinaryFilesIsNotASplit(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	ordinary := filepath.Join(dir, "known_hosts")
	recordChanged(t, ordinary, target())
	if err := os.WriteFile(filepath.Join(dir, "known_hosts copy"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "known_hosts2")
	if err := os.WriteFile(second, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	r := Verify(context.Background(), target(ordinary, second), Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options())
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want a changed key: a copy's name is not a split path; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a changed key: %d attempts", got)
	}
}
