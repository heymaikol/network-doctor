package sshverify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// recordKey writes a known_hosts file at path that records key for the test host.
func recordKey(t *testing.T, path string, key ssh.PublicKey) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	line := knownhosts.Line([]string{"[" + testHost + "]:" + strconv.Itoa(testPort)}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// recordChanged writes a known_hosts file that records a different key for the test host,
// so the server's real key is a change.
func recordChanged(t *testing.T, path string, other Target) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	key, _ := newEd25519(t)
	line := knownhosts.Line([]string{"[" + other.Host + "]:" + strconv.Itoa(other.Port)}, key.PublicKey())
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// testHomeDir is the home directory Resolve gives the parser, so a test parses a listing the
// way production does.
func testHomeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// knownHostsListing is the ssh -G output a configuration produces for the test host, with the
// two known-hosts values given exactly as ssh prints them.
func knownHostsListing(userKH, globalKH string) string {
	return fmt.Sprintf("hostname %s\nport %d\nuser %s\nrevokedhostkeys none\nuserknownhostsfile %s\nglobalknownhostsfile %s\n",
		testHost, testPort, testUser, userKH, globalKH)
}

// verifyFromListing runs a listing through the parser and, if it is accepted, through the check.
// A refused listing returns the parser's error, and nothing is dialed.
func verifyFromListing(s *server, listing, home string) (Result, error) {
	tgt, err := parseConfig([]byte(listing), home)
	if err != nil {
		return Result{}, err
	}
	return Verify(context.Background(), tgt, Attempt{Method: MethodPassword, Password: []byte(testPassword)}, s.options()), nil
}

// expectRefused fails the test unless the listing is refused before anything is dialed, and no
// credential is sent.
func expectRefused(t *testing.T, s *server, listing, home string) {
	t.Helper()
	r, err := verifyFromListing(s, listing, home)
	if err == nil {
		t.Fatalf("the listing was accepted, outcome %q; it must be refused: %s", r.Outcome, strings.ReplaceAll(listing, "\n", " | "))
	}
	if got := s.dials.Load(); got != 0 {
		t.Errorf("a refused listing dialed %d time(s)", got)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent for a refused listing: %d attempt(s)", got)
	}
}

// A listing that ssh prints for a path with a space, or for a list, does not show where each
// name ends. The text is the same whether OpenSSH was given one quoted path or several bare
// paths. Here the first fragment is a real file that holds the server's key and the whole name
// is missing. OpenSSH reads only the whole name, so the key is unknown to it, and netdoc must not
// trust it either.
func TestFragmentOfASpacedNameIsNotTrusted(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	fragment := filepath.Join(dir, "known_hosts")
	recordKey(t, fragment, host.PublicKey())
	expectRefused(t, s, knownHostsListing(fragment+" "+filepath.Join(dir, "missing"), "none"), dir)
}

// A path with a space that exists is refused as well, so that the parser never has to decide
// where the name ends.
func TestSpacedNameThatExistsIsRefused(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordKey(t, filepath.Join(dir, "my hosts"), host.PublicKey())
	expectRefused(t, s, knownHostsListing(filepath.Join(dir, "my hosts"), "none"), dir)
}

// Several custom files are refused, even when the one that matches is a real file. A listing of
// several paths is the same text as one path with a space in it.
func TestSeveralCustomFilesAreRefused(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordKey(t, filepath.Join(dir, "second"), host.PublicKey())
	expectRefused(t, s, knownHostsListing(filepath.Join(dir, "absent")+" "+filepath.Join(dir, "second"), "none"), dir)
}

// ssh prints a value with its padding. A trailing or leading space names another file, so the
// padded value is refused rather than trimmed to a file that exists.
func TestPaddedNameIsRefused(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	existing := filepath.Join(dir, "known_hosts")
	recordKey(t, existing, host.PublicKey())
	expectRefused(t, s, knownHostsListing(existing+"  ", "none"), dir)
	expectRefused(t, s, knownHostsListing(" "+existing, "none"), dir)
}

// A single custom file is read as before: a matching key is trusted, and the password is sent once.
func TestSingleCustomFileWithTheServersKeyIsTrusted(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	path := filepath.Join(dir, "known_hosts")
	recordKey(t, path, host.PublicKey())
	r, err := verifyFromListing(s, knownHostsListing(path, "none"), dir)
	if err != nil {
		t.Fatalf("a single file was refused: %v", err)
	}
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 1 {
		t.Fatalf("password attempts = %d, want 1", got)
	}
}

// A changed key in a single custom file is refused before any credential is sent.
func TestSingleCustomFileWithAChangedKeySendsNothing(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	path := filepath.Join(dir, "known_hosts")
	recordChanged(t, path, target())
	r, err := verifyFromListing(s, knownHostsListing(path, "none"), dir)
	if err != nil {
		t.Fatalf("a single file was refused: %v", err)
	}
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want a changed key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a changed key: %d attempts", got)
	}
}

// A single custom file that does not exist records no key, so the key is unknown and nothing is sent.
func TestSingleMissingCustomFileSendsNothing(t *testing.T) {
	dir := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	r, err := verifyFromListing(s, knownHostsListing(filepath.Join(dir, "absent"), "none"), dir)
	if err != nil {
		t.Fatalf("a single file was refused: %v", err)
	}
	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q, want an unknown key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with no recorded key: %d attempts", got)
	}
}

// A file that exists but cannot be read is refused. Its recorded key is not read as unknown,
// and no credential is sent. File modes do not restrict reads on Windows, and root reads any file.
func TestUnreadableSingleFileIsRefused(t *testing.T) {
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
	recordKey(t, path, host.PublicKey())
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	r, err := verifyFromListing(s, knownHostsListing(path, "none"), dir)
	if err != nil {
		t.Fatalf("a single file was refused by the parser: %v", err)
	}
	if r.Outcome != LocalFailure {
		t.Fatalf("outcome = %q, want the file refused; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with an unreadable known_hosts file: %d attempts", got)
	}
}

// OpenSSH's default pair is accepted. Its second file holds the key, which the first one does not.
func TestDefaultPairReadsBothFiles(t *testing.T) {
	home := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordKey(t, filepath.Join(home, ".ssh", "known_hosts2"), host.PublicKey())
	pair := strings.Join([]string{filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2")}, " ")
	r, err := verifyFromListing(s, knownHostsListing(pair, "none"), home)
	if err != nil {
		t.Fatalf("the default pair was refused: %v", err)
	}
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified from the second default file; detail %q", r.Outcome, r.Detail)
	}
}

// A changed key in the default pair is refused before any credential is sent.
func TestDefaultPairWithAChangedKeySendsNothing(t *testing.T) {
	home := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordChanged(t, filepath.Join(home, ".ssh", "known_hosts"), target())
	pair := strings.Join([]string{filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2")}, " ")
	r, err := verifyFromListing(s, knownHostsListing(pair, "none"), home)
	if err != nil {
		t.Fatalf("the default pair was refused: %v", err)
	}
	if r.Outcome != HostKeyChanged {
		t.Fatalf("outcome = %q, want a changed key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent to a changed key: %d attempts", got)
	}
}

// With neither default file present, the key is unknown and nothing is sent.
func TestDefaultPairWithNoFilesSendsNothing(t *testing.T) {
	home := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	pair := strings.Join([]string{filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2")}, " ")
	r, err := verifyFromListing(s, knownHostsListing(pair, "none"), home)
	if err != nil {
		t.Fatalf("the default pair was refused: %v", err)
	}
	if r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q, want an unknown key; detail %q", r.Outcome, r.Detail)
	}
	if got := s.password.Load(); got != 0 {
		t.Errorf("a credential was sent with no recorded key: %d attempts", got)
	}
}

// A home directory with a space is still the default, so its pair is accepted.
func TestDefaultPairInAHomeWithASpaceIsAccepted(t *testing.T) {
	home := filepath.Join(t.TempDir(), "my home")
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordKey(t, filepath.Join(home, ".ssh", "known_hosts2"), host.PublicKey())
	pair := strings.Join([]string{filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2")}, " ")
	r, err := verifyFromListing(s, knownHostsListing(pair, "none"), home)
	if err != nil {
		t.Fatalf("the default pair in a spaced home was refused: %v", err)
	}
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
}

// A file named like a default file, with a space and a word after it, is not part of the default
// pair. The default pair still reads its own files, and the copy is not read.
func TestCopyBesideTheDefaultFilesIsNotARefusal(t *testing.T) {
	home := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	recordKey(t, filepath.Join(home, ".ssh", "known_hosts2"), host.PublicKey())
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts copy"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pair := strings.Join([]string{filepath.Join(home, ".ssh", "known_hosts"), filepath.Join(home, ".ssh", "known_hosts2")}, " ")
	r, err := verifyFromListing(s, knownHostsListing(pair, "none"), home)
	if err != nil {
		t.Fatalf("the default pair was refused because of a copy beside it: %v", err)
	}
	if r.Outcome != Verified {
		t.Fatalf("outcome = %q, want verified; detail %q", r.Outcome, r.Detail)
	}
}

// A pair that differs from the built-in one, by a space or by order, is refused.
func TestNearlyTheDefaultPairIsRefused(t *testing.T) {
	home := t.TempDir()
	host, _ := newEd25519(t)
	s := passwordServer(host)
	kh := filepath.Join(home, ".ssh", "known_hosts")
	kh2 := filepath.Join(home, ".ssh", "known_hosts2")
	expectRefused(t, s, knownHostsListing(kh+"  "+kh2, "none"), home)
	expectRefused(t, s, knownHostsListing(kh2+" "+kh, "none"), home)
}

// A custom global list is refused for the same reason as a custom user list.
func TestCustomGlobalListIsRefused(t *testing.T) {
	if _, err := parseConfig([]byte(knownHostsListing("none", "/etc/ssh/ssh_known_hosts /etc/ssh/extra")), ""); err == nil {
		t.Fatal("a custom global list of two files was accepted")
	}
}

// The built-in global pair is accepted, whether or not its files exist.
func TestBuiltinGlobalPairIsAccepted(t *testing.T) {
	tgt, err := parseConfig([]byte(knownHostsListing("none", "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2")), "")
	if err != nil {
		t.Fatalf("the built-in global pair was refused: %v", err)
	}
	if len(tgt.GlobalHosts) != 2 {
		t.Fatalf("global files = %q, want the built-in pair", tgt.GlobalHosts)
	}
}

// A listing without one of the keywords is refused, and so is a listing that names both.
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

// ssh expands some known-hosts tokens only when it connects, and the printed global value keeps
// them. A value with %, $ or a leading ~ is refused for either keyword, so netdoc never reads a
// file it cannot match to the one OpenSSH reads.
func TestPathsWithExpansionTokensAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, userKH, globalKH string }{
		{"user percent token", "/tmp/kh/%k", "none"},
		{"user dollar", "$HOME/kh", "none"},
		{"global leading tilde", "none", "~/gk"},
		{"global percent d", "none", "%d/gk"},
		{"global percent h", "none", "/etc/ssh/%h_kh"},
		{"global dollar brace", "none", "${HOME}/gk"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseConfig([]byte(knownHostsListing(tc.userKH, tc.globalKH)), testHomeDir()); err == nil {
				t.Fatal("a value with an expansion token was accepted")
			}
		})
	}
}

// Resolve reads its listing through the same parser, so the refusal holds on the real path.
func TestResolveRefusesExpansionTokens(t *testing.T) {
	saved := resolveOutput
	t.Cleanup(func() { resolveOutput = saved })
	resolveOutput = func(context.Context, []string) ([]byte, error) {
		return []byte(knownHostsListing("none", "~/gk")), nil
	}
	if _, err := Resolve(context.Background(), testHost, testPort, testUser); err == nil {
		t.Fatal("Resolve accepted a global value with a leading ~")
	}
}
