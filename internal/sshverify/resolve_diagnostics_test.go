package sshverify

import (
	"strings"
	"testing"
)

const testReading = "debug1: Reading configuration data /etc/ssh/ssh_config\n"
const testExec = "debug1: Executing command: 'true'\n"

// capOf builds one complete read by hand, so each rule is tested without a client.
func capOf(diag, listing string, files map[string]string) capture {
	c := capture{diag: []byte(diag), listing: []byte(listing)}
	for name, body := range files {
		c.files = append(c.files, name)
		c.contents = append(c.contents, []byte(body))
	}
	return c
}

const cleanListing = "hostname 127.0.0.1\nport 22\nuser demo\nproxyjump none\n"

// The classifier accepts a clean read and refuses each rule that cannot be matched.
func TestClassifyRefusesWhatItCannotMatch(t *testing.T) {
	cases := []struct {
		name     string
		c        capture
		headless bool
		want     RouteKind
		reason   string
	}{
		{"clean read is direct", capOf(testReading, cleanListing, map[string]string{"/etc/ssh/ssh_config": "Host x\n"}), true, RouteDirect, ""},
		{"exec marker in the diagnostics", capOf(testReading+testExec, cleanListing, map[string]string{"/c": "Host x\n"}), false, RouteUnknown, "Match exec command runs"},
		{"exec test in a file", capOf(testReading, cleanListing, map[string]string{"/c": "Match host x exec true\n"}), false, RouteUnknown, "Match exec test"},
		{"dollar outside a comment, headless", capOf(testReading, cleanListing, map[string]string{"/c": "IdentityAgent ${SSH_AUTH_SOCK}\n"}), true, RouteUnknown, "environment variable"},
		{"dollar outside a comment, terminal", capOf(testReading, cleanListing, map[string]string{"/c": "IdentityAgent ${SSH_AUTH_SOCK}\n"}), false, RouteDirect, ""},
		{"dollar in an Include, terminal", capOf(testReading, cleanListing, map[string]string{"/c": "Include /d/${FOO}.conf\n"}), false, RouteUnknown, "Include uses an environment variable"},
		{"dollar in an Include, headless", capOf(testReading, cleanListing, map[string]string{"/c": "Include /d/${FOO}.conf\n"}), true, RouteUnknown, "Include uses an environment variable"},
		{"dollar in a full-line comment", capOf(testReading, cleanListing, map[string]string{"/c": "# $OpenBSD: ssh_config\n"}), true, RouteDirect, ""},
		{"KnownHostsCommand in the listing", capOf(testReading, "hostname x\nknownhostscommand touch /t\n", map[string]string{"/c": "Host x\n"}), false, RouteUnknown, "KnownHostsCommand"},
		{"KnownHostsCommand none is not a command", capOf(testReading, "hostname x\nknownhostscommand none\n", map[string]string{"/c": "Host x\n"}), false, RouteDirect, ""},
		{"ProxyJump in the listing is proxied", capOf(testReading, "hostname x\nproxyjump bastion\n", map[string]string{"/c": "Host x\n"}), true, RouteProxied, ""},
		{"ProxyCommand in the listing is proxied", capOf(testReading, "hostname x\nproxycommand nc %h %p\n", map[string]string{"/c": "Host x\n"}), true, RouteProxied, ""},
		{"ProxyJump none is direct", capOf(testReading, "hostname x\nproxyjump none\n", map[string]string{"/c": "Host x\n"}), true, RouteDirect, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := classify(c.c, c.headless)
			if r.Kind != c.want {
				t.Fatalf("kind = %s (%q), want %s", r.Kind, r.Reason, c.want)
			}
			if c.reason != "" && !strings.Contains(r.Reason, c.reason) {
				t.Fatalf("reason %q does not name %q", r.Reason, c.reason)
			}
		})
	}
}

// The line scanner follows ssh's own rules: keywords are case-insensitive, = is a
// separator, and a full-line comment is never parsed.
func TestScanFileFollowsSSHSyntax(t *testing.T) {
	cases := map[string]bool{ // true when the scanner refuses, in headless mode
		"match exec \"true\"\n":       true,
		"MATCH EXEC \"true\"\n":       true,
		"Match=exec \"true\"\n":       true,
		"Match\texec\t\"true\"\n":     true,
		"   Match exec 'true'\n":      true,
		"Match canonical exec x\n":    true,
		"Match !exec x\n":             true,
		"Match host \"exec\"\n":       true, // a false refusal, accepted on purpose
		"Match final all\n":           false,
		"# Match exec x\n":            false,
		"   # Match exec x\n":         false,
		"Host probe\n  Port 22\n":     false,
		"IdentityAgent ${SSH_AUTH}\n": true,
		"# $OpenBSD\n":                false,
	}
	for body, refuse := range cases {
		got := scanFile([]byte(body), true) != ""
		if got != refuse {
			t.Errorf("scanFile(%q) refused = %v, want %v", body, got, refuse)
		}
	}
}

// Reading lines are deduplicated, and a file's name may contain spaces.
func TestReadingFilesDeduplicatesAndKeepsSpaces(t *testing.T) {
	diag := "debug1: Reading configuration data /home/a b/ssh_config\n" +
		"debug1: Reading configuration data /home/a b/ssh_config\n" +
		"debug1: Reading configuration data /etc/ssh/ssh_config\n"
	got := readingFiles([]byte(diag))
	if len(got) != 2 || got[0] != "/home/a b/ssh_config" || got[1] != "/etc/ssh/ssh_config" {
		t.Fatalf("readingFiles = %q", got)
	}
}

// Two reads that disagree about a file make no route, however each one looked.
func TestCapturesThatDifferAreNotTheSameRead(t *testing.T) {
	a := capOf(testReading, cleanListing, map[string]string{"/c": "Host x\n"})
	b := capOf(testReading, cleanListing, map[string]string{"/c": "Host y\n"})
	if a.same(b) {
		t.Fatal("two reads with different file contents were treated as the same")
	}
	c := capOf(testReading, "hostname other\n", map[string]string{"/c": "Host x\n"})
	if a.same(c) {
		t.Fatal("two reads with different listings were treated as the same")
	}
}

// The debug lines are stripped only from failure text.
func TestWithoutDebugLinesKeepsTheRealMessage(t *testing.T) {
	got := string(withoutDebugLines([]byte(testReading + "Bad configuration option: nope\n" + testExec)))
	if strings.Contains(got, "debug") || !strings.Contains(got, "Bad configuration option") {
		t.Fatalf("the failure text was %q; want only the real message", got)
	}
}
