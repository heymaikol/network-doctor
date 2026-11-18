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

// cleanListing is what ssh prints for a direct route with canonicalization off.
const cleanListing = "hostname 127.0.0.1\nport 22\nuser demo\ncanonicalizehostname false\nproxyjump none\n"

// The classifier accepts a clean read and refuses each rule that cannot be matched.
func TestClassifyRefusesWhatItCannotMatch(t *testing.T) {
	cases := []struct {
		name   string
		c      capture
		want   RouteKind
		reason string
	}{
		{"clean read is direct", capOf(testReading, cleanListing, map[string]string{"/etc/ssh/ssh_config": "Host x\n"}), RouteDirect, ""},
		{"exec marker in the diagnostics", capOf(testReading+testExec, cleanListing, map[string]string{"/c": "Host x\n"}), RouteUnknown, "Match exec command runs"},
		{"exec test in a file", capOf(testReading, cleanListing, map[string]string{"/c": "Match host x exec true\n"}), RouteUnknown, "Match exec test"},
		{"dollar outside a comment", capOf(testReading, cleanListing, map[string]string{"/c": "IdentityAgent ${SSH_AUTH_SOCK}\n"}), RouteUnknown, "environment variable"},
		{"dollar in a User", capOf(testReading, cleanListing, map[string]string{"/c": "User ${FOO}u\n"}), RouteUnknown, "environment variable"},
		{"dollar in an Include", capOf(testReading, cleanListing, map[string]string{"/c": "Include /d/${FOO}.conf\n"}), RouteUnknown, "Include uses an environment variable"},
		{"dollar in a full-line comment", capOf(testReading, cleanListing, map[string]string{"/c": "# $OpenBSD: ssh_config\n"}), RouteDirect, ""},
		{"canonicalization on", capOf(testReading, "hostname x\ncanonicalizehostname true\nproxyjump none\n", map[string]string{"/c": "Host x\n"}), RouteUnknown, "CanonicalizeHostname is on"},
		{"canonicalization not reported", capOf(testReading, "hostname x\nproxyjump none\n", map[string]string{"/c": "Host x\n"}), RouteUnknown, "does not report it"},
		{"KnownHostsCommand in the listing", capOf(testReading, "hostname x\ncanonicalizehostname false\nknownhostscommand touch /t\n", map[string]string{"/c": "Host x\n"}), RouteUnknown, "KnownHostsCommand"},
		{"KnownHostsCommand none is not a command", capOf(testReading, "hostname x\ncanonicalizehostname false\nknownhostscommand none\n", map[string]string{"/c": "Host x\n"}), RouteDirect, ""},
		{"ProxyJump in the listing is proxied", capOf(testReading, "hostname x\ncanonicalizehostname false\nproxyjump bastion\n", map[string]string{"/c": "Host x\n"}), RouteProxied, ""},
		{"ProxyCommand in the listing is proxied", capOf(testReading, "hostname x\ncanonicalizehostname false\nproxycommand nc %h %p\n", map[string]string{"/c": "Host x\n"}), RouteProxied, ""},
		{"ProxyJump none is direct", capOf(testReading, cleanListing, map[string]string{"/c": "Host x\n"}), RouteDirect, ""},
		{"no hostname line is unknown", capOf(testReading, "canonicalizehostname false\n", map[string]string{"/c": "Host x\n"}), RouteUnknown, "no hostname line"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := classify(c.c, false)
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
	cases := map[string]bool{ // true when the scanner refuses
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

// Match criteria are refused unless the configuration alone decides them. A criterion
// the connection decides, or one that is not known, is refused, and a value is skipped
// as the argument of the criterion before it.
func TestMatchCriteriaAreKnownOnlyWhenTheConfigurationDecidesThem(t *testing.T) {
	known := map[string]bool{
		"host probe":               true,
		"user demo":                true,
		"all":                      true,
		"canonical":                true,
		"final":                    true,
		"host probe user demo":     true,
		"!host probe":              true,
		`host "probe"`:             true,
		"host command":             true, // a host named command is a value, not the criterion
		"command netdoc*":          false,
		"sessiontype shell":        false,
		"localnetwork 127.0.0.0/8": false,
		"tagged foo":               false,
		"user demo tagged foo":     false,
		"nonsense":                 false,
		`host "a b"`:               false, // a quoted value with a space is refused, not guessed at
	}
	for rest, want := range known {
		if got := matchCriteriaKnown(rest); got != want {
			t.Errorf("matchCriteriaKnown(%q) = %v, want %v", rest, got, want)
		}
	}
}

// On a terminal the literal keywords may keep a $; any other keyword, and any Match, is
// refused. Headless refuses every $.
func TestLiteralKeywordsAreAcceptedOnlyOnATerminal(t *testing.T) {
	for _, line := range []string{"HostName ${FOO}.example\n", "Host ${FOO}\n", "IdentityFile ${FOO}/k\n"} {
		if scanFile([]byte(line), false) != "" {
			t.Errorf("terminal refused the literal keyword %q", line)
		}
		if scanFile([]byte(line), true) == "" {
			t.Errorf("headless accepted a $ in %q", line)
		}
	}
	for _, line := range []string{"User ${FOO}u\n", "IdentityAgent ${FOO}\n", "Match host ${FOO}\n", "UnknownKeyword ${FOO}\n"} {
		if scanFile([]byte(line), false) == "" {
			t.Errorf("terminal accepted a $ in %q, which is not a measured literal keyword", line)
		}
	}
}
