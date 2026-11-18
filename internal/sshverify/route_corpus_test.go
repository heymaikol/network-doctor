package sshverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusCase is one configuration with the route the scanner must establish. The
// expectations are the measured rules on OpenSSH 10.5p1. A variable outside a comment
// is refused in both modes, so the route does not depend on the terminal.
type corpusCase struct {
	name string
	body string
	want RouteKind
}

// Each @DIR@ is replaced with a directory the test creates.
var corpus = []corpusCase{
	{"plain", "Host probe\n  HostName 127.0.0.1\n", RouteDirect},
	{"exec lower", "match exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec upper", "MATCH EXEC \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec quoted kw", "Match \"exec\" \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec tab", "Match\texec\t\"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec equals", "Match=exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec canonical first", "Match canonical exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec negated", "Match !exec \"false\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec single quoted arg", "Match exec 'true'\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"exec leading spaces", "   Match exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"host named exec (false refusal ok)", "Match host \"exec\"\nHost probe\n  HostName 127.0.0.2\n", RouteUnknown},
	{"dollar in comment", "# $OpenBSD: ssh_config\nHost probe\n  HostName 127.0.0.1\n", RouteDirect},
	{"dollar in directive", "Host probe\n  HostName 127.0.0.1\n  IdentityAgent ${SSH_AUTH_SOCK}\n", RouteUnknown},
	{"dollar in directive upper kw", "HOSTNAME x\nHost probe\n  IDENTITYAGENT ${SSH_AUTH_SOCK}\n", RouteUnknown},
	{"user dollar", "Host probe\n  HostName 127.0.0.1\n  User ${FOO}u\n", RouteUnknown},
	{"user-known-hosts dollar", "Host probe\n  HostName 127.0.0.1\n  UserKnownHostsFile @DIR@/kh/${FOO}\n", RouteUnknown},
	{"proxycommand none", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand none\n", RouteDirect},
	{"PROXYCOMMAND NONE eq", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand=NONE\n", RouteDirect},
	{"proxyjump none", "Host probe\n  HostName 127.0.0.1\n  ProxyJump none\n", RouteDirect},
	{"proxycommand real", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand nc %h %p\n", RouteProxied},
	{"proxy inherited then none", "Host *\n  ProxyCommand nc %h %p\nHost probe\n  ProxyCommand none\n", RouteProxied},
	{"proxy none then jump", "Host probe\n  ProxyJump none\nHost probe\n  ProxyJump bastion\n", RouteDirect},
	{"proxy for other host only", "Host vsock/*\n  ProxyCommand nc %h %p\nHost probe\n  HostName 127.0.0.1\n", RouteDirect},
	{"khc real", "Host probe\n  HostName 127.0.0.1\n  KnownHostsCommand echo\n", RouteUnknown},
	{"khc none", "Host probe\n  HostName 127.0.0.1\n  KnownHostsCommand none\n", RouteDirect},
	{"khc upper", "Host probe\n  KNOWNHOSTSCOMMAND echo\n", RouteUnknown},
	{"include plain", "Include @DIR@/plain.conf\nHost probe\n  HostName 127.0.0.1\n", RouteDirect},
	{"include dollar", "Include @DIR@/dir/${FOO}.conf\nHost probe\n  HostName 127.0.0.1\n", RouteUnknown},
	{"unevaluated exec (false refusal ok)", "Match host nomatch exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", RouteUnknown},
	{"match final exec", "Match final exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", RouteUnknown},
	{"match not-canonical exec", "Match !canonical exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", RouteUnknown},
	{"canonicalize yes", "Host probe\n  HostName 127.0.0.1\n  CanonicalizeHostname yes\n", RouteUnknown},
	{"canonicalize no", "Host probe\n  HostName 127.0.0.1\n  CanonicalizeHostname no\n", RouteDirect},
}

// writeCorpusCase writes one case with its include targets in a fresh directory.
func writeCorpusCase(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "kh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.conf"), []byte("Host probe\n  Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dir", "x.conf"), []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "case.config")
	if err := os.WriteFile(cfg, []byte(strings.ReplaceAll(body, "@DIR@", dir)), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every corpus case gets the route its measured rule requires, read by the real client.
func TestScannerCorpusRoutesAsMeasured(t *testing.T) {
	requireOpenSSH(t)
	if !configPlatformSupported {
		t.Skip("the configuration read is not validated on this platform")
	}
	for _, c := range corpus {
		t.Run(c.name, func(t *testing.T) {
			cfg := writeCorpusCase(t, c.body)
			cap, err := captureConfig(t.Context(), "ssh", []string{"-G", "-F", cfg, "--", "probe"})
			if err != nil {
				// The client refused the configuration outright, for example an unset
				// variable: no route is established, which is a refusal too.
				if c.want != RouteUnknown {
					t.Fatalf("the read failed where a route was expected: %v", err)
				}
				return
			}
			r := classify(cap)
			if r.Kind != c.want {
				t.Errorf("route = %s (%q), want %s", r.Kind, r.Reason, c.want)
			}
		})
	}
}

// For each configuration the scanner accepts as direct, the listing does not change
// when the environment the client sees changes. This is the property the headless
// rule exists to protect, so a change here is a false accept.
func TestDirectRoutesDoNotChangeWithTheEnvironment(t *testing.T) {
	requireOpenSSH(t)
	if !configPlatformSupported {
		t.Skip("the configuration read is not validated on this platform")
	}
	for _, c := range corpus {
		if c.want != RouteDirect {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			cfg := writeCorpusCase(t, c.body)
			args := []string{"-G", "-F", cfg, "--", "probe"}
			t.Setenv("FOO", "alpha")
			t.Setenv("SSH_AUTH_SOCK", "/tmp/netdoc-sock-a")
			base, err := captureConfig(t.Context(), "ssh", args)
			if err != nil {
				t.Fatalf("the base read failed: %v", err)
			}
			t.Setenv("FOO", "beta")
			t.Setenv("SSH_AUTH_SOCK", "/tmp/netdoc-sock-b")
			t.Setenv("HOME", t.TempDir())
			other, err := captureConfig(t.Context(), "ssh", args)
			if err != nil {
				t.Fatalf("the changed-environment read failed: %v", err)
			}
			if string(base.listing) != string(other.listing) {
				t.Errorf("the listing changed with the environment:\n%s\n---\n%s", base.listing, other.listing)
			}
		})
	}
}
