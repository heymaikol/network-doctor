package sshverify

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// corpusCase is one configuration with the route the scanner must establish, in each
// mode. The expectations are the measured rules on OpenSSH 10.5p1, and the rows from
// the challenge review. Rows the review could not test without a DNS fixture are left
// out: they are the open decision D6, and no route claim is made for them.
type corpusCase struct {
	name     string
	body     string
	terminal RouteKind
	headless RouteKind
}

const (
	direct  = RouteDirect
	proxied = RouteProxied
	refused = RouteUnknown
)

// Each @DIR@ is replaced with a directory the test creates; @USER@ with the login name.
var corpus = []corpusCase{
	{"plain", "Host probe\n  HostName 127.0.0.1\n", direct, direct},
	{"exec lower", "match exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec upper", "MATCH EXEC \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec quoted kw", "Match \"exec\" \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec tab", "Match\texec\t\"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec equals", "Match=exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec canonical first", "Match canonical exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec negated", "Match !exec \"false\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec single quoted arg", "Match exec 'true'\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"exec leading spaces", "   Match exec \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"host named exec (false refusal ok)", "Match host \"exec\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"dollar in comment", "# $OpenBSD: ssh_config\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"dollar in directive", "Host probe\n  HostName 127.0.0.1\n  IdentityAgent ${SSH_AUTH_SOCK}\n", refused, refused},
	{"dollar in directive upper kw", "HOSTNAME x\nHost probe\n  IDENTITYAGENT ${SSH_AUTH_SOCK}\n", refused, refused},
	{"user dollar", "Host probe\n  HostName 127.0.0.1\n  User ${FOO}u\n", refused, refused},
	{"user-known-hosts dollar", "Host probe\n  HostName 127.0.0.1\n  UserKnownHostsFile @DIR@/kh/${FOO}\n", refused, refused},
	{"identityfile dollar", "Host probe\n  HostName 127.0.0.1\n  IdentityFile ${FOO}/k\n", direct, refused},
	{"host dollar", "Host ${FOO}\n  HostName 127.0.0.1\n", direct, refused},
	{"match host dollar", "Match host ${FOO}\n  HostName 127.0.0.1\n", refused, refused},
	{"port dollar (client refuses)", "Host probe\n  HostName 127.0.0.1\n  Port ${FOO}\n", refused, refused},
	{"proxyjump dollar", "Host probe\n  HostName 127.0.0.1\n  ProxyJump ${FOO}\n", refused, refused},
	{"proxycommand dollar", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand echo ${FOO}\n", refused, refused},
	{"knownhostscommand dollar", "Host probe\n  HostName 127.0.0.1\n  KnownHostsCommand echo ${FOO}\n", refused, refused},
	{"proxycommand none", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand none\n", direct, direct},
	{"PROXYCOMMAND NONE eq", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand=NONE\n", direct, direct},
	{"proxyjump none", "Host probe\n  HostName 127.0.0.1\n  ProxyJump none\n", direct, direct},
	{"proxycommand real", "Host probe\n  HostName 127.0.0.1\n  ProxyCommand nc %h %p\n", proxied, proxied},
	{"proxy inherited then none", "Host *\n  ProxyCommand nc %h %p\nHost probe\n  ProxyCommand none\n", proxied, proxied},
	{"proxy none then jump", "Host probe\n  ProxyJump none\nHost probe\n  ProxyJump bastion\n", direct, direct},
	{"proxy jump then none", "Host probe\n  ProxyJump bastion\nHost probe\n  ProxyCommand none\n", proxied, proxied},
	{"proxy for other host only", "Host vsock/*\n  ProxyCommand nc %h %p\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"khc real", "Host probe\n  HostName 127.0.0.1\n  KnownHostsCommand echo\n", refused, refused},
	{"khc none", "Host probe\n  HostName 127.0.0.1\n  KnownHostsCommand none\n", direct, direct},
	{"khc upper", "Host probe\n  KNOWNHOSTSCOMMAND echo\n", refused, refused},
	{"include plain", "Include @DIR@/plain.conf\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"include dollar", "Include @DIR@/dir/${FOO}.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"include with exec in the included file", "Host other\n  HostName x\nInclude @DIR@/exec.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match host then include with exec", "Match host probe\nInclude @DIR@/exec.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"nested include, dollar only in the leaf", "Include @DIR@/chain1.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"include glob with one dollar file", "Include @DIR@/glob/*.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"unevaluated exec (false refusal ok)", "Match host nomatch exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match final exec", "Match final exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match not-canonical exec", "Match !canonical exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match canonical exec (negative control)", "Match canonical exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match originalhost exec", "Match originalhost probe exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match localuser self exec", "Match localuser @USER@ exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match localuser other exec", "Match localuser nosuchuser exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match tagged exec", "Match tagged foo exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"host other then match exec", "Host other\n  HostName x\nMatch exec \"true\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match command selects a proxy", "Match command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match command without a proxy", "Match command \"netdoc*\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match final selects a proxy", "Match final\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", proxied, proxied},
	{"match canonical with canonicalization off", "Match canonical\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"match sessiontype", "Match sessiontype shell\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match localnetwork", "Match localnetwork 127.0.0.0/8\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match tagged", "Match tagged foo\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"match user and host (known criteria)", "Match user demo host probe\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"match all", "Match all\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"canonicalize yes", "Host probe\n  HostName 127.0.0.1\n  CanonicalizeHostname yes\n", refused, refused},
	{"canonicalize no", "Host probe\n  HostName 127.0.0.1\n  CanonicalizeHostname no\n", direct, direct},

	{"CR match command selects a proxy", "Match\rcommand \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CR match command without a proxy", "Match\rcommand \"netdoc*\"\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CR match exec", "Match\rexec \"true\"\nHost probe\n  HostName 127.0.0.2\n", refused, refused},
	{"CR match sessiontype", "Match\rsessiontype shell\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CR match localnetwork", "Match\rlocalnetwork 127.0.0.0/8\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CR match user and host (known criteria)", "Match\ruser demo host probe\nHost probe\n  HostName 127.0.0.1\n", direct, direct},
	{"CR host separator (no directive)", "Host\rprobe\n  HostName 127.0.0.1\n", direct, direct},
	{"CR user dollar", "Host probe\n  HostName 127.0.0.1\n  User\r${FOO}u\n", refused, refused},
	{"CR identityfile dollar", "Host probe\n  HostName 127.0.0.1\n  IdentityFile\r${FOO}/k\n", direct, refused},
	{"CR include dollar", "Include\r@DIR@/dir/${FOO}.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CRLF plain (control)", "Host probe\r\n  HostName 127.0.0.1\r\n", direct, direct},
	{"CRLF match command, space form (control)", "Match command \"netdoc*\"\r\n  ProxyJump 127.0.0.3\r\nHost probe\r\n  HostName 127.0.0.1\r\n", refused, refused},
	{"CR match command in an included file", "Include @DIR@/crmatch.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"CR match command two includes down", "Include @DIR@/crchain1.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword match command", "\"Match\" command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword joined mid-token", "Ma\"tch\" command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword joined after its quote", "\"Match\"command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword match command, CRLF", "\"Match\" command \"netdoc*\"\r\n  ProxyJump 127.0.0.3\r\nHost probe\r\n  HostName 127.0.0.1\r\n", refused, refused},
	{"quoted keyword with a carriage return", "\"Match\"\rcommand \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted command name containing a space", "\"Match command\" \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword match command in an included file", "Include @DIR@/qmatch.conf\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted keyword Host (an accepted false refusal)", "\"Host\" probe\n  HostName 127.0.0.1\n", refused, refused},
	{"equals before a match command", "=Match command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"equals and a quoted keyword before a match command", "= \"Match\" command \"netdoc*\"\n  ProxyJump 127.0.0.3\nHost probe\n  HostName 127.0.0.1\n", refused, refused},
	{"quoted argument on a plain keyword (control)", "Host probe\n  HostName \"127.0.0.1\"\n  IdentityFile \"~/.ssh/k\"\n", direct, direct},
}

// writeCorpusCase writes one case with its include targets in a fresh directory.
func writeCorpusCase(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"dir", "kh", "glob", "nest"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"plain.conf":    "Host probe\n  Port 2222\n",
		"dir/x.conf":    "# nothing\n",
		"exec.conf":     "Match host probe exec \"true\"\n",
		"glob/a.conf":   "Host probe\n  Port 2222\n",
		"glob/b.conf":   "IdentityAgent ${SSH_AUTH_SOCK}\n",
		"chain1.conf":   "Include @DIR@/chain2.conf\n",
		"chain2.conf":   "Include @DIR@/chain3.conf\n",
		"chain3.conf":   "Host probe\n  IdentityAgent ${SSH_AUTH_SOCK}\n",
		"crmatch.conf":  "Match\rcommand \"netdoc*\"\n  ProxyJump 127.0.0.3\n",
		"crchain1.conf": "Include @DIR@/crmatch.conf\n",
		"qmatch.conf":   "\"Match\" command \"netdoc*\"\n  ProxyJump 127.0.0.3\n",
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.ReplaceAll(text, "@DIR@", dir)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	login := "nobody"
	if u, err := user.Current(); err == nil {
		login = u.Username
	}
	cfg := filepath.Join(dir, "case.config")
	text := strings.ReplaceAll(strings.ReplaceAll(body, "@DIR@", dir), "@USER@", login)
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Every corpus case gets the route its rule requires, in each mode, read by the real client.
// A client that refuses the configuration outright is a refusal, which is what an
// Unknown expectation requires.
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
				if c.terminal != refused || c.headless != refused {
					t.Fatalf("the read failed where a route was expected: %v", err)
				}
				return
			}
			if got := classify(cap, false); got.Kind != c.terminal {
				t.Errorf("terminal = %s (%q), want %s", got.Kind, got.Reason, c.terminal)
			}
			if got := classify(cap, true); got.Kind != c.headless {
				t.Errorf("headless = %s (%q), want %s", got.Kind, got.Reason, c.headless)
			}
		})
	}
}

// For each configuration the scanner accepts as direct, the listing does not change
// when the environment the client sees changes. A change here is a false accept.
func TestDirectRoutesDoNotChangeWithTheEnvironment(t *testing.T) {
	requireOpenSSH(t)
	if !configPlatformSupported {
		t.Skip("the configuration read is not validated on this platform")
	}
	for _, c := range corpus {
		if c.terminal != direct || c.headless != direct {
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

// Mutation check: a direct configuration with one line added first, that the rules must
// refuse, is refused in both modes. Each mutation is a route change the scanner must see.
func TestMutatedDirectRoutesAreRefused(t *testing.T) {
	requireOpenSSH(t)
	if !configPlatformSupported {
		t.Skip("the configuration read is not validated on this platform")
	}
	mutations := map[string]string{
		"added exec":            "Match host probe exec \"true\"\n",
		"added known hosts cmd": "KnownHostsCommand true\n",
		"added variable":        "IdentityAgent ${SSH_AUTH_SOCK}\n",
		"added proxy":           "ProxyJump bastion\n",
	}
	for _, c := range corpus {
		if c.terminal != direct || c.headless != direct {
			continue
		}
		for name, extra := range mutations {
			t.Run(c.name+" / "+name, func(t *testing.T) {
				// The first value OpenSSH reads for a keyword wins, so a line added
				// under a Host block that already sets it changes nothing. The
				// mutation goes first, where it applies to every host.
				cfg := writeCorpusCase(t, extra+c.body)
				cap, err := captureConfig(t.Context(), "ssh", []string{"-G", "-F", cfg, "--", "probe"})
				if err != nil {
					return // the client refused the mutated configuration outright
				}
				if got := classify(cap, false); got.Kind == direct {
					t.Errorf("terminal accepted the mutated route as direct")
				}
				if got := classify(cap, true); got.Kind == direct {
					t.Errorf("headless accepted the mutated route as direct")
				}
			})
		}
	}
}
