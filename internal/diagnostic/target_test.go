// ParseTarget grammar: the accepted forms and the rejects.

package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		port    int
		proto   Proto
		literal bool
	}{
		{"github.com", "github.com", 443, ProtoTLSHTTP, false},
		{"example.com.", "example.com.", 443, ProtoTLSHTTP, false},
		{"github.com:22", "github.com", 22, ProtoSSH, false},
		{"https://github.com", "github.com", 443, ProtoTLSHTTP, false},
		{"http://example.com", "example.com", 80, ProtoHTTP, false},
		{"https://host:80", "host", 80, ProtoTLSHTTP, false}, // scheme selects proto
		{"http://host:443", "host", 443, ProtoHTTP, false},   // scheme selects proto
		{"ssh://host:2222", "host", 2222, ProtoSSH, false},
		{"smtp://host:2525", "host", 2525, ProtoSMTP, false},
		{"ssh://host", "host", 22, ProtoSSH, false},
		{"smtp://host", "host", 25, ProtoSMTP, false},
		{"1.1.1.1", "1.1.1.1", 443, ProtoTLSHTTP, true},
		{"127.0.0.1", "127.0.0.1", 443, ProtoTLSHTTP, true},
		{"1.1.1.1:25", "1.1.1.1", 25, ProtoSMTP, true},
		{"mail.example.com:587", "mail.example.com", 587, ProtoSMTP, false},
		{"https://github.com/owner/repo", "github.com", 443, ProtoTLSHTTP, false},
		{"host:8443", "host", 8443, ProtoTLSHTTP, false},
		{"::1", "::1", 443, ProtoTLSHTTP, true},
		{"fe80::1%eth0", "fe80::1", 443, ProtoTLSHTTP, true},
		{"[::1]", "::1", 443, ProtoTLSHTTP, true},
		{"[2001:db8::1]:22", "2001:db8::1", 22, ProtoSSH, true},
		{"https://[2001:db8::1]:8443/path", "2001:db8::1", 8443, ProtoTLSHTTP, true},

		// Internationalized names arrive as the A-label DNS carries, whether
		// the person typed the A-label or the Unicode it stands for. The
		// lookup profile maps the case and the Unicode label separators on
		// the way, and an ASCII spelling is still returned untouched.
		{"xn--bcher-kva.example", "xn--bcher-kva.example", 443, ProtoTLSHTTP, false},
		{"bücher.example", "xn--bcher-kva.example", 443, ProtoTLSHTTP, false},
		{"BÜCHER.example", "xn--bcher-kva.example", 443, ProtoTLSHTTP, false},
		{"bücher.example.", "xn--bcher-kva.example.", 443, ProtoTLSHTTP, false},
		{"bücher。example", "xn--bcher-kva.example", 443, ProtoTLSHTTP, false},
		{"bücher.example:8022", "xn--bcher-kva.example", 8022, ProtoNone, false},
		{"ssh://bücher.example", "xn--bcher-kva.example", 22, ProtoSSH, false},
		{"https://bücher.example:8443/path", "xn--bcher-kva.example", 8443, ProtoTLSHTTP, false},
		// Fullwidth digits map to the ASCII ones, which makes this an address
		// rather than a name. Classified as the literal it converted into, so
		// Host and IP cannot disagree about which it is.
		{"１.１.１.１", "1.1.1.1", 443, ProtoTLSHTTP, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			tg, err := ParseTarget(c.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tg.Host != c.host {
				t.Errorf("host = %q, want %q", tg.Host, c.host)
			}
			if tg.Port != c.port {
				t.Errorf("port = %d, want %d", tg.Port, c.port)
			}
			if tg.Proto != c.proto {
				t.Errorf("proto = %d, want %d", tg.Proto, c.proto)
			}
			if (tg.IP != nil) != c.literal {
				t.Errorf("literal = %v, want %v", tg.IP != nil, c.literal)
			}
		})
	}
}

func TestParseTargetErrors(t *testing.T) {
	bad := []string{"", "host:0", "host:99999", "ftp://host", "bad_host!",
		"[::1", "[::1]x", "[1.2.3.4]:80", "[hostname]:80", "[]:80", "[fe80::1]", "a:b:c",
		"https://user@example.com", "https://host:not-a-port", "host:65536", "host:-1",
		"host:9999999999999999999999999999999999999999", "host:\x0080",
		// Internationalized names get no relaxation: the A-label the lookup
		// profile produces goes back through the same allowlist and the same
		// 253-byte limit, so everything an ASCII target is rejected for is
		// still rejected after conversion.
		"bücher..example",                    // empty label
		"-bücher.example", "bücher-.example", // label edge hyphens
		"bü_cher.example",                    // disallowed rune
		strings.Repeat("ü", 63) + ".example", // 69-byte label once punycoded
		strings.Repeat("ü", 30) + strings.Repeat("."+strings.Repeat("ü", 30), 6), // 265 bytes once converted
		"\u200b.example.com",          // first label maps away to nothing
		"\u202ebücher.example",        // bidi override, rejected by the profile
		"[bücher.example]:80",         // brackets are still IPv6 only
		"https://usér@bücher.example", // userinfo is still refused
		"\xff.example",                // invalid UTF-8
	}
	for _, in := range bad {
		if tg, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want error", in, tg)
		}
	}
}

// The unspecified address names no host. Connecting to it is left to the OS,
// which on Linux quietly means this machine, so a run would probe a local
// service while every row and report still named 0.0.0.0 or :: as the target.
// Rejected on the parsed address, not the spelling, so the port and URL forms
// and an IPv4-mapped :: are refused too. Loopback stays a valid destination.
func TestParseTargetRejectsUnspecifiedAddress(t *testing.T) {
	for _, in := range []string{
		"0.0.0.0", "0.0.0.0:80", "http://0.0.0.0:8080",
		"::", "[::]:80", "http://[::]:8080",
		"::ffff:0.0.0.0",
	} {
		tg, err := ParseTarget(in)
		if err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want the unspecified address rejected", in, tg)
			continue
		}
		if got := err.Error(); !strings.Contains(got, "unspecified") || got != textsafe.Clean(got) {
			t.Errorf("ParseTarget(%q) error = %q, want a terminal-safe unspecified-address reject", in, got)
		}
	}
}

func TestParseTargetPortExplicit(t *testing.T) {
	for _, c := range []struct {
		in       string
		explicit bool
	}{
		{"example.com", false},
		{"https://example.com", false},
		{"example.com:1", true},
		{"https://example.com:65535", true},
	} {
		tg, err := ParseTarget(c.in)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.in, err)
		}
		if tg.PortExplicit != c.explicit {
			t.Errorf("ParseTarget(%q).PortExplicit = %v, want %v", c.in, tg.PortExplicit, c.explicit)
		}
	}
}

// A rejected target's error text goes straight to a terminal, whether stderr,
// the restart prompt or the SSH form, so it must survive Clean unchanged. The
// wrapped errors are the risk: net.AddrError echoes the host without quoting
// it, which is how a bidi override used to reach the screen.
func TestParseTargetErrorsAreTerminalSafe(t *testing.T) {
	rlo := string(rune(0x202e))
	for _, in := range []string{
		rlo + ":1:2",            // net.AddrError, "too many colons"
		"ssh://" + rlo + ":1:2", // same, behind a scheme
		rlo + "host",            // hostname allowlist reject
		"[" + rlo + "]:80",      // bracket reject
		string(rune(0x1b)) + ":1:2",
		string(rune(0x200b)) + ".example.com",
	} {
		_, err := ParseTarget(in)
		if err == nil {
			t.Fatalf("ParseTarget(%q) = nil error, want reject", in)
		}
		if got := err.Error(); got != textsafe.Clean(got) {
			t.Errorf("ParseTarget(%q) error %q carries unsanitized bytes", in, got)
		}
	}
}

func TestParseTargetCanonicalRaw(t *testing.T) {
	tg, err := ParseTarget("HTTPS://example.com:8443/ignored?query#fragment\x1b[31m")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Raw != "https://example.com:8443" {
		t.Fatalf("Raw = %q, want validated endpoint only", tg.Raw)
	}
}

// A bare IPv6 literal has no brackets to set a port apart, so nothing after
// its last colon is a port, whatever that group looks like. "2001:db8::1"
// and "2001:db8::beef" are the same form, which the reference documents as
// accepted bare; a final group that happens to be decimal must not be what
// decides it, and neither may the RFC 4291 dotted-quad tail of a NAT64 or
// IPv4-mapped address. Each one is the target its bracketed spelling is, and
// Raw keeps the bare spelling that was typed, exactly as it does for "::1".
func TestParseTargetBareIPv6Literal(t *testing.T) {
	for _, bare := range []string{
		"2001:db8::1",    // decimal final group: always parsed
		"2620:fe::fe",    // hex final group
		"2001:db8::beef", // hex final group
		"fe80::a%eth0",   // one hex digit, and a zone
		"2001:db8::",     // no final group at all
		"64:ff9b::192.0.2.1",
		"::ffff:192.0.2.1",
	} {
		got, err := ParseTarget(bare)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v, want the bare IPv6 literal accepted", bare, err)
			continue
		}
		want, err := ParseTarget("[" + bare + "]")
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", "["+bare+"]", err)
		}
		if got.Raw != bare {
			t.Errorf("ParseTarget(%q).Raw = %q, want the spelling typed", bare, got.Raw)
		}
		if got.IP == nil || !got.IP.Equal(want.IP) || got.Host != want.Host || got.Port != want.Port ||
			got.Proto != want.Proto || got.PortExplicit != want.PortExplicit {
			t.Errorf("ParseTarget(%q) = %+v, want the target %q is: %+v", bare, *got, "["+bare+"]", *want)
		}
	}
}

// The Unicode spelling and the A-label are one target, not two that happen to
// resolve alike. Every field has to agree, Raw included, because Raw is the
// endpoint identity that reaches a .ndoc, a comparison's "target as typed",
// the restart prompt, and the worker that -via hands it to for reparsing. A
// Unicode Raw would make that worker's answer depend on its netdoc version.
func TestParseTargetInternationalizedIsOneIdentity(t *testing.T) {
	for _, c := range []struct{ unicode, alabel string }{
		{"bücher.example", "xn--bcher-kva.example"},
		{"BÜCHER.example", "xn--bcher-kva.example"},
		{"bücher。example", "xn--bcher-kva.example"},
		{"https://bücher.example:8443/path", "https://xn--bcher-kva.example:8443"},
		{"ssh://bücher.example", "ssh://xn--bcher-kva.example"},
		{"bücher.example:8022", "xn--bcher-kva.example:8022"},
	} {
		got, err := ParseTarget(c.unicode)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.unicode, err)
		}
		if got.Raw != c.alabel {
			t.Errorf("ParseTarget(%q).Raw = %q, want the canonical %q", c.unicode, got.Raw, c.alabel)
		}
		want, err := ParseTarget(c.alabel)
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", c.alabel, err)
		}
		if !reflect.DeepEqual(*got, *want) {
			t.Errorf("ParseTarget(%q) = %+v, ParseTarget(%q) = %+v, want one target", c.unicode, *got, c.alabel, *want)
		}
		// What a .ndoc carries and what replay rebuilds from it. Both halves
		// of the durable identity, so neither path can reinterpret the name.
		snap := BuildSnapshot(got, nil, nil).Target
		if snap.Raw != c.alabel || snap.Host != got.Host {
			t.Errorf("snapshot target of %q = %+v, want Raw %q and Host %q", c.unicode, snap, c.alabel, got.Host)
		}
	}
}

// Normalization that stops at the parser is decoration. These two probes decide
// which destination the run is actually talking about: the name the resolver is
// asked for, and the name TLS offers as SNI and verifies the certificate
// against. Neither is handed in by the test, both are read off the graph the
// Unicode target built.
func TestInternationalizedTargetReachesDNSAndTLSAsASCII(t *testing.T) {
	const want = "xn--bcher-kva.example"
	target := mustTarget(t, "https://bücher.example")
	var queried, sni string
	ops := &netops{
		lookupIP: func(_ context.Context, host string) ([]net.IP, []string, error) {
			queried = host
			return []net.IP{net.ParseIP("192.0.2.10")}, nil, nil
		},
		dialTLS: func(_ context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
			sni = cfg.ServerName
			return nil, errors.New("stopped after the ClientHello")
		},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.10")}}
	for _, p := range ops.buildProbes(target, "", true) {
		switch p.ID {
		case ProbeDNS, ProbeTLS:
			p.Run(context.Background(), deps)
		}
		// The row labels travel with the answer, into the TUI, the report and
		// the artifact, so no probe in the graph may name the Unicode spelling.
		if p.Name != textsafe.Clean(p.Name) || strings.ContainsFunc(p.Name, func(r rune) bool { return r >= 0x80 }) {
			t.Errorf("probe %s is named %q, want an ASCII row label", p.ID, p.Name)
		}
	}
	if queried != want {
		t.Errorf("DNS resolved %q, want the A-label %q", queried, want)
	}
	if sni != want {
		t.Errorf("TLS ServerName = %q, want the A-label %q", sni, want)
	}
}

func FuzzParseTarget(f *testing.F) {
	seeds := []string{
		// Ordinary host, address, port, and URL forms.
		"example.com", "www.example.com", "example.com.", "192.0.2.1",
		"example.com:443", "192.0.2.1:80", "[2001:db8::1]", "[2001:db8::1]:443",
		"host:1", "host:65535", "HTTPS://example.com:8443/path?query#fragment",
		"ssh://example.com:8022/path",

		// IPv6 and colon ambiguity, including malformed bracket structures.
		"2001:db8::1", "::1", "::", "::::", "2001:db8::1:80", "example.com:80:90",
		"2620:fe::fe", "fe80::a", "64:ff9b::192.0.2.1", "::ffff:192.0.2.1",
		"2001:db8::1]:80", "[2001:db8::1:80", "[[2001:db8::1]]", "[example.com]:80",
		":80", "host:", ":", "[", "]", "[]", "[::1]]:80",

		// Port boundaries and hostile numeric spellings.
		"host:0", "host:65536", "host:-1", "host:+80", "host: 80", "host:\t80",
		"host:8o", "host:0x50", "host:9999999999999999999999999999999999999999",
		"host:" + strings.Repeat("9", 256),

		// Empty, whitespace, controls, punctuation, and bounded long inputs.
		"", " ", "\t\r\n", " example.com ", "\x00", "\n", "\r", "\t", "\x1f",
		"exam\x00ple.com", "host:\n80", "https://example.com/path\x1b[31m", "...", ":::[]",
		strings.Repeat("a", 300) + ".example", strings.Repeat("[]:.\x00", 256),

		// Internationalized spellings and the runes the lookup profile maps,
		// rejects, or folds away to nothing.
		"bücher.example", "xn--bcher-kva.example", "BÜCHER.example", "bücher.example.",
		"bücher。example", "https://bücher.example:8443/path", "[bücher.example]:80",
		"bücher..example", "-bücher.example", "ü", "\u200b.example", "\u202ebücher.example",
		"１.１.１.１", "faß.example", "\xff.example", strings.Repeat("ü", 63) + ".example",
		strings.Repeat("ü", 30) + strings.Repeat("."+strings.Repeat("ü", 30), 6),

		// IPv6 zones: scoped, unscoped, encoded, empty, misplaced, hostile.
		"fe80::1%eth0", "[fe80::1%eth0]:22", "ssh://[fe80::1%eth0]:22", "ssh://[fe80::1%25eth0]",
		"ssh://[fe80::1%2525]", "[fe80::1%25]:80", "fe80::1%", "[fe80::1%]", "2001:db8::1%eth0",
		"[fe80::1%eth0%x]", "[fe80::1%eth0", "fe80::1%eth0:22", "[fe80::1%\u202e]",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		target, err := ParseTarget(input)
		// A bare address is an IP literal and nothing else: its final group is
		// never read as a port, and Raw is the spelling typed. The unspecified
		// address is the one literal refused outright.
		// A link-local IPv6 one is refused without its zone.
		if bare := strings.TrimSpace(input); !strings.Contains(bare, "://") {
			if ip := net.ParseIP(bare); ip != nil && !ip.IsUnspecified() && (ip.To4() != nil || !ip.IsLinkLocalUnicast()) && (err != nil || !ip.Equal(target.IP) || target.PortExplicit || target.Raw != bare) {
				t.Fatalf("ParseTarget(%q) = %+v, %v; want the IP literal %v", input, target, err, ip)
			}
		}
		if err != nil {
			if target != nil {
				t.Fatalf("ParseTarget(%q) returned target %+v with error %v", input, target, err)
			}
			if got := err.Error(); got != textsafe.Clean(got) {
				t.Fatalf("ParseTarget(%q) returned terminal-unsafe error %q", input, got)
			}
			return
		}
		if target == nil {
			t.Fatalf("ParseTarget(%q) succeeded with a nil target", input)
		}
		if target.Host == "" || target.Raw == "" {
			t.Fatalf("ParseTarget(%q) = %+v, want non-empty Host and Raw", input, target)
		}
		if target.Port < 1 || target.Port > 65535 {
			t.Fatalf("ParseTarget(%q).Port = %d, want 1..65535", input, target.Port)
		}
		if target.Proto < 0 || target.Proto >= Proto(len(protoNames)) {
			t.Fatalf("ParseTarget(%q).Proto = %d, want a defined protocol", input, target.Proto)
		}
		if target.Host != textsafe.Clean(target.Host) || target.Raw != textsafe.Clean(target.Raw) {
			t.Fatalf("ParseTarget(%q) returned terminal-unsafe target %+v", input, target)
		}
		if linkLocal := target.IP != nil && target.IP.To4() == nil && target.IP.IsLinkLocalUnicast(); linkLocal != (target.Zone != "") ||
			target.Zone != "" && !ValidZone(target.Zone) || strings.Contains(target.Host, "%") {
			t.Fatalf("ParseTarget(%q) = %+v, want a valid zone exactly on a link-local IP, and never in Host", input, target)
		}

		ip := net.ParseIP(target.Host)
		if (ip == nil) != (target.IP == nil) || ip != nil && !ip.Equal(target.IP) {
			t.Fatalf("ParseTarget(%q) Host/IP disagree: Host %q, IP %v", input, target.Host, target.IP)
		}

		again, err := ParseTarget(target.Raw)
		if err != nil {
			t.Fatalf("ParseTarget(%q) produced Raw %q that cannot be parsed: %v", input, target.Raw, err)
		}
		sameIP := target.IP == nil && again.IP == nil || target.IP != nil && again.IP != nil && target.IP.Equal(again.IP)
		if again.Raw != target.Raw || again.Host != target.Host || again.Port != target.Port ||
			again.Proto != target.Proto || again.PortExplicit != target.PortExplicit || again.Zone != target.Zone || !sameIP {
			t.Fatalf("ParseTarget(%q) is not stable through Raw: first %+v, again %+v", input, target, again)
		}
	})
}

func TestProtoString(t *testing.T) {
	cases := []struct {
		p    Proto
		want string
	}{
		{ProtoNone, "none"},
		{ProtoTLSHTTP, "tls+http"},
		{ProtoHTTP, "http"},
		{ProtoSSH, "ssh"},
		{ProtoSMTP, "smtp"},
		{Proto(-1), "none"},
		{Proto(99), "none"}, // out-of-range collapses to none, not a panic
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Proto(%d).String() = %q, want %q", c.p, got, c.want)
		}
	}
}

// An IPv6 link-local address names a destination only together with its
// zone, so the scoped form parses into the address and its zone, kept apart,
// and the bare form is refused with the reason rather than accepted unusable.
func TestParseTargetIPv6Zone(t *testing.T) {
	cases := []struct {
		in, raw, host, zone string
		port                int
		proto               Proto
	}{
		{"fe80::1%eth0", "fe80::1%eth0", "fe80::1", "eth0", 443, ProtoTLSHTTP},
		{"[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "fe80::1", "eth0", 22, ProtoSSH},
		{"[fe80::1%eth0]", "[fe80::1%eth0]", "fe80::1", "eth0", 443, ProtoTLSHTTP},
		// A URL spells the zone the RFC 6874 way, and so does its Raw, since
		// that is the spelling a reparse reads back unambiguously.
		{"ssh://[fe80::1%eth0]:2222", "ssh://[fe80::1%25eth0]:2222", "fe80::1", "eth0", 2222, ProtoSSH},
		{"ssh://[fe80::1%25eth0]", "ssh://[fe80::1%25eth0]", "fe80::1", "eth0", 22, ProtoSSH},
		{"ssh://[fe80::1%2525]", "ssh://[fe80::1%2525]", "fe80::1", "25", 22, ProtoSSH},
		{"https://[fe80::a%en0.100]:8443/x", "https://[fe80::a%25en0.100]:8443", "fe80::a", "en0.100", 8443, ProtoTLSHTTP},
		// Outside a URL the zone is verbatim.
		{"fe80::1%12", "fe80::1%12", "fe80::1", "12", 443, ProtoTLSHTTP},
		{"[fe80::1%25]:80", "[fe80::1%25]:80", "fe80::1", "25", 80, ProtoHTTP},
	}
	for _, c := range cases {
		got, err := ParseTarget(c.in)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", c.in, err)
			continue
		}
		if got.Raw != c.raw || got.Host != c.host || got.Zone != c.zone || got.Port != c.port || got.Proto != c.proto ||
			got.IP.String() != c.host {
			t.Errorf("ParseTarget(%q) = %+v, want raw %q host %q zone %q port %d proto %v", c.in, got, c.raw, c.host, c.zone, c.port, c.proto)
		}
		// Raw is what the restart prompt and a --via worker parse again.
		again, err := ParseTarget(got.Raw)
		if err != nil || !reflect.DeepEqual(again, got) {
			t.Errorf("ParseTarget(%q) reparsed to %+v, %v; want %+v", got.Raw, again, err, got)
		}
	}

	for _, in := range []string{
		"fe80::1", "[fe80::1]:22", "ssh://[fe80::1]:22", "https://[fe80::1]", // link-local needs its zone
		"fe80::1%", "[fe80::1%]:22", "ssh://[fe80::1%25]", // empty zone
		"2001:db8::1%eth0", "[2001:db8::1%eth0]:22", "::1%lo", // a zone only scopes link-local
		"192.0.2.1%eth0", "example.com%eth0", "[example.com%eth0]:22", "ff02::1%eth0",
		"fe80::1%eth0:22",                       // a port needs the brackets
		"[fe80::1%eth 0]:22", "[fe80::1%eth/0]", // not an interface name
		"[fe80::1%" + strings.Repeat("a", 33) + "]",
		"[fe80::1%eth0\u202e]:22", "fe80::1%eth0\x1b[2J",
	} {
		if got, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want error", in, got)
		}
	}
	_, err := ParseTarget("[fe80::1]:22")
	if err == nil || !strings.Contains(err.Error(), "zone") {
		t.Errorf("unscoped link-local error = %v, want one that asks for the zone", err)
	}
}

// The zone reaches every connection the target rows make, and only there:
// the address the rows report, and the name TLS is offered, stay unscoped.
func TestScopedTargetDialsCarryTheZone(t *testing.T) {
	for _, raw := range []string{"[fe80::1%eth0]:443", "ssh://[fe80::1%eth0]", "smtp://[fe80::1%eth0]:465"} {
		target, err := ParseTarget(raw)
		if err != nil {
			t.Fatal(err)
		}
		var (
			mu     sync.Mutex
			dialed []string
			sni    []string
		)
		record := func(addr string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			dialed = append(dialed, addr)
			return nil, errors.New("no network in tests")
		}
		o := &netops{
			interfaces:     func() ([]net.Interface, error) { return nil, nil },
			interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return nil, nil },
			proxyFromEnv:   func(*http.Request) (*url.URL, error) { return nil, nil },
			ssid:           func(context.Context, string) string { return "" },
			dialContext:    func(_ context.Context, _, addr string) (net.Conn, error) { return record(addr) },
			dialTLS: func(_ context.Context, _, addr string, cfg *tls.Config) (net.Conn, error) {
				mu.Lock()
				sni = append(sni, cfg.ServerName)
				mu.Unlock()
				return record(addr)
			},
			zone: target.Zone,
		}
		ip := target.IP
		deps := map[ProbeID]ProbeResult{
			ProbeDNS:       {Addrs: []net.IP{ip}, SelectedIP: ip},
			ProbeTargetTCP: {SelectedIP: ip},
			ProbeTLS:       {SelectedIP: ip},
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		for _, p := range o.buildProbes(target, "", false, ProbePMTU) {
			switch p.ID {
			case ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTP, ProbeHTTPS, ProbeSSH, ProbeSMTP:
				p.Run(ctx, deps)
			}
		}
		cancel()
		t.Logf("%s: dialed %q, offered TLS %q", raw, dialed, sni)
		want := "[fe80::1%eth0]:" + strconv.Itoa(target.Port)
		if !slices.Contains(dialed, want) {
			t.Errorf("%s: dialed %q, want %q among them", raw, dialed, want)
		}
		for _, addr := range dialed {
			if strings.Contains(addr, "fe80::1") && !strings.HasPrefix(addr, "[fe80::1%eth0]:") {
				t.Errorf("%s: dialed %q, want the link-local address only with its zone", raw, addr)
			}
		}
		for _, name := range sni {
			if name != "fe80::1" {
				t.Errorf("%s: TLS offered %q, want the unscoped address", raw, name)
			}
		}
	}
}
