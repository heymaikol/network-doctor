package diagnostic

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Proto selects which protocol-specific probe rows append to the target path.
type Proto int

const (
	ProtoNone Proto = iota // stop at Target TCP, no protocol-specific check
	ProtoTLSHTTP
	ProtoHTTP
	ProtoSSH
	ProtoSMTP
)

var protoNames = [...]string{"none", "tls+http", "http", "ssh", "smtp"}

func (p Proto) String() string {
	if p < 0 || p >= Proto(len(protoNames)) {
		return "none"
	}
	return protoNames[p]
}

// Target is the parsed, validated destination. Two independent axes: the
// endpoint Port (explicit > scheme default > 443) and the Proto of the
// protocol rows (explicit scheme wins; else inferred from the effective port).
type Target struct {
	Raw          string // validated endpoint spelling, echoed back in the restart prompt
	Host         string
	IP           net.IP // non-nil iff the target is an IP literal
	Port         int
	Proto        Proto
	PortExplicit bool
}

// TargetForms documents the grammar ParseTarget accepts. --help and the
// restart prompt render it verbatim; no trailing newline, since the seams around
// the block belong to the callers.
const TargetForms = `  example.com            hostname (default port 443)
  example.com:8022       hostname with port (protocol inferred from the port)
  ssh://example.com:8022 URL (scheme sets protocol and default port; path ignored)
  192.0.2.1, 2001:db8::1 IP literal
  [2001:db8::1]:443      IP literal with port (IPv6 needs the brackets)
  (nothing)              no target, runs the generic checks`

// hostnameRe is a strict RFC-1123-ish hostname allowlist (labels of
// alphanumerics + internal hyphens, dot-separated). Everything else is rejected
// so nothing user-supplied is ever fed to a probe or (later) a command. An
// internationalized name reaches it as the A-label canonicalHostname produced,
// never as the Unicode a person typed.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// canonicalHostname converts an internationalized hostname to the A-label
// spelling DNS actually carries. An all-ASCII host is returned byte for byte,
// so every target that parsed before this existed still parses to the same
// Target, mixed case and trailing root dot included; only a name carrying a
// non-ASCII rune is converted.
//
// idna.Lookup is the profile because looking the name up is what netdoc does
// with it: resolve it, offer it as SNI, verify a certificate against it, name
// it as an HTTP or proxy destination. Its mapping is what makes a person's
// spelling and the A-label one destination, case-folding and the Unicode label
// separators (U+3002 and friends) included. Registration would reject the
// mixed case a person types, and Punycode encodes without validating at all,
// which is how a bidi override would reach a probe.
//
// The profile is not the whole check, and is not trusted as one. idna.Lookup
// enforces neither label nor name length and accepts an empty label, so the
// converted name goes back through the same allowlist and 253-byte limit every
// ASCII target passes. A label that only overflows once punycoded, a name that
// only overflows once converted, and a label that maps away to nothing are all
// rejected there, before a probe or a command sees the target.
func canonicalHostname(host string) (string, bool) {
	if !strings.ContainsFunc(host, func(r rune) bool { return r >= utf8.RuneSelf }) {
		return host, true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", false
	}
	return ascii, true
}

// ParseTarget parses a CLI target: <host> | <host>:<port> | <ipv6> |
// [<ipv6>][:<port>] | <scheme>://<host>[:port][/path], where scheme is HTTP,
// HTTPS, SSH, or SMTP. Returns a typed Target
// or an error (caller exits 2 on error).
//
// The error is sanitized here rather than at each caller: every one of them
// prints it straight at a terminal (stderr, the restart prompt, the SSH form),
// and not every error we wrap quotes what it echoes: net.AddrError embeds the
// host verbatim, so a target carrying U+202E would reorder the line it lands
// in. Replaced, not wrapped: nothing unwraps a parse error, it only gets shown.
func ParseTarget(raw string) (*Target, error) {
	t, err := parseTarget(raw)
	if err != nil {
		return nil, errors.New(textsafe.Clean(err.Error()))
	}
	return t, nil
}

func parseTarget(raw string) (*Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty target")
	}
	t := &Target{}
	parseable := s
	if !strings.Contains(s, "://") {
		parseable = "//" + s
	}
	u, err := url.Parse(parseable)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", s, err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "", "http", "https", "ssh", "smtp":
	default:
		return nil, fmt.Errorf("unsupported scheme %q (only http/https/ssh/smtp)", scheme)
	}
	if u.User != nil {
		return nil, errors.New("userinfo is not allowed in target")
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}

	host, rawHost := u.Host, u.Host
	// Brackets belong to IPv6 literals and nothing else. Go 1.26's url.Parse
	// enforces that itself, but go.mod still supports 1.25, where
	// SplitHostPort happily peels the brackets off "[1.2.3.4]:80" and
	// "[hostname]:80". Check it here so the rule doesn't depend on toolchain.
	if strings.HasPrefix(host, "[") {
		if h := u.Hostname(); !strings.Contains(h, ":") || net.ParseIP(h) == nil {
			return nil, fmt.Errorf("invalid target %q: brackets are only for IPv6 literals", s)
		}
	}
	if net.ParseIP(host) == nil {
		if host == "["+u.Hostname()+"]" {
			host = u.Hostname()
		} else if strings.Contains(host, ":") {
			var port string
			host, port, err = net.SplitHostPort(host)
			if err != nil {
				return nil, fmt.Errorf("invalid target %q: %w", s, err)
			}
			t.Port, err = parsePort(port)
			if err != nil {
				return nil, err
			}
			t.PortExplicit = true
		}
	}
	if host == "" {
		return nil, errors.New("missing host")
	}
	// The one canonicalization. DNS, SNI, certificate verification, the HTTP
	// and proxy destination, the durable snapshot identity, a comparison's
	// notion of which endpoint was asked about, and the spelling a remote
	// worker reparses all read Host or Raw, so the A-label is derived once
	// here and never recomputed downstream, where the five implementations
	// would be free to drift apart. Before ParseIP, not after: a name whose
	// labels map to digits is an IP literal once converted, and classifying it
	// as a hostname would leave Host and IP disagreeing.
	canonical, ok := canonicalHostname(host)
	if !ok {
		return nil, fmt.Errorf("invalid hostname %q", host)
	}
	if canonical != host {
		// Raw is not the verbatim input and never was: it is already the
		// validated endpoint, lowercased scheme and no path. Canonical here
		// too, so the restart prompt, the history, an ssh drill-down's
		// arguments and a support artifact carry ASCII only, one .ndoc target
		// identity answers for both spellings, and a worker that predates this
		// still parses what -via sends it.
		host = canonical
		rawHost = host
		if t.PortExplicit {
			rawHost = net.JoinHostPort(host, strconv.Itoa(t.Port))
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		t.IP = ip
		if v4 := ip.To4(); v4 != nil {
			t.IP = v4
		}
		t.Host = host
	} else {
		name := strings.TrimSuffix(host, ".")
		if len(name) > 253 || !hostnameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid hostname %q", host)
		}
		t.Host = host
	}

	// Endpoint port: explicit > scheme default > 443.
	if !t.PortExplicit {
		switch scheme {
		case "http":
			t.Port = 80
		case "ssh":
			t.Port = 22
		case "smtp":
			t.Port = 25
		default: // https or bare host
			t.Port = 443
		}
	}

	// Protocol rows: explicit scheme wins; else infer from the effective port.
	switch scheme {
	case "https":
		t.Proto = ProtoTLSHTTP
	case "http":
		t.Proto = ProtoHTTP
	case "ssh":
		t.Proto = ProtoSSH
	case "smtp":
		t.Proto = ProtoSMTP
	default:
		switch t.Port {
		case 443, 8443: // 8443: where HTTPS admin panels go to feel special
			t.Proto = ProtoTLSHTTP
		case 80:
			t.Proto = ProtoHTTP
		case 22:
			t.Proto = ProtoSSH
		case 25, 587:
			t.Proto = ProtoSMTP
		default:
			t.Proto = ProtoNone
		}
	}
	t.Raw = rawHost
	if scheme != "" {
		t.Raw = scheme + "://" + rawHost
	}
	return t, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return port, nil
}
