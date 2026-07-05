package diagnostic

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Proto selects which protocol-specific probe rows append to the target path.
type Proto int

const (
	ProtoNone Proto = iota // stop at Target TCP — no protocol-specific check
	ProtoTLSHTTP
	ProtoHTTP
	ProtoSSH
	ProtoSMTP
)

// Target is the parsed, validated destination. Two independent axes: the
// endpoint Port (explicit > scheme default > 443) and the Proto of the
// protocol rows (explicit scheme wins; else inferred from the effective port).
type Target struct {
	Raw          string // original CLI spelling, echoed back in the rerun prompt
	Host         string
	IP           net.IP // set iff IsLiteral
	Port         int
	Proto        Proto
	PortExplicit bool
	IsLiteral    bool
}

// hostnameRe is a strict RFC-1123-ish hostname allowlist (labels of
// alphanumerics + internal hyphens, dot-separated). Everything else is rejected
// so nothing user-supplied is ever fed to a probe or (later) a command.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ParseTarget parses a CLI target: <host> | <host>:<port> | <ipv6> |
// [<ipv6>][:<port>] | http(s)://<host>[:port][/path]. Returns a typed Target
// or an error (caller exits 2 on error).
func ParseTarget(raw string) (*Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty target")
	}
	t := &Target{Raw: s}
	var scheme string

	if i := strings.Index(s, "://"); i >= 0 {
		scheme = strings.ToLower(s[:i])
		if scheme != "http" && scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme %q (only http/https)", scheme)
		}
		s = s[i+3:]
	}
	// Drop any path/query/fragment.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil, errors.New("missing host")
	}

	host := s
	switch {
	case strings.HasPrefix(s, "["):
		// Bracketed IPv6 literal, optionally with a port: [<ipv6>][:<port>].
		end := strings.Index(s, "]")
		if end < 0 {
			return nil, errors.New("missing ']' in bracketed IPv6 literal")
		}
		host = s[1:end]
		if rest := s[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return nil, fmt.Errorf("unexpected %q after ']'", rest)
			}
			port, err := parsePort(rest[1:])
			if err != nil {
				return nil, err
			}
			t.Port, t.PortExplicit = port, true
		}
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("brackets require an IPv6 literal, got %q", host)
		}
	case strings.Count(s, ":") > 1:
		// Bare IPv6 literal — any port form must use brackets.
	default:
		if i := strings.LastIndex(s, ":"); i >= 0 {
			host = s[:i]
			port, err := parsePort(s[i+1:])
			if err != nil {
				return nil, err
			}
			t.Port, t.PortExplicit = port, true
		}
	}
	if host == "" {
		return nil, errors.New("missing host")
	}

	if ip := net.ParseIP(host); ip != nil {
		t.IsLiteral = true
		t.IP = ip
		if v4 := ip.To4(); v4 != nil {
			t.IP = v4
		}
		t.Host = host
	} else {
		if len(host) > 253 || !hostnameRe.MatchString(host) {
			return nil, fmt.Errorf("invalid hostname %q", host)
		}
		t.Host = host
	}

	// Endpoint port: explicit > scheme default > 443.
	if !t.PortExplicit {
		switch scheme {
		case "http":
			t.Port = 80
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
	default:
		switch t.Port {
		case 443, 8443:
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
	return t, nil
}

func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return port, nil
}
