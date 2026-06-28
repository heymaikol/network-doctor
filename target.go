package main

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
	Host         string
	IP           net.IP // set iff IsLiteral
	Port         int
	Scheme       string
	Proto        Proto
	PortExplicit bool
	IsLiteral    bool
	Raw          string
}

// hostnameRe is a strict RFC-1123-ish hostname allowlist (labels of
// alphanumerics + internal hyphens, dot-separated). Everything else is rejected
// so nothing user-supplied is ever fed to a probe or (later) a command.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// parseTarget parses a CLI target: <host> | <host>:<port> | http(s)://<host>[:port][/path].
// IPv6 literals are rejected (out of scope). Returns a typed Target or an error
// (caller exits 2 on error).
func parseTarget(raw string) (*Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty target")
	}
	t := &Target{Raw: raw}

	if i := strings.Index(s, "://"); i >= 0 {
		t.Scheme = strings.ToLower(s[:i])
		if t.Scheme != "http" && t.Scheme != "https" {
			return nil, fmt.Errorf("unsupported scheme %q (only http/https)", t.Scheme)
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
	// IPv6 literal forms (bracketed, or >1 colon) are out of scope.
	if strings.ContainsAny(s, "[]") || strings.Count(s, ":") > 1 {
		return nil, errors.New("IPv6 literals are out of scope (IPv4 only)")
	}

	host := s
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host = s[:i]
		port, err := strconv.Atoi(s[i+1:])
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", s[i+1:])
		}
		t.Port = port
		t.PortExplicit = true
	}
	if host == "" {
		return nil, errors.New("missing host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return nil, errors.New("IPv6 literals are out of scope (IPv4 only)")
		}
		t.IsLiteral = true
		t.IP = ip.To4()
		t.Host = host
	} else {
		if len(host) > 253 || !hostnameRe.MatchString(host) {
			return nil, fmt.Errorf("invalid hostname %q", host)
		}
		t.Host = host
	}

	// Endpoint port: explicit > scheme default > 443.
	if !t.PortExplicit {
		switch t.Scheme {
		case "http":
			t.Port = 80
		default: // https or bare host
			t.Port = 443
		}
	}

	// Protocol rows: explicit scheme wins; else infer from the effective port.
	switch t.Scheme {
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
