package diagnostic

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		port    int
		proto   Proto
		literal bool
	}{
		{"github.com", "github.com", 443, ProtoTLSHTTP, false},
		{"github.com:22", "github.com", 22, ProtoSSH, false},
		{"https://github.com", "github.com", 443, ProtoTLSHTTP, false},
		{"http://example.com", "example.com", 80, ProtoHTTP, false},
		{"https://host:80", "host", 80, ProtoTLSHTTP, false}, // scheme selects proto
		{"http://host:443", "host", 443, ProtoHTTP, false},   // scheme selects proto
		{"1.1.1.1", "1.1.1.1", 443, ProtoTLSHTTP, true},
		{"1.1.1.1:25", "1.1.1.1", 25, ProtoSMTP, true},
		{"mail.example.com:587", "mail.example.com", 587, ProtoSMTP, false},
		{"https://github.com/owner/repo", "github.com", 443, ProtoTLSHTTP, false},
		{"host:8443", "host", 8443, ProtoTLSHTTP, false},
		{"::1", "::1", 443, ProtoTLSHTTP, true},
		{"fe80::1", "fe80::1", 443, ProtoTLSHTTP, true},
		{"[::1]", "::1", 443, ProtoTLSHTTP, true},
		{"[2001:db8::1]:22", "2001:db8::1", 22, ProtoSSH, true},
		{"https://[2001:db8::1]:8443/path", "2001:db8::1", 8443, ProtoTLSHTTP, true},
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
			if tg.IsLiteral != c.literal {
				t.Errorf("literal = %v, want %v", tg.IsLiteral, c.literal)
			}
		})
	}
}

func TestParseTargetErrors(t *testing.T) {
	bad := []string{"", "host:0", "host:99999", "ftp://host", "bad_host!",
		"[::1", "[::1]x", "[1.2.3.4]:80", "[hostname]:80", "[]:80", "[fe80::1%eth0]", "a:b:c"}
	for _, in := range bad {
		if tg, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want error", in, tg)
		}
	}
}
