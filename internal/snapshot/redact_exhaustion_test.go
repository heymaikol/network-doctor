package snapshot

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestSupportAliasExhaustion(t *testing.T) {
	pinLocalIdentity(t)
	for _, tc := range []struct {
		prefix   string
		textOnly bool
	}{{"0.0.0.0/1", false}, {"", false}, {"0.0.0.0/1", true}} {
		t.Run(fmt.Sprintf("prefix=%s/text=%t", tc.prefix, tc.textOnly), func(t *testing.T) {
			const original = "10.1.0.0"
			s := routePrefixSnapshot(Route{Destination: original, Source: original, Family: "ipv4", Prefix: tc.prefix})
			s.Target = &Target{Raw: original + ":9100", Host: original, IP: original, Port: 9100, Protocol: "tcp", PortExplicit: true}
			s.Checks[0].Detail = "peer " + original
			s.Checks[0].Fix = "connect " + original + ":9100"
			var detail strings.Builder
			detail.WriteString(s.Checks[0].Detail)
			reserved := make(map[string]bool, 1<<16)
			for n := uint32(1); n <= 1<<16; n++ {
				// Independent enumeration of the allocator's first 65,536 candidates.
				ip := fmt.Sprintf("10.%d.%d.%d", n>>16, (n>>8)&255, n&255)
				reserved[ip] = true
				if tc.textOnly {
					detail.WriteByte(' ')
					detail.WriteString(ip)
				} else {
					s.Checks[0].Observed.Addresses = append(s.Checks[0].Observed.Addresses, ip)
				}
			}
			if tc.textOnly {
				s.Checks[0].Detail = detail.String()
			}
			input, err := Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(input); err != nil {
				t.Fatal(err)
			}
			safe := SanitizeForSupport(s)
			alias := safe.Target.IP
			t.Logf("input bytes=%d reserved=%d original=%s alias=%s reserved alias=%t", len(input), len(reserved), original, alias, reserved[alias])
			if alias == original || reserved[alias] {
				t.Fatalf("support alias leaked a reserved original: %s", alias)
			}
			if alias != redactedAddress && !netip.MustParseAddr(alias).IsPrivate() {
				t.Fatalf("private class lost: %s", alias)
			}
			// A literal target cannot carry the existing erasure marker: publication
			// must fail rather than treating erased evidence as a usable endpoint.
			if data, err := Encode(safe); err == nil || len(data) != 0 {
				t.Fatalf("erased literal target published: %v", err)
			}
			if safe.Checks[0].Observed.Routes[0].Destination != alias || safe.Checks[0].Observed.Routes[0].Source != alias || !strings.HasPrefix(safe.Checks[0].Detail, "peer "+alias) {
				t.Fatal("equality lost across structured and text fields")
			}
			if safe.Checks[0].Fix != "connect "+alias+":9100" {
				t.Fatalf("endpoint text lost erasure or port: %s", safe.Checks[0].Fix)
			}
			again := SanitizeForSupport(s)
			if again.Target.IP != alias || again.Checks[0].Detail != safe.Checks[0].Detail {
				t.Fatal("non-deterministic exhaustion")
			}
			// Without a literal target, support-v1 permits address erasure markers.
			safe.Target = nil
			data, err := Encode(safe)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(data); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(original)) {
				t.Fatal("original survived in support bytes")
			}
			seen := map[string]bool{}
			for _, ip := range safe.Checks[0].Observed.Addresses {
				if ip == redactedAddress {
					continue
				}
				if reserved[ip] || seen[ip] {
					t.Fatalf("unsafe or reused successful alias: %s", ip)
				}
				seen[ip] = true
			}
		})
	}
}

func TestSupportAliasNearExhaustion(t *testing.T) {
	pinLocalIdentity(t)
	const original, remaining = "10.20.30.40", "10.1.0.0"
	s := routePrefixSnapshot(Route{Destination: original, Source: original, Gateway: "10.20.30.41", Family: "ipv4", Prefix: "0.0.0.0/1"})
	s.Checks[0].Detail = "peer " + original
	reserved := map[string]bool{original: true, "10.20.30.41": true}
	for n := uint32(1); n <= 1<<16; n++ {
		ip := fmt.Sprintf("10.%d.%d.%d", n>>16, (n>>8)&255, n&255)
		if ip != remaining {
			reserved[ip] = true
			s.Checks[0].Observed.Addresses = append(s.Checks[0].Observed.Addresses, ip)
		}
	}
	safe := SanitizeForSupport(s)
	route := safe.Checks[0].Observed.Routes[0]
	if route.Destination != remaining {
		t.Fatalf("near exhaustion alias=%s, want %s", route.Destination, remaining)
	}
	if route.Source != route.Destination || safe.Checks[0].Detail != "peer "+remaining {
		t.Fatal("equality lost")
	}
	if route.Gateway == route.Destination {
		t.Fatal("distinct originals collapsed")
	}
	for _, ip := range []string{route.Destination, route.Gateway} {
		if reserved[ip] || !netip.MustParseAddr(ip).IsPrivate() {
			t.Fatalf("unsafe alias %s", ip)
		}
	}
	data, err := Encode(safe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
	again, err := Encode(SanitizeForSupport(s))
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("non-deterministic near exhaustion: %v", err)
	}
}

func TestSupportPrefixAliasExhaustion(t *testing.T) {
	pinLocalIdentity(t)
	s := routePrefixSnapshot(Route{Destination: "10.0.0.0", Source: "10.0.0.0", Family: "ipv4", Prefix: "10.0.0.0/16"})
	reserved := map[string]bool{}
	for n := range 256 {
		ip := fmt.Sprintf("10.%d.0.0", n)
		reserved[ip] = true
		s.Checks[0].Observed.Addresses = append(s.Checks[0].Observed.Addresses, ip)
	}
	input, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(input); err != nil {
		t.Fatal(err)
	}
	safe := SanitizeForSupport(s)
	route := safe.Checks[0].Observed.Routes[0]
	if route.Prefix != "" {
		t.Fatalf("exhausted prefix published: %s", route.Prefix)
	}
	if reserved[route.Destination] || !netip.MustParseAddr(route.Destination).IsPrivate() {
		t.Fatalf("unsafe fallback %s", route.Destination)
	}
	data, err := Encode(safe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("10.0.0.0/16")) {
		t.Fatal("original prefix leaked")
	}
	again, err := Encode(SanitizeForSupport(s))
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("non-deterministic prefix exhaustion: %v", err)
	}
}

// A finite namespace can also fill with issued aliases rather than originals.
func TestSupportAliasIssuedExhaustion(t *testing.T) {
	pinLocalIdentity(t)
	s := routePrefixSnapshot()
	originals := map[string]bool{}
	for n := uint32(0); n <= 1<<16; n++ {
		ip := fmt.Sprintf("203.%d.%d.%d", n>>16, (n>>8)&255, n&255)
		originals[ip] = true
		s.Checks[0].Observed.Addresses = append(s.Checks[0].Observed.Addresses, ip)
	}
	if _, err := Encode(s); err != nil {
		t.Fatal(err)
	}
	safe := SanitizeForSupport(s)
	seen := map[string]bool{}
	for i, ip := range safe.Checks[0].Observed.Addresses {
		if i == 1<<16 {
			if ip != redactedAddress {
				t.Fatalf("full namespace reused alias %s", ip)
			}
			continue
		}
		if originals[ip] || seen[ip] {
			t.Fatalf("original or issued alias reused: %s", ip)
		}
		seen[ip] = true
	}
	data, err := Encode(safe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
}
