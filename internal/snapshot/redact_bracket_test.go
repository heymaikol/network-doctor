package snapshot

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// nat64Prefix is the RFC 6052 well-known prefix. An address inside it carries
// an IPv4 address in its last 32 bits, which identifies the same host.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// identitiesOf is every address that names original: the address itself,
// unmapped, and the IPv4 host a NAT64 address embeds.
func identitiesOf(original string) []netip.Addr {
	address := netip.MustParseAddr(original).Unmap()
	identities := []netip.Addr{address}
	if nat64Prefix.Contains(address) {
		raw := address.As16()
		identities = append(identities, netip.AddrFrom4([4]byte(raw[12:])))
	}
	return identities
}

// assertNoAddress fails when any spelling of any identity of original
// survives in data. The artifact is read the way a person would read it, as
// address-shaped runs of text: compressed or expanded, either case, with a
// dotted-quad tail, in brackets, with a port or a zone. A search for one
// exact string would pass while another spelling of the same address leaked.
// Punctuation is tried on and off each side, since "::" can open an address
// and a colon or a period can close the sentence around one.
func assertNoAddress(t *testing.T, data []byte, original string) {
	t.Helper()
	identities := identitiesOf(original)
	for _, token := range strings.FieldsFunc(string(data), func(r rune) bool {
		return !strings.ContainsRune("0123456789abcdefABCDEF:.%", r)
	}) {
		for _, candidate := range []string{token, strings.TrimRight(token, ".:%"), strings.TrimLeft(token, ".:"), strings.Trim(token, ".:%")} {
			address, err := netip.ParseAddr(candidate)
			if err != nil {
				endpoint, err := netip.ParseAddrPort(candidate)
				if err != nil {
					continue
				}
				address = endpoint.Addr()
			}
			if slices.Contains(identities, address.Unmap().WithZone("")) {
				t.Errorf("support artifact leaked %s as %q:\n%s", original, token, data)
				break
			}
		}
	}
}

// literalEndpoint reads an address and any port out of one address-shaped
// run of text: bare, bracketed, or with a port after either. Brackets belong
// to IPv6 alone, so a bracketed IPv4 address is not an endpoint.
func literalEndpoint(value string) (address netip.Addr, port string, ok bool) {
	if inner, bracketed := strings.CutPrefix(value, "["); bracketed {
		inner, rest, closed := strings.Cut(inner, "]")
		address, err := netip.ParseAddr(inner)
		if !closed || err != nil || !address.Is6() {
			return netip.Addr{}, "", false
		}
		if rest == "" {
			return address, "", true
		}
		port, ok = strings.CutPrefix(rest, ":")
		_, err = strconv.ParseUint(port, 10, 64)
		return address, port, ok && err == nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address, "", true
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || !endpoint.Addr().Is4() {
		return netip.Addr{}, "", false
	}
	return endpoint.Addr(), strconv.Itoa(int(endpoint.Port())), true
}

// An IPv6 target is typed in brackets, and a bracketed address with no port
// is valid to neither netip parser the text pass tried. Target.Raw reached the
// artifact exactly as typed while Host and IP beside it were pseudonymized.
// Only a spelling byte for byte the canonical one escaped, and only in fields
// sanitized after the target had been given its pseudonym: the diagnosis
// summary is sanitized before it, so there even that spelling survived. Each
// target below is what ParseTarget records for its spelling.
func TestSupportPseudonymizesBracketedTargetSpellings(t *testing.T) {
	for _, target := range []Target{
		{Raw: "[64:ff9b::192.0.2.1]", Host: "64:ff9b::192.0.2.1", IP: "64:ff9b::c000:201", Port: 443, Protocol: "tls+http"},
		{Raw: "[64:FF9B::C000:201]", Host: "64:FF9B::C000:201", IP: "64:ff9b::c000:201", Port: 443, Protocol: "tls+http"},
		{Raw: "[2001:db8::beef]", Host: "2001:db8::beef", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http"},
		{Raw: "[2001:DB8::BEEF]", Host: "2001:DB8::BEEF", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http"},
		{Raw: "[2001:0db8:0000:0000:0000:0000:0000:beef]", Host: "2001:0db8:0000:0000:0000:0000:0000:beef", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http"},
		{Raw: "[::ffff:192.0.2.1]", Host: "::ffff:192.0.2.1", IP: "192.0.2.1", Port: 443, Protocol: "tls+http"},
		{Raw: "[::FFFF:C000:201]", Host: "::FFFF:C000:201", IP: "192.0.2.1", Port: 443, Protocol: "tls+http"},
		{Raw: "[2001:db8::beef]:443", Host: "2001:db8::beef", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http", PortExplicit: true},
		{Raw: "[2001:DB8::BEEF]:8443", Host: "2001:DB8::BEEF", IP: "2001:db8::beef", Port: 8443, Protocol: "tls+http", PortExplicit: true},
		{Raw: "[64:ff9b::192.0.2.1]:8443", Host: "64:ff9b::192.0.2.1", IP: "64:ff9b::c000:201", Port: 8443, Protocol: "tls+http", PortExplicit: true},
		{Raw: "[::ffff:192.0.2.1]:443", Host: "::ffff:192.0.2.1", IP: "192.0.2.1", Port: 443, Protocol: "tls+http", PortExplicit: true},
		// The bare spellings accepted since #202 are the same targets.
		{Raw: "64:ff9b::192.0.2.1", Host: "64:ff9b::192.0.2.1", IP: "64:ff9b::c000:201", Port: 443, Protocol: "tls+http"},
		{Raw: "2001:db8::beef", Host: "2001:db8::beef", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http"},
		{Raw: "2001:DB8::BEEF", Host: "2001:DB8::BEEF", IP: "2001:db8::beef", Port: 443, Protocol: "tls+http"},
		{Raw: "::ffff:192.0.2.1", Host: "::ffff:192.0.2.1", IP: "192.0.2.1", Port: 443, Protocol: "tls+http"},
		{Raw: "https://[64:ff9b::192.0.2.1]", Host: "64:ff9b::192.0.2.1", IP: "64:ff9b::c000:201", Port: 443, Protocol: "tls+http"},
		{Raw: "https://[2001:DB8::BEEF]:8443", Host: "2001:DB8::BEEF", IP: "2001:db8::beef", Port: 8443, Protocol: "tls+http", PortExplicit: true},
	} {
		t.Run(target.Raw, func(t *testing.T) {
			s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z", Target: &target,
				Checks:    []Check{{ID: "target_tcp", Name: "TCP " + target.Raw, Status: StatusPass, Ran: true, DurationMs: 1}},
				Diagnosis: Diagnosis{Verdict: "ok", Summary: target.Raw + " is reachable"}, OK: true,
			}
			got := sanitizeValid(t, s)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, spelling := range []string{target.Raw, target.Host} {
				if strings.Contains(string(data), spelling) {
					t.Errorf("support artifact kept the typed spelling %q:\n%s", spelling, data)
				}
			}
			assertNoAddress(t, data, target.IP)

			// Raw is still the endpoint Host and IP name, with the port it had.
			hostPort := got.Target.Raw
			if scheme, rest, ok := strings.Cut(hostPort, "://"); ok {
				if scheme != "https" {
					t.Errorf("sanitized raw %q lost its scheme", got.Target.Raw)
				}
				hostPort = rest
			}
			address, port, ok := literalEndpoint(hostPort)
			ip, ipErr := netip.ParseAddr(got.Target.IP)
			host, hostErr := netip.ParseAddr(got.Target.Host)
			if !ok || ipErr != nil || hostErr != nil || address.Unmap() != ip || host.Unmap() != ip {
				t.Errorf("sanitized target no longer names one endpoint: %+v", *got.Target)
			}
			wantPort := ""
			if target.PortExplicit {
				wantPort = strconv.Itoa(target.Port)
			}
			if port != wantPort || got.Target.Port != target.Port || got.Target.PortExplicit != target.PortExplicit {
				t.Errorf("sanitized target %+v, want port %q kept exactly as explicit as %+v", *got.Target, wantPort, target)
			}
			if !strings.Contains(got.Checks[0].Name, got.Target.Raw) || !strings.Contains(got.Diagnosis.Summary, got.Target.Raw) {
				t.Errorf("free text did not reuse the target pseudonym %q: name=%q summary=%q",
					got.Target.Raw, got.Checks[0].Name, got.Diagnosis.Summary)
			}

			again, err := Encode(SanitizeForSupport(s))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("sanitizing twice differed:\n%s\n%s", data, again)
			}
			decoded, err := Decode(data)
			if err != nil || decoded.Target == nil || *decoded.Target != *got.Target {
				t.Errorf("sanitized target did not round trip: %+v, %v", decoded.Target, err)
			}
		})
	}
}

// The text pass meets bracketed addresses in every free-text field, not only
// in the target: Go writes an IPv6 peer in brackets in its dial errors, and a
// person types one into a summary. None of those may survive, whichever field
// holds them and whatever punctuation surrounds them, and each keeps one
// pseudonym however many fields repeat it.
func TestSupportPseudonymizesBracketedAddressesInText(t *testing.T) {
	for _, test := range []struct{ before, spelling, after, original, port string }{
		{"", "[2001:db8::beef]", "", "2001:db8::beef", ""},
		{"", "[2001:DB8::BEEF]", "", "2001:db8::beef", ""},
		{"", "[2001:0db8:0:0:0:0:0:beef]", "", "2001:db8::beef", ""},
		{"", "[64:ff9b::192.0.2.1]", "", "64:ff9b::c000:201", ""},
		{"", "[::ffff:10.1.2.3]", "", "10.1.2.3", ""},
		{"", "[fe80::1%2]", "", "fe80::1", ""},
		{"", "[fe80::1%12]:53", "", "fe80::1", "53"},
		{"", "[10.1.2.3]", "", "10.1.2.3", ""},
		{"", "[10.1.2.3]:443", "", "10.1.2.3", "443"},
		{"", "[2001:db8::beef]:99999", "", "2001:db8::beef", "99999"},
		{"", "[2001:db8::beef]:443", "", "2001:db8::beef", "443"},
		{"(", "[64:ff9b::192.0.2.1]", ")", "64:ff9b::c000:201", ""},
		{`"`, "[64:ff9b::192.0.2.1]", `",`, "64:ff9b::c000:201", ""},
		{"", "[64:ff9b::192.0.2.1]", ".", "64:ff9b::c000:201", ""},
		{"", "[64:ff9b::192.0.2.1]", ":", "64:ff9b::c000:201", ""},
		{"", "[2001:DB8::BEEF]:443", ".", "2001:db8::beef", "443"},
	} {
		text := test.before + test.spelling + test.after
		t.Run(text, func(t *testing.T) {
			s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
				Checks: []Check{{ID: "route", Name: "Route " + text, Status: StatusFail, Ran: true, DurationMs: 1,
					Detail: "no route to " + text, Fix: "check " + text,
					Observed: &Observed{Attempts: []Attempt{{IP: "198.51.100.7", Error: "dial " + text}}}}},
				Diagnosis: Diagnosis{Verdict: "route", Summary: "unreachable via " + text, FailedStage: "route",
					Findings: []Finding{{ID: "route_failure", Verdict: "route", Summary: "blocked at " + text}}},
			}
			got := sanitizeValid(t, s)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), test.spelling) {
				t.Errorf("support artifact kept %q:\n%s", test.spelling, data)
			}
			assertNoAddress(t, data, test.original)

			fields := map[string]string{"no route to ": got.Checks[0].Detail, "Route ": got.Checks[0].Name,
				"check ": got.Checks[0].Fix, "dial ": got.Checks[0].Observed.Attempts[0].Error,
				"unreachable via ": got.Diagnosis.Summary, "blocked at ": got.Diagnosis.Findings[0].Summary}
			pseudonym := ""
			for prefix, field := range fields {
				rest, okPrefix := strings.CutPrefix(field, prefix+test.before)
				rest, okSuffix := strings.CutSuffix(rest, test.after)
				if !okPrefix || !okSuffix {
					t.Fatalf("text lost its shape around the address: %q", field)
				}
				if pseudonym == "" {
					pseudonym = rest
				}
				if rest != pseudonym {
					t.Errorf("one address got two pseudonyms: %q and %q", pseudonym, rest)
				}
			}
			address, port, ok := literalEndpoint(pseudonym)
			if !ok || port != test.port || address.Unmap() == netip.MustParseAddr(test.original) {
				t.Errorf("pseudonym %q is not an endpoint with port %q standing in for %s", pseudonym, test.port, test.original)
			}

			again, err := Encode(SanitizeForSupport(s))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("sanitizing twice differed:\n%s\n%s", data, again)
			}
		})
	}
}

// Go writes a scoped IPv6 peer with its zone, and on Unix the zone is the name
// of the interface: "dial udp [fe80::1%wlan0]:53". No recorded field names the
// address or the interface here, so the text pass is the only thing that can
// find them, and the zone is not kept: a recorded address loses it too.
func TestSupportPseudonymizesScopedAddressesInText(t *testing.T) {
	for _, test := range []struct{ before, spelling, after, zone, port string }{
		{"", "[fe80::1%wlan0]:53", "", "wlan0", "53"},
		{"", "[fe80::1%wlan0]", "", "wlan0", ""},
		{"", "fe80::1%wlan0", "", "wlan0", ""},
		// An interface name can hold a dot, but punctuation right after a
		// zone belongs to the sentence and has to stay there.
		{"", "[fe80::1%eth0.100]:53", "", "eth0.100", "53"},
		{"", "fe80::1%wlan0", ".", "wlan0", ""},
		{"", "fe80::1%wlan0", ":", "wlan0", ""},
		// A name can hold nearly any character, and Go writes the name it was
		// given, so a zone is read to the end of its word: read as letters,
		// digits, dots, "_" and "-" alone, it leaves "@peer" of "veth@peer".
		{"", "[fe80::1%veth@peer]:53", "", "veth@peer", "53"},
		{"", "fe80::1%veth@peer", "", "veth@peer", ""},
		{"", "fe80::1%veth@peer", "?", "veth@peer", ""},
		{"", "fe80::1%veth@peer", ",", "veth@peer", ""},
		{"", "fe80::1%veth@br0", ":", "veth@br0", ""},
		{"(", "fe80::1%veth@peer", ")", "veth@peer", ""},
		{"", "[fe80::1%veth@peer]:53", ".", "veth@peer", "53"},
		{"", "[fe80::1%veth@peer]:53", ",", "veth@peer", "53"},
		{"(", "[fe80::1%veth@peer]:53", ")", "veth@peer", "53"},
		// In brackets the "]" ends the zone, whatever the name holds.
		{"", "[fe80::1%a+b=c~d$e^f!g?h]:53", "", "a+b=c~d$e^f!g?h", "53"},
		{"", "[fe80::1%a,b]:53", "", "a,b", "53"},
		{"", "[fe80::1%lan#prod]:53", "", "lan#prod", "53"},
		{"", "[fe80::1%lan[prod]:53", "", "lan[prod", "53"},
		// Linux refuses only "/", ":" and whitespace in an interface name, so
		// "lan#prod", "lan,prod" and "lan(prod" are names like "wlan0". A bare
		// zone is read to the next of those, and only the punctuation that
		// ends it stays in the text.
		{"", "fe80::1%lan#prod", "", "lan#prod", ""},
		{"", "fe80::1%lan,prod", "", "lan,prod", ""},
		{"", "fe80::1%lan;prod", "", "lan;prod", ""},
		{"", "fe80::1%lan(prod", "", "lan(prod", ""},
		{"", "fe80::1%lan{prod", "", "lan{prod", ""},
		{"", "fe80::1%lan]prod", "", "lan]prod", ""},
		{"", `fe80::1%lan"prod`, "", `lan"prod`, ""},
		{"", "fe80::1%lan,prod", ", retrying", "lan,prod", ""},
		{"", "fe80::1%lan#prod", ":", "lan#prod", ""},
		{"(", "fe80::1%lan(prod", ")", "lan(prod", ""},
		{`"`, "fe80::1%lan;prod", `".`, "lan;prod", ""},
		{"", "fe80::1%veth@br0", ":53", "veth@br0", ""},
		// netip takes "%" in a zone too, and a zone ends at no "%".
		{"", "fe80::1%%lan", "", "%lan", ""},
		{"", "fe80::1%lan,prod%x", "", "lan,prod%x", ""},
		// Punctuation that ends a zone stays in the text: ping writes
		// "%wlan0(", and a sentence goes on after a comma or a semicolon.
		{"", "fe80::1%wlan0", ",", "wlan0", ""},
		{"", "fe80::1%wlan0", ";", "wlan0", ""},
		{"", "fe80::1%wlan0", ", retrying", "wlan0", ""},
		{"", "fe80::1%wlan0", "; retrying", "wlan0", ""},
		{"(", "fe80::1%wlan0", ")", "wlan0", ""},
		{"(", "fe80::1%wlan0", "),", "wlan0", ""},
		{`"`, "fe80::1%wlan0", `"`, "wlan0", ""},
		// nslookup and dig write a port after "#", but "wlan0#53" is a name
		// too, and one that cannot be told from it. The "#53" goes with the
		// zone rather than leave what may be the end of a name behind.
		{"", "fe80::1%wlan0#53", "", "wlan0#53", ""},
	} {
		text := test.before + test.spelling + test.after
		t.Run(text, func(t *testing.T) {
			s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
				Checks: []Check{{ID: "route", Name: "Route", Status: StatusFail, Ran: true, DurationMs: 1,
					Detail: "dial udp " + text, Fix: "check " + text}},
				Diagnosis: Diagnosis{Verdict: "route", Summary: "unreachable via " + text, FailedStage: "route"},
			}
			got := sanitizeValid(t, s)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), test.zone) || strings.Contains(string(data), "%") {
				t.Errorf("support artifact kept the zone %q:\n%s", test.zone, data)
			}
			// A zone read only up to its punctuation leaves the rest of the
			// name behind: "@peer" of "veth@peer".
			for i := 1; i < len(test.zone); i++ {
				if !identifierByte(test.zone[i]) && strings.Contains(string(data), test.zone[i:]) {
					t.Errorf("support artifact kept %q of the zone %q:\n%s", test.zone[i:], test.zone, data)
				}
			}
			assertNoAddress(t, data, "fe80::1")

			fields := map[string]string{"dial udp ": got.Checks[0].Detail, "check ": got.Checks[0].Fix,
				"unreachable via ": got.Diagnosis.Summary}
			pseudonym := ""
			for prefix, field := range fields {
				rest, okPrefix := strings.CutPrefix(field, prefix+test.before)
				rest, okSuffix := strings.CutSuffix(rest, test.after)
				if !okPrefix || !okSuffix {
					t.Fatalf("text lost its shape around the address: %q", field)
				}
				if pseudonym == "" {
					pseudonym = rest
				}
				if rest != pseudonym {
					t.Errorf("one address got two pseudonyms: %q and %q", pseudonym, rest)
				}
			}
			address, port, ok := literalEndpoint(pseudonym)
			if !ok || port != test.port || address.Zone() != "" || address == netip.MustParseAddr("fe80::1") {
				t.Errorf("pseudonym %q is not an unscoped endpoint with port %q standing in for fe80::1", pseudonym, test.port)
			}

			again, err := Encode(SanitizeForSupport(s))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("sanitizing twice differed:\n%s\n%s", data, again)
			}
		})
	}
}

// A line can hold a zone more than once, or run one zone into the next
// address with no space between: ping writes "PING host(address)", dig writes
// "address#port(address)", and a list joins addresses with commas. Every
// zone goes, whatever punctuation its name holds, and the text between the
// addresses stays. In want, "{n}" stands for the pseudonym of fe80::bee:n,
// which has to be an unscoped address, and "{user}" for a user label's alias.
func TestSupportScopedTextDropsEveryZoneOnALine(t *testing.T) {
	for _, test := range []struct{ text, want string }{
		{"PING fe80::bee:1%lan(prod(fe80::bee:1%lan(prod) 56 data bytes", "PING {1}({1}) 56 data bytes"},
		{"PING fe80::bee:1%wlan0(fe80::bee:1%wlan0) 56 data bytes", "PING {1}({1}) 56 data bytes"},
		{"SERVER: fe80::bee:1%lan#prod#53(fe80::bee:1%lan#prod)", "SERVER: {1}({1})"},
		{"SERVER: fe80::bee:1%wlan0#53(fe80::bee:1%wlan0)", "SERVER: {1}({1})"},
		{"fe80::bee:1%lan,prod,fe80::bee:2%lan;prod", "{1},{2}"},
		{"fe80::bee:1%wlan0,fe80::bee:2%eth0", "{1},{2}"},
		{"fe80::bee:1%wlan0,fe80::bee:2,fe80::bee:2", "{1},{2},{2}"},
		{"fe80::bee:1%lan#prod,[fe80::bee:2]:53", "{1},[{2}]:53"},
		{"fe80::bee:1%lan,prod,user:alice", "{1},user={user}"},
	} {
		t.Run(test.text, func(t *testing.T) {
			s := freeTextSnapshot("unreachable: "+test.text, test.text, "check "+test.text)
			got := sanitizeValid(t, s)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"%", "prod", "wlan0", "eth0", "alice"} {
				if strings.Contains(string(data), secret) {
					t.Errorf("support artifact kept %q:\n%s", secret, data)
				}
			}
			assertNoAddress(t, data, "fe80::bee:1")
			assertNoAddress(t, data, "fe80::bee:2")

			placeholder := regexp.MustCompile(`\\\{([12])\\\}`)
			quoted := regexp.QuoteMeta(test.want)
			var order []string
			for _, match := range placeholder.FindAllStringSubmatch(quoted, -1) {
				order = append(order, match[1])
			}
			pattern := regexp.MustCompile("^" + strings.Replace(placeholder.ReplaceAllString(quoted, "([0-9a-f:.]+)"), regexp.QuoteMeta("{user}"), "user-[0-9]+", 1) + "$")
			pseudonyms := map[string]string{}
			for prefix, field := range map[string]string{"unreachable: ": got.Diagnosis.Summary, "": got.Checks[0].Detail, "check ": got.Checks[0].Fix} {
				rest, ok := strings.CutPrefix(field, prefix)
				groups := pattern.FindStringSubmatch(rest)
				if !ok || groups == nil {
					t.Fatalf("sanitized %q, want the shape %q", field, test.want)
				}
				for i, pseudonym := range groups[1:] {
					original := netip.MustParseAddr("fe80::bee:" + order[i])
					address, err := netip.ParseAddr(pseudonym)
					if err != nil || address.Zone() != "" || address == original {
						t.Errorf("pseudonym %q is not an unscoped address standing in for %s", pseudonym, original)
					}
					if seen, ok := pseudonyms[original.String()]; ok && seen != pseudonym {
						t.Errorf("%s got two pseudonyms: %q and %q", original, seen, pseudonym)
					}
					pseudonyms[original.String()] = pseudonym
				}
			}
			if len(pseudonyms) == 2 && pseudonyms["fe80::bee:1"] == pseudonyms["fe80::bee:2"] {
				t.Errorf("two addresses share the pseudonym %q", pseudonyms["fe80::bee:1"])
			}

			again, err := Encode(SanitizeForSupport(s))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("sanitizing twice differed:\n%s\n%s", data, again)
			}
		})
	}
}

// freeTextSnapshot carries its text in free-text fields alone, so only the
// text pass can find what they name.
func freeTextSnapshot(summary, detail, fix string) Snapshot {
	return Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Checks: []Check{{ID: "route", Name: "Route", Status: StatusFail, Ran: true, DurationMs: 1,
			Detail: detail, Fix: fix}},
		Diagnosis: Diagnosis{Verdict: "route", Summary: summary, FailedStage: "route"},
	}
}

// A zone only proposes a longer candidate, and reading one must never cost an
// address beside it its pseudonym. Read as far as the next address, the zone
// "?10.9.8.7" of "100%?10.9.8.7" makes a run that parses as nothing, and such
// a run is returned whole. A candidate a zone made that does not parse is
// read again piece by piece, the IPv4 address netip will not scope and the
// zone each on its own, and the zone of an address that did parse is dropped
// with what it holds.
func TestSupportScopedTextHidesNoOtherAddress(t *testing.T) {
	for _, test := range []struct {
		text      string
		originals []string
	}{
		{"loss 100%?10.9.8.7", []string{"10.9.8.7"}},
		{"loss 100%x 10.9.8.7", []string{"10.9.8.7"}},
		{"loss 100%x10.9.8.7", []string{"10.9.8.7"}},
		{"route 10.9.8.7%eth0", []string{"10.9.8.7"}},
		{"dial udp [10.9.8.7%eth0]:53", []string{"10.9.8.7"}},
		{"via a%br-lan2620:fe::fe", []string{"2620:fe::fe"}},
		{"fe80::1%?10.9.8.7", []string{"fe80::1", "10.9.8.7"}},
		{"fe80::1%x@10.9.8.7:53", []string{"fe80::1", "10.9.8.7"}},
		{"[fe80::1%veth@peer]:53 then 10.9.8.7", []string{"fe80::1", "10.9.8.7"}},
		{"fe80::1%veth@peer,fe80::2%wlan0", []string{"fe80::1", "fe80::2"}},
	} {
		t.Run(test.text, func(t *testing.T) {
			s := freeTextSnapshot("unreachable: "+test.text, test.text, "check "+test.text)
			data, err := Encode(sanitizeValid(t, s))
			if err != nil {
				t.Fatal(err)
			}
			for _, original := range test.originals {
				assertNoAddress(t, data, original)
			}
			again, err := Encode(SanitizeForSupport(s))
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(data) {
				t.Errorf("sanitizing twice differed:\n%s\n%s", data, again)
			}
		})
	}
}

// A label, a certificate name or a path that begins in the rest of a zone
// and runs on past it ends the zone there, and is left whole to the pattern
// that redacts it, which needs all of it: dropping the "=" of "@y=/home/alice"
// would leave the path without the "=" it is found after.
func TestSupportScopedTextLeavesLabelsWhole(t *testing.T) {
	for _, text := range []string{
		"fe80::1%x@user:alice",
		"fe80::1%x@y=/home/alice",
		"fe80::1%x?cert is for alice",
	} {
		t.Run(text, func(t *testing.T) {
			data, err := Encode(sanitizeValid(t, freeTextSnapshot("unreachable: "+text, text, "check "+text)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "alice") {
				t.Errorf("support artifact kept alice:\n%s", data)
			}
			assertNoAddress(t, data, "fe80::1")
		})
	}
}

// replaceKnown writes the name of whatever the pass has named wherever it
// meets the spelling again, so what one field names has to be named for the
// same text everywhere. A spelling collected in two alias namespaces is named
// before any field is sanitized, from the text the collection pass read,
// which is why that pass reads a zone's rest as text instead of dropping it.
// A candidate that did not parse is recovered only after the label patterns,
// so a certificate name that holds one is named for the same text in every
// field. And an IPv6 address that failed with its zone is malformed and left
// unnamed: "::dead:beef" stands apart inside "fe80::dead:beef", and named, it
// would split the scoped address in the next field and leave its zone behind.
func TestSupportScopedTextNamesALabelTheSameEverywhere(t *testing.T) {
	for _, test := range []struct {
		summary, detail, fix, secret string
		originals                    []string
	}{
		{"", "open /srv/fe80::1%veth@peer10.9.8.7x", "ssid:/srv/fe80::1%veth@peer10.9.8.7x", "peer", []string{"fe80::1", "10.9.8.7"}},
		{"tls: cert is for frank10.9.8.7%12", "dial frank10.9.8.7%12", "", "frank", []string{"10.9.8.7"}},
		{"gateway ::dead:beef.%eth0 unreachable", "dial udp [fe80::dead:beef%veth]:53", "", "veth", []string{"fe80::dead:beef"}},
	} {
		t.Run(test.secret, func(t *testing.T) {
			data, err := Encode(sanitizeValid(t, freeTextSnapshot(test.summary, test.detail, test.fix)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), test.secret) {
				t.Errorf("support artifact kept %s:\n%s", test.secret, data)
			}
			for _, original := range test.originals {
				assertNoAddress(t, data, original)
			}
		})
	}
}

// A profile's own text goes through the same pass as every component's.
func TestProfileSupportPseudonymizesBracketedAddressesInText(t *testing.T) {
	pinLocalIdentity(t)
	profile := profileFixture()
	profile.Profile.Title = "SSH via [64:ff9b::192.0.2.1]"
	profile.Components[0].Label = "ssh [2001:DB8::BEEF]"
	profile.Aggregate.Summary = "[64:ff9b::192.0.2.1] refused; [2001:DB8::BEEF] answered."
	before, err := EncodeProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	sanitized := SanitizeProfileForSupport(profile)
	after, err := EncodeProfile(profile)
	if err != nil || string(after) != string(before) {
		t.Fatalf("SanitizeProfileForSupport modified the full-fidelity profile: %v", err)
	}
	data, err := EncodeProfile(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAddress(t, data, "64:ff9b::c000:201")
	assertNoAddress(t, data, "2001:db8::beef")
	nat64, _ := strings.CutPrefix(sanitized.Profile.Title, "SSH via ")
	beef, _ := strings.CutPrefix(sanitized.Components[0].Label, "ssh ")
	if want := nat64 + " refused; " + beef + " answered."; sanitized.Aggregate.Summary != want || nat64 == beef {
		t.Errorf("profile text lost one pseudonym per address: title=%q label=%q summary=%q",
			sanitized.Profile.Title, sanitized.Components[0].Label, sanitized.Aggregate.Summary)
	}
}

// Only the configured public resolver stays readable, and it stays readable in
// brackets too. A bracketed public address that is not the resolver is
// pseudonymized like any other.
func TestSupportBracketedTextKeepsTheRetainedResolver(t *testing.T) {
	s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Options: Options{PublicDNS: "2620:fe::fe"},
		Checks: []Check{{ID: "dns_public", Name: "Public DNS", Status: StatusFail, Ran: true, DurationMs: 1,
			Detail: "dial [2620:fe::fe]:53 and [2620:fe::fe] refused; [2620:fe::9] timed out"}},
		Diagnosis: Diagnosis{Verdict: "dns", Summary: "failed", FailedStage: "dns_public"},
	}
	got := sanitizeValid(t, s)
	if got.Options.PublicDNS != "2620:fe::fe" {
		t.Errorf("configured resolver lost: public_dns=%q", got.Options.PublicDNS)
	}
	rest, ok := strings.CutPrefix(got.Checks[0].Detail, "dial [2620:fe::fe]:53 and [2620:fe::fe] refused; ")
	if !ok {
		t.Fatalf("the retained resolver did not stay readable: %q", got.Checks[0].Detail)
	}
	data, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAddress(t, data, "2620:fe::9")
	if !strings.HasPrefix(rest, "[") || !strings.HasSuffix(rest, "] timed out") {
		t.Errorf("text-only public address lost its brackets: %q", got.Checks[0].Detail)
	}
}

// A hostname target has no address for any of this to find, so it is
// sanitized exactly as it was: one host alias, the explicit port kept.
func TestSupportHostnameTargetsKeepTheirAlias(t *testing.T) {
	for _, target := range []Target{
		{Raw: "uniquetarget.example", Host: "uniquetarget.example", Port: 443, Protocol: "tls+http"},
		{Raw: "uniquetarget.example:8443", Host: "uniquetarget.example", Port: 8443, Protocol: "tls+http", PortExplicit: true},
		{Raw: "https://uniquetarget.example", Host: "uniquetarget.example", Port: 443, Protocol: "tls+http"},
	} {
		s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
			Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z", Target: &target,
			Checks: []Check{}, Diagnosis: Diagnosis{Verdict: "ok", Summary: "healthy"}, OK: true,
		}
		got := sanitizeValid(t, s)
		want := strings.Replace(target.Raw, target.Host, got.Target.Host, 1)
		if !strings.HasSuffix(got.Target.Host, ".invalid") || got.Target.Raw != want || got.Target.IP != "" ||
			got.Target.Port != target.Port || got.Target.PortExplicit != target.PortExplicit {
			t.Errorf("%s: sanitized target %+v, want raw %q", target.Raw, *got.Target, want)
		}
	}
}
