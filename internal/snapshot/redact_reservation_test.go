package snapshot

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// hostPairSnapshot names first as the target and second as the captive portal
// the run was redirected to, so collection meets first before second.
func hostPairSnapshot(first, second string) Snapshot {
	return Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Target: &Target{Raw: first + ":443", Host: first, Port: 443, Protocol: "tcp", PortExplicit: true},
		Checks: []Check{{
			ID: "portal", Name: "Portal", Status: StatusPass, Ran: true, DurationMs: 1,
			Detail:   "redirected from " + first + " to " + second,
			Observed: &Observed{Portal: &Portal{RedirectURL: "http://" + second + "/login"}},
		}},
		Diagnosis: Diagnosis{Verdict: "ok", Summary: "healthy"}, OK: true,
	}
}

// assertNotLeaked fails when any original survives anywhere in the artifact.
func assertNotLeaked(t *testing.T, data []byte, originals ...string) {
	t.Helper()
	for _, original := range originals {
		if strings.Contains(string(data), original) {
			t.Errorf("support artifact leaked %q:\n%s", original, data)
		}
	}
}

// inspectSupport is SanitizeForSupport with its redactor kept for inspection.
// assertAliasInvariants checks the two stay the same pipeline.
func inspectSupport(t *testing.T, s Snapshot) (Snapshot, *redactor) {
	t.Helper()
	r := newRedactor()
	r.collectSnapshot(s)
	r.snapshot(s)
	r.finishCollection()
	got := r.snapshot(s)
	if !reflect.DeepEqual(got, SanitizeForSupport(s)) {
		t.Fatal("inspectSupport no longer matches SanitizeForSupport")
	}
	return got, r
}

// assertAliasInvariants holds every alias namespace to the property the
// reservation exists for: no pseudonym names an original of its namespace,
// and no two originals share one, except the pinned local machine's long and
// short names, which are one host by design. Host names are compared as DNS
// names, so spellings of one hostname are one original.
func assertAliasInvariants(t *testing.T, r *redactor) {
	t.Helper()
	for kind, values := range r.aliases {
		identity := func(name string) string { return name }
		if kind == "host" {
			identity = dnsName
		}
		originals := map[string]bool{}
		for original := range values {
			originals[identity(original)] = true
		}
		for reserved := range r.originalAliases[kind] {
			originals[identity(reserved)] = true
		}
		owners := map[string]map[string]bool{}
		for original, alias := range values {
			if originals[identity(alias)] {
				t.Errorf("%s alias %q for %q is also an original", kind, alias, original)
			}
			if owners[identity(alias)] == nil {
				owners[identity(alias)] = map[string]bool{}
			}
			owners[identity(alias)][identity(original)] = true
		}
		for alias, owned := range owners {
			var names []string
			for name := range owned {
				names = append(names, name)
			}
			sort.Strings(names)
			if len(names) > 1 && !reflect.DeepEqual(names, []string{"sanitizer-test-box", "sanitizer-test-box.example"}) {
				t.Errorf("%s originals %q collapsed onto %q", kind, names, alias)
			}
		}
	}
}

// A host alias is chosen only once every host original is known, so an
// original spelled like an alias cannot be handed to another host, in
// whichever order the two are met.
func TestSupportHostAliasesAvoidEveryOriginalInBothOrders(t *testing.T) {
	pinLocalIdentity(t)
	// The pinned machine name takes host-1.invalid, so host-2.invalid is the
	// alias the first collected host would otherwise receive.
	for _, order := range [][2]string{{"corp.example", "host-2.invalid"}, {"host-2.invalid", "corp.example"}} {
		t.Run(order[0]+" first", func(t *testing.T) {
			s := hostPairSnapshot(order[0], order[1])
			got, r := inspectSupport(t, s)
			assertAliasInvariants(t, r)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			assertNotLeaked(t, data, order[0], order[1])
			portal, err := url.Parse(got.Checks[0].Observed.Portal.RedirectURL)
			if err != nil {
				t.Fatal(err)
			}
			target, redirected := got.Target.Host, portal.Hostname()
			if target == redirected {
				t.Errorf("distinct hosts %q and %q collapsed onto %q", order[0], order[1], target)
			}
			if host, _, err := net.SplitHostPort(got.Target.Raw); err != nil || host != target {
				t.Errorf("Target.Raw = %q, want host %q", got.Target.Raw, target)
			}
			if want := "redirected from " + target + " to " + redirected; got.Checks[0].Detail != want {
				t.Errorf("detail = %q, want %q", got.Checks[0].Detail, want)
			}
			again, err := Encode(SanitizeForSupport(s))
			if err != nil || string(again) != string(data) {
				t.Errorf("the same snapshot did not sanitize deterministically")
			}
		})
	}
}

// A profile shares one mapping across its components, so a host collected
// from one component has to be kept off an alias another component's host is
// literally spelled as.
func TestProfileSupportHostAliasesAvoidEveryComponentOriginal(t *testing.T) {
	pinLocalIdentity(t)
	profile := profileFixture()
	for i, host := range []string{"corp.example", "host-2.invalid"} {
		s := &profile.Components[i].Snapshot
		s.Target.Raw, s.Target.Host = host+":22", host
		s.Checks[0].Name, s.Diagnosis.Summary = "TCP "+host+":22", host+" result"
	}
	sanitized := SanitizeProfileForSupport(profile)
	data, err := EncodeProfile(sanitized)
	if err != nil {
		t.Fatal(err)
	}
	assertNotLeaked(t, data, "corp.example", "host-2.invalid")
	first, second := sanitized.Components[0].Snapshot, sanitized.Components[1].Snapshot
	if first.Target.Host == second.Target.Host {
		t.Errorf("distinct component hosts collapsed onto %q", first.Target.Host)
	}
	for _, component := range []Snapshot{first, second} {
		if want := "TCP " + component.Target.Host + ":22"; component.Checks[0].Name != want {
			t.Errorf("check name = %q, want %q", component.Checks[0].Name, want)
		}
	}
	again, err := EncodeProfile(SanitizeProfileForSupport(profile))
	if err != nil || string(again) != string(data) {
		t.Error("the same profile did not sanitize deterministically")
	}
}

// An incident's states share one mapping, so a host met only in a nested
// state is reserved before the onset's target takes an alias.
func TestSupportIncidentHostAliasesAvoidNestedOriginals(t *testing.T) {
	pinLocalIdentity(t)
	s := watchIncident()
	s.Incident.During.Checks[0].Observed = &Observed{Portal: &Portal{RedirectURL: "http://host-2.invalid/login"}}
	data, err := Encode(SanitizeForSupport(s))
	if err != nil {
		t.Fatal(err)
	}
	assertNotLeaked(t, data, "example.com", "host-2.invalid")
	got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	portal, err := url.Parse(got.Incident.During.Checks[0].Observed.Portal.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if portal.Hostname() == got.Target.Host {
		t.Errorf("the nested portal host collapsed onto the target's %q", got.Target.Host)
	}
}

// Only a custom table name is an identity. A literal "route-table-1" is one
// too, and has to keep its distance from the alias another table would get.
func TestSupportRouteTableAliasesAvoidEveryOriginalInBothOrders(t *testing.T) {
	pinLocalIdentity(t)
	route := func(table string) Route {
		return Route{Destination: "192.0.2.1", Family: "ipv4", Table: table, TableKnown: true}
	}
	for _, order := range [][2]string{{"corp-vpn", "route-table-1"}, {"route-table-1", "corp-vpn"}} {
		t.Run(order[0]+" first", func(t *testing.T) {
			s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
				Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
				Checks: []Check{{ID: "route", Name: "Route", Status: StatusPass, Ran: true, DurationMs: 1,
					Observed: &Observed{Routes: []Route{
						route(order[0]), route(order[1]), route(order[0]),
						route("main"), route("default"), route("local"), route("254"),
					}},
				}},
				Diagnosis: Diagnosis{Verdict: "ok", Summary: "healthy"}, OK: true,
			}
			got, r := inspectSupport(t, s)
			assertAliasInvariants(t, r)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			assertNotLeaked(t, data, "corp-vpn", "route-table-1")
			var tables []string
			for _, route := range got.Checks[0].Observed.Routes {
				tables = append(tables, route.Table)
			}
			if tables[0] == tables[1] || tables[0] != tables[2] {
				t.Errorf("tables = %q, want two distinct pseudonyms with the first repeated", tables)
			}
			if want := []string{"main", "default", "local", "254"}; !reflect.DeepEqual(tables[3:], want) {
				t.Errorf("reserved tables = %q, want %q unchanged", tables[3:], want)
			}
		})
	}
}

// Identities found only by the text patterns are originals too. Each literal
// below is exactly the alias a structured or seeded value would take if the
// text were not reserved first, and each one has to stay a different identity
// from that value while the structured spelling keeps its own alias in text.
func TestSupportTextIdentitiesAreReservedBeforeAllocation(t *testing.T) {
	pinLocalIdentity(t)
	s := Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Target: &Target{Raw: "corp.example:443", Host: "corp.example", Port: 443, Protocol: "tcp", PortExplicit: true},
		Checks: []Check{{
			ID: "wifi", Name: "Wi-Fi", Status: StatusFail, Ran: true, DurationMs: 1,
			Detail: "hostname=corp.example hostname=host-2.invalid machine=sanitizer-test-box hostname=host-1.invalid " +
				"user=sanitizer-test-account user=user-1 SSID=CafeWifi SSID=ssid-1",
			Fix:      "certificate is for host-3.invalid, retry host-3.invalid",
			Observed: &Observed{SSID: "CafeWifi"},
		}},
		Diagnosis: Diagnosis{Verdict: "wifi", Summary: "failed", FailedStage: "wifi"},
	}
	got, r := inspectSupport(t, s)
	assertAliasInvariants(t, r)
	data, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	assertNotLeaked(t, data, "corp.example", "host-1.invalid", "host-2.invalid", "host-3.invalid",
		"sanitizer-test", "user-1", "ssid-1", "CafeWifi")

	var named []string
	for _, match := range identityTextRE.FindAllStringSubmatch(got.Checks[0].Detail, -1) {
		named = append(named, match[2])
	}
	if len(named) != 8 {
		t.Fatalf("detail = %q, want eight identities", got.Checks[0].Detail)
	}
	corp, literal2, local, literal1, account, user1, cafe, ssid1 :=
		named[0], named[1], named[2], named[3], named[4], named[5], named[6], named[7]
	if corp != got.Target.Host || cafe != got.Checks[0].Observed.SSID {
		t.Errorf("text and structured spellings split: host %q vs %q, SSID %q vs %q",
			corp, got.Target.Host, cafe, got.Checks[0].Observed.SSID)
	}
	for _, pair := range [][2]string{{corp, literal2}, {local, literal1}, {account, user1}, {cafe, ssid1}} {
		if pair[0] == pair[1] {
			t.Errorf("distinct originals collapsed onto %q", pair[0])
		}
	}
	cert := certificateHostRE.FindStringSubmatch(got.Checks[0].Fix)
	if cert == nil || cert[2] == corp || cert[2] == literal1 || cert[2] == literal2 || cert[2] == local ||
		!strings.HasSuffix(got.Checks[0].Fix, "retry "+cert[2]) {
		t.Errorf("fix = %q, want the certificate host as its own repeated identity", got.Checks[0].Fix)
	}
}

// dnsName is how DNS, and compare.sameEndpointName, reads a hostname: without
// regard to ASCII case or the one terminal dot that spells the root.
func dnsName(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }

// An original that differs from the next host alias only in case or a root
// dot is still that DNS name, and has to keep it from every other host. The
// text copy is dropped once, because the text pattern stops short of a root
// dot and would otherwise reserve the bare spelling by itself.
func TestSupportHostAliasesAvoidDNSEquivalentOriginals(t *testing.T) {
	pinLocalIdentity(t)
	for _, literal := range []string{"HOST-2.INVALID", "host-2.invalid."} {
		for _, order := range [][2]string{{"corp.example", literal}, {literal, "corp.example"}} {
			for _, withText := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s first, text %t", order[0], withText), func(t *testing.T) {
					s := hostPairSnapshot(order[0], order[1])
					if !withText {
						s.Checks[0].Detail = ""
					}
					got, r := inspectSupport(t, s)
					assertAliasInvariants(t, r)
					data, err := Encode(got)
					if err != nil {
						t.Fatal(err)
					}
					assertNotLeaked(t, data, order[0], order[1])
					assertNotLeaked(t, []byte(strings.ToLower(string(data))), dnsName(literal))
					portal, err := url.Parse(got.Checks[0].Observed.Portal.RedirectURL)
					if err != nil {
						t.Fatal(err)
					}
					if dnsName(got.Target.Host) == dnsName(portal.Hostname()) {
						t.Errorf("distinct hosts %q and %q collapsed onto %q", order[0], order[1], got.Target.Host)
					}
					again, err := Encode(SanitizeForSupport(s))
					if err != nil || string(again) != string(data) {
						t.Errorf("the same snapshot did not sanitize deterministically")
					}
				})
			}
		}
	}
}

// Spellings of one hostname that differ only in case or a root dot are one
// host, so they share one alias, and each spelling is still replaced in text.
func TestSupportDNSEquivalentHostSpellingsShareAnAlias(t *testing.T) {
	pinLocalIdentity(t)
	s := hostPairSnapshot("Corp.Example.", "corp.example")
	s.Checks[0].Fix = "retry CORP.EXAMPLE"
	got, r := inspectSupport(t, s)
	assertAliasInvariants(t, r)
	data, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	assertNotLeaked(t, []byte(strings.ToLower(string(data))), "corp.example")
	portal, err := url.Parse(got.Checks[0].Observed.Portal.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	alias := got.Target.Host
	if portal.Hostname() != alias || got.Checks[0].Fix != "retry "+alias {
		t.Errorf("target %q, portal %q, fix %q: want one alias", alias, portal.Hostname(), got.Checks[0].Fix)
	}
}

// textAddressSnapshot names one address twice, in text only, so the returned
// sanitized Detail and Fix each carry the pseudonym after a fixed prefix.
func textAddressSnapshot(spelling string, observed *Observed) Snapshot {
	return Snapshot{Tool: Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: Schema, CreatedAt: "2026-08-25T12:00:00Z",
		Checks: []Check{{ID: "route", Name: "Route", Status: StatusFail, Ran: true, DurationMs: 1,
			Detail: "gateway " + spelling, Fix: "check " + spelling, Observed: observed}},
		Diagnosis: Diagnosis{Verdict: "route", Summary: "failed", FailedStage: "route"},
	}
}

func textAddressPseudonyms(t *testing.T, got Snapshot) (detail, fix string) {
	t.Helper()
	detail, okDetail := strings.CutPrefix(got.Checks[0].Detail, "gateway ")
	fix, okFix := strings.CutPrefix(got.Checks[0].Fix, "check ")
	if !okDetail || !okFix {
		t.Fatalf("text lost its shape: detail=%q fix=%q", got.Checks[0].Detail, got.Checks[0].Fix)
	}
	return detail, fix
}

// An address found only in text is an original like any other. Each original
// below is exactly the first pseudonym its family hands out, so unless the
// collection pass reserves it, the address is mapped onto itself and survives.
// Every spelling the text pattern reads has to reach the same identity the
// output side computes, or the reservation misses it.
func TestSupportTextOnlyAddressesAreReservedBeforeAllocation(t *testing.T) {
	pinLocalIdentity(t)
	for _, test := range []struct{ spelling, original string }{
		{"10.0.0.1", "10.0.0.1"},
		{"10.0.0.1:443", "10.0.0.1"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"fe80::1%2", "fe80::1"},
	} {
		t.Run(test.spelling, func(t *testing.T) {
			s := textAddressSnapshot(test.spelling, nil)
			got := SanitizeForSupport(s)
			data, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			assertNotLeaked(t, data, test.original)
			detail, fix := textAddressPseudonyms(t, got)
			if detail != fix {
				t.Errorf("one address got two pseudonyms: detail=%q fix=%q", detail, fix)
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

// A structured field and a sentence naming the same address describe one host,
// whichever spelling the sentence uses.
func TestSupportStructuredAndTextAddressShareAPseudonym(t *testing.T) {
	pinLocalIdentity(t)
	for _, spelling := range []string{"10.0.0.1", "::ffff:10.0.0.1"} {
		got := SanitizeForSupport(textAddressSnapshot(spelling, &Observed{SelectedIP: "10.0.0.1"}))
		detail, fix := textAddressPseudonyms(t, got)
		if selected := got.Checks[0].Observed.SelectedIP; detail != selected || fix != selected || selected == "10.0.0.1" {
			t.Errorf("%s: selected=%q detail=%q fix=%q, want one pseudonym", spelling, selected, detail, fix)
		}
	}
}

// Only the configured public resolver stays readable. The same well-known
// address in a sentence is still that resolver, but one found in text alone
// proves nothing about the run and is pseudonymized like any other address.
func TestSupportTextAddressRetentionFollowsStructuredResolver(t *testing.T) {
	pinLocalIdentity(t)
	s := textAddressSnapshot("8.8.8.8", nil)
	s.Options.PublicDNS = "9.9.9.9"
	s.Checks[0].Fix = "check 8.8.8.8 and 9.9.9.9"
	got := SanitizeForSupport(s)
	if got.Options.PublicDNS != "9.9.9.9" || !strings.HasSuffix(got.Checks[0].Fix, " and 9.9.9.9") {
		t.Errorf("configured resolver lost: public_dns=%q fix=%q", got.Options.PublicDNS, got.Checks[0].Fix)
	}
	detail, _ := textAddressPseudonyms(t, got)
	if detail == "8.8.8.8" || !strings.HasPrefix(got.Checks[0].Fix, "check "+detail+" and") {
		t.Errorf("text-only public address: detail=%q fix=%q, want one pseudonym", detail, got.Checks[0].Fix)
	}
}

// A route prefix is written with its network address, so a prefix pseudonym
// can publish an original IP as its spelled address even when every address
// pseudonym avoids it. Each original below is exactly the address the mapped
// host prefix would otherwise spell, so the whole artifact is what is checked.
func TestSupportPrefixPseudonymsAvoidOriginalAddresses(t *testing.T) {
	pinLocalIdentity(t)
	for _, test := range []struct{ spelling, original, destination, prefix string }{
		{"10.0.1.0", "10.0.1.0", "10.9.9.9", "10.9.9.9/32"},
		{"::ffff:10.0.1.0", "10.0.1.0", "10.9.9.9", "10.9.9.9/32"},
		{"fd00:0:0:1::1", "fd00:0:0:1::1", "fd00::9", "fd00::9/128"},
	} {
		t.Run(test.spelling, func(t *testing.T) {
			s := textAddressSnapshot(test.spelling, &Observed{
				Routes: []Route{{Destination: test.destination, Prefix: test.prefix}},
			})
			done := make(chan []byte, 1)
			go func() {
				data, err := Encode(SanitizeForSupport(s))
				if err != nil {
					t.Error(err)
				}
				done <- data
			}()
			var data []byte
			select {
			case data = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("SanitizeForSupport did not terminate on a host route prefix")
			}
			assertNotLeaked(t, data, test.original)
			got, err := Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			route := got.Checks[0].Observed.Routes[0]
			if route.Destination == test.destination {
				t.Errorf("route destination kept its original %q", route.Destination)
			}
			if prefix, err := netip.ParsePrefix(route.Prefix); err != nil ||
				prefix.Bits() != netip.MustParsePrefix(test.prefix).Bits() {
				t.Errorf("route prefix %q is not a valid host prefix: %v", route.Prefix, err)
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
