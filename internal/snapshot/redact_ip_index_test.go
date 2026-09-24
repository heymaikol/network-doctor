package snapshot

import (
	"net/netip"
	"testing"
)

// These are assignments from main before the issued-address index was added.
func TestSupportAddressAssignmentsStayStable(t *testing.T) {
	pinLocalIdentity(t)
	got := SanitizeForSupport(supportFixture())
	observed := got.Checks[0].Observed
	for name, pair := range map[string][2]string{
		"private source":  {got.Options.Source.IPv4, "10.0.1.1"},
		"second private":  {observed.Addresses[1], "10.0.1.2"},
		"public source":   {observed.SourceIP, "198.18.0.1"},
		"public answer":   {observed.Addresses[2], "198.18.0.2"},
		"IPv6 source":     {got.Options.Source.IPv6, "fd00::1"},
		"public resolver": {got.Options.PublicDNS, "9.9.9.9"},
		"route prefix":    {observed.Routes[0].Prefix, "10.0.1.0/24"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

func TestAddressSkipsIssuedAliasWithinPrefix(t *testing.T) {
	pinLocalIdentity(t)
	r := newRedactor()
	r.prefixOrder = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	r.finishCollection()
	r.mapIP("192.0.2.8", "198.18.1.1")
	if got := r.address("192.0.2.9"); got != "198.18.1.2" {
		t.Fatalf("address = %q, want 198.18.1.2", got)
	}
}

func TestAddressSkipsIssuedAliasAcrossFamily(t *testing.T) {
	pinLocalIdentity(t)
	r := newRedactor()
	r.finishCollection()
	r.mapIP("10.1.1.1", "10.0.0.1")
	if got := r.address("10.2.2.2"); got != "10.0.0.2" {
		t.Fatalf("address = %q, want 10.0.0.2", got)
	}
}

func TestAddressCanonicalSpellingsReuseAlias(t *testing.T) {
	pinLocalIdentity(t)
	r := newRedactor()
	r.finishCollection()
	first := r.address("::ffff:10.1.2.3")
	for _, spelling := range []string{"10.1.2.3", "::ffff:10.1.2.3", first} {
		if got := r.address(spelling); got != first {
			t.Errorf("address(%q) = %q, want %q", spelling, got, first)
		}
	}
	if first != "10.0.0.1" || len(r.ips) != 1 {
		t.Fatalf("canonical address mapped as %q across %d keys", first, len(r.ips))
	}
}

func TestIssuedIPAliasIndexFollowsMapIP(t *testing.T) {
	pinLocalIdentity(t)
	r := newRedactor()
	r.finishCollection()
	r.mapIP("10.1.1.1", "10.0.0.1")
	if r.ips["10.1.1.1"] != "10.0.0.1" || !r.issuedIPAliases["10.0.0.1"] {
		t.Fatal("mapIP did not update both address mappings")
	}
	if got := r.address("10.0.0.1"); got != "10.0.0.1" {
		t.Errorf("already issued alias changed to %q", got)
	}
	r.reserveIP("10.0.0.2")
	if !r.originalIPs["10.0.0.2"] || r.issuedIPAliases["10.0.0.2"] {
		t.Fatal("source addresses and issued aliases share an identity set")
	}
	if got := r.address("10.3.3.3"); got != "10.0.0.3" {
		t.Errorf("allocation after issued and original collisions = %q, want 10.0.0.3", got)
	}
}

func TestIssuedIPAliasIndexCoversSupportMappings(t *testing.T) {
	pinLocalIdentity(t)
	_, r := inspectSupport(t, supportFixture())
	if len(r.ips) != len(r.issuedIPAliases) {
		t.Fatalf("%d address mappings, %d issued aliases", len(r.ips), len(r.issuedIPAliases))
	}
	for original, alias := range r.ips {
		if !r.issuedIPAliases[alias] {
			t.Errorf("%q maps to unindexed alias %q", original, alias)
		}
	}
}
