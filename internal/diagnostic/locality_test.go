// What counts as a destination this machine could only have reached by leaving
// the network. Two conclusions rest on it: a failed endpoint on a local device
// is not explained by the egress rung, and a successful one on a public
// address refutes it. Both are wrong if the classification is.

package diagnostic

import (
	"net"
	"testing"
)

func TestLocalIP(t *testing.T) {
	cases := []struct {
		ip    string
		local bool
		why   string
	}{
		{"10.0.0.5", true, "RFC1918"},
		{"172.16.4.1", true, "RFC1918"},
		{"192.168.1.1", true, "RFC1918"},
		{"127.0.0.1", true, "this machine"},
		{"169.254.7.7", true, "link-local"},
		{"fd00::1", true, "unique local"},
		{"fe80::1", true, "link-local"},
		{"::1", true, "this machine"},
		// RFC 6598 shared address space, at both ends of the /10. This is
		// what a carrier hands out behind CGNAT and what Tailscale allocates
		// tailnet addresses from, and it is not globally routable, so nothing
		// reaches one of these by way of the public internet.
		{"100.64.0.0", true, "shared address space, first"},
		{"100.100.100.100", true, "shared address space, typical tailnet peer"},
		{"100.127.255.255", true, "shared address space, last"},
		{"::ffff:100.100.100.100", true, "shared address space, IPv4-mapped"},
		// Its neighbours on either side are ordinary public space.
		{"100.63.255.255", false, "below shared address space"},
		{"100.128.0.0", false, "above shared address space"},
		// RFC 3879 site-local, deprecated and never globally routable.
		{"fec0::1", true, "site-local"},
		{"feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, "site-local, last"},
		{"93.184.216.34", false, "public"},
		{"2606:2800:220:1:248:1893:25c8:1946", false, "public"},
		// The documentation and benchmarking ranges stay public here. They are
		// not globally routable either, but in this repository they are what a
		// public address is written as: the fixtures use them as stand-ins and
		// a --support artifact's pseudonym for a public address is one of them.
		{"192.0.2.1", false, "TEST-NET-1 stands in for a public address"},
		{"198.18.0.1", false, "the pseudonym --support gives a public address"},
		{"2001:db8::1", false, "the pseudonym --support gives a public IPv6 address"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("%s: unparseable", c.ip)
		}
		if got := localIP(ip); got != c.local {
			t.Errorf("localIP(%s) = %t, want %t (%s)", c.ip, got, c.local, c.why)
		}
	}
}

// The two questions the interpretation pass asks about a target, which read
// different evidence: localTarget reads the name that was asked for, because
// the connection it qualifies never happened, and publicTargetReachedDirectly
// reads the address that answered, because that is what proves where traffic
// went.
func TestTargetLocalityPredicates(t *testing.T) {
	name := func(addrs ...string) map[ProbeID]ProbeResult {
		var ips []net.IP
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return map[ProbeID]ProbeResult{ProbeDNS: {Status: StatusPass, Addrs: ips}}
	}
	literal := func(ip string) *Target { return &Target{Host: ip, IP: net.ParseIP(ip), Port: 9100} }
	for _, c := range []struct {
		name  string
		t     *Target
		res   map[ProbeID]ProbeResult
		local bool
	}{
		{"public literal", literal("93.184.216.34"), nil, false},
		{"private literal", literal("192.168.1.1"), nil, true},
		{"shared address space literal", literal("100.100.100.100"), nil, true},
		{"site-local literal", literal("fec0::1"), nil, true},
		{"no target at all", nil, nil, false},
		{"name resolving only locally", &Target{Host: "printer.lan"}, name("192.168.1.5", "100.64.0.9"), true},
		{"name with one public address", &Target{Host: "split.example"}, name("192.168.1.5", "93.184.216.34"), false},
	} {
		if got := localTarget(c.t, c.res); got != c.local {
			t.Errorf("localTarget(%s) = %t, want %t", c.name, got, c.local)
		}
	}

	// The endpoint row, which is the half that decides whether the run reached
	// anything off this network.
	for _, c := range []struct {
		name   string
		res    map[ProbeID]ProbeResult
		public bool
	}{
		{"no endpoint row", map[ProbeID]ProbeResult{}, false},
		{"endpoint failed", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusFail, SelectedIP: net.ParseIP("93.184.216.34")}}, false},
		{"public address answered", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("93.184.216.34")}}, true},
		{"public address answered slowly", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusWarn, SelectedIP: net.ParseIP("93.184.216.34")}}, true},
		{"local address answered", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("192.168.1.5")}}, false},
		{"shared address space answered", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("100.100.100.100")}}, false},
		// A split-horizon name whose LAN address is the one that answered. The
		// name is not local, so reading the name rather than the socket would
		// credit a printer down the hall to the public internet.
		{"public name reached at its local address", map[ProbeID]ProbeResult{
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.168.1.5"), net.ParseIP("93.184.216.34")}},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("192.168.1.5")},
		}, false},
		{"address never recorded", map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusPass}}, false},
	} {
		if got := publicTargetReachedDirectly(c.res); got != c.public {
			t.Errorf("publicTargetReachedDirectly(%s) = %t, want %t", c.name, got, c.public)
		}
	}
}
