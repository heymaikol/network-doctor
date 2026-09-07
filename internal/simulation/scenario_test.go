package simulation

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

const minimalScenario = `
name: t
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, gateway: 10.77.0.1}
    - {name: server, address: 10.77.0.1}
tests:
  - {node: client, target: example.test:80}
expect:
  verdict: ok
`

func TestParseScenarioDefaults(t *testing.T) {
	s, err := ParseScenario(strings.NewReader(minimalScenario))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := s.Topology.subnetOrDefault(); got != "10.77.0.0/24" {
		t.Errorf("subnet default = %q", got)
	}
	if s.Topology.Nodes[1].Role != "server" {
		t.Errorf("role default = %q, want server", s.Topology.Nodes[1].Role)
	}
	if s.Tests[0].Type != TestNetdoc {
		t.Errorf("test type default = %q", s.Tests[0].Type)
	}
	if s.Tests[0].Name == "" {
		t.Error("test name should be derived when omitted")
	}
	if c := s.Client(); c == nil || c.Name != "client" {
		t.Errorf("Client() = %v", c)
	}
}

func TestParseScenarioWordingExpectations(t *testing.T) {
	raw := strings.Replace(minimalScenario, "  verdict: ok",
		"  summary: exact diagnosis\n  checks: [{id: dns, status: FAIL, fix: exact remedy}]", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Expect.Summary != "exact diagnosis" || len(s.Expect.Checks) != 1 || s.Expect.Checks[0].Fix != "exact remedy" {
		t.Fatalf("expectation = %+v", s.Expect)
	}
}

func TestParseScenarioDocumentBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{name: "single document", yaml: minimalScenario},
		{name: "trailing whitespace and comments", yaml: minimalScenario + "\n  \n# trailing comment\n"},
		{name: "second document", yaml: minimalScenario + "\n---\n" + minimalScenario, wantErr: true},
		{name: "malformed trailing document", yaml: minimalScenario + "\n---\nname: [\n", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseScenario(strings.NewReader(tc.yaml))
			if tc.wantErr && err == nil {
				t.Fatal("want an error, got none")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
	}
}

func TestParseScenarioRejects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown field", minimalScenario + "\nwidgets: 3\n", "widgets"},
		{"unknown node field", strings.Replace(minimalScenario, "role: client", "rolle: client", 1), "rolle"},
		{"unknown expectation field", strings.Replace(minimalScenario, "verdict: ok", "verdict: ok\n  summmary: nope", 1), "summmary"},
		{"unknown expected check field", strings.Replace(minimalScenario, "verdict: ok", "checks: [{id: dns, status: FAIL, fiz: nope}]", 1), "fiz"},
		{"empty", "", "empty scenario"},
		{"two documents", minimalScenario + "\n---\n" + minimalScenario, "exactly one document"},
		{"no name", strings.Replace(minimalScenario, "name: t", "name: \"\"", 1), "name is required"},
		{"no client", strings.Replace(minimalScenario, "role: client", "role: server", 1), "exactly one node"},
		{"unknown role", strings.Replace(minimalScenario, "role: client", "role: alien", 1), "unknown role"},
		{"bad address", strings.Replace(minimalScenario, "10.77.0.10", "not-an-ip", 1), "address"},
		{"address off subnet", strings.Replace(minimalScenario, "10.77.0.10", "192.0.2.5", 1), "outside"},
		{"duplicate node", strings.Replace(minimalScenario, "name: server", "name: client", 1), "duplicate node"},
		{"unsafe node name", strings.Replace(minimalScenario, "name: server", "name: \"a b\"", 1), "letters, digits"},
		{"bad target", strings.Replace(minimalScenario, "example.test:80", "'::::'", 1), "invalid target"},
		{"unknown verdict", strings.Replace(minimalScenario, "verdict: ok", "verdict: broken", 1), "unknown verdict"},
		{"no tests", strings.Replace(minimalScenario, "  - {node: client, target: example.test:80}", "", 1), "at least one test"},
		{"nothing expected", strings.Replace(minimalScenario, "  verdict: ok", "  checks: []", 1), "must expect"},
		{
			"unknown probe id",
			strings.Replace(minimalScenario, "  verdict: ok", "  checks: [{id: nope, status: PASS}]", 1),
			"unknown probe id",
		},
		{
			"unknown status",
			strings.Replace(minimalScenario, "  verdict: ok", "  checks: [{id: dns, status: BROKEN}]", 1),
			"unknown status",
		},
		{
			"unknown cause",
			strings.Replace(minimalScenario, "  verdict: ok", "  checks: [{id: tls, status: FAIL, cause: invented}]", 1),
			"unknown cause",
		},
		{
			"cause on passing expectation",
			strings.Replace(minimalScenario, "  verdict: ok", "  checks: [{id: tls, status: PASS, cause: hostname_mismatch}]", 1),
			"requires FAIL or WARN",
		},
		{
			"duplicate expectation",
			strings.Replace(minimalScenario, "  verdict: ok", "  checks: [{id: dns, status: PASS}, {id: dns, status: FAIL}]", 1),
			"duplicate probe id",
		},
		{
			"unknown service",
			strings.Replace(minimalScenario, "address: 10.77.0.1}", "address: 10.77.0.1, services: [{type: gopher}]}", 1),
			"unknown service type",
		},
		{
			"duplicate service name",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: duplicate, type: tcp, port: 80}, {name: duplicate, type: tcp, port: 81}]}", 1),
			"duplicate service name",
		},
		{
			"conflicting DNS record spelling",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: dns, zone: {Example.Test: 10.77.0.1, example.test.: 10.77.0.2}}]}", 1),
			"duplicate DNS record",
		},
		{
			"unknown DNS fault field",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: dns, dns_fault: {a: [answer], wrong_aa: 192.0.2.1}}]}", 1),
			"wrong_aa",
		},
		{
			"wrong DNS answer matches the zone",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: dns, zone: {example.test: 192.0.2.1}, dns_fault: {a: [wrong_answer], wrong_a: 192.0.2.1}}]}", 1),
			"matches zone address",
		},
		{
			"unsupported SOCKS option",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, resolver: 10.77.0.1, services: [{type: socks5, body: nope}]}", 1),
			"unsupported options",
		},
		{
			"portal mode on a non-HTTP service",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: tcp, port: 80, portal: true}]}", 1),
			"unsupported options",
		},
		{
			"date offset on a non-HTTP service",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: tcp, port: 80, date_offset: 1h}]}", 1),
			"only supported by http services",
		},
		{
			"malformed HTTP date offset",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: http, date_offset: tomorrow}]}", 1),
			"date_offset",
		},
		{
			"TLS missing certificate",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: tls-target, type: tls, port: 9443}]}", 1),
			"configuration is required",
		},
		{
			"TLS unknown certificate mode",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: tls-target, type: tls, port: 9443, certificate: {mode: forged, dns_names: [example.test]}}]}", 1),
			"unknown mode",
		},
		{
			"TLS empty SAN list",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: tls-target, type: tls, port: 9443, certificate: {mode: valid, dns_names: []}}]}", 1),
			"must not be empty",
		},
		{
			"TLS IP literal SAN",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: tls-target, type: tls, port: 9443, certificate: {mode: valid, dns_names: [192.0.2.1]}}]}", 1),
			"IP literal",
		},
		{
			"TLS unknown certificate field",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{name: tls-target, type: tls, certificate: {mode: valid, dns_names: [example.test], private_key: /tmp/key}}]}", 1),
			"private_key",
		},
		{
			"zone name is not a hostname",
			strings.Replace(minimalScenario, "address: 10.77.0.1}",
				"address: 10.77.0.1, services: [{type: dns, zone: {'a b': 10.77.0.1}}]}", 1),
			"not a hostname",
		},
		{
			"unknown fault",
			minimalScenario + "\nfaults: [{type: meltdown, node: client}]\n",
			"unknown fault type",
		},
		{
			"fault on unknown node",
			minimalScenario + "\nfaults: [{type: no_default_route, node: ghost}]\n",
			"unknown node",
		},
		{
			"netem with nothing to do",
			minimalScenario + "\nfaults: [{type: netem, node: client}]\n",
			"needs delay",
		},
		{
			"jitter without delay",
			minimalScenario + "\nfaults: [{type: netem, node: client, jitter: 10ms}]\n",
			"jitter needs a delay",
		},
		{
			"loss is not a percentage",
			minimalScenario + "\nfaults: [{type: netem, node: client, loss: lots}]\n",
			"not a percentage",
		},
		{
			"drop port without protocol",
			minimalScenario + "\nfaults: [{type: drop, node: client, port: 53}]\n",
			"needs a protocol",
		},
		{
			"unknown direction",
			minimalScenario + "\nfaults: [{type: drop, node: client, direction: sideways}]\n",
			"unknown direction",
		},
		{
			"unknown test type",
			strings.Replace(minimalScenario, "  - {node: client,", "  - {type: fuzz, node: client,", 1),
			"unknown test type",
		},
		{
			"unsupported proxy scheme",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks4, node: server}", 1),
			"unsupported scheme",
		},
		{
			"proxy on unknown node",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5, node: missing}", 1),
			"unknown node",
		},
		{
			"proxy port out of range",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5, node: server, port: 70000}", 1),
			"out of range",
		},
		{
			"proxy references no service",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5, node: server}", 1),
			"has no socks5 service",
		},
		{
			"http proxy references no CONNECT service",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: http, node: server}", 1),
			"has no http_connect service",
		},
		{
			"CONNECT proxy without a node resolver",
			strings.Replace(minimalScenario, "- {name: server, address: 10.77.0.1}",
				"- {name: server, address: 10.77.0.1, services: [{name: connect-proxy, type: http_connect}]}", 1),
			"http_connect service needs the node resolver",
		},
		{
			"unknown proxy option",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5, node: server, command: sh}", 1),
			"command",
		},
		{
			"unknown trust service",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, trust: {service: missing}", 1),
			"unknown tls service",
		},
		{
			"unknown trust option",
			strings.Replace(minimalScenario, "target: example.test:80", "target: example.test:80, trust: {service: tls-target, path: /tmp/ca}", 1),
			"path",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseScenario(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatal("want an error, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestFaultDefaults(t *testing.T) {
	s, err := ParseScenario(strings.NewReader(
		minimalScenario + "\nfaults: [{type: drop, node: client, protocol: udp, port: 53}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Faults[0].Direction != DirectionOutbound {
		t.Errorf("direction default = %q, want %q", s.Faults[0].Direction, DirectionOutbound)
	}
}

func TestDNSRecordsAllowOrderedSameFamilyAnswers(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, services: [{type: dns, records: [{name: Failover.Test, address: 10.77.0.20}, {name: failover.test., address: 10.77.0.21}]}]}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	records := s.Topology.Nodes[1].Services[0].Records
	if len(records) != 2 || records[0].Name != "failover.test" || records[0].Address != "10.77.0.20" ||
		records[1].Name != "failover.test" || records[1].Address != "10.77.0.21" {
		t.Fatalf("records = %+v, want canonicalized input order", records)
	}

	duplicate := strings.Replace(raw, "10.77.0.21", "10.77.0.20", 1)
	if _, err := ParseScenario(strings.NewReader(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate DNS record") {
		t.Errorf("duplicate address error = %v, want duplicate DNS record", err)
	}
}

// dualStackRoutedScenario gives the router a transit interface carrying IPv6,
// which is the only case where the MTU floor a scenario may ask for changes.
var dualStackRoutedScenario = strings.NewReplacer(
	"{name: upstream, subnet: 10.77.2.0/24}", `{name: upstream, ipv4: 10.77.2.0/24, ipv6: "fd00:2::/64"}`,
	"{segment: upstream, address: 10.77.2.1/24}", `{segment: upstream, ipv4: 10.77.2.1/24, ipv6: "fd00:2::1/64"}`,
).Replace(routedScenario)

// A PMTU black hole is two conditions at once, and each half of the schema
// guards one of them: a hop that actually narrows, on a node that actually
// forwards. Everything rejected here would produce a network that looks
// impaired without being a black hole.
func TestPMTUBlackholeValidation(t *testing.T) {
	fault := func(fields string) string {
		return routedScenario + "\nfaults: [{type: pmtu_blackhole, " + fields + "}]\n"
	}
	for _, tc := range []struct {
		name string
		yaml string
		want string
	}{
		{"endpoint is not a hop", fault("node: client, segment: client-lan, mtu: 1400"), "must be a router"},
		{"no such segment", fault("node: gateway, segment: nowhere, mtu: 1400"), "no interface on segment"},
		{"mtu below the IPv4 floor", fault("node: gateway, segment: upstream, mtu: 500"), "out of range"},
		{"mtu narrows nothing", fault("node: gateway, segment: upstream, mtu: 1500"), "out of range"},
		{"mtu missing entirely", fault("node: gateway, segment: upstream"), "out of range"},
		{
			"mtu would strip IPv6 off the link",
			dualStackRoutedScenario + "\nfaults: [{type: pmtu_blackhole, node: gateway, segment: upstream, mtu: 576}]\n",
			"disable IPv6",
		},
		{"route options are not accepted", fault("node: gateway, segment: upstream, mtu: 1400, via: 10.77.2.1"), "node, segment and mtu only"},
		{"traffic selectors are not accepted", fault("node: gateway, segment: upstream, mtu: 1400, protocol: tcp"), "node, segment and mtu only"},
		{"mtu belongs to no other fault", routedScenario + "\nfaults: [{type: link_down, node: gateway, segment: upstream, mtu: 1400}]\n", "does not accept mtu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseScenario(strings.NewReader(tc.yaml))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPMTUBlackholeAccepted(t *testing.T) {
	// 1280 is the IPv6 floor, so a dual-stack transit hop keeps both families;
	// only the packet size changes.
	s, err := ParseScenario(strings.NewReader(dualStackRoutedScenario +
		"\nfaults: [{type: pmtu_blackhole, node: gateway, segment: upstream, mtu: 1280}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Faults[0].MTU != 1280 {
		t.Errorf("mtu = %d, want 1280", s.Faults[0].MTU)
	}
}

func TestProxyDefaultsAndUsesValidatedNodeAddress(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, resolver: 10.77.0.1, services: [{name: proxy, type: socks5}]}", 1)
	raw = strings.Replace(raw, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5h, node: server}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	proxy := s.Tests[0].Proxy
	if proxy == nil || proxy.Port != 1080 || proxy.address != "10.77.0.1" {
		t.Errorf("proxy = %+v", proxy)
	}
	if got := s.Topology.Nodes[1].Services[0].Port; got != 1080 {
		t.Errorf("service port = %d", got)
	}
}

func TestTLSServiceDefaultsAndValidatedTrust(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, services: [{name: tls-target, type: tls, certificate: {mode: valid, dns_names: [Secure-Target.Test.]}}]}", 1)
	raw = strings.Replace(raw, "target: example.test:80", "target: example.test:80, trust: {service: tls-target}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	svc := s.Topology.Nodes[1].Services[0]
	if svc.Port != 443 || svc.Certificate.DNSNames[0] != "secure-target.test" {
		t.Errorf("TLS service = %+v", svc)
	}
	if s.Tests[0].Trust == nil || s.Tests[0].Trust.Service != "tls-target" {
		t.Errorf("trust = %+v", s.Tests[0].Trust)
	}
}

func TestTLSCertificateNotYetValidAccepted(t *testing.T) {
	cfg := &TLSCertificate{Mode: TLSCertificateNotYetValid, DNSNames: []string{"secure-target.test"}}
	if err := validateTLSCertificate(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestTCPBannerValidation(t *testing.T) {
	withService := func(service string) string {
		return strings.Replace(minimalScenario, "address: 10.77.0.1}",
			"address: 10.77.0.1, services: ["+service+"]}", 1)
	}
	valid := withService(fmt.Sprintf("{type: tcp, port: 9443, banner: %q}", "SSH-2.0-test\r\n"))
	s, err := ParseScenario(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Topology.Nodes[1].Services[0].Banner; got != "SSH-2.0-test\r\n" {
		t.Errorf("banner = %q", got)
	}

	for _, raw := range []string{
		withService(`{type: http, port: 8080, banner: "220 mail.test ESMTP\r\n"}`),
		withService(`{type: tcp, port: 9443, banner: "SSH-2.0-test"}`),
		withService(fmt.Sprintf("{type: tcp, port: 9443, banner: %q}", strings.Repeat("x", maxServiceBannerBytes)+"\n")),
	} {
		if _, err := ParseScenario(strings.NewReader(raw)); err == nil {
			t.Errorf("accepted invalid banner scenario: %s", raw)
		}
	}
}

func TestTLSCertificateRejectsExcessiveOrInvalidNames(t *testing.T) {
	many := make([]string, tlsMaxDNSNames+1)
	for i := range many {
		many[i] = fmt.Sprintf("host-%d.test", i)
	}
	for _, cfg := range []*TLSCertificate{
		{Mode: TLSCertificateValid, DNSNames: many},
		{Mode: TLSCertificateValid, DNSNames: []string{strings.Repeat("a", 64) + ".test"}},
		{Mode: TLSCertificateValid, DNSNames: []string{"Example.Test", "example.test."}},
	} {
		if err := validateTLSCertificate(cfg); err == nil {
			t.Errorf("accepted invalid TLS certificate intent: %+v", cfg)
		}
	}
}

// TestLibraryScenariosValidate is the guard that keeps a shipped scenario from
// rotting: every one of them has to parse and validate in the plain unit suite,
// where no namespace is needed to find out.
func TestLibraryScenariosValidate(t *testing.T) {
	names := LibraryNames()
	if len(names) < 2 {
		t.Fatalf("library has %d scenarios, want at least 2", len(names))
	}
	for _, name := range names {
		if _, err := LibraryScenario(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := LibraryScenario("no-such-scenario"); err == nil {
		t.Error("want an error for an unknown scenario")
	}
}

func TestLibraryScenariosCoverKnownCauses(t *testing.T) {
	covered := make(map[string]bool, len(knownCauses))
	for _, name := range LibraryNames() {
		scenario, err := LibraryScenario(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, check := range scenario.Expect.Checks {
			if check.Cause != "" {
				covered[check.Cause] = true
			}
		}
		for _, test := range scenario.Tests {
			if test.Expect == nil {
				continue
			}
			for _, check := range test.Expect.Checks {
				if check.Cause != "" {
					covered[check.Cause] = true
				}
			}
		}
	}
	var missing []string
	for _, cause := range knownCauses {
		if cause == diagnostic.TLSCauseTCPUnreachable {
			// A real-socket scenario cannot deterministically force ECONNREFUSED
			// after an earlier TCP connection succeeds. The structured errno
			// mapping is covered by TestTLSProbeClassifiesStructuredFailures.
			continue
		}
		if !covered[cause] {
			missing = append(missing, cause)
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		t.Fatalf("stable causes with no scenario assertion: %s", strings.Join(missing, ", "))
	}
}

// TestEncryptedDNSIsolationPair pins the two halves of the README's claim that
// ordinary DNS and encrypted DNS are independent capabilities. Each scenario
// has to assert a working path beside the broken one: an encrypted-DNS FAIL
// next to a dead network, or an encrypted-DNS PASS next to a working resolver,
// proves nothing about either. Deterministic and rootless on purpose, so
// deleting the positive rows fails the ordinary suite rather than only the
// namespace one.
func TestEncryptedDNSIsolationPair(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		drops    []string
		want     map[string]string
	}{
		{
			scenario: "encrypted-dns-blocked",
			// Exactly the two flows the encrypted-DNS row dials, each pinned
			// to the bootstrap address so nothing else on 443 is caught.
			drops: []string{"tcp/443 to 1.1.1.1", "tcp/853 to 1.1.1.1"},
			want: map[string]string{
				string(diagnostic.ProbeDNSEncrypted): "FAIL",
				string(diagnostic.ProbeDNS):          "PASS",
				string(diagnostic.ProbeDNSPublic):    "PASS",
				string(diagnostic.ProbeInternet):     "PASS",
				string(diagnostic.ProbeQUIC):         "PASS",
			},
		},
		{
			scenario: "plain-dns-blocked",
			// Both transports port 53 runs on, every destination, so the fault
			// is "plaintext DNS" rather than "UDP DNS". The TCP half is stated
			// here rather than asserted from a run on purpose: nothing in the
			// scenario truncates an answer, so the stub resolver never retries
			// over TCP and no namespace run can observe that rule either way.
			drops: []string{"udp/53", "tcp/53"},
			want: map[string]string{
				string(diagnostic.ProbeDNSEncrypted): "PASS",
				string(diagnostic.ProbeDNS):          "FAIL",
				string(diagnostic.ProbeInternet):     "PASS",
			},
		},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			s, err := LibraryScenario(tc.scenario)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, check := range s.Expect.Checks {
				got[check.ID] = check.Status
			}
			for id, status := range tc.want {
				if got[id] != status {
					t.Errorf("expects %s = %q, want %q", id, got[id], status)
				}
			}
			// The isolation lives in the faults too, and an exact list is the
			// point: a drop that lost its port or its address would still
			// produce the rows above on some runs, but by taking out more of
			// the network than the claim is about.
			var drops []string
			for _, fault := range s.Faults {
				if fault.Type != FaultDrop || fault.Port == 0 {
					t.Errorf("fault %+v is not a port-scoped drop", fault)
					continue
				}
				drop := fmt.Sprintf("%s/%d", fault.Protocol, fault.Port)
				if fault.To != "" {
					drop += " to " + fault.To
				}
				drops = append(drops, drop)
			}
			if !slices.Equal(drops, tc.drops) {
				t.Errorf("drops = %v, want %v", drops, tc.drops)
			}
		})
	}
}

func TestLibraryScenarioReturnsIndependentCopies(t *testing.T) {
	first, err := LibraryScenario("healthy")
	if err != nil {
		t.Fatal(err)
	}
	first.Topology.Nodes[0].Name = "changed"
	second, err := LibraryScenario("healthy")
	if err != nil {
		t.Fatal(err)
	}
	if second.Topology.Nodes[0].Name == "changed" {
		t.Error("mutating one library scenario changed the next load")
	}
}

func TestLoadPrefersFilesForPathLikeRefs(t *testing.T) {
	// A reference that looks like a path must never resolve to a built-in, or a
	// local scenario could be silently shadowed by one shipped in the binary.
	if _, err := Load("./healthy.yaml"); err == nil {
		t.Error("want a file-not-found error, got a built-in")
	}
}

func TestNormalizePercent(t *testing.T) {
	for raw, want := range map[string]string{
		"0%": "0%", "10%": "10%", "0.5%": "0.5%", "100%": "100%", "10.00%": "10%", "07%": "7%",
	} {
		got, ok := normalizePercent(raw)
		if !ok || got != want {
			t.Errorf("normalizePercent(%q) = %q, %t, want %q, true", raw, got, ok, want)
		}
	}
	// Everything tc cannot parse, including the Go float spellings that are
	// numerically in range but syntactically not a tc percentage.
	for _, bad := range []string{
		"", "%", ".%", "10", "1.2.3%", "ten%", "10%%", "100.01%", "NaN%", "Inf%",
		"1e2%", "+5%", "-5%", "0x1p6%", " 5%", "5 %",
	} {
		if got, ok := normalizePercent(bad); ok {
			t.Errorf("normalizePercent(%q) = %q, true", bad, got)
		}
	}
}

func TestDNSFaultValidation(t *testing.T) {
	valid := []*DNSFault{
		nil,
		{A: []string{DNSOutcomeAnswer, DNSOutcomeSERVFAIL, DNSOutcomeREFUSED, DNSOutcomeTruncated}},
		{A: []string{DNSOutcomeWrongAnswer}, WrongA: "192.0.2.7"},
		{AAAA: []string{DNSOutcomeWrongAnswer}, WrongAAAA: "2001:db8::7"},
	}
	for _, fault := range valid {
		if err := validateDNSFault(fault); err != nil {
			t.Errorf("validateDNSFault(%+v): %v", fault, err)
		}
	}

	invalid := []struct {
		name  string
		fault *DNSFault
	}{
		{"empty", &DNSFault{}},
		{"unknown outcome", &DNSFault{A: []string{"random"}}},
		{"too many outcomes", &DNSFault{A: make([]string, dnsMaxScheduledOutcomes+1)}},
		{"missing wrong A", &DNSFault{A: []string{DNSOutcomeWrongAnswer}}},
		{"missing wrong AAAA", &DNSFault{AAAA: []string{DNSOutcomeWrongAnswer}}},
		{"unused wrong A", &DNSFault{A: []string{DNSOutcomeAnswer}, WrongA: "192.0.2.7"}},
		{"unused wrong AAAA", &DNSFault{AAAA: []string{DNSOutcomeAnswer}, WrongAAAA: "2001:db8::7"}},
		{"invalid wrong A", &DNSFault{A: []string{DNSOutcomeWrongAnswer}, WrongA: "999.0.2.7"}},
		{"invalid wrong AAAA", &DNSFault{AAAA: []string{DNSOutcomeWrongAnswer}, WrongAAAA: "not-an-ip"}},
		{"unusable wrong A", &DNSFault{A: []string{DNSOutcomeWrongAnswer}, WrongA: "0.0.0.0"}},
		{"unusable wrong AAAA", &DNSFault{AAAA: []string{DNSOutcomeWrongAnswer}, WrongAAAA: "::"}},
		{"IPv6 in wrong A", &DNSFault{A: []string{DNSOutcomeWrongAnswer}, WrongA: "2001:db8::7"}},
		{"IPv4 in wrong AAAA", &DNSFault{AAAA: []string{DNSOutcomeWrongAnswer}, WrongAAAA: "192.0.2.7"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDNSFault(tc.fault); err == nil {
				t.Errorf("accepted invalid DNS fault: %+v", tc.fault)
			}
		})
	}
}

func TestExistingDNSFaultScenarioRemainsCompatible(t *testing.T) {
	s, err := LibraryScenario("intermittent-dns")
	if err != nil {
		t.Fatal(err)
	}
	fault := s.Topology.node("resolver").Services[0].DNSFault
	if fault == nil || len(fault.A) == 0 || len(fault.AAAA) == 0 || fault.WrongA != "" || fault.WrongAAAA != "" {
		t.Fatalf("intermittent DNS fault = %+v", fault)
	}
	for _, outcomes := range [][]string{fault.A, fault.AAAA} {
		for _, outcome := range outcomes {
			if outcome != DNSOutcomeSERVFAIL {
				t.Fatalf("existing outcome = %q, want %q", outcome, DNSOutcomeSERVFAIL)
			}
		}
	}
}

func TestCampaignRejectsUnknownFields(t *testing.T) {
	raw := minimalScenario + `
campaign:
  runs: 2
  arbitrary_command: ip route flush table main
`
	if _, err := ParseScenario(strings.NewReader(raw)); err == nil {
		t.Error("accepted unknown campaign field")
	}
}

func TestIsSafeName(t *testing.T) {
	for _, ok := range []string{"client", "node-1", "a"} {
		if !isSafeName(ok) {
			t.Errorf("isSafeName(%q) = false", ok)
		}
	}
	// These are the ones that matter: every name reaches an argv.
	for _, bad := range []string{"", "-lead", "a b", "a;b", "a/b", "a$b", "a\nb", strings.Repeat("a", 33)} {
		if isSafeName(bad) {
			t.Errorf("isSafeName(%q) = true", bad)
		}
	}
}

func TestIsSafeHostname(t *testing.T) {
	for _, ok := range []string{"private-target.test", "EXAMPLE.test.", strings.Repeat("a", 63) + ".test"} {
		if !isSafeHostname(ok) {
			t.Errorf("isSafeHostname(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", ".", "-bad.test", "bad-.test", "bad_name.test", strings.Repeat("a", 64) + ".test"} {
		if isSafeHostname(bad) {
			t.Errorf("isSafeHostname(%q) = true", bad)
		}
	}
}

func TestBuiltInScenariosMatchFixedProbeDestinations(t *testing.T) {
	for _, name := range LibraryNames() {
		t.Run(name, func(t *testing.T) {
			scenario, err := LibraryScenario(name)
			if err != nil {
				t.Fatal(err)
			}

			usedAliases := scenarioAliasConsumers(scenario)
			carriers := 0
			for _, node := range scenario.Topology.Nodes {
				if !nodeHasService(node, ServiceEncryptedDNS, encryptedDNSProbeService) {
					continue
				}
				carriers++
				checkProbeCarrier(t, scenario, node, usedAliases)
			}
			if carriers == 0 {
				t.Error("no node provides the encrypted-DNS probe fixture")
			}
		})
	}
}

func checkProbeCarrier(t *testing.T, scenario *Scenario, carrier Node, usedAliases map[string]bool) {
	t.Helper()
	for _, family := range []string{"ipv4", "ipv6"} {
		if !carrier.hasFamily(family) {
			continue
		}
		actual := aliasesForFamily(carrier.Aliases, family)
		expected := fixedScenarioAliases(family)
		for _, alias := range actual {
			if usedAliases[alias] && !slices.Contains(expected, alias) {
				expected = append(expected, alias)
			}
		}
		slices.Sort(actual)
		slices.Sort(expected)
		if !slices.Equal(actual, expected) {
			t.Errorf("node %q %s aliases = %v, want fixed probe aliases %v", carrier.Name, family, actual, expected)
		}
	}

	quicFixture := false
	for _, service := range carrier.Services {
		switch {
		case service.Type == ServiceEncryptedDNS && service.Name == encryptedDNSProbeService:
			if service.Certificate == nil || !certificateCoversHost(service.Certificate, diagnostic.EncryptedDNSHost) {
				t.Errorf("node %q encrypted-DNS certificate names = %v, want %q", carrier.Name, certificateNames(service), diagnostic.EncryptedDNSHost)
			}
			if !serviceAnswersName(service, diagnostic.ConnectivityProbeHost) {
				t.Errorf("node %q encrypted-DNS records = %v, want query name %q", carrier.Name, serviceRecordNames(service), diagnostic.ConnectivityProbeHost)
			}
		case service.Type == ServiceQUIC && service.Name == quicProbeService:
			quicFixture = true
			if service.Certificate == nil || !certificateCoversHost(service.Certificate, diagnostic.ConnectivityProbeHost) {
				t.Errorf("node %q QUIC certificate names = %v, want %q", carrier.Name, certificateNames(service), diagnostic.ConnectivityProbeHost)
			}
		}
	}
	if !quicFixture {
		t.Errorf("node %q has no QUIC probe fixture", carrier.Name)
	}

	for _, node := range scenario.Topology.Nodes {
		if !nodeProvidesConfiguredResolver(scenario, node) {
			continue
		}
		for _, service := range node.Services {
			if service.Type == ServiceDNS && len(service.Zone)+len(service.Records) > 0 &&
				!serviceAnswersName(service, diagnostic.ConnectivityProbeHost) {
				t.Errorf("node %q DNS records = %v, want fixed probe name %q", node.Name, serviceRecordNames(service), diagnostic.ConnectivityProbeHost)
			}
		}
	}

	checkProbeRoutes(t, scenario, carrier, usedAliases)
}

func fixedScenarioAliases(family string) []string {
	aliases := internetEndpointsForFamily(family)
	// Every resolver the untouched default may query, not just one: the default
	// picks per address family, so a scenario that carries a family has to claim
	// that family's candidate or netdoc dials the real Internet from it.
	for _, candidate := range diagnostic.PublicDNSCandidates(diagnostic.DefaultPublicDNS, true) {
		if resolver, err := netip.ParseAddr(candidate); err == nil && addressFamily(resolver) == family &&
			!slices.Contains(aliases, resolver.String()) {
			aliases = append(aliases, resolver.String())
		}
	}
	return aliases
}

func aliasesForFamily(aliases []string, family string) []string {
	var out []string
	for _, raw := range aliases {
		if addr, err := netip.ParseAddr(raw); err == nil && addressFamily(addr) == family {
			out = append(out, addr.String())
		}
	}
	return out
}

func scenarioAliasConsumers(scenario *Scenario) map[string]bool {
	used := map[string]bool{}
	for _, candidate := range diagnostic.PublicDNSCandidates(diagnostic.DefaultPublicDNS, true) {
		used[candidate] = true
	}
	for _, node := range scenario.Topology.Nodes {
		if addr, err := netip.ParseAddr(node.Resolver); err == nil {
			used[addr.String()] = true
		}
		for _, service := range node.Services {
			if service.DNSFault == nil {
				continue
			}
			for _, raw := range []string{service.DNSFault.WrongA, service.DNSFault.WrongAAAA} {
				if addr, err := netip.ParseAddr(raw); err == nil {
					used[addr.String()] = true
				}
			}
		}
	}
	for _, test := range scenario.Tests {
		target, err := diagnostic.ParseTarget(test.Target)
		if err == nil && target.IP != nil {
			used[target.IP.String()] = true
		}
	}
	return used
}

func nodeHasService(node Node, serviceType, name string) bool {
	for _, service := range node.Services {
		if service.Type == serviceType && service.Name == name && service.Port == 443 {
			return true
		}
	}
	return false
}

func nodeProvidesConfiguredResolver(scenario *Scenario, node Node) bool {
	for _, candidate := range diagnostic.PublicDNSCandidates(diagnostic.DefaultPublicDNS, true) {
		if nodeOwnsAddress(node, candidate) {
			return true
		}
	}
	for _, consumer := range scenario.Topology.Nodes {
		if nodeOwnsAddress(node, consumer.Resolver) {
			return true
		}
	}
	return false
}

func serviceAnswersName(service Service, name string) bool {
	key := dnsKey(name)
	for candidate := range service.Zone {
		if dnsKey(candidate) == key {
			return true
		}
	}
	for _, record := range service.Records {
		if dnsKey(record.Name) == key {
			return true
		}
	}
	return false
}

func serviceRecordNames(service Service) []string {
	var names []string
	for name := range service.Zone {
		names = append(names, dnsKey(name))
	}
	for _, record := range service.Records {
		names = append(names, dnsKey(record.Name))
	}
	slices.Sort(names)
	return names
}

func certificateNames(service Service) []string {
	if service.Certificate == nil {
		return nil
	}
	return service.Certificate.DNSNames
}

func checkProbeRoutes(t *testing.T, scenario *Scenario, carrier Node, usedAliases map[string]bool) {
	t.Helper()
	routes := make(map[string][]string)
	for _, route := range scenario.Topology.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() || !nodeOwnsAddress(carrier, route.Via) {
			continue
		}
		family := addressFamily(prefix.Addr())
		key := route.Node + "\x00" + family
		routes[key] = append(routes[key], prefix.Addr().String())
	}
	for key, destinations := range routes {
		node, family, _ := strings.Cut(key, "\x00")
		expected := internetEndpointsForFamily(family)
		var actual []string
		for _, destination := range destinations {
			if !usedAliases[destination] || slices.Contains(expected, destination) {
				actual = append(actual, destination)
			}
		}
		if len(actual) == 0 {
			continue
		}
		slices.Sort(actual)
		slices.Sort(expected)
		if !slices.Equal(actual, expected) {
			t.Errorf("router %q %s probe routes = %v, want %v", node, family, actual, expected)
		}
	}
}

func TestScenarioPMTUExpectationsMatchTargetPolicy(t *testing.T) {
	check := func(name, raw string, checks []ExpectedCheck) {
		t.Helper()
		if raw == "" {
			return
		}
		target, err := diagnostic.ParseTarget(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if target.Proto == diagnostic.ProtoNone {
			for _, expected := range checks {
				if expected.ID == string(diagnostic.ProbePMTU) {
					t.Errorf("%s: default unknown target %s expects PMTU", name, raw)
				}
			}
		}
	}
	for _, name := range LibraryNames() {
		s, err := LibraryScenario(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range s.Tests {
			expect := s.Expect
			if test.Expect != nil {
				expect = *test.Expect
			}
			check("library/"+name+"/"+test.Name, test.Target, expect.Checks)
		}
	}
	for _, s := range LabScenarios() {
		for i, view := range s.Views {
			check(fmt.Sprintf("lab/%s/view-%d", s.Name, i), view.Target, view.Expected.Checks)
		}
	}
}
