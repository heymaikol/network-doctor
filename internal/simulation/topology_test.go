package simulation

import (
	"strings"
	"testing"
)

const routedScenario = `
name: routed
topology:
  segments:
    - {name: client-lan, subnet: 10.77.1.0/24}
    - {name: upstream, subnet: 10.77.2.0/24}
  nodes:
    - name: client
      role: client
      resolver: 10.77.2.20
      interfaces:
        - {segment: client-lan, address: 10.77.1.10/24}
    - name: gateway
      role: router
      interfaces:
        - {segment: client-lan, address: 10.77.1.1/24}
        - {segment: upstream, address: 10.77.2.1/24}
    - name: target
      interfaces:
        - {segment: upstream, address: 10.77.2.20/24}
  routes:
    - {node: client, destination: default, via: 10.77.1.1, metric: 100}
    - {node: target, destination: 10.77.1.0/24, via: 10.77.2.1}
tests:
  - {node: client, target: 10.77.2.20:80}
expect:
  verdict: ok
`

func TestRoutedTopologyValidationAndCanonicalization(t *testing.T) {
	s, err := ParseScenario(strings.NewReader(routedScenario))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Topology.Segments) != 2 || len(s.Topology.Nodes[1].Interfaces) != 2 {
		t.Fatalf("topology was not retained: %+v", s.Topology)
	}
	if got := s.Topology.Nodes[0].Address; got != "10.77.1.10" {
		t.Errorf("primary address = %q", got)
	}
	if got := s.Topology.Nodes[0].Gateway; got != "10.77.1.1" {
		t.Errorf("preferred gateway = %q", got)
	}
	routes := s.Topology.Routes
	if len(routes) != 2 || routes[0].Node != "client" || routes[0].Destination != "default" || routes[0].Metric != 100 {
		t.Errorf("normalized routes = %+v", routes)
	}
}

func TestLegacyTopologyNormalizesWithoutChangingSourceSchema(t *testing.T) {
	s, err := ParseScenario(strings.NewReader(minimalScenario))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Topology.Segments) != 1 || s.Topology.Segments[0].Name != legacySegmentName {
		t.Fatalf("segments = %+v", s.Topology.Segments)
	}
	if got := s.Topology.Nodes[0].Interfaces[0].Address; got != "10.77.0.10/24" {
		t.Errorf("legacy interface = %q", got)
	}
	if len(s.Topology.Routes) != 1 || !s.Topology.Routes[0].Default {
		t.Errorf("legacy routes = %+v", s.Topology.Routes)
	}
}

func TestRoutedTopologyRejects(t *testing.T) {
	tests := []struct {
		name, old, replacement, want string
	}{
		{"duplicate segment", "- {name: upstream, subnet: 10.77.2.0/24}", "- {name: client-lan, subnet: 10.77.2.0/24}", "duplicate segment"},
		{"overlap segment", "10.77.2.0/24", "10.77.1.128/25", "overlaps"},
		{"unknown segment", "segment: upstream, address: 10.77.2.20/24", "segment: missing, address: 10.77.2.20/24", "unknown segment"},
		{"outside segment", "10.77.2.20/24", "10.77.3.20/24", "outside segment"},
		{"duplicate address", "10.77.2.20/24", "10.77.2.1/24", "duplicate interface address"},
		{"router needs two links", "role: router", "role: server", ""},
		{"gateway off link", "via: 10.77.1.1, metric: 100", "via: 10.77.2.1, metric: 100", "not on a directly connected"},
		{"negative metric", "metric: 100", "metric: -1", "out of range"},
		{"scoped gateway", "via: 10.77.1.1, metric: 100", "via: fe80::1%eth0, metric: 100", "scoped"},
	}
	for _, tc := range tests {
		if tc.want == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(routedScenario, tc.old, tc.replacement, 1)
			_, err := ParseScenario(strings.NewReader(raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestConflictingDefaultsNeedDistinctMetrics(t *testing.T) {
	insert := "    - {node: client, destination: default, via: 10.77.1.254, metric: 100}\n"
	first := "    - {node: client, destination: default, via: 10.77.1.1, metric: 100}\n"
	raw := strings.Replace(routedScenario, first, insert+first, 1)
	if _, err := ParseScenario(strings.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "conflicting routes") {
		t.Fatalf("same metric defaults error = %v", err)
	}
	raw = strings.Replace(raw, "via: 10.77.1.254, metric: 100", "via: 10.77.1.254, metric: 200", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	routes := s.Topology.Routes
	if len(routes) != 3 || routes[0].Node != "client" || routes[0].Destination != "default" || routes[0].Metric != 200 ||
		routes[1].Node != "client" || routes[1].Destination != "default" || routes[1].Metric != 100 {
		t.Errorf("normalized routes = %+v", routes)
	}
	if got := s.Topology.Nodes[0].Gateway; got != "10.77.1.1" {
		t.Errorf("preferred gateway = %q, want lower-metric route via 10.77.1.1", got)
	}
}

func TestFaultLogicalRouteAndLinkValidation(t *testing.T) {
	for _, addition := range []string{
		"faults: [{type: replace_default_route, node: client, via: 10.77.1.254, metric: 50}]\n",
		"faults: [{type: link_down, node: gateway, segment: client-lan}]\n",
	} {
		if _, err := ParseScenario(strings.NewReader(routedScenario + addition)); err != nil {
			t.Errorf("valid fault %q: %v", addition, err)
		}
	}
	bad := routedScenario + "faults: [{type: link_down, node: gateway, segment: missing}]\n"
	if _, err := ParseScenario(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "no interface") {
		t.Fatalf("bad link fault error = %v", err)
	}
}

func TestUnknownRoutedFieldsAreRejected(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(routedScenario, "subnet: 10.77.1.0/24", "subnet: 10.77.1.0/24, bridge: br0", 1),
		strings.Replace(routedScenario, "address: 10.77.1.10/24", "address: 10.77.1.10/24, name: eth0", 1),
		strings.Replace(routedScenario, "metric: 100", "metric: 100, expression: default-via", 1),
	} {
		if _, err := ParseScenario(strings.NewReader(raw)); err == nil {
			t.Fatal("unknown topology field was accepted")
		}
	}
}

func TestWarningExpectationMayCarryRouteCause(t *testing.T) {
	raw := strings.Replace(routedScenario, "  verdict: ok", "  checks: [{id: internet_tcp, status: WARN, cause: preferred_route_failed}]", 1)
	if _, err := ParseScenario(strings.NewReader(raw)); err != nil {
		t.Fatalf("warning route cause rejected: %v", err)
	}
}

const dualStackScenario = `
name: dual
topology:
  segments:
    - {name: lan, ipv4: 10.88.1.0/24, ipv6: fd88:1::/64}
    - {name: up, ipv4: 10.88.2.0/24, ipv6: fd88:2::/64}
  nodes:
    - name: client
      role: client
      interfaces:
        - {segment: lan, ipv4: 10.88.1.10/24, ipv6: fd88:1::10/64}
    - name: router
      role: router
      interfaces:
        - {segment: lan, ipv4: 10.88.1.1/24, ipv6: fd88:1::1/64}
        - {segment: up, ipv4: 10.88.2.1/24, ipv6: fd88:2::1/64}
    - name: target
      interfaces:
        - {segment: up, ipv4: 10.88.2.20/24, ipv6: fd88:2::20/64}
  routes:
    - {node: client, destination: default, via: 10.88.1.1, metric: 100}
    - {node: client, destination: "::/0", via: "fd88:1::1", metric: 100}
tests: [{node: client, target: "[fd88:2::20]:80"}]
expect: {verdict: ok}
`

func TestDualStackTopologyValidation(t *testing.T) {
	s, err := ParseScenario(strings.NewReader(dualStackScenario))
	if err != nil {
		t.Fatal(err)
	}
	iface := s.Topology.Nodes[0].Interfaces[0]
	if iface.IPv4 != "10.88.1.10/24" || iface.IPv6 != "fd88:1::10/64" || iface.Address != "" {
		t.Errorf("dual interface = %+v", iface)
	}
	routes := s.Topology.Routes
	if len(routes) != 2 || routes[0].Node != "client" || routes[0].Destination != "default" || routes[0].Family != "ipv4" {
		t.Errorf("IPv4 default = %+v", routes)
	}
	if len(routes) != 2 || routes[1].Node != "client" || routes[1].Destination != "::/0" || routes[1].Family != "ipv6" || !routes[1].Default {
		t.Errorf("IPv6 default = %+v", routes)
	}
}

func TestDualStackTopologyRejectsInvalidFamilies(t *testing.T) {
	cases := []struct{ name, old, replacement, want string }{
		{"IPv6 outside segment", "fd88:2::20/64", "fd88:3::20/64", "outside segment"},
		{"duplicate IPv6", "fd88:2::20/64", "fd88:2::1/64", "duplicate interface address"},
		{"cross-family gateway", "via: \"fd88:1::1\"", "via: 10.88.1.1", "cannot be used"},
		{"scoped IPv6", "via: \"fd88:1::1\"", "via: \"fe80::1%eth0\"", "scoped"},
		{"mapped IPv6", "fd88:1::10/64", "\"::ffff:10.88.1.10/64\"", "IPv4-mapped"},
		{"multicast gateway", "via: \"fd88:1::1\"", "via: \"ff02::1\"", "usable simulator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(dualStackScenario, tc.old, tc.replacement, 1)
			_, err := ParseScenario(strings.NewReader(raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFamilySpecificFaultValidation(t *testing.T) {
	for _, fault := range []string{
		"faults: [{type: no_default_route, node: client, family: ipv6}]\n",
		"faults: [{type: drop, node: router, family: ipv4, direction: outbound}]\n",
	} {
		if _, err := ParseScenario(strings.NewReader(dualStackScenario + fault)); err != nil {
			t.Errorf("valid family fault: %v", err)
		}
	}
	bad := dualStackScenario + "faults: [{type: no_default_route, node: client, family: ipx}]\n"
	if _, err := ParseScenario(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "unknown family") {
		t.Fatalf("bad family error = %v", err)
	}
}

// TestNoDefaultRouteRequiresAMatchingDefault covers issue #164: the fault
// deletes a default route, so a scenario that never installs one for the
// selected family has to fail validation rather than the kernel.
func TestNoDefaultRouteRequiresAMatchingDefault(t *testing.T) {
	// The routers and targets in dualStackScenario carry no routes at all, so
	// they are the mismatch cases; client has one default per family.
	cases := []struct{ name, fault, want string }{
		{"IPv4 without an IPv4 default", "{type: no_default_route, node: router}", `node "router" has no initial ipv4 default route`},
		{"IPv6 without an IPv6 default", "{type: no_default_route, node: target, family: ipv6}", `node "target" has no initial ipv6 default route`},
		{"IPv4 default accepted", "{type: no_default_route, node: client}", ""},
		{"IPv6 default accepted", "{type: no_default_route, node: client, family: ipv6}", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseScenario(strings.NewReader(dualStackScenario + "faults: [" + tc.fault + "]\n"))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("error = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestNoDefaultRouteFamilyMismatch keeps the single-family cases apart from the
// missing-node-routes ones: here the node does have a default route, just not
// for the family the fault names.
func TestNoDefaultRouteFamilyMismatch(t *testing.T) {
	const ipv4Only = `
name: v4-only
topology:
  segments:
    - {name: lan, ipv4: 10.88.1.0/24, ipv6: fd88:1::/64}
  nodes:
    - name: client
      role: client
      interfaces:
        - {segment: lan, ipv4: 10.88.1.10/24, ipv6: fd88:1::10/64}
    - name: gateway
      interfaces:
        - {segment: lan, ipv4: 10.88.1.1/24, ipv6: fd88:1::1/64}
  routes:
    - {node: client, destination: DEST, via: VIA}
tests: [{node: client}]
expect: {verdict: ok}
faults: [{type: no_default_route, node: client, family: FAMILY}]
`
	cases := []struct{ name, dest, via, family, want string }{
		{"IPv6 default asked for IPv4", `"::/0"`, `"fd88:1::1"`, "ipv4", `has no initial ipv4 default route`},
		{"IPv4 default asked for IPv6", "0.0.0.0/0", "10.88.1.1", "ipv6", `has no initial ipv6 default route`},
		{"explicit IPv4 zero prefix", "0.0.0.0/0", "10.88.1.1", "ipv4", ""},
		{"explicit IPv6 zero prefix", `"::/0"`, `"fd88:1::1"`, "ipv6", ""},
		{"default keyword", "default", "10.88.1.1", "ipv4", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.NewReplacer("DEST", tc.dest, "VIA", tc.via, "FAMILY", tc.family).Replace(ipv4Only)
			_, err := ParseScenario(strings.NewReader(raw))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("error = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestNoDefaultRouteAcceptsLegacyGateway pins the implicit-IPv4 path: the
// legacy gateway shorthand normalizes into a default route, so the fault has
// something to delete even though the scenario declares no routes.
func TestNoDefaultRouteAcceptsLegacyGateway(t *testing.T) {
	const legacy = `
name: legacy
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, gateway: 10.77.0.1}
    - {name: gateway, address: 10.77.0.1}
tests: [{node: client}]
expect: {verdict: ok}
faults: [{type: no_default_route, node: client}]
`
	if _, err := ParseScenario(strings.NewReader(legacy)); err != nil {
		t.Fatalf("legacy gateway shorthand: %v", err)
	}
	withoutGateway := strings.Replace(legacy, ", gateway: 10.77.0.1", "", 1)
	if _, err := ParseScenario(strings.NewReader(withoutGateway)); err == nil ||
		!strings.Contains(err.Error(), `node "client" has no initial ipv4 default route`) {
		t.Fatalf("error = %v, want the missing default route", err)
	}
}
