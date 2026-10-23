package routepath

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

const (
	jsonEth1 = `{"ifname":"eth1","link_type":"ether"}`
	jsonVRF0 = `{"ifname":"vrf0","link_type":"ether","linkinfo":{"info_kind":"vrf"}}`
	// jsonEth0InVRF is eth0 enslaved to vrf0, which the same capture lists as a vrf.
	jsonEth0InVRF = `{"ifname":"eth0","link_type":"ether","master":"vrf0"}`
)

// lookupAt is the collection time of the route lookups below. It differs from the
// time of every other capture, so a record that borrowed another capture's time
// shows.
var lookupAt = t0.Add(2 * time.Minute)

// routeGetBody is the ip -j route get output for dst leaving by dev. extra is
// spliced into the object after its last key, for the fields a case adds.
func routeGetBody(dst, dev, extra string) string {
	return fmt.Sprintf(`[{"dst":%q,"dev":%q,"flags":[],"cache":[]%s}]`, dst, dev, extra)
}

// routeGetCapture is one ip -j route get capture of node for endpoint, holding body.
func routeGetCapture(source, node, endpoint, body string) TunnelCapture {
	return TunnelCapture{Source: source, Node: node, Command: TunnelCommandRouteGetPrefix + endpoint, CollectedAt: lookupAt, Data: []byte(body)}
}

// wgRow is one WireGuard import. Zero fields take the proven shape: r1 holds eth0
// and wg0, the default rules, a dump naming wg0 with one peer at 10.0.25.1, and one
// lookup of that endpoint leaving by eth0.
type wgRow struct {
	name  string
	links []string
	rules string
	dump  []string
	// lookup replaces the lookup of the default endpoint. A row that wants its own
	// lookups lists them in gets, and lookup is then left empty.
	lookup string
	gets   []TunnelCapture
	// want lists text each refusal set must contain, one entry per expected
	// refusal. A row with no want must record the tunnel.
	want []string
}

// captures builds the row's captures in the order the import reads them.
func (r wgRow) captures() []TunnelCapture {
	links := r.links
	if links == nil {
		links = []string{jsonEth0, jsonWG0}
	}
	rules := cmpOr(r.rules, defaultRules)
	dump := r.dump
	if dump == nil {
		dump = wgOK("wg0")
	}
	gets := r.gets
	if gets == nil {
		gets = []TunnelCapture{routeGetCapture("ip-route-get-r1", "r1", "10.0.25.1", cmpOr(r.lookup, routeGetBody("10.0.25.1", "eth0", "")))}
	}
	caps := []TunnelCapture{linkCapture("ip-link-r1", "r1", links...), ruleCapture("ip-rule-r1", "r1", rules), dumpCapture("wg-r1", "r1", dump...)}
	return append(caps, gets...)
}

// cmpOr returns v, or fallback when v is empty.
func cmpOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// run imports the row and checks it: a row with no want records exactly one tunnel
// and refuses nothing, and any other row records nothing, proves nothing, and
// refuses once per want entry with text that entry names.
func (r wgRow) run(t *testing.T) TunnelImport {
	t.Helper()
	imp, err := ImportTunnels(importModel(t), r.captures())
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(r.want) == 0 {
		if len(imp.Tunnels) != 1 || len(imp.WireGuard) != 1 || len(imp.Refused) != 0 {
			t.Fatalf("tunnels = %+v, evidence = %+v, refused = %+v; want one record, its evidence, and no refusal", imp.Tunnels, imp.WireGuard, imp.Refused)
		}
		return imp
	}
	if len(imp.Tunnels) != 0 || len(imp.WireGuard) != 0 || len(imp.Unproven) != 0 {
		t.Errorf("tunnels = %+v, evidence = %+v, unproven = %+v; want none, since the proof does not hold", imp.Tunnels, imp.WireGuard, imp.Unproven)
	}
	var reasons []string
	for _, f := range imp.Refused {
		reasons = append(reasons, f.Reason)
	}
	// The row's refusals are the ones about WireGuard. Refusals of the fixture's own
	// fallback devices are not what a row is about, and the model has none.
	if len(reasons) != len(r.want) {
		t.Fatalf("refused = %q; want %d refusals naming %q", reasons, len(r.want), r.want)
	}
	for _, want := range r.want {
		if !refusedFor(imp, want) {
			t.Errorf("refused = %q; want one that says %q", reasons, want)
		}
	}
	return imp
}

// TestWireGuardUnderlayProof checks the proven record and every way the proof is
// refused. Each refusal leaves no record and no evidence, and the one capture that
// shows the problem is named in a refusal, so nothing is read around.
func TestWireGuardUnderlayProof(t *testing.T) {
	steered6 := wgRow{
		// An IPv6 endpoint's lookup follows IPv6 policy rules, which no capture
		// shows. The lookup is a clean unicast route, and still proves nothing.
		name:  "ipv6 endpoint, whose policy rules are not read",
		dump:  []string{wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "[2001:db8::1]:51820")},
		gets:  []TunnelCapture{routeGetCapture("ip-route-get-r1", "r1", "2001:db8::1", routeGetBody("2001:db8::1", "eth0", ""))},
		want:  []string{"IPv6", "IPv6"},
		rules: defaultRules,
	}
	rows := []wgRow{
		{name: "proven"},
		steered6,
		{name: "ipv4 rules steer the lookup", rules: `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"100"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`,
			want: []string{"lists 4 IPv4 policy rules", "the underlay routing table is not proven"}},
		{name: "duplicate route captures", gets: []TunnelCapture{
			routeGetCapture("ip-route-get-a", "r1", "10.0.25.1", routeGetBody("10.0.25.1", "eth0", "")),
			routeGetCapture("ip-route-get-b", "r1", "10.0.25.1", routeGetBody("10.0.25.1", "eth0", "")),
		}, want: []string{"has 2 route get captures", "has 2 route get captures"}},
		{name: "egress device is enslaved to a vrf", links: []string{jsonEth0InVRF, jsonVRF0, jsonWG0},
			want: []string{"the underlay device is enslaved to a vrf"}},
		{name: "egress device is a vrf", links: []string{jsonEth0, jsonVRF0, jsonWG0}, lookup: routeGetBody("10.0.25.1", "vrf0", ""),
			want: []string{"leaves through a vrf device"}},
		{name: "lookup used a vrf table", lookup: routeGetBody("10.0.25.1", "eth0", `,"table":"10"`),
			want: []string{"a table other than main"}},
		{name: "lookup names the main table", lookup: routeGetBody("10.0.25.1", "eth0", `,"table":"main"`)},
		{name: "self-referential egress", lookup: routeGetBody("10.0.25.1", "wg0", ""),
			want: []string{"leaves through the tunnel's own device"}},
		{name: "egress device is not in the link capture", links: []string{jsonWG0}, want: []string{"is not in the link capture"}},
		{name: "destination differs from the endpoint", lookup: routeGetBody("10.0.25.2", "eth0", ""),
			want: []string{"does not match peer endpoint"}},
		{name: "ambiguous multipath", lookup: routeGetBody("10.0.25.1", "eth0", `,"nexthops":[{"dev":"eth0"},{"dev":"eth1"}]`),
			want: []string{"multiple nexthops"}},
		{name: "nexthops is not a list", lookup: routeGetBody("10.0.25.1", "eth0", `,"nexthops":{}`),
			want: []string{"nexthops field that is not a list"}},
		{name: "lookup is marked linkdown", lookup: `[{"dst":"10.0.25.1","dev":"eth0","flags":["linkdown"],"cache":[]}]`,
			want: []string{"dead or linkdown"}},
		{name: "flags is not a list", lookup: `[{"dst":"10.0.25.1","dev":"eth0","flags":"none"}]`,
			want: []string{"flags field that is not a list"}},
		{name: "no egress device", lookup: `[{"dst":"10.0.25.1","flags":[]}]`, want: []string{"names no egress device"}},
		{name: "egress name is not an interface name", lookup: routeGetBody("10.0.25.1", "a/b", ""),
			want: []string{"not a valid Linux interface name"}},
		{name: "two route objects", lookup: `[{"dst":"10.0.25.1","dev":"eth0"},{"dst":"10.0.25.1","dev":"eth1"}]`,
			want: []string{"lists 2 route get objects"}},
		{name: "empty list", lookup: `[]`, want: []string{"lists 0 route get objects"}},
		{name: "not json", lookup: `eth0`, want: []string{"is not valid JSON"}},
		{name: "key differs only in case", lookup: `[{"dst":"10.0.25.1","Dev":"eth0"}]`, want: []string{"differs from \"dev\" only in case"}},
		{name: "dst is not a string", lookup: `[{"dst":10,"dev":"eth0"}]`, want: []string{"dst field that is not a string"}},
		{name: "dst is not an address", lookup: `[{"dst":"endpoint","dev":"eth0"}]`, want: []string{"dst is not an IP address"}},
	}
	// A route type other than unicast is not a lookup that sends the endpoint's
	// packets out of a device, or not one a tunnel can rest on.
	for _, typ := range []string{"unreachable", "blackhole", "prohibit", "throw", "local", "broadcast", "multicast", "anycast", "nat"} {
		rows = append(rows, wgRow{name: "route type " + typ, lookup: routeGetBody("10.0.25.1", "eth0", `,"type":"`+typ+`"`), want: []string{"route lookup is " + typ + ", not a unicast route"}})
	}
	rows = append(rows,
		wgRow{name: "route type unicast", lookup: routeGetBody("10.0.25.1", "eth0", `,"type":"unicast"`)},
		wgRow{name: "route type is not a string", lookup: routeGetBody("10.0.25.1", "eth0", `,"type":null`), want: []string{"type field that is not a string"}},
		wgRow{name: "route type is not a kernel name", lookup: routeGetBody("10.0.25.1", "eth0", `,"type":"Not A Type"`), want: []string{"route type that is not a unicast route"}},
	)
	// The error field is an integer iproute2 prints only when it is not zero.
	// Anything else cannot be read as a lookup that succeeded.
	for _, e := range []struct{ name, value, want string }{
		{"error code", `-113`, "reports an error"},
		{"error text", `"ENETUNREACH"`, "not an integer"},
		{"error null", `null`, "not an integer"},
		{"error empty text", `""`, "not an integer"},
		{"error fraction", `1.5`, "not an integer"},
		{"error object", `{}`, "not an integer"},
		{"error boolean", `false`, "not an integer"},
		{"error list", `[]`, "not an integer"},
	} {
		rows = append(rows, wgRow{name: "malformed " + e.name, lookup: routeGetBody("10.0.25.1", "eth0", `,"error":`+e.value), want: []string{e.want}})
	}
	rows = append(rows, wgRow{name: "error zero", lookup: routeGetBody("10.0.25.1", "eth0", `,"error":0`)})

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) { r.run(t) })
	}
}

// TestWireGuardLookupsAreAccountedFor gives lookups that no WireGuard record can use.
// Each one is refused with a reason, rather than left out of the report.
func TestWireGuardLookupsAreAccountedFor(t *testing.T) {
	good := routeGetBody("10.0.25.1", "eth0", "")
	other := routeGetCapture("ip-route-get-other", "r1", "10.0.25.9", routeGetBody("10.0.25.9", "eth0", ""))
	rows := []wgRow{
		{name: "lookup of an address no interface names", gets: []TunnelCapture{
			routeGetCapture("ip-route-get-r1", "r1", "10.0.25.1", good), other,
		}, want: []string{"is not used: no wireguard interface of node r1 is reported with endpoint 10.0.25.9"}},
		{name: "lookup of an interface refused for its peers", dump: []string{
			wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "10.0.25.1:51820"), wgPeerLine("wg0", "10.0.25.9:51820"),
		}, gets: []TunnelCapture{routeGetCapture("ip-route-get-r1", "r1", "10.0.25.1", good)},
			want: []string{"has 2 peers", "is not used"}},
		{name: "lookup of an interface refused for its fwmark", dump: []string{wgIfaceLine("wg0", "1"), wgPeerLine("wg0", "10.0.25.1:51820")},
			want: []string{"has a fwmark", "is not used"}},
		{name: "lookup on a node with no link capture", gets: []TunnelCapture{
			routeGetCapture("ip-route-get-r1", "r1", "10.0.25.1", good), routeGetCapture("ip-route-get-r2", "r2", "10.0.25.1", good),
		}, want: []string{"needs one usable ip -d -j link capture of node r2"}},
		{name: "lookup on a node the model does not describe", gets: []TunnelCapture{
			routeGetCapture("ip-route-get-r1", "r1", "10.0.25.1", good), routeGetCapture("ip-route-get-r9", "r9", "10.0.25.1", good),
		}, want: []string{"needs one usable ip -d -j link capture of node r9"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			imp, err := ImportTunnels(importModel(t), r.captures())
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			for _, want := range r.want {
				if !refusedFor(imp, want) {
					t.Errorf("refused = %+v; want one that says %q", imp.Refused, want)
				}
			}
			// A refusal names the capture it is about, so the report accounts for
			// every lookup the row adds beside the good one.
			for _, g := range r.gets[min(1, len(r.gets)):] {
				if !slices.ContainsFunc(imp.Refused, func(f TunnelRefusal) bool { return f.Source == g.Source }) {
					t.Errorf("capture %s is not refused: %+v", g.Source, imp.Refused)
				}
			}
		})
	}
}

// TestWireGuardLookupCommandsAreRefused names lookup commands that are not the exact
// command the import reads. Each capture is refused as a command the import does not
// read, so a lookup spelled another way never matches an endpoint by accident.
func TestWireGuardLookupCommandsAreRefused(t *testing.T) {
	for _, command := range []string{
		"ip -j route get",
		"ip -j route get ",
		"ip -j route get example.com",
		"ip -j route get 10.0.25.1 oif eth0",
		"ip -j route get 10.0.25.1/32",
		"ip -j route get 010.0.25.1",
		"ip -j route get fe80::1%eth0",
		"ip -j route get 2001:DB8::1",
		"ip -j route get  10.0.25.1",
		"ip -j -6 route get 2001:db8::1",
	} {
		t.Run(command, func(t *testing.T) {
			caps := wgRow{gets: []TunnelCapture{{Source: "ip-route-get-r1", Node: "r1", Command: command, CollectedAt: lookupAt, Data: []byte(routeGetBody("10.0.25.1", "eth0", ""))}}}.captures()
			imp, err := ImportTunnels(importModel(t), caps)
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			if len(imp.Tunnels) != 0 || len(imp.WireGuard) != 0 || len(imp.Unproven) != 1 {
				t.Errorf("tunnels = %+v, evidence = %+v, unproven = %+v; want the endpoint unproven and no record", imp.Tunnels, imp.WireGuard, imp.Unproven)
			}
			if !refusedFor(imp, "is not one the import reads") {
				t.Errorf("refused = %+v; want the command refused as one the import does not read", imp.Refused)
			}
		})
	}
}

// TestWireGuardRecordKeepsEveryCapture checks the evidence of a proven record: the
// device, dump, lookup, and rules captures, each with its own source and time, and
// the egress device the lookup named.
func TestWireGuardRecordKeepsEveryCapture(t *testing.T) {
	imp := wgRow{}.run(t)
	got := imp.WireGuard[0]
	for what, c := range map[string]struct{ got, want string }{
		"device":   {stamp(got.Device), stamp(netmodelProv("ip-link-r1", t0))},
		"endpoint": {stamp(got.Endpoint), stamp(netmodelProv("wg-r1", t0.Add(time.Minute)))},
		"lookup":   {stamp(got.Lookup), stamp(netmodelProv("ip-route-get-r1", lookupAt))},
		"rules":    {stamp(got.Rules), stamp(netmodelProv("ip-rule-r1", t0))},
	} {
		if c.got != c.want {
			t.Errorf("%s evidence = %s, want %s", what, c.got, c.want)
		}
	}
	if got.Node != "r1" || got.Interface != "wg0" || got.Egress != "eth0" {
		t.Errorf("evidence = %+v, want r1 wg0 leaving by eth0", got)
	}
	if rec := imp.Tunnels[0]; rec.Node != "r1" || rec.VRF != "default" || rec.Interface != "wg0" || rec.Remote != addr("10.0.25.1") || rec.UnderlayVRF != "default" {
		t.Errorf("record = %+v, want r1 default wg0 remote 10.0.25.1 underlay default", rec)
	}
}

// netmodelProv is a capture's source and time as the evidence names them.
func netmodelProv(source string, at time.Time) netmodel.Provenance {
	return netmodel.Provenance{Source: source, CollectedAt: at}
}

// TestWireGuardEndpointWithoutLookupStaysUnproven checks that an endpoint with no
// lookup is reported as before: unproven, with no record and no refusal.
func TestWireGuardEndpointWithoutLookupStaysUnproven(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), wgRow{gets: []TunnelCapture{}}.captures())
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Tunnels) != 0 || len(imp.WireGuard) != 0 || len(imp.Refused) != 0 || len(imp.Unproven) != 1 {
		t.Fatalf("tunnels = %+v, unproven = %+v, refused = %+v; want one unproven endpoint and nothing else", imp.Tunnels, imp.Unproven, imp.Refused)
	}
	if u := imp.Unproven[0]; u.Endpoint.Source != "wg-r1" || strings.Contains(fmt.Sprint(imp.Refused), "route get") {
		t.Errorf("unproven = %+v, want the endpoint of wg-r1", u)
	}
}
