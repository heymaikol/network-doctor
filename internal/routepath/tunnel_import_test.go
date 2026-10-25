package routepath

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// importModel is the tunnel topology with r1's default routing domain listing
// the devices the import tests expect to be recorded, so tunnelRecorded accepts
// them. gre9 is left out on purpose: a test that names it reads the unknown
// interface refusal.
func importModel(t *testing.T) netmodel.Model {
	t.Helper()
	obs := append(without(tunnelTopology(), "config:r1:default"), configured("r1", "default", []netmodel.Interface{
		ifc("eth0", "10.0.12.1/30"), ifc("eth2", "10.0.13.1/30"), ifc("wg0", "172.16.0.1/30"), ifc("gre1"),
	}))
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return m
}

// oneNodeModel models r1 alone, with one configured interface, so an import of r1's
// captures is the whole import and its completeness is r1's alone.
func oneNodeModel(t *testing.T) netmodel.Model {
	t.Helper()
	m, err := netmodel.New(configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.12.1/30")}))
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return m
}

// The device objects the rows share. Each is the shape ip -d -j link prints,
// with the keys the importer reads and the rest left out.
const (
	jsonEth0 = `{"ifname":"eth0","link_type":"ether"}`
	jsonWG0  = `{"ifname":"wg0","link_type":"none","linkinfo":{"info_kind":"wireguard"}}`
	jsonBr0  = `{"ifname":"br0","link_type":"ether","linkinfo":{"info_kind":"bridge"}}`
)

// linkCapture is one ip -d -j link capture of node, built from the JSON of each
// device it lists.
func linkCapture(source, node string, devices ...string) TunnelCapture {
	return TunnelCapture{Source: source, Node: node, Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[" + strings.Join(devices, ",") + "]")}
}

// defaultRules is the ip -j rule show output of a kernel with no policy rules.
const defaultRules = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`

// ruleCapture is one ip -j rule show capture of node, holding the rules as given.
func ruleCapture(source, node, rules string) TunnelCapture {
	return TunnelCapture{Source: source, Node: node, Command: TunnelCommandRules, CollectedAt: t0, Data: []byte(rules)}
}

// dumpCapture is one wg show all dump capture of node, one line per argument.
func dumpCapture(source, node string, lines ...string) TunnelCapture {
	return TunnelCapture{Source: source, Node: node, Command: TunnelCommandWireGuard, CollectedAt: t0.Add(time.Minute), Data: []byte(strings.Join(lines, "\n") + "\n")}
}

// wgIfaceLine is an interface line of a wg show all dump: name, private key,
// public key, listen port, fwmark. The keys are sentinels, so a copy shows up.
func wgIfaceLine(name, fwmark string) string {
	return strings.Join([]string{name, "SENTINEL-PRIVATE-" + name, "SENTINEL-PUBLIC-" + name, "51820", fwmark}, "\t")
}

// wgPeerLine is a peer line: name, public key, preshared key, endpoint, allowed
// IPs, latest handshake, transfer received, transfer sent, keepalive.
func wgPeerLine(name, endpoint string) string {
	return strings.Join([]string{name, "SENTINEL-PEER-PUBLIC", "SENTINEL-PSK", endpoint, "172.16.0.2/32", "0", "0", "0", "0"}, "\t")
}

// keySentinel is shaped like a WireGuard key: 44 characters, longer than any
// Linux interface name. The credential tests put it where a key would sit, so
// an echo of it reaches the output.
var keySentinel = "SENTINEL-KEY-" + strings.Repeat("A", 31)

// wgOK is one interface with its single good peer.
func wgOK(name string) []string {
	return []string{wgIfaceLine(name, "off"), wgPeerLine(name, "10.0.25.1:51820")}
}

// readImportFixture reads one recorded capture from testdata/tunnel_import.
func readImportFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("testdata", "tunnel_import", name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fixtureCaptures is the recorded r1 ip -d -j link capture, its IPv4 rules, its
// WireGuard dump, and the route lookup of the wg0 endpoint. The lookup is the last
// capture, so fixtureCaptures(t)[:3] is the same import with wg0's endpoint unproven.
func fixtureCaptures(t *testing.T) []TunnelCapture {
	t.Helper()
	return []TunnelCapture{
		{Source: "ip-link-r1", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: readImportFixture(t, "r1-ip-link.json")},
		{Source: "wg-r1", Node: "r1", Command: TunnelCommandWireGuard, CollectedAt: t0.Add(time.Minute), Data: readImportFixture(t, "r1-wg-show-all-dump.txt")},
		{Source: "ip-rule-r1", Node: "r1", Command: TunnelCommandRules, CollectedAt: t0, Data: readImportFixture(t, "r1-ip-rule.json")},
		{Source: "ip-route-fibmatch-r1", Node: "r1", Command: TunnelCommandRouteGetFibmatchPrefix + "10.0.25.1", CollectedAt: t0.Add(2 * time.Minute), Data: readImportFixture(t, "r1-ip-route-fibmatch.json")},
	}
}

// renderImport is the text form pinned by the golden file: each record, the
// evidence behind each WireGuard record, each unproven endpoint, and each refusal,
// in the order ImportTunnels returns them.
func renderImport(imp TunnelImport) string {
	var b strings.Builder
	for _, r := range imp.Tunnels {
		fmt.Fprintf(&b, "tunnel %s (%s) %s remote %s underlay %s source %s at %s\n",
			r.Node, r.VRF, r.Interface, r.Remote, r.UnderlayVRF, r.Source, r.CollectedAt.UTC().Format(time.RFC3339))
	}
	for _, w := range imp.WireGuard {
		fmt.Fprintf(&b, "wireguard %s %s egress %s device %s endpoint %s lookup %s rules %s\n",
			w.Node, w.Interface, w.Egress, stamp(w.Device), stamp(w.Endpoint), stamp(w.Lookup), stamp(w.Rules))
	}
	for _, u := range imp.Unproven {
		fmt.Fprintf(&b, "unproven %s (%s) %s remote %s device %s at %s endpoint %s at %s: underlay not shown\n",
			u.Node, u.VRF, u.Interface, u.Remote, u.Device.Source, u.Device.CollectedAt.UTC().Format(time.RFC3339),
			u.Endpoint.Source, u.Endpoint.CollectedAt.UTC().Format(time.RFC3339))
	}
	for _, r := range imp.Refused {
		fmt.Fprintf(&b, "refused %s %s %s: %s\n", r.Source, r.Node, r.Interface, r.Reason)
	}
	for _, n := range imp.Uncovered {
		fmt.Fprintf(&b, "uncovered %s\n", n)
	}
	return b.String()
}

// stamp prints a capture's source and collection time the way the golden file pins them.
func stamp(p netmodel.Provenance) string {
	return p.Source + " at " + p.CollectedAt.UTC().Format(time.RFC3339)
}

// assertImportGolden fails when got differs from the golden file at path.
func assertImportGolden(t *testing.T, path, got string) {
	t.Helper()
	// #nosec G304 -- path is built from this test's own golden file names.
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("output drifted from %s\n--- got\n%s\n--- want\n%s", path, got, want)
	}
}

// assertNoSecret fails when the sentinel the dump fixtures put in their key
// columns reaches the import. The check reads the whole value as JSON.
func assertNoSecret(t *testing.T, imp TunnelImport) {
	t.Helper()
	b, err := json.Marshal(imp)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SENTINEL")) {
		t.Errorf("import output carries a key sentinel: %s", b)
	}
}

// refusedFor reports whether one refusal's reason contains want.
func refusedFor(imp TunnelImport, want string) bool {
	return slices.ContainsFunc(imp.Refused, func(r TunnelRefusal) bool { return strings.Contains(r.Reason, want) })
}

// TestTunnelImportRefusesWhatTheSourcesDoNotProve gives each rule its own row.
// A row yields no record, and a refusal whose reason says which rule refused it.
func TestTunnelImportRefusesWhatTheSourcesDoNotProve(t *testing.T) {
	gre := func(extra, info string) string {
		return `{"ifname":"gre9",` + extra + `"linkinfo":{"info_kind":"gre","info_data":{` + info + `}}}`
	}
	const withEth0 = `{"ifname":"eth0","link_type":"ether"}`
	cases := []struct {
		name     string
		captures []TunnelCapture
		want     string
	}{
		{"gre without a remote",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0",`, `"local":"10.0.12.1"`))}, "names no remote"},
		{"gre multipoint remote any",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0",`, `"remote":"any"`))}, "remote any is a multipoint tunnel"},
		{"gre IPv6 remote",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0",`, `"remote":"2001:db8::1"`))}, "remote is IPv6"},
		{"gre remote that is not an address",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0",`, `"remote":"10.0.25"`))}, "remote is not an IP address"},
		{"ipip without a remote",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"ipip9","link":"eth0","linkinfo":{"info_kind":"ipip","info_data":{}}}`)}, "names no remote"},
		{"gre with a link_netnsid",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0","link_netnsid":0,`, `"remote":"10.0.25.1"`))}, "has a link_netnsid"},
		{"gre externally controlled",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth0",`, `"external":true,"remote":"10.0.25.1"`))}, "is externally controlled"},
		{"gre names no underlay device",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(``, `"remote":"10.0.25.1"`))}, "names no underlay device"},
		{"gre underlay device not in the capture",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, gre(`"link":"eth9",`, `"remote":"10.0.25.1"`))}, `its underlay device is not in the capture`},
		{"gre enslaved to a bridge",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, jsonBr0, gre(`"master":"br0","link":"eth0",`, `"remote":"10.0.25.1"`))}, "the tunnel is enslaved to a device the capture does not show as a vrf"},
		{"underlay device enslaved to a bridge",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", `{"ifname":"eth0","master":"br0","link_type":"ether"}`, jsonBr0, gre(`"link":"eth0",`, `"remote":"10.0.25.1"`))}, "the underlay device is enslaved to a device the capture does not show as a vrf"},
		{"gre the topology does not list",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", withEth0, gre(`"link":"eth0",`, `"remote":"10.0.25.1"`))}, `r1 (default) lists no interface "gre9"`},
		{"wireguard device not in the ip capture",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg7", "off"), wgPeerLine("wg7", "10.0.25.1:51820"))}, "is not in the ip -d -j link capture of r1"},
		{"wireguard device of another kind",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", `{"ifname":"wg0","link_type":"none","linkinfo":{"info_kind":"vxlan"}}`), dumpCapture("wg-r1", "r1", wgOK("wg0")...)}, "is not a wireguard device"},
		{"wireguard device enslaved to a bridge",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonBr0, `{"ifname":"wg0","master":"br0","link_type":"none","linkinfo":{"info_kind":"wireguard"}}`), dumpCapture("wg-r1", "r1", wgOK("wg0")...)}, "the device is enslaved to a device the capture does not show as a vrf"},
		{"wireguard fwmark set",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "1"), wgPeerLine("wg0", "10.0.25.1:51820"))}, "has a fwmark, which steers"},
		{"wireguard interface name has a slash",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg/0", "off"), wgPeerLine("wg/0", "10.0.25.1:51820"))}, "is not a Linux interface name"},
		{"wireguard interface name is sixteen bytes",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg-name-too-long", "off"), wgPeerLine("wg-name-too-long", "10.0.25.1:51820"))}, "is not a Linux interface name"},
		{"wireguard without a peer",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"))}, "has no peer"},
		{"wireguard with two peers",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "10.0.25.1:51820"), wgPeerLine("wg0", "10.0.25.9:51820"))}, "has 2 peers"},
		{"wireguard peer names no endpoint",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "(none)"))}, "names no endpoint"},
		{"wireguard endpoint without a port",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "10.0.25.1"))}, "is not an address and port"},
		{"wireguard node with no ip capture",
			[]TunnelCapture{dumpCapture("wg-r1", "r1", wgOK("wg0")...)}, "needs one usable ip -d -j link capture of node r1"},
		{"node with two ip captures",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), linkCapture("ip-link-r1b", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgOK("wg0")...)}, "has 2 ip -d -j link captures"},
		{"wireguard device the topology does not list",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", `{"ifname":"wg9","link_type":"none","linkinfo":{"info_kind":"wireguard"}}`), dumpCapture("wg-r1", "r1", wgOK("wg9")...)}, `r1 (default) lists no interface "wg9"`},
		{"wireguard node the topology does not know",
			[]TunnelCapture{linkCapture("ip-link-r9", "r9", jsonWG0), dumpCapture("wg-r9", "r9", wgOK("wg0")...)}, `describes node "r9"`},
		{"plain devices of a node the topology does not know",
			[]TunnelCapture{linkCapture("ip-link-r9", "r9", jsonEth0)}, `describes node "r9"`},
		{"dump line with six fields",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), "wg0\ta\tb\tc\td\te")}, "has 6 fields"},
		{"dump peer before its interface",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgPeerLine("wg0", "10.0.25.1:51820"))}, "is a peer line with no interface line before it"},
		{"dump repeats an interface",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), wgIfaceLine("wg0", "off"))}, "repeats an interface"},
		{"wireguard fwmark is a key-shaped value",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", keySentinel), wgPeerLine("wg0", "10.0.25.1:51820"))}, "has a fwmark"},
		{"wireguard interface name is key-shaped",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine(keySentinel, "off"), wgPeerLine(keySentinel, "10.0.25.1:51820"))}, "is not a Linux interface name"},
		{"wireguard peer names a key-shaped interface",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1", wgIfaceLine("wg0", "off"), wgPeerLine(keySentinel, "10.0.25.1:51820"))}, "is not a Linux interface name"},
		{"wireguard dump names a gre device",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1"}}}`), dumpCapture("wg-r1", "r1", wgOK("gre1")...)}, "a wg show all dump also names it"},
		{"wireguard device no dump names",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0)}, "no usable wg show all dump names it"},
		{"device of a kind the import does not read",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"vx0","link_type":"ether","linkinfo":{"info_kind":"vxlan"}}`)}, `has kind "vxlan", which the import does not read`},
		{"device with no kind and an unread link type",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"tun0","link_type":"none"}`)}, `has no kind and link type "none", which the import does not read`},
		{"gre with no policy rules capture",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1"}}}`)}, "node r1 has no ip -j rule show capture"},
		{"empty dump",
			[]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0), dumpCapture("wg-r1", "r1")}, "is empty"},
		{"command the import does not read",
			[]TunnelCapture{{Source: "x", Node: "r1", Command: "ip -j link", CollectedAt: t0, Data: []byte("[]")}}, "is not one the import reads"},
		{"capture with no node",
			[]TunnelCapture{{Source: "x", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[]")}}, "has no node"},
		{"capture with no collection time",
			[]TunnelCapture{func() TunnelCapture {
				c := linkCapture("ip-link-r1", "r1", jsonEth0)
				c.CollectedAt = time.Time{}
				return c
			}()}, "has no collection time"},
		{"ip capture that is not JSON",
			[]TunnelCapture{{Source: "x", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("not json")}}, "is not valid JSON"},
		{"capture over its size limit",
			[]TunnelCapture{{Source: "x", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: bytes.Repeat([]byte(" "), MaxTunnelCaptureBytes+1)}}, "is larger than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imp, err := ImportTunnels(importModel(t), c.captures)
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			if len(imp.Tunnels) != 0 || len(imp.Unproven) != 0 {
				t.Errorf("tunnels = %+v, unproven = %+v, want none", imp.Tunnels, imp.Unproven)
			}
			if !refusedFor(imp, c.want) {
				t.Errorf("refusals = %+v, want one that says %q", imp.Refused, c.want)
			}
			assertNoSecret(t, imp)
		})
	}
}

// TestWireGuardEndpointIsUnproven imports one WireGuard interface. Its endpoint
// and device are shown, but no capture shows the routing domain the endpoint is
// looked up in, so the import lists it as unproven and records no tunnel. Each
// fact keeps the source and time of the capture that showed it.
func TestWireGuardEndpointIsUnproven(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), []TunnelCapture{
		linkCapture("ip-link-r1", "r1", jsonWG0),
		dumpCapture("wg-r1", "r1", wgOK("wg0")...),
	})
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Refused) != 0 || len(imp.Tunnels) != 0 || len(imp.Unproven) != 1 {
		t.Fatalf("tunnels = %+v, unproven = %+v, refused = %+v; want one unproven endpoint and nothing else", imp.Tunnels, imp.Unproven, imp.Refused)
	}
	u := imp.Unproven[0]
	if u.Node != "r1" || u.VRF != "default" || u.Interface != "wg0" || u.Remote != addr("10.0.25.1") {
		t.Errorf("unproven = %+v, want wg0 of r1 in default to 10.0.25.1", u)
	}
	if u.Device.Source != "ip-link-r1" || !u.Device.CollectedAt.Equal(t0) {
		t.Errorf("device provenance = %+v, want ip-link-r1 at %s", u.Device, t0)
	}
	if u.Endpoint.Source != "wg-r1" || !u.Endpoint.CollectedAt.Equal(t0.Add(time.Minute)) {
		t.Errorf("endpoint provenance = %+v, want wg-r1 at %s", u.Endpoint, t0.Add(time.Minute))
	}
}

// TestTunnelImportFixtureGolden imports the recorded fixtures and pins the result
// byte for byte, in two forms. With the endpoint's route lookup, the GRE record and
// the WireGuard record are written, and the WireGuard evidence names the dump, the
// lookup, the rules, and the device capture it rests on. Without the lookup, the
// WireGuard endpoint stays unproven and nothing is written for it. Every refusal
// carries its reason in both.
func TestTunnelImportFixtureGolden(t *testing.T) {
	for _, c := range []struct {
		golden   string
		captures []TunnelCapture
	}{
		{"golden.txt", fixtureCaptures(t)},
		{"golden-unproven.txt", fixtureCaptures(t)[:3]},
	} {
		t.Run(c.golden, func(t *testing.T) {
			imp, err := ImportTunnels(importModel(t), c.captures)
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			assertNoSecret(t, imp)
			assertImportGolden(t, filepath.Join("testdata", "tunnel_import", c.golden), renderImport(imp))
		})
	}
}

// TestTunnelImportIsDeterministic gives the same captures in the opposite order.
// The import, and the topology file it encodes to, must not change.
func TestTunnelImportIsDeterministic(t *testing.T) {
	forward := fixtureCaptures(t)
	reversed := slices.Clone(forward)
	slices.Reverse(reversed)
	a, err := ImportTunnels(importModel(t), forward)
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	b, err := ImportTunnels(importModel(t), reversed)
	if err != nil {
		t.Fatalf("ImportTunnels reversed: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("reversed capture order changed the import:\n%s\nwant:\n%s", renderImport(b), renderImport(a))
	}
	ea, err := Encode(File{Source: fromR1, Model: importModel(t), Tunnels: a.Tunnels})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	eb, err := Encode(File{Source: fromR1, Model: importModel(t), Tunnels: b.Tunnels})
	if err != nil {
		t.Fatalf("Encode reversed: %v", err)
	}
	if !bytes.Equal(ea, eb) {
		t.Error("reversed capture order changed the encoded topology")
	}
}

// TestTunnelImportEncodesAsATopologyFile hands the records to Encode, which reads
// back what it writes, so each record passes the topology's own checks. The
// encoded file must carry no key.
func TestTunnelImportEncodesAsATopologyFile(t *testing.T) {
	m := importModel(t)
	imp, err := ImportTunnels(m, fixtureCaptures(t))
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	data, err := Encode(File{Source: fromR1, Model: m, Tunnels: imp.Tunnels})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Contains(data, []byte("SENTINEL")) {
		t.Errorf("encoded topology carries a key sentinel:\n%s", data)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(back.Tunnels) != len(imp.Tunnels) {
		t.Errorf("decoded %d tunnels, want %d", len(back.Tunnels), len(imp.Tunnels))
	}
}

// TestImportedFactsKeepTheirOwnSourceAndTime checks each emitted record against
// the captures of the import. A record may carry the source and time of a capture
// that showed it, and no other pair.
func TestImportedFactsKeepTheirOwnSourceAndTime(t *testing.T) {
	captures := fixtureCaptures(t)
	imp, err := ImportTunnels(importModel(t), captures)
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	fromCapture := func(p netmodel.Provenance) bool {
		return slices.ContainsFunc(captures, func(c TunnelCapture) bool { return c.Source == p.Source && c.CollectedAt.Equal(p.CollectedAt) })
	}
	for _, r := range imp.Tunnels {
		if !fromCapture(r.Provenance) {
			t.Errorf("record %s at %s matches no capture of the import", r.Source, r.CollectedAt.Format(time.RFC3339))
		}
	}
	for _, u := range imp.Unproven {
		for _, p := range []netmodel.Provenance{u.Device, u.Endpoint} {
			if !fromCapture(p) {
				t.Errorf("unproven %s fact from %s at %s matches no capture of the import", u.Interface, p.Source, p.CollectedAt.Format(time.RFC3339))
			}
		}
	}
	for _, w := range imp.WireGuard {
		for _, p := range []netmodel.Provenance{w.Device, w.Endpoint, w.Lookup, w.Rules} {
			if !fromCapture(p) {
				t.Errorf("wireguard %s fact from %s at %s matches no capture of the import", w.Interface, p.Source, p.CollectedAt.Format(time.RFC3339))
			}
		}
	}
}

// TestUnderlayUnknownWireGuardIsNotEncoded imports the fixtures without the endpoint's
// route lookup and encodes the records. The WireGuard endpoint has no proven underlay
// routing domain, so the topology file must not carry it as a tunnel observed by a
// source.
func TestUnderlayUnknownWireGuardIsNotEncoded(t *testing.T) {
	m := importModel(t)
	imp, err := ImportTunnels(m, fixtureCaptures(t)[:3])
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	data, err := Encode(File{Source: fromR1, Model: m, Tunnels: imp.Tunnels})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for _, r := range back.Tunnels {
		if r.Interface == "wg0" {
			t.Errorf("topology carries wg0 as a tunnel record %+v; its underlay routing domain is not shown", r)
		}
	}
}

// TestTunnelImportRefusesConflictingDumps gives two dumps of one node that
// disagree about one interface. Neither is used, so the import never picks one
// by source order.
func TestTunnelImportRefusesConflictingDumps(t *testing.T) {
	cases := []struct {
		name  string
		dumps []TunnelCapture
	}{
		{"endpoints differ", []TunnelCapture{
			dumpCapture("wg-a", "r1", wgOK("wg0")...),
			dumpCapture("wg-b", "r1", wgIfaceLine("wg0", "off"), wgPeerLine("wg0", "10.0.25.9:51820")),
		}},
		{"fwmark differs", []TunnelCapture{
			dumpCapture("wg-a", "r1", wgOK("wg0")...),
			dumpCapture("wg-b", "r1", wgIfaceLine("wg0", "1"), wgPeerLine("wg0", "10.0.25.1:51820")),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			captures := append([]TunnelCapture{linkCapture("ip-link-r1", "r1", jsonWG0)}, c.dumps...)
			imp, err := ImportTunnels(importModel(t), captures)
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			if len(imp.Tunnels) != 0 || len(imp.Unproven) != 0 {
				t.Errorf("tunnels = %+v, unproven = %+v, want none", imp.Tunnels, imp.Unproven)
			}
			conflicts := 0
			for _, r := range imp.Refused {
				if strings.Contains(r.Reason, "conflicts with source") {
					conflicts++
				}
			}
			if conflicts != 2 {
				t.Errorf("refusals = %+v, want both dumps refused as conflicting", imp.Refused)
			}
			assertNoSecret(t, imp)
		})
	}
}

// TestTunnelImportKeepsOneRecordPerInterface gives two dumps for one interface.
// The source that sorts first is kept, and the other is refused by name.
func TestTunnelImportKeepsOneRecordPerInterface(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), []TunnelCapture{
		linkCapture("ip-link-r1", "r1", jsonWG0),
		dumpCapture("wg-b", "r1", wgOK("wg0")...),
		dumpCapture("wg-a", "r1", wgOK("wg0")...),
	})
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Tunnels) != 0 || len(imp.Unproven) != 1 || imp.Unproven[0].Endpoint.Source != "wg-a" {
		t.Fatalf("tunnels = %+v, unproven = %+v, want one unproven endpoint from wg-a", imp.Tunnels, imp.Unproven)
	}
	if !refusedFor(imp, "the same interface is already reported from source wg-a") {
		t.Errorf("refusals = %+v, want the second dump refused for the duplicate", imp.Refused)
	}
}

// TestTunnelImportInfersNothingFromNames gives tunnel-like names to devices of
// other kinds. A plain bridge is read as one and not refused. Each device of a
// kind the import does not read is refused by its kind, never by its name.
func TestTunnelImportInfersNothingFromNames(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), []TunnelCapture{linkCapture("ip-link-r1", "r1",
		`{"ifname":"gre5","link_type":"ether","linkinfo":{"info_kind":"bridge"}}`,
		`{"ifname":"tun0","link_type":"none"}`,
		`{"ifname":"wg0","link_type":"none","linkinfo":{"info_kind":"vxlan"}}`,
		`{"ifname":"ipip0","link_type":"tunnel"}`,
	)})
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Tunnels) != 0 || len(imp.Refused) != 3 {
		t.Errorf("tunnels = %+v, refused = %+v; want no tunnel and three refusals", imp.Tunnels, imp.Refused)
	}
	for _, want := range []string{`no kind and link type "none"`, `kind "vxlan"`, `no kind and link type "tunnel"`} {
		if !refusedFor(imp, want) {
			t.Errorf("refusals = %+v, want one that says %q", imp.Refused, want)
		}
	}
}

// TestTunnelImportRefusesAnEnslavedTunnel reads a tunnel whose own device is
// enslaved to a vrf. The import does not validate a vrf domain, so the tunnel is
// refused rather than recorded, even with a default rules capture.
func TestTunnelImportRefusesAnEnslavedTunnel(t *testing.T) {
	obs := append(without(tunnelTopology(), "config:r1:blue"), configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.14.1/30"), ifc("gre1")}))
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	imp, err := ImportTunnels(m, []TunnelCapture{
		linkCapture("ip-link-r1", "r1",
			`{"ifname":"blue","link_type":"ether","linkinfo":{"info_kind":"vrf"}}`,
			jsonEth0,
			`{"ifname":"gre1","master":"blue","link":"eth0","link_type":"gre","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1"}}}`,
		),
		ruleCapture("ip-rule-r1", "r1", defaultRules),
	})
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Tunnels) != 0 || !refusedFor(imp, "is enslaved to a vrf, which the import does not validate") {
		t.Fatalf("tunnels = %+v, refused = %+v; want no record and the vrf refusal", imp.Tunnels, imp.Refused)
	}
}

// TestTunnelImportLimits pins the bounds on one import and on each capture. The
// boundary cases sit exactly at a limit, so a change to either side shows.
func TestTunnelImportLimits(t *testing.T) {
	m := importModel(t)
	t.Run("more captures than the limit", func(t *testing.T) {
		captures := make([]TunnelCapture, MaxTunnelCaptures+1)
		for i := range captures {
			captures[i] = TunnelCapture{Source: fmt.Sprintf("c%03d", i), Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[]")}
		}
		if _, err := ImportTunnels(m, captures); err == nil {
			t.Error("ImportTunnels accepted more captures than the limit")
		}
	})
	t.Run("exactly the capture limit", func(t *testing.T) {
		captures := make([]TunnelCapture, MaxTunnelCaptures)
		for i := range captures {
			captures[i] = TunnelCapture{Source: fmt.Sprintf("c%03d", i), Node: "r1", Command: "unread", CollectedAt: t0, Data: []byte("[]")}
		}
		imp, err := ImportTunnels(m, captures)
		if err != nil {
			t.Fatalf("ImportTunnels at the limit: %v", err)
		}
		if len(imp.Refused) != MaxTunnelCaptures {
			t.Errorf("refused %d captures, want all %d", len(imp.Refused), MaxTunnelCaptures)
		}
	})
	t.Run("captures together over the byte limit", func(t *testing.T) {
		big := bytes.Repeat([]byte(" "), MaxTunnelCaptureBytes)
		var captures []TunnelCapture
		for i := 0; i <= MaxTunnelImportBytes/MaxTunnelCaptureBytes; i++ {
			captures = append(captures, TunnelCapture{Source: fmt.Sprintf("big%02d", i), Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: big})
		}
		if _, err := ImportTunnels(m, captures); err == nil {
			t.Error("ImportTunnels accepted captures over the byte limit together")
		}
	})
	t.Run("capture exactly at its byte limit is read, not size-refused", func(t *testing.T) {
		imp, err := ImportTunnels(m, []TunnelCapture{{Source: "x", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: bytes.Repeat([]byte(" "), MaxTunnelCaptureBytes)}})
		if err != nil {
			t.Fatalf("ImportTunnels: %v", err)
		}
		if refusedFor(imp, "larger than") {
			t.Errorf("refusals = %+v, want the capture read, not refused for its size", imp.Refused)
		}
	})
	t.Run("capture without a source label", func(t *testing.T) {
		if _, err := ImportTunnels(m, []TunnelCapture{{Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[]")}}); err == nil {
			t.Error("ImportTunnels accepted a capture with no source label")
		}
	})
	t.Run("two captures with one source label", func(t *testing.T) {
		c := TunnelCapture{Source: "same", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte("[]")}
		if _, err := ImportTunnels(m, []TunnelCapture{c, c}); err == nil {
			t.Error("ImportTunnels accepted two captures with one source label")
		}
	})
}

// mergeRecord is one gre1 record the import never produces, since its underlay
// is unproven. The merge tests use it to exercise the path a lifted gate would take.
func mergeRecord() Tunnel {
	return Tunnel{
		Provenance:  netmodel.Provenance{Source: "ip-link-r1", CollectedAt: t0},
		Node:        "r1",
		VRF:         "default",
		Interface:   "gre1",
		Remote:      netip.MustParseAddr("10.0.25.1"),
		UnderlayVRF: "default",
	}
}

// TestMergeTunnelImportAddsARecord hands the merge one record. The merged file
// must encode and read back, and the record must keep its own source and time.
func TestMergeTunnelImportAddsARecord(t *testing.T) {
	merged, err := MergeTunnelImport(File{Source: fromR1, Model: importModel(t)}, TunnelImport{Tunnels: []Tunnel{mergeRecord()}})
	if err != nil {
		t.Fatalf("MergeTunnelImport: %v", err)
	}
	data, err := Encode(merged)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(back.Tunnels) != 1 || back.Tunnels[0].Interface != "gre1" || back.Tunnels[0].Source != "ip-link-r1" || !back.Tunnels[0].CollectedAt.Equal(t0) {
		t.Errorf("decoded tunnels = %+v, want the one record", back.Tunnels)
	}
}

// TestTunnelImportRefusesAnUnusableInventory gives a capture that decodes but shows
// no device inventory. It is refused, and its node is left uncovered, so the import
// cannot read as complete for that node.
func TestTunnelImportRefusesAnUnusableInventory(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"JSON null", "null", "is not ip -d -j link output"},
		{"empty array", "[]", "lists no devices"},
		{"entry with no ifname", `[{}]`, "has a device with no ifname"},
		{"null entry", `[null]`, "has an element that is not an object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			capture := TunnelCapture{Source: "ip-link-r1", Node: "r1", Command: TunnelCommandIPLink, CollectedAt: t0, Data: []byte(c.data)}
			imp, err := ImportTunnels(importModel(t), []TunnelCapture{capture})
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			if !refusedFor(imp, c.want) {
				t.Errorf("refused = %+v, want one that says %q", imp.Refused, c.want)
			}
			if !slices.Contains(imp.Uncovered, "r1") {
				t.Errorf("uncovered = %v, want r1, whose capture was refused", imp.Uncovered)
			}
		})
	}
}

// TestTunnelImportNamesEveryUncapturedNode gives captures for r1 alone. Every other
// modeled node is named as uncovered, in order, so the import is incomplete.
func TestTunnelImportNamesEveryUncapturedNode(t *testing.T) {
	imp, err := ImportTunnels(importModel(t), fixtureCaptures(t))
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if want := []string{"r2", "r3", "r4", "r5"}; !slices.Equal(imp.Uncovered, want) {
		t.Errorf("uncovered = %v, want %v", imp.Uncovered, want)
	}
}

// TestTunnelImportCoversEveryModeledNode gives each modeled node a plain inventory.
// Nothing is uncovered and nothing is refused, so the import is complete.
func TestTunnelImportCoversEveryModeledNode(t *testing.T) {
	const lo = `{"ifname":"lo","link_type":"loopback"}`
	var captures []TunnelCapture
	for _, node := range []string{"r1", "r2", "r3", "r4", "r5"} {
		captures = append(captures, linkCapture("ip-link-"+node, node, lo))
	}
	imp, err := ImportTunnels(importModel(t), captures)
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Uncovered) != 0 || len(imp.Refused) != 0 || len(imp.Unproven) != 0 {
		t.Errorf("import = %+v, want every node covered and nothing refused", imp)
	}
}

// TestMergeTunnelImportKeepsEveryBaseField merges an empty import into a base that
// uses every File field, then reads the encoding back. The file must hold the same
// evidence as the base, so nothing the base holds is lost on the way to disk.
func TestMergeTunnelImportKeepsEveryBaseField(t *testing.T) {
	base := populatedFile(t)
	merged, err := MergeTunnelImport(base, TunnelImport{})
	if err != nil {
		t.Fatalf("MergeTunnelImport: %v", err)
	}
	data, err := Encode(merged)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !sameEvidence(base, back) {
		t.Errorf("written file differs from the base:\n%s", data)
	}
}

// TestMergeTunnelImportRefusesWhatItCannotAdd gives the merge an incomplete
// import, and a record the base already holds. Each is refused. A complete import
// with nothing to add leaves the encoding of the base unchanged.
func TestMergeTunnelImportRefusesWhatItCannotAdd(t *testing.T) {
	base := File{Source: fromR1, Model: importModel(t)}
	held := base
	held.Tunnels = []Tunnel{mergeRecord()}
	cases := []struct {
		name string
		base File
		imp  TunnelImport
		want string
	}{
		{"refused candidate", base, TunnelImport{Tunnels: []Tunnel{mergeRecord()}, Refused: []TunnelRefusal{{Source: "x", Reason: "y"}}}, "the import is incomplete"},
		{"unproven endpoint", base, TunnelImport{Unproven: []UnprovenTunnel{{Interface: "wg0"}}}, "the import is incomplete"},
		{"node without a capture", base, TunnelImport{Uncovered: []string{"r2"}}, "the import is incomplete"},
		{"record the base holds", held, TunnelImport{Tunnels: []Tunnel{mergeRecord()}}, "already has a tunnel on r1 (default) gre1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := MergeTunnelImport(c.base, c.imp); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("MergeTunnelImport error = %v, want one that says %q", err, c.want)
			}
		})
	}
	want, err := Encode(base)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	merged, err := MergeTunnelImport(base, TunnelImport{})
	if err != nil {
		t.Fatalf("MergeTunnelImport: %v", err)
	}
	got, err := Encode(merged)
	if err != nil {
		t.Fatalf("Encode merged: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("merging an empty complete import changed the encoding:\n%s\nwant:\n%s", got, want)
	}
}

// TestTunnelImportRecordsGREOnlyWhenItsUnderlayIsProven gives each way the
// underlay proof can fail its own row, and the one row that proves it.
func TestTunnelImportRecordsGREOnlyWhenItsUnderlayIsProven(t *testing.T) {
	const (
		eth0 = `{"ifname":"eth0","link_type":"ether"}`
		gre1 = `{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1"}}}`
	)
	cases := []struct {
		name     string
		captures []TunnelCapture
		want     string
		proven   bool
	}{
		{"default rules prove the underlay", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", defaultRules)}, "", true},
		{"a rule at a new priority", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"100"},{"priority":32766,"src":"all","table":"main"}]`)}, "is not one of the kernel default rules", false},
		{"main table moved", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"100"},{"priority":32767,"src":"all","table":"default"}]`)}, "looks up a table other than main", false},
		{"a selector the import does not read", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", `[{"priority":0,"src":"all","table":"local"},{"priority":1000,"src":"all","l3mdev":null},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`)}, "a rule has a key the import does not read", false},
		{"a rule count other than three", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]`)}, "lists 2 IPv4 policy rules", false},
		{"two rules captures of one node", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", defaultRules), ruleCapture("ip-rule-r1b", "r1", defaultRules)}, "has 2 ip -j rule show captures", false},
		{"rules capture of a node with no ip capture", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r9", "r9", defaultRules)}, "needs one usable ip -d -j link capture of node r9", false},
		{"rules that are not JSON", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, gre1), ruleCapture("ip-rule-r1", "r1", "not json")}, "is not valid JSON at byte", false},
		{"gre with a fwmark", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, `{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{"remote":"10.0.25.1","fwmark":"0x10"}}}`), ruleCapture("ip-rule-r1", "r1", defaultRules)}, "has a fwmark", false},
		{"underlay device in a vrf", []TunnelCapture{linkCapture("ip-link-r1", "r1", `{"ifname":"blue","link_type":"ether","linkinfo":{"info_kind":"vrf"}}`, `{"ifname":"eth0","master":"blue","link_type":"ether"}`, gre1), ruleCapture("ip-rule-r1", "r1", defaultRules)}, "the underlay device is enslaved to a vrf", false},
		{"ipip device absent from the model", []TunnelCapture{linkCapture("ip-link-r1", "r1", eth0, `{"ifname":"ipip9","link":"eth0","linkinfo":{"info_kind":"ipip","info_data":{"remote":"10.0.25.1"}}}`), ruleCapture("ip-rule-r1", "r1", defaultRules)}, "lists no interface", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			imp, err := ImportTunnels(importModel(t), c.captures)
			if err != nil {
				t.Fatalf("ImportTunnels: %v", err)
			}
			if c.proven {
				if len(imp.Tunnels) != 1 || imp.Tunnels[0].Interface != "gre1" || len(imp.Refused) != 0 {
					t.Fatalf("tunnels = %+v, refused = %+v; want the gre1 record and no refusal", imp.Tunnels, imp.Refused)
				}
				want := []RulesProof{{Node: "r1", Rules: netmodel.Provenance{Source: "ip-rule-r1", CollectedAt: t0}}}
				if !reflect.DeepEqual(imp.Rules, want) {
					t.Fatalf("rules = %+v, want %+v", imp.Rules, want)
				}
				return
			}
			if len(imp.Tunnels) != 0 || !refusedFor(imp, c.want) {
				t.Fatalf("tunnels = %+v, refused = %+v; want no record and a refusal that says %q", imp.Tunnels, imp.Refused, c.want)
			}
		})
	}
}

// Each default rule as ip -j rule show prints it, and a way to join them into an
// array. The rows below change one rule at a time.
const (
	ruleLocal   = `{"priority":0,"src":"all","table":"local"}`
	ruleMain    = `{"priority":32766,"src":"all","table":"main"}`
	ruleDefault = `{"priority":32767,"src":"all","table":"default"}`
)

func ruleArray(objs ...string) string {
	return "[" + strings.Join(objs, ",") + "]"
}

// TestCheckDefaultRulesAcceptsOnlyTheKernelSet gives checkDefaultRules one
// malformed rules array per row. Only the kernel default set passes: each rule
// names its priority, source, and table explicitly, and each default priority
// appears exactly once.
func TestCheckDefaultRulesAcceptsOnlyTheKernelSet(t *testing.T) {
	for _, tc := range []struct {
		name, rules, want string
	}{
		{"the kernel default set", ruleArray(ruleLocal, ruleMain, ruleDefault), ""},
		{"main listed twice", ruleArray(ruleLocal, ruleMain, ruleMain), "priority 32766 is listed twice"},
		{"default listed twice", ruleArray(ruleLocal, ruleDefault, ruleDefault), "priority 32767 is listed twice"},
		{"local rule without a priority", ruleArray(`{"src":"all","table":"local"}`, ruleMain, ruleDefault), "has no priority"},
		{"priority null", ruleArray(`{"priority":null,"src":"all","table":"local"}`, ruleMain, ruleDefault), "priority that is not an integer"},
		{"priority as a string", ruleArray(`{"priority":"0","src":"all","table":"local"}`, ruleMain, ruleDefault), "priority that is not an integer"},
		{"priority negative zero", ruleArray(`{"priority":-0,"src":"all","table":"local"}`, ruleMain, ruleDefault), "priority that is not an integer"},
		{"a null rule", ruleArray("null", ruleMain, ruleDefault), "is not ip -j rule show output"},
		{"priority repeated, valid last", ruleArray(`{"priority":5,"priority":0,"src":"all","table":"local"}`, ruleMain, ruleDefault), "repeats its priority"},
		{"priority key in another case", ruleArray(`{"Priority":5,"priority":0,"src":"all","table":"local"}`, ruleMain, ruleDefault), "a rule has a key the import does not read"},
		{"source key in another case", ruleArray(`{"priority":0,"SRC":"all","table":"local"}`, ruleMain, ruleDefault), "a rule has a key the import does not read"},
		{"no source", ruleArray(`{"priority":0,"table":"local"}`, ruleMain, ruleDefault), "has no src"},
		{"source that is a number", ruleArray(`{"priority":0,"src":1,"table":"local"}`, ruleMain, ruleDefault), "source that is not a string"},
		{"source other than all", ruleArray(`{"priority":0,"src":"10.0.0.0/8","table":"local"}`, ruleMain, ruleDefault), "selects by a source other than all"},
		{"no table", ruleArray(`{"priority":0,"src":"all"}`, ruleMain, ruleDefault), "has no table"},
		{"main table moved", ruleArray(ruleLocal, `{"priority":32766,"src":"all","table":"100"}`, ruleDefault), "looks up a table other than main"},
		{"a priority outside the set", ruleArray(ruleLocal, `{"priority":100,"src":"all","table":"100"}`, ruleMain), "is not one of the kernel default rules"},
		{"one rule short", ruleArray(ruleLocal, ruleMain), "lists 2 IPv4 policy rules"},
		{"a key the import does not read", ruleArray(ruleLocal, ruleMain, `{"priority":32767,"src":"all","table":"default","dst":"10.0.0.0/8"}`), "a rule has a key the import does not read"},
		{"not JSON", "not json", "is not valid JSON at byte"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDefaultRules([]byte(tc.rules))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// TestBridgePortWithoutKindIsAccepted checks that a port enslaved to a bridge, which
// iproute2 prints with only info_slave_kind in its linkinfo, is a device with no kind
// and refuses nothing. A null kind, or info data with no kind, is refused, since a gre
// device could hide in either.
func TestBridgePortWithoutKindIsAccepted(t *testing.T) {
	port := `{"ifindex":8,"ifname":"eth1","master":"br0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP","link_type":"ether","address":"02:00:00:00:00:02","linkinfo":{"info_slave_kind":"bridge_slave","info_slave_data":{"state":"forwarding"}}}`
	if _, err := parseIPLink([]byte("[" + port + "]")); err != nil {
		t.Fatalf("parseIPLink refused a bridge port: %v", err)
	}
	imp, err := ImportTunnels(importModel(t), []TunnelCapture{linkCapture("ip-link-r1", "r1", jsonBr0, port)})
	if err != nil {
		t.Fatalf("ImportTunnels: %v", err)
	}
	if len(imp.Refused) != 0 {
		t.Errorf("refused = %+v, want the bridge port accepted", imp.Refused)
	}
	for _, bad := range []string{
		`{"ifname":"eth1","link_type":"ether","linkinfo":{"info_data":{"remote":"10.0.25.1"}}}`,
		`{"ifname":"eth1","link_type":"ether","linkinfo":{"info_kind":null,"info_slave_kind":"bridge_slave"}}`,
	} {
		if _, err := parseIPLink([]byte("[" + bad + "]")); err == nil {
			t.Errorf("parseIPLink read %s", bad)
		}
	}
}

// TestKindAndLinkTypeEchoOnlyKernelNames checks that a kind or link type the capture
// supplies is quoted in a refusal only when it has the shape of a kernel name. Any other
// value is named generically, and a vrf name is not echoed at all.
func TestKindAndLinkTypeEchoOnlyKernelNames(t *testing.T) {
	const secret = "zq-secret"
	cases := map[string]TunnelCapture{
		"kind":      linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"x0","link_type":"none","linkinfo":{"info_kind":"`+secret+`"}}`),
		"link type": linkCapture("ip-link-r1", "r1", jsonEth0, `{"ifname":"x1","link_type":"`+secret+`"}`),
	}
	for name, c := range cases {
		imp, err := ImportTunnels(importModel(t), []TunnelCapture{c})
		if err != nil {
			t.Fatalf("%s: ImportTunnels: %v", name, err)
		}
		if len(imp.Refused) != 1 {
			t.Fatalf("%s: refused = %+v, want one refusal", name, imp.Refused)
		}
		if strings.Contains(imp.Refused[0].Reason, secret) {
			t.Errorf("%s: refusal %q names the capture value", name, imp.Refused[0].Reason)
		}
	}
	if err := underlayProven(wireTunnel{VRF: secret, UnderlayVRF: "default"}, ruleState{}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("a tunnel in a vrf was refused with %v, want a refusal without the vrf name", err)
	}
	if got := namedValue("kind", "vxlan"); got != `kind "vxlan"` {
		t.Errorf("namedValue of a kernel name = %q", got)
	}
	if got := namedValue("kind", secret); got != "a kind" {
		t.Errorf("namedValue of a non-kernel name = %q, want \"a kind\"", got)
	}
}

// TestGuardedKeysRefuseOtherCase spells each key a strict reader guards in capitals,
// and two in a Unicode case fold, and checks that the reader refuses it by name. The
// key lists are written out here, so a name dropped from a guard fails this test.
// Each surface first parses its base object, so a refusal is the case check and not
// some other error, and the refusal never repeats the spelling it found.
func TestGuardedKeysRefuseOtherCase(t *testing.T) {
	const (
		ethBase  = `{"ifindex":2,"ifname":"eth0","flags":["UP"],"master":"br0","link":null,"link_type":"ether","link_netnsid":0,"address":"00:00:00:00:00:01","operstate":"UP","linkinfo":{"info_slave_kind":"bridge"},"netns-immutable":false}`
		greBase  = `{"ifindex":3,"ifname":"gre1","link":"eth0","link_type":"gre","address":"10.0.12.1","operstate":"UNKNOWN","linkinfo":{"info_kind":"gre","info_data":{"local":"10.0.12.1","remote":"10.0.12.2","ttl":64}}}`
		addrBase = `{"ifindex":2,"ifname":"gre0","flags":["NOARP"],"operstate":"DOWN","link_type":"gre","address":"0.0.0.0","addr_info":[]}`
		devBase  = `{"type":"unicast","dst":"10.0.12.0/30","dev":"eth0"}`
		nhBase   = `{"type":"unicast","dst":"10.0.12.0/30","nexthops":[{"dev":"eth0"}]}`
		nhidBase = `{"type":"unicast","dst":"10.0.12.0/30","nhid":5}`
	)
	parseLink := func(obj string) error { _, err := parseIPLink([]byte("[" + obj + "]")); return err }
	parseAddr := func(obj string) error { _, err := parseIPAddr([]byte("[" + obj + "]")); return err }
	parseRoute := func(obj string) error { _, err := parseRoutes([]byte("["+obj+"]"), TunnelCommandRoute4); return err }
	// greWith is a gre device whose only info_data attribute is key.
	greWith := func(key string) string {
		return `{"ifname":"gre1","link":"eth0","linkinfo":{"info_kind":"gre","info_data":{"` + key + `":"x"}}}`
	}
	type row struct {
		surface, base, key, spelled string
		parse                       func(string) error
	}
	var rows []row
	add := func(surface string, parse func(string) error, base string, keys ...string) {
		for _, k := range keys {
			rows = append(rows, row{surface: surface, parse: parse, base: base, key: k})
		}
	}
	add("ip link device", parseLink, ethBase, "ifname", "ifindex", "master", "link", "link_type", "link_netnsid", "address", "flags", "operstate", "linkinfo", "netns-immutable")
	add("ip link linkinfo", parseLink, greBase, "info_kind", "info_data")
	for _, k := range []string{"external", "fwmark", "ikey", "okey", "key", "iseq", "oseq", "csum", "icsum", "ocsum", "local", "remote", "proto", "ttl", "pmtudisc", "erspan_index", "erspan_ver"} {
		add("info_data attribute", parseLink, greWith(k), k)
	}
	add("ip addr device", parseAddr, addrBase, "ifindex", "ifname", "flags", "address", "addr_info")
	add("route", parseRoute, devBase, "type", "dev")
	add("route nhid", parseRoute, nhidBase, "nhid")
	add("route nexthops", parseRoute, nhBase, "nexthops", "dev")
	// The Kelvin sign folds to k and the long s folds to s, so EqualFold matches both.
	rows = append(rows,
		row{surface: "info_data attribute", parse: parseLink, base: greWith("key"), key: "key", spelled: "Key"},
		row{surface: "ip link device", parse: parseLink, base: ethBase, key: "flags", spelled: "flagſ"},
	)
	for _, r := range rows {
		if err := r.parse(r.base); err != nil {
			t.Fatalf("%s: base for %q does not parse: %v", r.surface, r.key, err)
		}
		old := `"` + r.key + `":`
		if n := strings.Count(r.base, old); n != 1 {
			t.Fatalf("%s: base holds %d copies of %s, want 1", r.surface, n, old)
		}
		spelled := r.spelled
		if spelled == "" {
			spelled = strings.ToUpper(r.key)
		}
		err := r.parse(strings.Replace(r.base, old, `"`+spelled+`":`, 1))
		want := fmt.Sprintf("differs from %q only in case", r.key)
		switch {
		case err == nil:
			t.Errorf("%s: %q spelled %q was accepted", r.surface, r.key, spelled)
		case !strings.Contains(err.Error(), want):
			t.Errorf("%s: %q spelled %q: error %q, want %q", r.surface, r.key, spelled, err, want)
		case strings.Contains(err.Error(), spelled):
			t.Errorf("%s: error repeats the spelling it found: %v", r.surface, err)
		}
	}
}

// TestGuardedRuleKeysRefuseOtherCase spells each rule key in capitals in the first
// rule of the kernel default set. ruleKeys is not used for the list, so a key
// dropped from it fails here.
func TestGuardedRuleKeysRefuseOtherCase(t *testing.T) {
	if err := checkDefaultRules([]byte(defaultRules)); err != nil {
		t.Fatalf("the kernel default rules are refused: %v", err)
	}
	for _, k := range []string{"priority", "src", "table"} {
		rules := strings.Replace(defaultRules, `"`+k+`":`, `"`+strings.ToUpper(k)+`":`, 1)
		err := checkDefaultRules([]byte(rules))
		switch {
		case err == nil:
			t.Errorf("rule key %q spelled in capitals was accepted", k)
		case !strings.Contains(err.Error(), "a rule has a key the import does not read"):
			t.Errorf("rule key %q spelled in capitals: error %q", k, err)
		case strings.Contains(err.Error(), strings.ToUpper(k)):
			t.Errorf("rule error repeats the spelling it found: %v", err)
		}
	}
}

// TestNonFallbackKindsAreRefusedWhateverTheRules checks the policy text: a gretap,
// erspan device that is not an inert fallback is refused by its kind, under
// the kernel default rules and under rules that steer.
func TestNonFallbackKindsAreRefusedWhateverTheRules(t *testing.T) {
	const steered = `[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","table":"main"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`
	devices := []struct{ dev, want string }{
		{`{"ifname":"gretap9","link_type":"ether","linkinfo":{"info_kind":"gretap","info_data":{"local":"10.0.12.1","remote":"10.0.12.2"}}}`, `has kind "gretap", which the import does not read`},
		{`{"ifname":"erspan9","link_type":"ether","linkinfo":{"info_kind":"erspan","info_data":{"local":"10.0.12.1","remote":"10.0.12.2"}}}`, `has kind "erspan", which the import does not read`},
	}
	for _, d := range devices {
		for _, rules := range []string{defaultRules, steered} {
			caps := []TunnelCapture{linkCapture("ip-link-r1", "r1", jsonEth0, d.dev), ruleCapture("ip-rule-r1", "r1", rules)}
			imp, err := ImportTunnels(importModel(t), caps)
			if err != nil {
				t.Fatal(err)
			}
			if len(imp.Tunnels) != 0 || len(imp.Inert) != 0 {
				t.Errorf("%s: a non-fallback device made a record or an inert fallback: %+v %+v", d.dev[:strings.Index(d.dev, ",")], imp.Tunnels, imp.Inert)
			}
			if !refusedFor(imp, d.want) {
				t.Errorf("refusals %+v, want one containing %q", imp.Refused, d.want)
			}
		}
	}
}
