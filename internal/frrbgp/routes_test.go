package frrbgp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// routeFixtureRoot is the FRR 10.7.0 evidence tree, relative to this package.
var routeFixtureRoot = filepath.Join("..", "..", "testdata", "frr", "10.7.0")

// routeCaptureSums pins the original show ip bgp json captures. The digests are the
// ones internal/frrospf pins, so a changed fixture fails here as well.
var routeCaptureSums = map[string]string{
	"r1": "313beb714d6f538726cbd3b518cabf703c90aeba53deb5849d52030a0223f65a",
	"r2": "025d059a6755d1f6be889d5881ab0dac0650c9070f3ad2697408ec0d2dc40bee",
}

// routeOnePath is a path with no peerId: pathFrom, path, origin and one next hop.
const routeOnePath = `{"pathFrom":"external","path":"65002","origin":"IGP","nexthops":[{"ip":"10.0.1.2"}]}`

// routeCapture reads one genuine capture. It returns the raw bytes and the JSON body
// between the echoed command and the node prompt. It fails on a digest or framing
// mismatch, and it never writes the fixture.
func routeCapture(t *testing.T, node string) (raw, body []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(routeFixtureRoot, "bgp", "steady", node+"-show_ip_bgp_json.raw"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != routeCaptureSums[node] {
		t.Fatalf("%s capture digest is %s, want %s", node, got, routeCaptureSums[node])
	}
	const echo = "show ip bgp json\r\n"
	prompt := node + "> "
	if !bytes.HasPrefix(raw, []byte(echo)) || !bytes.HasSuffix(raw, []byte(prompt)) {
		t.Fatalf("%s capture is not echo, JSON, then %q", node, prompt)
	}
	return raw, raw[len(echo) : len(raw)-len(prompt)]
}

// routeReplaceOnce replaces the only occurrence of old in body. It fails the test
// unless old occurs exactly once, so a stale needle cannot leave body unchanged.
func routeReplaceOnce(t *testing.T, body []byte, old, repl string) []byte {
	t.Helper()
	if n := bytes.Count(body, []byte(old)); n != 1 {
		t.Fatalf("needle %q occurs %d times, want 1", old, n)
	}
	return bytes.Replace(body, []byte(old), []byte(repl), 1)
}

// routeDoc returns a table with one prefix whose path array holds paths.
func routeDoc(prefix, paths string) string {
	return `{"routes":{"` + prefix + `":[` + paths + `]}}`
}

// routePeerDoc returns a table whose one path sets peerId to the JSON value peer.
func routePeerDoc(peer string) string {
	return routeDoc("10.0.0.0/8", `{"peerId":`+peer+`,"pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}`)
}

// routeHopDoc returns a table whose one path sets nexthops to the JSON value hops.
func routeHopDoc(hops string) string {
	return routeDoc("10.0.0.0/8", `{"pathFrom":"external","path":"65002","origin":"IGP","nexthops":`+hops+`}`)
}

func TestRouteGenuineR1(t *testing.T) {
	_, body := routeCapture(t, "r1")
	table, err := DecodeRouteTable(body)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddr("10.0.1.2")
	want := RouteTable{RouterID: "1.1.1.1", LocalAS: 65001, VRFName: "default", Routes: []RouteEntry{
		{Prefix: netip.MustParsePrefix("10.10.2.0/24"), Paths: []RoutePath{
			{Source: RouteSourceLearned, Peer: peer, PathFrom: "external", ASPath: "65002", Origin: "IGP", NextHops: []netip.Addr{peer}},
		}},
	}}
	if !reflect.DeepEqual(table, want) {
		t.Errorf("r1 table = %+v\nwant %+v", table, want)
	}
}

func TestRouteGenuineR2(t *testing.T) {
	_, body := routeCapture(t, "r2")
	table, err := DecodeRouteTable(body)
	if err != nil {
		t.Fatal(err)
	}
	// pathFrom external alone does not make this path learned: peerId (unspec) decides it.
	hop := netip.MustParseAddr("0.0.0.0")
	want := RouteTable{RouterID: "2.2.2.2", LocalAS: 65002, VRFName: "default", Routes: []RouteEntry{
		{Prefix: netip.MustParsePrefix("10.10.2.0/24"), Paths: []RoutePath{
			{Source: RouteSourceNoPeer, PathFrom: "external", Origin: "IGP", NextHops: []netip.Addr{hop}},
		}},
	}}
	if !reflect.DeepEqual(table, want) {
		t.Errorf("r2 table = %+v\nwant %+v", table, want)
	}
}

// TestRouteSourceFromPeerID checks that the source class follows peerId alone. The
// origin text and the path text do not change it.
func TestRouteSourceFromPeerID(t *testing.T) {
	_, base := routeCapture(t, "r1")
	tests := []struct {
		name string
		body []byte
		want RouteSource
	}{
		{"peer address is learned", base, RouteSourceLearned},
		{"origin IGP is not a protocol", routeReplaceOnce(t, base, `"origin":"IGP"`, `"origin":"EGP"`), RouteSourceLearned},
		{"external pathFrom without peerId stays unknown", routeReplaceOnce(t, base, `"peerId":"10.0.1.2",`, ``), RouteSourceUnknown},
		{"unspec peer with a non-empty path", routeReplaceOnce(t, base, `"peerId":"10.0.1.2"`, `"peerId":"(unspec)"`), RouteSourceNoPeer},
		{"unspecified IPv4 peer address stays unknown", routeReplaceOnce(t, base, `"peerId":"10.0.1.2"`, `"peerId":"0.0.0.0"`), RouteSourceUnknown},
		{"unspecified IPv6 peer address stays unknown", routeReplaceOnce(t, base, `"peerId":"10.0.1.2"`, `"peerId":"::"`), RouteSourceUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table, err := DecodeRouteTable(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			if got := table.Routes[0].Paths[0].Source; got != tc.want {
				t.Errorf("Source = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestRouteGenuineMutations edits the genuine r1 body and checks the rejection reason.
func TestRouteGenuineMutations(t *testing.T) {
	_, base := routeCapture(t, "r1")
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"repeated routes key", routeReplaceOnce(t, base, `"routes": {`, `"routes": {},"routes": {`), "duplicate key"},
		{"PeerId in place of peerId", routeReplaceOnce(t, base, `"peerId":"10.0.1.2"`, `"PeerId":"10.0.1.2"`), "only in case"},
		{"localAS as a string", routeReplaceOnce(t, base, `"localAS": 65001`, `"localAS": "65001"`), "localAS:"},
		{"prefix without a length", routeReplaceOnce(t, base, `"10.10.2.0/24": [`, `"10.10.2.0": [`), "canonical"},
		{"bytes after the object", append(bytes.Clone(base), "r1> "...), "data follows"},
		{"echoed command kept", append([]byte("show ip bgp json\r\n"), base...), "invalid character"},
		{"routerId with a trailing invisible rune", routeReplaceOnce(t, base, `"routerId": "1.1.1.1"`, `"routerId": "1.1.1.1`+string(rune(0x200b))+`"`), "not a canonical IPv4"},
		{"routerId with a leading zero", routeReplaceOnce(t, base, `"routerId": "1.1.1.1"`, `"routerId": "01.1.1.1"`), "not a canonical IPv4"},
		{"routerId as an IPv4-mapped IPv6 address", routeReplaceOnce(t, base, `"routerId": "1.1.1.1"`, `"routerId": "::ffff:1.1.1.1"`), "not a canonical IPv4"},
		{"localAS zero", routeReplaceOnce(t, base, `"localAS": 65001`, `"localAS": 0`), "not a BGP ASN"},
		{"vrfName empty", routeReplaceOnce(t, base, `"vrfName": "default"`, `"vrfName": ""`), "vrfName is empty"},
		{"vrfName with a bidi override", routeReplaceOnce(t, base, `"vrfName": "default"`, `"vrfName": "def`+string(rune(0x202e))+`ault"`), "control or invisible"},
		{"vrfName with a tab", routeReplaceOnce(t, base, `"vrfName": "default"`, `"vrfName": "de\tfault"`), "control or invisible"},
		{"vrfName with an escape sequence", routeReplaceOnce(t, base, `"vrfName": "default"`, `"vrfName": "\u001b[31mdefault"`), "control or invisible"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRouteTable(tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestRouteRejectsMalformedTables covers empty, truncated, malformed, duplicate, typed,
// peer-address and prefix errors, plus size and nesting edges built from synthetic input.
func TestRouteRejectsMalformedTables(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"empty input", "", "empty"},
		{"whitespace only", " \r\n", "empty"},
		{"missing routes", `{"routerId":"1.1.1.1"}`, "routes is missing"},
		{"null routes", `{"routes":null}`, "routes is null"},
		{"array routes", `{"routes":[]}`, "routes:"},
		{"truncated object", `{"routes":{`, "unexpected end of JSON input"},
		{"two objects", `{"routes":{}}{"routes":{}}`, "data follows"},
		{"bytes after the object", `{"routes":{}}r1> `, "data follows"},
		{"top-level array", `[]`, "not a JSON object"},
		{"not JSON", `routes`, "invalid character"},
		{"invalid UTF-8", "{\"routes\":{},\"x\":\"\xff\"}", "not valid UTF-8"},
		{"duplicate routes key", `{"routes":{},"routes":{}}`, "duplicate key"},
		{"duplicate prefix", `{"routes":{"10.0.0.0/8":[` + routeOnePath + `],"10.0.0.0/8":[` + routeOnePath + `]}}`, "duplicate key"},
		{"duplicate key in a path", routeDoc("10.0.0.0/8", `{"peerId":"10.0.1.2","peerId":"10.0.1.2","pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}`), "duplicate key"},
		{"duplicate unknown key ignoring case", `{"routes":{},"Foo":1,"foo":2}`, "duplicate key"},
		{"path key differing in case", routeDoc("10.0.0.0/8", `{"PeerId":"10.0.1.2","pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}`), "only in case"},
		{"routes key differing in case", `{"Routes":{}}`, "only in case"},
		{"localAS as a string", `{"localAS":"65001","routes":{}}`, "localAS:"},
		{"localAS negative", `{"localAS":-1,"routes":{}}`, "localAS:"},
		{"routerId as a number", `{"routerId":1,"routes":{}}`, "routerId:"},
		{"vrfName null", `{"vrfName":null,"routes":{}}`, "vrfName is null"},
		{"vrfName empty string", `{"vrfName":"","routes":{}}`, "vrfName is empty"},
		{"vrfName with a line separator", `{"vrfName":"de fault","routes":{}}`, "control or invisible"},
		{"routerId not canonical IPv4", `{"routerId":"1.1.1","routes":{}}`, "not a canonical IPv4"},
		{"routerId empty string", `{"routerId":"","routes":{}}`, "not a canonical IPv4"},
		{"routerId IPv6 address", `{"routerId":"::1","routes":{}}`, "not a canonical IPv4"},
		{"localAS zero", `{"localAS":0,"routes":{}}`, "not a BGP ASN"},
		{"localAS 4294967295", `{"localAS":4294967295,"routes":{}}`, "not a BGP ASN"},
		{"localAS past uint32", `{"localAS":4294967296,"routes":{}}`, "localAS:"},
		{"peerId as a number", routePeerDoc(`5`), "peerId:"},
		{"peerId null", routePeerDoc(`null`), "peerId is null"},
		{"peerId not an address", routePeerDoc(`"10.0.1.300"`), "peerId:"},
		{"peerId empty", routePeerDoc(`""`), "peerId:"},
		{"peerId with a zone", routePeerDoc(`"fe80::1%eth0"`), "peerId:"},
		{"next hop not an address", routeHopDoc(`[{"ip":"10.0.1.300"}]`), "ip:"},
		{"next hop without ip", routeHopDoc(`[{}]`), "ip is missing"},
		{"nexthops not an array", routeHopDoc(`{}`), "nexthops:"},
		{"path without origin", routeDoc("10.0.0.0/8", `{"pathFrom":"external","path":"65002","nexthops":[]}`), "origin is missing"},
		{"path null", routeDoc("10.0.0.0/8", `{"pathFrom":"external","path":null,"origin":"IGP","nexthops":[]}`), "path is null"},
		{"path not an object", routeDoc("10.0.0.0/8", `5`), "path is not a JSON object"},
		{"null path", routeDoc("10.0.0.0/8", `null`), "path is not a JSON object"},
		{"empty path list", routeDoc("10.0.0.0/8", ``), "has no paths"},
		{"prefix with host bits", routeDoc("10.0.0.1/8", routeOnePath), "canonical"},
		{"prefix length 33", routeDoc("10.0.0.0/33", routeOnePath), "canonical"},
		{"IPv6 prefix", routeDoc("2001:db8::/32", routeOnePath), "canonical"},
		{"IPv4-mapped IPv6 prefix", routeDoc("::ffff:10.0.0.0/104", routeOnePath), "canonical"},
		{"leading zero octet", routeDoc("010.0.0.0/8", routeOnePath), "canonical"},
		{"prefix without a length", routeDoc("10.0.0.0", routeOnePath), "canonical"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRouteTable([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestRouteIdentityBoundaries checks the accepted edges of localAS, routerId and
// vrfName, and that a missing identity key keeps its zero value without an error.
func TestRouteIdentityBoundaries(t *testing.T) {
	_, base := routeCapture(t, "r1")
	for _, tc := range []struct {
		text string
		want uint32
	}{{"1", 1}, {"64512", 64512}, {"65534", 65534}, {"4200000000", 4200000000}, {"4294967294", 4294967294}} {
		table, err := DecodeRouteTable(routeReplaceOnce(t, base, `"localAS": 65001`, `"localAS": `+tc.text))
		if err != nil {
			t.Errorf("localAS %s: %v", tc.text, err)
		} else if table.LocalAS != tc.want {
			t.Errorf("localAS %s decoded as %d, want %d", tc.text, table.LocalAS, tc.want)
		}
	}
	body := routeReplaceOnce(t, base, `"routerId": "1.1.1.1"`, `"routerId": "255.255.255.255"`)
	body = routeReplaceOnce(t, body, `"vrfName": "default"`, `"vrfName": "vrf-ä"`)
	table, err := DecodeRouteTable(body)
	if err != nil {
		t.Fatal(err)
	}
	if table.RouterID != "255.255.255.255" || table.VRFName != "vrf-ä" {
		t.Errorf("RouterID = %q, VRFName = %q; want 255.255.255.255 and vrf-ä", table.RouterID, table.VRFName)
	}
	for _, tc := range []struct {
		drop string
		want RouteTable
	}{
		{`"routerId": "1.1.1.1",`, RouteTable{LocalAS: 65001, VRFName: "default"}},
		{`"localAS": 65001,`, RouteTable{RouterID: "1.1.1.1", VRFName: "default"}},
		{`"vrfName": "default",`, RouteTable{RouterID: "1.1.1.1", LocalAS: 65001}},
	} {
		table, err := DecodeRouteTable(routeReplaceOnce(t, base, tc.drop, ""))
		if err != nil {
			t.Errorf("without %s: %v", tc.drop, err)
			continue
		}
		if table.RouterID != tc.want.RouterID || table.LocalAS != tc.want.LocalAS || table.VRFName != tc.want.VRFName || len(table.Routes) != 1 {
			t.Errorf("without %s: RouterID %q, LocalAS %d, VRFName %q, %d routes", tc.drop, table.RouterID, table.LocalAS, table.VRFName, len(table.Routes))
		}
	}
}

// TestRouteEmptyTable checks that a table with no prefixes is valid, not an error.
func TestRouteEmptyTable(t *testing.T) {
	table, err := DecodeRouteTable([]byte(`{"routes":{}}`))
	if err != nil || len(table.Routes) != 0 {
		t.Errorf("empty routes = %+v, %v; want no routes and no error", table, err)
	}
}

// TestRoutePartialGenuineBodies cuts each genuine body short. Every cut leaves the root
// object open, so each must fail, while the whole object must still decode.
func TestRoutePartialGenuineBodies(t *testing.T) {
	for _, node := range []string{"r1", "r2"} {
		_, body := routeCapture(t, node)
		end := bytes.LastIndexByte(body, '}')
		for n := 1; n <= end; n++ {
			if _, err := DecodeRouteTable(body[:n]); err == nil {
				t.Errorf("%s cut at %d bytes decoded; want an error", node, n)
			}
		}
		if _, err := DecodeRouteTable(body[:end+1]); err != nil {
			t.Errorf("%s whole object: %v", node, err)
		}
	}
}

// TestRouteCleansTextFields checks that capture text is stored after textsafe.Clean, so
// an escape sequence in the origin never reaches the screen.
func TestRouteCleansTextFields(t *testing.T) {
	_, base := routeCapture(t, "r1")
	table, err := DecodeRouteTable(routeReplaceOnce(t, base, `"origin":"IGP"`, `"origin":"I\u001b[31mGP"`))
	if err != nil {
		t.Fatal(err)
	}
	if got := table.Routes[0].Paths[0].Origin; got != "IGP" {
		t.Errorf("Origin = %q, want the escape removed: %q", got, "IGP")
	}
}

// TestRouteSizeLimit checks the byte cap at its edge: exactly routeMaxBytes is accepted,
// and one more byte is refused.
func TestRouteSizeLimit(t *testing.T) {
	doc := `{"routes":{}}`
	atLimit := doc + strings.Repeat(" ", routeMaxBytes-len(doc))
	if _, err := DecodeRouteTable([]byte(atLimit)); err != nil {
		t.Errorf("%d bytes: %v", len(atLimit), err)
	}
	over := atLimit + " "
	if _, err := DecodeRouteTable([]byte(over)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("%d bytes: err = %v, want a limit error", len(over), err)
	}
}

// TestRouteNestingLimit checks the depth cap at its edge. The root object is level one,
// so n arrays under "x" reach level n+1.
func TestRouteNestingLimit(t *testing.T) {
	nest := func(n int) string {
		return `{"routes":{},"x":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
	}
	if _, err := DecodeRouteTable([]byte(nest(routeMaxDepth - 1))); err != nil {
		t.Errorf("nesting to level %d: %v", routeMaxDepth, err)
	}
	if _, err := DecodeRouteTable([]byte(nest(routeMaxDepth))); err == nil || !strings.Contains(err.Error(), "nests") {
		t.Errorf("nesting to level %d: err = %v, want a nesting error", routeMaxDepth+1, err)
	}
}

// TestRouteOrdersPrefixesAndKeepsPathOrder checks that prefixes sort by address, not by
// text, and that paths keep the order FRR printed them.
func TestRouteOrdersPrefixesAndKeepsPathOrder(t *testing.T) {
	doc := `{"routes":{"10.10.2.0/24":[` + routeOnePath + `],"9.0.0.0/8":[{"pathFrom":"external","path":"65003","origin":"IGP","nexthops":[]},{"pathFrom":"external","path":"65002","origin":"IGP","nexthops":[]}],"10.0.0.0/8":[` + routeOnePath + `]}}`
	table, err := DecodeRouteTable([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range table.Routes {
		got = append(got, entry.Prefix.String())
	}
	if want := []string{"9.0.0.0/8", "10.0.0.0/8", "10.10.2.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("prefix order = %q, want %q", got, want)
	}
	if paths := table.Routes[0].Paths; len(paths) != 2 || paths[0].ASPath != "65003" || paths[1].ASPath != "65002" {
		t.Errorf("9.0.0.0/8 paths = %+v, want the capture order 65003 then 65002", paths)
	}
}

// TestRouteStdlibKeepsDuplicateKey shows why the walker exists: encoding/json accepts a
// repeated key and keeps the last one, so DecodeRouteTable must refuse it itself.
func TestRouteStdlibKeepsDuplicateKey(t *testing.T) {
	doc := []byte(`{"routes":{"10.0.0.0/8":[]},"routes":{}}`)
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		t.Fatalf("encoding/json rejected the duplicate: %v", err)
	}
	if _, err := DecodeRouteTable(doc); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Errorf("DecodeRouteTable err = %v, want duplicate key", err)
	}
}
