package frrospf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// These tests run decodeZebraRIB on the installed r1 and r2 R bodies, after the pin
// and the frame check, and on edits of them. Edits are made on generic values and
// encoded again, so the members an edit leaves alone keep their genuine values. The
// synthetic candidates use the same required keys as the genuine ones. Nothing here
// writes a capture file.

// zebraTestCandidate returns one valid candidate for the canonical prefix key. mutate,
// when not nil, changes its members before it is encoded.
func zebraTestCandidate(t *testing.T, key string, mutate func(c map[string]any)) json.RawMessage {
	t.Helper()
	p, err := netip.ParsePrefix(key)
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{
		"prefix": key, "prefixLen": p.Bits(), "protocol": "ospf", "distance": 110, "metric": 20,
		"vrfName": "default", "vrfId": 0, "table": 254, "nexthops": []any{},
	}
	if mutate != nil {
		mutate(c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zebraTestBody encodes the candidates under key as one body. encoding/json sorts the
// members of each object, so the bytes are the same on every run.
func zebraTestBody(t *testing.T, key string, candidates ...json.RawMessage) []byte {
	t.Helper()
	b, err := json.Marshal(map[string][]json.RawMessage{key: candidates})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zebraTestGenuine returns the R body of node with the one candidate under key changed
// by edit.
func zebraTestGenuine(t *testing.T, node, key string, edit func(c map[string]any)) []byte {
	t.Helper()
	raw := zebraRIBReadFiles(t)[node+"-R-show_ip_route_json.raw"]
	body, err := zebraRIBCheckFrame(raw, "show ip route json", node)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string][]map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	if len(top[key]) != 1 {
		t.Fatalf("%s holds %d candidates under %s, want one", node, len(top[key]), key)
	}
	edit(top[key][0])
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// zebraTestAccept decodes body and fails the test on any refusal.
func zebraTestAccept(t *testing.T, body []byte) zebraRIB {
	t.Helper()
	rib, reason := decodeZebraRIB(body)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	return rib
}

// zebraTestRefuse decodes body and checks that it is refused for a reason containing want.
func zebraTestRefuse(t *testing.T, body []byte, want string) {
	t.Helper()
	if _, reason := decodeZebraRIB(body); !strings.Contains(reason, want) {
		t.Errorf("reason %q, want one containing %q", reason, want)
	}
}

// zebraTestCandidates decodes body and returns the candidates printed under key.
func zebraTestCandidates(t *testing.T, body []byte, key string) []zebraCandidate {
	t.Helper()
	for _, p := range zebraTestAccept(t, body).Prefixes {
		if p.Prefix.String() == key {
			return p.Candidates
		}
	}
	t.Fatalf("no prefix %s in the decoded body", key)
	return nil
}

// zebraBoolText names an optional flag for a failure message.
func zebraBoolText(p *bool) string {
	switch {
	case p == nil:
		return "absent"
	case *p:
		return "true"
	}
	return "false"
}

// zebraGenuineWant is one candidate expected in a genuine body. An empty hopIP means
// the hop is directly connected.
type zebraGenuineWant struct {
	key      string
	protocol string
	distance uint64
	metric   uint64
	hopIP    string
	hopIface string
}

// zebraGenuineWants are representative candidates of the installed captures, one of
// each protocol the bodies print.
var zebraGenuineWants = map[string][]zebraGenuineWant{
	"r1": {
		{"10.0.1.0/24", "connected", 0, 0, "", "e1"},
		{"10.0.1.1/32", "local", 0, 0, "", "e1"},
		{"10.10.2.0/24", "ospf", 110, 20, "10.0.1.2", "e1"},
	},
	"r2": {
		{"10.10.1.0/24", "ospf", 110, 20, "10.0.1.1", "e2"},
		{"10.20.0.1/32", "local", 0, 0, "", "stub3"},
	},
}

// TestZebraRIBGenuineBodies decodes the installed r1 and r2 R bodies after the pin and
// the frame check. Each holds its pinned number of prefixes in sorted order, and the
// representative candidates print the values the capture holds.
func TestZebraRIBGenuineBodies(t *testing.T) {
	files := zebraRIBReadFiles(t)
	for _, node := range zebraRIBNodes {
		raw := files[node+"-R-show_ip_route_json.raw"]
		if err := zebraRIBCheckPin(node, zebraRIBPins[node], raw); err != nil {
			t.Fatal(err)
		}
		body, err := zebraRIBCheckFrame(raw, "show ip route json", node)
		if err != nil {
			t.Fatal(err)
		}
		rib := zebraTestAccept(t, body)
		if !rib.Known || len(rib.Prefixes) != zebraRIBPrefixes[node] {
			t.Fatalf("%s: known %v with %d prefixes; want known with %d", node, rib.Known, len(rib.Prefixes), zebraRIBPrefixes[node])
		}
		var keys []string
		byKey := map[string]zebraPrefix{}
		for _, p := range rib.Prefixes {
			keys = append(keys, p.Prefix.String())
			byKey[p.Prefix.String()] = p
			for _, c := range p.Candidates {
				// Every genuine candidate prints table and vrfId as 254 and 0. They are
				// checked as data, and nothing assumes that they hold for every candidate.
				if c.Table != 254 || c.VRFID != 0 || c.VRFName != "default" {
					t.Errorf("%s %s: table %d, vrfId %d, vrfName %q", node, p.Prefix, c.Table, c.VRFID, c.VRFName)
				}
			}
		}
		if !slices.IsSorted(keys) {
			t.Errorf("%s: prefixes %v are not in sorted order", node, keys)
		}
		for _, w := range zebraGenuineWants[node] {
			zp, ok := byKey[w.key]
			if !ok || len(zp.Candidates) != 1 {
				t.Fatalf("%s: %s is missing or does not hold one candidate", node, w.key)
			}
			c := zp.Candidates[0]
			if c.Protocol != w.protocol || c.Distance != w.distance || c.Metric != w.metric {
				t.Errorf("%s %s: %s %d/%d, want %s %d/%d", node, w.key, c.Protocol, c.Distance, c.Metric, w.protocol, w.distance, w.metric)
			}
			if !boolIs(c.Selected, true) || !boolIs(c.DestSelected, true) || !boolIs(c.Installed, true) {
				t.Errorf("%s %s: selected %s, destSelected %s, installed %s; want all true",
					node, w.key, zebraBoolText(c.Selected), zebraBoolText(c.DestSelected), zebraBoolText(c.Installed))
			}
			if !c.HopsIdentified || len(c.NextHops) != 1 {
				t.Fatalf("%s %s: %d hops, identified %v; want one identified hop", node, w.key, len(c.NextHops), c.HopsIdentified)
			}
			h := c.NextHops[0]
			if h.InterfaceName != w.hopIface || !boolIs(h.Active, true) || !boolIs(h.FIB, true) {
				t.Errorf("%s %s: hop on %q, active %s, fib %s; want %q, true, true",
					node, w.key, h.InterfaceName, zebraBoolText(h.Active), zebraBoolText(h.FIB), w.hopIface)
			}
			if w.hopIP == "" {
				if h.IP.IsValid() || !boolIs(h.DirectlyConnected, true) {
					t.Errorf("%s %s: direct hop has IP %v and directlyConnected %s", node, w.key, h.IP, zebraBoolText(h.DirectlyConnected))
				}
			} else if h.IP != netip.MustParseAddr(w.hopIP) || h.DirectlyConnected != nil {
				t.Errorf("%s %s: hop IP %v and directlyConnected %s; want %s and absent", node, w.key, h.IP, zebraBoolText(h.DirectlyConnected), w.hopIP)
			}
		}
	}
}

// boolIs reports whether an optional flag is present and equal to want.
func boolIs(p *bool, want bool) bool {
	return p != nil && *p == want
}

// TestZebraRIBFlagsStayAsPrinted checks that the optional flags are kept as zebra
// printed them. A false stays false, an absent key stays nil, and a malformed value
// refuses the body. The edits change the genuine r1 candidate for 10.0.1.0/24.
func TestZebraRIBFlagsStayAsPrinted(t *testing.T) {
	const key = "10.0.1.0/24"
	firstHop := func(c map[string]any) map[string]any {
		return c["nexthops"].([]any)[0].(map[string]any)
	}
	t.Run("false is kept", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) { c["selected"] = false })
		if c := zebraTestCandidates(t, body, key)[0]; !boolIs(c.Selected, false) {
			t.Errorf("selected is %s, want false", zebraBoolText(c.Selected))
		}
	})
	t.Run("absent is nil", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) { delete(c, "selected") })
		if c := zebraTestCandidates(t, body, key)[0]; c.Selected != nil {
			t.Errorf("selected is %s, want absent", zebraBoolText(c.Selected))
		}
	})
	t.Run("string refused", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) { c["selected"] = "true" })
		zebraTestRefuse(t, body, `key "selected" is not a boolean`)
	})
	t.Run("null refused", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) { c["installed"] = nil })
		zebraTestRefuse(t, body, `key "installed" is not a boolean`)
	})
	t.Run("hop fib false and active absent", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) {
			h := firstHop(c)
			h["fib"] = false
			delete(h, "active")
		})
		h := zebraTestCandidates(t, body, key)[0].NextHops[0]
		if !boolIs(h.FIB, false) || h.Active != nil {
			t.Errorf("hop fib %s, active %s; want false and absent", zebraBoolText(h.FIB), zebraBoolText(h.Active))
		}
		if !h.Identified {
			t.Errorf("direct hop is unidentified; want identified")
		}
	})
	t.Run("hop directlyConnected of the wrong type refused", func(t *testing.T) {
		body := zebraTestGenuine(t, "r1", key, func(c map[string]any) { firstHop(c)["directlyConnected"] = 1 })
		zebraTestRefuse(t, body, `key "directlyConnected" is not a boolean`)
	})
}

// TestZebraRIBRequiredKeysRefuseTheCandidate removes each required candidate key, sets
// it to null, and sets it to a value of the wrong JSON type. Each must refuse the body.
func TestZebraRIBRequiredKeysRefuseTheCandidate(t *testing.T) {
	const key = "10.0.1.0/24"
	wrong := map[string]any{
		"prefix": 24, "prefixLen": "24", "protocol": 1, "distance": "110", "metric": 1.5,
		"vrfName": 0, "vrfId": "0", "table": true, "nexthops": map[string]any{},
	}
	for _, name := range slices.Sorted(maps.Keys(wrong)) {
		t.Run(name, func(t *testing.T) {
			refuse := func(edit func(c map[string]any), want string) {
				t.Helper()
				zebraTestRefuse(t, zebraTestBody(t, key, zebraTestCandidate(t, key, edit)), want)
			}
			refuse(func(c map[string]any) { delete(c, name) }, fmt.Sprintf("missing key %q", name))
			refuse(func(c map[string]any) { c[name] = nil }, fmt.Sprintf("key %q is null", name))
			refuse(func(c map[string]any) { c[name] = wrong[name] }, fmt.Sprintf("key %q has the wrong type", name))
		})
	}
}

// TestZebraRIBCandidateMustMatchItsKey checks that a candidate's prefix and prefixLen
// are the key's own, and that only the default VRF is read. The VRF ID and the table
// are kept as printed, so a value other than 0 or 254 is accepted.
func TestZebraRIBCandidateMustMatchItsKey(t *testing.T) {
	const key = "10.0.1.0/24"
	one := func(edit func(c map[string]any)) []byte {
		return zebraTestBody(t, key, zebraTestCandidate(t, key, edit))
	}
	zebraTestRefuse(t, one(func(c map[string]any) { c["prefix"] = "10.0.2.0/24" }), "does not match its key")
	zebraTestRefuse(t, one(func(c map[string]any) { c["prefixLen"] = 16 }), "prefixLen 16 does not match its key")
	zebraTestRefuse(t, one(func(c map[string]any) { c["vrfName"] = "red" }), `vrfName "red" is not the default VRF`)
	got := zebraTestCandidates(t, one(func(c map[string]any) {
		c["vrfId"] = 7
		c["table"] = 100
	}), key)[0]
	if got.VRFID != 7 || got.Table != 100 || got.VRFName != "default" {
		t.Errorf("vrfId %d, table %d, vrfName %q; want 7, 100, default", got.VRFID, got.Table, got.VRFName)
	}
}

// TestZebraRIBPrefixKeysMustBeCanonicalIPv4 refuses each key that is not a canonical
// IPv4 prefix. The two valid rows show that the default route and a zero length are read.
func TestZebraRIBPrefixKeysMustBeCanonicalIPv4(t *testing.T) {
	for _, key := range []string{"10.0.1.5/24", "10.0.1.0", "10.0.1.0/33", "10.0.1.0/0", "2001:db8::/32", "::ffff:10.0.1.0/120", "default"} {
		body, err := json.Marshal(map[string]json.RawMessage{key: json.RawMessage("[]")})
		if err != nil {
			t.Fatal(err)
		}
		zebraTestRefuse(t, body, "is not a canonical IPv4 prefix")
	}
	for _, key := range []string{"0.0.0.0/0", "10.0.1.0/24"} {
		body, err := json.Marshal(map[string]json.RawMessage{key: json.RawMessage("[]")})
		if err != nil {
			t.Fatal(err)
		}
		if rib := zebraTestAccept(t, body); len(rib.Prefixes) != 1 || rib.Prefixes[0].Prefix.String() != key {
			t.Errorf("%s: decoded %v; want one prefix", key, rib.Prefixes)
		}
	}
}

// TestZebraRIBKeepsEveryCandidate checks that a prefix keeps all of its candidates in
// printed order and that no candidate is chosen. An empty array is a prefix with none,
// and {} is unknown rather than an empty RIB.
func TestZebraRIBKeepsEveryCandidate(t *testing.T) {
	const key = "10.0.1.0/24"
	connected := zebraTestCandidate(t, key, func(c map[string]any) {
		c["protocol"], c["distance"], c["metric"] = "connected", 0, 0
		c["selected"] = true
	})
	ospf := zebraTestCandidate(t, key, func(c map[string]any) { c["selected"] = false })
	got := zebraTestCandidates(t, zebraTestBody(t, key, connected, ospf), key)
	if len(got) != 2 || got[0].Protocol != "connected" || got[1].Protocol != "ospf" ||
		!boolIs(got[0].Selected, true) || !boolIs(got[1].Selected, false) {
		t.Errorf("candidates %+v; want connected selected, then ospf not selected", got)
	}
	if empty := zebraTestCandidates(t, []byte(`{"10.0.1.0/24":[]}`), key); len(empty) != 0 {
		t.Errorf("empty array decoded %d candidates; want none", len(empty))
	}
	if rib := zebraTestAccept(t, []byte(`{}`)); rib.Known || len(rib.Prefixes) != 0 {
		t.Errorf("{} is known %v with %d prefixes; want unknown and empty", rib.Known, len(rib.Prefixes))
	}
}

// TestZebraRIBRefusesCaseFoldedKeys refuses a candidate or hop key that differs from a
// read key only in case, even when the exact spelling is also present. The global
// guard covers decodedKeys, and the local lists cover the rest.
func TestZebraRIBRefusesCaseFoldedKeys(t *testing.T) {
	const key = "10.0.1.0/24"
	one := func(edit func(c map[string]any)) []byte {
		return zebraTestBody(t, key, zebraTestCandidate(t, key, edit))
	}
	zebraTestRefuse(t, one(func(c map[string]any) { c["Selected"] = true }), `key "Selected" differs from a candidate key only in case`)
	zebraTestRefuse(t, one(func(c map[string]any) { c["Prefix"] = key }), `key "Prefix" differs from a candidate key only in case`)
	zebraTestRefuse(t, one(func(c map[string]any) { c["Table"] = 254 }), `key "Table" differs from a candidate key only in case`)
	zebraTestRefuse(t, one(func(c map[string]any) { c["Metric"] = 20 }), `"Metric" differs`)
	hopIP := one(func(c map[string]any) { c["nexthops"] = json.RawMessage(`[{"IP":"10.0.1.2","interfaceName":"e1"}]`) })
	zebraTestRefuse(t, hopIP, `nexthops key "IP" differs from a hop key only in case`)
	hopBoth := one(func(c map[string]any) {
		c["nexthops"] = json.RawMessage(`[{"ip":"10.0.1.2","IP":"10.0.1.2","interfaceName":"e1"}]`)
	})
	zebraTestRefuse(t, hopBoth, `nexthops key "IP" differs from a hop key only in case`)
}

// TestZebraRIBRefusesDuplicatesAndTrailingData checks the strict pass on the RIB body.
// A repeated key at any depth, a second top-level value, and a non-object are refused.
func TestZebraRIBRefusesDuplicatesAndTrailingData(t *testing.T) {
	const key = "10.0.1.0/24"
	candidate := string(zebraTestCandidate(t, key, nil))
	dupHop := strings.Replace(candidate, `"nexthops":[]`, `"nexthops":[{"ip":"10.0.1.2","ip":"10.0.1.2","interfaceName":"e1"}]`, 1)
	zebraTestRefuse(t, []byte(`{"10.0.1.0/24":[],"10.0.1.0/24":[]}`), "duplicate key")
	zebraTestRefuse(t, []byte(`{"10.0.1.0/24":[{"prefixLen":24,"prefixLen":24}]}`), "duplicate key")
	zebraTestRefuse(t, []byte(`{"10.0.1.0/24":[`+dupHop+`]}`), "duplicate key")
	zebraTestRefuse(t, []byte(`{}{}`), "data follows the JSON object")
	zebraTestRefuse(t, []byte(`[]`), "not JSON output")
}

// zebraTestOneHop decodes a candidate under key whose only next hop is the JSON object
// hop. It checks the identity of the hop and of its candidate, the address the hop
// keeps, and its interface name. An empty wantIP means the hop keeps no address. It
// returns the hop so the caller can check its flags.
func zebraTestOneHop(t *testing.T, key, hop string, identified bool, wantIP, wantIface string) zebraHop {
	t.Helper()
	body := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
		m["nexthops"] = json.RawMessage("[" + hop + "]")
	}))
	got := zebraTestCandidates(t, body, key)[0]
	if len(got.NextHops) != 1 {
		t.Fatalf("%d hops, want 1", len(got.NextHops))
	}
	h := got.NextHops[0]
	if h.Identified != identified || got.HopsIdentified != identified {
		t.Errorf("hop identified %v, candidate %v; want %v", h.Identified, got.HopsIdentified, identified)
	}
	ip := ""
	if h.IP.IsValid() {
		ip = h.IP.String()
	}
	if ip != wantIP || h.InterfaceName != wantIface {
		t.Errorf("hop IP %q, interface %q; want %q, %q", ip, h.InterfaceName, wantIP, wantIface)
	}
	return h
}

// TestZebraRIBHopIdentity checks the identity rule one hop at a time. An identified hop
// has an interface name and either a valid IPv4 ip or directlyConnected true with no ip
// key. Any other hop is unidentified and keeps its flags. A malformed flag refuses the body.
func TestZebraRIBHopIdentity(t *testing.T) {
	const key = "10.0.1.0/24"
	cases := []struct {
		name, hop  string
		identified bool
		ip, iface  string
	}{
		{"address with interface", `{"ip":"10.0.1.2","interfaceName":"e1"}`, true, "10.0.1.2", "e1"},
		{"address and directly connected", `{"ip":"10.0.1.2","interfaceName":"e1","directlyConnected":true}`, false, "", ""},
		{"directly connected", `{"directlyConnected":true,"interfaceName":"stub1"}`, true, "", "stub1"},
		{"directly connected false, no address", `{"directlyConnected":false,"interfaceName":"e1"}`, false, "", ""},
		{"directly connected, no interface", `{"directlyConnected":true}`, false, "", ""},
		{"address, no interface", `{"ip":"10.0.1.2"}`, false, "", ""},
		{"three-octet address", `{"ip":"10.0.1","interfaceName":"e1"}`, false, "", ""},
		{"IPv6 address", `{"ip":"::1","interfaceName":"e1"}`, false, "", ""},
		{"unspecified address", `{"ip":"0.0.0.0","interfaceName":"e1"}`, false, "", ""},
		{"address as a number", `{"ip":167772162,"interfaceName":"e1"}`, false, "", ""},
		{"empty interface", `{"ip":"10.0.1.2","interfaceName":""}`, false, "", ""},
		{"interface with a space", `{"ip":"10.0.1.2","interfaceName":"e 1"}`, false, "", ""},
		{"empty object", `{}`, false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			zebraTestOneHop(t, key, c.hop, c.identified, c.ip, c.iface)
		})
	}
	mixed := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
		m["nexthops"] = json.RawMessage(`[{"ip":"10.0.1.2","interfaceName":"e1"},{}]`)
	}))
	if got := zebraTestCandidates(t, mixed, key)[0]; got.HopsIdentified || len(got.NextHops) != 2 || !got.NextHops[0].Identified || got.NextHops[1].Identified {
		t.Errorf("mixed hops: identified %v, %d hops; want not identified, two hops, first identified", got.HopsIdentified, len(got.NextHops))
	}
	empty := zebraTestCandidates(t, zebraTestBody(t, key, zebraTestCandidate(t, key, nil)), key)[0]
	if empty.HopsIdentified || len(empty.NextHops) != 0 {
		t.Errorf("empty nexthops: identified %v, %d hops; want not identified and none", empty.HopsIdentified, len(empty.NextHops))
	}
	unidentifiedFlags := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
		m["nexthops"] = json.RawMessage(`[{"active":true,"fib":false}]`)
	}))
	if h := zebraTestCandidates(t, unidentifiedFlags, key)[0].NextHops[0]; h.Identified || !boolIs(h.Active, true) || !boolIs(h.FIB, false) {
		t.Errorf("unidentified hop: identified %v, active %s, fib %s; want false, true, false", h.Identified, zebraBoolText(h.Active), zebraBoolText(h.FIB))
	}
	refusals := []struct{ hop, want string }{
		{`{"ip":"10.0.1.2","interfaceName":"e1","active":"yes"}`, `key "active" is not a boolean`},
		{`{"interfaceName":"e1","fib":1}`, `key "fib" is not a boolean`},
		{`"10.0.1.2"`, "nexthops element: not a JSON object"},
		{`null`, "nexthops element: not a JSON object"},
	}
	for _, r := range refusals {
		body := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
			m["nexthops"] = json.RawMessage("[" + r.hop + "]")
		}))
		zebraTestRefuse(t, body, r.want)
	}
}

// TestZebraRIBDirectlyConnectedWithIPKey checks a hop that prints an ip key next to
// directlyConnected true. Any ip value makes the hop unidentified, valid or not, and the
// flags stay as printed. With directlyConnected false, or with no ip key, the hop keeps
// its identity. A candidate is identified only when every hop is.
func TestZebraRIBDirectlyConnectedWithIPKey(t *testing.T) {
	const key = "10.0.1.0/24"
	cases := []struct {
		name, hop  string
		identified bool
		ip, iface  string
		direct     string
	}{
		{"valid address, directly connected true", `{"ip":"10.0.1.2","interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"zero address, directly connected true", `{"ip":"0.0.0.0","interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"three-octet address, directly connected true", `{"ip":"10.0.1","interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"address as a number, directly connected true", `{"ip":167772162,"interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"null address, directly connected true", `{"ip":null,"interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"empty address, directly connected true", `{"ip":"","interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, false, "", "", "true"},
		{"valid address, directly connected false", `{"ip":"10.0.1.2","interfaceName":"e1","directlyConnected":false,"active":true,"fib":true}`, true, "10.0.1.2", "e1", "false"},
		{"valid address, no directly connected key", `{"ip":"10.0.1.2","interfaceName":"e1","active":true,"fib":true}`, true, "10.0.1.2", "e1", "absent"},
		{"directly connected true, no address key", `{"interfaceName":"e1","directlyConnected":true,"active":true,"fib":true}`, true, "", "e1", "true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := zebraTestOneHop(t, key, c.hop, c.identified, c.ip, c.iface)
			if zebraBoolText(h.DirectlyConnected) != c.direct || !boolIs(h.Active, true) || !boolIs(h.FIB, true) {
				t.Errorf("hop directlyConnected %s, active %s, fib %s; want %s, true, true",
					zebraBoolText(h.DirectlyConnected), zebraBoolText(h.Active), zebraBoolText(h.FIB), c.direct)
			}
		})
	}
	// A valid hop beside a contradictory hop: both are recorded, the first stays
	// identified, and the candidate is not identified as a whole.
	mixed := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
		m["nexthops"] = json.RawMessage(`[{"ip":"10.0.1.2","interfaceName":"e1"},{"ip":"10.0.1.2","interfaceName":"e1","directlyConnected":true}]`)
	}))
	if got := zebraTestCandidates(t, mixed, key)[0]; got.HopsIdentified || len(got.NextHops) != 2 || !got.NextHops[0].Identified || got.NextHops[1].Identified || !boolIs(got.NextHops[1].DirectlyConnected, true) {
		t.Errorf("contradictory hop: identified %v, %d hops; want not identified, two hops, first identified, second not", got.HopsIdentified, len(got.NextHops))
	}
	// Every hop is identified: one has no ip key, the other has directlyConnected false.
	allIdentified := zebraTestBody(t, key, zebraTestCandidate(t, key, func(m map[string]any) {
		m["nexthops"] = json.RawMessage(`[{"interfaceName":"stub1","directlyConnected":true},{"ip":"10.0.1.2","interfaceName":"e1","directlyConnected":false}]`)
	}))
	if got := zebraTestCandidates(t, allIdentified, key)[0]; !got.HopsIdentified || len(got.NextHops) != 2 {
		t.Errorf("identified hops: identified %v, %d hops; want identified and two hops", got.HopsIdentified, len(got.NextHops))
	}
}

// TestZebraRIBAggregateBounds checks the prefix, candidate, and next-hop limits at the
// edge. Each count at the limit is accepted, and one more is refused.
func TestZebraRIBAggregateBounds(t *testing.T) {
	t.Run("prefixes", func(t *testing.T) {
		body := func(n int) []byte {
			top := make(map[string]json.RawMessage, n)
			for i := range n {
				top[fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)] = json.RawMessage("[]")
			}
			b, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		if rib := zebraTestAccept(t, body(maxEntries)); len(rib.Prefixes) != maxEntries {
			t.Errorf("%d prefixes decoded; want %d", len(rib.Prefixes), maxEntries)
		}
		zebraTestRefuse(t, body(maxEntries+1), "more than 4096 is refused")
	})
	t.Run("candidates", func(t *testing.T) {
		body := func(first, second int) []byte {
			list := func(key string, n int) []json.RawMessage {
				out := make([]json.RawMessage, n)
				for i := range out {
					out[i] = zebraTestCandidate(t, key, nil)
				}
				return out
			}
			b, err := json.Marshal(map[string][]json.RawMessage{
				"10.0.1.0/24": list("10.0.1.0/24", first),
				"10.0.2.0/24": list("10.0.2.0/24", second),
			})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		total := 0
		for _, p := range zebraTestAccept(t, body(maxEntries/2, maxEntries/2)).Prefixes {
			total += len(p.Candidates)
		}
		if total != maxEntries {
			t.Errorf("%d candidates decoded; want %d", total, maxEntries)
		}
		zebraTestRefuse(t, body(maxEntries/2+1, maxEntries/2), "more than 4096 candidate routes is refused")
	})
	t.Run("next hops", func(t *testing.T) {
		const key = "10.0.1.0/24"
		hops := func(n int) json.RawMessage {
			return json.RawMessage("[" + strings.TrimSuffix(strings.Repeat("{},", n), ",") + "]")
		}
		body := func(counts ...int) []byte {
			var cands []json.RawMessage
			for _, n := range counts {
				cands = append(cands, zebraTestCandidate(t, key, func(c map[string]any) { c["nexthops"] = hops(n) }))
			}
			return zebraTestBody(t, key, cands...)
		}
		if got := zebraTestCandidates(t, body(maxEntries), key)[0]; len(got.NextHops) != maxEntries || got.HopsIdentified {
			t.Errorf("%d hops decoded, identified %v; want %d unidentified", len(got.NextHops), got.HopsIdentified, maxEntries)
		}
		zebraTestRefuse(t, body(maxEntries+1), "more than 4096 next hops is refused")
		zebraTestAccept(t, body(maxEntries/2, maxEntries/2))
		zebraTestRefuse(t, body(maxEntries/2, maxEntries/2+1), "more than 4096 next hops is refused")
	})
}

// TestZebraRIBInputLimit checks the size limit, which runs before any parse. The input
// over the limit is not JSON, so a parse first would name a different reason. The
// genuine r1 body padded with spaces to exactly the limit is accepted.
func TestZebraRIBInputLimit(t *testing.T) {
	zebraTestRefuse(t, bytes.Repeat([]byte(" "), MaxCaptureBytes+1), "exceeds")
	raw := zebraRIBReadFiles(t)["r1-R-show_ip_route_json.raw"]
	body, err := zebraRIBCheckFrame(raw, "show ip route json", "r1")
	if err != nil {
		t.Fatal(err)
	}
	padded := append(bytes.Clone(body), bytes.Repeat([]byte(" "), MaxCaptureBytes-len(body))...)
	if rib := zebraTestAccept(t, padded); len(rib.Prefixes) != zebraRIBPrefixes["r1"] {
		t.Errorf("%d prefixes at the limit; want %d", len(rib.Prefixes), zebraRIBPrefixes["r1"])
	}
}

// TestZebraRIBDecodeIsDeterministic decodes the same body twice, and again with its
// top-level members in reverse order. Each result must be equal. Two bad prefixes must
// give the same refusal on every run.
func TestZebraRIBDecodeIsDeterministic(t *testing.T) {
	raw := zebraRIBReadFiles(t)["r1-R-show_ip_route_json.raw"]
	body, err := zebraRIBCheckFrame(raw, "show ip route json", "r1")
	if err != nil {
		t.Fatal(err)
	}
	first := zebraTestAccept(t, body)
	if !reflect.DeepEqual(first, zebraTestAccept(t, body)) {
		t.Error("two decodes of the same body differ")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(top))
	slices.Reverse(keys)
	var reversed bytes.Buffer
	reversed.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			reversed.WriteByte(',')
		}
		name, err := json.Marshal(k)
		if err != nil {
			t.Fatal(err)
		}
		reversed.Write(name)
		reversed.WriteByte(':')
		reversed.Write(top[k])
	}
	reversed.WriteByte('}')
	if !reflect.DeepEqual(first, zebraTestAccept(t, reversed.Bytes())) {
		t.Error("reversed member order decodes differently")
	}
	bad := []byte(`{"10.0.9.0/24":[{"x":1}],"10.0.1.0/24":[{"x":1}]}`)
	_, want := decodeZebraRIB(bad)
	if !strings.Contains(want, `"10.0.1.0/24"`) {
		t.Fatalf("refusal %q does not name the first sorted prefix", want)
	}
	for range 20 {
		if _, reason := decodeZebraRIB(bad); reason != want {
			t.Fatalf("refusal %q, then %q; want the same every run", want, reason)
		}
	}
}

// TestImportStillRefusesRouteCommand keeps the RIB out of Import. The genuine R body,
// declared as show ip route json, is refused for its command, and nothing is written.
func TestImportStillRefusesRouteCommand(t *testing.T) {
	c := fixture(t, "bcast", "r1", CommandNeighborDetail)
	c.Command = "show ip route json"
	c.Data = zebraRIBReadFiles(t)["r1-R-show_ip_route_json.raw"]
	res, err := Import([]Capture{c})
	if err != nil {
		t.Fatal(err)
	}
	cr := res.Report.Captures[0]
	if cr.Accepted || !strings.Contains(cr.Reason, "not supported") {
		t.Errorf("accepted=%v reason=%q, want refused as not supported", cr.Accepted, cr.Reason)
	}
	if len(res.Observations) != 0 {
		t.Errorf("refused capture wrote %d observations", len(res.Observations))
	}
}
