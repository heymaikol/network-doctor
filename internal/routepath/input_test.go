package routepath

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

const threeRoutersFile = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}],
     "neighbors": [{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "remote_addr": "10.0.12.2"}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "eth1", "addresses": ["10.0.23.2/30"]}]},
    {"source": "config:r3", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r3", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.23.3/30"]}, {"name": "eth1", "addresses": ["10.20.40.8/24"]}]},
    {"source": "fib:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r1", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.12.2", "interface": "eth1"}]}]},
    {"source": "fib:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r2", "vrf": "default", "routes_complete": true,
     "routes": [{"prefix": "10.20.0.0/16", "origin": "kernel", "next_hops": [{"addr": "10.0.23.3", "interface": "eth1"}]}]}
  ],
  "checks": [
    {"source": "probe:r2", "collected_at": "2026-10-09T12:01:00Z", "node": "r2", "vrf": "default", "interface": "eth1", "destination": "10.20.40.8", "result": "fail"}
  ]
}`

func TestDecodedFileExplainsLikeTheInMemoryModel(t *testing.T) {
	f, err := Decode([]byte(threeRoutersFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := Explain(f, addr(dest))
	fwd := spine(e.Forwarding)
	if got := nodesOf(fwd); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Fatalf("forwarding path = %v, want r1 r2 r3", got)
	}
	// r3 owns the destination address, so it is local and needs no FIB row.
	if last := fwd[2].Decision; last.Kind != KindLocal {
		t.Errorf("r3 decision = %+v, want local: the destination is r3's address", last)
	}
	if got := findings(e, FindingForwardingFailed); len(got) != 1 || got[0].Node != "r2" {
		t.Errorf("fib_forwarding_failed = %+v, want one at r2 from the recorded check", got)
	}
}

// The acceptance criteria ask that each hop name the routing evidence it used,
// so the human text has to carry the source row, not only the JSON.
func TestHumanTextNamesTheEvidenceForEachHop(t *testing.T) {
	f, err := Decode([]byte(threeRoutersFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	txt := Explain(f, addr(dest)).Text()
	for _, want := range []string{"evidence fib:r1 (kernel)", "evidence fib:r2 (kernel)"} {
		if !strings.Contains(txt, want) {
			t.Errorf("human text lacks %q, so a hop does not say where its route came from:\n%s", want, txt)
		}
	}
}

func TestDecodeRefusesMalformedFiles(t *testing.T) {
	base := threeRoutersFile
	cases := []struct {
		name string
		data string
		want string
	}{
		{"unknown field", strings.Replace(base, `"version": 1,`, `"version": 1, "verison_typo": 2,`, 1), "unknown field"},
		{"missing version", strings.Replace(base, `"version": 1,`, "", 1), `needs "version": 1`},
		{"future version", strings.Replace(base, `"version": 1,`, `"version": 2,`, 1), "not supported"},
		{"trailing data", base + " {}", "data follows"},
		{"empty source", strings.Replace(base, `"node": "r1", "vrf": "default"},`, `"node": "", "vrf": "default"},`, 1), "needs a node and a vrf"},
		{"bad prefix", strings.Replace(base, "10.20.0.0/16", "10.20.0.0/33", 1), "route prefix"},
		{"bad time", strings.Replace(base, "2026-10-09T12:00:00Z", "yesterday", 1), "collected_at"},
		{"bad plane", strings.Replace(base, `"plane": "fib", "node": "r2"`, `"plane": "rib", "node": "r2"`, 1), "unknown plane"},
		{"bad check result", strings.Replace(base, `"result": "fail"`, `"result": "maybe"`, 1), `not "pass" or "fail"`},
		{"hostname destination", strings.Replace(base, `"destination": "10.20.40.8"`, `"destination": "server.example"`, 1), "destination"},
		{"bad check next hop", strings.Replace(base, `"result": "fail"`, `"next_hop": "not-an-address", "result": "fail"`, 1), "next_hop"},
		{"oversize", strings.Repeat(" ", MaxFileBytes+1), "exceeds the maximum topology size"},
		{"bad source address", strings.Replace(base, `"node": "r1", "vrf": "default"},`, `"node": "r1", "vrf": "default", "address": "10.0.12.x"},`, 1), `source" address`},
		{"bad boundary kind", strings.Replace(base, `"checks": [`, `"boundaries": [{"source": "policy:r2", "collected_at": "2026-10-09T12:00:00Z", "node": "r2", "vrf": "default", "kind": "proxy"}], "checks": [`, 1), `kind "proxy"`},
		{"boundary without provenance", strings.Replace(base, `"checks": [`, `"boundaries": [{"collected_at": "2026-10-09T12:00:00Z", "node": "r2", "vrf": "default", "kind": "nat"}], "checks": [`, 1), "needs source"},
		{"tunnel without source", withTunnels(strings.Replace(tunnelRow, `"source": "config:r1", `, "", 1)), "needs source"},
		{"tunnel without node", withTunnels(strings.Replace(tunnelRow, `"node": "r1", `, "", 1)), "needs source"},
		{"tunnel without vrf", withTunnels(strings.Replace(tunnelRow, `"vrf": "default", `, "", 1)), "needs source"},
		{"tunnel without interface", withTunnels(strings.Replace(tunnelRow, `"interface": "wg0", `, "", 1)), "needs source"},
		{"tunnel without remote", withTunnels(strings.Replace(tunnelRow, `"remote": "10.0.25.1", `, "", 1)), "needs source"},
		{"tunnel without underlay vrf", withTunnels(strings.Replace(tunnelRow, `, "underlay_vrf": "default"`, "", 1)), "needs source"},
		{"tunnel bad time", withTunnels(strings.Replace(tunnelRow, "2026-10-09T12:00:00Z", "yesterday", 1)), "collected_at"},
		{"tunnel unknown field", withTunnels(strings.Replace(tunnelRow, `"remote": `, `"peers": 2, "remote": `, 1)), "unknown field"},
		{"tunnel hostname remote", withTunnels(tunnelTo("vpn.example")), `remote "vpn.example"`},
		{"tunnel prefix remote", withTunnels(tunnelTo("10.0.25.1/32")), `remote "10.0.25.1/32"`},
		{"tunnel zoned remote", withTunnels(tunnelTo("fe80::1%eth0")), "zone"},
		{"tunnel mapped remote", withTunnels(tunnelTo("::ffff:10.0.25.1")), "IPv4-mapped"},
		{"tunnel unspecified remote", withTunnels(tunnelTo("0.0.0.0")), "unspecified"},
		{"tunnel loopback remote", withTunnels(tunnelTo("::1")), "loopback"},
		{"tunnel link-local remote", withTunnels(tunnelTo("fe80::1")), "link-local"},
		{"tunnel multicast remote", withTunnels(tunnelTo("239.1.1.1")), "multipoint"},
		{"tunnel broadcast remote", withTunnels(tunnelTo("255.255.255.255")), "multipoint"},
		{"duplicate tunnel", withTunnels(tunnelRow, tunnelRow), "declares r1 (default) wg0 again"},
		{"conflicting tunnel remotes", withTunnels(tunnelRow, tunnelTo("10.0.26.1")), "declares r1 (default) wg0 again"},
		{"misspelled tunnel interface", withTunnels(strings.Replace(tunnelRow, `"wg0"`, `"wgo"`, 1)), `r1 (default) lists no interface "wgo" and names it on no route`},
		{"tunnel interface only intended", withTunnels(strings.Replace(tunnelRow, `"wg0"`, `"wg9"`, 1)), `r1 (default) lists no interface "wg9"`},
		{"tunnel on a node without the interface", withTunnels(strings.Replace(tunnelRow, `"node": "r1"`, `"node": "r2"`, 1)), `r2 (default) lists no interface "wg0"`},
		{"tunnel in an unrecorded routing domain", withTunnels(strings.Replace(tunnelRow, `"vrf": "default"`, `"vrf": "green"`, 1)), "no configured, control, or fib observation describes r1 (green)"},
		{"tunnel on an unrecorded node", withTunnels(strings.Replace(tunnelRow, `"node": "r1"`, `"node": "r9"`, 1)), "no configured, control, or fib observation describes r9 (default)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode([]byte(c.data))
			if err == nil {
				t.Fatalf("Decode accepted the file; want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

const tunnelRow = `{"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "node": "r1", "vrf": "default", "interface": "wg0", "remote": "10.0.25.1", "underlay_vrf": "default"}`

// tunnelTo is tunnelRow with another remote.
func tunnelTo(remote string) string {
	return strings.Replace(tunnelRow, `"remote": "10.0.25.1"`, `"remote": "`+remote+`"`, 1)
}

// tunnelEvidence records the interfaces the tunnel rows name: r1 lists wg0 in
// two routing domains, r3 names it only on a FIB next hop, and wg9 is only
// intended.
const tunnelEvidence = `
    {"source": "config:r1-wg0", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default", "interfaces": [{"name": "wg0"}]},
    {"source": "config:r1-blue", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "blue", "interfaces": [{"name": "wg0"}]},
    {"source": "intent:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "intended", "node": "r1", "vrf": "default", "interfaces": [{"name": "wg9"}]},
    {"source": "fib:r3", "collected_at": "2026-10-09T12:00:00Z", "plane": "fib", "node": "r3", "vrf": "default",
     "routes": [{"prefix": "10.50.0.0/24", "origin": "static", "next_hops": [{"interface": "wg0"}]}]},`

// withTunnels is threeRoutersFile with tunnelEvidence and these tunnel rows.
func withTunnels(rows ...string) string {
	return strings.NewReplacer(`"observations": [`, `"observations": [`+tunnelEvidence,
		`"checks": [`, `"tunnels": [`+strings.Join(rows, ", ")+`], "checks": [`).Replace(threeRoutersFile)
}

func TestDecodeReadsTunnels(t *testing.T) {
	other := strings.NewReplacer(`"source": "config:r1"`, `"source": "config:r3"`, `"node": "r1"`, `"node": "r3"`, `"remote": "10.0.25.1"`, `"remote": "2001:db8::5"`, `"underlay_vrf": "default"`, `"underlay_vrf": "transit"`).Replace(tunnelRow)
	f, err := Decode([]byte(withTunnels(other, tunnelRow)))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	want := []Tunnel{
		{Provenance: netmodel.Provenance{Source: "config:r1", CollectedAt: t0}, Node: "r1", VRF: "default", Interface: "wg0", Remote: addr("10.0.25.1"), UnderlayVRF: "default"},
		{Provenance: netmodel.Provenance{Source: "config:r3", CollectedAt: t0}, Node: "r3", VRF: "default", Interface: "wg0", Remote: addr("2001:db8::5"), UnderlayVRF: "transit"},
	}
	if !reflect.DeepEqual(f.Tunnels, want) {
		t.Errorf("tunnels = %+v, want %+v in node order with their provenance, r3's wg0 recorded by a next hop alone", f.Tunnels, want)
	}
	// The same interface name in another routing domain is another interface.
	blue := strings.Replace(tunnelRow, `"vrf": "default"`, `"vrf": "blue"`, 1)
	if _, err := Decode([]byte(withTunnels(tunnelRow, blue))); err != nil {
		t.Errorf("one interface name in two routing domains: %v", err)
	}
}

func TestDecodeReadsACheckNextHop(t *testing.T) {
	data := strings.Replace(threeRoutersFile, `"result": "fail"`, `"next_hop": "10.0.23.3", "result": "fail"`, 1)
	f, err := Decode([]byte(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(f.Checks) != 1 || f.Checks[0].NextHop != addr("10.0.23.3") {
		t.Errorf("checks = %+v, want the one check to name next hop 10.0.23.3", f.Checks)
	}
}

// rewriteFile re-encodes threeRoutersFile after mutate adds or changes keys in
// each observation. Only the keys mutate touches differ from the legacy file.
func rewriteFile(t *testing.T, mutate func(obs map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(threeRoutersFile), &doc); err != nil {
		t.Fatalf("legacy file: %v", err)
	}
	for _, o := range doc["observations"].([]any) {
		mutate(o.(map[string]any))
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return out
}

// setAttributes gives every row of the named list in one observation the same
// attribute list, so a variant differs from the legacy file only in that key.
func setAttributes(obs map[string]any, attrs []any) {
	for _, list := range []string{"interfaces", "neighbors", "routes"} {
		rows, _ := obs[list].([]any)
		for _, r := range rows {
			r.(map[string]any)["attributes"] = attrs
		}
	}
}

// explainOutput returns the human and JSON explanation for one topology file.
func explainOutput(t *testing.T, data []byte) (string, string, File) {
	t.Helper()
	f, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := Explain(f, addr(dest))
	js, err := e.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	return e.Text(), string(js), f
}

// Empty attribute lists and the new completeness flag must leave the model and
// both outputs exactly as the legacy file leaves them.
func TestEmptyNewKeysLeaveTheExplanationUnchanged(t *testing.T) {
	legacyText, legacyJSON, legacy := explainOutput(t, []byte(threeRoutersFile))
	variant := rewriteFile(t, func(o map[string]any) {
		o["neighbors_complete"] = false
		setAttributes(o, []any{})
	})
	text, js, f := explainOutput(t, variant)
	if text != legacyText || js != legacyJSON {
		t.Fatalf("empty attribute lists changed the explanation\ntext:\n%s\nwant:\n%s", text, legacyText)
	}
	if !reflect.DeepEqual(f.Model.Observations(), legacy.Model.Observations()) {
		t.Fatal("empty attribute lists built a different model than absent ones")
	}
}

// Real protocol attributes and a complete neighbor inventory are recorded, but
// Lookup, the walks, and the output still read the same answer.
func TestRealAttributesNeverMoveAWalk(t *testing.T) {
	legacyText, legacyJSON, _ := explainOutput(t, []byte(threeRoutersFile))
	variant := rewriteFile(t, func(o map[string]any) {
		o["neighbors_complete"] = true
		setAttributes(o, []any{
			map[string]any{"key": "ospf.area", "value": "0"},
			map[string]any{"key": "ospf.state", "value": "full"},
		})
	})
	text, js, _ := explainOutput(t, variant)
	if text != legacyText || js != legacyJSON {
		t.Fatalf("protocol attributes changed the explanation\ntext:\n%s\nwant:\n%s", text, legacyText)
	}
}

// Neighbor records that share one identity keep their attributes in one
// canonical order, whatever order the file lists them in.
func TestSameIdentityNeighborsDecodeInFileOrder(t *testing.T) {
	first := map[string]any{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "remote_addr": "10.0.12.2",
		"attributes": []any{map[string]any{"key": "ospf.state", "value": "full"}}}
	second := map[string]any{"local_interface": "eth1", "remote_node": "r2", "remote_interface": "eth0", "remote_addr": "10.0.12.2",
		"attributes": []any{map[string]any{"key": "ospf.state", "value": "init"}}}
	models := make([]any, 0, 2)
	for _, order := range [][]any{{first, second}, {second, first}} {
		data := rewriteFile(t, func(o map[string]any) {
			if o["plane"] == "configured" && o["node"] == "r1" {
				o["neighbors"] = order
			}
		})
		_, _, f := explainOutput(t, data)
		models = append(models, f.Model.Observations())
	}
	if !reflect.DeepEqual(models[0], models[1]) {
		t.Fatal("file order changed the neighbor order of one identity")
	}
}

// A malformed attribute or flag is refused with a reason, never read as an
// empty value.
func TestDecodeRefusesMalformedAttributes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(o map[string]any)
		want   string
	}{
		{"unknown field in an attribute", func(o map[string]any) {
			o["neighbors"].([]any)[0].(map[string]any)["attributes"] = []any{map[string]any{"key": "a", "value": "b", "extra": 1}}
		}, "unknown field"},
		{"attributes as an object", func(o map[string]any) {
			o["neighbors"].([]any)[0].(map[string]any)["attributes"] = map[string]any{"key": "a", "value": "b"}
		}, "invalid topology file"},
		{"numeric value", func(o map[string]any) {
			o["neighbors"].([]any)[0].(map[string]any)["attributes"] = []any{map[string]any{"key": "ospf.area", "value": 0}}
		}, "invalid topology file"},
		{"empty neighbor key", func(o map[string]any) {
			o["neighbors"].([]any)[0].(map[string]any)["attributes"] = []any{map[string]any{"key": "", "value": "0"}}
		}, "neighbor r2 on eth1 has an attribute with an empty key"},
		{"empty interface value", func(o map[string]any) {
			o["interfaces"].([]any)[0].(map[string]any)["attributes"] = []any{map[string]any{"key": "ospf.area", "value": ""}}
		}, `interface "eth1" attribute "ospf.area" has an empty value`},
		{"string for neighbors_complete", func(o map[string]any) {
			o["neighbors_complete"] = "true"
		}, "invalid topology file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := rewriteFile(t, func(o map[string]any) {
				if o["plane"] == "configured" && o["node"] == "r1" {
					c.mutate(o)
				}
			})
			_, err := Decode(data)
			if err == nil {
				t.Fatalf("Decode accepted the file; want an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}
