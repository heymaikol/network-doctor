package frrospf

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The tests in this file read the route report as JSON. They marshal the decoded
// table and check the keys of one route object, so they compile on the base
// before the route model gains fields. On base each one fails with a missing
// key, which is the capability gap.

// routeEntry decodes a route table and returns the JSON object of one prefix.
func routeEntry(t *testing.T, raw []byte, prefix string) map[string]any {
	t.Helper()
	rt, reason := decodeRoutes(raw)
	if reason != "" {
		t.Fatalf("table refused: %s", reason)
	}
	data, err := json.Marshal(rt.Entries)
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e["prefix"] == prefix {
			return e
		}
	}
	t.Fatalf("no route %s in the table", prefix)
	return nil
}

// expect checks one JSON key of a route object. A missing key fails as a missing
// key, and a different value fails with both encodings.
func expect(t *testing.T, r map[string]any, key string, want any) {
	t.Helper()
	got, ok := r[key]
	if !ok {
		t.Fatalf("missing key %s", key)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("%s = %s, want %s", key, gotJSON, wantJSON)
	}
}

// addrHop is one address hop element as FRR prints it.
func addrHop(ip, via, adv string) map[string]any {
	return map[string]any{"ip": ip, "via": via, "advertisedRouter": adv}
}

// directHop is one direct hop element as FRR prints it.
func directHop(name string) map[string]any {
	return map[string]any{"ip": " ", "directlyAttachedTo": name}
}

// hopJSON is one expected forwarding_hops entry.
func hopJSON(addr, iface string, advs ...string) map[string]any {
	return map[string]any{"address": addr, "interface": iface, "advertised_by": advs}
}

// synthRoute returns the route object of 10.10.2.0/24 in the steady table after
// its nexthops array is replaced. The table is genuine except for that array.
func synthRoute(t *testing.T, hops []any) map[string]any {
	t.Helper()
	raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = hops })
	return routeEntry(t, raw, "10.10.2.0/24")
}

// committedRoute returns the route object of one prefix in a committed capture.
func committedRoute(t *testing.T, c Capture, prefix string) map[string]any {
	t.Helper()
	return routeEntry(t, c.Data, prefix)
}

// F1 to F5: committed captures from the cost-50, LSDB, and steady scenarios.
func TestRouteHopsCommittedCaptures(t *testing.T) {
	t.Run("F1 cost50 r1 10.10.2.0/24 address hop", func(t *testing.T) {
		r := committedRoute(t, fixture(t, "cost50", "r1", CommandRoute), "10.10.2.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "2.2.2.2")})
	})
	t.Run("F2 cost50 r1 10.0.1.0/24 direct hop", func(t *testing.T) {
		r := committedRoute(t, fixture(t, "cost50", "r1", CommandRoute), "10.0.1.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
		expect(t, r, "direct_interfaces", []any{"e1"})
	})
	t.Run("F3 cost50 r2 10.10.1.0/24 address hop", func(t *testing.T) {
		r := committedRoute(t, fixture(t, "cost50", "r2", CommandRoute), "10.10.1.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.1", "e2", "1.1.1.1")})
	})
	t.Run("F4 steady r1 10.20.0.0/24 N E2", func(t *testing.T) {
		r := committedRoute(t, lsdbCapture(t, "steady", "r1", "E"), "10.20.0.0/24")
		expect(t, r, "type2_cost", 20)
		expect(t, r, "cost", 10)
		expect(t, r, "metric_status", "representable")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
	})
	t.Run("F5 steady r1 10.10.2.0/24 same route as F1", func(t *testing.T) {
		r := committedRoute(t, lsdbCapture(t, "steady", "r1", "E"), "10.10.2.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
	})
}

// F29 to F31: the committed ECMP bracket. These are added beyond the F1 to F28
// list, because ECMP is the claim this PR makes and it needs a real capture.
func TestRouteHopsECMPCapture(t *testing.T) {
	t.Run("F29 r1 10.10.2.0/24 has two hops and no e5 path", func(t *testing.T) {
		r := committedRoute(t, ecmpCapture(t, "r1", "E"), "10.10.2.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 2)
		expect(t, r, "forwarding_hops", []any{
			hopJSON("10.0.1.2", "e1", "2.2.2.2"),
			hopJSON("10.0.3.2", "e3", "2.2.2.2"),
		})
		expect(t, r, "direct_interfaces", []any{})
	})
	t.Run("F30 r2 10.10.1.0/24 has three hops", func(t *testing.T) {
		r := committedRoute(t, ecmpCapture(t, "r2", "E"), "10.10.1.0/24")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 3)
		expect(t, r, "forwarding_hops", []any{
			hopJSON("10.0.1.1", "e2", "1.1.1.1"),
			hopJSON("10.0.3.1", "e4", "1.1.1.1"),
			hopJSON("10.0.5.1", "e6", "1.1.1.1"),
		})
	})
	t.Run("F31 r1 10.0.5.0/24 is reached through r2, not the direct cost-50 link", func(t *testing.T) {
		r := committedRoute(t, ecmpCapture(t, "r1", "E"), "10.0.5.0/24")
		expect(t, r, "cost", 20)
		expect(t, r, "forwarding_hop_count", 2)
		expect(t, r, "direct_interfaces", []any{})
	})
}

// F6 to F23, F25 to F28: synthetic routes built from the steady table.
func TestRouteHopsSynthetic(t *testing.T) {
	t.Run("F6 same hop, two advertisers, not ECMP", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("10.0.1.2", "e1", "1.1.1.1"), addrHop("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "1.1.1.1", "2.2.2.2")})
		expect(t, r, "next_hops", 2)
	})
	t.Run("F7 two identical address elements are ambiguous", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("10.0.1.2", "e1", "2.2.2.2"), addrHop("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "next_hop_status", "ambiguous")
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "2.2.2.2")})
	})
	t.Run("F8 two identical direct elements are ambiguous", func(t *testing.T) {
		r := synthRoute(t, []any{directHop("e1"), directHop("e1")})
		expect(t, r, "next_hop_status", "ambiguous")
		expect(t, r, "direct_interfaces", []any{"e1"})
	})
	t.Run("F9 an empty object is incomplete", func(t *testing.T) {
		r := synthRoute(t, []any{map[string]any{}})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "next_hops", 1)
	})
	t.Run("F10 empty nexthops is explicitly empty", func(t *testing.T) {
		r := synthRoute(t, []any{})
		expect(t, r, "next_hop_status", "explicitly_empty")
		expect(t, r, "forwarding_hop_count", 0)
		expect(t, r, "forwarding_hops", []any{})
		expect(t, r, "direct_interfaces", []any{})
	})
	t.Run("F11 one valid hop and one empty object lists the valid hop only", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("10.0.1.2", "e1", "2.2.2.2"), map[string]any{}})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "2.2.2.2")})
	})
	t.Run("F12 address hop missing advertisedRouter is incomplete", func(t *testing.T) {
		r := synthRoute(t, []any{map[string]any{"ip": "10.0.1.2", "via": "e1"}})
		expect(t, r, "next_hop_status", "incomplete")
	})
	t.Run("F13 empty interface name is incomplete", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("10.0.1.2", "", "2.2.2.2")})
		expect(t, r, "next_hop_status", "incomplete")
		r = synthRoute(t, []any{map[string]any{"ip": " ", "directlyAttachedTo": ""}})
		expect(t, r, "next_hop_status", "incomplete")
	})
	t.Run("F14 ip of dash is incomplete, and a space ip without a name is incomplete", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("-", "e1", "2.2.2.2")})
		expect(t, r, "next_hop_status", "incomplete")
		r = synthRoute(t, []any{map[string]any{"ip": " "}})
		expect(t, r, "next_hop_status", "incomplete")
	})
	t.Run("F15 malformed ip values are each incomplete", func(t *testing.T) {
		for _, ip := range []string{"10.0.1", "10.0.1.256", "10.0.1.2/24", "::1", "010.0.1.2", " 10.0.1.2", "0.0.0.0"} {
			r := synthRoute(t, []any{addrHop(ip, "e1", "2.2.2.2")})
			if got, _ := r["next_hop_status"].(string); got != "incomplete" {
				t.Fatalf("ip %q: next_hop_status %v, want incomplete", ip, r["next_hop_status"])
			}
		}
	})
	t.Run("F16 malformed advertisedRouter values are each incomplete", func(t *testing.T) {
		for _, adv := range []string{"2.2.2", "::1", "0.0.0.0"} {
			r := synthRoute(t, []any{addrHop("10.0.1.2", "e1", adv)})
			if got, _ := r["next_hop_status"].(string); got != "incomplete" {
				t.Fatalf("advertisedRouter %q: next_hop_status %v, want incomplete", adv, r["next_hop_status"])
			}
		}
	})
	t.Run("F17 fold variant beside the exact key is ambiguous and not listed", func(t *testing.T) {
		r := synthRoute(t, []any{map[string]any{"ip": "10.0.1.2", "IP": "10.0.1.2", "via": "e1", "advertisedRouter": "2.2.2.2"}})
		expect(t, r, "next_hop_status", "ambiguous")
		expect(t, r, "forwarding_hops", []any{})
		expect(t, r, "next_hops", 1)
	})
	t.Run("F18 fold variant as the only spelling is ambiguous, not listed, not counted", func(t *testing.T) {
		r := synthRoute(t, []any{map[string]any{"IP": "10.0.1.2", "via": "e1", "advertisedRouter": "2.2.2.2"}})
		expect(t, r, "next_hop_status", "ambiguous")
		expect(t, r, "forwarding_hops", []any{})
	})
	t.Run("F19 mixed valid and unknown elements are incomplete, with the valid ones listed", func(t *testing.T) {
		r := synthRoute(t, []any{addrHop("10.0.1.2", "e1", "2.2.2.2"), map[string]any{}, directHop("stub1")})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "direct_interfaces", []any{"stub1"})
	})
	t.Run("F20 N E1 keeps the printed total cost, with no area and no type2_cost", func(t *testing.T) {
		raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) {
			r["routeType"] = "N E1"
			r["cost"] = 30
			delete(r, "area")
		})
		r := routeEntry(t, raw, "10.10.2.0/24")
		expect(t, r, "cost", 30)
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
		if _, ok := r["area"]; ok {
			t.Fatal("N E1 route carries an area key")
		}
		if _, ok := r["type2_cost"]; ok {
			t.Fatal("N E1 route carries a type2_cost key")
		}
	})
	t.Run("F21 a direct hop and an address hop on e1 are two forwarding hops", func(t *testing.T) {
		r := synthRoute(t, []any{directHop("e1"), addrHop("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 2)
		expect(t, r, "direct_interfaces", []any{"e1"})
	})
	t.Run("F22 cost above MaxUint32 is unrepresentable and the route stays", func(t *testing.T) {
		raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["cost"] = 4294967296 })
		r := routeEntry(t, raw, "10.10.2.0/24")
		expect(t, r, "metric_status", "unrepresentable")
		expect(t, r, "next_hop_status", "complete")
		expect(t, r, "forwarding_hop_count", 1)
	})
	t.Run("F23 type2cost above MaxUint32 on N E2 is unrepresentable", func(t *testing.T) {
		raw := routeTable(t, "10.20.0.0/24", func(r map[string]any) { r["type2cost"] = 4294967296 })
		r := routeEntry(t, raw, "10.20.0.0/24")
		expect(t, r, "metric_status", "unrepresentable")
		expect(t, r, "next_hop_status", "complete")
	})
	t.Run("F25 non-object elements are unidentified and counted", func(t *testing.T) {
		r := synthRoute(t, []any{float64(5), "x", nil, []any{}, addrHop("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "forwarding_hops", []any{hopJSON("10.0.1.2", "e1", "2.2.2.2")})
		expect(t, r, "next_hops", 5)
	})
	t.Run("F26 wrong-typed fields are unidentified and counted", func(t *testing.T) {
		r := synthRoute(t, []any{
			map[string]any{"ip": float64(10), "via": "e1", "advertisedRouter": "2.2.2.2"},
			map[string]any{"ip": "10.0.1.2", "via": nil, "advertisedRouter": "2.2.2.2"},
			map[string]any{"ip": "10.0.1.2", "via": "e1", "advertisedRouter": true},
		})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "forwarding_hops", []any{})
		expect(t, r, "next_hops", 3)
	})
	t.Run("F27 missing ip or missing via is unidentified and counted", func(t *testing.T) {
		r := synthRoute(t, []any{
			map[string]any{"via": "e1", "advertisedRouter": "2.2.2.2"},
			map[string]any{"ip": "10.0.1.2", "advertisedRouter": "2.2.2.2"},
		})
		expect(t, r, "next_hop_status", "incomplete")
		expect(t, r, "forwarding_hops", []any{})
		expect(t, r, "next_hops", 2)
	})
	t.Run("F28 Unicode fold of advertisedRouter is ambiguous, not listed, not counted", func(t *testing.T) {
		r := synthRoute(t, []any{map[string]any{"ip": "10.0.1.2", "via": "e1", "adverti\u017fedRouter": "2.2.2.2"}})
		expect(t, r, "next_hop_status", "ambiguous")
		expect(t, r, "forwarding_hops", []any{})
		expect(t, r, "next_hops", 1)
	})
}

// Interface names from a hop element are text from the router. A name with a
// space, a control rune, a format rune, a bidi override, or invalid UTF-8 is not
// an identity. The hop is unidentified, and the table is still accepted.
func TestRouteHopsUnusableInterfaceNames(t *testing.T) {
	cases := map[string]any{
		"bidi override in via":    addrHop("10.0.1.2", "e1\u202e", "2.2.2.2"),
		"zero-width space in via": addrHop("10.0.1.2", "e1\u200b", "2.2.2.2"),
		"no-break space in via":   addrHop("10.0.1.2", "e\u00a01", "2.2.2.2"),
		"tab in via":              addrHop("10.0.1.2", "e\t1", "2.2.2.2"),
		"bell in via":             addrHop("10.0.1.2", "e\u00071", "2.2.2.2"),
		"invalid UTF-8 in via":    addrHop("10.0.1.2", "e\xff1", "2.2.2.2"),
		"bidi override in direct": directHop("stub1\u202e"),
		"zero-width in direct":    directHop("stub1\u200b"),
	}
	for name, hop := range cases {
		t.Run(name, func(t *testing.T) {
			r := synthRoute(t, []any{hop, addrHop("10.0.9.9", "e9", "9.9.9.9")})
			expect(t, r, "next_hop_status", "incomplete")
			expect(t, r, "forwarding_hops", []any{hopJSON("10.0.9.9", "e9", "9.9.9.9")})
			expect(t, r, "direct_interfaces", []any{})
			expect(t, r, "next_hops", 2)
		})
	}
}

// F24: every ordering of one five-element set gives the same route JSON. The set
// has two hops that share (ip, via) with different advertisers, one direct hop,
// one empty object, and one fold variant. Unit test, not a fuzz invariant.
func TestRouteHopsPermutationInvariance(t *testing.T) {
	set := []any{
		addrHop("10.0.1.2", "e1", "1.1.1.1"),
		addrHop("10.0.1.2", "e1", "2.2.2.2"),
		directHop("stub1"),
		map[string]any{},
		map[string]any{"IP": "10.0.3.2", "via": "e3", "advertisedRouter": "2.2.2.2"},
	}
	var first []byte
	var perms int
	var permute func(k int)
	permute = func(k int) {
		if k == len(set) {
			perms++
			hops := append([]any(nil), set...)
			raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = hops })
			r := routeEntry(t, raw, "10.10.2.0/24")
			if _, ok := r["next_hop_status"]; !ok {
				t.Fatal("missing key next_hop_status")
			}
			got, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if first == nil {
				first = got
			} else if !bytes.Equal(first, got) {
				t.Fatalf("ordering %d changed the route JSON:\n%s\nwant\n%s", perms, got, first)
			}
			return
		}
		for i := k; i < len(set); i++ {
			set[k], set[i] = set[i], set[k]
			permute(k + 1)
			set[k], set[i] = set[i], set[k]
		}
	}
	permute(0)
	if perms != 120 {
		t.Fatalf("checked %d orderings, want 120", perms)
	}
}
