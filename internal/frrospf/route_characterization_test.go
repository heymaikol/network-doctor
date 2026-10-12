package frrospf

import (
	"reflect"
	"testing"
)

// The tests in this file pin how the calculated route table and the LSDB
// capture are read today. They run on the recorded lab output and pass before
// any hop-level change, so a later change that moves one of these behaviors
// shows up here.

// routeTable returns the steady r1 route table with edit applied to the object
// of one prefix.
func routeTable(t *testing.T, prefix string, edit func(route map[string]any)) []byte {
	t.Helper()
	return mutateJSON(t, lsdbCapture(t, "steady", "r1", "E").Data, func(top map[string]any) {
		edit(top[prefix].(map[string]any))
	})
}

// renameKey moves the value of old to new, so the object holds only new.
func renameKey(m map[string]any, old, new string) {
	m[new] = m[old]
	delete(m, old)
}

// The route table refuses each of these shapes, and each refusal names the
// route. The refusals are part of the contract the hop change keeps.
func TestCharacterizeRouteTableRefusals(t *testing.T) {
	steady := lsdbCapture(t, "steady", "r1", "E").Data
	cases := map[string][]byte{
		// C1: a routeType outside the prefix route types.
		"D IA route type": routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["routeType"] = "D IA" }),
		// C5: an unknown routeType.
		"unknown route type": routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["routeType"] = "N E9" }),
		// C3: nexthops missing, null, an object, or a string.
		"nexthops missing": routeTable(t, "10.10.2.0/24", func(r map[string]any) { delete(r, "nexthops") }),
		"nexthops null":    routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = nil }),
		"nexthops object":  routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = map[string]any{} }),
		"nexthops string":  routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = "10.0.1.2" }),
		// C4: cost and type2cost must be unsigned integers.
		"cost string":      routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["cost"] = "20" }),
		"cost negative":    routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["cost"] = -1 }),
		"cost fractional":  routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["cost"] = 1.5 }),
		"type2cost string": routeTable(t, "10.20.0.0/24", func(r map[string]any) { r["type2cost"] = "20" }),
		// C6: a case variant of a decoded key is refused, not read.
		"RouteType key": routeTable(t, "10.10.2.0/24", func(r map[string]any) { renameKey(r, "routeType", "RouteType") }),
		"Cost key":      routeTable(t, "10.10.2.0/24", func(r map[string]any) { renameKey(r, "cost", "Cost") }),
		"NextHops key":  routeTable(t, "10.10.2.0/24", func(r map[string]any) { renameKey(r, "nexthops", "NextHops") }),
		"Type2Cost key": routeTable(t, "10.20.0.0/24", func(r map[string]any) { renameKey(r, "type2cost", "Type2Cost") }),
		"NEXTHOPS key":  routeTable(t, "10.10.2.0/24", func(r map[string]any) { renameKey(r, "nexthops", "NEXTHOPS") }),
		// C7: a repeated key, in the route object or in a hop element.
		"duplicate cost key": replaceOnce(t, steady,
			`"10.10.2.0/24":{"routeType":"N","transit":false,"cost":20,`,
			`"10.10.2.0/24":{"routeType":"N","transit":false,"cost":20,"cost":20,`),
		"duplicate hop key": replaceOnce(t, steady,
			`"10.10.2.0/24":{"routeType":"N","transit":false,"cost":20,"area":"0.0.0.0","nexthops":[{"ip":"10.0.1.2","via":"e1",`,
			`"10.10.2.0/24":{"routeType":"N","transit":false,"cost":20,"area":"0.0.0.0","nexthops":[{"ip":"10.0.1.2","via":"e1","via":"e1",`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, reason := decodeRoutes(raw); reason == "" {
				t.Fatal("accepted; want a refusal")
			}
		})
	}
}

// The steady route table is read without refusal and keeps its prefix routes.
func TestCharacterizeRouteTableIsAccepted(t *testing.T) {
	rt, reason := decodeRoutes(lsdbCapture(t, "steady", "r1", "E").Data)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if len(rt.Entries) != 4 || rt.Routers != 1 || !rt.Known {
		t.Fatalf("entries %d, routers %d, known %v; want 4, 1, true", len(rt.Entries), rt.Routers, rt.Known)
	}
}

// C2: the empty object is the unknown table, not an empty one.
func TestCharacterizeEmptyObjectIsUnknown(t *testing.T) {
	rt, reason := decodeRoutes([]byte("{}\n"))
	if reason != "" || rt.Known {
		t.Fatalf("reason %q, known %v; want no refusal and unknown", reason, rt.Known)
	}
}

// C10 and C11: a hop element of any JSON shape is accepted and counted, and an
// empty array is zero hops. The count is the raw element count.
func TestCharacterizeHopElementsAreCountedNotRead(t *testing.T) {
	cases := map[string]struct {
		hops []any
		want int
	}{
		"empty array":        {[]any{}, 0},
		"non-object hops":    {[]any{float64(5), "x", nil, []any{}}, 4},
		"wrong-type fields":  {[]any{map[string]any{"ip": float64(10), "via": nil, "advertisedRouter": true}}, 1},
		"duplicate elements": {[]any{map[string]any{"ip": "10.0.1.2"}, map[string]any{"ip": "10.0.1.2"}}, 2},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["nexthops"] = c.hops })
			rt, reason := decodeRoutes(raw)
			if reason != "" {
				t.Fatalf("refused: %s", reason)
			}
			for _, r := range rt.Entries {
				if r.Prefix.String() == "10.10.2.0/24" {
					if r.NextHops != c.want {
						t.Fatalf("next hops %d; want %d", r.NextHops, c.want)
					}
					return
				}
			}
			t.Fatal("10.10.2.0/24 missing from entries")
		})
	}
}

// C12: a router entry is counted, and its own fields are not read. Its cost and
// nexthops can hold any value.
func TestCharacterizeRouterEntryIsCountOnly(t *testing.T) {
	raw := mutateJSON(t, lsdbCapture(t, "steady", "r1", "E").Data, func(top map[string]any) {
		top["2.2.2.2"] = map[string]any{"routeType": "R ", "cost": "not a number", "nexthops": []any{float64(5)}}
	})
	rt, reason := decodeRoutes(raw)
	if reason != "" {
		t.Fatalf("refused: %s", reason)
	}
	if rt.Routers != 1 || len(rt.Entries) != 4 {
		t.Fatalf("routers %d, entries %d; want 1 and 4", rt.Routers, len(rt.Entries))
	}
}

// C9: a case variant of a hop key is accepted wherever it appears outside a
// decoded key position, and it changes no decoded value. The neighbor, interface,
// LSDB, and route objects each take one variant.
func TestCharacterizeFoldedHopKeysAreAcceptedAndIgnored(t *testing.T) {
	t.Run("neighbor", func(t *testing.T) {
		c := fixture(t, "bcast", "r1", CommandNeighborDetail)
		base, reason := decodeNeighborDetail(c.Data)
		if reason != "" {
			t.Fatal(reason)
		}
		raw := mutateJSON(t, c.Data, func(top map[string]any) {
			for _, recs := range top["neighbors"].(map[string]any) {
				recs.([]any)[0].(map[string]any)["VIA"] = "e2"
			}
		})
		got, reason := decodeNeighborDetail(raw)
		if reason != "" {
			t.Fatalf("refused: %s", reason)
		}
		if !reflect.DeepEqual(base, got) {
			t.Fatal("a folded hop key changed the neighbor records")
		}
	})
	t.Run("interface", func(t *testing.T) {
		c := fixture(t, "bcast", "r1", CommandInterface)
		base, reason := decodeInterfaces(c.Data)
		if reason != "" {
			t.Fatal(reason)
		}
		raw := mutateJSON(t, c.Data, func(top map[string]any) {
			top["interfaces"].(map[string]any)["e1"].(map[string]any)["DirectlyAttachedTo"] = "e1"
		})
		got, reason := decodeInterfaces(raw)
		if reason != "" {
			t.Fatalf("refused: %s", reason)
		}
		if !reflect.DeepEqual(base, got) {
			t.Fatal("a folded hop key changed the interface records")
		}
	})
	t.Run("LSDB", func(t *testing.T) {
		c := lsdbCapture(t, "steady", "r1", "B")
		base, reason := decodeLSDB(c.Data)
		if reason != "" {
			t.Fatal(reason)
		}
		// The variant sits inside a router LSA. A key at the top of the LSDB is
		// unknown content and is recorded as such, so it is not a case here.
		raw := mutateJSON(t, c.Data, func(top map[string]any) {
			area := top["routerLinkStates"].(map[string]any)["areas"].(map[string]any)["0.0.0.0"]
			area.([]any)[0].(map[string]any)["AdvertisedRouter"] = "2.2.2.2"
		})
		got, reason := decodeLSDB(raw)
		if reason != "" {
			t.Fatalf("refused: %s", reason)
		}
		if !reflect.DeepEqual(base, got) {
			t.Fatal("a folded hop key changed the LSDB")
		}
	})
	t.Run("route", func(t *testing.T) {
		base, reason := decodeRoutes(lsdbCapture(t, "steady", "r1", "E").Data)
		if reason != "" {
			t.Fatal(reason)
		}
		raw := routeTable(t, "10.10.2.0/24", func(r map[string]any) { r["Via"] = "e1" })
		got, reason := decodeRoutes(raw)
		if reason != "" {
			t.Fatalf("refused: %s", reason)
		}
		if !reflect.DeepEqual(base, got) {
			t.Fatal("a folded hop key changed the route table")
		}
	})
}

// C16: the interface facts of PR 6 are read as before. The broadcast r1 e1
// interface keeps its address, cost, network type, and state.
func TestCharacterizeInterfaceFactsUnchanged(t *testing.T) {
	c := fixture(t, "bcast", "r1", CommandInterface)
	raw, reason := decodeInterfaces(c.Data)
	if reason != "" {
		t.Fatal(reason)
	}
	e1, ok := raw["e1"]
	if !ok {
		t.Fatal("no e1 record")
	}
	if e1.IPAddress == nil || *e1.IPAddress != "10.0.1.1" {
		t.Fatalf("ipAddress = %v; want 10.0.1.1", e1.IPAddress)
	}
	if string(e1.Cost) != "10" || string(e1.NetworkType) != `"BROADCAST"` || string(e1.State) != `"Backup"` {
		t.Fatalf("cost %s, networkType %s, state %s; want 10, BROADCAST, Backup", e1.Cost, e1.NetworkType, e1.State)
	}
}
