package netmodel

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Minute)
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

func obs(source string, at time.Time, plane Plane, node, vrf string, complete bool, routes ...Route) Observation {
	return Observation{
		Provenance:     Provenance{Source: source, CollectedAt: at},
		Plane:          plane,
		Node:           node,
		VRF:            vrf,
		RoutesComplete: complete,
		Routes:         routes,
	}
}

// ctl is a control-plane observation of r1 in the default VRF.
func ctl(source string, complete bool, routes ...Route) Observation {
	return obs(source, t0, PlaneControl, "r1", "default", complete, routes...)
}

func route(prefix, origin string, hops ...NextHop) Route {
	return Route{Prefix: pfx(prefix), Origin: origin, NextHops: hops}
}

func hop(addr, iface string) NextHop { return NextHop{Addr: ip(addr), Interface: iface} }

func TestLookupStates(t *testing.T) {
	const prefix = "10.1.0.0/16"
	nh := func(addr string) NextHop { return hop(addr, "eth0") }
	known := func(metric uint32, origin string, hops ...NextHop) Route {
		return Route{Prefix: pfx(prefix), Origin: origin, Metric: metric, MetricKnown: true, NextHops: hops}
	}
	cases := []struct {
		name string
		obs  []Observation
		want State
		rows int
	}{
		{"empty model is unknown", nil, Unknown, 0},
		{
			"partial observation without the prefix is unknown",
			[]Observation{ctl("frr", false, route("10.9.0.0/16", OriginStatic, nh("10.0.0.2")))},
			Unknown, 0,
		},
		{"complete observation without the prefix is absent", []Observation{ctl("frr", true)}, Absent, 0},
		{
			"one route is present",
			[]Observation{ctl("frr", true, route(prefix, OriginOSPF, nh("10.0.0.2")))},
			Present, 1,
		},
		{
			"route beside complete absence is conflicting",
			[]Observation{
				ctl("frr", true, route(prefix, OriginOSPF, nh("10.0.0.2"))),
				ctl("cisco", true),
			},
			Conflicting, 1,
		},
		{
			"same origin with different next hops is conflicting",
			[]Observation{
				ctl("frr", false, route(prefix, OriginOSPF, nh("10.0.0.2"))),
				ctl("cisco", false, route(prefix, OriginOSPF, nh("10.0.0.3"))),
			},
			Conflicting, 2,
		},
		{
			"same origin with different known metrics is conflicting",
			[]Observation{
				ctl("frr", false, known(10, OriginOSPF, nh("10.0.0.2"))),
				ctl("cisco", false, known(20, OriginOSPF, nh("10.0.0.2"))),
			},
			Conflicting, 2,
		},
		{
			"an unknown metric never contradicts a known one",
			[]Observation{
				ctl("frr", false, known(0, OriginOSPF, nh("10.0.0.2"))),
				ctl("cisco", false, route(prefix, OriginOSPF, nh("10.0.0.2"))),
			},
			Present, 2,
		},
		{
			"a discard beside a forwarding route is conflicting",
			[]Observation{
				ctl("frr", false, Route{Prefix: pfx(prefix), Origin: OriginStatic, Discard: true}),
				ctl("cisco", false, route(prefix, OriginStatic, nh("10.0.0.2"))),
			},
			Conflicting, 2,
		},
		{
			"a route with no reported next hops never contradicts one that has them",
			[]Observation{
				ctl("frr", false, route(prefix, OriginStatic)),
				ctl("cisco", false, route(prefix, OriginStatic, nh("10.0.0.2"))),
			},
			Present, 2,
		},
		{
			"same origin differing only in attributes is present",
			[]Observation{
				ctl("frr", false, Route{Prefix: pfx(prefix), Origin: OriginBGP, NextHops: []NextHop{nh("10.0.0.2")}, Attributes: []Attribute{{Key: "bgp.as_path", Value: "65001"}}}),
				ctl("cisco", false, Route{Prefix: pfx(prefix), Origin: OriginBGP, NextHops: []NextHop{nh("10.0.0.2")}, Attributes: []Attribute{{Key: "bgp.as_path", Value: "65002"}}}),
			},
			Present, 2,
		},
		{
			"same origin with identical routes is corroborated",
			[]Observation{
				ctl("frr", false, route(prefix, OriginOSPF, nh("10.0.0.2"))),
				ctl("cisco", false, route(prefix, OriginOSPF, nh("10.0.0.2"))),
			},
			Present, 2,
		},
		{
			"different origins are candidates, not conflict",
			[]Observation{
				ctl("frr", false, route(prefix, OriginOSPF, nh("10.0.0.2"))),
				ctl("bird", false, route(prefix, OriginBGP, nh("10.0.0.3"))),
			},
			Present, 2,
		},
		{
			"a next hop with no reported interface matches the same gateway",
			[]Observation{
				ctl("frr", false, route(prefix, OriginOSPF, hop("10.0.0.2", ""))),
				ctl("cisco", false, route(prefix, OriginOSPF, hop("10.0.0.2", "eth0"))),
			},
			Present, 2,
		},
		{
			"same gateway on different reported interfaces is conflicting",
			[]Observation{
				ctl("frr", false, route(prefix, OriginOSPF, hop("10.0.0.2", "eth0"))),
				ctl("cisco", false, route(prefix, OriginOSPF, hop("10.0.0.2", "eth1"))),
			},
			Conflicting, 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := New(c.obs...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got := m.Lookup("r1", "default", PlaneControl, pfx(prefix))
			if got.State != c.want || len(got.Evidence) != c.rows {
				t.Fatalf("Lookup = %s with %d rows, want %s with %d rows", got.State, len(got.Evidence), c.want, c.rows)
			}
		})
	}
}

func TestAbsenceNamesItsSource(t *testing.T) {
	cisco := ctl("cisco", true)
	m, err := New(ctl("frr", true, route("10.1.0.0/16", OriginOSPF, hop("10.0.0.2", "eth0"))), cisco)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("10.1.0.0/16"))
	if got.State != Conflicting || len(got.AbsentIn) != 1 || got.AbsentIn[0].Source != "cisco" {
		t.Fatalf("Lookup = %+v, want conflicting with cisco named as the absent source", got)
	}
	absent := ctl("cisco", true)
	m, err = New(absent)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.Lookup("r1", "default", PlaneControl, pfx("10.1.0.0/16")); got.State != Absent || got.AbsentIn[0].Source != "cisco" {
		t.Fatalf("Lookup = %+v, want absent proven by cisco", got)
	}
}

func TestOneObservationKeepsEveryOrigin(t *testing.T) {
	m, err := New(ctl("collector", true,
		route("10.2.0.0/16", OriginOSPF, hop("10.0.0.2", "eth0")),
		route("10.2.0.0/16", OriginBGP, hop("10.0.0.3", "eth1")),
	))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
	if got.State != Present || len(got.Evidence) != 2 {
		t.Fatalf("Lookup = %s with %d rows, want present with both origins", got.State, len(got.Evidence))
	}
}

func TestECMPKeepsEveryNextHopInCanonicalOrder(t *testing.T) {
	m, err := New(ctl("frr", true, route("10.2.0.0/16", OriginOSPF,
		hop("10.0.2.2", "eth2"),
		hop("10.0.1.2", "eth1"),
	)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
	want := []NextHop{hop("10.0.1.2", "eth1"), hop("10.0.2.2", "eth2")}
	if got.State != Present || len(got.Evidence) != 1 || !reflect.DeepEqual(got.Evidence[0].Route.NextHops, want) {
		t.Fatalf("Lookup = %+v, want one present row with next hops %v", got, want)
	}
}

func TestVRFsDoNotCollide(t *testing.T) {
	red := obs("frr", t0, PlaneControl, "r1", "red", true, route("10.1.0.0/16", OriginStatic, hop("10.0.0.1", "red0")))
	blue := obs("frr", t0, PlaneControl, "r1", "blue", true, route("10.1.0.0/16", OriginStatic, hop("10.0.0.9", "blue0")))
	m, err := New(red, blue)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := pfx("10.1.0.0/16")
	for vrf, iface := range map[string]string{"red": "red0", "blue": "blue0"} {
		got := m.Lookup("r1", vrf, PlaneControl, p)
		if got.State != Present || len(got.Evidence) != 1 || got.Evidence[0].Route.NextHops[0].Interface != iface {
			t.Errorf("VRF %s: Lookup = %+v, want present via %s", vrf, got, iface)
		}
	}
	if got := m.Lookup("r1", "default", PlaneControl, p); got.State != Unknown {
		t.Errorf("default VRF: Lookup = %s, want unknown", got.State)
	}
	if got := m.Lookup("r1", "", PlaneControl, p); got.State != Unknown {
		t.Errorf("empty VRF: Lookup = %s, want unknown", got.State)
	}
	if _, err := New(obs("frr", t0, PlaneControl, "r1", "", true)); err == nil {
		t.Error("New accepted an empty VRF; it must name the domain")
	}
}

func TestPlanesStayIndependent(t *testing.T) {
	intended := obs("policy", t0, PlaneIntended, "r1", "default", true, route("10.1.0.0/16", OriginStatic, hop("10.0.0.2", "eth0")))
	fib := obs("kernel", t0, PlaneFIB, "r1", "default", true, route("10.1.0.0/16", OriginStatic, hop("10.0.0.3", "eth1")))
	m, err := New(intended, fib)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for plane, iface := range map[Plane]string{PlaneIntended: "eth0", PlaneFIB: "eth1"} {
		got := m.Lookup("r1", "default", plane, pfx("10.1.0.0/16"))
		if got.State != Present || len(got.Evidence) != 1 || got.Evidence[0].Route.NextHops[0].Interface != iface {
			t.Errorf("plane %s: Lookup = %+v, want present via %s", plane, got, iface)
		}
	}
}

func TestSmallRoutedTopologyWithTwoDomains(t *testing.T) {
	m, err := New(
		Observation{
			Provenance:     Provenance{Source: "linux-ip", CollectedAt: t0},
			Plane:          PlaneConfigured,
			Node:           "r1",
			VRF:            "default",
			RoutesComplete: false,
			Interfaces:     []Interface{{Name: "eth0", VLANKnown: true, VLAN: 100, Addresses: []netip.Prefix{pfx("10.0.0.1/24")}}},
			Neighbors:      []Neighbor{{LocalInterface: "eth0", RemoteNode: "r2", RemoteInterface: "eth0", RemoteAddr: ip("10.0.0.2")}},
		},
		ctl("frr-ospf", true, route("10.2.0.0/16", OriginOSPF, hop("10.0.0.2", "eth0"))),
		obs("frr-static", t0, PlaneControl, "r1", "red", true, route("10.2.0.0/16", OriginStatic, hop("10.9.0.2", "eth1"))),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p := pfx("10.2.0.0/16")
	if got := m.Lookup("r1", "default", PlaneControl, p); got.State != Present || got.Evidence[0].Route.Origin != OriginOSPF {
		t.Errorf("default domain: Lookup = %+v, want ospf route", got)
	}
	if got := m.Lookup("r1", "red", PlaneControl, p); got.State != Present || got.Evidence[0].Route.Origin != OriginStatic {
		t.Errorf("red domain: Lookup = %+v, want static route", got)
	}
	if got := m.Lookup("r1", "default", PlaneFIB, p); got.State != Unknown {
		t.Errorf("FIB plane: Lookup = %s, want unknown; planes must not leak", got.State)
	}
	// r2 appears only as r1's neighbor. Nothing reports r2, so nothing about it
	// is absent: every answer for r2 is unknown.
	if got := m.Lookup("r2", "default", PlaneControl, p); got.State != Unknown {
		t.Errorf("incomplete topology: Lookup on r2 = %s, want unknown", got.State)
	}
	var found bool
	for _, o := range m.Observations() {
		if o.Plane == PlaneConfigured {
			found = true
			if o.Interfaces[0].VLAN != 100 || o.Interfaces[0].Addresses[0] != pfx("10.0.0.1/24") || o.Neighbors[0].RemoteNode != "r2" {
				t.Errorf("configured observation lost interface or neighbor data: %+v", o)
			}
		}
	}
	if !found {
		t.Error("configured observation missing from model")
	}
}

// ospfRoute and bgpRoute stand in for what each protocol collector reports.
// Each adapter below is the only code that knows its protocol's field names.
type ospfRoute struct{ prefix, nexthop, iface, area string }
type bgpRoute struct{ prefix, nexthop, iface, asPath string }

func fromOSPF(source string, r ospfRoute) Observation {
	return ctl(source, true, Route{
		Prefix:     pfx(r.prefix),
		Origin:     OriginOSPF,
		NextHops:   []NextHop{hop(r.nexthop, r.iface)},
		Attributes: []Attribute{{Key: "ospf.area", Value: r.area}},
	})
}

func fromBGP(source string, r bgpRoute) Observation {
	return ctl(source, true, Route{
		Prefix:     pfx(r.prefix),
		Origin:     OriginBGP,
		NextHops:   []NextHop{hop(r.nexthop, r.iface)},
		Attributes: []Attribute{{Key: "bgp.as_path", Value: r.asPath}},
	})
}

func TestOSPFAndBGPPopulateOneSchema(t *testing.T) {
	m, err := New(
		fromOSPF("ospf-lsdb:r1", ospfRoute{"10.2.0.0/16", "10.0.0.2", "eth0", "0.0.0.0"}),
		fromBGP("bgp-rib:r1", bgpRoute{"10.2.0.0/16", "10.0.0.3", "eth1", "65001 65002"}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
	if got.State != Present || len(got.Evidence) != 2 {
		t.Fatalf("Lookup = %s with %d rows, want present with 2 candidates", got.State, len(got.Evidence))
	}
	seen := map[string]Attribute{}
	for _, e := range got.Evidence {
		seen[e.Route.Origin] = e.Route.Attributes[0]
		if e.Source == "" || e.CollectedAt.IsZero() {
			t.Errorf("evidence lost provenance: %+v", e)
		}
	}
	if seen[OriginOSPF] != (Attribute{Key: "ospf.area", Value: "0.0.0.0"}) || seen[OriginBGP] != (Attribute{Key: "bgp.as_path", Value: "65001 65002"}) {
		t.Errorf("protocol attributes not kept under namespaced keys: %+v", seen)
	}
}

func TestConflictKeepsEveryProvenance(t *testing.T) {
	a := obs("frr", t0, PlaneControl, "r1", "default", false, route("10.1.0.0/16", OriginOSPF, hop("10.0.0.2", "eth0")))
	b := obs("cisco", t1, PlaneControl, "r1", "default", false, route("10.1.0.0/16", OriginOSPF, hop("10.0.0.3", "eth0")))
	m, err := New(a, b)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("10.1.0.0/16"))
	if got.State != Conflicting || len(got.Evidence) != 2 {
		t.Fatalf("Lookup = %s with %d rows, want conflicting with 2 rows", got.State, len(got.Evidence))
	}
	// Rows come back in canonical order, so match them by source, not position.
	for _, want := range []Provenance{a.Provenance, b.Provenance} {
		var found bool
		for _, e := range got.Evidence {
			found = found || (e.Source == want.Source && e.CollectedAt.Equal(want.CollectedAt))
		}
		if !found {
			t.Errorf("no evidence row keeps provenance %+v; rows = %+v", want, got.Evidence)
		}
	}
}

// rich is one observation with every list populated, reversed when asked, so
// tests can show the model does not depend on the order inside an observation.
func rich(reverse bool) Observation {
	o := Observation{
		Provenance: Provenance{Source: "linux-ip", CollectedAt: t0},
		Plane:      PlaneControl,
		Node:       "r1",
		VRF:        "default",
		Interfaces: []Interface{
			{Name: "eth0", VLANKnown: true, VLAN: 10, Addresses: []netip.Prefix{pfx("10.0.0.1/24"), pfx("10.0.1.1/24")}},
			{Name: "eth1", Addresses: []netip.Prefix{pfx("10.0.2.1/24")}},
		},
		Neighbors: []Neighbor{
			{LocalInterface: "eth0", RemoteNode: "r2", RemoteInterface: "eth0", RemoteAddr: ip("10.0.0.2")},
			{LocalInterface: "eth1", RemoteNode: "r3", RemoteInterface: "eth0", RemoteAddr: ip("10.0.2.3")},
		},
		Routes: []Route{
			{Prefix: pfx("10.2.0.0/16"), Origin: OriginOSPF, NextHops: []NextHop{hop("10.0.0.2", "eth0"), hop("10.0.2.3", "eth1")},
				Attributes: []Attribute{{Key: "ospf.area", Value: "0"}, {Key: "ospf.route_type", Value: "intra"}}},
			{Prefix: pfx("10.3.0.0/16"), Origin: OriginBGP, NextHops: []NextHop{hop("10.0.2.3", "eth1")}},
		},
	}
	if reverse {
		// rich builds fresh slices on every call, so reversing in place is safe.
		slices.Reverse(o.Interfaces)
		for i := range o.Interfaces {
			slices.Reverse(o.Interfaces[i].Addresses)
		}
		slices.Reverse(o.Neighbors)
		slices.Reverse(o.Routes)
		for i := range o.Routes {
			slices.Reverse(o.Routes[i].NextHops)
			slices.Reverse(o.Routes[i].Attributes)
		}
	}
	return o
}

func TestDeterministicRegardlessOfInputOrder(t *testing.T) {
	inputs := []Observation{
		fromOSPF("ospf-lsdb:r1", ospfRoute{"10.2.0.0/16", "10.0.0.2", "eth0", "0.0.0.0"}),
		fromBGP("bgp-rib:r1", bgpRoute{"10.2.0.0/16", "10.0.0.3", "eth1", "65001"}),
		ctl("frr", true),
	}
	orders := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	var first Model
	var firstAnswer Answer
	for i, order := range orders {
		in := make([]Observation, 0, len(order))
		for _, j := range order {
			in = append(in, inputs[j])
		}
		m, err := New(in...)
		if err != nil {
			t.Fatalf("New(%v): %v", order, err)
		}
		answer := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
		if i == 0 {
			first, firstAnswer = m, answer
			continue
		}
		if !reflect.DeepEqual(m, first) || !reflect.DeepEqual(answer, firstAnswer) {
			t.Fatalf("order %v differs from order %v", order, orders[0])
		}
	}

	forward, err := New(rich(false))
	if err != nil {
		t.Fatalf("New(rich): %v", err)
	}
	backward, err := New(rich(true))
	if err != nil {
		t.Fatalf("New(reversed rich): %v", err)
	}
	if !reflect.DeepEqual(forward, backward) {
		t.Fatalf("reversing lists inside one observation changed the model:\n%+v\n%+v", forward.Observations(), backward.Observations())
	}
}

func TestInputAndOutputDoNotAlias(t *testing.T) {
	in := rich(false)
	m, err := New(in)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	in.Interfaces[0].Addresses[0] = pfx("192.0.2.1/32")
	in.Neighbors[0].RemoteNode = "changed"
	in.Routes[0].NextHops[0].Interface = "changed"
	in.Routes[0].Attributes[0].Value = "changed"

	got := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
	got.Evidence[0].Route.NextHops[0].Interface = "changed"
	got.Evidence[0].Route.Attributes[0].Value = "changed"
	view := m.Observations()
	view[0].Interfaces[0].Addresses[0] = pfx("192.0.2.2/32")
	view[0].Neighbors[0].RemoteNode = "changed"
	view[0].Routes[0].NextHops[0].Interface = "changed"

	again := m.Lookup("r1", "default", PlaneControl, pfx("10.2.0.0/16"))
	if again.Evidence[0].Route.NextHops[0].Interface != "eth0" || again.Evidence[0].Route.Attributes[0].Value != "0" {
		t.Fatalf("model changed through lookup output: %+v", again.Evidence[0].Route)
	}
	if fresh := m.Observations(); fresh[0].Interfaces[0].Addresses[0] != pfx("10.0.0.1/24") ||
		fresh[0].Neighbors[0].RemoteNode != "r2" || fresh[0].Routes[0].NextHops[0].Interface != "eth0" {
		t.Fatalf("model changed through Observations output: %+v", fresh[0])
	}
}

func TestNextHopAddressesAreCanonical(t *testing.T) {
	m, err := New(
		ctl("frr", true,
			route("10.1.0.0/16", OriginStatic, NextHop{Addr: ip("::ffff:10.0.0.1")}),
			route("10.3.0.0/16", OriginBGP, hop("2001:db8::1", "eth0")),
			route("10.4.0.0/16", OriginBGP, hop("fe80::1%eth0", "")),
			route("10.5.0.0/16", OriginBGP, hop("fe80::1", "eth0"), hop("fe80::1", "eth0")),
		),
		ctl("cisco", false,
			route("10.5.0.0/16", OriginBGP, hop("fe80::1", "eth0")),
		),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	mapped := m.Lookup("r1", "default", PlaneControl, pfx("10.1.0.0/16")).Evidence[0].Route.NextHops[0].Addr
	if mapped != ip("10.0.0.1") || !mapped.Is4() {
		t.Errorf("IPv4-mapped next hop = %v, want 10.0.0.1", mapped)
	}
	if got := m.Lookup("r1", "default", PlaneControl, pfx("10.3.0.0/16")); got.State != Present {
		t.Errorf("IPv4 prefix via IPv6 next hop = %s, want present (RFC 8950)", got.State)
	}
	zoned := m.Lookup("r1", "default", PlaneControl, pfx("10.4.0.0/16")).Evidence[0].Route.NextHops[0]
	if zoned != hop("fe80::1", "eth0") {
		t.Errorf("zoned next hop = %+v, want fe80::1 on eth0", zoned)
	}
	if got := m.Lookup("r1", "default", PlaneControl, pfx("10.5.0.0/16")); got.State != Present || len(got.Evidence[0].Route.NextHops) != 1 {
		t.Errorf("duplicate next hop = %+v, want one next hop and present", got)
	}
}

func TestDiscardRouteIsPresentWithoutNextHops(t *testing.T) {
	m, err := New(ctl("frr", true, Route{Prefix: pfx("192.0.2.0/24"), Origin: OriginStatic, Discard: true}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.Lookup("r1", "default", PlaneControl, pfx("192.0.2.0/24"))
	if got.State != Present || !got.Evidence[0].Route.Discard || len(got.Evidence[0].Route.NextHops) != 0 {
		t.Fatalf("Lookup = %+v, want present discard route", got)
	}
}

func TestVLANKnownAndUnknownStayDistinct(t *testing.T) {
	o := Observation{
		Provenance: Provenance{Source: "linux-ip", CollectedAt: t0},
		Plane:      PlaneConfigured,
		Node:       "r1",
		VRF:        "default",
		Interfaces: []Interface{
			{Name: "eth0", VLANKnown: true, VLAN: 0},
			{Name: "eth1", VLANKnown: false, VLAN: 0},
			{Name: "eth2", VLANKnown: true, VLAN: 4094},
		},
	}
	m, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ifs := m.Observations()[0].Interfaces
	if !ifs[0].VLANKnown || ifs[0].VLAN != 0 || ifs[1].VLANKnown || ifs[2].VLAN != 4094 {
		t.Fatalf("VLAN states collapsed: %+v", ifs)
	}
}

func TestNeighborZoneNamesTheObserversLink(t *testing.T) {
	m, err := New(Observation{
		Provenance: Provenance{Source: "linux-ip", CollectedAt: t0},
		Plane:      PlaneConfigured,
		Node:       "r1",
		VRF:        "default",
		Neighbors:  []Neighbor{{LocalInterface: "eth0", RemoteNode: "r2", RemoteAddr: ip("fe80::2%eth0")}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	n := m.Observations()[0].Neighbors[0]
	if n.RemoteAddr != ip("fe80::2") || n.RemoteInterface != "" {
		t.Fatalf("neighbor = %+v, want fe80::2 with no invented remote interface", n)
	}
}

func TestRejectsInvalidObservations(t *testing.T) {
	valid := func() Observation {
		return Observation{
			Provenance: Provenance{Source: "frr", CollectedAt: t0},
			Plane:      PlaneControl,
			Node:       "r1",
			VRF:        "default",
			Interfaces: []Interface{{Name: "eth0"}},
			Neighbors:  []Neighbor{{LocalInterface: "eth0", RemoteNode: "r2"}},
			Routes: []Route{{
				Prefix:     pfx("10.1.0.0/16"),
				Origin:     OriginStatic,
				NextHops:   []NextHop{hop("10.0.0.2", "eth0")},
				Attributes: []Attribute{{Key: "static.tag", Value: "7"}},
			}},
		}
	}
	cases := map[string]func(*Observation){
		"no source":             func(o *Observation) { o.Source = "" },
		"zero collection time":  func(o *Observation) { o.CollectedAt = time.Time{} },
		"unknown plane":         func(o *Observation) { o.Plane = "bogus" },
		"empty node":            func(o *Observation) { o.Node = "" },
		"empty VRF":             func(o *Observation) { o.VRF = "" },
		"empty interface name":  func(o *Observation) { o.Interfaces[0].Name = "" },
		"duplicate interface":   func(o *Observation) { o.Interfaces = append(o.Interfaces, Interface{Name: "eth0"}) },
		"VLAN above 4094":       func(o *Observation) { o.Interfaces[0].VLANKnown, o.Interfaces[0].VLAN = true, 4095 },
		"neighbor without node": func(o *Observation) { o.Neighbors[0].RemoteNode = "" },
		"neighbor zone conflict": func(o *Observation) {
			o.Neighbors[0].LocalInterface, o.Neighbors[0].RemoteAddr = "eth0", ip("fe80::2%eth1")
		},
		"unmasked route prefix":    func(o *Observation) { o.Routes[0].Prefix = pfx("10.1.0.1/16") },
		"empty origin":             func(o *Observation) { o.Routes[0].Origin = "" },
		"duplicate route origin":   func(o *Observation) { o.Routes = append(o.Routes, o.Routes[0]) },
		"discard with next hop":    func(o *Observation) { o.Routes[0].Discard = true },
		"next hop with no target":  func(o *Observation) { o.Routes[0].NextHops = []NextHop{{}} },
		"next hop zone conflict":   func(o *Observation) { o.Routes[0].NextHops = []NextHop{hop("fe80::1%eth1", "eth0")} },
		"link-local without iface": func(o *Observation) { o.Routes[0].NextHops = []NextHop{{Addr: ip("fe80::1")}} },
		"empty attribute key":      func(o *Observation) { o.Routes[0].Attributes[0].Key = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := valid()
			mutate(&o)
			if _, err := New(o); err == nil {
				t.Fatal("New accepted an invalid observation")
			}
		})
	}
	if _, err := New(valid()); err != nil {
		t.Fatalf("New rejected a valid observation: %v", err)
	}
}
