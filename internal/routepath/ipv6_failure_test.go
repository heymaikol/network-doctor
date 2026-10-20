package routepath

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// v6Of moves an IPv4 address into 2001:db8::/96, keeping its 32 IPv4 bits as the
// low bits. A prefix moves the same way and keeps its length plus 96, so the
// IPv6 twin of a topology differs from the IPv4 original in address family
// alone: every host bit, prefix boundary, and next hop lines up.
func v6Of(a netip.Addr) netip.Addr {
	b := a.As4()
	var out [16]byte
	copy(out[:4], []byte{0x20, 0x01, 0x0d, 0xb8})
	copy(out[12:], b[:])
	return netip.AddrFrom16(out)
}

func v6Prefix(p netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(v6Of(p.Addr()), p.Bits()+96)
}

// twin rewrites the IPv4 topology obs so that every address move accepts becomes
// its IPv6 twin, and every other address stays as it was. Interface addresses,
// route prefixes, next hops, and neighbor addresses all move together, so a
// link is IPv6 on both ends.
func twin(obs []netmodel.Observation, move func(netip.Addr) bool) []netmodel.Observation {
	out := slices.Clone(obs)
	for i := range out {
		o := &out[i]
		o.Interfaces = slices.Clone(o.Interfaces)
		for j := range o.Interfaces {
			addrs := slices.Clone(o.Interfaces[j].Addresses)
			for k, p := range addrs {
				if move(p.Addr()) {
					addrs[k] = v6Prefix(p)
				}
			}
			o.Interfaces[j].Addresses = addrs
		}
		o.Routes = slices.Clone(o.Routes)
		for j := range o.Routes {
			r := &o.Routes[j]
			if move(r.Prefix.Addr()) {
				r.Prefix = v6Prefix(r.Prefix)
			}
			r.NextHops = slices.Clone(r.NextHops)
			for k := range r.NextHops {
				if a := r.NextHops[k].Addr; a.IsValid() && move(a) {
					r.NextHops[k].Addr = v6Of(a)
				}
			}
		}
		o.Neighbors = slices.Clone(o.Neighbors)
		for j := range o.Neighbors {
			if a := o.Neighbors[j].RemoteAddr; a.IsValid() && move(a) {
				o.Neighbors[j].RemoteAddr = v6Of(a)
			}
		}
	}
	return out
}

// twinTunnels moves the remote of each record that move accepts.
func twinTunnels(ts []Tunnel, move func(netip.Addr) bool) []Tunnel {
	out := slices.Clone(ts)
	for i := range out {
		if move(out[i].Remote) {
			out[i].Remote = v6Of(out[i].Remote)
		}
	}
	return out
}

// twinText is the text an IPv4 address of the original takes in the twin.
func twinText(d string, move func(netip.Addr) bool) string {
	if a := netip.MustParseAddr(d); move(a) {
		return v6Of(a).String()
	}
	return d
}

// shape is one walk with its addresses left out: each node, routing domain,
// decision, and the interface each branch left by. Two walks with equal shapes
// reach the same nodes through the same decisions.
func shape(h *Hop) string {
	if h == nil {
		return "-"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s/%s:%s", h.Node, h.VRF, h.Decision.Kind)
	if h.Via != nil {
		fmt.Fprintf(&b, "@%s:%s", h.Via.Interface, h.Via.Outcome)
	}
	if len(h.Next) > 0 {
		b.WriteString("(")
		for i := range h.Next {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(shape(&h.Next[i]))
		}
		b.WriteString(")")
	}
	return b.String()
}

// requireTwin holds the IPv6 twin's simulation to the IPv4 original's. The
// counts, every affected destination's rating and owners, and every walk's
// shape must agree. Only the address text may differ.
func requireTwin(t *testing.T, want, got Simulation, move func(netip.Addr) bool) {
	t.Helper()
	if got.Considered != want.Considered || got.Unchanged != want.Unchanged || got.Truncated != want.Truncated {
		t.Errorf("considered %d unchanged %d truncated %t, want %d %d %t",
			got.Considered, got.Unchanged, got.Truncated, want.Considered, want.Unchanged, want.Truncated)
	}
	byDest := map[string]Affected{}
	for _, a := range got.Affected {
		byDest[a.Destination] = a
	}
	if len(got.Affected) != len(want.Affected) {
		t.Fatalf("%d affected, want %d: %+v", len(got.Affected), len(want.Affected), got.Affected)
	}
	for _, w := range want.Affected {
		d := twinText(w.Destination, move)
		g, ok := byDest[d]
		switch {
		case !ok:
			t.Errorf("%s not affected in the twin, want %s", d, w.Impact)
			continue
		case g.Impact != w.Impact:
			t.Errorf("%s: impact %s, want %s (%s)", d, g.Impact, w.Impact, g.Reason)
		case !slices.Equal(g.Owners, w.Owners):
			t.Errorf("%s: owners %v, want %v", d, g.Owners, w.Owners)
		case shape(g.After) != shape(w.After):
			t.Errorf("%s: walk %s, want %s", d, shape(g.After), shape(w.After))
		}
	}
}

// requireV6 checks that the twin is IPv6 exactly where move says the IPv4
// original was, so a parity pass cannot come from a twin that stayed IPv4. An
// IPv6 destination is read back to the IPv4 address it came from.
func requireV6(t *testing.T, s Simulation, move func(netip.Addr) bool) {
	t.Helper()
	for _, a := range s.Affected {
		d := netip.MustParseAddr(a.Destination)
		orig, moved := d, d.Is6()
		if moved {
			b := d.As16()
			orig = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		}
		if move(orig) != moved {
			t.Errorf("%s: IPv6 %t, but the IPv4 original %s moves %t", d, moved, orig, move(orig))
		}
	}
}

// v6Failure is the failure the IPv6 twin takes: the same node, routing domain,
// interface, and neighbor, with any next hop moved too.
func v6Failure(f Failure, move func(netip.Addr) bool) Failure {
	if a := f.NextHop; a != "" {
		if p := netip.MustParseAddr(a); move(p) {
			f.NextHop = v6Of(p).String()
		}
	}
	return f
}

type twinCase struct {
	name string
	obs  []netmodel.Observation
	src  Start
	fail Failure
}

// TestIPv6TwinRatesLikeIPv4 runs every structural selector on each IPv4 topology
// and on its IPv6 twin, and requires the same ratings, owners, counts, and walks.
func TestIPv6TwinRatesLikeIPv4(t *testing.T) {
	all := func(netip.Addr) bool { return true }
	partialR4 := partial(diamond(), "r4")
	cases := []twinCase{
		{"diamond router", diamond(), fromR1, Failure{Node: "r2"}},
		{"diamond interface", diamond(), fromR1, Failure{Node: "r1", Interface: "eth1"}},
		{"diamond far interface", diamond(), fromR1, Failure{Node: "r4", Interface: "eth1"}},
		{"diamond router behind the fan-in", diamond(), fromR1, Failure{Node: "r3"}},
		{"diamond partial table", partialR4, fromR1, Failure{Node: "r2"}},
		{"diamond next hop", diamond(), fromR1, Failure{Node: "r1", NextHop: "10.0.12.2", Interface: "eth1"}},
		{"diamond next hop, any interface", diamond(), fromR1, Failure{Node: "r1", NextHop: "10.0.12.2"}},
		{"single-homed router", singleHomed(), fromR1, Failure{Node: "r2"}},
		{"single-homed interface", singleHomed(), fromR1, Failure{Node: "r2", Interface: "eth1"}},
		{"single-homed source link", singleHomed(), fromR1, Failure{Node: "r1", Interface: "eth1"}},
		{"single-homed next hop", singleHomed(), fromR1, Failure{Node: "r2", NextHop: "10.0.23.3"}},
		{"ospf adjacency, diamond", ospfDiamond(), fromR1, Failure{Node: "r1", Interface: "eth1", OSPFNeighbor: "r2"}},
		{"ospf adjacency, far end", ospfDiamond(), fromR1, Failure{Node: "r2", Interface: "eth0", OSPFNeighbor: "r1"}},
		{"ospf adjacency, single-homed", ospfSingleHomed(), fromR1, Failure{Node: "r1", Interface: "eth1", OSPFNeighbor: "r2"}},
		{"gateway on a shared LAN", gatewayLAN(), fromR1, Failure{Node: "r1", NextHop: "10.0.1.2", Interface: "eth0"}},
		{"gateway, another routing domain", twoDomains(), Start{Node: "r1", VRF: "red"}, Failure{Node: "r1", VRF: "red", NextHop: "10.0.1.2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := simulateFrom(t, c.obs, c.src, c.fail)
			got := simulateFrom(t, twin(c.obs, all), c.src, v6Failure(c.fail, all))
			requireV6(t, got, all)
			requireTwin(t, want, got, all)
		})
	}
}

// TestIPv6TwinKeepsItsBounds holds the bounds to the same numbers: a chain
// long enough to pass the destination cap and the walk depth truncates alike.
func TestIPv6TwinKeepsItsBounds(t *testing.T) {
	all := func(netip.Addr) bool { return true }
	f := chain(t, 200)
	want, err := Simulate(f, Failure{Node: "r100"})
	if err != nil {
		t.Fatal(err)
	}
	if !want.Truncated {
		t.Fatal("the IPv4 chain is not truncated, so the bounds are not exercised")
	}
	f.Model = mustModel(t, twin(f.Model.Observations(), all))
	got, err := Simulate(f, v6Failure(Failure{Node: "r100"}, all))
	if err != nil {
		t.Fatal(err)
	}
	requireTwin(t, want, got, all)
}

// TestIPv6TwinIsAddressFamilyOnly checks that the twin keeps every prefix length
// of the original, plus 96, and that an address maps to the same host bits.
func TestIPv6TwinIsAddressFamilyOnly(t *testing.T) {
	for _, p := range []string{"10.0.12.1/30", "10.20.0.0/16", "10.20.40.0/24", "10.0.12.2/32"} {
		got := v6Prefix(pfx(p))
		if !got.Addr().Is6() || got.Bits() != pfx(p).Bits()+96 {
			t.Errorf("%s moved to %s", p, got)
		}
	}
	if got := v6Of(addr("10.0.12.1")).String(); got != "2001:db8::a00:c01" {
		t.Errorf("v6Of(10.0.12.1) = %s", got)
	}
}

// mustModel builds the model of obs, failing the test on a bad observation.
func mustModel(t *testing.T, obs []netmodel.Observation) netmodel.Model {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	return m
}

// TestMixedFamilyTunnelsRateLikeTheIPv4Tunnel moves the tunnel's underlay, its
// overlay, or both to IPv6, and requires the overlay's ratings to be those of
// the all-IPv4 tunnel. Address family alone must never decide a rating.
func TestMixedFamilyTunnelsRateLikeTheIPv4Tunnel(t *testing.T) {
	underlay := func(a netip.Addr) bool { return netip.MustParsePrefix("10.0.0.0/16").Contains(a) }
	overlay := func(a netip.Addr) bool { return !underlay(a) }
	all := func(netip.Addr) bool { return true }
	fails := []Failure{
		{Node: "r5"}, {Node: "r2"}, {Node: "r2", Interface: "eth1"}, {Node: "r5", Interface: "eth0"},
		{Node: "r1", Interface: "wg0"}, {Node: "r5", Interface: "wg0"}, {Node: "r3"}, {Node: "r1", Interface: "eth0"},
	}
	modes := []struct {
		name  string
		obs   []netmodel.Observation
		move  func(netip.Addr) bool
		recs  []Tunnel
		fails []Failure
	}{
		{"IPv6 underlay, IPv4 overlay", tunnelTopology(), underlay, nil, fails},
		{"IPv4 underlay, IPv6 overlay", tunnelTopology(), overlay, nil, fails},
		{"IPv6 underlay and overlay", tunnelTopology(), all, nil, fails},
		{"IPv6 underlay, partial underlay table", partial(tunnelTopology(), "r2"), underlay, nil, fails},
		{"IPv6 underlay, BGP-origin underlay", underlayBy("r2", netmodel.OriginBGP), underlay, nil, fails},
	}
	for _, m := range modes {
		for _, fail := range m.fails {
			t.Run(m.name+" "+fail.String(), func(t *testing.T) {
				want := simulateTunnels(t, m.obs, []Tunnel{r1wg0}, fromR1, fail)
				got := simulateTunnels(t, twin(m.obs, m.move), twinTunnels([]Tunnel{r1wg0}, m.move), fromR1, v6Failure(fail, m.move))
				requireV6(t, got, m.move)
				requireTwin(t, want, got, m.move)
				checkTunnelReasonsAgree(t, got)
			})
		}
	}
}

// partial marks node's recorded tables partial, so no absence in them proves
// anything.
func partial(obs []netmodel.Observation, node string) []netmodel.Observation {
	obs = slices.Clone(obs)
	for i := range obs {
		if obs[i].Node == node {
			obs[i].RoutesComplete = false
		}
	}
	return obs
}

// checkTunnelReasonsAgree requires the text and the JSON output to carry every
// rating reason the simulation holds, so the tunnel record's provenance reaches
// both renderings unchanged.
func checkTunnelReasonsAgree(t *testing.T, s Simulation) {
	t.Helper()
	text := s.Text()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Simulation
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	for i, a := range s.Affected {
		if !strings.Contains(text, a.Reason) {
			t.Errorf("text omits the reason for %s", a.Destination)
		}
		if back.Affected[i].Reason != a.Reason {
			t.Errorf("JSON reason for %s = %q, want %q", a.Destination, back.Affected[i].Reason, a.Reason)
		}
	}
}
