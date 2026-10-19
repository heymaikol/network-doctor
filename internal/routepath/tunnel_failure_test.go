package routepath

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// The overlay destinations: r5's LAN, which r1 reaches only over wg0, and r5's
// end of the tunnel subnet.
const (
	overlayDest = "10.50.0.1"
	tunnelPeer  = "172.16.0.2"
)

// tunnelTopology is r1 with three egresses in its default domain: eth0 to r2,
// eth2 to r3, and wg0, a tunnel whose far end is r5. r1 reaches r5's
// underlay endpoint 10.0.25.1 only through r2. r2 also holds 10.60.0.1, a
// physical route from r1 over the same egress, and r3 holds 10.70.0.1, an
// unrelated route on the same node and domain. r1 in domain blue reaches
// 10.80.0.1 on r4.
func tunnelTopology() []netmodel.Observation {
	return []netmodel.Observation{
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.12.1/30"), ifc("eth2", "10.0.13.1/30"), ifc("wg0", "172.16.0.1/30")}),
		configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.14.1/30")}),
		configured("r2", "default", []netmodel.Interface{ifc("eth0", "10.0.12.2/30"), ifc("eth1", "10.0.25.2/30"), ifc("lan2", "10.60.0.1/24")}),
		configured("r3", "default", []netmodel.Interface{ifc("eth0", "10.0.13.2/30"), ifc("lan", "10.70.0.1/24")}),
		configured("r4", "blue", []netmodel.Interface{ifc("eth0", "10.0.14.2/30"), ifc("lan", "10.80.0.1/24")}),
		configured("r5", "default", []netmodel.Interface{ifc("eth0", "10.0.25.1/30"), ifc("wg0", "172.16.0.2/30"), ifc("lan", "10.50.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.12.0/30", "kernel", onLink("eth0")),
			route("10.0.13.0/30", "kernel", onLink("eth2")),
			route("172.16.0.0/30", "kernel", onLink("wg0")),
			route("10.0.25.0/30", "static", nh("10.0.12.2", "eth0")),
			route("10.60.0.0/24", "static", nh("10.0.12.2", "eth0")),
			route("10.70.0.0/24", "static", nh("10.0.13.2", "eth2")),
			route("10.50.0.0/24", "static", nh("172.16.0.2", "wg0"))),
		table(netmodel.PlaneFIB, "r1", "blue", true,
			route("10.0.14.0/30", "kernel", onLink("eth3")),
			route("10.80.0.0/24", "static", nh("10.0.14.2", "eth3"))),
		table(netmodel.PlaneFIB, "r2", "default", true,
			route("10.0.12.0/30", "kernel", onLink("eth0")),
			route("10.0.25.0/30", "kernel", onLink("eth1")),
			route("10.60.0.0/24", "kernel", onLink("lan2"))),
		table(netmodel.PlaneFIB, "r3", "default", true,
			route("10.0.13.0/30", "kernel", onLink("eth0")),
			route("10.70.0.0/24", "kernel", onLink("lan"))),
		table(netmodel.PlaneFIB, "r4", "blue", true, route("10.80.0.0/24", "kernel", onLink("lan"))),
		table(netmodel.PlaneFIB, "r5", "default", true,
			route("10.0.25.0/30", "kernel", onLink("eth0")),
			route("172.16.0.0/30", "kernel", onLink("wg0")),
			route("10.50.0.0/24", "kernel", onLink("lan"))),
	}
}

func tunnelRecord(node, vrf, iface, remote, underlay string) Tunnel {
	return Tunnel{
		Provenance:  netmodel.Provenance{Source: "tunnels:" + node, CollectedAt: t0},
		Node:        node,
		VRF:         vrf,
		Interface:   iface,
		Remote:      addr(remote),
		UnderlayVRF: underlay,
	}
}

// r1wg0 is the record that ties r1's wg0 to r5's underlay endpoint.
var r1wg0 = tunnelRecord("r1", "default", "wg0", "10.0.25.1", "default")

// The file goes through Encode, which decodes what it writes, so every record a
// test simulates passes the decoder's checks.
func simulateTunnels(t *testing.T, obs []netmodel.Observation, tunnels []Tunnel, src Start, fail Failure) Simulation {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatalf("netmodel.New: %v", err)
	}
	data, err := Encode(File{Source: src, Model: m, Tunnels: tunnels})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	f, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	s, err := Simulate(f, fail)
	if err != nil {
		t.Fatalf("Simulate(%+v): %v", fail, err)
	}
	return s
}

// withOverlay is the ratings of the same failure without tunnel records, with
// the overlay destinations overridden, so a test asserts that nothing else moves.
func withOverlay(t *testing.T, obs []netmodel.Observation, src Start, fail Failure, overlay map[string]Impact) map[string]Impact {
	t.Helper()
	want := impacts(simulateTunnels(t, obs, nil, src, fail))
	maps.Copy(want, overlay)
	for d, i := range want {
		if i == ImpactNone {
			delete(want, d)
		}
	}
	return want
}

// leafOf returns the first leaf below h that left r1 by iface.
func leafOf(h *Hop, iface string) *Hop {
	var out *Hop
	walkHops(h, func(x *Hop) {
		if out == nil && x.Via != nil && x.Via.From == "r1" && x.Via.Interface == iface && x.Node == "" {
			out = x
		}
	})
	return out
}

// The pinned F2 baseline: with no tunnel record, nothing ties wg0 to an
// underlay, so the walk treats it as a wire and an underlay failure leaves the
// overlay unchanged. Files without tunnels keep this.
func TestWithoutTunnelRecordsTheOverlayReadsAsAWire(t *testing.T) {
	for _, fail := range []Failure{{Node: "r2"}, {Node: "r2", Interface: "eth1"}, {Node: "r1", Interface: "eth0"}} {
		got := impacts(simulateTunnels(t, tunnelTopology(), nil, fromR1, fail))
		for _, d := range []string{overlayDest, tunnelPeer} {
			if i, ok := got[d]; ok {
				t.Errorf("%s: %s = %s, want none: no record ties wg0 to an underlay", fail, d, i)
			}
		}
		if got["10.0.25.1"] != ImpactReachabilityLost {
			t.Errorf("%s: underlay endpoint = %s, want reachability_lost", fail, got["10.0.25.1"])
		}
	}
}

func TestUnderlayFailureLeavesTheOverlayUnknown(t *testing.T) {
	for _, fail := range []Failure{{Node: "r2"}, {Node: "r2", Interface: "eth1"}, {Node: "r1", Interface: "eth0"}} {
		s := simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, fail)
		want := withOverlay(t, tunnelTopology(), fromR1, fail, map[string]Impact{overlayDest: ImpactUnknown, tunnelPeer: ImpactUnknown})
		if got := impacts(s); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: impacts = %v, want %v", fail, got, want)
			continue
		}
		leaf := leafOf(affected(t, s, overlayDest).After, "wg0")
		if leaf == nil || leaf.Decision.Kind != KindUnknown {
			t.Fatalf("%s: wg0 leaf = %+v, want an unknown leaf in place of the walk past the tunnel", fail, leaf)
		}
		if !strings.Contains(leaf.Decision.Reason, "10.0.25.1") || !strings.Contains(leaf.Decision.Reason, "meets the failure") {
			t.Errorf("%s: reason = %q, want it to name the remote and the underlay meeting the failure", fail, leaf.Decision.Reason)
		}
		if ev := leaf.Decision.Evidence; len(ev) != 1 || ev[0].Source != "tunnels:r1" {
			t.Errorf("%s: evidence = %+v, want the tunnel record's source", fail, ev)
		}
	}
}

// An underlay loss alone never makes the overlay lost, even where the
// underlay is certainly cut and only static routes are involved.
func TestUnderlayFailureNeverClaimsAnOverlayLoss(t *testing.T) {
	s := simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, Failure{Node: "r1", Interface: "eth0"})
	for _, a := range s.Affected {
		if (a.Destination == overlayDest || a.Destination == tunnelPeer) && a.Impact == ImpactReachabilityLost {
			t.Errorf("%s = reachability_lost from the underlay alone", a.Destination)
		}
	}
}

// A tunnel interface going down is a link failure, and the record does not
// soften it.
func TestTunnelInterfaceDownIsStillALoss(t *testing.T) {
	for _, fail := range []Failure{{Node: "r1", Interface: "wg0"}, {Node: "r5", Interface: "wg0"}} {
		got := impacts(simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, fail))
		want := withOverlay(t, tunnelTopology(), fromR1, fail, nil)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: impacts = %v, want %v", fail, got, want)
		}
		if got[overlayDest] != ImpactReachabilityLost {
			t.Errorf("%s: overlay = %s, want reachability_lost", fail, got[overlayDest])
		}
	}
}

func TestFailureOffTheUnderlayLeavesTheOverlayUnchanged(t *testing.T) {
	fail := Failure{Node: "r3"}
	got := impacts(simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, fail))
	if want := withOverlay(t, tunnelTopology(), fromR1, fail, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("impacts = %v, want %v", got, want)
	}
	if _, ok := got[overlayDest]; ok {
		t.Errorf("overlay = %s, want none: the underlay does not cross r3", got[overlayDest])
	}
}

// A record names one routing domain. The same interface name in another
// domain is another interface, and a walk in another domain never rides it.
func TestTunnelRecordStaysInItsRoutingDomain(t *testing.T) {
	fail := Failure{Node: "r2"}
	obs := append(without(tunnelTopology(), "config:r1:blue"),
		configured("r1", "blue", []netmodel.Interface{ifc("eth3", "10.0.14.1/30"), {Name: "wg0"}}))
	blue := tunnelRecord("r1", "blue", "wg0", "10.0.25.1", "default")
	got := impacts(simulateTunnels(t, obs, []Tunnel{blue}, fromR1, fail))
	if want := withOverlay(t, obs, fromR1, fail, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("record in blue: impacts = %v, want %v", got, want)
	}
	fromBlue := Start{Node: "r1", VRF: "blue"}
	got = impacts(simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromBlue, fail))
	if want := withOverlay(t, tunnelTopology(), fromBlue, fail, nil); !reflect.DeepEqual(got, want) {
		t.Errorf("walk from blue: impacts = %v, want %v", got, want)
	}
}

func TestUnprovenUnderlayIsUnknown(t *testing.T) {
	partial := without(tunnelTopology(), "fib:r2:default")
	partial = append(partial, table(netmodel.PlaneFIB, "r2", "default", false,
		route("10.0.25.0/30", "kernel", onLink("eth1")),
		route("10.60.0.0/24", "kernel", onLink("lan2"))))
	cases := []struct {
		name    string
		obs     []netmodel.Observation
		tunnel  Tunnel
		because string
	}{
		{"partial underlay FIB", partial, r1wg0, "does not prove delivery"},
		{"remote no node holds", tunnelTopology(), tunnelRecord("r1", "default", "wg0", "10.0.25.9", "default"), "does not prove delivery"},
		{"underlay domain with no table", tunnelTopology(), tunnelRecord("r1", "default", "wg0", "10.0.25.1", "transit"), "does not prove delivery"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// r3 is not on the underlay, so only the unproven underlay can
			// make the overlay unknown.
			s := simulateTunnels(t, c.obs, []Tunnel{c.tunnel}, fromR1, Failure{Node: "r3"})
			a := affected(t, s, overlayDest)
			if a.Impact != ImpactUnknown {
				t.Fatalf("overlay = %s, want unknown", a.Impact)
			}
			if leaf := leafOf(a.After, "wg0"); leaf == nil || !strings.Contains(leaf.Decision.Reason, c.because) {
				t.Errorf("wg0 leaf = %+v, want a reason saying it %s", leaf, c.because)
			}
			if got := impacts(s)["10.70.0.1"]; got != ImpactReachabilityLost {
				t.Errorf("unrelated route = %s, want reachability_lost as without the record", got)
			}
		})
	}
}

// An underlay that rides the tunnel itself is recursive. It is unknown, and
// the check ends instead of following the tunnel again.
func TestUnderlayThroughTheTunnelIsUnknown(t *testing.T) {
	looped := without(tunnelTopology(), "fib:r1:default")
	looped = append(looped, table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.0.12.0/30", "kernel", onLink("eth0")),
		route("10.0.13.0/30", "kernel", onLink("eth2")),
		route("172.16.0.0/30", "kernel", onLink("wg0")),
		route("10.0.25.0/30", "static", nh("172.16.0.2", "wg0")),
		route("10.70.0.0/24", "static", nh("10.0.13.2", "eth2")),
		route("10.50.0.0/24", "static", nh("172.16.0.2", "wg0"))))
	for name, c := range map[string]struct {
		obs    []netmodel.Observation
		tunnel Tunnel
	}{
		"underlay route over the tunnel": {looped, r1wg0},
		"remote is the overlay peer":     {tunnelTopology(), tunnelRecord("r1", "default", "wg0", "172.16.0.2", "default")},
	} {
		t.Run(name, func(t *testing.T) {
			s := simulateTunnels(t, c.obs, []Tunnel{c.tunnel}, fromR1, Failure{Node: "r3"})
			a := affected(t, s, overlayDest)
			leaf := leafOf(a.After, "wg0")
			if a.Impact != ImpactUnknown || leaf == nil || !strings.Contains(leaf.Decision.Reason, "rides a tunnel") {
				t.Fatalf("overlay = %s, wg0 leaf = %+v, want unknown because the underlay rides a tunnel", a.Impact, leaf)
			}
			if s.Truncated {
				t.Error("simulation truncated; the recursive underlay should end at once, not exhaust a bound")
			}
		})
	}
}

// A record names one remote. Overlay traffic over the same interface to a
// node that does not hold that remote contradicts it, as a multipoint
// interface would, so that destination is unknown rather than rated by the
// one remote. A destination behind the recorded peer keeps its rating.
func TestMultipointTunnelIsNotReadAsOneRemote(t *testing.T) {
	obs := without(tunnelTopology(), "config:r1:default", "fib:r1:default")
	obs = append(obs,
		configured("r1", "default", []netmodel.Interface{ifc("eth0", "10.0.12.1/30"), ifc("eth2", "10.0.13.1/30"), ifc("wg0", "172.16.0.1/29")}),
		configured("r6", "default", []netmodel.Interface{ifc("wg0", "172.16.0.3/29"), ifc("lan", "10.66.0.1/24")}),
		table(netmodel.PlaneFIB, "r1", "default", true,
			route("10.0.12.0/30", "kernel", onLink("eth0")),
			route("10.0.13.0/30", "kernel", onLink("eth2")),
			route("10.0.25.0/30", "static", nh("10.0.12.2", "eth0")),
			route("10.70.0.0/24", "static", nh("10.0.13.2", "eth2")),
			route("10.50.0.0/24", "static", nh("172.16.0.2", "wg0")),
			route("10.66.0.0/24", "static", nh("172.16.0.3", "wg0"))),
		table(netmodel.PlaneFIB, "r6", "default", true, route("10.66.0.0/24", "kernel", onLink("lan"))))
	s := simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"})
	a := affected(t, s, "10.66.0.1")
	if leaf := leafOf(a.After, "wg0"); a.Impact != ImpactUnknown || leaf == nil || !strings.Contains(leaf.Decision.Reason, "one remote") {
		t.Fatalf("10.66.0.1 = %s, wg0 leaf = %+v, want unknown because the record names one remote", a.Impact, leaf)
	}
	if got := impacts(s)[overlayDest]; got != "" {
		t.Errorf("overlay to the recorded peer = %s, want none", got)
	}
}

// A next hop that names no interface may leave by the tunnel. It is unknown
// when the tunnel's underlay meets the failure, unless it goes to a node other
// than the one holding the remote, which a single-remote tunnel cannot reach.
func TestNextHopWithNoInterfaceMayRideTheTunnel(t *testing.T) {
	obs := without(tunnelTopology(), "fib:r1:default")
	obs = append(obs, table(netmodel.PlaneFIB, "r1", "default", true,
		route("10.0.12.0/30", "kernel", onLink("eth0")),
		route("10.0.13.0/30", "kernel", onLink("eth2")),
		route("172.16.0.0/30", "kernel", onLink("wg0")),
		route("10.0.25.0/30", "static", nh("10.0.12.2", "eth0")),
		route("10.70.0.0/24", "static", nh("10.0.13.2", "")),
		route("10.50.0.0/24", "static", nh("172.16.0.2", ""))))
	fail := Failure{Node: "r2"}
	got := impacts(simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, fail))
	want := withOverlay(t, obs, fromR1, fail, map[string]Impact{overlayDest: ImpactUnknown, tunnelPeer: ImpactUnknown})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("impacts = %v, want %v", got, want)
	}
}

// A record that names an interface its node and routing domain do not record
// matches no segment, so the overlay over the real wg0 would read none under an
// underlay failure. The decoder refuses it instead.
func TestUnmatchedTunnelRecordIsRefused(t *testing.T) {
	m, err := netmodel.New(tunnelTopology()...)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tunnel Tunnel
		want   string
	}{
		{tunnelRecord("r1", "default", "wgo", "10.0.25.1", "default"), `r1 (default) lists no interface "wgo"`},
		{tunnelRecord("r1", "blue", "wg0", "10.0.25.1", "default"), `r1 (blue) lists no interface "wg0"`},
		{tunnelRecord("r2", "default", "wg0", "10.0.25.1", "default"), `r2 (default) lists no interface "wg0"`},
		{tunnelRecord("r9", "default", "wg0", "10.0.25.1", "default"), "no configured, control, or fib observation describes r9 (default)"},
	} {
		_, err := Encode(File{Source: fromR1, Model: m, Tunnels: []Tunnel{c.tunnel}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("record %s (%s) %s: error = %v, want it to say %q", c.tunnel.Node, c.tunnel.VRF, c.tunnel.Interface, err, c.want)
		}
	}
}

func TestTunnelReasonReachesTheText(t *testing.T) {
	txt := simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, Failure{Node: "r2"}).Text()
	for _, want := range []string{"unknown " + overlayDest, "tunnel r1 (default) wg0", "evidence tunnels:r1"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text lacks %q:\n%s", want, txt)
		}
	}
}

// editFIB returns obs with edit applied to the routes of node's FIB table in
// vrf. It copies what it edits, so the caller's observations are unchanged.
func editFIB(obs []netmodel.Observation, node, vrf string, edit func([]netmodel.Route) []netmodel.Route) []netmodel.Observation {
	out := slices.Clone(obs)
	for i := range out {
		if out[i].Source == "fib:"+node+":"+vrf {
			out[i].Routes = edit(slices.Clone(out[i].Routes))
		}
	}
	return out
}

// underlayBy is the tunnel topology with node's row for r5's underlay endpoint,
// 10.0.25.1, set to origin. No other row changes.
func underlayBy(node, origin string) []netmodel.Observation {
	return editFIB(tunnelTopology(), node, "default", func(rs []netmodel.Route) []netmodel.Route {
		for i := range rs {
			if rs[i].Prefix == pfx("10.0.25.0/30") {
				rs[i].Origin = origin
			}
		}
		return rs
	})
}

func addFIB(obs []netmodel.Observation, node, vrf string, r netmodel.Route) []netmodel.Observation {
	return editFIB(obs, node, vrf, func(rs []netmodel.Route) []netmodel.Route { return append(rs, r) })
}

// A recorded underlay that forwards by a BGP route is a control-plane
// dependency that the file does not record, so an unrelated router failure
// cannot leave the overlay none.
func TestBGPUnderlayIsUnknown(t *testing.T) {
	for _, c := range []struct {
		name, node string
		unchanged  int
	}{{"selected at the source", "r1", 8}, {"selected further along", "r2", 9}} {
		t.Run(c.name, func(t *testing.T) {
			obs := underlayBy(c.node, netmodel.OriginBGP)
			fail := Failure{Node: "r3"}
			s := simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, fail)
			want := withOverlay(t, obs, fromR1, fail, map[string]Impact{overlayDest: ImpactUnknown, tunnelPeer: ImpactUnknown})
			if got := impacts(s); !reflect.DeepEqual(got, want) {
				t.Fatalf("impacts = %v, want %v", got, want)
			}
			if s.Considered != 14 || s.Unchanged != c.unchanged || s.Truncated {
				t.Errorf("considered %d, unchanged %d, truncated %t, want 14, %d, false", s.Considered, s.Unchanged, s.Truncated, c.unchanged)
			}
			leaf := leafOf(affected(t, s, overlayDest).After, "wg0")
			if leaf == nil || leaf.Decision.Kind != KindUnknown {
				t.Fatalf("wg0 leaf = %+v, want an unknown leaf", leaf)
			}
			reason := "the underlay of tunnel r1 (default) wg0, from r1 (default) to remote 10.0.25.1, forwards by BGP route 10.0.25.0/30 at " + c.node + " (default), in fib:" + c.node + ":default (bgp); the file records no BGP session, peer, or next-hop resolution for that route, so whether the failure disrupts it is not in the evidence, and BGP withdrawal is not modeled"
			if leaf.Decision.Reason != reason {
				t.Errorf("reason = %q, want %q", leaf.Decision.Reason, reason)
			}
			if !strings.Contains(s.Text(), reason) {
				t.Errorf("text lacks the reason:\n%s", s.Text())
			}
			if b, err := json.Marshal(s); err != nil || !strings.Contains(string(b), reason) {
				t.Errorf("json lacks the reason: %v\n%s", err, b)
			}
		})
	}
}

// The BGP rule reads an underlay walk that selects a bgp row under a router or
// interface failure. Each other case keeps the rating the same record-free walk
// gives, since the tunnel's only effect is through its underlay.
func TestBGPUnderlayRuleIsConfined(t *testing.T) {
	bgp := netmodel.OriginBGP
	cases := []struct {
		name    string
		obs     []netmodel.Observation
		tunnels []Tunnel
		src     Start
		fail    Failure
	}{
		{"static and connected underlay", tunnelTopology(), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"OSPF underlay", underlayBy("r1", netmodel.OriginOSPF), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"BGP in another routing domain", addFIB(tunnelTopology(), "r1", "blue", route("10.0.25.0/30", bgp, nh("10.0.14.2", "eth3"))), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"BGP on a node off the underlay", addFIB(tunnelTopology(), "r3", "default", route("10.0.25.0/30", bgp, nh("10.0.13.1", "eth0"))), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"BGP for another prefix", addFIB(tunnelTopology(), "r1", "default", route("10.99.0.0/16", bgp, nh("10.0.12.2", "eth0"))), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"BGP shadowed by the underlay's static route", addFIB(tunnelTopology(), "r1", "default", route("10.0.0.0/8", bgp, nh("10.0.12.2", "eth0"))), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"BGP only on the control plane", append(tunnelTopology(), table(netmodel.PlaneControl, "r1", "default", true, route("10.0.25.0/30", bgp, nh("10.0.12.2", "eth0")))), []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"}},
		{"no tunnel record", underlayBy("r1", bgp), nil, fromR1, Failure{Node: "r3"}},
		{"walk from another routing domain", underlayBy("r1", bgp), []Tunnel{r1wg0}, Start{Node: "r1", VRF: "blue"}, Failure{Node: "r3"}},
		{"tunnel interface down at its node", underlayBy("r1", bgp), []Tunnel{r1wg0}, fromR1, Failure{Node: "r1", Interface: "wg0"}},
		{"tunnel interface down at its far end", underlayBy("r1", bgp), []Tunnel{r1wg0}, fromR1, Failure{Node: "r5", Interface: "wg0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := withOverlay(t, c.obs, c.src, c.fail, nil)
			if got := impacts(simulateTunnels(t, c.obs, c.tunnels, c.src, c.fail)); !reflect.DeepEqual(got, want) {
				t.Errorf("impacts = %v, want %v", got, want)
			}
		})
	}
}

// A next-hop loss off a BGP-selected underlay gives the same output as the loss
// over a static underlay. The BGP rule reads router and interface failures only,
// so removing the gateway guard turns the overlay unknown and fails this test.
func TestBGPUnderlayRuleSparesANextHopLoss(t *testing.T) {
	fail := Failure{Node: "r1", NextHop: "10.0.13.2"}
	got := simulateTunnels(t, underlayBy("r1", netmodel.OriginBGP), []Tunnel{r1wg0}, fromR1, fail)
	want := simulateTunnels(t, tunnelTopology(), []Tunnel{r1wg0}, fromR1, fail)
	if got.Text() != want.Text() {
		t.Errorf("text differs from the static underlay:\n%s\nwant:\n%s", got.Text(), want.Text())
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("json differs from the static underlay:\n%s\nwant:\n%s", gotJSON, wantJSON)
	}
	if got.Failure.VRF != "default" || got.Gateway == nil || len(got.Gateway.Evidence) != 1 {
		t.Errorf("failure %+v, gateway %+v; want the default VRF filled in and one FIB row naming the gateway", got.Failure, got.Gateway)
	}
	if got.Considered != 14 || got.Unchanged != 12 || got.Truncated {
		t.Errorf("considered %d, unchanged %d, truncated %t; want 14, 12, false", got.Considered, got.Unchanged, got.Truncated)
	}
	if d, ok := impacts(got)[overlayDest]; ok {
		t.Errorf("overlay = %s, want none: the gateway is off the underlay", d)
	}
}

// The failures the BGP rule leaves to their own reasons: an underlay the
// failure cuts or does not prove keeps that reason, and a lost adjacency or
// next hop that cuts the underlay keeps the one it already gave.
func TestBGPUnderlayKeepsItsStructuralReasons(t *testing.T) {
	partial := without(underlayBy("r1", netmodel.OriginBGP), "fib:r2:default")
	partial = append(partial, table(netmodel.PlaneFIB, "r2", "default", false,
		route("10.0.25.0/30", "kernel", onLink("eth1")),
		route("10.60.0.0/24", "kernel", onLink("lan2"))))
	adjacency := append(underlayBy("r1", netmodel.OriginBGP),
		ospfControl("frr:r1", "r1", "default", "point-to-point", []string{"eth2"}, ospfNeighbor("eth2", "r3", "eth0", "10.0.13.2", "Full")))
	bgpUnderlay := underlayBy("r1", netmodel.OriginBGP)
	cases := []struct {
		name     string
		obs      []netmodel.Observation
		fail     Failure
		because  string
		unwanted string
	}{
		{"underlay cut at r2", bgpUnderlay, Failure{Node: "r2"}, "meets the failure", ""},
		{"underlay not proven", partial, Failure{Node: "r3"}, "does not prove delivery", ""},
		{"--fail-ospf on the underlay adjacency", adjacency, Failure{Node: "r1", Interface: "eth2", OSPFNeighbor: "r3"}, "is unknown, not proven cut, at r1 (default) eth0 via 10.0.12.2", "meets the failure"},
		{"--fail-next-hop on the underlay gateway", bgpUnderlay, Failure{Node: "r1", Interface: "eth0", NextHop: "10.0.12.2"}, "meets the failure", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := simulateTunnels(t, c.obs, []Tunnel{r1wg0}, fromR1, c.fail)
			leaf := leafOf(affected(t, s, overlayDest).After, "wg0")
			if leaf == nil || !strings.Contains(leaf.Decision.Reason, c.because) || strings.Contains(leaf.Decision.Reason, "by BGP route") || (c.unwanted != "" && strings.Contains(leaf.Decision.Reason, c.unwanted)) {
				t.Errorf("wg0 leaf = %+v, want its reason to say %q, not %q, and not name a BGP route", leaf, c.because, c.unwanted)
			}
		})
	}
}

// Under --fail-ospf, an underlay branch that is unknown for another reason must
// not hide the segment the lost adjacency made unknown. The first branch reaches
// a router with a partial FIB, and the second has no interface, so only the lost
// adjacency makes it unknown. The reason names that second segment.
func TestBGPUnderlayNamesTheLostAdjacencySegment(t *testing.T) {
	obs := editFIB(without(tunnelTopology(), "fib:r2:default"), "r1", "default", func(rs []netmodel.Route) []netmodel.Route {
		for i := range rs {
			if rs[i].Prefix == pfx("10.0.25.0/30") {
				rs[i] = route("10.0.25.0/30", "kernel", nh("10.0.12.2", "eth0"), nh("10.0.13.2", ""))
			}
		}
		return rs
	})
	obs = append(obs,
		table(netmodel.PlaneFIB, "r2", "default", false,
			route("10.0.25.0/30", "kernel", onLink("eth1")),
			route("10.60.0.0/24", "kernel", onLink("lan2"))),
		ospfControl("frr:r1", "r1", "default", "point-to-point", []string{"eth2"}, ospfNeighbor("eth2", "r3", "eth0", "10.0.13.2", "Full")))
	s := simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, Failure{Node: "r1", VRF: "default", Interface: "eth2", OSPFNeighbor: "r3"})
	leaf := leafOf(affected(t, s, overlayDest).After, "wg0")
	if leaf == nil || !strings.Contains(leaf.Decision.Reason, "via 10.0.13.2: r1 (default) names no interface for next hop 10.0.13.2") {
		t.Errorf("wg0 leaf = %+v, want the reason to name the lost adjacency's segment", leaf)
	}
	if leaf != nil && strings.Contains(leaf.Decision.Reason, "FIB for this node is partial") {
		t.Errorf("reason names the partial FIB branch: %q", leaf.Decision.Reason)
	}
}

// Under --fail r5:lan the tunnel's remote holds the overlay destination on its
// down lan interface, and the BGP-selected underlay leaves the walk at the tunnel.
// The leaf keeps the BGP route and says, conditionally, what the remote holds,
// with the rows that show it. Ratings and counts are those of the BGP rule alone.
func TestBGPUnderlayKeepsTheRemoteDownInterface(t *testing.T) {
	obs := underlayBy("r1", netmodel.OriginBGP)
	fail := Failure{Node: "r5", Interface: "lan"}
	s := simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, fail)
	want := withOverlay(t, obs, fromR1, fail, map[string]Impact{overlayDest: ImpactUnknown, tunnelPeer: ImpactUnknown})
	if got := impacts(s); !reflect.DeepEqual(got, want) {
		t.Fatalf("impacts = %v, want %v", got, want)
	}
	if s.Considered != 14 || s.Unchanged != 14-len(want) || s.Truncated {
		t.Errorf("considered %d, unchanged %d, truncated %t; want 14, %d, false", s.Considered, s.Unchanged, s.Truncated, 14-len(want))
	}
	leaf := leafOf(affected(t, s, overlayDest).After, "wg0")
	if leaf == nil || leaf.Decision.Kind != KindUnknown {
		t.Fatalf("wg0 leaf = %+v, want an unknown leaf", leaf)
	}
	const bgpRoute = "forwards by BGP route 10.0.25.0/30 at r1 (default), in fib:r1:default (bgp)"
	const remoteHolds = "if the traffic crosses the tunnel, r5 (default) holds 10.50.0.1 on lan, which is down"
	if !strings.Contains(leaf.Decision.Reason, bgpRoute) || !strings.Contains(leaf.Decision.Reason, remoteHolds) {
		t.Errorf("reason = %q, want it to name the BGP route and the remote's down interface", leaf.Decision.Reason)
	}
	var sources []string
	for _, e := range leaf.Decision.Evidence {
		sources = append(sources, e.Source)
	}
	if want := []string{"config:r5:default", "tunnels:r1"}; !slices.Equal(sources, want) {
		t.Errorf("evidence sources = %v, want %v", sources, want)
	}
	if !strings.Contains(s.Text(), remoteHolds) {
		t.Errorf("text lacks the remote's down interface:\n%s", s.Text())
	}
	if b, err := json.Marshal(s); err != nil || !strings.Contains(string(b), remoteHolds) {
		t.Errorf("json lacks the remote's down interface: %v\n%s", err, b)
	}
	other := simulateTunnels(t, obs, []Tunnel{r1wg0}, fromR1, Failure{Node: "r3"})
	if leaf := leafOf(affected(t, other, overlayDest).After, "wg0"); leaf == nil || strings.Contains(leaf.Decision.Reason, "if the traffic crosses") {
		t.Errorf("under r3, wg0 leaf = %+v, want no remote interface: the failure is not on the remote", leaf)
	}
}

// A BGP underlay longer than maxDepth stops before it proves delivery. The
// overlay is unknown for that reason, the unproven one, and not for the BGP
// route its first hop selects, since a walk cut short says nothing about it.
func TestTruncatedBGPUnderlayIsUnproven(t *testing.T) {
	const hops = maxDepth + 8
	var obs []netmodel.Observation
	for k := 0; k <= hops; k++ {
		node := fmt.Sprintf("u%d", k)
		var ifaces []netmodel.Interface
		var routes []netmodel.Route
		if k > 0 {
			ifaces = append(ifaces, ifc("in", fmt.Sprintf("10.1.%d.2/24", k)))
		}
		if k < hops {
			ifaces = append(ifaces, ifc("out", fmt.Sprintf("10.1.%d.1/24", k+1)))
			origin := "kernel"
			if k == 0 {
				origin = netmodel.OriginBGP
			}
			routes = append(routes, route("10.9.0.0/16", origin, nh(fmt.Sprintf("10.1.%d.2", k+1), "out")))
		} else {
			ifaces = append(ifaces, ifc("lan", "10.9.0.1/16"))
		}
		obs = append(obs, configured(node, "transit", ifaces), table(netmodel.PlaneFIB, node, "transit", true, routes...))
	}
	obs = append(obs,
		configured("u0", "default", []netmodel.Interface{ifc("wg0", "172.16.0.1/30")}),
		table(netmodel.PlaneFIB, "u0", "default", true, route("10.50.0.0/24", netmodel.OriginStatic, onLink("wg0"))),
		configured(fmt.Sprintf("u%d", hops), "default", []netmodel.Interface{ifc("lan", "10.50.0.1/24")}),
		configured("x", "default", []netmodel.Interface{ifc("eth0", "10.77.0.1/24")}))
	src := Start{Node: "u0", VRF: "default"}
	s := simulateTunnels(t, obs, []Tunnel{tunnelRecord("u0", "default", "wg0", "10.9.0.1", "transit")}, src, Failure{Node: "x"})
	a := affected(t, s, overlayDest)
	if a.Impact != ImpactUnknown {
		t.Fatalf("overlay = %s, want unknown", a.Impact)
	}
	var leaf *Hop
	walkHops(a.After, func(x *Hop) {
		if leaf == nil && x.Node == "" && x.Via != nil && x.Via.Interface == "wg0" {
			leaf = x
		}
	})
	if leaf == nil || !strings.Contains(leaf.Decision.Reason, "does not prove delivery") || strings.Contains(leaf.Decision.Reason, "BGP route") {
		t.Errorf("wg0 leaf = %+v, want the unproven reason and no BGP route", leaf)
	}
}
