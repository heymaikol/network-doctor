package diagnostic

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
)

// stubRouteOps is a run whose kernel answers come from a table, so the wiring
// between the probes and the route collector is testable without a network
// stack, a routing table, or a VPN of any kind.
func stubRouteOps(answers map[string]RouteDecision, asked *[]string) *netops {
	var mu sync.Mutex
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("198.51.100.7")}, []string{"192.168.1.1:53"}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no network in tests")
		},
		routeFor: func(dst, _ net.IP) (RouteDecision, bool) {
			mu.Lock()
			if asked != nil {
				*asked = append(*asked, dst.String())
			}
			mu.Unlock()
			d, ok := answers[dst.String()]
			return d, ok
		},
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	return o
}

// Each row records the decisions for the destinations it is about: general
// Internet endpoints on the interface row, each recorded resolver target on the
// DNS row, and every resolved address on the target row.
func TestProbesRecordTheRoutesForTheirOwnDestinations(t *testing.T) {
	answers := map[string]RouteDecision{
		internetEndpointCloudflareIPv4: {Iface: "eth0", Tunnel: TunnelDirect},
		internetEndpointCloudflareIPv6: {Iface: "eth0", Tunnel: TunnelDirect},
		"192.168.1.1":                  {Iface: "eth0", Tunnel: TunnelDirect},
		"198.51.100.7":                 {Iface: "wg0", Tunnel: TunnelKnown, TunnelKind: "wireguard"},
	}
	var asked []string
	o := stubRouteOps(answers, &asked)
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	res := map[ProbeID]ProbeResult{}
	for _, p := range o.buildProbes(target, "", false) {
		if p.ID == ProbeIface || p.ID == ProbeDNS || p.ID == ProbeTargetTCP {
			res[p.ID] = p.Run(context.Background(), res)
		}
	}
	if got := res[ProbeIface].Routes; len(got) == 0 || got[0].Iface != "eth0" {
		t.Errorf("iface row routes = %+v, want the general Internet path", got)
	}
	if got := res[ProbeDNS].Routes; len(got) != 1 || got[0].Destination.String() != "192.168.1.1" {
		t.Errorf("dns row routes = %+v, want the configured resolver's path", got)
	}
	targetRoutes := res[ProbeTargetTCP].Routes
	if len(targetRoutes) != 1 || targetRoutes[0].Iface != "wg0" || !targetRoutes[0].Tunneled() {
		t.Errorf("target row routes = %+v, want the tunneled path for the resolved address", targetRoutes)
	}
	for _, dst := range asked {
		if _, expected := answers[dst]; !expected {
			t.Errorf("looked up %q, which is not a destination this run is about", dst)
		}
	}
}

func TestDNSProbeRecordsEveryResolverTargetRoute(t *testing.T) {
	answers := map[string]RouteDecision{
		internetEndpointCloudflareIPv4: {Iface: "eth0", Tunnel: TunnelDirect},
		internetEndpointCloudflareIPv6: {Iface: "eth0", Tunnel: TunnelDirect},
		"192.0.2.53":                   {Iface: "eth0", Tunnel: TunnelDirect},
		"2001:db8::53":                 {Iface: "wg0", Tunnel: TunnelKnown},
	}
	o := stubRouteOps(answers, nil)
	o.lookupIP = func(context.Context, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("198.51.100.7")}, []string{"192.0.2.53:53", "[2001:db8::53]:53"}, nil
	}
	r := o.dnsProbe("example.com", nil)(context.Background(), nil)
	if got := r.ResolverTargets; !slices.Equal(got, []string{"192.0.2.53:53", "[2001:db8::53]:53"}) {
		t.Fatalf("resolver targets = %v", got)
	}
	if len(r.Routes) != 2 || r.Routes[0].Destination.String() != "192.0.2.53" ||
		r.Routes[1].Destination.String() != "2001:db8::53" {
		t.Errorf("resolver routes = %+v, want both targets in evidence order", r.Routes)
	}
}

// A pass asks the kernel once per destination however many rows want it, so a
// run cannot report two different networks for one address.
func TestOneRunAsksTheKernelOncePerDestination(t *testing.T) {
	answers := map[string]RouteDecision{
		internetEndpointCloudflareIPv4: {Iface: "eth0", Tunnel: TunnelDirect},
		internetEndpointCloudflareIPv6: {Iface: "eth0", Tunnel: TunnelDirect},
		"192.168.1.1":                  {Iface: "eth0", Tunnel: TunnelDirect},
		"198.51.100.7":                 {Iface: "eth0", Tunnel: TunnelDirect},
	}
	var asked []string
	o := stubRouteOps(answers, &asked)
	res := map[ProbeID]ProbeResult{}
	for _, p := range o.buildProbes(&Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}, "", false) {
		if p.ID == ProbeIface || p.ID == ProbeDNS || p.ID == ProbeTargetTCP || p.ID == ProbeInternet {
			res[p.ID] = p.Run(context.Background(), res)
		}
	}
	seen := map[string]int{}
	for _, dst := range asked {
		seen[dst]++
	}
	for dst, n := range seen {
		if n != 1 {
			t.Errorf("asked the kernel about %s %d times in one pass, want once", dst, n)
		}
	}
}

// A route that really changes between two Watch Mode passes must be seen as a
// change, so the memoization cannot outlive the pass that created it.
func TestEachPassGetsAFreshRouteCache(t *testing.T) {
	iface := "eth0"
	answers := func(net.IP, net.IP) (RouteDecision, bool) {
		return RouteDecision{Iface: iface, Tunnel: TunnelDirect}, true
	}
	original := defaultOps.routeFor
	defaultOps.routeFor = answers
	defer func() { defaultOps.routeFor = original }()
	run := func(probes []Probe) string {
		for _, p := range probes {
			if p.ID == ProbeIface {
				r := p.Run(context.Background(), map[ProbeID]ProbeResult{})
				if len(r.Routes) == 0 {
					return ""
				}
				return r.Routes[0].Iface
			}
		}
		return ""
	}
	if got := run(BuildProbesFromSources(nil, nil, "", false)); got != "eth0" {
		t.Fatalf("first pass = %q, want eth0", got)
	}
	iface = "wg0"
	if got := run(BuildProbesFromSources(nil, nil, "", false)); got != "wg0" {
		t.Errorf("second pass = %q, want wg0: the cache outlived its pass", got)
	}
}

// A platform netdoc cannot ask records no routes, and nothing downstream may
// read that as "there was no route".
func TestAPlatformThatCannotAnswerRecordsNothing(t *testing.T) {
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("198.51.100.7")}, []string{"192.168.1.1:53"}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no network in tests")
		},
		routeFor: func(net.IP, net.IP) (RouteDecision, bool) { return RouteDecision{}, false },
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	res := map[ProbeID]ProbeResult{}
	for _, p := range o.buildProbes(&Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}, "", false) {
		if p.ID != ProbeIface && p.ID != ProbeDNS && p.ID != ProbeTargetTCP {
			continue
		}
		r := p.Run(context.Background(), res)
		res[p.ID] = r
		if len(r.Routes) != 0 {
			t.Errorf("%s recorded routes on a platform that answered nothing: %+v", p.ID, r.Routes)
		}
	}
	if _, ok := selectedTargetRoute(res); ok {
		t.Error("an unanswered platform produced a selected target route")
	}
}

// fe80::1 is on two links here, and a lookup that ignores the zone answers
// for wlan0. A target scoped to eth0 must record eth0's route or none: never
// a route the connection did not take. The platform's zoned lookup is what
// can answer; where there is none, nothing is recorded.
func TestScopedTargetRouteFollowsItsZone(t *testing.T) {
	answers := map[string]RouteDecision{
		internetEndpointCloudflareIPv4: {Iface: "eth0", Tunnel: TunnelDirect},
		internetEndpointCloudflareIPv6: {Iface: "eth0", Tunnel: TunnelDirect},
		"fe80::1":                      {Iface: "wlan0", Tunnel: TunnelDirect},
	}
	zoned := func(dst, _ net.IP, zone string) (RouteDecision, bool) {
		return RouteDecision{Iface: zone, Tunnel: TunnelDirect}, dst.String() == "fe80::1"
	}
	for _, c := range []struct {
		target, want string
		lookup       func(dst, source net.IP, zone string) (RouteDecision, bool)
	}{
		{"[fe80::1%eth0]:22", "eth0", zoned},
		{"[fe80::1%wlan0]:22", "wlan0", zoned},
		{"[fe80::1%eth0]:22", "", nil}, // a platform that cannot scope the lookup
	} {
		target, err := ParseTarget(c.target)
		if err != nil {
			t.Fatal(err)
		}
		o := stubRouteOps(answers, nil)
		o.routeForZone = c.lookup
		o.scope = netip.MustParseAddr("fe80::1%" + target.Zone)
		o.routes.scoped, o.routes.lookupZone = o.scoped, o.routeForZone
		res := map[ProbeID]ProbeResult{}
		for _, p := range o.buildProbes(target, "", false) {
			if p.ID == ProbeIface || p.ID == ProbeDNS || p.ID == ProbeTargetTCP {
				res[p.ID] = p.Run(context.Background(), res)
			}
		}
		var got []string
		for _, route := range res[ProbeTargetTCP].Routes {
			if route.Destination.Equal(target.IP) {
				got = append(got, route.Iface)
			}
		}
		if want := []string{c.want}; c.want == "" && len(got) != 0 || c.want != "" && !slices.Equal(got, want) {
			t.Errorf("%s with zoned lookup %v: target routes name %q, want %q", c.target, c.lookup != nil, got, c.want)
		}
	}
}

// The zone is part of the cache key: an answer for fe80::1%eth0 must not
// serve fe80::1%wlan0, nor the unscoped fe80::1, and the reverse.
func TestRouteCacheKeysOnTheZone(t *testing.T) {
	var asked []string
	cache := newRouteCache(func(dst, _ net.IP) (RouteDecision, bool) {
		asked = append(asked, dst.String())
		return RouteDecision{Iface: "wlan0"}, true
	}, nil)
	cache.lookupZone = func(dst, _ net.IP, zone string) (RouteDecision, bool) {
		asked = append(asked, dst.String()+"%"+zone)
		return RouteDecision{Iface: zone}, true
	}
	zone := ""
	cache.scoped = func(net.IP) string { return zone }
	dst := net.ParseIP("fe80::1")
	for _, z := range []string{"eth0", "wlan0", "", "eth0", "wlan0", ""} {
		zone = z
		got, ok := cache.get(dst)
		if want := cmp.Or(z, "wlan0"); !ok || got.Iface != want {
			t.Errorf("zone %q: route via %q, want %q", z, got.Iface, want)
		}
	}
	if want := []string{"fe80::1%eth0", "fe80::1%wlan0", "fe80::1"}; !slices.Equal(asked, want) {
		t.Errorf("asked %q, want each scope looked up exactly once: %q", asked, want)
	}
}
