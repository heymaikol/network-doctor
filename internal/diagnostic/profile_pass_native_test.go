package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

// Exercise the public graph builder with native probes and offline OS/network
// hooks. The gate requires both component DNS branches to run concurrently.
func TestProfilePassNativeGraphsRefreshAndKeepTargetRoutesLocal(t *testing.T) {
	var interfaces atomic.Int64
	var generation atomic.Int64
	var routeCalls sync.Map
	dnsStarted := make(chan string, 2)
	releaseDNS := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-releaseDNS:
		default:
			close(releaseDNS)
		}
	})
	o := netops{
		interfaces: func() ([]net.Interface, error) {
			interfaces.Add(1)
			return []net.Interface{{Name: "fixture", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		lookupIP: func(ctx context.Context, host string) ([]net.IP, []string, error) {
			dnsStarted <- host
			select {
			case <-releaseDNS:
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			ip := net.ParseIP("140.82.112.3")
			if host == "api.github.com" {
				ip = net.ParseIP("140.82.113.3")
			}
			return []net.IP{ip}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("offline fixture refuses target connection")
		},
		routeFor: func(dst, _ net.IP) (RouteDecision, bool) {
			counter, _ := routeCalls.LoadOrStore(dst.String(), new(atomic.Int64))
			counter.(*atomic.Int64).Add(1)
			return RouteDecision{Iface: fmt.Sprintf("route%d", generation.Load()), Tunnel: TunnelDirect}, true
		},
	}
	selection := ProbeSelection{Check: map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeInternet: {}, ProbeProxy: {}, ProbeDNSPublic: {}}, NoReferenceEgress: true}
	for watchPass := int64(1); watchPass <= 2; watchPass++ {
		generation.Store(watchPass)
		pass := &ProfilePass{ops: o}
		graphs := [][]Probe{
			pass.BuildProbes(mustTarget(t, "https://github.com"), selection, "", false),
			pass.BuildProbes(mustTarget(t, "https://api.github.com"), selection, "", false),
		}
		done := make(chan []map[ProbeID]ProbeResult, 1)
		go func() { done <- runProfileFixture(graphs) }()
		first, second := profileReceive(t, dnsStarted), profileReceive(t, dnsStarted)
		if first == second {
			t.Fatalf("DNS observations lost component identity: %q twice", first)
		}
		if watchPass == 1 {
			close(releaseDNS)
		}
		results := profileReceive(t, done)
		for i, result := range results {
			if result[ProbeIface].Status != StatusPass || result[ProbeIface].Iface != "fixture" {
				t.Errorf("component %d iface = %+v", i, result[ProbeIface])
			}
			for _, id := range []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP} {
				if len(result[id].Routes) == 0 || result[id].Routes[0].Iface != fmt.Sprintf("route%d", watchPass) {
					t.Errorf("pass %d component %d %s routes = %+v", watchPass, i, id, result[id].Routes)
				}
			}
			wantIP := "140.82.112.3"
			if i == 1 {
				wantIP = "140.82.113.3"
			}
			if got := result[ProbeTargetTCP].Routes[0].Destination.String(); got != wantIP {
				t.Errorf("component %d target route = %s, want %s", i, got, wantIP)
			}
		}
		if got := interfaces.Load(); got != watchPass {
			t.Errorf("iface executions after %d passes = %d, want %d", watchPass, got, watchPass)
		}
		for _, dst := range []string{internetEndpointCloudflareIPv4, internetEndpointCloudflareIPv6, "192.0.2.53", "140.82.112.3", "140.82.113.3"} {
			want := watchPass
			if dst == "192.0.2.53" {
				want *= 2
			}
			counter, ok := routeCalls.Load(dst)
			if !ok || counter.(*atomic.Int64).Load() != want {
				t.Errorf("route lookups for %s after pass %d = %v, want %d", dst, watchPass, counter, want)
			}
		}
	}
}

func TestProfilePassReferenceYardstickMatchesSharedInterface(t *testing.T) {
	pass := new(ProfilePass)
	for component := range 2 {
		var lookups atomic.Int64
		o := probeOps(mustTarget(t, "https://github.com"), &netops{
			routeFor: func(net.IP, net.IP) (RouteDecision, bool) {
				lookups.Add(1)
				return RouteDecision{Iface: "unexpected"}, true
			},
		})
		want := []RouteDecision{{Destination: net.ParseIP("1.1.1.1"), Iface: "observed"}}
		probes := []Probe{{ID: ProbeIface, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			return ProbeResult{Status: StatusPass, Routes: want}
		}}}
		pass.share(probes, o)
		r := probes[0].Run(context.Background(), nil)
		if got := o.referenceRouteDecisions(); !reflect.DeepEqual(got, r.Routes) {
			t.Errorf("component %d reference yardstick = %+v, shared iface routes = %+v", component, got, r.Routes)
		}
		if lookups.Load() != 0 {
			t.Errorf("component %d collected independent reference routes", component)
		}
	}
}

func TestProfilePassSourcesAreCapturedAndSeparate(t *testing.T) {
	var count atomic.Int64
	for _, source := range []string{"192.0.2.1", "192.0.2.2"} {
		sources := &SourceAddresses{IPv4: net.ParseIP(source)}
		pass := NewProfilePass(sources)
		sources.IPv4[0] ^= 1
		pass.ops.interfaces = func() ([]net.Interface, error) {
			count.Add(1)
			return []net.Interface{{Name: source, Flags: net.FlagUp | net.FlagRunning}}, nil
		}
		pass.ops.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPAddr{IP: net.ParseIP(source)}}, nil
		}
		pass.ops.passRoutes = nil
		pass.ops.routeFor = nil
		pass.ops.routeForZone = nil
		pass.ops.defaultRoutes = nil
		selection := ProbeSelection{Check: map[ProbeID]struct{}{ProbeIface: {}}}
		for range 2 {
			result := RunAll(context.Background(), pass.BuildProbes(mustTarget(t, "https://github.com"), selection, "", false), DefaultProbeTimeout)
			if got := result[ProbeIface].Source.String(); got != source {
				t.Errorf("captured source = %s, want %s", got, source)
			}
		}
	}
	if count.Load() != 2 {
		t.Errorf("separate source configurations executed iface %d times, want 2", count.Load())
	}
}

func TestProfilePassSharesOnlyExplicitNativeSet(t *testing.T) {
	var counts sync.Map
	pass := NewProfilePass(nil)
	for component := range 2 {
		target := mustTarget(t, "https://github.com")
		o := probeOps(target, opsFromSources(nil))
		probes := o.timedProbes(target, DefaultPublicDNS, true)
		for i, p := range probes {
			counter, _ := counts.LoadOrStore(p.ID, new(atomic.Int64))
			probes[i].Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
				counter.(*atomic.Int64).Add(1)
				return ProbeResult{Status: StatusPass}
			}
		}
		pass.share(probes, o)
		RunAll(context.Background(), probes, DefaultProbeTimeout)
		if component == 1 {
			for _, p := range probes {
				want := int64(2)
				if slices.Contains([]ProbeID{ProbeIface, ProbeInternet, ProbeProxy}, p.ID) {
					want = 1
				}
				counter, _ := counts.Load(p.ID)
				if got := counter.(*atomic.Int64).Load(); got != want {
					t.Errorf("%s executed %d times, want %d", p.ID, got, want)
				}
			}
		}
	}
}

func TestProfilePassSelectionAndReferenceSuppression(t *testing.T) {
	for _, selection := range []ProbeSelection{
		{Check: map[ProbeID]struct{}{ProbeInternet: {}, ProbeProxy: {}}, Skip: map[ProbeID]struct{}{ProbeInternet: {}}},
		{Check: map[ProbeID]struct{}{ProbeInternet: {}, ProbeProxy: {}, ProbeDNSPublic: {}, ProbeTargetTCP: {}}, NoReferenceEgress: true},
		{Check: map[ProbeID]struct{}{ProbeInternet: {}, ProbeProxy: {}, ProbeTargetTCP: {}}, Skip: map[ProbeID]struct{}{ProbeProxy: {}}},
	} {
		pass := NewProfilePass(nil)
		target := mustTarget(t, "https://github.com")
		want := selection.Apply(BuildProbesFromSources(target, nil, DefaultPublicDNS, true, slices.Collect(maps.Keys(selection.Check))...))
		got := pass.BuildProbes(target, selection, DefaultPublicDNS, true)
		if len(got) != len(want) {
			t.Fatalf("selection %+v returned %d probes, want %d", selection, len(got), len(want))
		}
		for i, p := range got {
			if p.ID != want[i].ID || !slices.Equal(p.Deps, want[i].Deps) || p.Reference != want[i].Reference {
				t.Errorf("selection %+v probe %d changed: got %+v, want %+v", selection, i, p, want[i])
			}
			if selection.NoReferenceEgress && p.Reference {
				t.Errorf("reference probe %s survived suppression", p.ID)
			}
		}
	}
}

func TestProfilePassRejectsChangedDependencies(t *testing.T) {
	for _, changed := range []ProbeID{ProbeIface, ProbeInternet, ProbeProxy} {
		t.Run(string(changed), func(t *testing.T) {
			pass := NewProfilePass(nil)
			var count atomic.Int64
			for range 2 {
				o := probeOps(nil, opsFromSources(nil))
				probes := []Probe{
					{ID: ProbeIface},
					{ID: ProbeInternet, Deps: []ProbeID{ProbeIface}},
					{ID: ProbeProxy, Deps: []ProbeID{ProbeIface}},
				}
				for i, p := range probes {
					if p.ID == changed {
						probes[i].Deps = []ProbeID{ProbeDNS}
					}
					probes[i].Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
						if p.ID == changed {
							count.Add(1)
						}
						return ProbeResult{Status: StatusPass}
					}
				}
				pass.share(probes, o)
				for _, p := range probes {
					p.Run(context.Background(), nil)
				}
			}
			if count.Load() != 2 {
				t.Errorf("changed %s dependencies allowed sharing: executions = %d", changed, count.Load())
			}
		})
	}
}
