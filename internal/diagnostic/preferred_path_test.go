package diagnostic

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func preferredPathResults(t *testing.T, family string) map[ProbeID]ProbeResult {
	t.Helper()
	preferred, alternate, source, target := "10.79.1.1", "10.79.3.1", "10.79.3.10", "9.9.9.9"
	if family == "ipv6" {
		preferred, alternate, source, target = "2001:db8:79:1::1", "2001:db8:79:3::1", "2001:db8:79:3::10", "2001:db8:79:4::20"
	}
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("network unreachable") },
		interfaces:  func() ([]net.Interface, error) { return nil, nil },
		routeCause:  func(net.IP) string { return RouteCausePreferredPathFailed },
		defaultRoutes: func(f string) []defaultRouteState {
			if f != family {
				return nil
			}
			return []defaultRouteState{{iface: "preferred", gateway: net.ParseIP(preferred), metric: 50}, {iface: "alternate", gateway: net.ParseIP(alternate), metric: 100}}
		},
	}
	ops.routes = newRouteCache(func(dst, _ net.IP) (RouteDecision, bool) {
		return RouteDecision{Destination: dst, Family: routeFamily(dst), Iface: "preferred", Gateway: net.ParseIP(preferred), TableKnown: true}, true
	}, nil)
	internet := ops.internetProbe(context.Background(), nil)
	selected := net.ParseIP(target)
	return map[ProbeID]ProbeResult{
		ProbeInternet: internet,
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: selected, Source: net.ParseIP(source), Iface: "alternate",
			Routes: []RouteDecision{{Destination: selected, Family: family, Iface: "alternate", Gateway: net.ParseIP(alternate), Source: net.ParseIP(source), TableKnown: true}}},
	}
}

func TestPreferredPathComparisonRequiresMeasuredAlternate(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				change func(map[ProbeID]ProbeResult)
				want   bool
			}{
				{"measured alternate", func(map[ProbeID]ProbeResult) {}, true},
				{"no default membership evidence", func(r map[ProbeID]ProbeResult) {
					p := r[ProbeInternet]
					p.alternateDefaults = nil
					r[ProbeInternet] = p
				}, false},
				{"family never tested", func(r map[ProbeID]ProbeResult) { p := r[ProbeInternet]; p.Families = nil; r[ProbeInternet] = p }, false},
				{"target in another family", func(r map[ProbeID]ProbeResult) { r[ProbeTargetTCP].Routes[0].Family = "unknown" }, false},
				{"unrelated third path", func(r map[ProbeID]ProbeResult) { r[ProbeTargetTCP].Routes[0].Gateway = net.ParseIP("192.0.2.1") }, false},
				{"all paths fail", func(r map[ProbeID]ProbeResult) { p := r[ProbeTargetTCP]; p.Status = StatusFail; r[ProbeTargetTCP] = p }, false},
				{"healthy preferred", func(r map[ProbeID]ProbeResult) { p := r[ProbeInternet]; p.Status = StatusPass; r[ProbeInternet] = p }, false},
				{"no successful address", func(r map[ProbeID]ProbeResult) { p := r[ProbeTargetTCP]; p.SelectedIP = nil; r[ProbeTargetTCP] = p }, false},
				{"no target route", func(r map[ProbeID]ProbeResult) { p := r[ProbeTargetTCP]; p.Routes = nil; r[ProbeTargetTCP] = p }, false},
				{"same next hop", func(r map[ProbeID]ProbeResult) { r[ProbeTargetTCP].Routes[0].Gateway = net.ParseIP("10.79.1.1") }, false},
				{"unknown routing table", func(r map[ProbeID]ProbeResult) { r[ProbeTargetTCP].Routes[0].TableKnown = false }, false},
				{"policy routing", func(r map[ProbeID]ProbeResult) { r[ProbeTargetTCP].Routes[0].Table = "table 100" }, false},
				{"wrong socket source", func(r map[ProbeID]ProbeResult) {
					p := r[ProbeTargetTCP]
					p.Source = net.ParseIP("192.0.2.10")
					r[ProbeTargetTCP] = p
				}, false},
				{"DNS alone", func(r map[ProbeID]ProbeResult) {
					delete(r, ProbeTargetTCP)
					r[ProbeDNS] = ProbeResult{Status: StatusPass}
				}, false},
				{"proxy alone", func(r map[ProbeID]ProbeResult) {
					delete(r, ProbeTargetTCP)
					r[ProbeProxy] = ProbeResult{Status: StatusPass}
				}, false},
				{"portal", func(r map[ProbeID]ProbeResult) { p := r[ProbeInternet]; p.Portal = &Portal{}; r[ProbeInternet] = p }, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					results := preferredPathResults(t, family)
					tc.change(results)
					Finalize(results)
					got := results[ProbeInternet]
					if recognized := got.Cause == "preferred_path_failed_alternate_reachable"; recognized != tc.want {
						t.Fatalf("cause = %q, want measured comparison = %v", got.Cause, tc.want)
					}
					if tc.want {
						if got.Status != StatusWarn || !strings.Contains(got.Detail, "alternate") {
							t.Fatalf("comparison not communicated: %+v", got)
						}
						Finalize(results)
						if !reflect.DeepEqual(got, results[ProbeInternet]) {
							t.Fatal("finalization is not idempotent")
						}
					}
				})
			}
		})
	}
}

func TestPreferredPathSelectionEvidenceIsLoadBearing(t *testing.T) {
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	for _, tc := range []struct {
		name   string
		change func(*[]defaultRouteState, *[]RouteDecision)
		want   bool
	}{
		{"strict preference", func(*[]defaultRouteState, *[]RouteDecision) {}, true},
		{"tied metrics", func(d *[]defaultRouteState, _ *[]RouteDecision) { (*d)[1].metric = 50 }, false},
		{"single default", func(d *[]defaultRouteState, _ *[]RouteDecision) { *d = (*d)[:1] }, false},
		{"no defaults", func(d *[]defaultRouteState, _ *[]RouteDecision) { *d = nil }, false},
		{"unknown reference route", func(_ *[]defaultRouteState, r *[]RouteDecision) { *r = (*r)[:1] }, false},
		{"reference policy table", func(_ *[]defaultRouteState, r *[]RouteDecision) { (*r)[0].Table = "table 100" }, false},
		{"unknown reference table", func(_ *[]defaultRouteState, r *[]RouteDecision) { (*r)[0].TableKnown = false }, false},
		{"one reference uses alternate", func(_ *[]defaultRouteState, r *[]RouteDecision) { (*r)[1].Gateway = net.ParseIP("10.79.3.1") }, false},
		{"alternate is same router", func(d *[]defaultRouteState, _ *[]RouteDecision) { (*d)[1].gateway = (*d)[0].gateway }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defaults := []defaultRouteState{{iface: "eth0", gateway: net.ParseIP("10.79.1.1"), metric: 50}, {iface: "eth1", gateway: net.ParseIP("10.79.3.1"), metric: 100}}
			routes := []RouteDecision{
				{Destination: ips[0], Iface: "eth0", Gateway: defaults[0].gateway, TableKnown: true},
				{Destination: ips[1], Iface: "eth0", Gateway: defaults[0].gateway, TableKnown: true},
			}
			tc.change(&defaults, &routes)
			ops := &netops{defaultRoutes: func(string) []defaultRouteState { return defaults }}
			if got := len(ops.preferredPathAlternates(ips, routes)) > 0; got != tc.want {
				t.Fatalf("alternates recorded = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPreferredPathComparisonSnapshotReplay(t *testing.T) {
	results := preferredPathResults(t, "ipv4")
	Finalize(results)
	target, err := ParseTarget("http://9.9.9.9:80")
	if err != nil {
		t.Fatal(err)
	}
	results[ProbeIface] = ProbeResult{Status: StatusPass}
	results[ProbeDNS] = ProbeResult{Status: StatusNA}
	results[ProbeHTTP] = ProbeResult{Status: StatusPass}
	probes := []Probe{{ID: ProbeIface}, {ID: ProbeInternet}, {ID: ProbeDNS}, {ID: ProbeTargetTCP}, {ID: ProbeHTTP}}
	before := Interpret(target, []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeHTTP}, results)
	after, err := ReplaySnapshot(BuildSnapshot(target, probes, results))
	if err != nil {
		t.Fatal(err)
	}
	if before.Summary != preferredPathSummary || after.Summary != before.Summary || after.Verdict != before.Verdict {
		t.Fatalf("live=%+v replay=%+v", before, after)
	}
}

func TestPathComparisonCannotExtendProbeDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	ops := &netops{
		dialContext:   func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() },
		interfaces:    func() ([]net.Interface, error) { return nil, nil },
		defaultRoutes: func(string) []defaultRouteState { return nil },
	}
	ops.routes = newRouteCache(func(net.IP, net.IP) (RouteDecision, bool) {
		close(entered)
		<-release
		return RouteDecision{}, false
	}, nil)
	done := make(chan ProbeResult, 1)
	go func() { done <- ops.internetProbe(ctx, nil) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("route lookup never started")
	}
	cancel()
	select {
	case result := <-done:
		if result.alternateDefaults != nil {
			t.Fatal("cancellation supplied comparison evidence")
		}
	case <-time.After(time.Second):
		t.Fatal("route metadata extended the canceled probe")
	}
}
