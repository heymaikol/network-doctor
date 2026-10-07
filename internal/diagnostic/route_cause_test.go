package diagnostic

import (
	"net"
	"testing"
)

// classifyDefaultRoutes is the one piece of routing judgement every OS shares,
// so it is tested once, off any host's real routing table.
func TestClassifyDefaultRoutes(t *testing.T) {
	gw := func(s string) net.IP { return net.ParseIP(s) }
	failed := func(r defaultRouteState) bool { return r.gateway != nil && r.gateway.Equal(gw("10.0.0.1")) }
	tests := []struct {
		name         string
		routes       []defaultRouteState
		gatewayCheck func(defaultRouteState) bool
		want         string
	}{
		{"no routes at all", nil, failed, RouteCauseNoDefaultRoute},
		{"sole route with a dead gateway",
			[]defaultRouteState{{iface: "en0", gateway: gw("10.0.0.1"), metric: 100}}, failed, RouteCauseGatewayUnreachable},
		{"sole route with a live gateway",
			[]defaultRouteState{{iface: "en0", gateway: gw("10.0.0.9"), metric: 100}}, failed, RouteCauseSelectedPathFailed},
		{"on-link route has no gateway to blame",
			[]defaultRouteState{{iface: "en0", metric: 100}}, failed, RouteCauseSelectedPathFailed},
		{"preferred route has an independently unresolved gateway",
			[]defaultRouteState{{iface: "en1", gateway: gw("10.0.0.9"), metric: 200},
				{iface: "en0", gateway: gw("10.0.0.1"), metric: 100}}, failed, RouteCauseGatewayUnreachable},
		{"equal metrics are load sharing, not preference",
			[]defaultRouteState{{iface: "en0", gateway: gw("10.0.0.1"), metric: 100},
				{iface: "en1", gateway: gw("10.0.0.9"), metric: 100}}, failed, RouteCauseSelectedPathFailed},
		{"no neighbour evidence never reaches the gateway verdict",
			[]defaultRouteState{{iface: "en0", gateway: gw("10.0.0.1"), metric: 100}}, nil, RouteCauseSelectedPathFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDefaultRoutes(tc.routes, tc.gatewayCheck); got != tc.want {
				t.Errorf("cause = %q, want %q", got, tc.want)
			}
		})
	}
}

// Equal-metric defaults are one unordered set: no evidence says which of them
// carried the failed reference connections (Linux even prefers a default whose
// gateway resolves). Every enumeration order must therefore classify alike,
// and an unresolved gateway is only blamed when every tied next hop is one.
func TestClassifyDefaultRoutesIgnoresEqualCostOrder(t *testing.T) {
	a := defaultRouteState{iface: "eth0", gateway: net.ParseIP("10.0.0.1"), metric: 100}
	b := defaultRouteState{iface: "eth1", gateway: net.ParseIP("10.0.1.1"), metric: 100}
	c := defaultRouteState{iface: "eth2", gateway: net.ParseIP("10.0.2.1"), metric: 100}
	onLink := defaultRouteState{iface: "wg0", metric: 100}
	worse := defaultRouteState{iface: "eth3", gateway: net.ParseIP("10.0.3.1"), metric: 200}
	failing := func(dead ...defaultRouteState) func(defaultRouteState) bool {
		return func(r defaultRouteState) bool {
			for _, d := range dead {
				if r.gateway != nil && r.iface == d.iface && r.gateway.Equal(d.gateway) {
					return true
				}
			}
			return false
		}
	}
	tests := []struct {
		name   string
		routes []defaultRouteState
		failed func(defaultRouteState) bool
		want   string
	}{
		{"only the first tied gateway is unresolved", []defaultRouteState{a, b}, failing(a), RouteCauseSelectedPathFailed},
		{"only the second tied gateway is unresolved", []defaultRouteState{a, b}, failing(b), RouteCauseSelectedPathFailed},
		{"every tied gateway is unresolved", []defaultRouteState{a, b}, failing(a, b), RouteCauseGatewayUnreachable},
		{"no tied gateway is unresolved", []defaultRouteState{a, b}, failing(), RouteCauseSelectedPathFailed},
		{"two of three tied gateways are unresolved", []defaultRouteState{a, b, c}, failing(a, b), RouteCauseSelectedPathFailed},
		{"all three tied gateways are unresolved", []defaultRouteState{a, b, c}, failing(a, b, c), RouteCauseGatewayUnreachable},
		{"a tied on-link default has no gateway to blame", []defaultRouteState{a, onLink}, failing(a), RouteCauseSelectedPathFailed},
		{"a worse metric does not join the tie", []defaultRouteState{a, b, worse}, failing(a, b), RouteCauseGatewayUnreachable},
		{"a healthy worse metric does not rescue the tie", []defaultRouteState{a, b, worse}, failing(a), RouteCauseSelectedPathFailed},
		{"a unique preferred route keeps its verdict", []defaultRouteState{worse, a}, failing(a), RouteCauseGatewayUnreachable},
		{"a duplicated dead route is still the whole tie", []defaultRouteState{a, a}, failing(a), RouteCauseGatewayUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, order := range permutations(tc.routes) {
				names := ifaces(order)
				if got := classifyDefaultRoutes(order, tc.failed); got != tc.want {
					t.Errorf("order %v: cause = %q, want %q", names, got, tc.want)
				}
			}
		})
	}
}

func permutations(routes []defaultRouteState) [][]defaultRouteState {
	if len(routes) <= 1 {
		return [][]defaultRouteState{append([]defaultRouteState(nil), routes...)}
	}
	var out [][]defaultRouteState
	for i := range routes {
		rest := append(append([]defaultRouteState(nil), routes[:i]...), routes[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]defaultRouteState{routes[i]}, p...))
		}
	}
	return out
}

func ifaces(routes []defaultRouteState) []string {
	out := make([]string, len(routes))
	for i, r := range routes {
		out[i] = r.iface
	}
	return out
}
