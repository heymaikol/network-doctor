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
				{iface: "en1", gateway: gw("10.0.0.9"), metric: 100}}, failed, RouteCauseGatewayUnreachable},
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
