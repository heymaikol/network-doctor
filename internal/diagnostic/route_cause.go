package diagnostic

import (
	"net"
	"sort"
)

// defaultRouteState is one usable default route as some operating system's
// routing table reports it.
type defaultRouteState struct {
	// iface identifies the outbound interface the way the same platform's own
	// neighbor table identifies it, so the two can be matched: Linux names
	// interfaces in /proc, while the BSD routing socket and the Windows IP
	// Helper API both number them. The value is opaque here and is only ever
	// compared against another value read from the same host.
	iface   string
	gateway net.IP // nil when the default route is on-link, with no next hop to check
	metric  int
}

// classifyDefaultRoutes turns a host's default routes into one route cause.
// gatewayFailed reports whether the selected route's next hop is unresolved at
// the link layer; a platform that cannot prove that passes nil, which keeps the
// classification at a selection-only legacy cause rather than inventing a
// neighbor failure. selected_path_failed and preferred_route_failed retain their
// wire IDs but neither proves where connectivity failed.
func classifyDefaultRoutes(routes []defaultRouteState, gatewayFailed func(defaultRouteState) bool) string {
	if len(routes) == 0 {
		return RouteCauseNoDefaultRoute
	}
	sort.SliceStable(routes, func(i, j int) bool { return routes[i].metric < routes[j].metric })
	selected := routes[0]
	if gatewayFailed != nil && gatewayFailed(selected) {
		return RouteCauseGatewayUnreachable
	}
	if len(routes) > 1 && routes[0].metric < routes[1].metric {
		return RouteCausePreferredPathFailed
	}
	return RouteCauseSelectedPathFailed
}
