package diagnostic

import (
	"context"
	"net"
	"sort"
)

// Route metadata is collected alongside the existing connections, never as a
// new post-timeout stage. The buffered result lets a slow kernel query finish
// safely after the probe has stopped waiting. Every kernel exchange is bounded,
// and cancellation prevents starting another lookup.
func (o *netops) collectPathComparison(ctx context.Context, v4, v6 []net.IP) <-chan ProbeResult {
	result := make(chan ProbeResult, 1)
	if o.routes == nil || o.defaultRoutes == nil {
		result <- ProbeResult{}
		return result
	}
	go func() {
		var evidence ProbeResult
		for _, ips := range [][]net.IP{v4, v6} {
			for _, ip := range ips {
				if ctx.Err() != nil {
					return
				}
				evidence.Routes = append(evidence.Routes, o.routeDecisions(ip)...)
			}
		}
		evidence.alternateDefaults = make(map[string][]defaultRouteState)
		for _, ips := range [][]net.IP{v4, v6} {
			if ctx.Err() != nil {
				return
			}
			if len(ips) > 0 {
				evidence.alternateDefaults[routeFamily(ips[0])] = o.preferredPathAlternates(ips, evidence.Routes)
			}
		}
		result <- evidence
	}()
	return result
}

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

// preferredPathAlternates correlates the kernel's selected reference paths
// with its default table. It does not establish reachability. A more-specific
// route through the same gateway still exercises that default's path; no
// claim is made that the default entry itself selected that destination.
func (o *netops) preferredPathAlternates(ips []net.IP, decisions []RouteDecision) []defaultRouteState {
	if len(ips) == 0 || o.defaultRoutes == nil {
		return nil
	}
	defaults := append([]defaultRouteState(nil), o.defaultRoutes(routeFamily(ips[0]))...)
	sort.SliceStable(defaults, func(i, j int) bool { return defaults[i].metric < defaults[j].metric })
	if len(defaults) < 2 || defaults[0].metric >= defaults[1].metric {
		return nil
	}
	for _, ip := range ips {
		path, ok := routeFor(decisions, ip)
		if !ok || !defaultPathMatches(path, defaults[0]) {
			return nil
		}
	}
	var alternates []defaultRouteState
	for _, route := range defaults[1:] {
		if route.gateway != nil && !route.gateway.Equal(defaults[0].gateway) {
			alternates = append(alternates, route)
		}
	}
	return alternates
}

// The default reader's main table is only comparable with a decision known
// to come from that table. Unsupported platforms and policy routing stay
// unknown. Interface plus gateway distinguishes routers sharing one link.
func defaultPathMatches(path RouteDecision, route defaultRouteState) bool {
	return !path.Unreachable && path.TableKnown && path.Table == "" &&
		path.Iface != "" && path.Iface == route.iface &&
		path.Gateway != nil && path.Gateway.Equal(route.gateway)
}

const preferredPathSummary = "Reference TCP connections failed through the preferred default path, but the target connected through a lower-preference alternate path."

func reconcilePreferredPath(res map[ProbeID]ProbeResult) {
	internet, target := res[ProbeInternet], res[ProbeTargetTCP]
	if internet.Status != StatusFail || internet.Portal != nil || internet.Families == nil ||
		!functional(target.Status) || target.SelectedIP == nil || target.Source == nil || target.ifaceAmbiguous {
		return
	}
	family := routeFamily(target.SelectedIP)
	if family == counterfactualIPv4 && internet.Families.IPv4 != FamilyUnreachable ||
		family == counterfactualIPv6 && internet.Families.IPv6 != FamilyUnreachable {
		return
	}
	// Do not use selectedTargetRoute's failure fallback: only the successful
	// address and its actual socket source can carry the comparison.
	path, ok := routeFor(target.Routes, target.SelectedIP)
	if !ok || path.Family != family || !path.Source.Equal(target.Source) || path.Iface != target.Iface {
		return
	}
	for _, alternate := range internet.alternateDefaults[family] {
		if defaultPathMatches(path, alternate) {
			internet.Cause, internet.causeFamily = RouteCausePreferredPathAlternateReachable, family
			internet.Detail = preferredPathSummary
			res[ProbeInternet] = internet
			return
		}
	}
}
