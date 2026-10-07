//go:build !linux

package diagnostic

import "net"

// lookupScopedRouteDecision is nil where the route API is not known to honor
// an IPv6 zone. A scoped target then records no route rather than the one an
// unscoped lookup would describe, which may belong to another link.
var lookupScopedRouteDecision func(dst, source net.IP, zone string) (RouteDecision, bool)
