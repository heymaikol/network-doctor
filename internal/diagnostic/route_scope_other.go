//go:build !linux

package diagnostic

import "net"

// lookupScopedRouteDecision is nil where the route API is not known to honor
// an IPv6 zone. A scoped target then records no route rather than the one an
// unscoped lookup would describe, which may belong to another link.
var lookupScopedRouteDecision func(dst, source net.IP, zone string) (RouteDecision, bool)

// newPassRouteLookups is nil here: interface facts are read per lookup, not
// shared across a pass, so the pass keeps the lookups it was given.
var newPassRouteLookups func() (
	func(dst, source net.IP) (RouteDecision, bool),
	func(dst, source net.IP, zone string) (RouteDecision, bool),
)
