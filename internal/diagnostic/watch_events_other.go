//go:build !linux

package diagnostic

import "errors"

// errNoRouteEvents says the platform has no route-change source yet. Watch keeps
// only watchMaxAge as its bound there, as it did before route events existed.
var errNoRouteEvents = errors.New("route change notifications are not available on this platform")

func openRouteEvents() (routeEvents, error) {
	return nil, errNoRouteEvents
}
