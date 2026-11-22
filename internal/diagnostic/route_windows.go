//go:build windows

package diagnostic

import (
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Route intelligence on Windows asks the IP Helper API for the decision it
// would make: GetBestRoute2 performs the route lookup for one destination and
// returns the entry it chose together with the source address it would use.
// That is the same choice made on Linux and Darwin, for the same reason: the
// kernel's answer is the answer, and reproducing its selection over
// GetIpForwardTable2 would be a second implementation that could disagree.
//
// x/sys/windows wraps the tables but not this call, so the proc is declared
// here the way this package already declares GetIpNetTable2.

// NL_ROUTE_PROTOCOL and interface type values used below. IF_TYPE_TUNNEL is
// the one type that means encapsulation on its own; the others are here so a
// virtual-but-not-encapsulating adapter is reported as direct rather than
// swept in with the tunnels.
const (
	ifTypeOther       = 1
	ifTypeEthernet    = 6
	ifTypePPP         = 23
	ifTypeSoftwareLpb = 24
	ifTypeTunnel      = 131
	ifTypeIEEE80211   = 71
)

var procGetBestRoute2 = modiphlpapi.NewProc("GetBestRoute2")

// lookupRouteDecision asks Windows which route one destination takes, for the
// flow this run actually makes.
//
// source is the local address the pass binds its dials to, and GetBestRoute2
// takes it as an input to the lookup rather than as a filter afterwards, which
// is what makes the answer this flow's route and not merely the machine's.
// Windows answers only for a source that is one of its own addresses, so a
// call it rejects is retried unconstrained: the machine's own decision is what
// every unbound run already records, and it beats no route intelligence.
// Windows reporting that no route exists is not one of those rejections. That
// is an answer, and it is this flow's answer, since the source is an address
// the run's own sockets bind to.
//
// Nothing here fills Table. GetBestRoute2 returns the route it chose and not
// the routing domain it chose it in, so the field stays unknown rather than
// claiming the main table.
func lookupRouteDecision(dst, source net.IP) (RouteDecision, bool) {
	addr, ok := netip.AddrFromSlice(dst)
	if !ok {
		return RouteDecision{}, false
	}
	addr = addr.Unmap()
	if err := procGetBestRoute2.Find(); err != nil {
		return RouteDecision{}, false
	}
	src, constrained := netip.AddrFromSlice(source)
	if src = src.Unmap(); !constrained || src.Is4() != addr.Is4() {
		constrained = false
	}
	decision, ok := bestRoute(addr, src, constrained)
	if !ok && constrained {
		return bestRoute(addr, netip.Addr{}, false)
	}
	return decision, ok
}

// bestRoute performs one GetBestRoute2 call, optionally from a chosen source.
func bestRoute(addr, src netip.Addr, constrained bool) (RouteDecision, bool) {
	best, bestSource, err := bestRouteRow(addr, src, constrained, 0)
	if err != nil {
		if unreachableRouteError(err) {
			return RouteDecision{Unreachable: true}, true
		}
		return RouteDecision{}, false
	}
	return routeDecisionFromBestRoute(&best, &bestSource, addr), true
}

func bestRouteRow(addr, src netip.Addr, constrained bool, index uint32) (windows.MibIpForwardRow2, windows.RawSockaddrInet, error) {
	destination := sockaddrInet(addr)
	// A nil source is the call's own way of saying "no constraint, select one
	// too", so the pointer is built here and converted inside the call rather
	// than parked in a uintptr.
	var from *windows.RawSockaddrInet
	if constrained {
		sa := sockaddrInet(src)
		from = &sa
	}
	var best windows.MibIpForwardRow2
	var bestSource windows.RawSockaddrInet
	code, _, _ := syscall.SyscallN(procGetBestRoute2.Addr(),
		0, uintptr(index),
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(&destination)),
		0, // AddressSortOptions
		uintptr(unsafe.Pointer(&best)),
		uintptr(unsafe.Pointer(&bestSource)))
	if code != 0 {
		return best, bestSource, syscall.Errno(code)
	}
	return best, bestSource, nil
}

// routeDecisionFromBestRoute reads one MIB_IPFORWARD_ROW2 into the shared
// model. Windows publishes both a route metric and an interface metric, and
// only their sum ranks two routes against each other, which is the same
// arithmetic the failed-default-route classification already does.
func routeDecisionFromBestRoute(best *windows.MibIpForwardRow2, source *windows.RawSockaddrInet, dst netip.Addr) RouteDecision {
	out := RouteDecision{Source: sockaddrInetIP(source)}
	if prefixBits := int(best.DestinationPrefix.PrefixLength); prefixBits >= 0 && prefixBits <= dst.BitLen() {
		if prefix, err := dst.Prefix(prefixBits); err == nil {
			out.Prefix = prefix
		}
	}
	if gateway := sockaddrInetIP(&best.NextHop); gateway != nil && !gateway.IsUnspecified() {
		out.Gateway = gateway
	}
	metric := uint64(best.Metric)
	if row := (mibIPInterfaceRow{Family: best.DestinationPrefix.Prefix.Family,
		InterfaceLuid: best.InterfaceLuid}); getIPInterfaceEntry(&row) == nil {
		metric += uint64(row.Metric)
	}
	if metric <= uint64(^uint32(0)) {
		out.Metric, out.MetricKnown = int(metric), true
	}
	out.Iface, out.MTU, out.Tunnel, out.TunnelKind = interfaceFacts(best.InterfaceIndex, best.InterfaceLuid)
	return out
}

// interfaceFacts reads the selected interface's name, MTU, and how much
// Windows is willing to say about what kind of device it is.
//
// The name comes from the portable interface list, so it matches what every
// other row in the report prints. The kind comes from MIB_IF_ROW2.Type, which
// is a structural property Windows maintains, not a name to pattern-match.
func interfaceFacts(index uint32, luid uint64) (name string, mtu int, state TunnelState, kind string) {
	if ifi, err := net.InterfaceByIndex(int(index)); err == nil {
		name, mtu = ifi.Name, ifi.MTU
	}
	facts := ifaceFacts{Name: name}
	row := windows.MibIfRow2{InterfaceLuid: luid, InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err == nil {
		if row.Mtu > 0 && row.Mtu <= uint32(^uint16(0)) {
			mtu = int(row.Mtu)
		}
		facts.Kind = windowsLinkKind(row.Type)
		facts.Loopback = row.Type == ifTypeSoftwareLpb
		facts.NoLinkLayer = row.PhysicalAddressLength == 0
	}
	if name == "" {
		return "", mtu, TunnelUnknown, ""
	}
	state, kind = classifyTunnel(facts)
	return name, mtu, state, kind
}

// windowsLinkKind maps the interface types Windows reports to the shared kind
// vocabulary, and returns nothing for a type that does not settle the
// question. An empty kind lets classifyTunnel fall through to the device's
// shape, which is what a WireGuard or OpenVPN adapter registered as a generic
// virtual device needs: those are reported as a likely tunnel rather than
// asserted to be one.
func windowsLinkKind(ifType uint32) string {
	switch ifType {
	case ifTypeTunnel:
		return "tunnel"
	case ifTypePPP:
		return "ppp"
	case ifTypeEthernet, ifTypeIEEE80211, ifTypeSoftwareLpb:
		return "ethernet"
	}
	// IF_TYPE_OTHER, and everything else, is the adapter declining to say. It
	// falls through to shape on purpose: a tunnel registered as a generic
	// device would otherwise be asserted to be an ordinary link.
	return ""
}

// sockaddrInet builds the SOCKADDR_INET union GetBestRoute2 takes.
func sockaddrInet(addr netip.Addr) windows.RawSockaddrInet {
	var out windows.RawSockaddrInet
	if addr.Is4() {
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&out))
		v4.Family = windows.AF_INET
		v4.Addr = addr.As4()
		return out
	}
	v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&out))
	v6.Family = windows.AF_INET6
	v6.Addr = addr.As16()
	// The scope is deliberately left at zero. A link-local destination needs
	// one to be routable, and netdoc never dials one as a target, so guessing
	// a zone here would answer a question nobody asked.
	return out
}

// defaultRoutesFor reuses the default-route reading the failed-egress
// classification already does, and renames its interfaces from index to name
// so a competing route reads the same way as the selected one.
func defaultRoutesFor(family string) []defaultRouteState {
	af := uint16(windows.AF_INET)
	if family == counterfactualIPv6 {
		af = windows.AF_INET6
	}
	var forward *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(af, &forward); err != nil {
		return nil
	}
	defer windows.FreeMibTable(unsafe.Pointer(forward))
	interfaces, freeInterfaces, err := getIPInterfaceRows(af)
	if err != nil {
		return nil
	}
	defer freeInterfaces()
	routes := windowsDefaultRoutes(af, forward.Rows(), interfaces)
	for i := range routes {
		routes[i].iface = interfaceNameForIndex(routes[i].iface)
	}
	return routes
}

// interfaceNameForIndex turns the numeric interface identity the Windows
// tables use into the name the rest of the report prints. An index with no
// name keeps its number rather than becoming empty, so a competitor is never
// silently unnamed.
func interfaceNameForIndex(index string) string {
	n, err := strconv.ParseUint(index, 10, 32)
	if err != nil {
		return index
	}
	ifi, err := net.InterfaceByIndex(int(n))
	if err != nil {
		return index
	}
	return ifi.Name
}

// unreachableRouteError separates Windows reporting that no route exists from
// every other reason the query can fail. Only the first is evidence.
func unreachableRouteError(err error) bool {
	switch err {
	case windows.ERROR_NETWORK_UNREACHABLE, windows.ERROR_HOST_UNREACHABLE, windows.ERROR_NOT_FOUND:
		return true
	}
	return false
}
