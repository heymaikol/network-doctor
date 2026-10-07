//go:build windows

package diagnostic

import (
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sockaddr builds the SOCKADDR_INET union the IP Helper tables carry, so a
// test row can be written the way Windows reports one.
func sockaddr(ip string) windows.RawSockaddrInet {
	var raw windows.RawSockaddrInet
	parsed := net.ParseIP(ip)
	if v4 := parsed.To4(); v4 != nil {
		raw.Family = windows.AF_INET
		copy((*windows.RawSockaddrInet4)(unsafe.Pointer(&raw)).Addr[:], v4)
		return raw
	}
	raw.Family = windows.AF_INET6
	copy((*windows.RawSockaddrInet6)(unsafe.Pointer(&raw)).Addr[:], parsed.To16())
	return raw
}

func forwardRow(luid uint64, index uint32, prefixLength uint8, destination, nextHop string, metric uint32) windows.MibIpForwardRow2 {
	return windows.MibIpForwardRow2{
		InterfaceLuid:     luid,
		InterfaceIndex:    index,
		DestinationPrefix: windows.IpAddressPrefix{Prefix: sockaddr(destination), PrefixLength: prefixLength},
		NextHop:           sockaddr(nextHop),
		Metric:            metric,
	}
}

func interfaceRow(family uint16, luid uint64, index uint32, metric uint32, connected, disableDefaults uint8) windows.MibIpInterfaceRow {
	return windows.MibIpInterfaceRow{
		Family: family, InterfaceLuid: luid, InterfaceIndex: index,
		Metric: metric, Connected: connected, DisableDefaultRoutes: disableDefaults,
	}
}

func neighborRow(index uint32, address string, state uint32, hardware []byte) mibIPNetRow2 {
	row := mibIPNetRow2{Address: sockaddr(address), InterfaceIndex: index, State: state}
	row.PhysicalAddressLength = uint32(copy(row.PhysicalAddress[:], hardware))
	return row
}

const (
	v4Default = "0.0.0.0"
	v6Default = "::"
	// The neighbour states the production code must not read as a failure.
	nlNeighborStale     = 4
	nlNeighborReachable = 5
)

func TestRouteFailureCauseFromTables(t *testing.T) {
	mac := []byte{0x02, 0x00, 0x5e, 0x10, 0x00, 0x01}
	up := interfaceRow(windows.AF_INET, 1, 4, 25, 1, 0)
	viaGateway := forwardRow(1, 4, 0, v4Default, "10.77.1.1", 0)

	tests := []struct {
		name       string
		family     uint16
		routes     []windows.MibIpForwardRow2
		interfaces []windows.MibIpInterfaceRow
		neighbors  []mibIPNetRow2
		want       string
	}{
		{"empty tables are no default route", windows.AF_INET, nil, nil, nil, RouteCauseNoDefaultRoute},
		{"a subnet route is not a default route", windows.AF_INET,
			[]windows.MibIpForwardRow2{forwardRow(1, 4, 24, "10.77.1.0", "0.0.0.0", 0)},
			[]windows.MibIpInterfaceRow{up}, nil, RouteCauseNoDefaultRoute},
		{"a default route on a disconnected interface is unusable", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway},
			[]windows.MibIpInterfaceRow{interfaceRow(windows.AF_INET, 1, 4, 25, 0, 0)}, nil, RouteCauseNoDefaultRoute},
		{"an interface barred from default routes is unusable", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway},
			[]windows.MibIpInterfaceRow{interfaceRow(windows.AF_INET, 1, 4, 25, 1, 1)}, nil, RouteCauseNoDefaultRoute},
		{"a route whose interface is missing from the table is unusable", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, nil, nil, RouteCauseNoDefaultRoute},
		{"a reachable neighbour leaves the gateway unaccused", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborReachable, mac)}, RouteCauseSelectedPathFailed},
		{"a stale neighbour still has an address and is not a failure", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborStale, mac)}, RouteCauseSelectedPathFailed},
		{"an incomplete neighbour is a dead gateway", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborIncomplete, nil)}, RouteCauseGatewayUnreachable},
		{"an unreachable neighbour is a dead gateway", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborUnreachable, mac)}, RouteCauseGatewayUnreachable},
		// Point-to-point and tunnel media carry no link-layer addresses, so an
		// empty PhysicalAddress on a neighbour Windows calls reachable is not
		// evidence of anything. Only the state field decides.
		{"a reachable neighbour with no hardware address is not a dead gateway", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborReachable, nil)}, RouteCauseSelectedPathFailed},
		{"an absent neighbour entry proves nothing", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up}, nil, RouteCauseSelectedPathFailed},
		{"a dead neighbour on another interface is not this gateway", windows.AF_INET,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(9, "10.77.1.1", nlNeighborIncomplete, nil)}, RouteCauseSelectedPathFailed},
		{"an on-link default route has no next hop to resolve", windows.AF_INET,
			[]windows.MibIpForwardRow2{forwardRow(1, 4, 0, v4Default, "0.0.0.0", 0)},
			[]windows.MibIpInterfaceRow{up},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborIncomplete, nil)}, RouteCauseSelectedPathFailed},
		// The route metrics alone would prefer the second interface. The
		// effective metric Windows routes by is the route metric plus the
		// interface metric, which prefers the first, and a gateway verdict
		// pinned to the wrong route is exactly the misdiagnosis to avoid.
		{"the interface metric decides which default route is preferred", windows.AF_INET,
			[]windows.MibIpForwardRow2{
				forwardRow(1, 4, 0, v4Default, "10.77.1.1", 100),
				forwardRow(2, 9, 0, v4Default, "10.77.3.1", 0)},
			[]windows.MibIpInterfaceRow{up, interfaceRow(windows.AF_INET, 2, 9, 200, 1, 0)},
			nil, RouteCausePreferredPathFailed},
		{"equally weighted defaults are load sharing, not preference", windows.AF_INET,
			[]windows.MibIpForwardRow2{
				forwardRow(1, 4, 0, v4Default, "10.77.1.1", 0),
				forwardRow(2, 9, 0, v4Default, "10.77.3.1", 0)},
			[]windows.MibIpInterfaceRow{up, interfaceRow(windows.AF_INET, 2, 9, 25, 1, 0)},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborIncomplete, nil)}, RouteCauseSelectedPathFailed},
		{"every equally weighted gateway dead is a dead gateway", windows.AF_INET,
			[]windows.MibIpForwardRow2{
				forwardRow(1, 4, 0, v4Default, "10.77.1.1", 0),
				forwardRow(2, 9, 0, v4Default, "10.77.3.1", 0)},
			[]windows.MibIpInterfaceRow{up, interfaceRow(windows.AF_INET, 2, 9, 25, 1, 0)},
			[]mibIPNetRow2{neighborRow(4, "10.77.1.1", nlNeighborIncomplete, nil),
				neighborRow(9, "10.77.3.1", nlNeighborIncomplete, nil)}, RouteCauseGatewayUnreachable},
		{"an IPv4 default route is not an IPv6 default route", windows.AF_INET6,
			[]windows.MibIpForwardRow2{viaGateway}, []windows.MibIpInterfaceRow{up}, nil, RouteCauseNoDefaultRoute},
		{"an IPv4 interface does not carry an IPv6 route", windows.AF_INET6,
			[]windows.MibIpForwardRow2{forwardRow(1, 4, 0, v6Default, "fe80::1", 0)},
			[]windows.MibIpInterfaceRow{up}, nil, RouteCauseNoDefaultRoute},
		{"an incomplete NDP entry is a dead IPv6 gateway", windows.AF_INET6,
			[]windows.MibIpForwardRow2{forwardRow(1, 4, 0, v6Default, "fe80::1", 0)},
			[]windows.MibIpInterfaceRow{interfaceRow(windows.AF_INET6, 1, 4, 25, 1, 0)},
			[]mibIPNetRow2{neighborRow(4, "fe80::1", nlNeighborIncomplete, nil)}, RouteCauseGatewayUnreachable},
		{"a resolved NDP entry leaves the IPv6 gateway unaccused", windows.AF_INET6,
			[]windows.MibIpForwardRow2{forwardRow(1, 4, 0, v6Default, "fe80::1", 0)},
			[]windows.MibIpInterfaceRow{interfaceRow(windows.AF_INET6, 1, 4, 25, 1, 0)},
			[]mibIPNetRow2{neighborRow(4, "fe80::1", nlNeighborReachable, mac)}, RouteCauseSelectedPathFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeFailureCauseFromTables(tc.family, tc.routes, tc.interfaces, tc.neighbors); got != tc.want {
				t.Errorf("cause = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRouteFailureCauseAddressFamilyGuard pins the only judgement made before
// any IP Helper table is read: an address of neither family gets no diagnosis.
func TestRouteFailureCauseAddressFamilyGuard(t *testing.T) {
	if got := routeFailureCause(net.IP{1, 2, 3}); got != "" {
		t.Errorf("cause for a malformed address = %q, want empty", got)
	}
}

// TestMibIPNetRow2MatchesTheDocumentedLayout pins the hand-declared
// MIB_IPNET_ROW2 against the field offsets iphlpapi.h lays it out at. Windows
// fills this memory, so a drifted offset would read a neighbour's state out of
// the middle of its hardware address and invent a dead gateway.
func TestMibIPNetRow2MatchesTheDocumentedLayout(t *testing.T) {
	var row mibIPNetRow2
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Address", unsafe.Offsetof(row.Address), 0},
		{"InterfaceIndex", unsafe.Offsetof(row.InterfaceIndex), 28},
		{"InterfaceLuid", unsafe.Offsetof(row.InterfaceLuid), 32},
		{"PhysicalAddress", unsafe.Offsetof(row.PhysicalAddress), 40},
		{"PhysicalAddressLength", unsafe.Offsetof(row.PhysicalAddressLength), 72},
		{"State", unsafe.Offsetof(row.State), 76},
		{"Flags", unsafe.Offsetof(row.Flags), 80},
		{"ReachabilityTime", unsafe.Offsetof(row.ReachabilityTime), 84},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("MIB_IPNET_ROW2.%s at offset %d, want %d", o.name, o.got, o.want)
		}
	}
	if got := unsafe.Sizeof(row); got != 88 {
		t.Errorf("sizeof MIB_IPNET_ROW2 = %d, want 88", got)
	}
	var table mibIPNetTable2
	if got := unsafe.Offsetof(table.Table); got != 8 {
		t.Errorf("MIB_IPNET_TABLE2.Table at offset %d, want 8", got)
	}
}

// TestWindowsIPHelperTablesAvailable is the availability half of this file: the
// unit tests above prove the reasoning, and this proves the three IP Helper
// calls the reasoning is fed by still succeed on the Windows actually running
// the test, including the hand-wrapped GetIpNetTable2. It reads local kernel
// state only and asserts nothing about its contents.
func TestWindowsIPHelperTablesAvailable(t *testing.T) {
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		var forward *windows.MibIpForwardTable2
		if err := windows.GetIpForwardTable2(family, &forward); err != nil {
			t.Errorf("GetIpForwardTable2(%d): %v", family, err)
		} else {
			windows.FreeMibTable(unsafe.Pointer(forward))
		}
		var interfaces *windows.MibIpInterfaceTable
		if err := windows.GetIpInterfaceTable(family, &interfaces); err != nil {
			t.Errorf("GetIpInterfaceTable(%d): %v", family, err)
		} else {
			windows.FreeMibTable(unsafe.Pointer(interfaces))
		}
		if _, free, err := getIPNetTable2(family); err != nil {
			t.Errorf("GetIpNetTable2(%d): %v", family, err)
		} else {
			free()
		}
	}
}
