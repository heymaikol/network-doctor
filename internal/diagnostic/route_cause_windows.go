//go:build windows

package diagnostic

import (
	"math"
	"net"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These states are inspected after reference TCP attempts have failed.
// Incomplete can mean resolution is still in progress; Unreachable records
// failed reachability detection. Neither alone proves the peer never answered.
// Other states are not classified as unresolved here.
const (
	nlNeighborUnreachable = 0
	nlNeighborIncomplete  = 1
)

// routeFailureCause reads the routing, interface, and neighbor tables through
// the IP Helper API. All three are ordinary unprivileged reads of kernel state,
// and each returns memory Windows allocated that the caller must hand back with
// FreeMibTable.
func routeFailureCause(destination net.IP) string {
	family := uint16(windows.AF_INET)
	if destination.To4() == nil {
		if destination.To16() == nil {
			return ""
		}
		family = windows.AF_INET6
	}

	var forward *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &forward); err != nil {
		return ""
	}
	defer windows.FreeMibTable(unsafe.Pointer(forward))

	// Windows route metrics are only comparable once the owning interface's
	// metric is added in, so the interface table is not optional evidence.
	var interfaces *windows.MibIpInterfaceTable
	if err := windows.GetIpInterfaceTable(family, &interfaces); err != nil {
		return ""
	}
	defer windows.FreeMibTable(unsafe.Pointer(interfaces))

	// A neighbor table we could not read is not evidence of a healthy
	// neighbor, so on failure the list stays empty and no gateway is accused.
	neighbors, free, err := getIPNetTable2(family)
	if err == nil {
		defer free()
	}

	return routeFailureCauseFromTables(family, forward.Rows(), ipInterfaceRows(interfaces), neighbors)
}

func routeFailureCauseFromTables(family uint16, routes []windows.MibIpForwardRow2,
	interfaces []windows.MibIpInterfaceRow, neighbors []mibIPNetRow2) string {
	return classifyDefaultRoutes(windowsDefaultRoutes(family, routes, interfaces), func(r defaultRouteState) bool {
		return r.gateway != nil && windowsNeighborUnresolved(family, neighbors, r.gateway, r.iface)
	})
}

// windowsDefaultRoutes keeps the zero-length-prefix routes of this family whose
// interface is connected and is allowed to carry default routes.
func windowsDefaultRoutes(family uint16, routes []windows.MibIpForwardRow2,
	interfaces []windows.MibIpInterfaceRow) []defaultRouteState {
	usable := make(map[uint64]uint32, len(interfaces))
	for i := range interfaces {
		row := &interfaces[i]
		if row.Family != family || row.Connected == 0 || row.DisableDefaultRoutes != 0 {
			continue
		}
		usable[row.InterfaceLuid] = row.Metric
	}
	var out []defaultRouteState
	for i := range routes {
		row := &routes[i]
		if row.DestinationPrefix.PrefixLength != 0 || row.DestinationPrefix.Prefix.Family != family {
			continue
		}
		if prefix := sockaddrInetIP(&row.DestinationPrefix.Prefix); prefix == nil || !prefix.IsUnspecified() {
			continue
		}
		interfaceMetric, ok := usable[row.InterfaceLuid]
		if !ok {
			continue
		}
		// Both halves are uint32, so their sum is widened before it is
		// narrowed to the int the comparison uses.
		metric := uint64(row.Metric) + uint64(interfaceMetric)
		if metric > math.MaxInt32 {
			metric = math.MaxInt32
		}
		// The unspecified next hop is how Windows spells an on-link default
		// route, which has no neighbor to resolve.
		gateway := sockaddrInetIP(&row.NextHop)
		if gateway != nil && gateway.IsUnspecified() {
			gateway = nil
		}
		out = append(out, defaultRouteState{iface: strconv.FormatUint(uint64(row.InterfaceIndex), 10),
			gateway: gateway, metric: int(metric)})
	}
	return out
}

// windowsNeighborUnresolved reports that the neighbor table holds an entry for
// this gateway on this interface and Windows has placed that entry in a state
// meaning unresolved or unreachable at the time of inspection. An absent entry
// proves nothing and is not a failure. Neither does an empty PhysicalAddress:
// point-to-point and tunnel media have no link-layer addresses to resolve, so reading that as a
// dead gateway would invent a failure the state field says is not there.
func windowsNeighborUnresolved(family uint16, neighbors []mibIPNetRow2, gateway net.IP, iface string) bool {
	for i := range neighbors {
		row := &neighbors[i]
		if strconv.FormatUint(uint64(row.InterfaceIndex), 10) != iface || row.Address.Family != family {
			continue
		}
		if !gateway.Equal(sockaddrInetIP(&row.Address)) {
			continue
		}
		return row.State == nlNeighborUnreachable || row.State == nlNeighborIncomplete
	}
	return false
}

// sockaddrInetIP copies the address out of a SOCKADDR_INET union. The copy
// matters: the union lives in memory owned by Windows that is freed as soon as
// the table it came from is released.
func sockaddrInetIP(addr *windows.RawSockaddrInet) net.IP {
	switch addr.Family {
	case windows.AF_INET:
		return append(net.IP(nil), (*windows.RawSockaddrInet4)(unsafe.Pointer(addr)).Addr[:]...)
	case windows.AF_INET6:
		return append(net.IP(nil), (*windows.RawSockaddrInet6)(unsafe.Pointer(addr)).Addr[:]...)
	}
	return nil
}

// MibIpInterfaceTable is a header followed by a variable-length row array, the
// same shape MibIpForwardTable2 already has a Rows accessor for.
func ipInterfaceRows(table *windows.MibIpInterfaceTable) []windows.MibIpInterfaceRow {
	return unsafe.Slice(&table.Table[0], table.NumEntries)
}

// mibIPNetRow2 is MIB_IPNET_ROW2, the neighbor (ARP and NDP) cache entry.
// x/sys/windows wraps the routing and interface tables but not this one, so the
// layout is declared here. The trailing pad is the C compiler's, keeping the
// 4-byte reachability time on its own alignment after the flags byte.
type mibIPNetRow2 struct {
	Address               windows.RawSockaddrInet
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	_                     [3]byte
	ReachabilityTime      uint32
}

// mibIPNetTable2 is MIB_IPNET_TABLE2. The pad is explicit rather than left to
// Go's alignment rules, so the row array keeps its C offset of 8 even where Go
// would align the row's 64-bit LUID to 4.
type mibIPNetTable2 struct {
	NumEntries uint32
	_          [4]byte
	Table      [1]mibIPNetRow2
}

var (
	modiphlpapi        = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2 = modiphlpapi.NewProc("GetIpNetTable2")
)

// getIPNetTable2 returns the neighbor cache and the function that releases it.
// The rows alias memory Windows allocated, so they must not outlive that call.
func getIPNetTable2(family uint16) ([]mibIPNetRow2, func(), error) {
	if err := procGetIpNetTable2.Find(); err != nil {
		return nil, nil, err
	}
	// The conversion has to sit inside the syscall call expression: that is
	// the only form the compiler keeps valid if the stack moves between here
	// and the call, and it is how x/sys/windows spells its own wrappers.
	var table *mibIPNetTable2
	code, _, _ := syscall.SyscallN(procGetIpNetTable2.Addr(), uintptr(family), uintptr(unsafe.Pointer(&table)))
	if code != 0 {
		return nil, nil, syscall.Errno(code)
	}
	free := func() { windows.FreeMibTable(unsafe.Pointer(table)) }
	if table.NumEntries == 0 {
		return nil, free, nil
	}
	return unsafe.Slice(&table.Table[0], table.NumEntries), free, nil
}
