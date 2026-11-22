package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func bindLANSocket(fd uintptr, link lanLink) error {
	const ipUnicastIf = 31
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(link.Index)) // #nosec G115 -- Windows interface index is a DWORD
	return windows.SetsockoptInet4Addr(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, index)
}

var (
	procIcmpCreateFile  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = modiphlpapi.NewProc("IcmpSendEcho2Ex")
)

func lanEchoProbe(link lanLink) (lanProbe, error) {
	if link.sharedSource {
		return nil, errors.New("IPv4 source is shared by multiple interfaces")
	}
	selected, err := currentWindowsLANInterface(link.Index)
	if err != nil {
		return nil, err
	}
	for _, proc := range []*windows.LazyProc{procIcmpCreateFile, procIcmpCloseHandle, procIcmpSendEcho2Ex, procGetBestRoute2} {
		if err := proc.Find(); err != nil {
			return nil, err
		}
	}
	src := windowsEchoAddr(link.source)
	return func(ctx context.Context, dst netip.Addr) (bool, error) {
		if ctx.Err() != nil {
			return false, nil
		}
		h, _, err := syscall.SyscallN(procIcmpCreateFile.Addr())
		if h == uintptr(windows.InvalidHandle) {
			return false, err
		}
		defer func() { _, _, _ = syscall.SyscallN(procIcmpCloseHandle.Addr(), h) }()
		if err := checkWindowsLANEchoPath(link, selected.InterfaceLuid, dst); err != nil {
			return false, err
		}
		deadline, _ := ctx.Deadline()
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			return false, nil
		}
		// Both Windows reply layouts start with address and IP status. The
		// remaining storage holds the native reply structure and error data.
		var reply struct {
			address, status uint32
			storage         [63]uint64
		}
		dest := windowsEchoAddr(dst)
		var payload [8]byte
		count, _, sendErr := syscall.SyscallN(procIcmpSendEcho2Ex.Addr(), h, 0, 0, 0, uintptr(src), uintptr(dest),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
			uintptr(unsafe.Pointer(&reply)), unsafe.Sizeof(reply), uintptr(max(1, remaining.Milliseconds()))) // #nosec G115 -- positive, bounded duration in milliseconds
		if count == 0 && (sendErr == windows.ERROR_ACCESS_DENIED || sendErr == windows.ERROR_NOT_SUPPORTED) {
			return false, sendErr
		}
		return count != 0 && reply.status == 0 && reply.address == dest, nil
	}, nil
}

// shortcut: IcmpSendEcho2Ex takes a source address only. These independent
// lookups cannot pin the send. Use a bound echo API if Windows provides one.
func checkWindowsLANEchoPath(link lanLink, luid uint64, dst netip.Addr) error {
	selected, err := currentWindowsLANInterface(link.Index)
	if err != nil {
		return err
	}
	if selected.InterfaceLuid != luid {
		return fmt.Errorf("IPv4 interface index %d changed during discovery", link.Index)
	}
	var table *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); err != nil {
		return fmt.Errorf("read IPv4 source ownership: %w", err)
	}
	if table == nil {
		return errors.New("IP Helper returned a nil IPv4 unicast address table")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	if err := windowsLANEchoSourceError(link, selected, unsafe.Slice(&table.Table[0], table.NumEntries)); err != nil {
		return err
	}
	route, source, err := bestRouteRow(dst, link.source, true, selected.InterfaceIndex)
	if err != nil {
		return fmt.Errorf("look up the on-link IPv4 route: %w", err)
	}
	return windowsLANEchoRouteError(link, selected, dst, route, source)
}

func currentWindowsLANInterface(index int) (mibIPInterfaceRow, error) {
	rows, free, err := getIPInterfaceRows(windows.AF_INET)
	if err != nil {
		return mibIPInterfaceRow{}, err
	}
	defer free()
	return windowsLANEchoInterface(index, rows)
}

func windowsLANEchoInterface(selected int, rows []mibIPInterfaceRow) (mibIPInterfaceRow, error) {
	var match mibIPInterfaceRow
	for _, row := range rows {
		if row.Family != windows.AF_INET {
			continue
		}
		if row.WeakHostSend != 0 || row.WeakHostReceive != 0 {
			return mibIPInterfaceRow{}, fmt.Errorf("IPv4 weak-host routing is enabled on interface index %d", row.InterfaceIndex)
		}
		if int(row.InterfaceIndex) == selected {
			if match.InterfaceIndex != 0 || row.InterfaceLuid == 0 || row.Connected == 0 {
				return mibIPInterfaceRow{}, fmt.Errorf("selected IPv4 interface index %d is disconnected or ambiguous", selected)
			}
			match = row
		}
	}
	if match.InterfaceIndex == 0 {
		return mibIPInterfaceRow{}, fmt.Errorf("selected IPv4 interface index %d is missing from the IP Helper table", selected)
	}
	return match, nil
}

func windowsLANEchoSourceError(link lanLink, selected mibIPInterfaceRow, rows []windows.MibUnicastIpAddressRow) error {
	found := false
	source := windowsEchoAddr(link.source)
	for _, row := range rows {
		// Flowinfo and the IPv4 address share offset 4 in SOCKADDR_INET.
		if row.Address.Family != windows.AF_INET || row.Address.Flowinfo != source {
			continue
		}
		if found || row.InterfaceIndex != selected.InterfaceIndex || row.InterfaceLuid != selected.InterfaceLuid {
			return fmt.Errorf("IPv4 source %s moved or is shared by multiple interfaces", link.source)
		}
		if row.DadState != windows.IpDadStatePreferred || row.SkipAsSource != 0 || row.ValidLifetime == 0 ||
			int(row.OnLinkPrefixLength) != link.prefix.Bits() {
			return fmt.Errorf("IPv4 source %s is no longer valid for this LAN sweep", link.source)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("IPv4 source %s is missing from the unicast address table", link.source)
	}
	return nil
}

func windowsLANEchoRouteError(link lanLink, selected mibIPInterfaceRow, dst netip.Addr, route windows.MibIpForwardRow2, source windows.RawSockaddrInet) error {
	if route.InterfaceIndex != selected.InterfaceIndex || route.InterfaceLuid != selected.InterfaceLuid ||
		route.Loopback != 0 || source.Family != windows.AF_INET || !sockaddrInetIP(&source).Equal(link.source.AsSlice()) {
		return errors.New("IPv4 route does not match the selected interface and source")
	}
	ip, _ := netip.AddrFromSlice(sockaddrInetIP(&route.DestinationPrefix.Prefix))
	prefix := netip.PrefixFrom(ip, int(route.DestinationPrefix.PrefixLength))
	hop := route.NextHop
	onLink := hop == (windows.RawSockaddrInet{}) || hop.Family == windows.AF_INET && sockaddrInetIP(&hop).IsUnspecified()
	if !prefix.IsValid() || prefix.Bits() == 0 || !prefix.Contains(dst) || !onLink {
		return fmt.Errorf("IPv4 route to %s is not on-link", dst)
	}
	return nil
}

func windowsEchoAddr(ip netip.Addr) uint32 {
	b := ip.As4()
	return binary.NativeEndian.Uint32(b[:])
}

func lanNeighbors(link lanLink) ([]netip.Addr, error) {
	rows, free, err := getIPNetTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	defer free()
	return windowsLANNeighbors(rows, link.Index), nil
}

func windowsLANNeighbors(rows []mibIPNetRow2, index int) []netip.Addr {
	var ips []netip.Addr
	for i := range rows {
		row := &rows[i]
		if int(row.InterfaceIndex) != index || row.Address.Family != windows.AF_INET ||
			row.State <= nlNeighborIncomplete || row.PhysicalAddressLength > uint32(len(row.PhysicalAddress)) ||
			!validLANHardware(row.PhysicalAddress[:row.PhysicalAddressLength]) {
			continue
		}
		if ip, ok := netip.AddrFromSlice(sockaddrInetIP(&row.Address)); ok {
			ips = append(ips, ip.Unmap())
		}
	}
	return ips
}
