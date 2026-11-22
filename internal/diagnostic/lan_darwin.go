package diagnostic

import (
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func bindLANSocket(fd uintptr, link lanLink) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, link.Index) // #nosec G115 -- Unix file descriptor
}

func configureLANEcho(fd int, link lanLink) error {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_STRIPHDR, 1); err != nil {
		return err
	}
	return bindLANSocket(uintptr(fd), link) // #nosec G115 -- socket succeeded
}

func lanNeighbors(link lanLink) ([]netip.Addr, error) {
	rows, err := fetchRIB(unix.AF_INET, ribTypeLinkInfo, unix.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	return darwinLANNeighbors(rows, link.Index), nil
}

func lanNeighborReader(link lanLink) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) { return lanNeighbors(link) }
}

func darwinLANNeighbors(rows []route.Message, index int) []netip.Addr {
	var ips []netip.Addr
	for _, row := range rows {
		rm, ok := row.(*route.RouteMessage)
		if !ok || rm.Index != index || rm.Flags&unix.RTF_PROXY != 0 {
			continue
		}
		dst, ipOK := addrAt(rm.Addrs, unix.RTAX_DST).(*route.Inet4Addr)
		link, macOK := addrAt(rm.Addrs, unix.RTAX_GATEWAY).(*route.LinkAddr)
		if ipOK && macOK && validLANHardware(link.Addr) {
			ips = append(ips, netip.AddrFrom4(dst.IP))
		}
	}
	return ips
}
