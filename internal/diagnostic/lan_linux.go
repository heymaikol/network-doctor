package diagnostic

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func bindLANSocket(fd uintptr, link lanLink) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BINDTOIFINDEX, link.Index) // #nosec G115 -- Unix file descriptor
}

func configureLANEcho(fd int, link lanLink) error {
	return bindLANSocket(uintptr(fd), link) // #nosec G115 -- socket succeeded
}

func lanNeighbors(link lanLink) ([]netip.Addr, error) {
	raw, err := os.ReadFile(procARPTable)
	if err != nil {
		return nil, err
	}
	return linuxLANNeighbors(string(raw), link.Name), nil
}

func lanNeighborReader(link lanLink) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) { return lanNeighbors(link) }
}

func linuxLANNeighbors(raw, iface string) []netip.Addr {
	var ips []netip.Addr
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 6 || fields[5] != iface {
			continue
		}
		const complete, published = 0x02, 0x08
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&complete == 0 || flags&published != 0 {
			continue
		}
		ip, ipErr := netip.ParseAddr(fields[0])
		mac, macErr := net.ParseMAC(fields[3])
		if ipErr == nil && ip.Is4() && macErr == nil && validLANHardware(mac) {
			ips = append(ips, ip)
		}
	}
	return ips
}
