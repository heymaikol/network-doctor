package diagnostic

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsLANEchoRejectsWeakHostInterfaces(t *testing.T) {
	const selected = 7
	wifi := mibIPInterfaceRow{Family: windows.AF_INET, InterfaceIndex: selected, InterfaceLuid: 7, Connected: 1}
	vpn := mibIPInterfaceRow{Family: windows.AF_INET, InterfaceIndex: 18}
	virtual := mibIPInterfaceRow{Family: windows.AF_INET, InterfaceIndex: 31}
	vpnSend, virtualReceive, wifiBoth, ipv6Only, disconnected := vpn, virtual, wifi, virtual, wifi
	disconnected.Connected = 0
	vpnSend.WeakHostSend, virtualReceive.WeakHostReceive = 1, 1
	wifiBoth.WeakHostSend, wifiBoth.WeakHostReceive = 1, 1
	ipv6Only.Family, ipv6Only.WeakHostSend, ipv6Only.WeakHostReceive = windows.AF_INET6, 1, 1
	for _, tc := range []struct {
		name string
		rows []mibIPInterfaceRow
		want string
	}{
		{"strong host with VPN and virtual adapters", []mibIPInterfaceRow{vpn, wifi, virtual}, ""},
		{"weak selected Wi-Fi", []mibIPInterfaceRow{wifiBoth, vpn, virtual}, "enabled on interface index 7"},
		{"weak send on a separate VPN", []mibIPInterfaceRow{wifi, vpnSend, virtual}, "enabled on interface index 18"},
		{"weak receive on a separate virtual adapter", []mibIPInterfaceRow{wifi, vpn, virtualReceive}, "enabled on interface index 31"},
		{"weak IPv6 on a virtual adapter", []mibIPInterfaceRow{wifi, vpn, ipv6Only}, ""},
		{"duplicate selected index", []mibIPInterfaceRow{wifi, wifi}, "disconnected or ambiguous"},
		{"disconnected selected interface", []mibIPInterfaceRow{vpn, disconnected}, "disconnected or ambiguous"},
		{"missing selected interface", []mibIPInterfaceRow{vpn, virtual}, "interface index 7 is missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := windowsLANEchoInterface(selected, tc.rows)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("strong IPv4 path rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestWindowsLANEchoSourceAndRoute(t *testing.T) {
	source := netip.MustParseAddr("192.168.1.240")
	peer := netip.MustParseAddr("192.168.1.206")
	link := lanLink{source: source, prefix: netip.MustParsePrefix("192.168.1.0/24")}
	selected := mibIPInterfaceRow{InterfaceIndex: 9, InterfaceLuid: 42}
	owner := windows.MibUnicastIpAddressRow{
		Address:        windows.RawSockaddrInet6{Family: windows.AF_INET, Flowinfo: windowsEchoAddr(source)},
		InterfaceIndex: 9, InterfaceLuid: 42, OnLinkPrefixLength: 24,
		DadState: windows.IpDadStatePreferred, ValidLifetime: 3600,
	}
	other := owner
	other.InterfaceIndex, other.InterfaceLuid = 17, 77
	deprecated := owner
	deprecated.DadState = windows.IpDadStateDeprecated
	for _, tc := range []struct {
		name string
		rows []windows.MibUnicastIpAddressRow
		ok   bool
	}{
		{"unique usable source", []windows.MibUnicastIpAddressRow{owner}, true},
		{"missing", nil, false},
		{"moved to another interface", []windows.MibUnicastIpAddressRow{other}, false},
		{"duplicated across interfaces", []windows.MibUnicastIpAddressRow{owner, other}, false},
		{"deprecated", []windows.MibUnicastIpAddressRow{deprecated}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := windowsLANEchoSourceError(link, selected, tc.rows); (err == nil) != tc.ok {
				t.Fatalf("source validation: %v, want success %t", err, tc.ok)
			}
		})
	}

	onLink := windows.MibIpForwardRow2{
		InterfaceIndex: 9, InterfaceLuid: 42, NextHop: sockaddrInet(netip.IPv4Unspecified()),
		DestinationPrefix: windows.IpAddressPrefix{Prefix: sockaddrInet(link.prefix.Addr()), PrefixLength: 24},
	}
	wrongLink, gateway, loopback, wrongNetwork, zeroHop, wrongHopFamily := onLink, onLink, onLink, onLink, onLink, onLink
	wrongLink.InterfaceLuid = 77 // index reused by a different interface
	gateway.NextHop = sockaddrInet(netip.MustParseAddr("192.168.1.1"))
	loopback.Loopback = 1
	wrongNetwork.DestinationPrefix.Prefix = sockaddrInet(netip.MustParseAddr("192.168.2.0"))
	zeroHop.NextHop = windows.RawSockaddrInet{}
	wrongHopFamily.NextHop = sockaddrInet(netip.IPv6Unspecified())
	for _, tc := range []struct {
		name   string
		route  windows.MibIpForwardRow2
		source netip.Addr
		ok     bool
	}{
		{"on-link from selected source", onLink, source, true},
		{"all-zero on-link next hop", zeroHop, source, true},
		{"IPv6 next hop on IPv4 route", wrongHopFamily, source, false},
		{"different interface with original index", wrongLink, source, false},
		{"different source", onLink, netip.MustParseAddr("192.168.1.3"), false},
		{"gateway", gateway, source, false},
		{"loopback", loopback, source, false},
		{"mismatched route prefix", wrongNetwork, source, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := windowsLANEchoRouteError(link, selected, peer, tc.route, sockaddrInet(tc.source)); (err == nil) != tc.ok {
				t.Fatalf("route validation: %v, want success %t", err, tc.ok)
			}
		})
	}
}

func TestWindowsLANUnicastTableLayout(t *testing.T) {
	var row windows.MibUnicastIpAddressRow
	var table windows.MibUnicastIpAddressTable
	// SDK sockaddr union and LARGE_INTEGER alignment on the release targets.
	got := [...]uintptr{unsafe.Offsetof(table.Table), unsafe.Sizeof(row), unsafe.Offsetof(row.Address.Flowinfo),
		unsafe.Offsetof(row.InterfaceLuid), unsafe.Offsetof(row.InterfaceIndex), unsafe.Offsetof(row.ValidLifetime),
		unsafe.Offsetof(row.OnLinkPrefixLength), unsafe.Offsetof(row.SkipAsSource), unsafe.Offsetof(row.DadState)}
	if want := [...]uintptr{8, 80, 4, 32, 40, 52, 60, 61, 64}; got != want {
		t.Fatalf("unicast table offset, stride and row field offsets = %v, want %v", got, want)
	}
}

func TestWindowsLANNeighbors(t *testing.T) {
	mac := []byte{2, 1, 2, 3, 4, 5}
	overlong := neighborRow(7, "10.0.0.7", nlNeighborReachable, mac)
	overlong.PhysicalAddressLength = 33
	rows := []mibIPNetRow2{
		neighborRow(7, "10.0.0.1", nlNeighborStale, mac),
		neighborRow(7, "10.0.0.2", nlNeighborReachable, mac),
		neighborRow(8, "10.0.0.3", nlNeighborReachable, mac),
		neighborRow(7, "10.0.0.4", nlNeighborIncomplete, mac),
		neighborRow(7, "10.0.0.5", nlNeighborUnreachable, mac),
		neighborRow(7, "10.0.0.6", nlNeighborStale, nil),
		neighborRow(7, "fe80::1", nlNeighborStale, mac),
		overlong,
	}
	if got := windowsLANNeighbors(rows, 7); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}) {
		t.Fatalf("selected neighbors = %v", got)
	}
	if got := windowsEchoAddr(netip.MustParseAddr("10.20.30.40")); got != 0x281e140a {
		t.Fatalf("ICMP IPAddr memory order = %x", got)
	}
}
