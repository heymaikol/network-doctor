package diagnostic

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// ResolveSource resolves an interface name to one usable address per family,
// or an exact local IP to only that address's family.
// Interface names prefer non-link-local addresses within each family.
func ResolveSource(iface string) (*SourceAddresses, error) {
	if want := net.ParseIP(iface); want != nil {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("list interfaces: %w", err)
		}
		for i := range ifaces {
			addrs, err := ifaces[i].Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipFromAddr(addr).Equal(want) {
					return sourceAddresses([]net.Addr{&net.IPAddr{IP: want}}), nil
				}
			}
		}
		return nil, fmt.Errorf("source IP %s is not assigned to a local interface", want)
	}
	chosen, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}
	addrs, err := chosen.Addrs()
	if err != nil {
		return nil, fmt.Errorf("addresses for interface %q: %w", iface, err)
	}
	if sources := sourceAddresses(addrs); sources != nil {
		sources.Iface = chosen.Name
		return sources, nil
	}
	return nil, fmt.Errorf("interface %q has no usable IP address", iface)
}

func ipFromAddr(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPNet:
		return a.IP
	case *net.IPAddr:
		return a.IP
	}
	return nil
}

func sourceAddresses(addrs []net.Addr) *SourceAddresses {
	var sources SourceAddresses
	for _, addr := range addrs {
		ip := ipFromAddr(addr)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			if sources.IPv4 == nil || sources.IPv4.IsLinkLocalUnicast() && !ip4.IsLinkLocalUnicast() {
				sources.IPv4 = append(net.IP(nil), ip4...)
			}
		} else if sources.IPv6 == nil || sources.IPv6.IsLinkLocalUnicast() && !ip.IsLinkLocalUnicast() {
			sources.IPv6 = append(net.IP(nil), ip...)
		}
	}
	if sources.IPv4 == nil && sources.IPv6 == nil {
		return nil
	}
	return &sources
}

func (s SourceAddresses) primary() net.IP {
	if s.IPv4 != nil {
		return s.IPv4
	}
	return s.IPv6
}

func containsSources(addrs []net.Addr, want *SourceAddresses) bool {
	found4, found6 := want.IPv4 == nil, want.IPv6 == nil
	for _, addr := range addrs {
		ip := ipFromAddr(addr)
		found4 = found4 || ip.Equal(want.IPv4)
		found6 = found6 || ip.Equal(want.IPv6)
	}
	return found4 && found6
}

// routedInterface names the interface that carries general Internet traffic,
// when the run's reference routes identify one and that route lands on a
// usable interface. referenceRouteDecisions come back ordered IPv4 then IPv6,
// which is the preference: IPv4 is the default route almost every machine has,
// and a v6-only host still yields a v6 decision. A routed interface that is not
// usable (down, loopback, or a name the kernel and the interface list do not
// share) is skipped.
//
// usable lists the interfaces that are up, running, and not loopback, as
// discovered once in ifaceProbe. It answers "" when routing cannot name a
// usable interface, which leaves the enumeration-order fallback, and when the
// interface was pinned by --iface or a source, which already names the
// interface on purpose.
//
// ponytail: this reads referenceRouteDecisions, the reference routes the iface
// probe already reports, so it reuses the kernel lookup the pass collected
// rather than asking the routing table a second time.
func (o *netops) routedInterface(usable []string) string {
	if o.sources != nil {
		return ""
	}
	set := map[string]bool{}
	for _, name := range usable {
		set[name] = true
	}
	for _, d := range o.referenceRouteDecisions() {
		if d.Iface != "" && set[d.Iface] {
			return d.Iface
		}
	}
	return ""
}

func (o *netops) ifaceProbe(_ context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	var r ProbeResult
	ifaces, err := o.interfaces()
	if err != nil {
		r.Status = StatusFail
		r.Detail, r.Fix = "cannot list interfaces: "+err.Error(), "check permissions / network stack"
		return r
	}
	if o.sources != nil {
		var matches []net.Interface
		for i := range ifaces {
			addrs, err := o.interfaceAddrs(&ifaces[i])
			if err != nil {
				continue
			}
			if containsSources(addrs, o.sources) {
				matches = append(matches, ifaces[i])
			}
		}
		primary := o.sources.primary()
		if len(matches) == 0 {
			r.Status, r.Detail = StatusFail, "selected source address is no longer assigned"
			r.Fix = "choose an active interface with --iface"
			return r
		}
		if len(matches) > 1 {
			r.Status, r.Source, r.Iface, r.ifaceAmbiguous = StatusWarn, primary, "(ambiguous)", true
			r.Detail = "selected source address is assigned to multiple interfaces"
			return r
		}
		if matches[0].Flags&net.FlagUp == 0 || matches[0].Flags&net.FlagRunning == 0 {
			r.Status, r.Source, r.Iface = StatusFail, primary, matches[0].Name
			r.Detail, r.Fix = "interface "+matches[0].Name+" is down", ifaceFix(runtime.GOOS)
			return r
		}
		r.Status, r.Source, r.Iface = StatusPass, primary, matches[0].Name
		r.Detail = "using " + matches[0].Name + " source " + primary.String()
		if o.sources.IPv4 != nil && o.sources.IPv6 != nil {
			r.Detail = "using " + matches[0].Name + " sources " + o.sources.IPv4.String() + ", " + o.sources.IPv6.String()
		}
		return r
	}
	// Prefer the interface the routing table says carries general Internet
	// traffic; only fall back to kernel enumeration order when routing names
	// none. Enumeration order is not the routing table's opinion, and with
	// Wi-Fi and Ethernet both up it may name the one traffic does not use,
	// which is what makes SSID detection pick the wrong link.
	var usable []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0 {
			usable = append(usable, ifi.Name)
		}
	}
	if len(usable) == 0 {
		r.Status = StatusFail
		r.Detail, r.Fix = "no interface up", ifaceFix(runtime.GOOS)
		return r
	}
	iface := usable[0]
	if routed := o.routedInterface(usable); routed != "" {
		iface = routed
	}
	r.Status, r.Iface, r.Detail = StatusPass, iface, "interface "+iface+" is up"
	return r
}

func (o *netops) ssidProbe(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
	network := o.ssid(ctx, deps[ProbeIface].Iface)
	if network == "" {
		return ProbeResult{Status: StatusNA, Detail: "Wi-Fi network unavailable"}
	}
	return ProbeResult{Status: StatusPass, Network: network, Detail: "connected to " + network}
}

// hasGlobalUnicast reports whether any live non-loopback interface holds a
// global unicast address of the given family. The machine was configured for
// it (statically, by DHCP, or by a router advertisement), so the network
// claimed to carry that family.
//
// Each family excludes the range that is routable on the LAN but never to the
// internet, where no egress is the design rather than a black hole: fc00::/7
// for IPv6, which Docker hands out and which would otherwise warn on every
// v4-only machine running a v6-enabled bridge, and 169.254.0.0/16 for IPv4,
// which is what a host self-assigns when DHCP never answered.
func (o *netops) hasGlobalUnicast(v4 bool) bool {
	if o.sources != nil {
		ip := o.sources.IPv6
		if v4 {
			ip = o.sources.IPv4
		}
		return ip != nil && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && (v4 || ip[0]&0xfe != 0xfc)
	}
	ifaces, err := o.interfaces()
	if err != nil {
		return false
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := o.interfaceAddrs(&ifi)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || !n.IP.IsGlobalUnicast() {
				continue
			}
			if v4 && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return true
			}
			if !v4 && n.IP.To4() == nil && n.IP[0]&0xfe != 0xfc {
				return true
			}
		}
	}
	return false
}

// ifaceForIP maps a source IP back to an interface name, plus whether that
// mapping was ambiguous. LocalAddr gives an IP, not a name, so ambiguity (same
// IP on >1 iface) and no-match are explicit states, not a guess. The name is
// display text; the bool is the state callers act on.
func (o *netops) ifaceForIP(ip net.IP) (string, bool) {
	ifaces, err := o.interfaces()
	if err != nil {
		return "", false
	}
	name, count := "", 0
	for _, ifi := range ifaces {
		addrs, err := o.interfaceAddrs(&ifi)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				name, count = ifi.Name, count+1
			}
		}
	}
	switch {
	case count == 0:
		return "(unknown iface)", false
	case count > 1:
		return "(ambiguous)", true
	default:
		return name, false
	}
}
