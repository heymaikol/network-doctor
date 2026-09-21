package simulation

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	legacySegmentName = "lan"
	maxRouteMetric    = int(^uint32(0) >> 1)
)

func (t *Topology) normalizeAndValidate(nodes map[string]*Node) error {
	if len(t.Segments) == 0 {
		if err := t.normalizeLegacy(); err != nil {
			return err
		}
	} else if t.Subnet != "" {
		return errors.New("topology: subnet shorthand cannot be combined with segments")
	}

	segments, err := t.validateSegments()
	if err != nil {
		return err
	}
	if err := t.validateInterfaces(segments); err != nil {
		return err
	}
	if err := t.validateRoutes(nodes); err != nil {
		return err
	}
	return nil
}

func (t *Topology) normalizeLegacy() error {
	for _, n := range t.Nodes {
		if len(n.Interfaces) != 0 {
			return errors.New("topology: node interfaces require explicit segments")
		}
	}
	if len(t.Routes) != 0 {
		return errors.New("topology: routes require explicit segments")
	}
	prefix, err := parsePrefix(t.subnetOrDefault())
	if err != nil {
		return fmt.Errorf("topology.subnet: %w", err)
	}
	if !prefix.Addr().Is4() {
		return errors.New("topology.subnet: only IPv4 segments are supported")
	}
	t.Subnet = prefix.String()
	t.Segments = []Segment{{Name: legacySegmentName, Subnet: prefix.String()}}
	for i := range t.Nodes {
		n := &t.Nodes[i]
		addr, canonical, err := parseAddr(n.Address)
		if err != nil {
			return fmt.Errorf("node %q: address: %w", n.Name, err)
		}
		if !prefix.Contains(addr) {
			return fmt.Errorf("node %q: address %s is outside %s", n.Name, addr, prefix)
		}
		n.Address = canonical
		n.Interfaces = []Interface{{Segment: legacySegmentName, Address: canonical + "/" + strconv.Itoa(prefix.Bits())}}
		if n.Gateway != "" {
			_, gateway, err := parseAddr(n.Gateway)
			if err != nil {
				return fmt.Errorf("node %q: gateway: %w", n.Name, err)
			}
			n.Gateway = gateway
			t.Routes = append(t.Routes, Route{Node: n.Name, Destination: "default", Via: gateway})
		}
	}
	return nil
}

type segmentPrefixes struct {
	v4 netip.Prefix
	v6 netip.Prefix
}

func (t *Topology) validateSegments() (map[string]segmentPrefixes, error) {
	if len(t.Segments) == 0 {
		return nil, errors.New("topology.segments: at least one segment is required")
	}
	out := make(map[string]segmentPrefixes, len(t.Segments))
	for i := range t.Segments {
		segment := &t.Segments[i]
		if !isSafeName(segment.Name) {
			return nil, fmt.Errorf("topology.segments[%d].name %q must be letters, digits or dashes", i, segment.Name)
		}
		if _, exists := out[segment.Name]; exists {
			return nil, fmt.Errorf("duplicate segment name %q", segment.Name)
		}
		if segment.Subnet != "" && segment.IPv4 != "" {
			return nil, fmt.Errorf("segment %q: subnet and ipv4 are alternate spellings and cannot be combined", segment.Name)
		}
		if segment.Subnet != "" {
			segment.IPv4 = segment.Subnet
		}
		if segment.IPv4 == "" && segment.IPv6 == "" {
			return nil, fmt.Errorf("segment %q: ipv4 or ipv6 prefix is required", segment.Name)
		}
		var prefixes segmentPrefixes
		for _, item := range []struct {
			label string
			raw   *string
			want4 bool
			dst   *netip.Prefix
		}{{"ipv4", &segment.IPv4, true, &prefixes.v4}, {"ipv6", &segment.IPv6, false, &prefixes.v6}} {
			if *item.raw == "" {
				continue
			}
			prefix, err := parsePrefix(*item.raw)
			if err != nil {
				return nil, fmt.Errorf("segment %q %s: %w", segment.Name, item.label, err)
			}
			if prefix.Addr().Is4() != item.want4 {
				return nil, fmt.Errorf("segment %q %s has the wrong address family", segment.Name, item.label)
			}
			if err := validateNetworkPrefix(prefix); err != nil {
				return nil, fmt.Errorf("segment %q %s: %w", segment.Name, item.label, err)
			}
			for otherName, other := range out {
				otherPrefix := other.v6
				if item.want4 {
					otherPrefix = other.v4
				}
				if otherPrefix.IsValid() && prefixesOverlap(prefix, otherPrefix) {
					return nil, fmt.Errorf("segment %q %s %s overlaps segment %q %s", segment.Name, item.label, prefix, otherName, otherPrefix)
				}
			}
			*item.raw, *item.dst = prefix.String(), prefix
		}
		if segment.Subnet != "" {
			segment.Subnet = segment.IPv4
		}
		out[segment.Name] = prefixes
	}
	return out, nil
}

func (t *Topology) validateInterfaces(segments map[string]segmentPrefixes) error {
	addresses := make(map[netip.Addr]string)
	aliases := make(map[netip.Addr]string)
	for ni := range t.Nodes {
		n := &t.Nodes[ni]
		if len(n.Interfaces) == 0 {
			return fmt.Errorf("node %q: at least one interface is required", n.Name)
		}
		if t.Subnet == "" && (n.Address != "" || n.Gateway != "") {
			return fmt.Errorf("node %q: legacy address/gateway cannot be combined with explicit interfaces", n.Name)
		}
		seenSegments := make(map[string]bool, len(n.Interfaces))
		for ii := range n.Interfaces {
			iface := &n.Interfaces[ii]
			segment, ok := segments[iface.Segment]
			if !ok {
				return fmt.Errorf("node %q interface %d: unknown segment %q", n.Name, ii, iface.Segment)
			}
			if seenSegments[iface.Segment] {
				return fmt.Errorf("node %q: duplicate interface on segment %q", n.Name, iface.Segment)
			}
			seenSegments[iface.Segment] = true
			if iface.Address != "" && iface.IPv4 != "" {
				return fmt.Errorf("node %q interface %q: address and ipv4 are alternate spellings and cannot be combined", n.Name, iface.Segment)
			}
			if iface.Address != "" {
				iface.IPv4 = iface.Address
			}
			if iface.IPv4 == "" && iface.IPv6 == "" {
				return fmt.Errorf("node %q interface %q: ipv4 or ipv6 address is required", n.Name, iface.Segment)
			}
			for _, item := range []struct {
				label string
				raw   *string
				want4 bool
				seg   netip.Prefix
			}{{"ipv4", &iface.IPv4, true, segment.v4}, {"ipv6", &iface.IPv6, false, segment.v6}} {
				if *item.raw == "" {
					continue
				}
				if !item.seg.IsValid() {
					return fmt.Errorf("node %q interface %q has %s but the segment does not", n.Name, iface.Segment, item.label)
				}
				prefix, err := parseInterfacePrefix(*item.raw)
				if err != nil {
					return fmt.Errorf("node %q interface %q %s: %w", n.Name, iface.Segment, item.label, err)
				}
				if prefix.Addr().Is4() != item.want4 {
					return fmt.Errorf("node %q interface %q %s has the wrong address family", n.Name, iface.Segment, item.label)
				}
				if err := validateInterfaceAddr(prefix.Addr()); err != nil {
					return fmt.Errorf("node %q interface %q %s: %w", n.Name, iface.Segment, item.label, err)
				}
				if prefix.Bits() != item.seg.Bits() || !item.seg.Contains(prefix.Addr()) {
					return fmt.Errorf("node %q interface address %s is outside segment %q %s", n.Name, prefix, iface.Segment, item.seg)
				}
				if owner, exists := addresses[prefix.Addr()]; exists {
					return fmt.Errorf("duplicate interface address %s on %s and %s", prefix.Addr(), owner, n.Name)
				}
				if owner, exists := aliases[prefix.Addr()]; exists {
					return fmt.Errorf("interface address %s conflicts with alias on %s", prefix.Addr(), owner)
				}
				addresses[prefix.Addr()] = n.Name
				*item.raw = prefix.String()
			}
			if iface.Address != "" {
				iface.Address = iface.IPv4
			}
		}
		if n.Role == "router" && len(seenSegments) < 2 {
			return fmt.Errorf("router %q needs interfaces on at least two segments", n.Name)
		}
		if n.Role == "router" && !n.forwardsFamily("ipv4") && !n.forwardsFamily("ipv6") {
			return fmt.Errorf("router %q needs at least two interfaces carrying the same address family", n.Name)
		}
		if n.Address == "" {
			for _, iface := range n.Interfaces {
				raw := iface.IPv4
				if raw == "" {
					raw = iface.IPv6
				}
				if prefix, err := netip.ParsePrefix(raw); err == nil {
					n.Address = prefix.Addr().String()
					break
				}
			}
		}
		for i, raw := range n.Aliases {
			addr, canonical, err := parseAddr(raw)
			if err != nil {
				return fmt.Errorf("node %q: alias: %w", n.Name, err)
			}
			if owner, exists := addresses[addr]; exists {
				return fmt.Errorf("node %q alias %s conflicts with interface on %s", n.Name, addr, owner)
			}
			if owner, exists := aliases[addr]; exists {
				return fmt.Errorf("duplicate alias address %s on %s and %s", addr, owner, n.Name)
			}
			aliases[addr] = n.Name
			n.Aliases[i] = canonical
		}
		if n.Resolver != "" {
			resolver, canonical, err := parseAddr(n.Resolver)
			if err != nil {
				return fmt.Errorf("node %q: resolver: %w", n.Name, err)
			}
			if err := validateInterfaceAddr(resolver); err != nil {
				return fmt.Errorf("node %q: resolver: %w", n.Name, err)
			}
			n.Resolver = canonical
		}
	}
	return nil
}

func (t *Topology) validateRoutes(nodes map[string]*Node) error {
	seen := make(map[string]Route)
	defaults := make(map[string][]Route)
	for i := range t.Routes {
		route := &t.Routes[i]
		node := nodes[route.Node]
		if node == nil {
			return fmt.Errorf("topology.routes[%d]: unknown node %q", i, route.Node)
		}
		if route.Metric < 0 || route.Metric > maxRouteMetric {
			return fmt.Errorf("topology.routes[%d]: metric %d is out of range", i, route.Metric)
		}
		via, canonicalVia, err := parseAddr(route.Via)
		if err != nil {
			return fmt.Errorf("topology.routes[%d].via: %w", i, err)
		}
		if err := validateGateway(via); err != nil {
			return fmt.Errorf("topology.routes[%d].via: %w", i, err)
		}
		_, onLink := nodeSegmentForAddress(node, via)
		if !onLink {
			return fmt.Errorf("topology.routes[%d]: gateway %s is not on a directly connected subnet for node %q", i, via, route.Node)
		}
		route.Via = canonicalVia
		route.Family = addressFamily(via)
		route.Default = route.Destination == "default"
		if !route.Default {
			prefix, err := parsePrefix(route.Destination)
			if err != nil {
				return fmt.Errorf("topology.routes[%d].destination: %w", i, err)
			}
			if prefix.Addr().Is4() != via.Is4() {
				return fmt.Errorf("topology.routes[%d]: %s gateway cannot be used for %s destination %s", i, route.Family, addressFamily(prefix.Addr()), prefix)
			}
			if err := validateNetworkPrefix(prefix); err != nil {
				return fmt.Errorf("topology.routes[%d].destination: %w", i, err)
			}
			route.Default = prefix.Bits() == 0
			route.Destination = prefix.String()
		}
		key := route.Node + "\x00" + route.Family + "\x00" + route.Destination + "\x00" + strconv.Itoa(route.Metric)
		if previous, exists := seen[key]; exists {
			if previous.Via != route.Via {
				return fmt.Errorf("conflicting routes for node %q destination %s metric %d", route.Node, route.Destination, route.Metric)
			}
			return fmt.Errorf("duplicate route for node %q destination %s metric %d", route.Node, route.Destination, route.Metric)
		}
		seen[key] = *route
		if route.Default {
			defaults[route.Node+"\x00"+route.Family] = append(defaults[route.Node+"\x00"+route.Family], *route)
		}
	}
	for key, routes := range defaults {
		sort.Slice(routes, func(i, j int) bool { return routes[i].Metric < routes[j].Metric })
		nodeName, family, _ := strings.Cut(key, "\x00")
		if family == "ipv4" || nodes[nodeName].Gateway == "" {
			nodes[nodeName].Gateway = routes[0].Via
		}
	}
	return nil
}

// hasDefaultRoute reports whether the node's normalized initial route table
// carries a default route for the family. validateRoutes has already resolved
// every spelling a scenario may use ("default", a /0 prefix, or the legacy
// gateway shorthand) into a Route with Default and Family set, so this is the
// single source of truth for what a fault would find installed.
func (t *Topology) hasDefaultRoute(node, family string) bool {
	for i := range t.Routes {
		route := &t.Routes[i]
		if route.Default && route.Node == node && route.Family == family {
			return true
		}
	}
	return false
}

func nodeSegmentForAddress(node *Node, addr netip.Addr) (string, bool) {
	for _, iface := range node.Interfaces {
		for _, raw := range []string{iface.IPv4, iface.IPv6} {
			prefix, err := netip.ParsePrefix(raw)
			if err == nil && prefix.Contains(addr) {
				return iface.Segment, true
			}
		}
	}
	return "", false
}

func (n *Node) interfaceOn(segment string) (*Interface, bool) {
	for i := range n.Interfaces {
		if n.Interfaces[i].Segment == segment {
			return &n.Interfaces[i], true
		}
	}
	return nil, false
}

func (n *Node) addresses() []string {
	out := make([]string, 0, 2*len(n.Interfaces)+len(n.Aliases))
	for _, iface := range n.Interfaces {
		for _, raw := range []string{iface.IPv4, iface.IPv6} {
			if prefix, err := netip.ParsePrefix(raw); err == nil {
				out = append(out, prefix.Addr().String())
			}
		}
	}
	return append(out, n.Aliases...)
}

func (n *Node) forwardsFamily(family string) bool {
	connected := 0
	for _, iface := range n.Interfaces {
		if _, ok := iface.addressForFamily(family); ok {
			connected++
		}
	}
	return connected >= 2
}

func (n *Node) hasFamily(family string) bool {
	for _, iface := range n.Interfaces {
		if _, ok := iface.addressForFamily(family); ok {
			return true
		}
	}
	for _, raw := range n.Aliases {
		if addr, err := netip.ParseAddr(raw); err == nil && addressFamily(addr) == family {
			return true
		}
	}
	return false
}

func parsePrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q: scoped addresses are not supported", raw)
	}
	return prefix.Masked(), nil
}

func parseInterfacePrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	if prefix.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("%q: scoped addresses are not supported", raw)
	}
	return prefix, nil
}

func validateNetworkPrefix(prefix netip.Prefix) error {
	addr := prefix.Addr()
	if addr.Is4In6() {
		return errors.New("IPv4-mapped IPv6 prefixes are not supported")
	}
	if addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return fmt.Errorf("prefix %s is not a simulator unicast network", prefix)
	}
	return nil
}

func validateInterfaceAddr(addr netip.Addr) error {
	if addr.Is4In6() {
		return errors.New("IPv4-mapped IPv6 addresses are not supported")
	}
	if addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return fmt.Errorf("address %s is not a usable simulator unicast address", addr)
	}
	return nil
}

func validateGateway(addr netip.Addr) error {
	if err := validateInterfaceAddr(addr); err != nil {
		return err
	}
	return nil
}

func addressFamily(addr netip.Addr) string {
	if addr.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func (i Interface) prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range []string{i.IPv4, i.IPv6} {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, prefix)
		}
	}
	return out
}

func (i Interface) addressForFamily(family string) (netip.Prefix, bool) {
	raw := i.IPv6
	if family == "ipv4" {
		raw = i.IPv4
	}
	prefix, err := netip.ParsePrefix(raw)
	return prefix, err == nil
}

func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
