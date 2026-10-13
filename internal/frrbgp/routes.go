package frrbgp

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// routeMaxBytes bounds one route table. It matches frrospf.MaxCaptureBytes, so
// both decoders take the same input size.
const routeMaxBytes = 1 << 20

// routeMaxDepth bounds object and array nesting. The genuine captures nest six
// levels; the rest is room for FRR fields this decoder does not read.
const routeMaxDepth = 16

// routeKnownKeys are the keys this decoder reads. A key that differs from one of
// them only in case is refused, since it would otherwise be skipped as unknown
// without notice.
var routeKnownKeys = []string{
	"routerId", "localAS", "vrfName", "routes",
	"peerId", "pathFrom", "path", "origin", "nexthops", "ip",
}

// RouteTable is one decoded "show ip bgp json" body. Routes are sorted by prefix.
type RouteTable struct {
	RouterID string
	LocalAS  uint32
	VRFName  string
	Routes   []RouteEntry
}

// RouteEntry is one prefix and the paths the capture lists for it, in FRR's order.
type RouteEntry struct {
	Prefix netip.Prefix
	Paths  []RoutePath
}

// RoutePath is one path. Source is decided by peerId alone, and Peer is set only
// for RouteSourceLearned. PathFrom, ASPath and Origin hold the capture's text
// after textsafe.Clean. Origin is the BGP ORIGIN attribute and names no protocol.
type RoutePath struct {
	Source   RouteSource
	Peer     netip.Addr
	PathFrom string
	ASPath   string
	Origin   string
	NextHops []netip.Addr
}

// RouteSource is what a path's peerId shows. The zero value is RouteSourceUnknown,
// so a path the capture does not classify is never reported as learned.
type RouteSource int

const (
	// RouteSourceUnknown means the path has no peerId.
	RouteSourceUnknown RouteSource = iota
	// RouteSourceLearned means peerId holds a specified peer address.
	RouteSourceLearned
	// RouteSourceNoPeer means peerId is "(unspec)", so FRR records no peer.
	RouteSourceNoPeer
)

// DecodeRouteTable decodes the JSON object of one "show ip bgp json" capture. The
// caller removes the echoed command and the node prompt first. It refuses input
// over routeMaxBytes, invalid UTF-8, a key repeated in one object (ignoring case),
// a key that differs from a decoded key only in case, nesting deeper than
// routeMaxDepth, and data after the object. A supplied routerId must be a canonical
// IPv4 address, a supplied localAS must be neither 0 nor 4294967295, and a supplied
// vrfName must be non-empty with no control or invisible characters. Such values are
// refused, never cleaned. A missing key keeps its zero value. Keys it does not read
// are skipped.
func DecodeRouteTable(data []byte) (RouteTable, error) {
	if len(data) > routeMaxBytes {
		return RouteTable{}, fmt.Errorf("route table is %d bytes, limit is %d", len(data), routeMaxBytes)
	}
	if !utf8.Valid(data) {
		return RouteTable{}, errors.New("route table is not valid UTF-8")
	}
	if err := routeCheckJSON(data); err != nil {
		return RouteTable{}, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return RouteTable{}, fmt.Errorf("route table is not a JSON object: %w", err)
	}
	var table RouteTable
	hasRouterID, err := routeRead(top, "routerId", &table.RouterID, false)
	if err != nil {
		return RouteTable{}, err
	}
	if hasRouterID && !routeCanonicalIPv4(table.RouterID) {
		return RouteTable{}, fmt.Errorf("routerId %q is not a canonical IPv4 address", table.RouterID)
	}
	hasLocalAS, err := routeRead(top, "localAS", &table.LocalAS, false)
	if err != nil {
		return RouteTable{}, err
	}
	if hasLocalAS && (table.LocalAS == 0 || table.LocalAS == math.MaxUint32) {
		return RouteTable{}, fmt.Errorf("localAS %d is not a BGP ASN", table.LocalAS)
	}
	hasVRFName, err := routeRead(top, "vrfName", &table.VRFName, false)
	if err != nil {
		return RouteTable{}, err
	}
	if hasVRFName && table.VRFName == "" {
		return RouteTable{}, errors.New("vrfName is empty")
	}
	if hasVRFName && textsafe.Clean(table.VRFName) != table.VRFName {
		return RouteTable{}, fmt.Errorf("vrfName %q holds a control or invisible character", table.VRFName)
	}
	var routes map[string][]json.RawMessage
	if _, err := routeRead(top, "routes", &routes, true); err != nil {
		return RouteTable{}, err
	}
	for _, key := range slices.Sorted(maps.Keys(routes)) {
		prefix, err := routeParsePrefix(key)
		if err != nil {
			return RouteTable{}, err
		}
		if len(routes[key]) == 0 {
			return RouteTable{}, fmt.Errorf("route %q has no paths", key)
		}
		entry := RouteEntry{Prefix: prefix}
		for _, raw := range routes[key] {
			path, err := routeDecodePath(raw)
			if err != nil {
				return RouteTable{}, fmt.Errorf("route %q: %w", key, err)
			}
			entry.Paths = append(entry.Paths, path)
		}
		table.Routes = append(table.Routes, entry)
	}
	slices.SortFunc(table.Routes, func(a, b RouteEntry) int {
		return cmp.Or(a.Prefix.Addr().Compare(b.Prefix.Addr()), a.Prefix.Bits()-b.Prefix.Bits())
	})
	return table, nil
}

// routeCheckJSON walks the whole document once. It refuses what encoding/json
// would take silently, then confirms that nothing follows the single object.
func routeCheckJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("route table is empty")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := routeWalk(dec, 1); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return errors.New("route table is truncated")
		}
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data follows the route table")
	}
	return nil
}

// routeWalk reads one JSON value at the given nesting level, where the root object
// is level one. It refuses a key repeated in an object, ignoring case, a key that
// differs from a known key only in case, and nesting beyond routeMaxDepth.
func routeWalk(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth > routeMaxDepth {
		return fmt.Errorf("JSON nests deeper than %d levels", routeMaxDepth)
	}
	folded := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := tok.(string)
			fold := routeFold(key)
			if folded[fold] {
				return fmt.Errorf("duplicate key %q", key)
			}
			folded[fold] = true
			if name, near := routeNearKnownKey(key); near {
				return fmt.Errorf("key %q differs from %q only in case", key, name)
			}
		}
		if err := routeWalk(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

// routeNearKnownKey returns the known key that key matches only when case is ignored.
func routeNearKnownKey(key string) (string, bool) {
	for _, name := range routeKnownKeys {
		if key != name && routeFold(key) == routeFold(name) {
			return name, true
		}
	}
	return "", false
}

// routeFold is the case fold that duplicate and near-key checks share. Going up and
// then down maps the long s and the final sigma onto the forms the keys use.
func routeFold(key string) string {
	return strings.ToLower(strings.ToUpper(key))
}

// routeRead decodes obj[name] into dst and reports whether the key is present. A
// missing required key is an error. A null is refused too: encoding/json would
// accept it and leave dst at its zero value.
func routeRead(obj map[string]json.RawMessage, name string, dst any, required bool) (bool, error) {
	raw, ok := obj[name]
	switch {
	case !ok && required:
		return false, fmt.Errorf("%s is missing", name)
	case !ok:
		return false, nil
	case string(raw) == "null":
		return true, fmt.Errorf("%s is null", name)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return true, fmt.Errorf("%s: %w", name, err)
	}
	return true, nil
}

// routeParsePrefix accepts only the canonical IPv4 spelling of a prefix, so each
// prefix has exactly one key.
func routeParsePrefix(key string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(key)
	if err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != key {
		return netip.Prefix{}, fmt.Errorf("route %q is not a canonical IPv4 prefix", key)
	}
	return p, nil
}

// routeCanonicalIPv4 reports whether text is an IPv4 address spelled the way netip
// prints it, so each address has exactly one spelling.
func routeCanonicalIPv4(text string) bool {
	addr, err := netip.ParseAddr(text)
	return err == nil && addr.Is4() && addr.String() == text
}

// routeAddr parses an IP address from a capture. A zone is refused, because the
// decoder reads only plain addresses.
func routeAddr(text string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", text)
	}
	return addr, nil
}

// routeDecodePath decodes one element of a prefix's path array. Source comes from
// peerId alone: a specified address means learned, "(unspec)" means no peer, and an
// absent or unspecified peerId stays unknown. A multicast address or the IPv4 limited
// broadcast address is refused, since neither names a peer. pathFrom, path, origin and
// nexthops are required.
func routeDecodePath(raw json.RawMessage) (RoutePath, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return RoutePath{}, errors.New("path is not a JSON object")
	}
	var path RoutePath
	var peer string
	present, err := routeRead(fields, "peerId", &peer, false)
	if err != nil {
		return RoutePath{}, err
	}
	switch {
	case !present:
		// Source stays RouteSourceUnknown.
	case peer == "(unspec)":
		path.Source = RouteSourceNoPeer
	default:
		addr, err := routeAddr(peer)
		if err != nil {
			return RoutePath{}, fmt.Errorf("peerId: %w", err)
		}
		// Unmap first, so an IPv4 address written in IPv6 form is judged the same way.
		unmapped := addr.Unmap()
		if unmapped.IsMulticast() {
			return RoutePath{}, fmt.Errorf("peerId: %q is a multicast address and names no BGP peer; want a unicast address or \"(unspec)\"", peer)
		}
		if unmapped == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return RoutePath{}, fmt.Errorf("peerId: %q is the limited broadcast address and names no BGP peer; want a unicast address or \"(unspec)\"", peer)
		}
		// The unspecified address names no peer, so the path stays unknown.
		if !unmapped.IsUnspecified() {
			path.Source, path.Peer = RouteSourceLearned, addr
		}
	}
	if _, err := routeRead(fields, "pathFrom", &path.PathFrom, true); err != nil {
		return RoutePath{}, err
	}
	if _, err := routeRead(fields, "path", &path.ASPath, true); err != nil {
		return RoutePath{}, err
	}
	if _, err := routeRead(fields, "origin", &path.Origin, true); err != nil {
		return RoutePath{}, err
	}
	path.PathFrom = textsafe.Clean(path.PathFrom)
	path.ASPath = textsafe.Clean(path.ASPath)
	path.Origin = textsafe.Clean(path.Origin)
	var hops []map[string]json.RawMessage
	if _, err := routeRead(fields, "nexthops", &hops, true); err != nil {
		return RoutePath{}, err
	}
	for _, hop := range hops {
		var ip string
		if _, err := routeRead(hop, "ip", &ip, true); err != nil {
			return RoutePath{}, err
		}
		addr, err := routeAddr(ip)
		if err != nil {
			return RoutePath{}, fmt.Errorf("ip: %w", err)
		}
		path.NextHops = append(path.NextHops, addr)
	}
	return path, nil
}
