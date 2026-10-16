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

// CommandRoute is the one route-table command this package reads. The transcript
// echoes it before the output.
const CommandRoute = "show ip bgp json"

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
	"peerId", "pathFrom", "path", "origin", "nexthops", "ip", "stale",
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
// Stale is what the path's optional stale key records.
type RoutePath struct {
	Source   RouteSource
	Peer     netip.Addr
	PathFrom string
	ASPath   string
	Origin   string
	NextHops []netip.Addr
	Stale    StaleFlag
}

// StaleFlag is what a path's optional stale key records, kept as printed. The zero
// value is StaleNotRecorded, so a path with no key is never read as false. FRR
// 10.7.0 printed the key only as true, on paths it kept after a session loss with
// graceful restart, but what set a flag is not read.
type StaleFlag int

const (
	// StaleNotRecorded means the path has no stale key.
	StaleNotRecorded StaleFlag = iota
	// StaleFalse means the path has "stale": false.
	StaleFalse
	// StaleTrue means the path has "stale": true.
	StaleTrue
)

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

// DecodeRouteCapture decodes one capture of CommandRoute taken on node. The framing
// is the summary's: the echo, one JSON object, then CRLF and the node's prompt. One
// difference is allowed. FRR prints a space after the table's closing brace, so
// spaces may stand between that brace and the CRLF. No other byte may.
func DecodeRouteCapture(data []byte, node string) (RouteTable, error) {
	body, err := transcriptBody(data, CommandRoute, node)
	if err != nil {
		return RouteTable{}, err
	}
	if body, err = objectBody(bytes.TrimRight(body, " ")); err != nil {
		return RouteTable{}, err
	}
	return DecodeRouteTable(body)
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

// routeThisNetwork and routeReserved are the blocks the IANA IPv4 Special-Purpose
// Address Space registry marks as not valid destinations. A peerId in either names no
// BGP peer, except the unspecified address, which stays unknown.
var (
	routeThisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	routeReserved    = netip.MustParsePrefix("240.0.0.0/4")
)

// routeDecodePath decodes one element of a prefix's path array. Source comes from
// peerId alone: a specified address means learned, "(unspec)" means no peer, and an
// absent or unspecified peerId stays unknown. A multicast address, the IPv4 limited
// broadcast address, or an IPv4 address in 0.0.0.0/8 or 240.0.0.0/4 (other than the
// unspecified address) is refused, since none names a peer. pathFrom, path, origin and
// nexthops are required. stale is optional and must be a JSON boolean.
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
		if routeReserved.Contains(unmapped) {
			return RoutePath{}, fmt.Errorf("peerId: %q is in 240.0.0.0/4 (reserved) and names no BGP peer; want a unicast address or \"(unspec)\"", peer)
		}
		if routeThisNetwork.Contains(unmapped) && !unmapped.IsUnspecified() {
			return RoutePath{}, fmt.Errorf("peerId: %q is in 0.0.0.0/8 (this network) and names no BGP peer; want a unicast address or \"(unspec)\"", peer)
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
	var stale bool
	if present, err = routeRead(fields, "stale", &stale, false); err != nil {
		return RoutePath{}, err
	}
	switch {
	case present && stale:
		path.Stale = StaleTrue
	case present:
		path.Stale = StaleFalse
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
