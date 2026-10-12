package frrospf

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// The steady zebra RIB is the output of show ip route json on zebra's vty. This
// file decodes one such body offline. It keeps every candidate route zebra printed
// and never picks one. The selected, destSelected, installed, active, and fib
// fields are zebra's own flags, kept as printed. They are not evidence of kernel
// forwarding, and nothing here matches a route with an OSPF result.

// zebraDefaultVRF is the only VRF whose routes are read. Any other name is refused.
const zebraDefaultVRF = "default"

// zebraCandidateKeys are the candidate keys this decoder reads, by exact spelling.
// A key that differs from one of them only in case is refused. The list is local,
// not part of decodedKeys, so the OSPF decoders keep the key set they already have.
var zebraCandidateKeys = []string{
	"prefix", "prefixLen", "protocol", "distance", "metric", "vrfName", "vrfId",
	"table", "nexthops", "selected", "destSelected", "installed",
}

// zebraHopKeys are the nexthops keys this decoder reads, by exact spelling. The same
// case rule applies to them.
var zebraHopKeys = []string{"ip", "interfaceName", "directlyConnected", "active", "fib"}

// zebraRIB is one decoded show ip route json body. Known is false for {}, which does
// not show that no route exists.
type zebraRIB struct {
	Known    bool
	Prefixes []zebraPrefix // in sorted key order
}

// zebraPrefix is one top-level key and every candidate printed under it. An empty
// Candidates list is a prefix that zebra printed with [].
type zebraPrefix struct {
	Prefix     netip.Prefix
	Candidates []zebraCandidate // in printed order, none chosen
}

// zebraCandidate is one route printed under a prefix. Table and VRFID are kept as
// printed for each candidate. A flag field is nil when its key is absent.
type zebraCandidate struct {
	Protocol     string
	Distance     uint64
	Metric       uint64
	VRFName      string
	VRFID        uint64
	Table        uint64
	Selected     *bool
	DestSelected *bool
	Installed    *bool
	NextHops     []zebraHop
	// HopsIdentified is true only when the candidate prints at least one hop and every
	// hop is identified. An empty nexthops array is unidentified.
	HopsIdentified bool
}

// zebraHop is one nexthops element. It is identified when it prints a valid IPv4 ip
// and an interface name, or directlyConnected true and an interface name with no ip
// key. A hop with an ip key and directlyConnected true is unidentified, since the two
// disagree. Any other hop is unidentified, and no identity is inferred for it.
type zebraHop struct {
	Identified        bool
	IP                netip.Addr // set only for an identified address hop
	InterfaceName     string     // set only for an identified hop
	DirectlyConnected *bool
	Active            *bool
	FIB               *bool
}

// decodeZebraRIB reads one show ip route json body. The second return is the reason
// the body is refused, empty when accepted. A refusal covers the whole body, since a
// partly read RIB would look complete.
func decodeZebraRIB(data []byte) (zebraRIB, string) {
	if len(data) > MaxCaptureBytes {
		return zebraRIB{}, fmt.Sprintf("output exceeds %d bytes", MaxCaptureBytes)
	}
	top, err := decodeTopLevel(data)
	if err != nil {
		return zebraRIB{}, err.Error()
	}
	if len(top) > maxEntries {
		return zebraRIB{}, fmt.Sprintf("output holds %d prefixes; more than %d is refused", len(top), maxEntries)
	}
	rib := zebraRIB{Known: len(top) > 0}
	candidates, hops := 0, 0
	// Keys are walked in sorted order, so one input always gives one refusal.
	for _, key := range slices.Sorted(maps.Keys(top)) {
		p, ok := zebraPrefixKey(key)
		if !ok {
			return zebraRIB{}, fmt.Sprintf("key %s is not a canonical IPv4 prefix", quote(key))
		}
		list, err := arrayOf(top[key])
		if err != nil {
			return zebraRIB{}, fmt.Sprintf("prefix %s: %v", quote(key), err)
		}
		candidates += len(list)
		if candidates > maxEntries {
			return zebraRIB{}, fmt.Sprintf("more than %d candidate routes is refused", maxEntries)
		}
		zp := zebraPrefix{Prefix: p}
		for _, raw := range list {
			c, err := readZebraCandidate(p, raw, maxEntries-hops)
			if err != nil {
				return zebraRIB{}, fmt.Sprintf("prefix %s: %v", quote(key), err)
			}
			hops += len(c.NextHops)
			zp.Candidates = append(zp.Candidates, c)
		}
		rib.Prefixes = append(rib.Prefixes, zp)
	}
	return rib, ""
}

// zebraPrefixKey accepts one canonical IPv4 prefix, such as 10.0.1.0/24. An address
// with host bits set, an IPv6 prefix, and a bare address are all refused.
func zebraPrefixKey(key string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(key)
	if err != nil || !p.Addr().Is4() || p.Masked() != p || p.String() != key {
		return netip.Prefix{}, false
	}
	return p, true
}

// readZebraCandidate reads one candidate route printed under prefix p. A missing,
// null, or mistyped required key refuses the candidate. So does a prefix or prefixLen
// that differs from p, or a VRF other than the default. hopsLeft is how many nexthops
// elements the body may still hold.
func readZebraCandidate(p netip.Prefix, raw json.RawMessage, hopsLeft int) (zebraCandidate, error) {
	obj, err := objectFields(raw)
	if err != nil {
		return zebraCandidate{}, err
	}
	if name, ok := foldedKey(obj, zebraCandidateKeys); ok {
		return zebraCandidate{}, fmt.Errorf("key %s differs from a candidate key only in case", quote(name))
	}
	prefix, err := get[string](obj, "prefix")
	if err != nil {
		return zebraCandidate{}, err
	}
	if prefix != p.String() {
		return zebraCandidate{}, fmt.Errorf("prefix %s does not match its key", quote(prefix))
	}
	length, err := get[int](obj, "prefixLen")
	if err != nil {
		return zebraCandidate{}, err
	}
	if length != p.Bits() {
		return zebraCandidate{}, fmt.Errorf("prefixLen %d does not match its key", length)
	}
	protocol, err := get[string](obj, "protocol")
	if err != nil {
		return zebraCandidate{}, err
	}
	distance, err := get[uint64](obj, "distance")
	if err != nil {
		return zebraCandidate{}, err
	}
	metric, err := get[uint64](obj, "metric")
	if err != nil {
		return zebraCandidate{}, err
	}
	vrf, err := get[string](obj, "vrfName")
	if err != nil {
		return zebraCandidate{}, err
	}
	if vrf != zebraDefaultVRF {
		return zebraCandidate{}, fmt.Errorf("vrfName %s is not the default VRF", quote(vrf))
	}
	vrfID, err := get[uint64](obj, "vrfId")
	if err != nil {
		return zebraCandidate{}, err
	}
	table, err := get[uint64](obj, "table")
	if err != nil {
		return zebraCandidate{}, err
	}
	hopList, err := get[[]json.RawMessage](obj, "nexthops")
	if err != nil {
		return zebraCandidate{}, err
	}
	if len(hopList) > hopsLeft {
		return zebraCandidate{}, fmt.Errorf("more than %d next hops is refused", maxEntries)
	}
	selected, err := optionalBool(obj, "selected")
	if err != nil {
		return zebraCandidate{}, err
	}
	destSelected, err := optionalBool(obj, "destSelected")
	if err != nil {
		return zebraCandidate{}, err
	}
	installed, err := optionalBool(obj, "installed")
	if err != nil {
		return zebraCandidate{}, err
	}
	c := zebraCandidate{
		Protocol:       protocol,
		Distance:       distance,
		Metric:         metric,
		VRFName:        vrf,
		VRFID:          vrfID,
		Table:          table,
		Selected:       selected,
		DestSelected:   destSelected,
		Installed:      installed,
		HopsIdentified: len(hopList) > 0,
	}
	for _, raw := range hopList {
		h, err := readZebraHop(raw)
		if err != nil {
			return zebraCandidate{}, err
		}
		c.NextHops = append(c.NextHops, h)
		c.HopsIdentified = c.HopsIdentified && h.Identified
	}
	return c, nil
}

// readZebraHop reads one nexthops element. A non-object element refuses the
// candidate, and so does a malformed directlyConnected, active, or fib. A missing,
// null, or mistyped ip or interfaceName leaves the hop unidentified, as the identity
// rule says, and the flags are still read. A present ip key with directlyConnected
// true also leaves the hop unidentified, whatever the ip holds.
func readZebraHop(raw json.RawMessage) (zebraHop, error) {
	obj, err := objectFields(raw)
	if err != nil {
		return zebraHop{}, fmt.Errorf("nexthops element: %w", err)
	}
	if name, ok := foldedKey(obj, zebraHopKeys); ok {
		return zebraHop{}, fmt.Errorf("nexthops key %s differs from a hop key only in case", quote(name))
	}
	direct, err := optionalBool(obj, "directlyConnected")
	if err != nil {
		return zebraHop{}, err
	}
	active, err := optionalBool(obj, "active")
	if err != nil {
		return zebraHop{}, err
	}
	fib, err := optionalBool(obj, "fib")
	if err != nil {
		return zebraHop{}, err
	}
	h := zebraHop{DirectlyConnected: direct, Active: active, FIB: fib}
	// hopText reads a missing, null, or mistyped value as "", which is neither an
	// address nor an interface name.
	ip, hasIP, _ := hopText(obj, "ip")
	name, _, _ := hopText(obj, "interfaceName")
	if !ifaceName(name) {
		return h, nil
	}
	// An ip key with directlyConnected true disagrees with itself, so no identity is
	// inferred, whatever the ip holds.
	if hasIP && direct != nil && *direct {
		return h, nil
	}
	if addr, ok := parseIPv4(ip); ok && !addr.IsUnspecified() {
		h.Identified, h.IP, h.InterfaceName = true, addr, name
	} else if direct != nil && *direct {
		h.Identified, h.InterfaceName = true, name
	}
	return h, nil
}

// optionalBool reads an optional boolean. A missing key is nil. A null is refused,
// since encoding/json takes null as no value and would leave the flag looking absent.
func optionalBool(f fields, key string) (*bool, error) {
	raw, ok := f[key]
	if !ok {
		return nil, nil
	}
	var b bool
	if string(raw) == "null" || json.Unmarshal(raw, &b) != nil {
		return nil, fmt.Errorf("key %s is not a boolean", quote(key))
	}
	return &b, nil
}

// foldedKey returns the first key of f, in sorted order, that differs from one of
// names only in case. Sorting keeps the refusal the same on every run.
func foldedKey(f fields, names []string) (string, bool) {
	for _, k := range slices.Sorted(maps.Keys(f)) {
		if slices.Contains(names, k) {
			continue
		}
		if slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, k) }) {
			return k, true
		}
	}
	return "", false
}
