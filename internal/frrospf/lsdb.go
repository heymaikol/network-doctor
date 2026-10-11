package frrospf

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"

	"github.com/heymaikol/network-doctor/internal/ospf"
)

// The three commands behind the LSDB comparison. A node that has any of them
// needs two process-state captures, one LSDB capture, and one route capture. The
// manifest enforces that count.
const (
	CommandProcessState = "show ip ospf json"
	CommandLSDB         = "show ip ospf database detail json"
	CommandRoute        = "show ip ospf route json"
)

// fields is one JSON object read by exact key. encoding/json matches struct
// fields without regard to case, so these decoders read maps. checkStrictJSON
// refuses any spelling that differs only in case from a key these decoders read.
type fields map[string]json.RawMessage

// get reads one key by its exact spelling. A missing key, a null, and a value of
// the wrong JSON type are each refused, and the refusal names the key.
func get[T any](f fields, key string) (T, error) {
	var v T
	raw, ok := f[key]
	switch {
	case !ok:
		return v, fmt.Errorf("missing key %s", quote(key))
	case string(raw) == "null":
		return v, fmt.Errorf("key %s is null", quote(key))
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("key %s has the wrong type", quote(key))
	}
	return v, nil
}

// ipv4Key reads a key that holds a dotted IPv4 address.
func ipv4Key(f fields, key string) (netip.Addr, error) {
	s, err := get[string](f, key)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := parseIPv4(s)
	if !ok {
		return netip.Addr{}, fmt.Errorf("key %s is %s, not a dotted IPv4 address", key, quote(s))
	}
	return addr, nil
}

// hexKey reads a key that holds an unsigned hexadecimal value of at most bits
// bits. FRR prints checksums as four hex digits and sequence numbers as eight.
func hexKey(f fields, key string, bitSize int) (uint64, error) {
	s, err := get[string](f, key)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(s, 16, bitSize)
	if err != nil {
		return 0, fmt.Errorf("key %s is %s, not a %d-bit hex value", key, quote(s), bitSize)
	}
	return v, nil
}

// objectFields reads raw as a JSON object.
func objectFields(raw json.RawMessage) (fields, error) {
	var f fields
	if err := json.Unmarshal(raw, &f); err != nil || f == nil {
		return nil, errors.New("not a JSON object")
	}
	return f, nil
}

// arrayOf reads raw as a JSON array.
func arrayOf(raw json.RawMessage) ([]json.RawMessage, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil || list == nil {
		return nil, errors.New("not a JSON array")
	}
	return list, nil
}

// emptyJSON reports whether raw holds no content: null, an empty array or
// object, or an array or object whose members are all empty.
func emptyJSON(raw json.RawMessage) bool {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return isEmpty(v)
}

func isEmpty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		for _, e := range x {
			if !isEmpty(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range x {
			if !isEmpty(e) {
				return false
			}
		}
		return true
	}
	return false
}

// processCounters maps each area-scoped LSA type to its counter keys in the
// process state. The external type is at the instance level, not here.
var processCounters = []struct {
	t           ospf.LSAType
	number, sum string
}{
	{ospf.LSARouter, "lsaRouterNumber", "lsaRouterChecksum"},
	{ospf.LSANetwork, "lsaNetworkNumber", "lsaNetworkChecksum"},
	{ospf.LSASummary, "lsaSummaryNumber", "lsaSummaryChecksum"},
	{ospf.LSAASBRSummary, "lsaAsbrNumber", "lsaAsbrChecksum"},
	{ospf.LSANSSA, "lsaNssaNumber", "lsaNssaChecksum"},
}

// decodeProcessState reads one show ip ospf json output. The FRR 10.7.0 source
// prints {} when the default VRF has no running instance and some other OSPF
// instance exists (ospfd/ospf_vty.c:3536-3538). No capture shows that output for
// this command. The decoder reads {} as a process with no router ID and no areas
// (TestNotRunningProcessStateIsEmptyNotLSDB), and the guard then withholds the
// comparison. The source prints nothing when no OSPF instance exists
// (ospf_vty.c:3494-3495). That empty body has no JSON to read, so it is refused.
func decodeProcessState(data []byte) (ospf.Process, string) {
	top, err := decodeTopLevel(data)
	if err != nil {
		return ospf.Process{}, err.Error()
	}
	if len(top) == 0 {
		return ospf.Process{}, ""
	}
	p, err := processFrom(fields(top))
	if err != nil {
		return ospf.Process{}, err.Error()
	}
	return p, ""
}

// routerIdentity returns the router ID that a process reports, or "" when it
// reports none. FRR 10.7.0 prints 0.0.0.0 for an instance that has not taken a
// router ID. ospf_new_alloc sets the ID to 0 (ospfd/ospfd.c:335). The refresh
// assigns only a static ID or the ID that zebra supplies (ospfd.c:165-200), and
// zebra supplies 0.0.0.0 when no interface has an address (zebra/router-id.c:
// 61-84). The instance still counts as running (ospfd.c:458-459). The comparison
// treats "" as unknown.
func routerIdentity(id netip.Addr) string {
	if id.IsUnspecified() {
		return ""
	}
	return id.String()
}

func processFrom(f fields) (ospf.Process, error) {
	routerID, err := ipv4Key(f, "routerId")
	if err != nil {
		return ospf.Process{}, err
	}
	holdtime, err := get[uint64](f, "holdtimeMaxMsecs")
	if err != nil {
		return ospf.Process{}, err
	}
	delay, err := get[uint64](f, "spfScheduleDelayMsecs")
	if err != nil {
		return ospf.Process{}, err
	}
	extNumber, err := get[uint64](f, "lsaExternalCounter")
	if err != nil {
		return ospf.Process{}, err
	}
	extSum, err := get[uint64](f, "lsaExternalChecksum")
	if err != nil {
		return ospf.Process{}, err
	}
	areas, err := get[map[string]json.RawMessage](f, "areas")
	if err != nil {
		return ospf.Process{}, err
	}
	p := ospf.Process{
		RouterID:      routerIdentity(routerID),
		HoldtimeMaxMs: holdtime,
		SPFDelayMs:    delay,
		External:      ospf.Count{Number: extNumber, Checksum: extSum},
		Areas:         map[string]ospf.Area{},
	}
	for id, rawArea := range areas {
		if _, ok := parseIPv4(id); !ok {
			return ospf.Process{}, fmt.Errorf("area %s is not a dotted IPv4 area", quote(id))
		}
		af, err := objectFields(rawArea)
		if err != nil {
			return ospf.Process{}, fmt.Errorf("area %s: %w", quote(id), err)
		}
		spf, err := get[uint64](af, "spfExecutedCounter")
		if err != nil {
			return ospf.Process{}, fmt.Errorf("area %s: %w", quote(id), err)
		}
		area := ospf.Area{SPFExecuted: spf, Counts: map[ospf.LSAType]ospf.Count{}}
		for _, c := range processCounters {
			n, err := get[uint64](af, c.number)
			if err != nil {
				return ospf.Process{}, fmt.Errorf("area %s: %w", quote(id), err)
			}
			s, err := get[uint64](af, c.sum)
			if err != nil {
				return ospf.Process{}, fmt.Errorf("area %s: %w", quote(id), err)
			}
			area.Counts[c.t] = ospf.Count{Number: n, Checksum: s}
		}
		p.Areas[id] = area
	}
	return p, nil
}

// routeTypes are the prefix route types the calculation prints. "N E2" is the
// only type that carries type2cost.
var routeTypes = []string{"N", "N IA", "N E1", "N E2"}

// decodeRoutes reads one show ip ospf route json output. The command prints {}
// both when no route table exists and when the table is empty, so {} is
// unknown. It is not a list of absent prefixes.
func decodeRoutes(data []byte) (ospf.Routes, string) {
	top, err := decodeTopLevel(data)
	if err != nil {
		return ospf.Routes{}, err.Error()
	}
	rt := ospf.Routes{Known: len(top) > 0}
	for _, key := range slices.Sorted(maps.Keys(top)) {
		obj, err := objectFields(top[key])
		if err != nil {
			return ospf.Routes{}, fmt.Sprintf("route %s: %v", quote(key), err)
		}
		routeType, err := get[string](obj, "routeType")
		if err != nil {
			return ospf.Routes{}, fmt.Sprintf("route %s: %v", quote(key), err)
		}
		if p, err := netip.ParsePrefix(key); err == nil {
			if p.Masked() != p {
				return ospf.Routes{}, fmt.Sprintf("route %s is not a canonical prefix", quote(key))
			}
			r, err := routeFrom(p, obj, routeType)
			if err != nil {
				return ospf.Routes{}, fmt.Sprintf("route %s: %v", quote(key), err)
			}
			rt.Entries = append(rt.Entries, r)
			continue
		}
		// A router entry is keyed by router ID, with routeType "R " in FRR's
		// output. It is counted, and it never names a prefix.
		if _, ok := parseIPv4(key); ok && routeType == "R " {
			rt.Routers++
			continue
		}
		return ospf.Routes{}, fmt.Sprintf("route key %s is neither a canonical prefix nor a router ID", quote(key))
	}
	return rt, ""
}

func routeFrom(p netip.Prefix, obj fields, routeType string) (ospf.Route, error) {
	if !slices.Contains(routeTypes, routeType) {
		return ospf.Route{}, fmt.Errorf("routeType %s is not a prefix route type", quote(routeType))
	}
	cost, err := get[uint64](obj, "cost")
	if err != nil {
		return ospf.Route{}, err
	}
	r := ospf.Route{Prefix: p, RouteType: routeType, Cost: cost}
	if routeType == "N E2" {
		t2, err := get[uint64](obj, "type2cost")
		if err != nil {
			return ospf.Route{}, err
		}
		r.Type2Cost = &t2
	}
	if raw, ok := obj["area"]; ok {
		var area string
		if err := json.Unmarshal(raw, &area); err != nil || checkArea(area) != nil {
			return ospf.Route{}, errors.New("area is not a dotted IPv4 area")
		}
		r.Area = area
	}
	hops, err := get[[]json.RawMessage](obj, "nexthops")
	if err != nil {
		return ospf.Route{}, err
	}
	r.NextHops = len(hops)
	return r, nil
}

// lsdbSections are the area-scoped sections of the LSDB output. Each holds an
// "areas" object with one array per area. Opaque sections hold entries this
// package counts and does not derive.
var lsdbSections = []struct {
	key     string
	t       ospf.LSAType
	lsaName string // the lsaType FRR prints, checked when the entry carries one
	opaque  bool
}{
	{"routerLinkStates", ospf.LSARouter, "router-LSA", false},
	{"networkLinkStates", ospf.LSANetwork, "network-LSA", false},
	{"summaryLinkStates", ospf.LSASummary, "", false},
	{"asbrSummaryLinkStates", ospf.LSAASBRSummary, "", false},
	{"nssaExternalLinkStates", ospf.LSANSSA, "", false},
	{"linkLocalOpaqueLsa", "", "", true},
	{"areaLocalOpaqueLsa", "", "", true},
}

// lsdbASSections are the AS-scope sections. Each is an array at the top level.
var lsdbASSections = []struct {
	key    string
	t      ospf.LSAType
	opaque bool
}{
	{"asExternalLinkStates", ospf.LSAExternal, false},
	{"asExternalOpaqueLsa", "", true},
}

// decodeLSDB reads one show ip ospf database detail json output. Every known
// section must be present, so an absent section cannot pass for an empty one.
// Content in a section this package does not know is recorded as unknown, not
// refused, and it blocks prefix findings in its scope.
func decodeLSDB(data []byte) (ospf.LSDB, string) {
	top, err := decodeTopLevel(data)
	if err != nil {
		return ospf.LSDB{}, err.Error()
	}
	db, err := lsdbFrom(fields(top))
	if err != nil {
		return ospf.LSDB{}, err.Error()
	}
	return db, ""
}

// lsaKey is one advertisement's identity within its type and area. Link state
// ID alone is not enough: two routers may originate one ID.
type lsaKey struct {
	area, lsid, adv string
	t               ospf.LSAType
}

func lsdbFrom(f fields) (ospf.LSDB, error) {
	routerID, err := ipv4Key(f, "routerId")
	if err != nil {
		return ospf.LSDB{}, err
	}
	db := ospf.LSDB{RouterID: routerID.String()}
	known := map[string]bool{"routerId": true}
	seen := map[lsaKey]bool{}

	for _, s := range lsdbSections {
		known[s.key] = true
		raw, err := get[json.RawMessage](f, s.key)
		if err != nil {
			return ospf.LSDB{}, err
		}
		areas, extra, err := splitAreas(raw)
		if err != nil {
			return ospf.LSDB{}, fmt.Errorf("section %s: %w", quote(s.key), err)
		}
		if len(extra) > 0 {
			db.Unknown = append(db.Unknown, ospf.UnknownContent{Section: s.key})
		}
		for _, id := range slices.Sorted(maps.Keys(areas)) {
			if _, ok := parseIPv4(id); !ok {
				return ospf.LSDB{}, fmt.Errorf("section %s: area %s is not a dotted IPv4 area", quote(s.key), quote(id))
			}
			list, err := arrayOf(areas[id])
			if err != nil {
				return ospf.LSDB{}, fmt.Errorf("section %s area %s: %w", quote(s.key), quote(id), err)
			}
			if s.opaque {
				if len(list) > 0 {
					db.Unsupported = append(db.Unsupported, ospf.Unsupported{Area: id, Section: s.key, Entries: len(list)})
				}
				continue
			}
			for _, entry := range list {
				l, err := lsaFrom(entry, s.t, s.lsaName, id)
				if err != nil {
					return ospf.LSDB{}, fmt.Errorf("section %s area %s: %w", quote(s.key), quote(id), err)
				}
				k := lsaKey{id, l.LinkStateID, l.AdvertisingRouter, l.Type}
				if seen[k] {
					return ospf.LSDB{}, fmt.Errorf("section %s area %s repeats %s advertisement %s from %s", quote(s.key), quote(id), l.Type, quote(l.LinkStateID), quote(l.AdvertisingRouter))
				}
				seen[k] = true
				db.LSAs = append(db.LSAs, l)
			}
		}
	}

	for _, s := range lsdbASSections {
		known[s.key] = true
		raw, err := get[json.RawMessage](f, s.key)
		if err != nil {
			return ospf.LSDB{}, err
		}
		list, err := arrayOf(raw)
		if err != nil {
			return ospf.LSDB{}, fmt.Errorf("section %s: %w", quote(s.key), err)
		}
		if s.opaque {
			if len(list) > 0 {
				db.Unsupported = append(db.Unsupported, ospf.Unsupported{Section: s.key, Entries: len(list)})
			}
			continue
		}
		for _, entry := range list {
			l, err := lsaFrom(entry, s.t, "AS-external-LSA", "")
			if err != nil {
				return ospf.LSDB{}, fmt.Errorf("section %s: %w", quote(s.key), err)
			}
			k := lsaKey{"", l.LinkStateID, l.AdvertisingRouter, l.Type}
			if seen[k] {
				return ospf.LSDB{}, fmt.Errorf("section %s repeats external advertisement %s from %s", quote(s.key), quote(l.LinkStateID), quote(l.AdvertisingRouter))
			}
			seen[k] = true
			db.LSAs = append(db.LSAs, l)
		}
	}

	for _, key := range slices.Sorted(maps.Keys(f)) {
		if known[key] {
			continue
		}
		db.Unknown = append(db.Unknown, unknownSection(key, f[key])...)
	}
	return db, nil
}

// splitAreas reads an area-scoped section. It returns the per-area arrays and
// the names of any other keys that hold content.
func splitAreas(raw json.RawMessage) (map[string]json.RawMessage, []string, error) {
	f, err := objectFields(raw)
	if err != nil {
		return nil, nil, err
	}
	areas, err := get[map[string]json.RawMessage](f, "areas")
	if err != nil {
		return nil, nil, err
	}
	var extra []string
	for _, k := range slices.Sorted(maps.Keys(f)) {
		if k != "areas" && !emptyJSON(f[k]) {
			extra = append(extra, k)
		}
	}
	return areas, extra, nil
}

// unknownSection scopes the content of a section this package does not read. An
// area-scoped section with content in some areas is unknown in those areas only.
// Any other shape is unknown for the whole VRF.
func unknownSection(key string, raw json.RawMessage) []ospf.UnknownContent {
	if emptyJSON(raw) {
		return nil
	}
	areas, extra, err := splitAreas(raw)
	if err == nil && len(extra) == 0 {
		var out []ospf.UnknownContent
		for _, id := range slices.Sorted(maps.Keys(areas)) {
			if _, ok := parseIPv4(id); !ok {
				return []ospf.UnknownContent{{Section: key}}
			}
			if !emptyJSON(areas[id]) {
				out = append(out, ospf.UnknownContent{Area: id, Section: key})
			}
		}
		if len(out) > 0 {
			return out
		}
		return nil
	}
	return []ospf.UnknownContent{{Section: key}}
}

// lsaFrom reads one advertisement of a known type. area is empty for AS-scope
// advertisements. lsaName is checked against lsaType when the entry carries one.
func lsaFrom(raw json.RawMessage, t ospf.LSAType, lsaName, area string) (ospf.LSA, error) {
	f, err := objectFields(raw)
	if err != nil {
		return ospf.LSA{}, err
	}
	if v, ok := f["lsaType"]; ok && lsaName != "" {
		var got string
		if err := json.Unmarshal(v, &got); err != nil || got != lsaName {
			return ospf.LSA{}, fmt.Errorf("lsaType does not match its section, which holds %s", quote(lsaName))
		}
	}
	age, err := get[uint64](f, "lsaAge")
	if err != nil {
		return ospf.LSA{}, err
	}
	lsid, err := ipv4Key(f, "linkStateId")
	if err != nil {
		return ospf.LSA{}, err
	}
	adv, err := ipv4Key(f, "advertisingRouter")
	if err != nil {
		return ospf.LSA{}, err
	}
	seq, err := get[string](f, "lsaSeqNumber")
	if err != nil {
		return ospf.LSA{}, err
	}
	if _, err := strconv.ParseUint(seq, 16, 32); err != nil {
		return ospf.LSA{}, fmt.Errorf("key lsaSeqNumber is %s, not a 32-bit hex value", quote(seq))
	}
	sum, err := hexKey(f, "checksum", 16)
	if err != nil {
		return ospf.LSA{}, err
	}
	l := ospf.LSA{
		Area: area, Type: t, LinkStateID: lsid.String(), AdvertisingRouter: adv.String(),
		Age: age, Sequence: seq, Checksum: sum,
	}
	switch t {
	case ospf.LSARouter:
		prefixes, err := stubPrefixes(f)
		if err != nil {
			return ospf.LSA{}, err
		}
		l.Prefixes = prefixes
	case ospf.LSANetwork, ospf.LSASummary, ospf.LSANSSA, ospf.LSAExternal:
		p, note, err := integerPrefix(lsid, f)
		if err != nil {
			return ospf.LSA{}, err
		}
		l.Prefixes = []ospf.Prefix{{Prefix: p, Note: note}}
		if t == ospf.LSAExternal {
			metric, err := get[uint64](f, "metric")
			if err != nil {
				return ospf.LSA{}, err
			}
			l.Metric = &metric
		}
	}
	return l, nil
}

// stubPrefixes derives the prefixes of a router LSA's stub links. Each stub link
// names its prefix with a dotted mask. Transit, point-to-point, and virtual links
// name no prefix, so they yield none.
func stubPrefixes(f fields) ([]ospf.Prefix, error) {
	raw, ok := f["routerLinks"]
	if !ok {
		return nil, nil
	}
	links, err := objectFields(raw)
	if err != nil {
		return nil, fmt.Errorf("key \"routerLinks\": %w", err)
	}
	var out []ospf.Prefix
	for _, name := range slices.Sorted(maps.Keys(links)) {
		lf, err := objectFields(links[name])
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", quote(name), err)
		}
		kind, err := get[string](lf, "linkType")
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", quote(name), err)
		}
		if kind != "Stub Network" {
			continue
		}
		addr, err := ipv4Key(lf, "networkAddress")
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", quote(name), err)
		}
		mask, err := get[string](lf, "networkMask")
		if err != nil {
			return nil, fmt.Errorf("link %s: %w", quote(name), err)
		}
		n, ok := dottedMaskLength(mask)
		if !ok {
			return nil, fmt.Errorf("link %s: networkMask %s is not a contiguous dotted mask", quote(name), quote(mask))
		}
		p := netip.PrefixFrom(addr, n).Masked()
		var note string
		if p.Addr() != addr {
			note = fmt.Sprintf("network address %s has host bits; prefix taken as %s", addr, p)
		}
		out = append(out, ospf.Prefix{Prefix: p, Note: note})
	}
	return out, nil
}

// integerPrefix derives the prefix of an advertisement whose mask is an integer
// length, as Types 2, 3, 5, and 7 print it. Host bits in the link state ID are
// cleared, and the note says so.
func integerPrefix(lsid netip.Addr, f fields) (netip.Prefix, string, error) {
	n, err := get[uint64](f, "networkMask")
	if err != nil {
		return netip.Prefix{}, "", err
	}
	if n > 32 {
		return netip.Prefix{}, "", fmt.Errorf("networkMask %d is not a length from 0 to 32", n)
	}
	p := netip.PrefixFrom(lsid, int(n)).Masked()
	var note string
	if p.Addr() != lsid {
		note = fmt.Sprintf("link state ID %s has host bits; prefix taken as %s", lsid, p)
	}
	return p, note, nil
}

// dottedMaskLength returns the prefix length of a dotted mask. It refuses a mask
// that is not one unbroken run of ones.
func dottedMaskLength(s string) (int, bool) {
	addr, ok := parseIPv4(s)
	if !ok {
		return 0, false
	}
	b := addr.As4()
	m := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := bits.OnesCount32(m)
	if m != ^uint32(0)<<(32-n) {
		return 0, false
	}
	return n, true
}
