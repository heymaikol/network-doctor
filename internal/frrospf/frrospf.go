// Package frrospf reads recorded FRRouting 10.7.0 OSPFv2 command output and
// turns it into netmodel observations for the existing OSPF analyzer.
//
// The package reads only the captures it is handed. It never contacts a router,
// runs a command, or changes configuration. Each capture carries the node, VRF,
// source label, collection time, FRR version, and command its caller declares.
// None of those facts is read from the JSON. Every observation it returns says
// neighbors and routes are not complete: the command omits Down neighbors and
// covers one VRF at a time, so an absent neighbor proves nothing.
//
// The package has no command-line entry point of its own. The import mode in
// internal/app loads a manifest, calls Import, and writes the report and any
// topology file. This package decides only what the captures establish.
package frrospf

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Version is the one FRRouting release this package reads. A capture declares
// it, and any other version is refused.
const Version = "10.7.0"

// The two commands this package reads. A capture declares one of them, and its
// JSON must hold the payload that command produces.
const (
	CommandNeighborDetail = "show ip ospf neighbor detail json"
	CommandInterface      = "show ip ospf interface json"
)

// MaxCaptureBytes bounds one capture. It matches the topology file limit.
const MaxCaptureBytes = 1 << 20

// The attribute keys this package writes. internal/ospf reads the same keys,
// and a test in this package checks that they still agree.
const (
	keyState    = "ospf.state"
	keyRouterID = "ospf.router_id"
)

// Capture is one recorded command output and the facts its caller declares
// about it. Nothing here is read from Data.
type Capture struct {
	Node        string
	VRF         string
	Source      string    // unique within one Import, for example "frr:r1 neighbor detail"
	CollectedAt time.Time // when the command ran
	FRRVersion  string    // must be Version
	Command     string    // one of the Command constants
	Data        []byte    // the command output as recorded
}

// Result is what Import returns: the observations it could write, and the
// report of every capture and neighbor record it read.
type Result struct {
	Observations []netmodel.Observation
	Report       Report
}

// Report accounts for every capture and every neighbor record. Nothing is
// dropped silently.
type Report struct {
	Captures []CaptureReport
	Records  []Record
}

// CaptureReport is the outcome for one capture.
type CaptureReport struct {
	Source     string
	Node       string
	VRF        string
	Command    string
	Accepted   bool
	Reason     string   // why the capture was refused; empty when accepted
	Empty      bool     // accepted with an empty neighbor or interface list
	Interfaces int      // interfaces written to the observation
	Neighbors  int      // neighbors written to the observation
	Notes      []string // interface-level issues that did not refuse the capture
}

// Record is one neighbor record as FRR reported it, with its mapping outcome.
// A mapped record becomes a netmodel neighbor. An unmapped record keeps the
// reason, and no neighbor is written for it.
type Record struct {
	Source          string
	Node            string
	VRF             string
	LocalInterface  string
	NeighborAddr    string
	RouterID        string // empty when FRR reported no router ID
	State           string // nbrState as reported, state and role together
	Area            string // areaId as reported, qualifier included
	Mapped          bool
	RemoteNode      string // set when Mapped
	RemoteInterface string // set when Mapped
	Reason          string // set when not Mapped
}

// Import validates each capture, decodes the accepted ones, maps neighbor
// records to the captured peer interface that owns their address, and returns
// one observation per accepted capture. A record maps only when the address has
// exactly one captured owner, every node in the default VRF is accounted for,
// and the peer confirms the record's router ID. Captures are never merged, and
// nothing is chosen between conflicting ones. The error is a netmodel refusal,
// which means a bug in this package.
func Import(captures []Capture) (Result, error) {
	ordered := slices.Clone(captures)
	slices.SortStableFunc(ordered, compareCaptures)

	outcomes := make([]outcome, len(ordered))
	for i, c := range ordered {
		outcomes[i] = outcome{capture: c, reason: checkMetadata(c)}
	}
	markDuplicates(outcomes)
	for i := range outcomes {
		if outcomes[i].reason == "" {
			outcomes[i].parse()
		}
	}

	// Each captured node's interfaces, and the owners of each address in each
	// VRF. Only accepted interface captures contribute.
	local := map[scope]map[string]ifaceInfo{}
	owners := map[string]map[netip.Addr][]owner{}
	for i := range outcomes {
		o := &outcomes[i]
		if o.reason != "" || o.capture.Command != CommandInterface {
			continue
		}
		table := make(map[string]ifaceInfo, len(o.ifaces))
		byAddr := owners[o.capture.VRF]
		if byAddr == nil {
			byAddr = map[netip.Addr][]owner{}
			owners[o.capture.VRF] = byAddr
		}
		for _, info := range o.ifaces {
			table[info.name] = info
			if info.hasAddr {
				byAddr[info.addr] = append(byAddr[info.addr], owner{node: o.capture.Node, iface: info.name, routerID: info.routerID, prefixed: info.hasPrefix})
			}
		}
		local[scope{o.capture.Node, o.capture.VRF}] = table
	}

	gate := ownershipGate(outcomes, local)
	for i := range outcomes {
		o := &outcomes[i]
		if o.reason != "" || o.capture.Command != CommandNeighborDetail {
			continue
		}
		s := scope{o.capture.Node, o.capture.VRF}
		o.mapped = mapNeighbors(o.capture, o.entries, local[s], owners[o.capture.VRF], gate)
	}

	var res Result
	var obs []netmodel.Observation
	for i := range outcomes {
		o := &outcomes[i]
		cr := CaptureReport{
			Source:   textsafe.Clean(o.capture.Source),
			Node:     textsafe.Clean(o.capture.Node),
			VRF:      textsafe.Clean(o.capture.VRF),
			Command:  textsafe.Clean(o.capture.Command),
			Accepted: o.reason == "",
			Reason:   textsafe.Clean(o.reason),
			Empty:    o.empty,
			Notes:    o.notes,
		}
		if o.reason != "" {
			res.Report.Captures = append(res.Report.Captures, cr)
			continue
		}
		ob := netmodel.Observation{
			Provenance: netmodel.Provenance{Source: o.capture.Source, CollectedAt: o.capture.CollectedAt},
			Plane:      netmodel.PlaneControl,
			Node:       o.capture.Node,
			VRF:        o.capture.VRF,
		}
		if o.capture.Command == CommandInterface {
			ob.Interfaces = interfaceList(o.ifaces)
			cr.Interfaces = len(ob.Interfaces)
		} else {
			ob.Neighbors = o.mapped.neighbors
			cr.Neighbors = len(ob.Neighbors)
			res.Report.Records = append(res.Report.Records, o.mapped.records...)
		}
		obs = append(obs, ob)
		res.Report.Captures = append(res.Report.Captures, cr)
	}

	m, err := netmodel.New(obs...)
	if err != nil {
		return Result{}, fmt.Errorf("frrospf: %w", err)
	}
	res.Observations = m.Observations()
	return res, nil
}

// ownershipGate returns why no neighbor may map, or "" when mapping may proceed.
// Every node that any capture names, under any VRF label and whether or not that
// capture was accepted, must have an accepted default-VRF interface capture with
// no unusable ipAddress. Only then is every address in the default VRF accounted
// for. A node without a capture has subnets nobody can see, so no narrower rule
// is safe: an address in one of them could belong to it.
func ownershipGate(outcomes []outcome, local map[scope]map[string]ifaceInfo) string {
	named := map[string]bool{}
	for i := range outcomes {
		named[outcomes[i].capture.Node] = true
	}
	for _, node := range slices.Sorted(maps.Keys(named)) {
		ifaces, ok := local[scope{node, "default"}]
		if !ok {
			return fmt.Sprintf("node %s has no accepted interface capture in VRF \"default\"; address ownership incomplete", quote(node))
		}
		for _, name := range slices.Sorted(maps.Keys(ifaces)) {
			if ifaces[name].unusable {
				return fmt.Sprintf("node %s interface %s has an ipAddress that is not IPv4; address ownership incomplete", quote(node), quote(name))
			}
		}
	}
	return ""
}

// scope names one reporter's view: one node in one VRF.
type scope struct{ node, vrf string }

// owner is one captured interface that holds an address.
type owner struct {
	node     string
	iface    string
	routerID string // the router ID the interface reports, or ""
	prefixed bool   // the interface's prefix length is usable
}

// ifaceInfo is one interface from an accepted interface capture. hasAddr says
// the address parsed, so the interface owns it. hasPrefix says the prefix
// length is usable too, which the subnet checks need. unusable says the capture
// gave an ipAddress that is not IPv4, so the interface may hold an address this
// package cannot read.
type ifaceInfo struct {
	name      string
	addr      netip.Addr
	prefix    netip.Prefix
	hasAddr   bool
	hasPrefix bool
	unusable  bool
	routerID  string
}

// outcome carries one capture through the passes. reason is set once the
// capture is refused, and the other fields are read only when it is accepted.
type outcome struct {
	capture Capture
	reason  string
	empty   bool
	notes   []string
	ifaces  []ifaceInfo
	entries map[string][]detailRecord
	mapped  mappedNeighbors
}

// parse decodes an accepted capture by its declared command.
func (o *outcome) parse() {
	switch o.capture.Command {
	case CommandInterface:
		raw, reason := decodeInterfaces(o.capture.Data)
		if reason != "" {
			o.reason = reason
			return
		}
		ifaces, notes, err := buildInterfaces(raw)
		if err != nil {
			o.reason = err.Error()
			return
		}
		o.ifaces, o.notes, o.empty = ifaces, notes, len(raw) == 0
	case CommandNeighborDetail:
		raw, reason := decodeNeighborDetail(o.capture.Data)
		if reason != "" {
			o.reason = reason
			return
		}
		o.entries = raw
		o.empty = true
		for _, recs := range raw {
			if len(recs) > 0 {
				o.empty = false
			}
		}
	}
}

// checkMetadata returns why a capture's declared facts cannot be used, or "".
// Every declared string must be plain text, because it reaches the report.
func checkMetadata(c Capture) string {
	switch {
	case c.Source == "":
		return "source is empty"
	case !plain(c.Source):
		return "source has control or invisible characters"
	case c.Node == "":
		return "node is empty"
	case !plain(c.Node):
		return "node has control or invisible characters"
	case c.VRF == "":
		return `vrf is empty; use "default", the only VRF these commands read`
	case !plain(c.VRF):
		return "vrf has control or invisible characters"
	case c.VRF != "default":
		// Both commands read the default VRF when no VRF is named, so the label
		// must be default. The importer issues no VRF-qualified commands.
		return fmt.Sprintf("vrf %s is not supported; these commands read only the default VRF", quote(c.VRF))
	case c.CollectedAt.IsZero():
		return "collected_at is zero"
	case c.FRRVersion != Version:
		return fmt.Sprintf("FRR version %s is not %s", quote(c.FRRVersion), Version)
	case c.Command != CommandNeighborDetail && c.Command != CommandInterface:
		return fmt.Sprintf("command %s is not supported", quote(c.Command))
	case len(c.Data) > MaxCaptureBytes:
		return fmt.Sprintf("output exceeds %d bytes", MaxCaptureBytes)
	}
	return ""
}

// markDuplicates refuses every capture that shares its source label with
// another, and every capture that repeats a node and command under any VRF
// label. Only the default VRF is read, so a conflicting label is a mislabel and
// must not split the pair. Neither case has a right answer to pick, so both
// sides are refused. The groups include captures already refused for their own
// metadata, so a broken capture cannot leave its twin standing. A capture keeps
// its own reason when it has one.
func markDuplicates(outcomes []outcome) {
	// Identity is compared after sanitizing, because the report shows sanitized
	// text. Two declared names that read the same must count as one.
	bySource := map[string][]int{}
	byKey := map[[2]string][]int{}
	for i := range outcomes {
		c := outcomes[i].capture
		src := textsafe.Clean(c.Source)
		bySource[src] = append(bySource[src], i)
		k := [2]string{textsafe.Clean(c.Node), textsafe.Clean(c.Command)}
		byKey[k] = append(byKey[k], i)
	}
	mark := func(idx []int, reason string) {
		for _, i := range idx {
			if outcomes[i].reason == "" {
				outcomes[i].reason = reason
			}
		}
	}
	for src, idx := range bySource {
		if len(idx) > 1 {
			mark(idx, fmt.Sprintf("source label %s is used by %d captures", quote(src), len(idx)))
		}
	}
	for k, idx := range byKey {
		if len(idx) > 1 {
			mark(idx, fmt.Sprintf("%d captures give %s for node %s", len(idx), quote(k[1]), quote(k[0])))
		}
	}
}

// buildInterfaces turns the decoded interface entries into interface records,
// in name order. An address that cannot be used is noted and left off the
// interface, so the interface is still written but cannot be matched.
func buildInterfaces(raw map[string]interfaceRecord) ([]ifaceInfo, []string, error) {
	var out []ifaceInfo
	var notes []string
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		if name == "" || !plain(name) {
			return nil, nil, fmt.Errorf("interface name %s is not plain text", quote(name))
		}
		rec := raw[name]
		info := ifaceInfo{name: name}
		if rec.IPAddress != nil {
			addr, ok := parseIPv4(*rec.IPAddress)
			switch {
			case !ok:
				info.unusable = true
				notes = append(notes, fmt.Sprintf("interface %s: ipAddress %s is not IPv4; not matchable", quote(name), quote(*rec.IPAddress)))
			case rec.IPAddressPrefixlen == nil || *rec.IPAddressPrefixlen < 0 || *rec.IPAddressPrefixlen > 32:
				info.addr, info.hasAddr = addr, true
				notes = append(notes, fmt.Sprintf("interface %s: ipAddress has no valid ipAddressPrefixlen; subnet unverified", quote(name)))
			default:
				info.addr, info.hasAddr = addr, true
				info.prefix, info.hasPrefix = netip.PrefixFrom(addr, *rec.IPAddressPrefixlen), true
			}
		} else {
			notes = append(notes, fmt.Sprintf("interface %s: ipAddress is missing; not matchable", quote(name)))
		}
		if rec.RouterID == nil {
			notes = append(notes, fmt.Sprintf("interface %s: routerId is missing", quote(name)))
		} else if rid, ok := parseIPv4(*rec.RouterID); ok {
			info.routerID = rid.String()
		} else {
			notes = append(notes, fmt.Sprintf("interface %s: routerId %s is not IPv4", quote(name), quote(*rec.RouterID)))
		}
		out = append(out, info)
	}
	return out, notes, nil
}

// interfaceList writes the interfaces of an accepted capture as netmodel
// interfaces. The router ID is recorded as ospf.router_id, which the OSPF
// analyzer reads as the interface's own identity.
func interfaceList(ifaces []ifaceInfo) []netmodel.Interface {
	var out []netmodel.Interface
	for _, info := range ifaces {
		i := netmodel.Interface{Name: info.name}
		if info.hasPrefix {
			i.Addresses = []netip.Prefix{info.prefix}
		}
		if info.routerID != "" {
			i.Attributes = []netmodel.Attribute{{Key: keyRouterID, Value: info.routerID}}
		}
		out = append(out, i)
	}
	return out
}

// plain reports whether text is free of control and escape characters, so it
// can be stored and shown unchanged.
func plain(s string) bool { return textsafe.Clean(s) == s }

// parseIPv4 accepts only a dotted IPv4 address. IPv4-mapped IPv6 is refused.
func parseIPv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Is4()
}

// compareCaptures orders captures for a stable report, whatever order the caller
// passed them in.
func compareCaptures(a, b Capture) int {
	return strings.Compare(a.VRF+"\x00"+a.Node+"\x00"+a.Command+"\x00"+a.Source,
		b.VRF+"\x00"+b.Node+"\x00"+b.Command+"\x00"+b.Source)
}
