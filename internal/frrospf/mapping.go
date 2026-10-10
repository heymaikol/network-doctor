package frrospf

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// mappedNeighbors is the neighbor side of one accepted detail capture: the
// netmodel neighbors it wrote, and a record for every neighbor FRR reported.
type mappedNeighbors struct {
	neighbors []netmodel.Neighbor
	records   []Record
}

// candidate is one neighbor record after parsing. reason is set when the record
// is refused, and the record is then reported without a neighbor.
type candidate struct {
	rec      Record
	rid      string // router ID from the key, or "" for the noNbrId placeholder
	addr     netip.Addr
	state    string // left half of nbrState
	localAdr netip.Addr
	hasLocal bool
	reason   string
}

// mapNeighbors parses every neighbor record of one detail capture and maps each
// valid one to the captured peer interface that owns its address. local is the
// node's own interface table, or nil when its interface capture is absent.
// owners lists the captured interfaces that hold each address in the VRF.
func mapNeighbors(c Capture, entries map[string][]detailRecord, local map[string]ifaceInfo, owners map[netip.Addr][]owner) mappedNeighbors {
	var cands []candidate
	for _, key := range slices.Sorted(maps.Keys(entries)) {
		for _, rec := range entries[key] {
			cands = append(cands, parseEntry(c, key, rec))
		}
	}
	markRecordDuplicates(cands)

	var out mappedNeighbors
	for i := range cands {
		cd := &cands[i]
		if cd.reason == "" {
			resolve(cd, c.Node, local, owners[cd.addr])
		}
		if !cd.rec.Mapped {
			cd.rec.Reason = textsafe.Clean(cd.reason)
		}
		out.records = append(out.records, cd.rec)
		if cd.rec.Mapped {
			out.neighbors = append(out.neighbors, neighborOf(cd))
		}
	}
	return out
}

// parseEntry checks one neighbor record's fields. Each failed check sets the
// reason and stops, so a record is refused for its first problem. Known fields
// that are missing or invalid refuse the record, never the whole capture.
func parseEntry(c Capture, key string, rec detailRecord) candidate {
	cd := candidate{rec: Record{Source: c.Source, Node: c.Node, VRF: c.VRF}}
	fail := func(format string, args ...any) {
		if cd.reason == "" {
			cd.reason = fmt.Sprintf(format, args...)
		}
	}

	// decodeNeighborDetail has already checked that key is a dotted IPv4 router
	// ID or noNbrID.
	if key != noNbrID {
		cd.rid = key
		cd.rec.RouterID = key
	}

	switch {
	case rec.IfaceName == nil || *rec.IfaceName == "":
		fail("ifaceName is missing")
	case !plain(*rec.IfaceName):
		fail("ifaceName has control or invisible characters")
	case strings.Contains(*rec.IfaceName, ":"):
		fail("ifaceName %s carries an address label; the detail form names the bare interface", quote(*rec.IfaceName))
	default:
		cd.rec.LocalInterface = *rec.IfaceName
	}

	if rec.IfaceAddress == nil {
		fail("ifaceAddress is missing")
	} else if addr, ok := parseIPv4(*rec.IfaceAddress); ok {
		cd.addr = addr
		cd.rec.NeighborAddr = addr.String()
	} else {
		cd.rec.NeighborAddr = textsafe.Clean(*rec.IfaceAddress)
		fail("ifaceAddress %s is not IPv4", quote(*rec.IfaceAddress))
	}

	if rec.NbrState == nil {
		fail("nbrState is missing")
	} else {
		cd.rec.State = textsafe.Clean(*rec.NbrState)
		left, err := parseState(*rec.NbrState)
		switch {
		case err != nil:
			fail("%v", err)
		case key == noNbrID && left != "Attempt":
			// FRR prints the placeholder only for a neighbor in Attempt with no
			// router ID (ospf_vty.c, around line 5259 of the 10.7.0 tag).
			fail("%s is printed only for an Attempt neighbor; state is %s", quote(noNbrID), quote(left))
		default:
			cd.state = left
		}
	}

	if rec.AreaID == nil {
		fail("areaId is missing")
	} else {
		cd.rec.Area = textsafe.Clean(*rec.AreaID)
		if err := checkArea(*rec.AreaID); err != nil {
			fail("%v", err)
		}
	}

	if rec.LocalIfaceAddress != nil {
		if addr, ok := parseIPv4(*rec.LocalIfaceAddress); ok {
			cd.localAdr, cd.hasLocal = addr, true
		} else {
			fail("localIfaceAddress %s is not IPv4", quote(*rec.LocalIfaceAddress))
		}
	}

	return cd
}

// markRecordDuplicates refuses every valid record that repeats a local
// interface and neighbor address. The router ID and state of the repeats differ
// or agree, and nothing says which is right, so none of them is used. A repeat
// counts even when its twin is refused for another field, because the twin may
// be the right record.
func markRecordDuplicates(cands []candidate) {
	type pair struct{ iface, addr string }
	count := map[pair]int{}
	for i := range cands {
		if cands[i].rec.LocalInterface != "" && cands[i].addr.IsValid() {
			count[pair{cands[i].rec.LocalInterface, cands[i].rec.NeighborAddr}]++
		}
	}
	for i := range cands {
		cd := &cands[i]
		if cd.reason != "" {
			continue
		}
		if n := count[pair{cd.rec.LocalInterface, cd.rec.NeighborAddr}]; n > 1 {
			cd.reason = fmt.Sprintf("%d records for %s and %s; no state is chosen", n, quote(cd.rec.LocalInterface), quote(cd.rec.NeighborAddr))
		}
	}
}

// resolve maps a valid record to a peer. It refuses when the node has no
// accepted interface capture, when the local interface is missing from it or has
// no usable address and prefix, when the neighbor address is outside the local
// subnet, when the address is the node's own, when no captured peer owns it,
// when several interfaces own it, when the one owner has no usable prefix, or
// when the router ID contradicts the peer's own report. Router ID is only a
// cross-check. It never chooses the peer.
func resolve(cd *candidate, node string, local map[string]ifaceInfo, owners []owner) {
	if local == nil {
		cd.reason = "node has no accepted interface capture in this VRF; local interface unverified"
		return
	}
	li, ok := local[cd.rec.LocalInterface]
	switch {
	case !ok:
		cd.reason = fmt.Sprintf("interface %s is not in the node's interface capture", quote(cd.rec.LocalInterface))
		return
	case !li.hasPrefix:
		cd.reason = fmt.Sprintf("interface %s has no usable address and prefix; subnet unverified", quote(li.name))
		return
	case cd.hasLocal && cd.localAdr != li.addr:
		cd.reason = fmt.Sprintf("localIfaceAddress %s disagrees with interface %s address %s", quote(cd.localAdr.String()), quote(li.name), quote(li.addr.String()))
		return
	case !li.prefix.Masked().Contains(cd.addr):
		cd.reason = fmt.Sprintf("ifaceAddress %s is outside interface %s subnet %s", quote(cd.rec.NeighborAddr), quote(li.name), quote(li.prefix.Masked().String()))
		return
	}
	for _, ow := range owners {
		if ow.node == node {
			cd.reason = fmt.Sprintf("ifaceAddress %s is this node's own address", quote(cd.rec.NeighborAddr))
			return
		}
	}
	switch len(owners) {
	case 0:
		cd.reason = fmt.Sprintf("no captured interface in this VRF owns %s", quote(cd.rec.NeighborAddr))
		return
	case 1:
	default:
		cd.reason = fmt.Sprintf("%s is owned by %d captured interfaces; not matched", quote(cd.rec.NeighborAddr), len(owners))
		return
	}
	peer := owners[0]
	if !peer.prefixed {
		cd.reason = fmt.Sprintf("%s is owned by node %s interface %s, whose prefix length is unusable; not matched", quote(cd.rec.NeighborAddr), quote(peer.node), quote(peer.iface))
		return
	}
	if cd.rid != "" && peer.routerID != "" && cd.rid != peer.routerID {
		cd.reason = fmt.Sprintf("router ID %s disagrees with node %s interface %s, which reports %s", quote(cd.rid), quote(peer.node), quote(peer.iface), quote(peer.routerID))
		return
	}
	cd.rec.Mapped = true
	cd.rec.RemoteNode = peer.node
	cd.rec.RemoteInterface = peer.iface
}

// neighborOf writes a mapped record as a netmodel neighbor. The state is the
// left half of nbrState, which the analyzer reads. The router ID is written only
// when FRR reported one. The role half is not written, because the analyzer does
// not read it.
func neighborOf(cd *candidate) netmodel.Neighbor {
	attrs := []netmodel.Attribute{{Key: keyState, Value: cd.state}}
	if cd.rid != "" {
		attrs = append(attrs, netmodel.Attribute{Key: keyRouterID, Value: cd.rid})
	}
	return netmodel.Neighbor{
		LocalInterface:  cd.rec.LocalInterface,
		RemoteNode:      cd.rec.RemoteNode,
		RemoteInterface: cd.rec.RemoteInterface,
		RemoteAddr:      cd.addr,
		Attributes:      attrs,
	}
}

// nsmStates is the closed set of neighbor state machine names FRR prints. The
// analyzer reads only the eight that are OSPF states, and passes the other two
// through, where it reports them as unreadable.
var nsmStates = map[string]bool{
	"DependUpon": true, "Deleted": true, "Down": true, "Attempt": true, "Init": true,
	"2-Way": true, "ExStart": true, "Exchange": true, "Loading": true, "Full": true,
}

// ismRoles is the closed set of roles FRR prints after the slash. "-" marks a
// point-to-point link, where no role applies.
var ismRoles = map[string]bool{"DR": true, "Backup": true, "DROther": true, "-": true}

// parseState splits nbrState into its state and role halves. It returns the
// state half, which is the only half this package keeps.
func parseState(s string) (string, error) {
	state, role, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(role, "/") {
		return "", fmt.Errorf("nbrState %s is not a state and role pair", quote(s))
	}
	if !nsmStates[state] {
		return "", fmt.Errorf("nbrState %s has state %s, which is not a neighbor state", quote(s), quote(state))
	}
	if !ismRoles[role] {
		return "", fmt.Errorf("nbrState %s has role %s, which is not DR, Backup, DROther, or -", quote(s), quote(role))
	}
	return state, nil
}

// checkArea accepts a dotted IPv4 area with an optional known qualifier, as FRR
// prints it: "0.0.0.1", "0.0.0.1 [Stub]", or "0.0.0.1 [NSSA]". Anything else
// refuses the record. The qualifier is checked, not stripped, and it stays in
// the report. Whether it matters is decided later, when areas are ingested.
func checkArea(s string) error {
	base, qual, hasQual := strings.Cut(s, " ")
	if _, ok := parseIPv4(base); !ok {
		return fmt.Errorf("areaId %s is not a dotted IPv4 area", quote(s))
	}
	if hasQual && qual != "[Stub]" && qual != "[NSSA]" {
		return fmt.Errorf("areaId %s has qualifier %s, which is not [Stub] or [NSSA]", quote(s), quote(qual))
	}
	return nil
}
