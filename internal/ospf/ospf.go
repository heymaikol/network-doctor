// Package ospf reads the OSPF attributes a netmodel.Model carries and reports
// what the recorded evidence says about each adjacency. It reads what it is
// given. It runs no protocol, sends no probe, and never confirms a route or a
// link. Every finding states its strength, and no finding names a root cause.
//
// The attributes it reads are the neighbor and interface keys below, under the
// "ospf." namespace. Neighbor states come from the control plane, which holds
// what the control plane reports. Expected neighbors come from the configured
// and intended planes. Interface areas are compared only within the configured
// plane. Links are matched only when both sides report each other on the same
// routing domain and interfaces. A source may leave the remote interface empty,
// and that record then names the same neighbor as any remote interface.
package ospf

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// The attribute keys this package reads. Any other ospf.* key marks a record as
// OSPF but changes no finding.
const (
	KeyState    = "ospf.state"
	KeyArea     = "ospf.area"
	KeyRouterID = "ospf.router_id"
)

// states is the closed vocabulary of OSPF neighbor states. A value outside it is
// reported as unreadable and never interpreted.
var states = map[string]bool{
	"down": true, "attempt": true, "init": true, "2-way": true,
	"exstart": true, "exchange": true, "loading": true, "full": true,
}

// Strength says how far a finding's evidence goes.
type Strength string

const (
	// Reported: a source states the fact directly.
	Reported Strength = "reported"
	// ConsistentWith: the evidence fits a possible explanation. It does not
	// establish one.
	ConsistentWith Strength = "consistent_with"
	// Unknown: the evidence is missing or cannot be read.
	Unknown Strength = "unknown"
	// Conflicting: sources disagree, and no reading can settle which is right.
	Conflicting Strength = "conflicting"
)

// Kind names what a finding is about.
type Kind string

const (
	KindNeighborState        Kind = "neighbor_state"
	KindMissingNeighbor      Kind = "missing_neighbor"
	KindAreaMismatch         Kind = "area_mismatch"
	KindAttributeConflict    Kind = "attribute_conflict"
	KindIncompleteAttributes Kind = "incomplete_attributes"
	KindRouterIDUnconfirmed  Kind = "router_id_unconfirmed"
)

const (
	limitFull              = "FULL is the reporter's own claim. It does not prove that the link carries traffic or that the destination is reachable."
	limitTwoWay            = "2-way is the normal stable state between two non-designated routers on a broadcast network. Alone it shows no fault."
	limitBeforeFull        = "A state before FULL is what the reporter says. It names no root cause and does not prove the far side is down."
	limitStatesConflict    = "Sources disagree about this neighbor state. No state is chosen, and the newest timestamp does not decide."
	limitMissingConsistent = "The reporter marks its neighbor list complete, and that list holds OSPF records but none for this neighbor. The flag does not show that every OSPF source was collected. The omission does not prove the adjacency is down."
	limitMissingUnknown    = "The evidence cannot show whether the neighbor is absent. Nothing is concluded about the adjacency."
	limitMissingConflict   = "One complete neighbor list lacks a record that another source reports. Neither source is chosen."
	limitAreaMismatch      = "The configured areas differ on the two ends of a link that both sides report. That is consistent with a failed adjacency. It does not name a cause."
	limitAttributeConflict = "Sources or values disagree about one OSPF attribute. No value is chosen."
	limitIncomplete        = "The attribute is missing or cannot be read, so no conclusion rests on it."
	limitRouterID          = "A neighbor record reports this router ID, and the peer's node reports none that matches. A router ID never names a peer, so nothing is matched by it."
)

// Report is the OSPF reading of one model. It has no findings when no OSPF
// evidence applies, so a caller can omit it then.
type Report struct {
	Findings []Finding `json:"findings"`
}

// Finding is one reading of the evidence about one adjacency or one interface.
// Peer and PeerInterface are empty for an interface-only finding.
type Finding struct {
	Kind          Kind       `json:"kind"`
	Strength      Strength   `json:"strength"`
	Node          string     `json:"node"`
	VRF           string     `json:"vrf"`
	Interface     string     `json:"interface,omitempty"`
	Peer          string     `json:"peer,omitempty"`
	PeerInterface string     `json:"peer_interface,omitempty"`
	Detail        string     `json:"detail"`
	Limit         string     `json:"limit"`
	Evidence      []Evidence `json:"evidence"`
}

// Evidence is one recorded row behind a finding, with the provenance of the
// observation that holds it. Note says what the row shows when the row is an
// absence or a link, so a reader can tell it from a reported value.
type Evidence struct {
	Source        string `json:"source"`
	CollectedAt   string `json:"collected_at"`
	Plane         string `json:"plane"`
	Node          string `json:"node"`
	VRF           string `json:"vrf"`
	Interface     string `json:"interface,omitempty"`
	Peer          string `json:"peer,omitempty"`
	PeerInterface string `json:"peer_interface,omitempty"`
	State         string `json:"state,omitempty"`
	Area          string `json:"area,omitempty"`
	RouterID      string `json:"router_id,omitempty"`
	Note          string `json:"note,omitempty"`
}

// Analyze reads m and returns every OSPF finding it supports, in a stable order
// that does not depend on the order the observations were given.
func Analyze(m netmodel.Model) Report {
	a := collect(m.Observations())
	a.neighborStates()
	a.interfaceAreas()
	a.expectedNeighbors()
	a.areaMismatches()
	if len(a.findings) == 0 {
		return Report{}
	}
	slices.SortFunc(a.findings, func(x, y Finding) int { return strings.Compare(x.key(), y.key()) })
	return Report{Findings: a.findings}
}

// link names one directed neighbor identity: the record on node, in vrf,
// from iface, toward peer on peerIface.
type link struct{ node, vrf, iface, peer, peerIface string }

// mirror is the same link as the far side reports it.
func (l link) mirror() link {
	return link{node: l.peer, vrf: l.vrf, iface: l.peerIface, peer: l.node, peerIface: l.iface}
}

// pair is the identity sources agree on when one leaves the remote interface
// empty. An empty remote interface is unreported, so it names the same neighbor.
type pair struct{ node, vrf, iface, peer string }

func (l link) pair() pair { return pair{l.node, l.vrf, l.iface, l.peer} }

func compareLink(a, b link) int {
	return cmp.Or(
		strings.Compare(a.node, b.node),
		strings.Compare(a.vrf, b.vrf),
		strings.Compare(a.iface, b.iface),
		strings.Compare(a.peer, b.peer),
		strings.Compare(a.peerIface, b.peerIface),
	)
}

// record is one neighbor record and the observation that holds it.
type record struct {
	netmodel.Provenance
	plane netmodel.Plane
	link  link
	attrs []netmodel.Attribute
}

// inventory is the neighbor list of one observation.
type inventory struct {
	netmodel.Provenance
	plane     netmodel.Plane
	node, vrf string
	// complete is the reporter's NeighborsComplete flag. It names no protocol.
	complete bool
	// ospf says the list holds at least one OSPF record. A list with no OSPF record
	// says nothing about OSPF.
	ospf      bool
	neighbors []record
}

// absenceCounts says an absent OSPF record in this list is evidence of an
// omission. The list must be marked complete and must hold OSPF records. The flag
// says the list is complete. It does not say every OSPF source was collected.
func (i inventory) absenceCounts() bool { return i.complete && i.ospf }

// ifaceRow is one OSPF-attributed interface and the observation that holds it.
type ifaceRow struct {
	netmodel.Provenance
	plane     netmodel.Plane
	node, vrf string
	iface     string
	attrs     []netmodel.Attribute
}

type ifaceKey struct{ node, vrf, iface string }

// area is the one configured area of an interface, with the rows that set it.
type area struct {
	n    uint32
	rows []Evidence
}

// analysis holds the indexed evidence and the findings built from it.
type analysis struct {
	inv      []inventory
	ifaces   []ifaceRow
	areas    map[ifaceKey]area
	findings []Finding
}

// collect indexes the planes this package reads. Other planes are not read, so a
// fib or observed OSPF row changes nothing.
func collect(obs []netmodel.Observation) analysis {
	var a analysis
	for _, o := range obs {
		switch o.Plane {
		case netmodel.PlaneControl, netmodel.PlaneConfigured, netmodel.PlaneIntended:
		default:
			continue
		}
		inv := inventory{Provenance: o.Provenance, plane: o.Plane, node: o.Node, vrf: o.VRF, complete: o.NeighborsComplete}
		for _, n := range o.Neighbors {
			r := record{
				Provenance: o.Provenance,
				plane:      o.Plane,
				link:       link{o.Node, o.VRF, n.LocalInterface, n.RemoteNode, n.RemoteInterface},
				attrs:      n.Attributes,
			}
			inv.ospf = inv.ospf || ospfRecord(n.Attributes)
			inv.neighbors = append(inv.neighbors, r)
		}
		a.inv = append(a.inv, inv)
		for _, i := range o.Interfaces {
			if ospfRecord(i.Attributes) && o.Plane != netmodel.PlaneIntended {
				a.ifaces = append(a.ifaces, ifaceRow{Provenance: o.Provenance, plane: o.Plane, node: o.Node, vrf: o.VRF, iface: i.Name, attrs: i.Attributes})
			}
		}
	}
	return a
}

// neighborStates reports each operational OSPF neighbor identity. A single state
// from every source is reported. Two states, or a state that is not in the
// vocabulary, is not interpreted. Several reporters are kept side by side.
func (a *analysis) neighborStates() {
	groups := map[pair][]record{}
	for _, inv := range a.inv {
		if inv.plane != netmodel.PlaneControl {
			continue
		}
		for _, r := range inv.neighbors {
			if ospfRecord(r.attrs) {
				groups[r.link.pair()] = append(groups[r.link.pair()], r)
			}
		}
	}
	for p, recs := range groups {
		a.neighborGroup(p, recs)
	}
}

// neighborGroup reads every source's record for one neighbor pair. Sources are
// grouped without their remote interface, because one may leave it unreported.
// Two different remote interfaces are a conflict, and no state is reported for
// them.
func (a *analysis) neighborGroup(p pair, recs []record) {
	ev := evidenceOf(recs, "")
	var known, unreadable, areas, badArea, ids, badID, remote []string
	var reasons []string
	var areaNums []uint32
	missing := 0
	for _, r := range recs {
		if r.link.peerIface != "" {
			remote = appendUnique(remote, r.link.peerIface)
		}
		vals := values(r.attrs, KeyState)
		if len(vals) == 0 {
			missing++
		}
		for _, v := range vals {
			if s := strings.ToLower(strings.TrimSpace(v)); states[s] {
				known = appendUnique(known, s)
			} else {
				unreadable = appendUnique(unreadable, v)
			}
		}
		for _, v := range values(r.attrs, KeyArea) {
			if n, ok := parseArea(v); ok {
				areaNums = appendUniqueNum(areaNums, n)
				areas = appendUnique(areas, strconv.FormatUint(uint64(n), 10))
			} else {
				badArea = appendUnique(badArea, v)
			}
		}
		for _, v := range values(r.attrs, KeyRouterID) {
			if ip, ok := parseRouterID(v); ok {
				ids = appendUnique(ids, ip.String())
			} else {
				badID = appendUnique(badID, v)
			}
		}
	}
	if missing > 0 {
		reasons = append(reasons, fmt.Sprintf("%d record(s) carry no %s", missing, KeyState))
	}
	if len(unreadable) > 0 {
		reasons = append(reasons, fmt.Sprintf("%s %s is not an OSPF neighbor state", KeyState, quoted(unreadable)))
	}
	if len(badArea) > 0 {
		reasons = append(reasons, fmt.Sprintf("%s %s is not an OSPF area", KeyArea, quoted(badArea)))
	}
	if len(badID) > 0 {
		reasons = append(reasons, fmt.Sprintf("%s %s is not a dotted IPv4 router ID", KeyRouterID, quoted(badID)))
	}
	l := link{node: p.node, vrf: p.vrf, iface: p.iface, peer: p.peer}
	if len(remote) == 1 {
		l.peerIface = remote[0]
	}
	// A state is agreement only when every record for this neighbor reads one
	// state. A record with no readable state leaves the aggregate unknown.
	stateGap := missing > 0 || len(unreadable) > 0
	if stateGap && len(known) == 1 {
		reasons = append(reasons, "no state is reported for this neighbor")
	}
	if len(reasons) > 0 {
		a.add(KindIncompleteAttributes, Unknown, l, strings.Join(reasons, "; "), limitIncomplete, ev)
	}

	switch {
	case len(remote) > 1:
		a.add(KindAttributeConflict, Conflicting, l, "remote interface values disagree: "+strings.Join(remote, " and "), limitAttributeConflict, ev)
	case len(known) > 1:
		a.add(KindNeighborState, Conflicting, l, "reports states "+strings.Join(known, " and "), limitStatesConflict, ev)
	case len(known) == 1 && !stateGap:
		a.add(KindNeighborState, Reported, l, "reports state "+known[0], limitForState(known[0]), ev)
	}
	if len(areas) > 1 {
		a.add(KindAttributeConflict, Conflicting, l, KeyArea+" values disagree: "+strings.Join(areas, " and "), limitAttributeConflict, ev)
	}
	switch len(ids) {
	case 0:
	case 1:
		a.confirmRouterID(l, ids[0], ev)
	default:
		a.add(KindAttributeConflict, Conflicting, l, KeyRouterID+" values disagree: "+strings.Join(ids, " and "), limitAttributeConflict, ev)
	}
}

// confirmRouterID checks a router ID against the peer's own interface records in
// the same routing domain. The peer's name decides the identity. The router ID
// can only confirm it or disagree with it.
func (a *analysis) confirmRouterID(l link, id string, ev []Evidence) {
	var disagree []Evidence
	confirmed := false
	for _, r := range a.ifaces {
		if r.plane != netmodel.PlaneControl || r.node != l.peer || r.vrf != l.vrf {
			continue
		}
		for _, v := range values(r.attrs, KeyRouterID) {
			ip, ok := parseRouterID(v)
			switch {
			case !ok:
			case ip.String() == id:
				confirmed = true
			default:
				disagree = append(disagree, r.evidence("peer's own interface"))
			}
		}
	}
	switch {
	case len(disagree) > 0:
		a.add(KindAttributeConflict, Conflicting, l, fmt.Sprintf("%s reports a router ID other than %s", l.peer, id), limitAttributeConflict, append(slices.Clone(ev), disagree...))
	case !confirmed:
		a.add(KindRouterIDUnconfirmed, Unknown, l, fmt.Sprintf("router ID %s is reported for %s, which reports no matching ID", id, l.peer), limitRouterID, ev)
	}
}

// interfaceAreas reads the configured area of each OSPF interface. One value
// from every source is usable. Two values, or one that is not an area, is not.
func (a *analysis) interfaceAreas() {
	groups := map[ifaceKey][]ifaceRow{}
	for _, r := range a.ifaces {
		if r.plane == netmodel.PlaneConfigured && len(values(r.attrs, KeyArea)) > 0 {
			k := ifaceKey{r.node, r.vrf, r.iface}
			groups[k] = append(groups[k], r)
		}
	}
	a.areas = map[ifaceKey]area{}
	for k, rows := range groups {
		var ev []Evidence
		var nums []uint32
		var names, bad []string
		for _, r := range rows {
			ev = append(ev, r.evidence(""))
			for _, v := range values(r.attrs, KeyArea) {
				if n, ok := parseArea(v); ok {
					nums = appendUniqueNum(nums, n)
					names = appendUnique(names, strconv.FormatUint(uint64(n), 10))
				} else {
					bad = appendUnique(bad, v)
				}
			}
		}
		l := link{node: k.node, vrf: k.vrf, iface: k.iface}
		switch {
		case len(bad) > 0:
			a.add(KindIncompleteAttributes, Unknown, l, fmt.Sprintf("%s %s is not an OSPF area", KeyArea, quoted(bad)), limitIncomplete, ev)
		case len(nums) == 1:
			a.areas[k] = area{n: nums[0], rows: ev}
		default:
			a.add(KindAttributeConflict, Conflicting, l, KeyArea+" values disagree: "+strings.Join(names, " and "), limitAttributeConflict, ev)
		}
	}
}

type expKey struct {
	plane netmodel.Plane
	link  link
}

// expectedNeighbors checks each configured or intended OSPF neighbor against the
// operational inventory of the node that names it. Its absence is evidence only
// when a complete neighbor list holds OSPF records.
func (a *analysis) expectedNeighbors() {
	groups := map[expKey][]record{}
	for _, inv := range a.inv {
		if inv.plane != netmodel.PlaneConfigured && inv.plane != netmodel.PlaneIntended {
			continue
		}
		for _, r := range inv.neighbors {
			if ospfRecord(r.attrs) {
				k := expKey{r.plane, r.link}
				groups[k] = append(groups[k], r)
			}
		}
	}
	for k, recs := range groups {
		a.expected(k.link, recs)
	}
}

func (a *analysis) expected(l link, recs []record) {
	ev := evidenceOf(recs, "expected neighbor")
	if l.peerIface == "" {
		a.add(KindMissingNeighbor, Unknown, l, "expected neighbor names no remote interface, so the far end cannot be matched", limitMissingUnknown, ev)
		return
	}
	var present, named, omitted, otherMiss []Evidence
	var others []string
	consulted := 0
	for _, inv := range a.inv {
		if inv.plane != netmodel.PlaneControl || inv.node != l.node || inv.vrf != l.vrf {
			continue
		}
		consulted++
		hit := false
		var here []Evidence
		for _, r := range inv.neighbors {
			// Only an OSPF record can show OSPF presence. A generic record names a
			// link, not an OSPF adjacency.
			if r.link.pair() != l.pair() || !ospfRecord(r.attrs) {
				continue
			}
			// A record that leaves the remote interface empty is the same neighbor.
			if r.link.peerIface == "" || r.link.peerIface == l.peerIface {
				hit = true
				present = append(present, r.evidence("operational record"))
				continue
			}
			here = append(here, r.evidence("operational record names another remote interface"))
			others = appendUnique(others, r.link.peerIface)
		}
		switch {
		case hit:
		case len(here) > 0:
			named = append(named, here...)
		case inv.absenceCounts():
			omitted = append(omitted, invEvidence(inv, "complete neighbor list with OSPF records; no OSPF record for this neighbor"))
		default:
			otherMiss = append(otherMiss, invEvidence(inv, "list is partial or holds no OSPF records; no OSPF record for this neighbor"))
		}
	}
	switch {
	case len(present) > 0 && len(omitted) > 0:
		a.add(KindMissingNeighbor, Conflicting, l, fmt.Sprintf("%s reports the neighbor, and its complete neighbor list with OSPF records does not", l.node), limitMissingConflict, append(append(slices.Clone(ev), present...), omitted...))
	case len(present) > 0:
	case len(named) > 0:
		a.add(KindMissingNeighbor, Unknown, l, fmt.Sprintf("the operational inventory of %s names remote interface %s for %s, not the expected %s, so the expected neighbor is not shown", l.node, strings.Join(others, " and "), l.peer, l.peerIface), limitMissingUnknown, append(slices.Clone(ev), named...))
	case len(omitted) > 0:
		a.add(KindMissingNeighbor, ConsistentWith, l, fmt.Sprintf("the complete neighbor list of %s, which holds OSPF records, has no OSPF record of %s on %s", l.node, l.peer, l.iface), limitMissingConsistent, append(slices.Clone(ev), omitted...))
	case consulted == 0:
		a.add(KindMissingNeighbor, Unknown, l, fmt.Sprintf("no operational inventory from %s to check the expected neighbor", l.node), limitMissingUnknown, ev)
	default:
		a.add(KindMissingNeighbor, Unknown, l, fmt.Sprintf("the operational inventory of %s is partial or holds no OSPF records, so a missing record proves nothing", l.node), limitMissingUnknown, append(slices.Clone(ev), otherMiss...))
	}
}

// areaMismatches compares the configured areas on both ends of a link that the
// control plane reports from both sides. Areas are never matched by name or by
// address alone, so an area on an unrelated interface is never compared.
func (a *analysis) areaMismatches() {
	byLink := map[link][]record{}
	for _, inv := range a.inv {
		if inv.plane != netmodel.PlaneControl {
			continue
		}
		for _, r := range inv.neighbors {
			byLink[r.link] = append(byLink[r.link], r)
		}
	}
	for l, recs := range byLink {
		// An unreported remote interface cannot be matched with the far end.
		if l.peerIface == "" {
			continue
		}
		m := l.mirror()
		// Each link has two directed keys. Report it once, from the smaller one.
		if compareLink(l, m) >= 0 {
			continue
		}
		mrecs, ok := byLink[m]
		if !ok {
			continue
		}
		ka := ifaceKey{l.node, l.vrf, l.iface}
		kb := ifaceKey{m.node, m.vrf, m.iface}
		aa, okA := a.areas[ka]
		ab, okB := a.areas[kb]
		if !okA || !okB || aa.n == ab.n {
			continue
		}
		ev := append(slices.Clone(aa.rows), ab.rows...)
		ev = append(ev, evidenceOf(recs, "link reported by this side")...)
		ev = append(ev, evidenceOf(mrecs, "link reported by the far side")...)
		a.add(KindAreaMismatch, ConsistentWith, l,
			fmt.Sprintf("configured area %d on %s %s and area %d on %s %s differ over a link both sides report", aa.n, l.node, l.iface, ab.n, m.node, m.iface),
			limitAreaMismatch, ev)
	}
}

func (a *analysis) add(kind Kind, s Strength, l link, detail, limit string, ev []Evidence) {
	ev = slices.Clone(ev)
	slices.SortFunc(ev, func(x, y Evidence) int { return strings.Compare(x.key(), y.key()) })
	a.findings = append(a.findings, Finding{
		Kind: kind, Strength: s,
		Node: l.node, VRF: l.vrf, Interface: l.iface, Peer: l.peer, PeerInterface: l.peerIface,
		Detail: detail, Limit: limit, Evidence: slices.Compact(ev),
	})
}

func (f Finding) key() string {
	var b strings.Builder
	for _, s := range []string{string(f.Kind), string(f.Strength), f.Node, f.VRF, f.Interface, f.Peer, f.PeerInterface, f.Detail, f.Limit} {
		b.WriteString(s)
		b.WriteByte(0)
	}
	for _, e := range f.Evidence {
		b.WriteString(e.key())
		b.WriteByte(1)
	}
	return b.String()
}

func (e Evidence) key() string {
	return strings.Join([]string{e.Source, e.CollectedAt, e.Plane, e.Node, e.VRF, e.Interface, e.Peer, e.PeerInterface, e.State, e.Area, e.RouterID, e.Note}, "\x00")
}

func (r record) evidence(note string) Evidence {
	return Evidence{
		Source: r.Source, CollectedAt: utcText(r.CollectedAt), Plane: string(r.plane),
		Node: r.link.node, VRF: r.link.vrf, Interface: r.link.iface, Peer: r.link.peer, PeerInterface: r.link.peerIface,
		State:    strings.Join(values(r.attrs, KeyState), ", "),
		Area:     strings.Join(values(r.attrs, KeyArea), ", "),
		RouterID: strings.Join(values(r.attrs, KeyRouterID), ", "),
		Note:     note,
	}
}

func (r ifaceRow) evidence(note string) Evidence {
	return Evidence{
		Source: r.Source, CollectedAt: utcText(r.CollectedAt), Plane: string(r.plane),
		Node: r.node, VRF: r.vrf, Interface: r.iface,
		Area:     strings.Join(values(r.attrs, KeyArea), ", "),
		RouterID: strings.Join(values(r.attrs, KeyRouterID), ", "),
		Note:     note,
	}
}

func invEvidence(inv inventory, note string) Evidence {
	return Evidence{Source: inv.Source, CollectedAt: utcText(inv.CollectedAt), Plane: string(inv.plane), Node: inv.node, VRF: inv.vrf, Note: note}
}

func evidenceOf(recs []record, note string) []Evidence {
	out := make([]Evidence, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.evidence(note))
	}
	return out
}

func limitForState(s string) string {
	switch s {
	case "full":
		return limitFull
	case "2-way":
		return limitTwoWay
	}
	return limitBeforeFull
}

// ospfRecord says a record carries any OSPF key. Such a record is OSPF evidence,
// even when its keys are incomplete.
func ospfRecord(attrs []netmodel.Attribute) bool {
	return slices.ContainsFunc(attrs, func(a netmodel.Attribute) bool { return strings.HasPrefix(a.Key, "ospf.") })
}

func values(attrs []netmodel.Attribute, key string) []string {
	var out []string
	for _, a := range attrs {
		if a.Key == key {
			out = append(out, a.Value)
		}
	}
	return out
}

// parseArea reads an OSPF area as the number it names. Routers write area 0 as
// "0" or as "0.0.0.0", so both spellings map to one value.
func parseArea(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), true
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.Is4() {
		b := ip.As4()
		return binary.BigEndian.Uint32(b[:]), true
	}
	return 0, false
}

// parseRouterID reads an OSPF router ID. The protocol writes it as a 32-bit
// identifier in dotted IPv4 form, so an IPv6 or IPv4-mapped address is unusable.
func parseRouterID(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	return ip, err == nil && ip.Is4()
}

func appendUnique(xs []string, x string) []string {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

func appendUniqueNum(xs []uint32, x uint32) []uint32 {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

func quoted(vals []string) string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strconv.Quote(v)
	}
	return strings.Join(out, ", ")
}

func utcText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Text renders the findings for a person. It is empty when there are none, so a
// caller can append it unconditionally. Every line passes through
// textsafe.Clean, because names and values come from the file.
func (r Report) Text() string {
	if len(r.Findings) == 0 {
		return ""
	}
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(textsafe.Clean(fmt.Sprintf(format, args...)))
		b.WriteByte('\n')
	}
	line("")
	line("OSPF (from recorded evidence for every node in the file; nothing was probed):")
	for _, f := range r.Findings {
		line("  %s [%s] %s: %s", f.Kind, f.Strength, f.subject(), f.Detail)
		for _, e := range f.Evidence {
			line("    evidence: %s", e.text())
		}
		line("    limit: %s", f.Limit)
	}
	return b.String()
}

func (f Finding) subject() string {
	s := f.Node
	if f.Interface != "" {
		s += " " + f.Interface
	}
	if f.Peer != "" {
		s += " to " + f.Peer
		if f.PeerInterface != "" {
			s += " " + f.PeerInterface
		}
	}
	return s + " (vrf " + f.VRF + ")"
}

func (e Evidence) text() string {
	subject := e.Node
	if e.Interface != "" {
		subject += " " + e.Interface
	}
	if e.Peer != "" {
		subject += " to " + e.Peer
		if e.PeerInterface != "" {
			subject += " " + e.PeerInterface
		}
	}
	parts := []string{subject}
	if e.State != "" {
		parts = append(parts, "state "+e.State)
	}
	if e.Area != "" {
		parts = append(parts, "area "+e.Area)
	}
	if e.RouterID != "" {
		parts = append(parts, "router ID "+e.RouterID)
	}
	if e.Note != "" {
		parts = append(parts, e.Note)
	}
	return fmt.Sprintf("%s at %s (%s plane, vrf %s): %s", e.Source, e.CollectedAt, e.Plane, e.VRF, strings.Join(parts, ", "))
}
