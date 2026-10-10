// Package netmodel is the vendor-neutral model of network topology and routing
// state. Adapters for static configuration, Linux, FRR, OSPF, BGP, LLDP, and
// vendor CLIs turn what they collect into Observations. A consumer reads them
// through Lookup and never sees which protocol or vendor produced a row.
//
// Schema:
//
//   - An Observation is one reporter's view of one node, in one VRF, on one
//     plane, at one time. Source is the reporter and Node is the subject, so
//     an OSPF database read on r1 can describe r2.
//   - VRF doubles as the routing domain. The default domain is named
//     "default". An empty VRF is rejected, never read as the default domain.
//   - Plane says what kind of state the rows describe. Intended is the design
//     or policy, configured is device configuration, control is the RIB the
//     control plane holds, fib is what forwards traffic, and observed is what
//     live measurement saw. Planes never merge. A difference between planes is
//     a finding for the caller, not a conflict.
//   - Interfaces and Neighbors are always partial. A missing neighbor proves
//     nothing.
//   - Routes are complete only when RoutesComplete is set. Only a complete
//     observation can prove a prefix absent.
//   - A Route is one candidate from one Origin for one prefix. ECMP is several
//     NextHops on that one Route. Several origins for one prefix are separate
//     candidates, and the model never picks a best path. A Route with no
//     NextHops and no Discard means the source did not report its forwarding.
//   - Attributes carry protocol or vendor detail under namespaced keys such as
//     "bgp.as_path". Lookup never reads them, and they never decide a conflict.
//   - Every Evidence row keeps the Source and CollectedAt of its Observation.
//
// Lookup answers present, absent, unknown, or conflicting. See Lookup.
package netmodel

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Plane names the kind of routing state an Observation describes.
type Plane string

const (
	PlaneIntended   Plane = "intended"
	PlaneConfigured Plane = "configured"
	PlaneControl    Plane = "control"
	PlaneFIB        Plane = "fib"
	PlaneObserved   Plane = "observed"
)

// Origins that adapters commonly write. The model compares them for equality
// only, so an adapter may use any other non-empty name.
const (
	OriginConnected = "connected"
	OriginStatic    = "static"
	OriginOSPF      = "ospf"
	OriginBGP       = "bgp"
)

// State is the answer to a Lookup.
type State string

const (
	Present     State = "present"
	Absent      State = "absent"
	Unknown     State = "unknown"
	Conflicting State = "conflicting"
)

// Provenance records who reported a fact and when.
type Provenance struct {
	Source      string
	CollectedAt time.Time
}

// Attribute is one protocol or vendor detail. Keys are namespaced by adapter.
type Attribute struct{ Key, Value string }

// NextHop is where a route hands traffic. A zero Addr means the destination is
// on the named interface, with no gateway.
type NextHop struct {
	Addr      netip.Addr
	Interface string
}

// Route is one candidate for one prefix from one origin. Metric is meaningful
// only with MetricKnown. Discard marks a blackhole or unreachable route, and it
// has no NextHops.
type Route struct {
	Prefix      netip.Prefix
	Origin      string
	Metric      uint32
	MetricKnown bool
	Discard     bool
	NextHops    []NextHop
	Attributes  []Attribute
}

// Interface is a node's port. VLAN is meaningful only with VLANKnown. Then 0
// means untagged and 1 to 4094 are 802.1Q tags. Trunk membership is not modeled.
type Interface struct {
	Name      string
	VLANKnown bool
	VLAN      uint16
	Addresses []netip.Prefix
}

// Neighbor is one directed view from LocalInterface toward a remote node. A
// link is two Neighbor records, one from each side, when both sides report.
type Neighbor struct {
	LocalInterface  string
	RemoteNode      string
	RemoteInterface string
	RemoteAddr      netip.Addr
}

// Observation is one reporter's view of one node in one VRF on one plane.
// RoutesComplete says Routes lists every route the reporter saw.
type Observation struct {
	Provenance
	Plane          Plane
	Node           string
	VRF            string
	RoutesComplete bool
	Interfaces     []Interface
	Neighbors      []Neighbor
	Routes         []Route
}

// Evidence is one route and the observation that reported it.
type Evidence struct {
	Provenance
	Route Route
}

// Answer is the result of a Lookup. Evidence holds every matching route in a
// stable order. AbsentIn names the complete observations that lack the prefix.
type Answer struct {
	State    State
	Evidence []Evidence
	AbsentIn []Provenance
}

// Model holds validated, canonically ordered copies of its observations. The
// zero Model is empty.
type Model struct {
	observations []Observation
}

// New validates and copies the observations. The result does not depend on
// input order, and it shares no slices with the arguments.
func New(observations ...Observation) (Model, error) {
	out := make([]Observation, 0, len(observations))
	for i, o := range observations {
		c, err := canonical(o)
		if err != nil {
			return Model{}, fmt.Errorf("observation %d: %w", i, err)
		}
		out = append(out, c)
	}
	slices.SortFunc(out, compareObservations)
	return Model{observations: out}, nil
}

// Observations returns a deep copy of the model's observations in canonical
// order.
func (m Model) Observations() []Observation {
	out := slices.Clone(m.observations)
	for i := range out {
		out[i] = cloneObservation(out[i])
	}
	return out
}

// Lookup answers whether node in vrf has prefix on plane. The prefix is masked
// first. The match is exact, so Lookup does not do longest-prefix match.
//
//   - Absent: complete observations lack the prefix, and none has it. AbsentIn
//     names them.
//   - Unknown: no observation has the prefix, and none is complete without it.
//   - Present: observations have the prefix, and no two from one origin state
//     different values.
//   - Conflicting: two rows from one origin state different values, or a
//     complete observation lacks a prefix that another observation has.
//     Evidence and AbsentIn keep both sides. Time never picks a winner.
func (m Model) Lookup(node, vrf string, plane Plane, prefix netip.Prefix) Answer {
	prefix = prefix.Masked()
	if !prefix.IsValid() {
		return Answer{State: Unknown}
	}
	// ponytail: linear scan over every observation. Index by (node, vrf, plane)
	// when the model grows.
	var rows []Evidence
	var absent []Provenance
	for _, o := range m.observations {
		if o.Node != node || o.VRF != vrf || o.Plane != plane {
			continue
		}
		found := false
		for _, r := range o.Routes {
			if r.Prefix == prefix {
				rows = append(rows, Evidence{Provenance: o.Provenance, Route: cloneRoute(r)})
				found = true
			}
		}
		if !found && o.RoutesComplete {
			absent = append(absent, o.Provenance)
		}
	}
	switch {
	case len(rows) == 0 && len(absent) > 0:
		return Answer{State: Absent, AbsentIn: absent}
	case len(rows) == 0:
		return Answer{State: Unknown}
	case len(absent) > 0 || sameOriginDisagrees(rows):
		return Answer{State: Conflicting, Evidence: rows, AbsentIn: absent}
	}
	return Answer{State: Present, Evidence: rows}
}

func sameOriginDisagrees(rows []Evidence) bool {
	for i := range rows {
		for j := i + 1; j < len(rows); j++ {
			a, b := rows[i].Route, rows[j].Route
			if a.Origin == b.Origin && disagree(a, b) {
				return true
			}
		}
	}
	return false
}

// disagree reports whether two routes for one prefix and origin state different
// values. A value counts only when both routes state it, so an unreported field
// never contradicts a reported one.
func disagree(a, b Route) bool {
	if a.MetricKnown && b.MetricKnown && a.Metric != b.Metric {
		return true
	}
	if forwards(a) && forwards(b) {
		return a.Discard != b.Discard || !sameHops(a.NextHops, b.NextHops)
	}
	return false
}

// sameHops reports whether every next hop in each list has a counterpart in the
// other.
func sameHops(a, b []NextHop) bool { return CoversHops(a, b) && CoversHops(b, a) }

// CoversHops reports whether every next hop in want has a counterpart in have.
// An empty Interface is unreported, so it matches any interface on the same
// gateway.
func CoversHops(have, want []NextHop) bool {
	for _, w := range want {
		if !slices.ContainsFunc(have, func(h NextHop) bool {
			return w.Addr == h.Addr && (w.Interface == "" || h.Interface == "" || w.Interface == h.Interface)
		}) {
			return false
		}
	}
	return true
}

func forwards(r Route) bool { return r.Discard || len(r.NextHops) > 0 }

// canonical validates o and returns a deep copy with every list in sorted order.
func canonical(o Observation) (Observation, error) {
	switch {
	case o.Source == "":
		return Observation{}, errors.New("source is empty")
	case o.CollectedAt.IsZero():
		return Observation{}, errors.New("collected_at is zero")
	case !validPlane(o.Plane):
		return Observation{}, fmt.Errorf("unknown plane %q", o.Plane)
	case o.Node == "":
		return Observation{}, errors.New("node is empty")
	case o.VRF == "":
		return Observation{}, errors.New(`vrf is empty; name the routing domain, "default" for the default one`)
	}
	out := Observation{Provenance: o.Provenance, Plane: o.Plane, Node: o.Node, VRF: o.VRF, RoutesComplete: o.RoutesComplete}

	names := map[string]bool{}
	for _, i := range o.Interfaces {
		if i.Name == "" {
			return Observation{}, errors.New("interface name is empty")
		}
		if names[i.Name] {
			return Observation{}, fmt.Errorf("interface %q listed twice", i.Name)
		}
		names[i.Name] = true
		if i.VLANKnown && i.VLAN > 4094 {
			return Observation{}, fmt.Errorf("interface %q has VLAN %d; tags run 1 to 4094", i.Name, i.VLAN)
		}
		if !i.VLANKnown {
			i.VLAN = 0
		}
		for _, a := range i.Addresses {
			if !a.IsValid() {
				return Observation{}, fmt.Errorf("interface %q has an invalid address", i.Name)
			}
		}
		i.Addresses = slices.Clone(i.Addresses)
		slices.SortFunc(i.Addresses, comparePrefix)
		out.Interfaces = append(out.Interfaces, i)
	}
	slices.SortFunc(out.Interfaces, func(a, b Interface) int { return strings.Compare(a.Name, b.Name) })

	for _, n := range o.Neighbors {
		if n.LocalInterface == "" || n.RemoteNode == "" {
			return Observation{}, errors.New("neighbor needs a local interface and a remote node")
		}
		// A zone on a neighbor address names the observer's own link, so it
		// must match LocalInterface. It says nothing about the remote port.
		addr, _, err := normalizeAddr(n.RemoteAddr, n.LocalInterface)
		if err != nil {
			return Observation{}, fmt.Errorf("neighbor %s: %w", n.RemoteNode, err)
		}
		n.RemoteAddr = addr
		out.Neighbors = append(out.Neighbors, n)
	}
	slices.SortFunc(out.Neighbors, compareNeighbors)

	type routeKey struct {
		prefix netip.Prefix
		origin string
	}
	seen := map[routeKey]bool{}
	for _, r := range o.Routes {
		if !r.Prefix.IsValid() || r.Prefix.Masked() != r.Prefix {
			return Observation{}, fmt.Errorf("route prefix %v is invalid or has host bits set", r.Prefix)
		}
		if r.Origin == "" {
			return Observation{}, fmt.Errorf("route %v has no origin", r.Prefix)
		}
		k := routeKey{r.Prefix, r.Origin}
		if seen[k] {
			return Observation{}, fmt.Errorf("route %v from origin %q listed twice; several next hops belong in one route", r.Prefix, r.Origin)
		}
		seen[k] = true
		if r.Discard && len(r.NextHops) > 0 {
			return Observation{}, fmt.Errorf("discard route %v has next hops", r.Prefix)
		}
		hops := make([]NextHop, 0, len(r.NextHops))
		for _, nh := range r.NextHops {
			addr, iface, err := normalizeAddr(nh.Addr, nh.Interface)
			if err != nil {
				return Observation{}, fmt.Errorf("route %v: %w", r.Prefix, err)
			}
			nh = NextHop{Addr: addr, Interface: iface}
			if !nh.Addr.IsValid() && nh.Interface == "" {
				return Observation{}, fmt.Errorf("route %v has a next hop with neither address nor interface", r.Prefix)
			}
			if nh.Addr.IsLinkLocalUnicast() && nh.Interface == "" {
				return Observation{}, fmt.Errorf("route %v has link-local next hop %v without an interface", r.Prefix, nh.Addr)
			}
			hops = append(hops, nh)
		}
		slices.SortFunc(hops, compareNextHops)
		hops = slices.Compact(hops)
		attrs := slices.Clone(r.Attributes)
		for _, a := range attrs {
			if a.Key == "" {
				return Observation{}, fmt.Errorf("route %v has an attribute with an empty key", r.Prefix)
			}
		}
		slices.SortFunc(attrs, compareAttributes)
		r.NextHops, r.Attributes = hops, attrs
		if !r.MetricKnown {
			r.Metric = 0
		}
		out.Routes = append(out.Routes, r)
	}
	slices.SortFunc(out.Routes, compareRoutes)
	return out, nil
}

// normalizeAddr drops the IPv4-mapped spelling and moves an IPv6 zone into the
// interface field, so one address has one spelling per interface.
func normalizeAddr(a netip.Addr, iface string) (netip.Addr, string, error) {
	// Read the zone before Unmap, which drops it from a 4in6 address.
	if z := a.Zone(); z != "" {
		if iface != "" && iface != z {
			return a, iface, fmt.Errorf("address %v names zone %q but interface is %q", a, z, iface)
		}
		iface = z
	}
	return a.WithZone("").Unmap(), iface, nil
}

func validPlane(p Plane) bool {
	switch p {
	case PlaneIntended, PlaneConfigured, PlaneControl, PlaneFIB, PlaneObserved:
		return true
	}
	return false
}

func cloneRoute(r Route) Route {
	r.NextHops = slices.Clone(r.NextHops)
	r.Attributes = slices.Clone(r.Attributes)
	return r
}

func cloneObservation(o Observation) Observation {
	o.Interfaces = slices.Clone(o.Interfaces)
	for i := range o.Interfaces {
		o.Interfaces[i].Addresses = slices.Clone(o.Interfaces[i].Addresses)
	}
	o.Neighbors = slices.Clone(o.Neighbors)
	o.Routes = slices.Clone(o.Routes)
	for i := range o.Routes {
		o.Routes[i] = cloneRoute(o.Routes[i])
	}
	return o
}

// compareObservations orders by the fields a reader scans first. Equal keys
// fall back to the JSON encoding, so the order never depends on input.
func compareObservations(a, b Observation) int {
	if c := cmp.Or(
		strings.Compare(string(a.Plane), string(b.Plane)),
		strings.Compare(a.Node, b.Node),
		strings.Compare(a.VRF, b.VRF),
		strings.Compare(a.Source, b.Source),
		a.CollectedAt.Compare(b.CollectedAt),
	); c != 0 {
		return c
	}
	// Every field is a string, number, bool, time, or netip value, so Marshal
	// cannot fail. Unlike fmt, its output tells nil lists from empty ones.
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Compare(ja, jb)
}

func compareNeighbors(a, b Neighbor) int {
	return cmp.Or(
		strings.Compare(a.LocalInterface, b.LocalInterface),
		strings.Compare(a.RemoteNode, b.RemoteNode),
		strings.Compare(a.RemoteInterface, b.RemoteInterface),
		a.RemoteAddr.Compare(b.RemoteAddr),
	)
}

func compareRoutes(a, b Route) int {
	return cmp.Or(
		strings.Compare(a.Prefix.String(), b.Prefix.String()),
		strings.Compare(a.Origin, b.Origin),
	)
}

func compareNextHops(a, b NextHop) int {
	return cmp.Or(a.Addr.Compare(b.Addr), strings.Compare(a.Interface, b.Interface))
}

func compareAttributes(a, b Attribute) int {
	return cmp.Or(strings.Compare(a.Key, b.Key), strings.Compare(a.Value, b.Value))
}

func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}
