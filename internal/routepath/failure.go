package routepath

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// maxDestinations bounds how many destinations one simulation considers, and
// maxSimStates bounds the node visits all of its walks make together. Either
// bound marks the simulation truncated.
const (
	maxDestinations = 256
	maxSimStates    = 32 * maxStates
)

// Failure names the one element a simulation removes. With no Interface, the
// router Node is unavailable. With an Interface, that interface of Node is down,
// in every routing domain that lists it. With an OSPFNeighbor as well, only the
// OSPF adjacency of Node on Interface toward that neighbor is lost, in routing
// domain VRF, and the interface stays up. Simulate fills an empty VRF from the
// neighbor records that name the adjacency. With a NextHop instead, only the
// FIB legs of Node in routing domain VRF through that gateway address are lost,
// on Interface when it is set, and the interface and the gateway's node stay
// up. Simulate fills an empty VRF from the FIB rows that name the next hop.
type Failure struct {
	Node         string `json:"node"`
	Interface    string `json:"interface,omitempty"`
	VRF          string `json:"vrf,omitempty"`
	OSPFNeighbor string `json:"ospf_neighbor,omitempty"`
	NextHop      string `json:"next_hop,omitempty"`
}

func (f Failure) String() string {
	switch {
	case f.NextHop != "":
		on := ""
		if f.Interface != "" {
			on = " on " + f.Interface
		}
		return "next hop " + f.NextHop + on + " of " + f.Node + " (" + f.VRF + ") unavailable"
	case f.OSPFNeighbor != "":
		return "OSPF adjacency " + f.Node + " (" + f.VRF + ") " + f.Interface + " to " + f.OSPFNeighbor + " lost"
	case f.Interface == "":
		return "router " + f.Node + " unavailable"
	}
	return "interface " + f.Node + " " + f.Interface + " down"
}

// The OSPF attribute keys an adjacency loss reads, as the reference documents
// them under OSPF.
const (
	keyOSPFState       = "ospf.state"
	keyOSPFNetworkType = "ospf.network_type"
)

// Adjacency is what the control-plane records say about a lost OSPF adjacency.
// Proven says the records establish the link's transit dependency on it: the
// link is point-to-point and the neighbor is full, so once the adjacency is
// gone SPF cannot use the link as a transit edge, and the simulation removes
// each recorded OSPF next hop across it. Proven says nothing about what the FIB
// holds after the loss. Reason says why the dependency is not proven, and each
// such next hop is then unknown. Evidence lists the neighbor and interface rows
// read.
type Adjacency struct {
	NeighborAddr    string    `json:"neighbor_addr,omitempty"`
	RemoteInterface string    `json:"remote_interface,omitempty"`
	Proven          bool      `json:"proven"`
	Reason          string    `json:"reason,omitempty"`
	Evidence        []Support `json:"evidence"`
	addr            netip.Addr
}

// Gateway is what the recorded FIB says about a lost next hop. Owners are the
// modeled routing domains that hold its address, and may be empty. Evidence
// lists the FIB rows that name it, which are what make it selectable.
type Gateway struct {
	Owners   []Start   `json:"owners"`
	Evidence []Support `json:"evidence"`
	addr     netip.Addr
}

// Impact says what a failure does to delivery of one destination from the
// source, read from the recorded FIB.
type Impact string

const (
	// ImpactNone: no recorded forwarding branch crosses the failure, and the
	// forwarding before it is proven, so nothing the evidence shows changes.
	ImpactNone Impact = "none"
	// ImpactRedundancyLost: delivery was proven, some branches cross the
	// failure, and every branch that survives still delivers.
	ImpactRedundancyLost Impact = "redundancy_lost"
	// ImpactReachabilityLost: delivery was proven, and after the failure some
	// branch from the source ends with no surviving next hop.
	ImpactReachabilityLost Impact = "reachability_lost"
	// ImpactUnknown: the evidence cannot rate the change.
	ImpactUnknown Impact = "unknown"
)

// Affected is one destination whose impact is not none. After is the forwarding
// walk with the failure applied, so a surviving path is shown with its evidence.
// It is nil once the walks listed before it hold maxStates hops, which keeps the
// output within about two walks' size, and the simulation is then truncated.
type Affected struct {
	Destination string  `json:"destination"`
	Owners      []Start `json:"owners,omitempty"`
	Impact      Impact  `json:"impact"`
	Reason      string  `json:"reason"`
	After       *Hop    `json:"after,omitempty"`
}

// Simulation is what one failure does to forwarding from the source. Adjacency
// is set for an OSPF adjacency loss only, and Gateway for a next-hop loss only.
// Considered counts the destinations walked, Unchanged those with no impact,
// and Affected lists the rest in address order. Truncated says a bound cut the output short: skipped says a
// destination went unconsidered, stopped says a walk was stopped by a bound of
// its own, and an Affected with no After says its walk was omitted after it was
// rated.
type Simulation struct {
	Failure    Failure    `json:"failure"`
	Adjacency  *Adjacency `json:"adjacency,omitempty"`
	Gateway    *Gateway   `json:"gateway,omitempty"`
	Source     Start      `json:"source"`
	Considered int        `json:"considered"`
	Unchanged  int        `json:"unchanged"`
	Affected   []Affected `json:"affected"`
	Truncated  bool       `json:"truncated"`
	skipped    bool
	stopped    bool
}

// Simulate removes one router or interface from the recorded FIB and compares
// forwarding from the source before and after, for every address an interface
// in the file holds and for each extra destination. Each node stops using a next
// hop whose segment crosses the failure, and nothing else changes: no route is
// recomputed and no convergence is predicted. It reads only f and changes
// nothing in it.
//
// Only a node whose own interface is down is taken to stop selecting a next hop
// through it. A leg cut anywhere else, toward a failed router or onto a down
// far end, leaves the node's link up, so a destination that keeps another leg
// there is never rated redundancy_lost: the node may keep hashing flows onto the
// cut leg.
//
// An OSPF adjacency loss leaves its link up, so only OSPF next hops that cross
// the link are stopped, where Adjacency proves the link's transit dependency on
// the adjacency, and no destination is rated
// reachability_lost: OSPF recomputes its routes after the loss, and no SPF is
// run here.
//
// A next-hop loss leaves the interface and the gateway's node up, so nothing
// tells the node to stop selecting the lost leg beside a surviving one, and no
// destination is rated redundancy_lost: whether flows hashed onto the lost leg
// move is not in the evidence.
func Simulate(f File, fail Failure, extra ...netip.Addr) (Simulation, error) {
	w := newWalker(f, netip.Addr{})
	var err error
	switch {
	case fail.NextHop != "":
		fail, w.gw, err = w.gateway(fail)
	case fail.OSPFNeighbor != "":
		fail, w.adj, err = w.adjacency(fail)
	default:
		err = w.checkFailure(f.Source, fail)
	}
	if err != nil {
		return Simulation{}, err
	}
	var dests []netip.Addr
	for _, d := range extra {
		if d = d.WithZone("").Unmap(); !slices.Contains(dests, d) {
			dests = append(dests, d)
		}
	}
	var owned []netip.Addr
	for a := range w.owners {
		if !slices.Contains(dests, a) {
			owned = append(owned, a)
		}
	}
	slices.SortFunc(owned, netip.Addr.Compare)
	dests = append(dests, owned...)

	s := Simulation{Failure: fail, Adjacency: w.adj, Gateway: w.gw, Source: f.Source, Affected: []Affected{}}
	if len(dests) > maxDestinations {
		dests, s.skipped = dests[:maxDestinations], true
	}
	src := state{f.Source.Node, f.Source.VRF}
	spent := 0
	for _, d := range dests {
		if spent >= maxSimStates {
			s.skipped = true
			break
		}
		s.Considered++
		w.dest, w.fail, w.touched = d, &fail, false
		after, trunc := w.run(forwardingPlanes, src)
		spent += maxStates - w.budget
		w.fail = nil
		before := after
		if w.touched {
			var t bool
			before, t = w.run(forwardingPlanes, src)
			spent += maxStates - w.budget
			trunc = trunc || t
		}
		s.stopped = s.stopped || trunc
		a := Affected{Destination: d.String(), After: &after}
		for _, o := range w.owners[d] {
			a.Owners = append(a.Owners, Start{Node: o.node, VRF: o.vrf})
		}
		a.Impact, a.Reason = rate(reachOf(&before, nil), reachOf(&after, nil), w.touched)
		if a.Impact == ImpactReachabilityLost && w.adj != nil {
			a.Impact, a.Reason = ImpactUnknown, "after the adjacency loss, a forwarding branch has no surviving recorded next hop; OSPF recomputes its routes after the loss, and no SPF is run here, so whether another path takes over is unknown"
		}
		if a.Impact == ImpactRedundancyLost && w.gw != nil {
			a.Impact, a.Reason = ImpactUnknown, "every surviving recorded branch delivers, but the recorded route still lists the lost next hop; whether the node stops selecting it while its link stays up is not in the evidence, so traffic hashed onto it may be dropped"
		}
		if a.Impact == ImpactRedundancyLost && w.gw == nil && w.adj == nil {
			var far *Segment
			walkHops(a.After, func(h *Hop) {
				if far == nil && h.Decision.Kind == KindFailed && h.Via.From != fail.Node {
					far = h.Via
				}
			})
			if far != nil {
				a.Impact, a.Reason = ImpactUnknown, fmt.Sprintf("every surviving recorded branch delivers, but %s (%s) still lists a next hop that crosses the failure on another node; whether %s stops selecting it is not in the evidence, so traffic hashed onto it may be dropped", far.From, far.VRF, far.From)
			}
		}
		if a.Impact == ImpactNone {
			s.Unchanged++
			continue
		}
		s.Affected = append(s.Affected, a)
	}
	slices.SortFunc(s.Affected, func(a, b Affected) int {
		return netip.MustParseAddr(a.Destination).Compare(netip.MustParseAddr(b.Destination))
	})
	s.Truncated = s.skipped || s.stopped
	shown := 0
	for i := range s.Affected {
		if shown >= maxStates {
			s.Affected[i].After, s.Truncated = nil, true
			continue
		}
		walkHops(s.Affected[i].After, func(*Hop) { shown++ })
	}
	return s, nil
}

// rate compares delivery before and after the failure. Only proven delivery
// before it can be lost. A walk that never crossed the failure changes nothing,
// unless the walk before it is unknown, since the true path could cross it.
func rate(before, after reach, touched bool) (Impact, string) {
	switch {
	case before == reachUnknown:
		return ImpactUnknown, "the recorded forwarding does not prove delivery before the failure, so the path may cross it"
	case !touched:
		return ImpactNone, ""
	case before == reachFailed:
		return ImpactUnknown, "the recorded forwarding does not deliver it before the failure"
	case after == reachOK:
		return ImpactRedundancyLost, "some forwarding branches cross the failure, and every surviving branch delivers"
	case after == reachFailed:
		return ImpactReachabilityLost, "after the failure, a forwarding branch from the source has no surviving next hop"
	}
	return ImpactUnknown, "after the failure, the surviving forwarding does not prove delivery"
}

// checkFailure refuses a failure the file does not describe, so a mistyped name
// never reads as a failure that affects nothing.
func (w *walker) checkFailure(src Start, f Failure) error {
	switch {
	case f.Node == "":
		return errors.New("the failure names no node")
	case f.VRF != "":
		return errors.New("a VRF names the routing domain of an OSPF adjacency, and the failure names no OSPF neighbor")
	case f.Interface == "" && f.Node == src.Node:
		return fmt.Errorf("router %s is the source; nothing leaves a failed source", f.Node)
	}
	node, iface := false, f.Interface == ""
	for _, o := range w.obs {
		if o.Node != f.Node || !slices.Contains(readPlanes, o.Plane) {
			continue
		}
		node = true
		iface = iface || slices.ContainsFunc(o.Interfaces, func(i netmodel.Interface) bool { return i.Name == f.Interface }) ||
			slices.ContainsFunc(o.Routes, func(r netmodel.Route) bool {
				return slices.ContainsFunc(r.NextHops, func(n netmodel.NextHop) bool { return n.Interface == f.Interface })
			})
	}
	switch {
	case !node:
		return fmt.Errorf("no configured, control, or fib observation describes node %q", f.Node)
	case !iface:
		return fmt.Errorf("node %q lists no interface %q and names it on no route", f.Node, f.Interface)
	}
	return nil
}

// adjacency reads the control-plane OSPF neighbor records that name the lost
// adjacency, and returns the failure with its routing domain filled in. It
// refuses an adjacency no record names, so a mistyped name never reads as a loss
// that affects nothing, and one recorded in several routing domains when the
// failure names none. The link's transit dependency on the adjacency is proven
// only on a point-to-point interface with no other OSPF neighbor, whose records
// agree on one neighbor address and state full. A router lists a point-to-point
// link to its neighbor in its router-LSA only while that neighbor is full (RFC
// 2328 12.4.1.1), and SPF uses a link between two routers only when both list
// it (16.1), so once the adjacency is gone SPF cannot use the link as a transit
// edge in either direction. That is the recorded structure the simulation
// assumes, not a reading of the FIB after the loss: the router may still
// advertise the link's stub network, and what OSPF installs instead is not
// computed. On any other network type, a router can forward to a neighbor it holds no
// full adjacency with, and losing the adjacency to the designated router drops
// the whole network, so the next hops that depend on it are not in the evidence.
func (w *walker) adjacency(f Failure) (Failure, *Adjacency, error) {
	if f.Node == "" || f.Interface == "" {
		return f, nil, errors.New("an OSPF adjacency needs a node, an interface, and a neighbor")
	}
	names := func(n netmodel.Neighbor) bool {
		return n.LocalInterface == f.Interface && n.RemoteNode == f.OSPFNeighbor && ospfRecord(n.Attributes)
	}
	var vrfs []string
	for _, o := range w.obs {
		if o.Plane == netmodel.PlaneControl && o.Node == f.Node && (f.VRF == "" || o.VRF == f.VRF) &&
			slices.ContainsFunc(o.Neighbors, names) && !slices.Contains(vrfs, o.VRF) {
			vrfs = append(vrfs, o.VRF)
		}
	}
	switch len(vrfs) {
	case 0:
		return f, nil, fmt.Errorf("no control-plane OSPF neighbor record on node %q interface %q names neighbor %q", f.Node, f.Interface, f.OSPFNeighbor)
	case 1:
		f.VRF = vrfs[0]
	default:
		slices.Sort(vrfs)
		return f, nil, fmt.Errorf("OSPF neighbor records on node %q interface %q name neighbor %q in routing domains %s, so the adjacency is ambiguous", f.Node, f.Interface, f.OSPFNeighbor, strings.Join(vrfs, ", "))
	}

	adj := &Adjacency{}
	var addrs, states, remotes, types, others []string
	for _, o := range w.obs {
		if o.Plane != netmodel.PlaneControl || o.Node != f.Node || o.VRF != f.VRF {
			continue
		}
		sup := Support{Source: o.Source, CollectedAt: utcText(o.CollectedAt)}
		for _, n := range o.Neighbors {
			switch {
			case n.LocalInterface != f.Interface || !ospfRecord(n.Attributes):
			case n.RemoteNode != f.OSPFNeighbor:
				others = appendNew(others, n.RemoteNode)
			default:
				adj.Evidence = appendNew(adj.Evidence, sup)
				addrs = appendNew(addrs, addrText(n.RemoteAddr))
				if n.RemoteInterface != "" {
					remotes = appendNew(remotes, n.RemoteInterface)
				}
				vals := attrValues(n.Attributes, keyOSPFState)
				if len(vals) == 0 {
					vals = []string{""}
				}
				for _, v := range vals {
					states = appendNew(states, strings.ToLower(strings.TrimSpace(v)))
				}
			}
		}
		for _, i := range o.Interfaces {
			if vals := attrValues(i.Attributes, keyOSPFNetworkType); i.Name == f.Interface && len(vals) > 0 {
				adj.Evidence = appendNew(adj.Evidence, sup)
				for _, v := range vals {
					types = appendNew(types, v)
				}
			}
		}
	}
	adj.Evidence = sortSupports(adj.Evidence)
	for _, l := range [][]string{addrs, states, remotes, types, others} {
		slices.Sort(l)
	}
	if len(addrs) == 1 && addrs[0] != "" {
		adj.NeighborAddr, adj.addr = addrs[0], netip.MustParseAddr(addrs[0])
	}
	if len(remotes) == 1 {
		adj.RemoteInterface = remotes[0]
	}
	at := fmt.Sprintf("%s (%s) %s", f.Node, f.VRF, f.Interface)
	switch {
	case adj.NeighborAddr == "":
		adj.Reason = fmt.Sprintf("the neighbor records on %s name no single address for %s", at, f.OSPFNeighbor)
	case slices.Contains(states, ""):
		adj.Reason = fmt.Sprintf("a neighbor record on %s states no %s", at, keyOSPFState)
	case len(states) > 1:
		adj.Reason = fmt.Sprintf("the neighbor records on %s state %s", at, strings.Join(states, " and "))
	case states[0] != "full":
		adj.Reason = fmt.Sprintf("the recorded state on %s is %s, not full, so the records do not show the link as an OSPF transit edge to begin with", at, states[0])
	case len(remotes) > 1:
		adj.Reason = fmt.Sprintf("the neighbor records on %s name remote interfaces %s", at, strings.Join(remotes, " and "))
	case len(types) == 0:
		adj.Reason = fmt.Sprintf("%s reports no %s", at, keyOSPFNetworkType)
	case len(types) > 1:
		adj.Reason = fmt.Sprintf("%s reports network types %s", at, strings.Join(types, " and "))
	case types[0] != "point-to-point":
		adj.Reason = fmt.Sprintf("%s reports network type %s; off a point-to-point link, a router can forward to a neighbor it holds no full adjacency with, and losing the adjacency to the designated router drops the whole network, so which next hops depend on this one is not in the evidence", at, types[0])
	case len(others) > 0:
		adj.Reason = fmt.Sprintf("%s also records OSPF neighbors %s, which a point-to-point link cannot hold", at, strings.Join(others, ", "))
	default:
		adj.Proven = true
	}
	return f, adj, nil
}

// gateway reads the FIB rows of the failure's node that name its next hop, and
// returns the failure with its routing domain filled in and its address in
// canonical form. Only FIB rows count, since the simulation walks only the FIB.
// It refuses a next hop no FIB row of the node names, so a mistyped address
// never reads as a loss that affects nothing, and one named in several routing
// domains or on several interfaces when the failure does not choose one. A
// link-local address names a neighbor only together with its link, so it needs
// an interface.
func (w *walker) gateway(f Failure) (Failure, *Gateway, error) {
	a, err := netip.ParseAddr(f.NextHop)
	switch {
	case f.Node == "":
		return f, nil, errors.New("a next-hop loss needs a node and a next-hop address")
	case f.OSPFNeighbor != "":
		return f, nil, errors.New("a next-hop loss names no OSPF neighbor")
	case err != nil || a.Zone() != "":
		return f, nil, fmt.Errorf("next hop %q is not an IP address", f.NextHop)
	}
	a = a.Unmap()
	f.NextHop = a.String()
	node := f.Node
	if f.VRF != "" {
		node += "@" + f.VRF
	}
	if a.IsLinkLocalUnicast() && f.Interface == "" {
		return f, nil, fmt.Errorf("link-local next hop %s needs an interface: %s:%s%%INTERFACE", a, node, a)
	}
	names := func(n netmodel.NextHop) bool { return n.Addr == a }
	var vrfs []string
	for _, o := range w.obs {
		if o.Plane == netmodel.PlaneFIB && o.Node == f.Node && (f.VRF == "" || o.VRF == f.VRF) && !slices.Contains(vrfs, o.VRF) &&
			slices.ContainsFunc(o.Routes, func(r netmodel.Route) bool { return slices.ContainsFunc(r.NextHops, names) }) {
			vrfs = append(vrfs, o.VRF)
		}
	}
	switch {
	case len(vrfs) == 0 && f.VRF != "":
		return f, nil, fmt.Errorf("no fib route of node %q in routing domain %q names next hop %s", f.Node, f.VRF, a)
	case len(vrfs) == 0:
		return f, nil, fmt.Errorf("no fib route of node %q names next hop %s", f.Node, a)
	case len(vrfs) > 1:
		slices.Sort(vrfs)
		return f, nil, fmt.Errorf("fib routes of node %q name next hop %s in routing domains %s; name one as %s@VRF:%s", f.Node, a, strings.Join(vrfs, ", "), f.Node, a)
	}
	f.VRF = vrfs[0]

	gw := &Gateway{Owners: []Start{}, addr: a}
	var ifaces []string
	for _, o := range w.obs {
		if o.Plane != netmodel.PlaneFIB || o.Node != f.Node || o.VRF != f.VRF {
			continue
		}
		for _, r := range o.Routes {
			for _, n := range r.NextHops {
				if n.Addr != a {
					continue
				}
				if n.Interface != "" {
					ifaces = appendNew(ifaces, n.Interface)
				}
				if f.Interface == "" || n.Interface == f.Interface {
					gw.Evidence = appendNew(gw.Evidence, Support{Source: o.Source, CollectedAt: utcText(o.CollectedAt)})
				}
			}
		}
	}
	slices.Sort(ifaces)
	at := fmt.Sprintf("%s (%s)", f.Node, f.VRF)
	switch {
	case f.Interface != "" && len(gw.Evidence) == 0:
		on := "on no named interface"
		if len(ifaces) > 0 {
			on = "on " + strings.Join(ifaces, ", ")
		}
		return f, nil, fmt.Errorf("fib routes of %s name next hop %s %s, not on %s", at, a, on, f.Interface)
	case f.Interface == "" && len(ifaces) > 1:
		return f, nil, fmt.Errorf("fib routes of %s name next hop %s on %s; name one as %s%%INTERFACE", at, a, strings.Join(ifaces, ", "), a)
	}
	gw.Evidence = sortSupports(gw.Evidence)
	for _, o := range w.owners[a] {
		gw.Owners = append(gw.Owners, Start{Node: o.node, VRF: o.vrf})
	}
	return f, gw, nil
}

func ospfRecord(attrs []netmodel.Attribute) bool {
	return slices.ContainsFunc(attrs, func(a netmodel.Attribute) bool { return strings.HasPrefix(a.Key, "ospf.") })
}

func attrValues(attrs []netmodel.Attribute, key string) []string {
	var out []string
	for _, a := range attrs {
		if a.Key == key {
			out = append(out, a.Value)
		}
	}
	return out
}

func appendNew[T comparable](xs []T, x T) []T {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// severAdjacency says what a lost OSPF adjacency does to the segment that
// leaves at through n, whose decision rests on ev. The link stays up, so a
// connected or static route across it keeps forwarding. An OSPF route across it
// loses the segment when the link's transit dependency is proven, and is
// unknown otherwise, as
// is any other origin and a mix of origins. A BGP route is unknown wherever it
// is, because its session or next-hop resolution may run over the adjacency,
// and BGP withdrawal is not modeled.
func (w *walker) severAdjacency(at state, n netmodel.NextHop, seg *Segment, ev []Support) (Hop, bool) {
	f, adj := w.fail, w.adj
	var origins []string
	for _, e := range ev {
		if !e.Absent {
			origins = appendNew(origins, e.Origin)
		}
	}
	slices.Sort(origins)
	unknown := func(why string) (Hop, bool) {
		w.touched = true
		return Hop{Via: seg, Decision: Decision{Kind: KindUnknown, Reason: why}}, true
	}
	if slices.Contains(origins, netmodel.OriginBGP) {
		return unknown(fmt.Sprintf("%s (%s) forwards by a BGP route; whether its session or next-hop resolution runs over the lost adjacency is not in the evidence, and BGP withdrawal is not modeled", at.node, at.vrf))
	}
	leaves := at == state{f.Node, f.VRF}
	why := ""
	switch {
	case leaves && n.Interface == f.Interface:
	case leaves && n.Interface == "":
		why = fmt.Sprintf("%s (%s) names no interface for next hop %s, so whether it leaves by %s is unknown", at.node, at.vrf, n.Addr, f.Interface)
	case leaves:
		return Hop{}, false
	default:
		target := n.Addr
		if !target.IsValid() {
			target = w.dest
		}
		if owners := w.owners[target]; len(owners) != 1 || owners[0] != (state{f.Node, f.VRF}) {
			return Hop{}, false
		}
		steps := []Step{{Node: at.node, VRF: at.vrf, Interface: n.Interface, NextHop: addrText(n.Addr)}, {Node: f.Node, VRF: f.VRF}}
		_, far, reason := w.segmentEnds(steps, 0, w.dest)
		switch {
		case reason != "":
			why = reason + ", so whether the segment arrives on " + f.Interface + " is unknown"
		case far.iface != f.Interface:
			return Hop{}, false
		}
	}
	if !slices.ContainsFunc(origins, func(o string) bool { return o != netmodel.OriginConnected && o != netmodel.OriginStatic }) {
		return Hop{}, false
	}
	switch {
	case why != "":
	case !slices.Equal(origins, []string{netmodel.OriginOSPF}):
		why = fmt.Sprintf("%s (%s) forwards by origin %s; whether that route depends on the OSPF adjacency is not in the evidence", at.node, at.vrf, strings.Join(origins, " and "))
	case !adj.Proven:
		why = "the segment crosses the link of the lost adjacency, and " + adj.Reason
	case leaves && n.Addr != adj.addr:
		why = fmt.Sprintf("next hop %s on %s is not the neighbor's recorded address %s", n.Addr, f.Interface, adj.NeighborAddr)
	case !leaves && at.node != f.OSPFNeighbor:
		why = fmt.Sprintf("the segment arrives on %s from %s, which is not the recorded neighbor %s", f.Interface, at.node, f.OSPFNeighbor)
	}
	if why != "" {
		return unknown(why)
	}
	w.touched = true
	return Hop{Via: seg, Decision: Decision{Kind: KindFailed, Reason: "the segment crosses the simulated failure: " + f.String()}}, true
}

// severGateway says what a lost next hop does to the segment that leaves at
// through n. Only the failure's node and routing domain lose it, and only on
// the named interface when there is one: the same address on another node, in
// another routing domain, or on another link is another next hop. A leg that
// names no interface may or may not be the one on the named interface. An
// on-link leg to the gateway's own address is unknown, since whether the
// gateway still answers for itself once it stops forwarding is not recorded.
func (w *walker) severGateway(at state, n netmodel.NextHop, seg *Segment) (Hop, bool) {
	f := w.fail
	target := n.Addr
	if !target.IsValid() {
		target = w.dest
	}
	why := ""
	switch {
	case at != (state{f.Node, f.VRF}) || target != w.gw.addr:
		return Hop{}, false
	case f.Interface != "" && n.Interface != "" && n.Interface != f.Interface:
		return Hop{}, false
	case f.Interface != "" && n.Interface == "":
		why = fmt.Sprintf("%s (%s) names no interface for next hop %s, so whether it is the lost next hop on %s is unknown", at.node, at.vrf, target, f.Interface)
	case !n.Addr.IsValid():
		why = fmt.Sprintf("%s is the lost next hop's own address, on link from %s (%s); whether it still answers once it stops forwarding is not in the evidence", target, at.node, at.vrf)
	}
	w.touched = true
	if why != "" {
		return Hop{Via: seg, Decision: Decision{Kind: KindUnknown, Reason: why}}, true
	}
	return Hop{Via: seg, Decision: Decision{Kind: KindFailed, Reason: "the segment crosses the simulated failure: " + f.String()}}, true
}

// sever says what the failure does to the segment that leaves at through n,
// whose decision rests on ev. It returns the leaf that takes the place of the
// walk past the segment, and false when the segment does not cross the failure.
// A segment whose crossing the evidence cannot decide ends in an unknown leaf.
func (w *walker) sever(at state, n netmodel.NextHop, seg *Segment, ev []Support) (Hop, bool) {
	f := w.fail
	switch {
	case w.gw != nil:
		return w.severGateway(at, n, seg)
	case w.adj != nil:
		return w.severAdjacency(at, n, seg, ev)
	}
	target := n.Addr
	if !target.IsValid() {
		target = w.dest
	}
	var to *state
	if owners := w.owners[target]; len(owners) == 1 {
		to = &owners[0]
	}
	why := ""
	switch {
	case f.Interface == "":
		if to == nil || to.node != f.Node {
			return Hop{}, false
		}
	case at.node == f.Node && n.Interface == f.Interface:
	case at.node == f.Node && n.Interface == "":
		why = fmt.Sprintf("%s (%s) names no interface for next hop %s, so whether it leaves by %s is unknown", at.node, at.vrf, n.Addr, f.Interface)
	case at.node == f.Node || to == nil || to.node != f.Node:
		return Hop{}, false
	default:
		steps := []Step{{Node: at.node, VRF: at.vrf, Interface: n.Interface, NextHop: addrText(n.Addr)}, {Node: to.node, VRF: to.vrf}}
		_, far, reason := w.segmentEnds(steps, 0, w.dest)
		switch {
		case reason != "":
			why = reason + ", so whether the segment arrives on " + f.Interface + " is unknown"
		case far.iface != f.Interface:
			return Hop{}, false
		}
	}
	w.touched = true
	if why != "" {
		return Hop{Via: seg, Decision: Decision{Kind: KindUnknown, Reason: why}}, true
	}
	return Hop{Via: seg, Decision: Decision{Kind: KindFailed, Reason: "the segment crosses the simulated failure: " + f.String()}}, true
}

// heldOnFailure says why delivery is unknown when the destination is an address
// of the down interface at at, and returns "" otherwise. Whether a node still
// answers for an address on a down interface depends on its platform, which the
// evidence does not record: Linux keeps the address local and delivers what
// reaches it another way, where many routers withdraw it. When another
// interface of at holds the destination too, which one delivers it is not in
// the evidence either. A lost next hop or OSPF adjacency leaves its interface
// up, so neither makes an address on it unknown here.
func (w *walker) heldOnFailure(at state) string {
	if w.fail == nil || w.adj != nil || w.gw != nil || w.fail.Interface == "" || w.fail.Node != at.node {
		return ""
	}
	names := w.ownerIfaces(at.node, at.vrf, w.dest)
	if !slices.Contains(names, w.fail.Interface) {
		return ""
	}
	w.touched = true
	if len(names) > 1 {
		return fmt.Sprintf("%s (%s) holds %s on %s, so which one delivers it with %s down is unknown", at.node, at.vrf, w.dest, strings.Join(names, ", "), w.fail.Interface)
	}
	return fmt.Sprintf("%s (%s) holds %s on %s, which is down; whether a node still answers for an address on a down interface depends on its platform, which the evidence does not record", at.node, at.vrf, w.dest, w.fail.Interface)
}

// Text renders the simulation for a person. Every line passes through
// textsafe.Clean, because names come from the file.
func (s Simulation) Text() string {
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(textsafe.Clean(fmt.Sprintf(format, args...)))
		b.WriteByte('\n')
	}
	line("")
	line("Failure simulation: %s, from %s (%s)", s.Failure, s.Source.Node, s.Source.VRF)
	if g := s.Gateway; g != nil {
		f := s.Failure
		on := ""
		if f.Interface != "" {
			on = " on " + f.Interface
		}
		line("Recorded FIB only: %s (%s) loses next hop %s%s, and nothing else changes: the interface stays up, so other next hops and on-link destinations on it keep forwarding, and every other node keeps its forwarding through the address. The loss is simulated, not observed. No route is recomputed. Convergence is not predicted.", f.Node, f.VRF, f.NextHop, on)
		line("Whether %s (%s) stops selecting a next hop that stops forwarding while its link stays up is not in the evidence, so a destination that keeps another recorded next hop is unknown, never redundancy_lost.", f.Node, f.VRF)
		owners := make([]string, len(g.Owners))
		for i, o := range g.Owners {
			owners[i] = o.Node + " (" + o.VRF + ")"
		}
		line("Next hop: held by %s; recorded in %s.", cmp.Or(strings.Join(owners, ", "), "no modeled node"), evidenceText(g.Evidence))
	} else if a := s.Adjacency; a != nil {
		line("Recorded FIB only: each node stops using an OSPF next hop that crosses the adjacency's link. The link stays up, so connected and static routes across it keep forwarding. No SPF is run, so a destination left with no recorded next hop is unknown, never lost. Convergence is not predicted.")
		line("Adjacency: neighbor address %s, remote interface %s, evidence %s.", cmp.Or(a.NeighborAddr, "unknown"), cmp.Or(a.RemoteInterface, "unreported"), evidenceText(a.Evidence))
		if a.Proven {
			line("Transit dependency proven: the link is point-to-point and the neighbor is full, so once the adjacency is gone SPF cannot use the link as a transit edge (RFC 2328 12.4.1.1, 16.1), and each recorded OSPF next hop across it is removed. This assumes the records are current. It does not prove what the FIB holds after the loss, and the link's stub network may still be advertised.")
		} else {
			line("Transit dependency not proven: %s. Every OSPF next hop across the link is unknown.", a.Reason)
		}
	} else {
		line("Recorded FIB only: each node stops using a next hop that crosses the failure, and no route is recomputed. Convergence is not predicted.")
	}
	line("%d destinations considered, %d unchanged.", s.Considered, s.Unchanged)
	if s.skipped {
		line("The simulation stopped at a bound; destinations past it were not considered.")
	}
	if s.stopped {
		line("Some walks stopped at a depth, state, or fan-out bound, and a walk stopped by a bound never proves delivery.")
	}
	omitted := 0
	for _, a := range s.Affected {
		if a.After == nil {
			omitted++
		}
	}
	if omitted > 0 {
		line("The output stopped at a bound; %d affected destinations below are rated, and their walks are omitted.", omitted)
	}
	for _, a := range s.Affected {
		owners := make([]string, len(a.Owners))
		for i, o := range a.Owners {
			owners[i] = o.Node + " " + o.VRF
		}
		line("  %s %s (%s): %s", a.Impact, a.Destination, cmp.Or(strings.Join(owners, ", "), "no modeled owner"), a.Reason)
		if a.After == nil {
			line("    walk omitted: the walks above reach the output bound")
			continue
		}
		renderTree(line, a.After, 2)
	}
	return b.String()
}
