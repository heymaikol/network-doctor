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
// in every routing domain that lists it.
type Failure struct {
	Node      string `json:"node"`
	Interface string `json:"interface,omitempty"`
}

func (f Failure) String() string {
	if f.Interface == "" {
		return "router " + f.Node + " unavailable"
	}
	return "interface " + f.Node + " " + f.Interface + " down"
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
// output within about two walks' size.
type Affected struct {
	Destination string  `json:"destination"`
	Owners      []Start `json:"owners,omitempty"`
	Impact      Impact  `json:"impact"`
	Reason      string  `json:"reason"`
	After       *Hop    `json:"after,omitempty"`
}

// Simulation is what one failure does to forwarding from the source. Considered
// counts the destinations walked, Unchanged those with no impact, and Affected
// lists the rest in address order.
type Simulation struct {
	Failure    Failure    `json:"failure"`
	Source     Start      `json:"source"`
	Considered int        `json:"considered"`
	Unchanged  int        `json:"unchanged"`
	Affected   []Affected `json:"affected"`
	Truncated  bool       `json:"truncated"`
}

// Simulate removes one router or interface from the recorded FIB and compares
// forwarding from the source before and after, for every address an interface
// in the file holds and for each extra destination. Each node stops using a next
// hop whose segment crosses the failure, and nothing else changes: no route is
// recomputed and no convergence is predicted. It reads only f and changes
// nothing in it.
func Simulate(f File, fail Failure, extra ...netip.Addr) (Simulation, error) {
	w := newWalker(f, netip.Addr{})
	if err := w.checkFailure(f.Source, fail); err != nil {
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

	s := Simulation{Failure: fail, Source: f.Source, Affected: []Affected{}}
	if len(dests) > maxDestinations {
		dests, s.Truncated = dests[:maxDestinations], true
	}
	src := state{f.Source.Node, f.Source.VRF}
	spent := 0
	for _, d := range dests {
		if spent >= maxSimStates {
			s.Truncated = true
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
		s.Truncated = s.Truncated || trunc
		a := Affected{Destination: d.String(), After: &after}
		for _, o := range w.owners[d] {
			a.Owners = append(a.Owners, Start{Node: o.node, VRF: o.vrf})
		}
		a.Impact, a.Reason = rate(reachOf(&before, nil), reachOf(&after, nil), w.touched)
		if a.Impact == ImpactNone {
			s.Unchanged++
			continue
		}
		s.Affected = append(s.Affected, a)
	}
	slices.SortFunc(s.Affected, func(a, b Affected) int {
		return netip.MustParseAddr(a.Destination).Compare(netip.MustParseAddr(b.Destination))
	})
	shown := 0
	for i := range s.Affected {
		if shown >= maxStates {
			s.Affected[i].After = nil
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

// sever says what the failure does to the segment that leaves at through n. It
// returns the leaf that takes the place of the walk past the segment, and false
// when the segment does not cross the failure. A segment whose crossing the
// evidence cannot decide ends in an unknown leaf.
func (w *walker) sever(at state, n netmodel.NextHop, seg *Segment) (Hop, bool) {
	f := w.fail
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

// heldOnFailure reports that the destination is an address of the down interface
// at at. A down interface owns nothing, as a failed router owns nothing, so the
// node forwards the destination like any other address. When
// another interface of at holds the destination too, which one delivers it is
// not in the evidence, and why says so.
func (w *walker) heldOnFailure(at state) (lost bool, why string) {
	if w.fail == nil || w.fail.Interface == "" || w.fail.Node != at.node {
		return false, ""
	}
	names := w.ownerIfaces(at.node, at.vrf, w.dest)
	if !slices.Contains(names, w.fail.Interface) {
		return false, ""
	}
	w.touched = true
	if len(names) > 1 {
		return false, fmt.Sprintf("%s (%s) holds %s on %s, so which one delivers it with %s down is unknown", at.node, at.vrf, w.dest, strings.Join(names, ", "), w.fail.Interface)
	}
	return true, ""
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
	line("Recorded FIB only: each node stops using a next hop that crosses the failure, and no route is recomputed. Convergence is not predicted.")
	line("%d destinations considered, %d unchanged.", s.Considered, s.Unchanged)
	if s.Truncated {
		line("The simulation stopped at a bound; destinations past it were not considered, and a walk stopped by a bound proves nothing.")
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
