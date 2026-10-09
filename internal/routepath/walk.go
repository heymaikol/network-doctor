package routepath

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// maxDepth bounds how many hops one walk follows, and maxStates bounds how many
// node visits it makes. A wide ECMP fabric multiplies visits, so the state
// budget is what stops it. maxFanout bounds the next hops followed at one node:
// a route can list thousands, and the walk keeps the first maxFanout and marks
// the walk truncated.
// ponytail: flat state budget over the whole walk, not per-depth limits. Add per-depth caps if large fabrics need them.
const (
	maxDepth  = 32
	maxStates = 512
	maxFanout = 64
)

// The expected walk trusts the control plane, then the configured plane, which
// is where static routes live when no routing collector ran. The forwarding walk
// trusts only the FIB, because the FIB is what the kernel sends traffic by.
var (
	expectedPlanes   = []netmodel.Plane{netmodel.PlaneControl, netmodel.PlaneConfigured}
	forwardingPlanes = []netmodel.Plane{netmodel.PlaneFIB}
	// readPlanes are the only planes the explanation reads. The decoder validates
	// intended and observed rows and then leaves them unread, so they cannot own
	// an address or name a neighbor.
	readPlanes = []netmodel.Plane{netmodel.PlaneControl, netmodel.PlaneConfigured, netmodel.PlaneFIB}
)

// state is one routing domain on one node: where a walk stands.
type state struct{ node, vrf string }

// checkKey names the segment a recorded Check describes. nh is the next-hop
// address text, or empty for a check that names none.
type checkKey struct {
	node, vrf, iface string
	dest             netip.Addr
	nh               string
}

// walker holds what one Explain call reads from the file. It is built once, so
// every walk sees the same canonical rows in the same order.
type walker struct {
	m         netmodel.Model
	obs       []netmodel.Observation
	dest      netip.Addr
	owners    map[netip.Addr][]state
	checks    map[checkKey][]Check
	budget    int
	truncated bool
}

// Explain walks file from its source toward dest, once along the expected
// routes and once along the forwarding table, then compares the two. It sends
// no traffic and reads nothing beyond file.
func Explain(f File, dest netip.Addr) Explanation {
	dest = dest.WithZone("").Unmap()
	w := newWalker(f, dest)
	start := state{node: f.Source.Node, vrf: f.Source.VRF}
	e := Explanation{
		Source:      f.Source,
		Destination: dest.String(),
		Findings:    []Finding{},
		Regions:     []FailureRegion{},
		Limitations: []string{},
	}
	var expTrunc, fwdTrunc bool
	e.Expected, expTrunc = w.run(expectedPlanes, start)
	e.Forwarding, fwdTrunc = w.run(forwardingPlanes, start)
	e.Truncated = expTrunc || fwdTrunc
	e.Findings = compareWalks(&e.Expected, &e.Forwarding)
	e.Regions = failureRegions(&e.Forwarding)
	e.Limitations = limitations(&e.Expected, &e.Forwarding)
	return e
}

func newWalker(f File, dest netip.Addr) *walker {
	w := &walker{
		m:      f.Model,
		dest:   dest,
		owners: map[netip.Addr][]state{},
		checks: map[checkKey][]Check{},
	}
	for _, o := range f.Model.Observations() {
		if slices.Contains(readPlanes, o.Plane) {
			w.obs = append(w.obs, o)
		}
	}
	for _, o := range w.obs {
		for _, i := range o.Interfaces {
			for _, a := range i.Addresses {
				k := a.Addr().WithZone("").Unmap()
				s := state{o.Node, o.VRF}
				if !slices.Contains(w.owners[k], s) {
					w.owners[k] = append(w.owners[k], s)
				}
			}
		}
	}
	for _, c := range f.Checks {
		k := checkKey{c.Node, c.VRF, c.Interface, c.Destination.WithZone("").Unmap(), keyAddr(c.NextHop)}
		w.checks[k] = append(w.checks[k], c)
	}
	return w
}

func (w *walker) run(planes []netmodel.Plane, start state) (Hop, bool) {
	w.budget, w.truncated = maxStates, false
	h := w.walk(planes, start, nil, nil)
	return h, w.truncated
}

// walk decides what happens to the destination at one node, and follows every
// next hop that the evidence names. path holds the states already on this branch.
func (w *walker) walk(planes []netmodel.Plane, at state, via *Segment, path []state) Hop {
	h := Hop{Node: at.node, VRF: at.vrf, Via: via}
	switch {
	case slices.Contains(path, at):
		h.Decision = Decision{Kind: KindLoop, Reason: "returns to a node already on this path"}
		return h
	case len(path) >= maxDepth || w.budget == 0:
		w.truncated = true
		h.Decision = Decision{Kind: KindTruncated, Reason: "traversal bound reached"}
		return h
	}
	w.budget--
	if slices.Contains(w.owners[w.dest], at) {
		h.Decision = Decision{Kind: KindLocal, Proven: true, Reason: "destination is an address on this node"}
		return h
	}
	d, hops := w.decide(planes, at)
	h.Decision = d
	if d.Kind != KindForward {
		return h
	}
	branch := append(slices.Clone(path), at)
	shared := map[string]int{}
	for _, n := range hops {
		shared[n.Interface]++
	}
	for _, n := range hops {
		seg := &Segment{From: at.node, VRF: at.vrf, Interface: n.Interface, NextHop: addrText(n.Addr), Outcome: w.outcome(at, n, shared[n.Interface])}
		h.Next = append(h.Next, w.resolve(planes, at, n, seg, branch))
	}
	return h
}

// resolve follows one next hop to the node that owns its address. The owner's
// VRF comes from the observation that lists the address, never from the name
// of the current VRF. An on-link next hop is resolved by the destination itself.
// When no modeled node owns the address, the walk stops there and says why.
func (w *walker) resolve(planes []netmodel.Plane, from state, n netmodel.NextHop, seg *Segment, branch []state) Hop {
	target := n.Addr
	if !target.IsValid() {
		target = w.dest
	}
	owners := w.owners[target]
	switch len(owners) {
	case 1:
		return w.walk(planes, owners[0], seg, branch)
	case 0:
		if !n.Addr.IsValid() {
			return Hop{Via: seg, Decision: Decision{Kind: KindOnLink, Reason: fmt.Sprintf("destination is on link through %s, and no modeled node owns it", n.Interface)}}
		}
		return Hop{Via: seg, Decision: Decision{Kind: KindUnresolved, Reason: fmt.Sprintf("no modeled interface owns %s; %s", n.Addr, w.neighborClaim(from, n))}}
	default:
		names := make([]string, len(owners))
		for i, s := range owners {
			names[i] = s.node + " (" + s.vrf + ")"
		}
		return Hop{Via: seg, Decision: Decision{Kind: KindAmbiguous, Reason: fmt.Sprintf("%s is owned by several nodes: %s", target, strings.Join(names, ", "))}}
	}
}

// neighborClaim says whether a neighbor record names the next hop. That is
// evidence of a node, but it names no routing domain, so the walk stops there.
func (w *walker) neighborClaim(from state, n netmodel.NextHop) string {
	for _, o := range w.obs {
		if o.Node != from.node || o.VRF != from.vrf {
			continue
		}
		for _, nb := range o.Neighbors {
			if (n.Interface == "" || nb.LocalInterface == n.Interface) && nb.RemoteAddr == n.Addr {
				return "neighbor " + nb.RemoteNode + " reports it, but no routing domain is known for that node"
			}
		}
	}
	return "no neighbor record names it either"
}

// decide picks the routing decision at one node from the first plane in planes
// that holds a route for the destination. A plane with no route proves absence
// only when it is complete. A partial plane proves nothing, so the next plane
// is asked. The returned next hops are the candidates the walk should follow.
func (w *walker) decide(planes []netmodel.Plane, at state) (Decision, []netmodel.NextHop) {
	for _, p := range planes {
		cands := w.candidates(at, p)
		if len(cands) > 0 {
			return w.choose(at, p, cands)
		}
		if w.complete(at, p) {
			return Decision{Kind: KindNoRoute, Basis: p, Proven: true, Reason: fmt.Sprintf("complete %s table holds no route to %s", p, w.dest)}, nil
		}
	}
	return Decision{Kind: KindUnknown, Basis: planes[0], Reason: "no complete table and no matching route for this node"}, nil
}

// choose takes the longest prefix that matches the destination in plane p and
// reads its rows through netmodel.Lookup. A partial table cannot prove that the
// longest match is installed, so the FIB decision stays unknown there, and the
// expected walk keeps the candidate as unproven.
func (w *walker) choose(at state, p netmodel.Plane, cands []netip.Prefix) (Decision, []netmodel.NextHop) {
	ans := w.m.Lookup(at.node, at.vrf, p, cands[0])
	d := Decision{
		Basis:    p,
		Prefix:   cands[0].String(),
		Shadowed: prefixTexts(cands[1:]),
		Proven:   w.complete(at, p),
		Evidence: supports(ans),
	}
	switch ans.State {
	case netmodel.Present:
		first := ans.Evidence[0].Route
		for _, e := range ans.Evidence[1:] {
			if !sameForwarding(first, e.Route) {
				d.Kind = KindConflicting
				d.Reason = fmt.Sprintf("%s origins disagree on forwarding for %s; no path is chosen", p, cands[0])
				return d, nil
			}
		}
		switch {
		case p == netmodel.PlaneFIB && !d.Proven:
			d.Kind = KindUnknown
			d.Reason = "FIB for this node is partial, so a more specific route may exist; no path is chosen"
			return d, nil
		case first.Discard:
			d.Kind = KindDiscard
		case len(first.NextHops) == 0:
			d.Kind = KindUnknown
			d.Reason = "route names no next hop and is not a discard, so forwarding is unknown"
			return d, nil
		default:
			hops := first.NextHops
			if len(hops) > maxFanout {
				hops = hops[:maxFanout]
				w.truncated = true
			}
			d.Kind = KindForward
			d.NextHops = nextHopTexts(hops)
			return d, hops
		}
		return d, nil
	case netmodel.Conflicting:
		d.Kind = KindConflicting
		d.Reason = fmt.Sprintf("%s rows for %s disagree; both sides are kept", p, cands[0])
		return d, nil
	}
	d.Kind = KindUnknown
	d.Reason = "evidence for this prefix does not resolve"
	return d, nil
}

// candidates lists the prefixes in plane p of node at that contain the
// destination, longest first. The match is the longest one, but a shorter one
// still matched, so it is kept as a shadowed alternative.
func (w *walker) candidates(at state, p netmodel.Plane) []netip.Prefix {
	var out []netip.Prefix
	for _, o := range w.obs {
		if o.Node != at.node || o.VRF != at.vrf || o.Plane != p {
			continue
		}
		for _, r := range o.Routes {
			if r.Prefix.Contains(w.dest) && !slices.Contains(out, r.Prefix) {
				out = append(out, r.Prefix)
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return cmp.Compare(b.Bits(), a.Bits()) })
	return out
}

// complete reports whether some observation of node in plane p holds its full
// routing table, which is what lets an absence count as proof.
func (w *walker) complete(at state, p netmodel.Plane) bool {
	for _, o := range w.obs {
		if o.Node == at.node && o.VRF == at.vrf && o.Plane == p && o.RoutesComplete {
			return true
		}
	}
	return false
}

// outcome reads the recorded checks for the segment that leaves at through n.
// A check that names this next hop applies to it. A check that names none
// applies to the interface only when the interface carries one next hop. When
// several share it, the check is unattributed rather than given to one of them.
// Silence is OutcomeNone, and it never counts as a failure.
func (w *walker) outcome(at state, n netmodel.NextHop, shared int) Outcome {
	key := func(nh string) checkKey { return checkKey{at.node, at.vrf, n.Interface, w.dest, nh} }
	if nh := keyAddr(n.Addr); nh != "" {
		if rs := w.checks[key(nh)]; len(rs) > 0 {
			return resultOf(rs)
		}
	}
	rs := w.checks[key("")]
	switch {
	case len(rs) == 0:
		return OutcomeNone
	case shared > 1:
		return OutcomeUnattributed
	}
	return resultOf(rs)
}

// resultOf turns the checks for one segment into its outcome.
func resultOf(cs []Check) Outcome {
	pass, fail := false, false
	for _, c := range cs {
		pass = pass || c.Result == CheckPass
		fail = fail || c.Result == CheckFail
	}
	switch {
	case pass && fail:
		return OutcomeConflicting
	case fail:
		return OutcomeFail
	}
	return OutcomePass
}

// keyAddr is the canonical text of a next-hop address, or empty when there is none.
func keyAddr(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.WithZone("").Unmap().String()
}

func sameForwarding(a, b netmodel.Route) bool {
	return a.Discard == b.Discard && slices.Equal(a.NextHops, b.NextHops)
}

func supports(ans netmodel.Answer) []Support {
	var out []Support
	for _, e := range ans.Evidence {
		out = append(out, Support{Source: e.Source, CollectedAt: utcText(e.CollectedAt), Origin: e.Route.Origin})
	}
	for _, p := range ans.AbsentIn {
		out = append(out, Support{Source: p.Source, CollectedAt: utcText(p.CollectedAt), Absent: true})
	}
	return out
}

func nextHopTexts(hops []netmodel.NextHop) []NextHop {
	out := make([]NextHop, len(hops))
	for i, h := range hops {
		out[i] = NextHop{Addr: addrText(h.Addr), Interface: h.Interface}
	}
	return out
}

func prefixTexts(ps []netip.Prefix) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func utcText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
