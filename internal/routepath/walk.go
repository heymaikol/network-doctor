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
	// The intended walk overlays intent on the FIB. Where intent is silent, the
	// FIB decides, so the walk goes on past nodes that intent does not describe.
	intendedPlanes = []netmodel.Plane{netmodel.PlaneIntended, netmodel.PlaneFIB}
	// readPlanes are the only planes that can own an address or name a neighbor.
	// The walker keeps intended rows for their routes alone, and drops observed
	// rows after the decoder validates them.
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

// ownerKey is one address on one routing domain, the unit a local decision names.
type ownerKey struct {
	addr netip.Addr
	at   state
}

// owning is one observation that lists an address on a read plane.
type owning struct {
	plane netmodel.Plane
	sup   Support
}

// walker holds what one Explain call reads from the file. It is built once, so
// every walk sees the same canonical rows in the same order.
type walker struct {
	m         netmodel.Model
	obs       []netmodel.Observation
	dest      netip.Addr
	owners    map[netip.Addr][]state
	owned     map[ownerKey][]owning
	checks    map[checkKey][]Check
	budget    int
	truncated bool
	notes     []string
}

// Explain walks file from its source toward dest, once along the expected
// routes and once along the forwarding table, then compares the two. When file
// names the source address, it also compares the return route. It sends no
// traffic and reads nothing beyond file.
func Explain(f File, dest netip.Addr) Explanation {
	e, w := explainWalks(f, dest)
	e.Asymmetry = w.asymmetry(f, e)
	e.Drift = w.drift(&e)
	return e
}

// explainWalks is Explain without the return comparison. The return walk uses
// it, so a return walk never compares itself with another return.
func explainWalks(f File, dest netip.Addr) (Explanation, *walker) {
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
	expNotes := w.notes
	e.Forwarding, fwdTrunc = w.run(forwardingPlanes, start)
	fwdNotes := w.notes
	e.Truncated = expTrunc || fwdTrunc
	e.Findings = compareWalks(&e.Expected, &e.Forwarding)
	e.Regions = failureRegions(&e.Forwarding)
	e.Limitations = limitations(&e.Expected, &e.Forwarding, expNotes, fwdNotes)
	return e, w
}

func newWalker(f File, dest netip.Addr) *walker {
	w := &walker{
		m:      f.Model,
		dest:   dest,
		owners: map[netip.Addr][]state{},
		owned:  map[ownerKey][]owning{},
		checks: map[checkKey][]Check{},
	}
	for _, o := range f.Model.Observations() {
		if slices.Contains(readPlanes, o.Plane) || o.Plane == netmodel.PlaneIntended {
			w.obs = append(w.obs, o)
		}
	}
	for _, o := range w.obs {
		if !slices.Contains(readPlanes, o.Plane) {
			continue
		}
		for _, i := range o.Interfaces {
			for _, a := range i.Addresses {
				k := a.Addr().WithZone("").Unmap()
				s := state{o.Node, o.VRF}
				ok := ownerKey{k, s}
				row := owning{o.Plane, Support{Source: o.Source, CollectedAt: utcText(o.CollectedAt)}}
				if !slices.Contains(w.owned[ok], row) {
					w.owned[ok] = append(w.owned[ok], row)
				}
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
	w.budget, w.truncated, w.notes = maxStates, false, nil
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
	if owned := w.owned[ownerKey{w.dest, at}]; len(owned) > 0 {
		h.Decision = w.localDecision(planes, at, owned)
		w.noteOtherOwners(at, owned)
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
	if len(hops) > maxFanout {
		hops = hops[:maxFanout]
		w.truncated = true
	}
	for _, n := range hops {
		out, checks := w.outcome(at, n, shared[n.Interface])
		seg := &Segment{From: at.node, VRF: at.vrf, Interface: n.Interface, NextHop: addrText(n.Addr), Outcome: out, Checks: checks}
		h.Next = append(h.Next, w.resolve(planes, at, n, seg, branch))
	}
	return h
}

// localDecision says the destination is an address on this node. Ownership
// decides the hop, as the kernel's local table does, but the decision names only
// the plane whose rows list the address, and it claims no proof: interface lists
// are partial, so no complete table backs ownership. noteUnchecked names any
// decision the walk's planes make at the node that contradicts that ownership.
func (w *walker) localDecision(planes []netmodel.Plane, at state, owned []owning) Decision {
	var p netmodel.Plane
	for _, q := range slices.Concat(planes, readPlanes) {
		if slices.ContainsFunc(owned, func(o owning) bool { return o.plane == q }) {
			p = q
			break
		}
	}
	var ev []Support
	for _, o := range owned {
		if o.plane == p {
			ev = append(ev, o.sup)
		}
	}
	ev = sortSupports(ev)
	w.noteUnchecked(planes, at, ev)
	return Decision{Kind: KindLocal, Basis: p, Evidence: ev, Reason: "destination is an address on this node"}
}

// noteUnchecked records the decision the walk's planes make at the node when
// that decision contradicts local ownership. A missing route and an on-link
// route are consistent with ownership: main tables normally omit local
// addresses, and a connected route covers them. An unknown decision with no
// matching prefix says nothing either. Any other decision is named rather than
// dropped, including a route with no next hops, which is named as forwarding
// unknown, and an unproven partial-FIB candidate.
func (w *walker) noteUnchecked(planes []netmodel.Plane, at state, ev []Support) {
	d, hops := w.decide(planes, at)
	if d.Kind == KindNoRoute || (d.Kind == KindUnknown && d.Prefix == "") || onLinkOnly(d, hops) {
		return
	}
	w.notes = append(w.notes, fmt.Sprintf("%s (%s): destination is an address in %s. The walk's planes decide %s. The local decision keeps ownership without checking that decision.", at.node, at.vrf, evidenceText(ev), decisionText(d)))
}

// noteOtherOwners names every other routing domain that also lists the
// destination. The walk stops at its own owner, so without this note the other
// claim would reach neither walk's output.
func (w *walker) noteOtherOwners(at state, own []owning) {
	here := evidenceText(ownSupports(own))
	for _, s := range w.owners[w.dest] {
		if s == at {
			continue
		}
		there := evidenceText(ownSupports(w.owned[ownerKey{w.dest, s}]))
		w.notes = append(w.notes, fmt.Sprintf("%s (%s) and %s (%s) both list %s, in %s and in %s. The walk stops at %s (%s) and does not follow the other claim.", at.node, at.vrf, s.node, s.vrf, w.dest, here, there, at.node, at.vrf))
	}
}

// ownSupports returns the rows of owned as sorted evidence.
func ownSupports(owned []owning) []Support {
	out := make([]Support, 0, len(owned))
	for _, o := range owned {
		out = append(out, o.sup)
	}
	return sortSupports(out)
}

// onLinkOnly reports a forward decision whose next hops name no address, so the
// destination itself is the next hop, as a connected route says.
func onLinkOnly(d Decision, hops []netmodel.NextHop) bool {
	if d.Kind != KindForward {
		return false
	}
	for _, n := range hops {
		if n.Addr.IsValid() {
			return false
		}
	}
	return true
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
		if o.Node != from.node || o.VRF != from.vrf || !slices.Contains(readPlanes, o.Plane) {
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
			return Decision{Kind: KindNoRoute, Basis: p, Proven: true, Evidence: w.absence(at, p), Reason: fmt.Sprintf("complete %s table holds no route to %s", p, w.dest)}, nil
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
			d.Kind = KindForward
			d.NextHops = nextHopTexts(first.NextHops)
			return d, first.NextHops
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
// applies to the interface when the interface carries one next hop. When
// several share it, an unnamed check cannot be placed on any of them, so the
// segment is unattributed unless a named failure or conflict says more.
// Silence is OutcomeNone, and it never counts as a failure.
func (w *walker) outcome(at state, n netmodel.NextHop, shared int) (Outcome, []Support) {
	key := func(nh string) checkKey { return checkKey{at.node, at.vrf, n.Interface, w.dest, nh} }
	var named []Check
	if nh := keyAddr(n.Addr); nh != "" {
		named = w.checks[key(nh)]
	}
	unnamed := w.checks[key("")]
	if shared > 1 && len(unnamed) > 0 {
		if len(named) > 0 {
			if out, sup := resultOf(named); out == OutcomeFail || out == OutcomeConflicting {
				return out, sup
			}
		}
		return OutcomeUnattributed, supportsOf(unnamed)
	}
	// Named and unnamed checks both apply to a single-hop interface, so they
	// combine. A pass beside an unnamed failure is a conflict, not a pass.
	all := append(slices.Clone(named), unnamed...)
	if len(all) == 0 {
		return OutcomeNone, nil
	}
	return resultOf(all)
}

// resultOf turns the checks for one segment into its outcome, and keeps each
// check's provenance so a conclusion traces back to its input.
func resultOf(cs []Check) (Outcome, []Support) {
	pass, fail := false, false
	for _, c := range cs {
		pass = pass || c.Result == CheckPass
		fail = fail || c.Result == CheckFail
	}
	out := supportsOf(cs)
	switch {
	case pass && fail:
		return OutcomeConflicting, out
	case fail:
		return OutcomeFail, out
	}
	return OutcomePass, out
}

// supportsOf lists checks as provenance, in a fixed order, so the output does
// not depend on the order the file lists them.
func supportsOf(cs []Check) []Support {
	out := make([]Support, 0, len(cs))
	for _, c := range cs {
		out = append(out, Support{Source: c.Source, CollectedAt: utcText(c.CollectedAt)})
	}
	return sortSupports(out)
}

func sortSupports(out []Support) []Support {
	slices.SortFunc(out, func(a, b Support) int {
		return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.CollectedAt, b.CollectedAt))
	})
	return out
}

// absence names the complete observations that prove a route is missing, so a
// no-route decision traces back to the tables that hold the proof.
func (w *walker) absence(at state, p netmodel.Plane) []Support {
	var out []Support
	for _, o := range w.obs {
		if o.Node == at.node && o.VRF == at.vrf && o.Plane == p && o.RoutesComplete {
			out = append(out, Support{Source: o.Source, CollectedAt: utcText(o.CollectedAt), Absent: true})
		}
	}
	return sortSupports(out)
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
