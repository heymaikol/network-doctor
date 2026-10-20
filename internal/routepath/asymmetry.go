package routepath

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// AsymmetryAssessment says what the forward and return routes of one flow show.
type AsymmetryAssessment string

const (
	// AssessSymmetric: the return retraces the forward route in reverse, router by
	// router and routing domain by routing domain, over the same link between
	// each pair of routers.
	AssessSymmetric AsymmetryAssessment = "symmetric"
	// AssessBenign: the return differs from the forward route, and no concern holds.
	// Asymmetry alone is not a fault, so this is not a failure.
	AssessBenign AsymmetryAssessment = "asymmetric_benign"
	// AssessRisk: the directions differ, and a concern ties the difference to a
	// policy boundary, a routing-domain change, or a recorded failure. It is a
	// risk to check, not a proven failure.
	AssessRisk AsymmetryAssessment = "asymmetric_risk"
	// AssessUnknown: one direction, or the link at one hop, is not proven, so the two
	// cannot be compared.
	AssessUnknown AsymmetryAssessment = "unknown"
)

// Concern kinds that do not come from a boundary. Boundary concerns use the
// BoundaryKind value as their kind.
const (
	concernVRF     = "vrf_crossing"
	concernFailure = "recorded_failure"
)

// BoundaryKind names a policy boundary that the topology file records on a node.
type BoundaryKind string

const (
	BoundaryStatefulFirewall BoundaryKind = "stateful_firewall"
	BoundaryNAT              BoundaryKind = "nat"
	BoundaryTunnel           BoundaryKind = "tunnel"
)

// Boundary is one recorded policy boundary on a node in one routing domain. It
// was recorded elsewhere, and nothing here checks it against a device.
// ponytail: a boundary applies to the whole node within its routing domain, not
// to one interface. Add per-interface placement when a device filters one port only.
type Boundary struct {
	netmodel.Provenance
	Node string
	VRF  string
	Kind BoundaryKind
}

// Step is one router on a proven route. Interface and NextHop name the egress
// it leaves by. The last step is the node that owns the target address, and it
// has no egress.
type Step struct {
	Node      string  `json:"node"`
	VRF       string  `json:"vrf"`
	Interface string  `json:"interface,omitempty"`
	NextHop   string  `json:"next_hop,omitempty"`
	Outcome   Outcome `json:"outcome"`
}

// Concern is evidence that makes an asymmetry relevant. Direction says which
// route holds the evidence: forward, return, or both.
type Concern struct {
	Kind      string    `json:"kind"`
	Direction string    `json:"direction"`
	Node      string    `json:"node,omitempty"`
	VRF       string    `json:"vrf,omitempty"`
	Detail    string    `json:"detail"`
	Evidence  []Support `json:"evidence,omitempty"`
}

// Asymmetry compares the forward route with the return route, which is the
// route from the destination back to ReturnTo. It exists only when the
// topology names the source address. Asymmetry alone never raises a concern.
type Asymmetry struct {
	Assessment AsymmetryAssessment `json:"assessment"`
	Reason     string              `json:"reason"`
	ReturnTo   string              `json:"return_to"`
	// ForwardRoute and ReturnRoute are set only when that direction is proven.
	ForwardRoute []Step    `json:"forward_route,omitempty"`
	ReturnRoute  []Step    `json:"return_route,omitempty"`
	Concerns     []Concern `json:"concerns,omitempty"`
	// Return is the full walk toward ReturnTo, with its own findings and
	// failure regions. It is nil when the destination has no single routing
	// domain to start from.
	Return *Explanation `json:"return,omitempty"`
}

// asymmetry compares the forward walk in fwd with the return walk. The return
// walk starts at the one routing domain that owns the destination, and it
// heads for f.SourceAddr. It returns nil when the topology names no source
// address, because then the question is not asked, and when the source owns
// the destination itself, because then there is no path to compare.
func (w *walker) asymmetry(f File, fwd Explanation) *Asymmetry {
	if !f.SourceAddr.IsValid() || fwd.Forwarding.Decision.Kind == KindLocal {
		return nil
	}
	src := f.SourceAddr.WithZone("").Unmap()
	a := &Asymmetry{ReturnTo: src.String()}
	fSteps, fOK, fWhy := chainOf(&fwd.Forwarding)
	if fOK {
		a.ForwardRoute = fSteps
	}

	var rSteps []Step
	var rOK bool
	var rWhy string
	if owners := w.owners[w.dest]; len(owners) == 1 {
		ret, _ := explainWalks(File{Source: Start{Node: owners[0].node, VRF: owners[0].vrf}, Model: f.Model, Checks: f.Checks}, src)
		a.Return = &ret
		rSteps, rOK, rWhy = chainOf(&ret.Forwarding)
		// A return that ends anywhere but the source does not reply to the flow
		// it is compared with, so it is not that flow's return route.
		if rOK {
			if end := rSteps[len(rSteps)-1]; end.Node != f.Source.Node || end.VRF != f.Source.VRF {
				rOK, rWhy = false, fmt.Sprintf("the return ends at %s (%s), not at the source %s (%s)", end.Node, end.VRF, f.Source.Node, f.Source.VRF)
			}
		}
	} else {
		rWhy = fmt.Sprintf("%s is owned by %d routing domains, so the return path has no single start", w.dest, len(owners))
	}

	switch {
	case !fOK:
		a.Assessment, a.Reason = AssessUnknown, "forward route not proven: "+fWhy
		return a
	case !rOK:
		a.Assessment, a.Reason = AssessUnknown, "return route not proven: "+rWhy
		return a
	}
	a.ReturnRoute = rSteps
	fwdSet, retSet := statesOf(fSteps), statesOf(rSteps)
	differ := "forward and return cross different routers or routing domains"
	if isReverse(fwdSet, retSet) {
		links, unknown := w.linksOf(fSteps, rSteps, src)
		switch {
		case links != "":
			differ = "forward and return cross the same routers in reverse order, but " + links
		case unknown != "":
			a.Assessment, a.Reason = AssessUnknown, "forward and return cross the same routers in reverse order, but "+unknown
			return a
		default:
			a.Assessment, a.Reason = AssessSymmetric, "forward and return cross the same routers and links in the same routing domains, in reverse order."
			return a
		}
	} else if sameStates(fwdSet, retSet) {
		differ = "forward and return cross the same routers, but the return does not retrace the forward route"
	}
	a.Concerns = concernsOf(f.Boundaries, fwdSet, retSet, fwd.Regions, a.Return.Regions)
	if len(a.Concerns) > 0 {
		a.Assessment = AssessRisk
		a.Reason = differ + ", and a concern below ties the difference to a policy boundary, a routing-domain change, or a recorded failure."
	} else {
		a.Assessment = AssessBenign
		a.Reason = differ + ". No policy boundary, routing-domain change, or recorded failure sits on one direction only, so this asymmetry is not a fault by itself."
	}
	return a
}

// chainOf reads a walk as one route. It fails, and says where, at the first hop
// that is not a forward or local decision, or that branches. Branching is ECMP,
// and one route is not proven when several next hops are possible.
// ponytail: ECMP is reported as unknown. Compare alternatives when a fixture needs it.
func chainOf(h *Hop) ([]Step, bool, string) {
	var steps []Step
	for {
		switch {
		case h.Decision.Kind == KindLocal:
			return append(steps, Step{Node: h.Node, VRF: h.VRF, Outcome: OutcomeNone}), true, ""
		case h.Decision.Kind != KindForward:
			return nil, false, nodeLabel(h) + ": " + stopText(h.Decision)
		case len(h.Next) != 1:
			return nil, false, fmt.Sprintf("%s: %d next hops, so no single route is proven", nodeLabel(h), len(h.Next))
		}
		next := &h.Next[0]
		steps = append(steps, Step{Node: h.Node, VRF: h.VRF, Interface: next.Via.Interface, NextHop: next.Via.NextHop, Outcome: next.Via.Outcome})
		h = next
	}
}

func stopText(d Decision) string {
	if d.Reason != "" {
		return d.Reason
	}
	return string(d.Kind)
}

func statesOf(steps []Step) []state {
	out := make([]state, len(steps))
	for i, s := range steps {
		out[i] = state{s.Node, s.VRF}
	}
	return out
}

// isReverse reports whether ret is fwd traversed backward, router by router and
// routing domain by routing domain. A set match is not enough, because the same
// routers can be visited in another order. It does not look at the links between
// routers, which linksOf checks before a reverse route is called symmetric.
func isReverse(fwd, ret []state) bool {
	if len(fwd) != len(ret) {
		return false
	}
	for i := range ret {
		if ret[i] != fwd[len(fwd)-1-i] {
			return false
		}
	}
	return true
}

// endpoint is one end of a link: an interface of one node in one routing domain.
// Interface names mean nothing across nodes, so a link is compared by all three
// fields.
type endpoint struct {
	node, vrf, iface string
}

func (e endpoint) String() string {
	return e.node + " (" + e.vrf + ") " + e.iface
}

// linksOf checks, hop by hop, that the return crosses the forward link. Segment i
// of fwd runs from fwd[i] to fwd[i+1]. Its mirror in ret is segment n-2-i, which
// runs back over the same two routers. differ names the first hop that the
// evidence proves uses another link. unknown names the first hop whose link ends
// the evidence cannot name. A proven difference wins over an unknown hop. Both
// are empty when every hop matches.
// ponytail: a link end is named only by the one interface of the far node that
// holds the next hop, and only when both ends hold the same subnet around it. So a
// next hop held outside the egress subnet, such as a loopback /32, reads as unknown.
// The model records no interface type, so a loopback numbered inside the egress
// subnet still reads as the far end. Neighbor records are not used. Add them as a
// second source when a fixture needs unnumbered links or a loopback in a link subnet.
func (w *walker) linksOf(fwd, ret []Step, src netip.Addr) (differ, unknown string) {
	n := len(fwd)
	for i := 0; i+1 < n; i++ {
		fNear, fFar, fWhy := w.segmentEnds(fwd, i, w.dest)
		rNear, rFar, rWhy := w.segmentEnds(ret, n-2-i, src)
		if fWhy != "" || rWhy != "" {
			unknown = cmp.Or(unknown, "the link between "+fwd[i].Node+" and "+fwd[i+1].Node+" is not proven: "+cmp.Or(fWhy, rWhy))
			continue
		}
		if fNear != rFar || fFar != rNear {
			return fmt.Sprintf("between %s and %s they use different links: forward %s to %s, return %s to %s", fwd[i].Node, fwd[i+1].Node, fNear, fFar, rNear, rFar), ""
		}
	}
	return "", unknown
}

// segmentEnds names both ends of the link that one segment of a route crosses.
// The near end is the egress of steps[i]. The far end is the one interface of
// steps[i+1] that owns the next hop, or owns dest when the egress is on-link, and
// it must hold that address on a subnet the egress also holds. why names the first
// end the evidence cannot name, and it is empty when both are named.
func (w *walker) segmentEnds(steps []Step, i int, dest netip.Addr) (near, far endpoint, why string) {
	s, next := steps[i], steps[i+1]
	if s.Interface == "" {
		return near, far, fmt.Sprintf("%s (%s) does not name the interface it leaves by", s.Node, s.VRF)
	}
	target := dest
	if s.NextHop != "" {
		hop, err := netip.ParseAddr(s.NextHop)
		if err != nil {
			return near, far, fmt.Sprintf("%s (%s) names an unreadable next hop %q", s.Node, s.VRF, s.NextHop)
		}
		target = hop.WithZone("").Unmap()
	}
	near = endpoint{s.Node, s.VRF, s.Interface}
	nearNets := w.subnetsOf(near, target)
	if len(nearNets) == 0 {
		return near, far, fmt.Sprintf("%s holds no prefix containing %s", near, target)
	}
	iface, ok := w.ownerIface(next.Node, next.VRF, target)
	if !ok {
		return near, far, fmt.Sprintf("%s (%s) does not name one interface holding %s", next.Node, next.VRF, target)
	}
	far = endpoint{next.Node, next.VRF, iface}
	farNets := w.subnetsOf(far, target)
	if !slices.ContainsFunc(farNets, func(p netip.Prefix) bool { return slices.Contains(nearNets, p) }) {
		return near, far, fmt.Sprintf("%s holds %s on %s, but %s holds it on %s, so the two ends share no subnet", far, target, prefixList(farNets), near, prefixList(nearNets))
	}
	return near, far, ""
}

// subnetsOf returns the subnets, masked, that interface e.iface of its routing
// domain holds around target, so the interface reaches target directly. Only the
// planes that can own an address count.
func (w *walker) subnetsOf(e endpoint, target netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, o := range w.obs {
		if o.Node != e.node || o.VRF != e.vrf || !slices.Contains(readPlanes, o.Plane) {
			continue
		}
		for _, i := range o.Interfaces {
			if i.Name != e.iface {
				continue
			}
			for _, p := range i.Addresses {
				if p.Contains(target) && !slices.Contains(out, p.Masked()) {
					out = append(out, p.Masked())
				}
			}
		}
	}
	return out
}

// prefixList joins subnets in the order given, for a reason.
func prefixList(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return strings.Join(out, ", ")
}

// ownerIface names the one interface of node in routing domain vrf that holds
// target as its own address. It fails when no interface holds it, and when more
// than one does, because the link to that address is then not named.
func (w *walker) ownerIface(node, vrf string, target netip.Addr) (string, bool) {
	names := w.ownerIfaces(node, vrf, target)
	if len(names) != 1 {
		return "", false
	}
	return names[0], true
}

// ownerIfaces names, in order, every interface of node in routing domain vrf
// that holds target as its own address.
func (w *walker) ownerIfaces(node, vrf string, target netip.Addr) []string {
	var names []string
	for _, o := range w.obs {
		if o.Node != node || o.VRF != vrf || !slices.Contains(readPlanes, o.Plane) {
			continue
		}
		for _, i := range o.Interfaces {
			for _, p := range i.Addresses {
				if p.Addr().WithZone("").Unmap() == target && !slices.Contains(names, i.Name) {
					names = append(names, i.Name)
				}
			}
		}
	}
	slices.Sort(names)
	return names
}

// sameStates reports whether a and b hold the same routers in the same routing
// domains, in any order. It only words the reason for an asymmetry, so the two
// routes are described correctly.
func sameStates(a, b []state) bool {
	return subsetStates(a, b) && subsetStates(b, a)
}

func subsetStates(a, b []state) bool {
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	return true
}

// concernsOf lists what makes an asymmetric pair relevant. A boundary counts
// only when exactly one direction crosses it. A routing-domain difference counts
// when the directions use different VRFs. A recorded failure counts on either
// direction. The bounds arrive sorted, so the output is deterministic.
func concernsOf(bounds []Boundary, fwd, ret []state, fwdRegions, retRegions []FailureRegion) []Concern {
	var out []Concern
	for _, b := range bounds {
		s := state{b.Node, b.VRF}
		inF, inR := slices.Contains(fwd, s), slices.Contains(ret, s)
		if inF == inR {
			continue
		}
		dir := "forward"
		if inR {
			dir = "return"
		}
		out = append(out, Concern{
			Kind:      string(b.Kind),
			Direction: dir,
			Node:      b.Node,
			VRF:       b.VRF,
			Detail:    boundaryDetail(b.Kind, dir, b.Node, b.VRF),
			Evidence:  []Support{{Source: b.Source, CollectedAt: utcText(b.CollectedAt)}},
		})
	}
	if fv, rv := vrfsOf(fwd), vrfsOf(ret); !slices.Equal(fv, rv) {
		out = append(out, Concern{
			Kind:      concernVRF,
			Direction: "both",
			Detail:    "forward route uses routing domains " + strings.Join(fv, ", ") + "; return route uses " + strings.Join(rv, ", ") + ". Policy and state in one routing domain may not apply to the other",
		})
	}
	for _, r := range fwdRegions {
		out = append(out, failureConcern(r, "forward"))
	}
	for _, r := range retRegions {
		out = append(out, failureConcern(r, "return"))
	}
	return out
}

// boundaryDetail names the mechanism that makes a one-sided boundary matter. It
// does not claim the mechanism failed.
func boundaryDetail(k BoundaryKind, dir, node, vrf string) string {
	what := fmt.Sprintf("the %s route crosses %s at %s (%s) and the other direction does not", dir, k, node, vrf)
	switch k {
	case BoundaryStatefulFirewall:
		return what + "; state set on one path may not match traffic on the other"
	case BoundaryNAT:
		return what + "; a translation made on one path may not apply to the other"
	case BoundaryTunnel:
		return what + "; encapsulation and MTU differ between the directions"
	}
	return what
}

func failureConcern(r FailureRegion, dir string) Concern {
	return Concern{
		Kind:      concernFailure,
		Direction: dir,
		Node:      r.Fail.From,
		VRF:       r.Fail.VRF,
		Detail:    "recorded check failed on " + dir + " segment " + segText(r.Fail),
		Evidence:  r.Fail.Checks,
	}
}

// vrfsOf returns the routing domains in ss, sorted and without repeats.
func vrfsOf(ss []state) []string {
	var out []string
	for _, s := range ss {
		if !slices.Contains(out, s.vrf) {
			out = append(out, s.vrf)
		}
	}
	slices.Sort(out)
	return out
}

// stepsText prints a route on one line. The last step, the owner of the
// destination, has no egress, so it reads "local".
func stepsText(steps []Step) string {
	parts := make([]string, len(steps))
	for i, s := range steps {
		parts[i] = s.Node + " (" + s.VRF + ")"
		switch {
		case s.Interface == "":
			parts[i] += " local"
		case s.NextHop != "":
			parts[i] += " " + s.Interface + " via " + s.NextHop
		default:
			parts[i] += " " + s.Interface + " on-link"
		}
	}
	return strings.Join(parts, " -> ")
}

// renderAsymmetry prints the comparison and the return walk under it. Each
// concern names its evidence, so a reader can see why the asymmetry matters.
func renderAsymmetry(line func(string, ...any), a *Asymmetry) {
	line("")
	line("Asymmetry (forward vs return to %s):", a.ReturnTo)
	line("  %s: %s", a.Assessment, a.Reason)
	if a.ForwardRoute != nil {
		line("  forward route: %s", stepsText(a.ForwardRoute))
	}
	if a.ReturnRoute != nil {
		line("  return route: %s", stepsText(a.ReturnRoute))
	}
	for _, c := range a.Concerns {
		line("  concern %s: %s", c.Kind, c.Detail)
	}
	if a.Return == nil {
		return
	}
	line("  return walk:")
	renderTree(line, &a.Return.Forwarding, 2)
	line("  return findings:")
	renderFindings(line, a.Return.Findings, "    ")
	line("  return failure regions:")
	renderRegions(line, a.Return.Regions, "    ")
	line("  return limitations:")
	renderLimitations(line, a.Return.Limitations, "    ")
}
