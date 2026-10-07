package diagnostic

import (
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
)

// TunnelState is how sure netdoc is that the interface a route selected
// encapsulates what leaves through it. It is deliberately three-valued rather
// than a boolean, because "the kernel named this device a tunnel" and "this
// device looks like one" are different claims and only the first one is safe to
// repeat back to a user as fact.
//
// The empty state is not "no tunnel". It is "nobody classified this", which is
// what every platform that cannot see device metadata reports, and what a
// consumer must read as unknown rather than as direct.
type TunnelState string

const (
	// TunnelUnknown is the zero value: the interface was never classified.
	TunnelUnknown TunnelState = ""
	// TunnelDirect is an ordinary interface, including a virtual one the
	// kernel named and that carries no encapsulation of its own: a bridge, a
	// VLAN, a bond.
	TunnelDirect TunnelState = "direct"
	// TunnelLikely is a link with no link layer of its own, or a
	// point-to-point one, on a platform that would not name its kind. Almost
	// every tunnel looks like this, and so does a mobile broadband modem, so
	// it is evidence and never an assertion that a VPN is in use.
	TunnelLikely TunnelState = "likely"
	// TunnelKnown is a device whose kind the operating system itself reports
	// as an encapsulating one. Kind carries which.
	TunnelKnown TunnelState = "tunnel"
)

// Tunneled reports whether this path leaves through something that
// encapsulates it, at either confidence. Callers that need the distinction
// read Tunnel; this is for the questions where "wrapped in something" is the
// whole question, such as whether two paths agree.
func (r RouteDecision) Tunneled() bool { return r.Tunnel == TunnelKnown || r.Tunnel == TunnelLikely }

// RouteReason names why one route was the one selected, in the vocabulary a
// diagnosis can branch on. It is derived from the decision the kernel already
// made plus, where one was taken, the decision for general Internet traffic:
// netdoc never re-runs the kernel's selection algorithm to second-guess it.
//
// It is empty whenever the evidence does not support any of these, which is
// the common case on a platform that reports no matched prefix.
type RouteReason string

const (
	RouteReasonUnknown RouteReason = ""
	// RouteReasonNoRoute is the kernel reporting that nothing leads to this
	// destination at all.
	RouteReasonNoRoute RouteReason = "no_route"
	// RouteReasonDefault is the destination matching the default route. It is
	// reported only where the platform names the entry that matched, because
	// nothing else proves which entry that was.
	RouteReasonDefault RouteReason = "default_route"
	// RouteReasonMoreSpecific is a route narrower than a default route
	// matching this destination, which is the entry-level statement of the
	// split-tunnel case. It too is reported only where the platform names the
	// matched entry: a path that merely differs from the general one does not
	// prove that prefix length is what decided it.
	RouteReasonMoreSpecific RouteReason = "more_specific_than_default"
	// RouteReasonSamePathAsDefault is this destination leaving by the same
	// interface and next hop that general Internet traffic leaves by, and,
	// where the platform names one, out of the same routing table. It says
	// nothing about which entry matched, because a platform that names no
	// prefix cannot tell a default route from a narrower one pointing the same
	// way.
	RouteReasonSamePathAsDefault RouteReason = "same_path_as_default"
	// RouteReasonDiffersFromDefault is this destination leaving by a different
	// interface or next hop than general Internet traffic, or out of a
	// different routing table where the platform names one, with no evidence
	// of what made the kernel choose differently.
	//
	// This is the honest answer where the matched entry is unnamed, and it is
	// deliberately weaker than more_specific_than_default. A policy rule, a
	// separate routing table, a VRF, source-specific routing, and a multipath
	// route picking a different next hop all produce exactly this observation
	// without any narrower prefix being involved: a rule sending one
	// destination to a table whose winning entry is itself a default route
	// looks identical from here. Reading it as longest-prefix matching would
	// be netdoc explaining a kernel decision it did not witness.
	RouteReasonDiffersFromDefault RouteReason = "differs_from_default_path"
	// RouteReasonOnLink is a destination on a directly attached network, with
	// no next hop between here and it.
	RouteReasonOnLink RouteReason = "on_link"
	// RouteReasonHostRoute is a route installed for this single address.
	RouteReasonHostRoute RouteReason = "host_route"
	// RouteReasonMetric is several routes covering the destination equally,
	// settled by preference. Only reported where the platform both exposes
	// metrics and let netdoc see more than one candidate.
	RouteReasonMetric RouteReason = "lower_metric"
)

// CompetingRoute is one route that covered the same destination and lost. It
// exists to explain a decision, not to mirror a routing table: it is recorded
// only where a competitor actually bears on the answer, and never as a dump.
type CompetingRoute struct {
	Iface  string
	Metric int
}

// RouteDecision is one destination's selected path, as the operating system
// reported its own decision.
//
// Every field is what some platform can answer and some cannot. A field the
// platform did not supply keeps its zero value and means "not known here",
// never "zero". That is why Metric has MetricKnown beside it: 0 is a real
// metric on Linux and on Windows, so absence cannot be spelled as 0.
//
// Nothing in this struct is inferred by netdoc from a routing table it read
// itself. The prefix is the prefix the kernel said it matched, the interface
// is the interface the kernel said it chose, and Reason is the only derived
// field, drawn from those plus the decision taken for general Internet traffic.
type RouteDecision struct {
	// Destination is the address the lookup was for, which is the identity of
	// this decision: route intelligence is per address, never per hostname.
	Destination net.IP
	// Family is "ipv4" or "ipv6", the same vocabulary the report already uses
	// for per-family reachability.
	Family string
	Iface  string
	// Gateway is the next hop, nil when the destination is on-link.
	Gateway net.IP
	// Source is the local address the kernel would select for this path.
	Source net.IP
	// Prefix is the route entry that matched. The zero Prefix is unknown, and
	// IsValid tells those apart from ::/0, which is a real answer.
	Prefix netip.Prefix
	// Metric is the selected route's preference, valid only with MetricKnown.
	Metric      int
	MetricKnown bool
	// Table names the routing table or routing domain the decision came from,
	// and is meaningful only with TableKnown. The main table is spelled as the
	// empty string, since a decision from it is the unremarkable case.
	Table string
	// TableKnown is the platform having said which routing table or routing
	// domain resolved this destination. It is what keeps "the kernel told us
	// this came from the main table" apart from "this platform never said",
	// which are the same empty Table and must never compare as equal: only
	// Linux answers this today, and reading Windows' or Darwin's silence as
	// the main table would invent a routing domain neither API reported.
	TableKnown bool
	// MTU is the selected interface's MTU. It is the link's own number and is
	// never a claim about the end-to-end path MTU; the path_mtu probe is the
	// only thing that measures that.
	MTU        int
	Tunnel     TunnelState
	TunnelKind string
	// Unreachable is the kernel answering that there is no route.
	Unreachable bool
	// Reason is why this route won, filled by routeReason.
	Reason RouteReason
	// Competing are the routes that lost, where seeing them is what explains
	// the decision. Usually empty.
	Competing []CompetingRoute
}

// routeFamily is the address family label a decision carries, matching the
// FamilyIPv4/FamilyIPv6 vocabulary the rest of the report uses.
func routeFamily(ip net.IP) string {
	if ip.To4() != nil {
		return counterfactualIPv4
	}
	return counterfactualIPv6
}

// ifaceFacts is what tunnel classification reads. It is gathered per platform
// so that the judgement itself stays one function with one table of cases,
// testable without a network stack of any particular kind.
type ifaceFacts struct {
	Name string
	// Kind is the device kind the operating system itself reports, empty on a
	// platform or a device that names none. This is the field that separates a
	// known tunnel from a guess, and it is why there is no list of product
	// names anywhere in this package.
	Kind         string
	PointToPoint bool
	Loopback     bool
	// NoLinkLayer means the interface has no hardware address. Tunnels
	// normally do not; Ethernet-like devices, TAP included, do.
	NoLinkLayer bool
}

// encapsulatingKinds are the link kinds that wrap traffic in another packet.
// They are operating-system-facing names, not vendor names: every VPN that
// presents a normal tunnel device lands on one of these regardless of who
// shipped it, and a product that installs an ordinary Ethernet device is
// deliberately not detected rather than guessed at from its name.
//
// Most of these are Linux kernel link kinds. "tunnel" is the name Windows
// gives IF_TYPE_TUNNEL, which is the one interface type that means
// encapsulation on its own, so every kind a platform can report here has to be
// present or that platform's tunnels read as direct links.
var encapsulatingKinds = []string{
	"geneve", "gre", "gretap", "ip6gre", "ip6tnl", "ipip", "ppp",
	"sit", "tun", "tunnel", "vti", "vti6", "vxlan", "wireguard", "xfrm",
}

// classifyTunnel decides how much netdoc may claim about one interface.
//
// A kind the operating system reported settles it in both directions: a kind
// that encapsulates is a tunnel, and a kind that does not, such as a bridge or
// a VLAN, is direct even when it is virtual. Only a device the platform would
// not name falls through to shape, and shape can only ever reach "likely",
// because a point-to-point link with no link layer is what a tunnel looks like
// and also what a mobile broadband modem looks like.
func classifyTunnel(f ifaceFacts) (TunnelState, string) {
	switch {
	case f.Name == "":
		return TunnelUnknown, ""
	case f.Loopback:
		return TunnelDirect, ""
	case f.Kind != "":
		if slices.Contains(encapsulatingKinds, f.Kind) {
			return TunnelKnown, f.Kind
		}
		return TunnelDirect, ""
	case f.PointToPoint || f.NoLinkLayer:
		return TunnelLikely, ""
	}
	return TunnelDirect, ""
}

// routeReason explains a selected route against the decision general Internet
// traffic took. reference is the zero value when no such decision was
// available, and then only the reasons that need no comparison are reachable.
//
// It answers from two kinds of evidence, and they are not interchangeable.
// Where the platform names the route entry that matched, that entry settles
// which entry won, and only there may this say a prefix decided anything.
// Where it does not, and Linux does not, all that is left is comparing this
// decision with the one the kernel gave for general Internet traffic, and that
// comparison can only report whether the two paths agree. Both are the
// operating system's own answers; nothing here reads a routing table and
// re-runs the selection to second-guess them, and nothing is reported that
// neither kind of evidence supports.
//
// The ordering matters. A destination with no route has no reason to explain,
// and a host route is a more specific statement than on-link, so those come
// first. A named prefix that beats the default and leaves by a different
// interface is the split-tunnel case, and calling it on-link would lose the
// only interesting part of it; a gatewayless route on the interface general
// traffic already uses is an attached network and is reported as on-link.
// Nothing here claims a metric decided anything unless a competitor was
// actually observed.
func routeReason(r, reference RouteDecision) RouteReason {
	switch {
	case r.Unreachable:
		return RouteReasonNoRoute
	case len(r.Competing) > 0 && r.MetricKnown:
		return RouteReasonMetric
	case r.Prefix.IsValid() && r.Prefix.Bits() == r.Prefix.Addr().BitLen():
		return RouteReasonHostRoute
	case r.Prefix.IsValid() && r.Prefix.Bits() == 0:
		return RouteReasonDefault
	case beatsDefaultElsewhere(r, reference):
		return RouteReasonMoreSpecific
	case r.Iface == "":
		return RouteReasonUnknown
	case r.Gateway == nil:
		return RouteReasonOnLink
	// A named prefix between a default route and a host route is a narrower
	// entry whatever path it points down, including the interface general
	// traffic already uses. The platform said which entry matched, so this is
	// read off the entry rather than off the comparison below.
	case r.Prefix.IsValid():
		return RouteReasonMoreSpecific
	case reference.Iface == "":
		return RouteReasonUnknown
	case samePath(r, reference):
		return RouteReasonSamePathAsDefault
	}
	return RouteReasonDiffersFromDefault
}

// beatsDefaultElsewhere reports the split-tunnel shape as the platforms that
// name the matched entry describe it: general traffic falls through to a
// default route, and this destination is covered by a narrower one that leaves
// by a different interface.
func beatsDefaultElsewhere(r, reference RouteDecision) bool {
	return r.Prefix.IsValid() && r.Prefix.Bits() > 0 &&
		reference.Prefix.IsValid() && reference.Prefix.Bits() == 0 &&
		r.Iface != "" && reference.Iface != "" && r.Iface != reference.Iface
}

// pathAgreement is what comparing one dimension of two selected paths
// established. The zero value is the important one: a dimension neither
// decision can be compared on is not agreement, and treating it as agreement
// is how an unknown routing table comes to read as the main one.
type pathAgreement uint8

const (
	pathNotComparable pathAgreement = iota
	pathSame
	pathDiffers
)

func pathAgreementOf(same bool) pathAgreement {
	if same {
		return pathSame
	}
	return pathDiffers
}

// pathComparison is two route decisions held side by side, dimension by
// dimension, rather than collapsed into one boolean. The dimensions are the
// ones that describe route selection itself, and each is answered separately
// because they are known separately: an operating system that names the
// interface and the next hop may say nothing at all about routing domains, and
// a comparison that folded them together could not tell "the tables agree"
// from "nobody asked".
//
// It is deliberately not every field of a RouteDecision. Tunnel state is a
// property of the interface, so two paths down one interface always share it;
// MTU is the link's, not the route's; the matched prefix and the metric
// explain why one entry won rather than where the packet goes.
type pathComparison struct {
	// Iface is the egress interface, which every platform that answers at all
	// reports.
	Iface pathAgreement
	// NextHop is the router the packet is handed to, where nil is the kernel
	// saying "on-link" rather than saying nothing: all three collectors omit
	// the gateway exactly when the destination is directly attached.
	NextHop pathAgreement
	// Table is the routing table or routing domain that resolved the
	// destination, comparable only where both sides' platform named one.
	Table pathAgreement
	// Source is the local address the kernel would send from. It is recorded
	// because differing source selection is a real observation, and it is
	// deliberately kept out of every verdict below: two addresses on one
	// interface are chosen between by ordinary source-address selection rather
	// than by routing policy, and the three platforms do not even mean the
	// same thing by it, Darwin reporting the interface's address rather than a
	// per-flow choice. It is comparable only within one address family, since
	// the two families never share a source.
	Source pathAgreement
}

// routingDomain is the routing table dimension as a comparison can use it,
// with the tables the kernel consults on its own reading as the ordinary case.
//
// A Linux machine with no policy routing whatsoever still resolves in three
// tables: local for its own addresses, main for everything else, and default.
// A flow that landed in one of those was not sent there by a rule, and reading
// the difference between them as a difference in routing would report one on
// every dual-stack host that talks to itself, since the kernel answers for
// 127.0.0.1 out of main and for ::1 out of local. Only a table outside that
// set is a routing domain that something selected.
//
// The names are the Linux collector's, which is the only one that fills this
// field, and a platform that named no table is still unknown here.
func routingDomain(r RouteDecision) (string, bool) {
	if !r.TableKnown {
		return "", false
	}
	switch r.Table {
	case "", "local", "default":
		return "", true
	}
	return r.Table, true
}

// comparePaths reads two kernel decisions against each other. It answers
// nothing at all where either side is not a decision: an empty interface is
// the zero value a platform netdoc could not ask leaves behind, and comparing
// against it would turn silence into agreement.
func comparePaths(a, b RouteDecision) pathComparison {
	var out pathComparison
	if a.Iface == "" || b.Iface == "" {
		return out
	}
	out.Iface = pathAgreementOf(a.Iface == b.Iface)
	out.NextHop = pathAgreementOf(a.Gateway.Equal(b.Gateway))
	domainA, knownA := routingDomain(a)
	domainB, knownB := routingDomain(b)
	if knownA && knownB {
		out.Table = pathAgreementOf(domainA == domainB)
	}
	if a.Family == b.Family && a.Source != nil && b.Source != nil {
		out.Source = pathAgreementOf(a.Source.Equal(b.Source))
	}
	return out
}

// differs is the question the rest of the package asks: did the kernel make
// materially different route decisions for these two destinations. Three
// dimensions answer it, and each one alone is enough, because each is the
// kernel sending the two flows somewhere different: out of another interface,
// to another router, or through another routing domain.
//
// The second return is whether there was anything to compare, and it stays
// false rather than reporting agreement when there was not.
func (c pathComparison) differs() (bool, bool) {
	if c.Iface == pathNotComparable {
		return false, false
	}
	return c.Iface == pathDiffers || c.NextHop == pathDiffers || c.Table == pathDiffers, true
}

// familyDiffers is the same question asked across two address families, where
// only the family-neutral dimensions can be asked. Every dual-stack host uses
// a different next hop and a different source for IPv4 than for IPv6, so
// reading either as a split would report one on every machine that has both.
// A routing domain is not family-scoped in that way, and comparing it is what
// lets one family routed through a policy table be seen even where the
// interface names agree.
func (c pathComparison) familyDiffers() (bool, bool) {
	if c.Iface == pathNotComparable {
		return false, false
	}
	return c.Iface == pathDiffers || c.Table == pathDiffers, true
}

// samePath reports that two decisions took the same way out, which is as much
// as a platform that names no matched entry can say about two destinations.
func samePath(a, b RouteDecision) bool {
	differs, known := comparePaths(a, b).differs()
	return known && !differs
}

// routeCache memoizes the operating system's route answers for the length of
// one diagnostic pass. Several probes ask about the same destination, and a
// kernel lookup repeated inside one pass cannot honestly report two different
// networks.
//
// It is created per BuildProbesFromSources call, which is once per pass, so
// Watch Mode gets a fresh cache every time and a route that really changes
// between passes is seen as a change rather than served from here.
//
// It also carries the pass's source binding, because the route netdoc reports
// has to be the route netdoc's own traffic took. Under --iface every dial in
// the pass leaves from a chosen local address, and on the platforms whose
// route API accepts a source, asking without one describes a flow the run
// never made: a rule selecting on source address would send the real
// connection somewhere else entirely. The binding is fixed for the pass, so it
// lives here rather than in the cache key.
type routeCache struct {
	lookup  func(dst, source net.IP) (RouteDecision, bool)
	sources *SourceAddresses
	// scoped names the zone a destination is dialed with, which a lookup for
	// it has to carry too, and lookupZone is the lookup that can. The zone is
	// part of the cache key, so a scoped answer never serves an unscoped
	// question for the same address, or the other way around.
	scoped     func(net.IP) string
	lookupZone func(dst, source net.IP, zone string) (RouteDecision, bool)
	mu         sync.Mutex
	// answers holds a pointer so that "the platform could not answer" is
	// cached as nil rather than retried by every later probe.
	answers map[string]*RouteDecision
	// reference is the pass's yardstick, computed once because three probe
	// rows read it and it costs a second look at the default routes.
	referenceOnce sync.Once
	reference     []RouteDecision
}

func newRouteCache(lookup func(dst, source net.IP) (RouteDecision, bool), sources *SourceAddresses) *routeCache {
	return &routeCache{lookup: lookup, sources: sources, answers: map[string]*RouteDecision{}}
}

// sourceFor is the local address this pass's probes dial a destination of this
// family from, and nil when the run binds nothing and lets the kernel choose.
func (c *routeCache) sourceFor(dst net.IP) net.IP {
	if c.sources == nil {
		return nil
	}
	if dst.To4() != nil {
		return c.sources.IPv4
	}
	return c.sources.IPv6
}

func (c *routeCache) get(dst net.IP) (RouteDecision, bool) {
	if c == nil || c.lookup == nil || dst == nil {
		return RouteDecision{}, false
	}
	key, zone := dst.String(), ""
	if c.scoped != nil {
		zone = c.scoped(dst)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if zone != "" {
		key += "%" + zone
	}
	if cached, seen := c.answers[key]; seen {
		if cached == nil {
			return RouteDecision{}, false
		}
		return *cached, true
	}
	var decision RouteDecision
	var ok bool
	switch {
	case zone == "":
		decision, ok = c.lookup(dst, c.sourceFor(dst))
	case c.lookupZone != nil:
		decision, ok = c.lookupZone(dst, c.sourceFor(dst), zone)
	}
	if !ok {
		c.answers[key] = nil
		return RouteDecision{}, false
	}
	decision.Destination = append(net.IP(nil), dst...)
	decision.Family = routeFamily(dst)
	c.answers[key] = &decision
	return decision, true
}

// maxRouteLookups bounds what one probe row may ask the kernel, so a hostname
// with a long answer cannot turn route intelligence into a scan. It matches
// maxAttempts, since a destination netdoc will not dial is one whose path it
// has no observation to correlate.
const maxRouteLookups = maxAttempts

// routeDecisions looks up a bounded, deduplicated list of destinations and
// returns only the answers the platform actually gave. The order follows the
// destinations as passed, so a row's routes read in the order the probe cared
// about them.
func (o *netops) routeDecisions(dsts ...net.IP) []RouteDecision {
	if o.routes == nil {
		return nil
	}
	var out []RouteDecision
	seen := map[string]bool{}
	for _, dst := range dsts {
		if dst == nil || len(out) >= maxRouteLookups {
			continue
		}
		key := dst.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if decision, ok := o.routes.get(dst); ok {
			out = append(out, decision)
		}
	}
	return out
}

// referenceRouteDecisions are the paths general Internet traffic takes, one
// per address family. They are the yardstick every other decision in the run
// is read against: without them "the target uses a tunnel" is a fact about one
// machine's interface list, and with them it is a statement about how this
// destination differs from everything else.
//
// The endpoints are the ones the direct-egress probe already dials, so the
// route being described is a route the run also exercised.
func (o *netops) referenceRouteDecisions() []RouteDecision {
	if o.routes == nil {
		return nil
	}
	o.routes.referenceOnce.Do(func() { o.routes.reference = o.collectReferenceRoutes() })
	return o.routes.reference
}

func (o *netops) collectReferenceRoutes() []RouteDecision {
	var dsts []net.IP
	if len(o.compatibleSourceIPs(internetEndpoints4)) > 0 {
		dsts = append(dsts, internetEndpoints4[0])
	}
	if len(o.compatibleSourceIPs(internetEndpoints6)) > 0 {
		dsts = append(dsts, internetEndpoints6[0])
	}
	out := o.routeDecisions(dsts...)
	for i := range out {
		out[i].Competing = o.competingDefaults(out[i])
		out[i].Reason = routeReason(out[i], RouteDecision{})
	}
	return out
}

// competingDefaults names the other default routes of this family when the
// decision fell through to one, and there is more than one to choose between.
// It reuses the per-platform default-route reading the failed-egress
// classification already does, so no second view of the routing table exists.
//
// It stays silent unless a competitor is genuinely there: one default route is
// not a competition, and a platform that reports no metrics cannot say which
// of several would win, so it names none.
//
// The prefix gate is what keeps this honest, and it is stricter than it looks.
// Naming losers only makes sense once the winner is known to be a default
// route, which means only where the platform named the matched entry, and the
// per-platform default-route readings behind it see one view of the tables at
// best: Linux reads the main table for IPv4 and no policy rules at all, so a
// route in a table a rule selected is not among these. What comes out is a
// short list of other default routes that were available, never an enumeration
// of every route that could have covered the destination.
func (o *netops) competingDefaults(selected RouteDecision) []CompetingRoute {
	if o.defaultRoutes == nil || !selected.Prefix.IsValid() || selected.Prefix.Bits() != 0 || !selected.MetricKnown {
		return nil
	}
	routes := o.defaultRoutes(selected.Family)
	var out []CompetingRoute
	for _, r := range routes {
		if r.iface == selected.Iface && r.metric == selected.Metric {
			continue
		}
		out = append(out, CompetingRoute{Iface: r.iface, Metric: r.metric})
	}
	if len(out) == 0 {
		return nil
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Metric != out[j].Metric {
			return out[i].Metric < out[j].Metric
		}
		return out[i].Iface < out[j].Iface
	})
	if len(out) > maxCompetingRoutes {
		out = out[:maxCompetingRoutes]
	}
	return out
}

// maxCompetingRoutes bounds the losers recorded beside a decision. A handful
// explains a choice; a full table is the routing dump this deliberately is not.
const maxCompetingRoutes = 4

// explainedRouteDecisions looks up destinations and fills each one's Reason
// against the run's reference path for that family.
func (o *netops) explainedRouteDecisions(reference []RouteDecision, dsts ...net.IP) []RouteDecision {
	out := o.routeDecisions(dsts...)
	for i := range out {
		out[i].Reason = routeReason(out[i], routeByFamily(reference, out[i].Family))
	}
	return out
}

// routeByFamily picks the decision for one address family out of a list, and
// reports the zero decision when the list holds none. The zero value is safe
// to read: every consumer treats an invalid prefix and an empty interface as
// unknown.
func routeByFamily(routes []RouteDecision, family string) RouteDecision {
	for _, r := range routes {
		if r.Family == family {
			return r
		}
	}
	return RouteDecision{}
}

// routeFor finds the decision for one exact destination.
func routeFor(routes []RouteDecision, dst net.IP) (RouteDecision, bool) {
	for _, r := range routes {
		if r.Destination.Equal(dst) {
			return r, true
		}
	}
	return RouteDecision{}, false
}

// selectedTargetRoute is the path the target connection actually took, which
// is the route for the address the probe selected. It falls back to the first
// recorded target route so a run where every address failed still has a path
// to talk about, since the kernel chose one regardless of the outcome.
func selectedTargetRoute(res map[ProbeID]ProbeResult) (RouteDecision, bool) {
	r := res[ProbeTargetTCP]
	if len(r.Routes) == 0 {
		return RouteDecision{}, false
	}
	if r.SelectedIP != nil {
		if decision, ok := routeFor(r.Routes, r.SelectedIP); ok {
			return decision, true
		}
	}
	return r.Routes[0], true
}

// pathsDiffer reports whether two selected paths leave this machine
// differently, and says nothing when either path is unknown.
//
// Tunnel state is deliberately not one of the dimensions: the two paths are
// classified by the same table on the same host, so one interface name has one
// state, and comparing states where the names already match could only ever
// answer "no".
func pathsDiffer(a, b RouteDecision) (bool, bool) { return comparePaths(a, b).differs() }

// splitTunnelState says how the target's path relates to the path general
// traffic takes, in a vocabulary a diagnosis and a comparison can share.
// Empty means the two paths agree, or that there was not enough to compare.
func splitTunnelState(target, reference RouteDecision) string {
	if target.Iface == "" || reference.Iface == "" ||
		target.Tunnel == TunnelUnknown || reference.Tunnel == TunnelUnknown {
		return ""
	}
	switch {
	case target.Tunneled() && !reference.Tunneled():
		return SplitTargetTunneled
	case !target.Tunneled() && reference.Tunneled():
		return SplitTargetBypassesTunnel
	}
	return ""
}

// The split-routing vocabulary. These are observations about how two paths
// differ, never verdicts: a machine on a split tunnel is working as designed
// far more often than it is broken.
const (
	SplitTargetTunneled       = "target_tunneled"
	SplitTargetBypassesTunnel = "target_bypasses_tunnel"
)

// familyPathsDiffer reports whether the target's IPv4 and IPv6 addresses take
// materially different routes. It needs a decision in both families to say
// anything, which a single-stack host never has.
func familyPathsDiffer(routes []RouteDecision) (bool, bool) {
	v4, v6 := routeByFamily(routes, counterfactualIPv4), routeByFamily(routes, counterfactualIPv6)
	return comparePaths(v4, v6).familyDiffers()
}

// narrowerPathMTU reports the target path's interface MTU when it is smaller
// than the one general traffic leaves through, which is the shape an
// encapsulated path has. It is interface MTU on both sides and nothing else:
// this never claims to be the end-to-end path MTU, which only the path_mtu
// probe measures.
func narrowerPathMTU(target, reference RouteDecision) (int, bool) {
	if target.MTU <= 0 || reference.MTU <= 0 || target.MTU >= reference.MTU {
		return 0, false
	}
	return target.MTU, true
}

// Summary renders one decision as the single line a details panel can show.
// It is display text; nothing parses it back, and the structured fields above
// are what the snapshot and the JSON report carry.
func (r RouteDecision) Summary() string {
	if r.Unreachable {
		return "no route"
	}
	parts := []string{}
	if r.Prefix.IsValid() {
		parts = append(parts, r.Prefix.String())
	}
	if r.Iface != "" {
		parts = append(parts, "dev "+r.Iface)
	}
	if r.Gateway != nil {
		parts = append(parts, "via "+r.Gateway.String())
	}
	// The routing domain, only where a rule selected one. The tables the
	// kernel consults by itself are the unremarkable case, and printing one on
	// every row would be noise.
	if domain, _ := routingDomain(r); domain != "" {
		parts = append(parts, domain)
	}
	if r.Tunneled() {
		kind := r.TunnelKind
		if kind == "" {
			kind = "tunnel"
		}
		parts = append(parts, "("+kind+")")
	}
	return strings.Join(parts, " ")
}

// resolverIP reads the address out of one resolver Dial target and returns nil
// for anything that is not one. The Go resolver already supplies a numeric
// address, but it is parsed rather than trusted: nil simply means no path is
// recorded for this target.
//
// A loopback resolver is deliberately one of those cases. A local stub, which
// is what 127.0.0.53 and friends are on most Linux desktops, is reached over
// lo by definition, and lo is not the interface application traffic uses. The
// path to the stub is therefore always different and never means what "the
// resolver is reached over another interface" is supposed to mean: the stub's
// own upstream path is the interesting one and netdoc cannot see it. Recording
// no resolver path is the honest answer, and the row still names the target it
// tried.
func resolverIP(server string) net.IP {
	if server == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(server)
	ip := net.ParseIP(host)
	if err != nil {
		ip = net.ParseIP(server)
	}
	if ip == nil || ip.IsLoopback() {
		return nil
	}
	return ip
}
