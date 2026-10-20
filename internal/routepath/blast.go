package routepath

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// maxBlastSources bounds how many sources one blast run simulates. Each source
// costs one whole single-source simulation, so the run's work is at most this
// many times maxSimStates node visits. Sources past it, in canonical order, are
// not simulated, and the run says how many.
// ponytail: a source count cap, not one shared visit budget. A shared budget
// would make a source's ratings depend on the sources simulated before it, so
// it could not match its single-source run. Page the sources if larger runs are needed.
const maxBlastSources = 64

// blastScope is the boundary every blast output states. It is the single-source
// boundary, applied to each source, and it says where owners come from.
const blastScope = "Recorded FIB only: every source is simulated over the recorded forwarding table, and no route is recomputed. Owners come only from recorded interface rows. Convergence is not predicted."

// Blast is one failure simulated from several sources. Each entry of Sources is
// the single-source Simulation of that source, so its ratings, and the bounds on
// its destinations and node visits, are the ones that run gives. Only the listed
// walks are shared. They are listed in canonical source order, as one simulation
// lists its own, until the walks listed so far hold maxStates hops. So the shared
// listing can pass maxStates by one walk, as one simulation's can. A walk past
// that point is omitted, and Truncated says so.
type Blast struct {
	Failure   Failure      `json:"failure"`
	Scope     string       `json:"scope"`
	Summary   Summary      `json:"summary"`
	Truncated bool         `json:"truncated"`
	Skipped   int          `json:"skipped"`
	Excluded  []Excluded   `json:"excluded"`
	Sources   []Simulation `json:"sources"`
}

// Excluded is a source that the run does not simulate, and why.
type Excluded struct {
	Source Start  `json:"source"`
	Reason string `json:"reason"`
}

// Summary groups the affected ratings by owner. A rating is one source's verdict
// on one destination, so a destination rated from two sources is two ratings.
// A node group counts a rating once, even when two routing domains of that node
// hold the destination. A routing domain group, a VRF on a node, counts it once
// for each domain that holds it. A rating whose destination no modeled node holds
// counts only as unowned. Owners are the recorded interface rows on the read
// planes, so no topology is inferred. Unchanged sums the unchanged destinations
// of every source.
type Summary struct {
	Unchanged int           `json:"unchanged"`
	Ratings   Counts        `json:"ratings"`
	Unowned   Counts        `json:"unowned"`
	Nodes     []NodeGroup   `json:"nodes"`
	Domains   []DomainGroup `json:"domains"`
}

// Counts is a number of affected ratings for each impact. Unchanged ratings are
// not affected, so they are not counted here.
type Counts struct {
	ReachabilityLost int `json:"reachability_lost"`
	RedundancyLost   int `json:"redundancy_lost"`
	Unknown          int `json:"unknown"`
}

// NodeGroup is a modeled node that owns an affected destination.
type NodeGroup struct {
	Node   string `json:"node"`
	Counts Counts `json:"counts"`
}

// DomainGroup is a routing domain, a VRF on a node, that owns an affected
// destination.
type DomainGroup struct {
	Node   string `json:"node"`
	VRF    string `json:"vrf"`
	Counts Counts `json:"counts"`
}

// ModeledSources lists every routing domain that the recorded control,
// configured, or FIB evidence names, in canonical order. These are the sources
// that a blast run takes when it takes all of them.
func ModeledSources(f File) []Start {
	var out []Start
	for _, o := range f.Model.Observations() {
		s := Start{Node: o.Node, VRF: o.VRF}
		if slices.Contains(readPlanes, o.Plane) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, compareStarts)
	return out
}

// ResolveSource names one modeled routing domain as a source. An empty vrf is
// accepted only when the node is modeled in one routing domain, the same
// condition the failure selectors apply.
func ResolveSource(f File, node, vrf string) (Start, error) {
	var vrfs []string
	for _, s := range ModeledSources(f) {
		if s.Node == node && (vrf == "" || s.VRF == vrf) {
			vrfs = append(vrfs, s.VRF)
		}
	}
	switch {
	case len(vrfs) == 0 && vrf != "":
		return Start{}, fmt.Errorf("no modeled routing domain %q on node %q", vrf, node)
	case len(vrfs) == 0:
		return Start{}, fmt.Errorf("no modeled node %q", node)
	case len(vrfs) > 1:
		return Start{}, fmt.Errorf("node %q is modeled in routing domains %s; name one as %s@VRF", node, strings.Join(vrfs, ", "), node)
	}
	return Start{Node: node, VRF: vrfs[0]}, nil
}

// SimulateBlast simulates fail from each source and groups the affected ratings
// by owner. With all, the sources are every modeled routing domain. A domain on
// the failed router is then excluded and listed, since nothing leaves a failed
// source. Otherwise the named sources are simulated, and naming the failed
// router is refused, as Simulate refuses it, before the source cap applies, so
// a refused source past the cap is not skipped. Each source runs Simulate unchanged,
// so its ratings and every bound on its destinations and node visits are its own.
// The run's work is therefore up to maxBlastSources simulations, and the source
// count is the only bound the run adds.
func SimulateBlast(f File, fail Failure, all bool, named []Start, extra ...netip.Addr) (Blast, error) {
	sources := named
	if all {
		sources = ModeledSources(f)
	}
	sources = slices.Clone(sources)
	slices.SortFunc(sources, compareStarts)
	sources = slices.Compact(sources)
	if len(sources) == 0 {
		return Blast{}, errors.New("the file models no routing domain to simulate from")
	}
	b := Blast{Scope: blastScope, Excluded: []Excluded{}, Sources: []Simulation{}}
	var rated []Start
	for _, s := range sources {
		if removesSource(fail, s) {
			reason := "router " + s.Node + " is the source; nothing leaves a failed source"
			if !all {
				return Blast{}, errors.New(reason)
			}
			b.Excluded = append(b.Excluded, Excluded{Source: s, Reason: reason})
			continue
		}
		rated = append(rated, s)
	}
	if len(rated) > maxBlastSources {
		b.Skipped = len(rated) - maxBlastSources
		rated = rated[:maxBlastSources]
	}
	for _, s := range rated {
		g := f
		g.Source = s
		sim, err := Simulate(g, fail, extra...)
		if err != nil {
			return Blast{}, err
		}
		b.Sources = append(b.Sources, sim)
	}
	b.Failure = fail
	if len(b.Sources) > 0 {
		b.Failure = b.Sources[0].Failure
	}
	shareWalks(b.Sources)
	b.Summary = summarize(b.Sources)
	b.Truncated = b.Skipped > 0
	for _, s := range b.Sources {
		b.Truncated = b.Truncated || s.Truncated
	}
	return b, nil
}

// removesSource says the failure is a router failure on the node of s. Simulate
// refuses that failure when s is the source, and no other failure names a node
// that its own source cannot use, so this is the one case the blast excludes.
func removesSource(fail Failure, s Start) bool {
	return fail.Node != "" && fail.Node == s.Node && fail.Interface == "" &&
		fail.OSPFNeighbor == "" && fail.NextHop == "" && fail.VRF == ""
}

// shareWalks lists the walks of all sources in order, as one simulation lists its
// own: a walk is listed while the walks listed before it hold fewer than maxStates
// hops, so the total can pass maxStates by one walk. A walk past that point is
// omitted, and its simulation is truncated. A walk that its own simulation
// already omitted costs nothing here.
func shareWalks(sims []Simulation) {
	shown := 0
	for i := range sims {
		for j := range sims[i].Affected {
			a := &sims[i].Affected[j]
			if a.After == nil {
				continue
			}
			if shown >= maxStates {
				a.After, sims[i].Truncated = nil, true
				continue
			}
			walkHops(a.After, func(*Hop) { shown++ })
		}
	}
}

// summarize groups the affected ratings of every source by owner, as Summary
// describes it.
func summarize(sims []Simulation) Summary {
	sum := Summary{Nodes: []NodeGroup{}, Domains: []DomainGroup{}}
	nodes := map[string]Counts{}
	domains := map[Start]Counts{}
	for _, s := range sims {
		sum.Unchanged += s.Unchanged
		for _, a := range s.Affected {
			sum.Ratings.add(a.Impact)
			if len(a.Owners) == 0 {
				sum.Unowned.add(a.Impact)
			}
			var counted []string
			for _, o := range a.Owners {
				dc := domains[o]
				dc.add(a.Impact)
				domains[o] = dc
				if !slices.Contains(counted, o.Node) {
					counted = append(counted, o.Node)
					nc := nodes[o.Node]
					nc.add(a.Impact)
					nodes[o.Node] = nc
				}
			}
		}
	}
	for node, c := range nodes {
		sum.Nodes = append(sum.Nodes, NodeGroup{Node: node, Counts: c})
	}
	slices.SortFunc(sum.Nodes, func(a, b NodeGroup) int { return cmp.Compare(a.Node, b.Node) })
	for d, c := range domains {
		sum.Domains = append(sum.Domains, DomainGroup{Node: d.Node, VRF: d.VRF, Counts: c})
	}
	slices.SortFunc(sum.Domains, func(a, b DomainGroup) int {
		return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.VRF, b.VRF))
	})
	return sum
}

// add counts one affected rating. Affected holds no ImpactNone rating, so that
// impact is not counted.
func (c *Counts) add(i Impact) {
	switch i {
	case ImpactReachabilityLost:
		c.ReachabilityLost++
	case ImpactRedundancyLost:
		c.RedundancyLost++
	case ImpactUnknown:
		c.Unknown++
	}
}

func (c Counts) total() int { return c.ReachabilityLost + c.RedundancyLost + c.Unknown }

// count writes n with the noun for one or for any other number, so the summary
// reads "1 source" and "2 sources".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func compareStarts(a, b Start) int {
	return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.VRF, b.VRF))
}

// Text renders the blast run for a person. Every line passes through
// textsafe.Clean, because names come from the file. Each source's own report
// follows as its single-source run writes it, except that a walk the shared
// listing omits reads as omitted.
func (b Blast) Text() string {
	var out strings.Builder
	line := func(format string, args ...any) {
		out.WriteString(textsafe.Clean(fmt.Sprintf(format, args...)))
		out.WriteByte('\n')
	}
	s := b.Summary
	var nodes, domains []string
	for _, n := range s.Nodes {
		nodes = append(nodes, n.Node)
	}
	for _, d := range s.Domains {
		domains = append(domains, d.Node+" ("+d.VRF+")")
	}
	line("")
	line("Failure simulation across %s: %s", count(len(b.Sources), "source", "sources"), b.Failure)
	line("%s", blastScope)
	line("Blast radius: %s, %s, %s (reachability_lost %d, redundancy_lost %d, unknown %d), %d unowned, %d unchanged.",
		count(len(s.Nodes), "affected node", "affected nodes"),
		count(len(s.Domains), "affected routing domain", "affected routing domains"),
		count(s.Ratings.total(), "affected rating", "affected ratings"),
		s.Ratings.ReachabilityLost, s.Ratings.RedundancyLost, s.Ratings.Unknown, s.Unowned.total(), s.Unchanged)
	line("Affected nodes: %s.", cmp.Or(strings.Join(nodes, ", "), "none"))
	line("Affected routing domains: %s.", cmp.Or(strings.Join(domains, ", "), "none"))
	for _, e := range b.Excluded {
		line("Excluded source %s (%s): %s.", e.Source.Node, e.Source.VRF, e.Reason)
	}
	if b.Skipped > 0 {
		line("The run simulates at most %d sources; %d more were not simulated.", maxBlastSources, b.Skipped)
	}
	for _, sim := range b.Sources {
		out.WriteString(sim.Text())
	}
	return out.String()
}
