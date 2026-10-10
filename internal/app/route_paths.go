package app

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/routepath"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// routeFiles names the optional topology file for each side of an offline
// two-sided reading. An empty name means that side has no route context.
type routeFiles struct{ a, b string }

// routeWindow bounds how far any topology row's collected_at may sit from the
// side's own capture. A row outside it may describe a different network, so the
// file does not bind to that side.
const routeWindow = 24 * time.Hour

// routePaths binds each named topology file to its side and explains that
// side's target. It returns nil when no file was named, so the reading is
// unchanged. Every error here is unusable input, not a finding.
func routePaths(files routeFiles, snapshots [2]snapshot.Snapshot) ([]compare.RoutePath, error) {
	if files.a != "" && (files.a == files.b || sameFile(files.a, files.b)) {
		return nil, fmt.Errorf("-route-a and -route-b name the same topology file; one file describes one vantage point")
	}
	var out []compare.RoutePath
	for i, named := range []struct{ side, path string }{{"a", files.a}, {"b", files.b}} {
		if named.path == "" {
			continue
		}
		data, err := readTopologyFile(named.path)
		if err != nil {
			return nil, fmt.Errorf("-route-%s: %w", named.side, err)
		}
		f, err := routepath.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("-route-%s: %s: %w", named.side, named.path, err)
		}
		bound, err := bindRoute(named.side, snapshots[i], f)
		if err != nil {
			return nil, err
		}
		out = append(out, bound)
	}
	return out, nil
}

// sameFile reports whether two names reach one file, through a hard link or a
// symbolic link, so one vantage point cannot be given two route files. A name that
// does not stat is not the same file as anything.
func sameFile(a, b string) bool {
	sa, errA := os.Stat(a)
	sb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(sa, sb)
}

// bindRoute ties one topology file to one side, or says why it does not. The
// destination and source come only from that side's own recorded artifact, so
// the file is checked against that one flow and never against the other side.
func bindRoute(side string, s snapshot.Snapshot, f routepath.File) (compare.RoutePath, error) {
	dest, src, reason := bindingOf(s, f)
	if reason != "" {
		return compare.RoutePath{Side: side, Status: compare.RouteUnbound, Reason: reason}, nil
	}
	e := routepath.Explain(f, dest)
	// Drift asks whether the configured intent matches the FIB. That is a question
	// about the network's configuration, not about this flow, so the two-sided
	// context leaves it out.
	e.Drift = nil
	hop := firstHopCheck(s, dest, e.Forwarding.Decision)
	if hop.verdict != compare.FirstHopAgrees {
		return compare.RoutePath{Side: side, Status: compare.RouteUnbound, Reason: hop.reason, FirstHop: hop.verdict}, nil
	}
	raw, err := e.JSON()
	if err != nil {
		return compare.RoutePath{}, err
	}
	return compare.RoutePath{
		Side: side, Status: compare.RouteBound, Destination: dest.String(), Source: src.String(),
		Basis: compare.BoundRouteBasis(), FirstHop: hop.verdict, Compared: hop.compared,
		NotCompared: hop.notCompared, Explanation: raw, Text: e.Text(),
	}, nil
}

// firstHop is the forwarding comparison between one side and the topology.
type firstHop struct {
	verdict     string
	reason      string
	compared    []string
	notCompared []string
}

// firstHopCheck compares what this side recorded for dest with the topology's
// forwarding decision at its source. A field is compared only when both sides
// record it, and a recorded field that disagrees is a conflict. Agreement needs
// the next hop, because a matching prefix alone does not show where traffic goes.
// Missing or ambiguous evidence is not comparable, and it is never agreement.
func firstHopCheck(s snapshot.Snapshot, dest netip.Addr, d routepath.Decision) firstHop {
	conflict := func(format string, args ...any) firstHop {
		return firstHop{verdict: compare.FirstHopConflicts, reason: fmt.Sprintf(format, args...)}
	}
	unknown := func(reason string) firstHop {
		return firstHop{verdict: compare.FirstHopNotComparable, reason: reason}
	}
	rt, n := recordedRoute(s, dest)
	switch {
	case n == 0:
		return unknown("This side recorded no route for the target, so its next hop cannot be compared.")
	case n > 1:
		return unknown("This side recorded several routes for the target, so no single next hop was selected.")
	case d.Kind != routepath.KindForward:
		return unknown("The topology's forwarding decision for the target is " + string(d.Kind) + ", so it names no next hop to compare.")
	case rt.Unreachable:
		return conflict("This side's kernel recorded no route for the target, but the topology forwards it.")
	case rt.Gateway == "":
		if rt.Reason == string(diagnostic.RouteReasonOnLink) && anyAddressedHop(d) {
			return conflict("This side's route is on link, but the topology forwards the target through a next hop.")
		}
		return unknown("This side recorded no next hop for the target's route, so its next hop cannot be compared.")
	}
	got, err := netip.ParseAddr(rt.Gateway)
	if err != nil {
		return unknown("This side's next hop is not readable.")
	}
	got = normalAddr(got)
	if got.Is6() && got.IsLinkLocalUnicast() {
		return unknown("This side's next hop is an IPv6 link-local address, which names no neighbor without its interface.")
	}
	var want []netip.Addr
	interfaceOnly := false
	for _, nh := range d.NextHops {
		if nh.Addr == "" {
			interfaceOnly = true
			continue
		}
		a, err := netip.ParseAddr(nh.Addr)
		if err != nil {
			return unknown("The topology's next hop is not readable.")
		}
		want = append(want, normalAddr(a))
	}
	if !slices.Contains(want, got) {
		if interfaceOnly || len(want) == 0 {
			return unknown("The topology's next hop has no address to compare with this side's next hop.")
		}
		return conflict("This side's next hop %s is not among the topology's next hops for the target (%s).", got, joinAddrs(want))
	}
	compared := []string{"source", "next_hop"}
	var notCompared []string
	if rt.Prefix == "" {
		notCompared = append(notCompared, "prefix")
	} else {
		gotP, err := netip.ParsePrefix(rt.Prefix)
		if err != nil {
			return unknown("This side's matched prefix is not readable.")
		}
		wantP, err := netip.ParsePrefix(d.Prefix)
		if err != nil {
			return unknown("The topology's matched prefix is not readable.")
		}
		if gotP.Masked() != wantP.Masked() {
			return conflict("This side matched %s, but the topology's forwarding table matches %s for the target.", gotP.Masked(), wantP.Masked())
		}
		compared = append(compared, "prefix")
	}
	if rt.TableKnown {
		compared = append(compared, "routing_table")
	} else {
		notCompared = append(notCompared, "routing_table")
	}
	return firstHop{
		verdict: compare.FirstHopAgrees, compared: compared,
		notCompared: append([]string{"interface"}, notCompared...),
	}
}

// recordedRoute returns the one route this side recorded for dest, and how many
// distinct routes it recorded. A route that several checks repeat counts once.
func recordedRoute(s snapshot.Snapshot, dest netip.Addr) (snapshot.Route, int) {
	var out []snapshot.Route
	seen := map[string]bool{}
	for _, c := range s.Checks {
		if c.Observed == nil {
			continue
		}
		for _, r := range c.Observed.Routes {
			if !sameAddr(r.Destination, dest) {
				continue
			}
			key := strings.Join([]string{r.Gateway, r.Prefix, strconv.FormatBool(r.Unreachable), r.Reason}, "|")
			if !seen[key] {
				seen[key] = true
				out = append(out, r)
			}
		}
	}
	if len(out) == 0 {
		return snapshot.Route{}, 0
	}
	return out[0], len(out)
}

// anyAddressedHop reports whether the decision names at least one next hop by address.
func anyAddressedHop(d routepath.Decision) bool {
	for _, nh := range d.NextHops {
		if nh.Addr != "" {
			return true
		}
	}
	return false
}

// joinAddrs spells addresses for a reason, in the order the topology gave them.
func joinAddrs(addrs []netip.Addr) string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return strings.Join(out, ", ")
}

// bindingOf reads the destination this side targeted and checks the file
// against the source address this side recorded for it. It returns a reason for
// the first gap, conflict, or stale row, and never a guess.
func bindingOf(s snapshot.Snapshot, f routepath.File) (netip.Addr, netip.Addr, string) {
	switch {
	case s.Redaction != nil:
		return netip.Addr{}, netip.Addr{}, "A sanitized support artifact: its addresses are pseudonyms, which cannot be tied to a topology"
	case s.Target == nil:
		return netip.Addr{}, netip.Addr{}, "A generic run has no target address to explain a route to"
	case s.Target.IP == "":
		return netip.Addr{}, netip.Addr{}, "The target is a name, which resolves on each machine, so no single destination address is bound"
	}
	dest, err := netip.ParseAddr(s.Target.IP)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "The target address is not readable"
	}
	dest = normalAddr(dest)
	// A link-local address is meaningful only through the interface it was reached
	// by, and the parser keeps that interface out of Target.IP. No topology row names it.
	if dest.Is6() && (dest.IsLinkLocalUnicast() || dest.IsLinkLocalMulticast()) {
		return netip.Addr{}, netip.Addr{}, "The target is an IPv6 link-local address, which needs an interface the topology cannot name"
	}
	if !f.SourceAddr.IsValid() {
		return netip.Addr{}, netip.Addr{}, "The topology names no source.address, so it cannot be tied to this side"
	}
	src := normalAddr(f.SourceAddr)
	switch {
	case f.SourceAddr.Zone() != "":
		return netip.Addr{}, netip.Addr{}, "The topology's source.address carries an interface zone"
	case dest.Is4() != src.Is4():
		return netip.Addr{}, netip.Addr{}, "The target and source.address are different address families"
	}
	recorded := recordedSources(s, dest)
	switch {
	case len(recorded) == 0:
		return netip.Addr{}, netip.Addr{}, "This side recorded no source address for the target"
	case len(recorded) > 1:
		return netip.Addr{}, netip.Addr{}, "This side recorded several source addresses for the target"
	case recorded[0] != src:
		return netip.Addr{}, netip.Addr{}, "The topology's source.address is not the source this side recorded for the target"
	}
	if domain, ok := routingDomainFor(s, dest); ok {
		return netip.Addr{}, netip.Addr{}, fmt.Sprintf("This side's route for the target is in routing domain %q, which the snapshot cannot tie to the topology's vrf", domain)
	}
	switch owners := routepath.OwnersOf(f, src); {
	case len(owners) == 0:
		return netip.Addr{}, netip.Addr{}, "The topology places the source address on no node"
	case len(owners) > 1:
		return netip.Addr{}, netip.Addr{}, "The topology places the source address on several nodes or routing domains"
	case owners[0] != f.Source:
		return netip.Addr{}, netip.Addr{}, "The topology places the source address on a node or routing domain other than its source"
	}
	at, err := time.Parse(time.RFC3339, s.CreatedAt)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "This side's capture time is not readable"
	}
	if !rowsWithin(at, f) {
		return netip.Addr{}, netip.Addr{}, "A topology row was collected more than " + strconv.Itoa(int(routeWindow.Hours())) + " hours from this side's run, so it may describe a different network"
	}
	return dest, src, ""
}

// recordedSources is every source address this side recorded for dest, taken
// from the route decision and from the probe that reached dest. It is sorted
// and unique, so more than one entry means the side's own records disagree.
func recordedSources(s snapshot.Snapshot, dest netip.Addr) []netip.Addr {
	var out []netip.Addr
	add := func(text string) {
		a, err := netip.ParseAddr(text)
		if err != nil {
			return
		}
		if a = normalAddr(a); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, c := range s.Checks {
		if c.Observed == nil {
			continue
		}
		if sameAddr(c.Observed.SelectedIP, dest) {
			add(c.Observed.SourceIP)
		}
		for _, r := range c.Observed.Routes {
			if sameAddr(r.Destination, dest) {
				add(r.Source)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// routingDomainFor names a non-main routing domain this side recorded for dest.
// The snapshot cannot tie such a name to a topology vrf, so the file does not bind.
func routingDomainFor(s snapshot.Snapshot, dest netip.Addr) (string, bool) {
	for _, c := range s.Checks {
		if c.Observed == nil {
			continue
		}
		for _, r := range c.Observed.Routes {
			if !sameAddr(r.Destination, dest) {
				continue
			}
			if name, known := r.RoutingDomain(); known && name != "" {
				return name, true
			}
		}
	}
	return "", false
}

// rowsWithin reports whether every row the file carries was collected within
// routeWindow of the side's capture.
func rowsWithin(at time.Time, f routepath.File) bool {
	near := func(t time.Time) bool { return t.Sub(at).Abs() <= routeWindow }
	for _, o := range f.Model.Observations() {
		if !near(o.CollectedAt) {
			return false
		}
	}
	for _, c := range f.Checks {
		if !near(c.CollectedAt) {
			return false
		}
	}
	for _, b := range f.Boundaries {
		if !near(b.CollectedAt) {
			return false
		}
	}
	return true
}

// sameAddr reports whether text is dest. An address that does not parse is not
// the destination, so it never binds.
func sameAddr(text string, dest netip.Addr) bool {
	a, err := netip.ParseAddr(text)
	return err == nil && normalAddr(a) == dest
}

// normalAddr drops the zone and the IPv4-mapped form, so one address has one
// spelling wherever it came from.
func normalAddr(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }
