//go:build netns_integration && linux

package simulation

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/routepath"
)

// structuralFailureDirector is set only on the copy of this test binary that
// TestStructuralFailureAgainstLiveFaults launches as its director.
var structuralFailureDirector = flag.Bool("structural-failure-director", false, "internal: run the live structural failure cases inside a director")

// failureDialTimeout bounds one dial. A delivered dial in these namespaces
// answers in well under a millisecond, so only a lost path spends it.
const failureDialTimeout = time.Second

// failureDialPort has no listener on any node, so a delivered dial is answered
// by the destination's own reset. No node filters or rejects anything, so only
// the destination's stack can send one, and a reset proves delivery both ways.
const failureDialPort = 9

// structuralFailureCase is one live network, one interface it brings down,
// and the destination the case exists for. Impact and delivered pin that the
// case exercises what it claims, so a topology that stopped exercising it
// fails instead of grading nothing. They are not the proof: every destination
// is graded against the dials, whatever the case names.
type structuralFailureCase struct {
	name     string
	scenario string
	// multipath installs one ECMP route the scenario schema cannot express, as
	// node, destination, then one gateway per leg.
	multipath []string
	dest      string
	impact    routepath.Impact
	delivered bool
	// partial, when set, names a node whose recorded table is then marked
	// partial. The same prediction, from evidence that no longer proves its
	// forwarding, must rate dest unknown, whatever the dials showed.
	partial string
	// fail, when set, is the failure predicted instead of the fault itself,
	// for a fault wider than the failure. Only what the source can observe of
	// the fault is then graded, never that the two are the same event.
	fail *routepath.Failure
	// unaffected, when set, is a destination that must be predicted none and
	// be delivered both before and after the fault.
	unaffected string
	// kept, when set, is node, prefix, then gateway: after the fault, the
	// node's route to the prefix must still list the gateway with no dead or
	// linkdown flag, so nothing in the node's table stops it selecting the
	// gateway, and every held address in the prefix must be predicted unknown.
	kept [3]string
}

// diamondScenario is r1 with two paths to r3's LAN, one through r2 and one
// through r4. The %s slot takes r1's routes, the only part the cases vary. r3
// routes each r1 link back the way it came, so a reply never depends on the
// failed leg.
const diamondScenario = `
name: structural-failure-diamond
topology:
  segments:
    - {name: s12, subnet: 10.71.12.0/24}
    - {name: s14, subnet: 10.71.14.0/24}
    - {name: s23, subnet: 10.71.23.0/24}
    - {name: s43, subnet: 10.71.43.0/24}
    - {name: lan3, subnet: 10.71.30.0/24}
  nodes:
    - name: r1
      role: client
      interfaces:
        - {segment: s12, address: 10.71.12.1/24}
        - {segment: s14, address: 10.71.14.1/24}
    - name: r2
      role: router
      interfaces:
        - {segment: s12, address: 10.71.12.2/24}
        - {segment: s23, address: 10.71.23.2/24}
    - name: r4
      role: router
      interfaces:
        - {segment: s14, address: 10.71.14.4/24}
        - {segment: s43, address: 10.71.43.4/24}
    - name: r3
      interfaces:
        - {segment: s23, address: 10.71.23.3/24}
        - {segment: s43, address: 10.71.43.3/24}
        - {segment: lan3, address: 10.71.30.1/24}
  routes:
    - {node: r2, destination: 10.71.30.0/24, via: 10.71.23.3}
    - {node: r4, destination: 10.71.30.0/24, via: 10.71.43.3}
    - {node: r3, destination: 10.71.12.0/24, via: 10.71.23.2}
    - {node: r3, destination: 10.71.14.0/24, via: 10.71.43.4}
%s
faults:
  - {type: link_down, node: r1, segment: s12}
# The schema requires a test. netdoc is not run here.
tests:
  - {name: unused, node: r1}
expect: {verdict: ok}
`

// singleHomedScenario is r1, r2, r3 in a line with one path. r2 holds a LAN of
// its own, so a failure past r2 leaves something it still reaches. The %s slot
// names the r2 interface that goes down.
const singleHomedScenario = `
name: structural-failure-single-homed
topology:
  segments:
    - {name: s12, subnet: 10.72.12.0/24}
    - {name: s23, subnet: 10.72.23.0/24}
    - {name: lan2, subnet: 10.72.20.0/24}
    - {name: lan3, subnet: 10.72.30.0/24}
  nodes:
    - name: r1
      role: client
      interfaces:
        - {segment: s12, address: 10.72.12.1/24}
    - name: r2
      role: router
      interfaces:
        - {segment: s12, address: 10.72.12.2/24}
        - {segment: s23, address: 10.72.23.2/24}
        - {segment: lan2, address: 10.72.20.1/24}
    - name: r3
      interfaces:
        - {segment: s23, address: 10.72.23.3/24}
        - {segment: lan3, address: 10.72.30.1/24}
  routes:
    - {node: r1, destination: 10.72.0.0/16, via: 10.72.12.2}
    - {node: r2, destination: 10.72.30.0/24, via: 10.72.23.3}
    - {node: r3, destination: 10.72.0.0/16, via: 10.72.23.2}
faults:
  - {type: link_down, node: r2, segment: %s}
tests:
  - {name: unused, node: r1}
expect: {verdict: ok}
`

// sharedLANScenario is r1 on one LAN, s1, with two gateways: r2 at 10.73.1.2
// and r4 at 10.73.1.4. Each holds a LAN of its own and reaches r3's LAN, and r3
// routes s1 back through r4 only, so a reply never depends on r2.
const sharedLANScenario = `
name: structural-failure-shared-lan
topology:
  segments:
    - {name: s1, subnet: 10.73.1.0/24}
    - {name: s23, subnet: 10.73.23.0/24}
    - {name: s43, subnet: 10.73.43.0/24}
    - {name: lan2, subnet: 10.73.20.0/24}
    - {name: lan3, subnet: 10.73.30.0/24}
    - {name: lan4, subnet: 10.73.40.0/24}
  nodes:
    - name: r1
      role: client
      interfaces:
        - {segment: s1, address: 10.73.1.1/24}
    - name: r2
      role: router
      interfaces:
        - {segment: s1, address: 10.73.1.2/24}
        - {segment: s23, address: 10.73.23.2/24}
        - {segment: lan2, address: 10.73.20.1/24}
    - name: r4
      role: router
      interfaces:
        - {segment: s1, address: 10.73.1.4/24}
        - {segment: s43, address: 10.73.43.4/24}
        - {segment: lan4, address: 10.73.40.1/24}
    - name: r3
      interfaces:
        - {segment: s23, address: 10.73.23.3/24}
        - {segment: s43, address: 10.73.43.3/24}
        - {segment: lan3, address: 10.73.30.1/24}
  routes:
    - {node: r1, destination: 10.73.20.0/24, via: 10.73.1.2}
    - {node: r1, destination: 10.73.40.0/24, via: 10.73.1.4}
    - {node: r2, destination: 10.73.30.0/24, via: 10.73.23.3}
    - {node: r4, destination: 10.73.30.0/24, via: 10.73.43.3}
    - {node: r3, destination: 10.73.1.0/24, via: 10.73.43.4}
faults:
  - {type: link_down, node: r2, segment: s1}
tests:
  - {name: unused, node: r1}
expect: {verdict: ok}
`

var structuralFailureCases = []structuralFailureCase{{
	// Both legs are in r1's FIB, so nothing has to reconverge: the kernel
	// marks the s12 leg dead and keeps forwarding on the other one.
	name:      "ecmp alternate survives the source link",
	scenario:  fmt.Sprintf(diamondScenario, ""),
	multipath: []string{"r1", "10.71.30.0/24", "10.71.12.2", "10.71.14.4"},
	dest:      "10.71.30.1", impact: routepath.ImpactRedundancyLost, delivered: true,
	partial: "r4",
}, {
	// The kernel deletes the metric 10 route with its link and starts using the
	// metric 20 one, a path no recorded branch holds. The file cannot record
	// both rows, so r1's table is partial and nothing it forwards is claimed.
	name: "metric backup is not predicted",
	scenario: fmt.Sprintf(diamondScenario, `    - {node: r1, destination: 10.71.30.0/24, via: 10.71.12.2, metric: 10}
    - {node: r1, destination: 10.71.30.0/24, via: 10.71.14.4, metric: 20}`),
	dest: "10.71.30.1", impact: routepath.ImpactUnknown, delivered: true,
}, {
	name:     "single-homed loses what lies past the link",
	scenario: fmt.Sprintf(singleHomedScenario, "s23"),
	dest:     "10.72.30.1", impact: routepath.ImpactReachabilityLost, delivered: false,
	partial: "r2",
}, {
	// Only the far end is down. r1's link keeps its carrier through the
	// segment bridge, so r1 keeps its route and has nothing to stop using: its
	// own table after the fault would predict no loss.
	name:     "far end of the only link",
	scenario: fmt.Sprintf(singleHomedScenario, "s12"),
	dest:     "10.72.30.1", impact: routepath.ImpactReachabilityLost, delivered: false,
}, {
	// r2's end of s1 goes down. That is a wider fault than the one predicted:
	// r2 loses s1 for every neighbor, and its own address there, not just its
	// role as r1's next hop. So only what r1 observes is graded. r1's link
	// keeps its carrier through the segment bridge and r4 still answers on
	// it, so from r1 a next hop stops answering on a link that stays up, and
	// r1's table keeps listing it.
	name:      "gateway lost on a shared LAN",
	scenario:  sharedLANScenario,
	multipath: []string{"r1", "10.73.30.0/24", "10.73.1.2", "10.73.1.4"},
	fail:      &routepath.Failure{Node: "r1", NextHop: "10.73.1.2"},
	dest:      "10.73.20.1", impact: routepath.ImpactReachabilityLost, delivered: false,
	unaffected: "10.73.40.1",
	kept:       [3]string{"r1", "10.73.30.0/24", "10.73.1.2"},
	partial:    "r1",
}}

// TestStructuralFailureAgainstLiveFaults holds the --explain --fail simulation
// to a real network. Each case builds namespaces, reads every node's kernel
// addresses and main table into a topology file, and simulates the scenario's
// one link_down fault, or the narrower failure the case names, from that file
// alone. Then it injects the fault and dials
// every destination the simulation considered, from the source, before and
// after. The prediction is graded against those dials and the kernel's own
// route selection, never against the scenario: the YAML only builds the
// network, and the prediction reads what the kernel holds.
//
// Routes are static, so nothing reconverges. What the kernel does after the
// fault is what it does with the FIB it already had, which is all a structural
// simulation can be compared with. It says nothing about OSPF or BGP.
func TestStructuralFailureAgainstLiveFaults(t *testing.T) {
	if *structuralFailureDirector {
		for _, c := range structuralFailureCases {
			t.Run(c.name, func(t *testing.T) { runStructuralFailureCase(t, c) })
		}
		return
	}
	t.Parallel()
	requireBackend(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	code, err := LaunchDirector(context.Background(), self, []string{
		"-test.run=^TestStructuralFailureAgainstLiveFaults$", "-test.v", "-structural-failure-director",
	}, nil, &log, &log)
	if err != nil || code != 0 {
		t.Fatalf("director exit %d (%v):\n%s", code, err, log.String())
	}
	// A director that matched no test exits 0 too, so each case has to be seen
	// passing, or a renamed test would pass here having run nothing.
	for _, c := range structuralFailureCases {
		if name := strings.ReplaceAll(c.name, " ", "_"); !strings.Contains(log.String(), "--- PASS: TestStructuralFailureAgainstLiveFaults/"+name) {
			t.Errorf("case %q did not run in the director:\n%s", c.name, log.String())
		}
	}
	t.Log(log.String())
}

func runStructuralFailureCase(t *testing.T, c structuralFailureCase) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := ParseScenario(strings.NewReader(c.scenario))
	if err != nil {
		t.Fatal(err)
	}
	fault := s.Faults[0]
	env, err := DefaultBackend(false, nil).Prepare(ctx, s, NewID())
	if env != nil {
		defer func() {
			if info := env.Cleanup(context.Background(), false); !info.Done || len(info.Errors) > 0 {
				t.Errorf("cleanup: done=%t errors=%v", info.Done, info.Errors)
			}
		}()
	}
	if err != nil {
		t.Fatal(err)
	}
	e := env.(*netnsEnv)
	src := e.byName[s.Client().Name]
	if c.multipath != nil {
		addMultipath(ctx, t, e, c.multipath[0], c.multipath[1], c.multipath[2:]...)
	}

	// The prediction is made before anything breaks, from kernel state alone.
	obs := kernelObservations(ctx, t, e)
	file := topologyFile(t, src.node.Name, obs)
	fail := routepath.Failure{Node: fault.Node, Interface: fault.Segment}
	if c.fail != nil {
		fail = *c.fail
	}
	sim, err := routepath.Simulate(file, fail)
	if err != nil {
		t.Fatal(err)
	}
	dests := heldAddresses(obs)
	if sim.Considered != len(dests) || sim.Truncated {
		t.Fatalf("simulation considered %d destinations (truncated %t), want all %d held", sim.Considered, sim.Truncated, len(dests))
	}
	before := map[string]bool{}
	for _, d := range dests {
		before[d] = dialDelivers(ctx, t, src, d)
	}

	if _, err := e.ApplyFaults(ctx, s.Faults); err != nil {
		t.Fatal(err)
	}
	link := e.Exec(ctx, fault.Node, []string{"ip", "-o", "link", "show", "dev", e.byName[fault.Node].interfaceForSegment(fault.Segment).iface}, nil)
	if link.Err != nil || link.ExitCode != 0 || parseLinkUp(string(link.Stdout)) {
		t.Fatalf("%s %s is not down in the kernel after the fault: %s %v", fault.Node, fault.Segment, link.Stdout, execResultError(link))
	}
	after := map[string]bool{}
	for _, d := range dests {
		after[d] = dialDelivers(ctx, t, src, d)
	}
	for _, node := range slices.Compact([]string{src.node.Name, fault.Node}) {
		if table := e.Exec(ctx, node, []string{"ip", "-4", "route", "show"}, nil); table.ExitCode == 0 {
			t.Logf("%s main table after the fault:\n%s", node, table.Stdout)
		}
	}

	rated := map[string]routepath.Affected{}
	for _, a := range sim.Affected {
		rated[a.Destination] = a
	}
	for _, d := range dests {
		a, ok := rated[d]
		if !ok {
			a.Impact = routepath.ImpactNone
		}
		t.Logf("%-12s predicted %-17s dialed before %-5t after %t", d, a.Impact, before[d], after[d])
		if why := disagreement(ctx, e, src, a, before[d], after[d]); why != "" {
			t.Errorf("%s: predicted %s, but %s (%s)", d, a.Impact, why, a.Reason)
		}
	}
	if got := cmp.Or(rated[c.dest].Impact, routepath.ImpactNone); got != c.impact || after[c.dest] != c.delivered {
		t.Errorf("%s: predicted %s and delivered %t after the fault, want %s and %t: the case no longer exercises what it is for",
			c.dest, got, after[c.dest], c.impact, c.delivered)
	}
	if d := c.unaffected; d != "" {
		if got := cmp.Or(rated[d].Impact, routepath.ImpactNone); got != routepath.ImpactNone || !before[d] || !after[d] {
			t.Errorf("%s: predicted %s and delivered %t then %t, want none and delivered both times", d, got, before[d], after[d])
		}
	}
	if c.kept[0] != "" {
		checkKept(ctx, t, e, c.kept, dests, rated)
	}

	if c.partial == "" {
		return
	}
	for i := range obs {
		if obs[i].Node == c.partial {
			obs[i].RoutesComplete = false
		}
	}
	thin, err := routepath.Simulate(topologyFile(t, src.node.Name, obs), fail)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range thin.Affected {
		if a.Destination == c.dest && a.Impact == routepath.ImpactUnknown {
			t.Logf("with %s's table partial, %s is unknown, though the dial after the fault delivered %t", c.partial, c.dest, after[c.dest])
			return
		}
	}
	t.Errorf("with %s's table partial, %s is not unknown: %+v", c.partial, c.dest, thin.Affected)
}

// disagreement says how the dials, or the kernel's own route choice, contradict
// one predicted impact, or returns "". One dial follows one ECMP leg, so a loss
// on some branches is graded only when no branch of the walk still delivers.
// Unknown claims nothing, so nothing contradicts it.
func disagreement(ctx context.Context, e *netnsEnv, src *nodeProc, a routepath.Affected, before, after bool) string {
	switch a.Impact {
	case routepath.ImpactNone:
		if before != after {
			return fmt.Sprintf("delivery changed from %t to %t", before, after)
		}
	case routepath.ImpactRedundancyLost:
		if !before || !after {
			return fmt.Sprintf("delivery went from %t to %t", before, after)
		}
		res := e.Exec(ctx, src.node.Name, []string{"ip", "-4", "route", "get", a.Destination}, nil)
		if res.Err != nil || res.ExitCode != 0 {
			return "the kernel selects no route for it: " + execResultError(res).Error()
		}
		selected, err := parseRouteGet(res.Stdout, src, "ipv4")
		if err != nil {
			return err.Error()
		}
		if !slices.ContainsFunc(a.After.Next, func(h routepath.Hop) bool {
			return h.Decision.Kind != routepath.KindFailed && h.Via.Interface == selected.Segment && h.Via.NextHop == selected.Via
		}) {
			return fmt.Sprintf("the kernel now sends it on %s via %s, which is not a surviving branch", selected.Segment, selected.Via)
		}
	case routepath.ImpactReachabilityLost:
		switch {
		case !before:
			return "it was not delivered before the fault"
		case after && !delivers(a.After):
			return "it is still delivered, though no branch of the walk delivers"
		}
	}
	return ""
}

// checkKept requires that a node still lists a gateway in its route to a prefix
// after the fault, with no dead or linkdown flag, and that every held address
// in the prefix is predicted unknown: nothing in the table stops the node
// selecting the gateway, and whether something else does is not in the file.
// The route lookup and the gateway's neighbor entry are logged, not graded. A
// lookup with no source address is one hash selection, under a seed the file
// does not record, and a dial's own lookup may hash differently, so it shows
// what the kernel selects for that lookup, never which leg a flow took.
func checkKept(ctx context.Context, t *testing.T, e *netnsEnv, kept [3]string, dests []string, rated map[string]routepath.Affected) {
	t.Helper()
	node, prefix, gateway := kept[0], netip.MustParsePrefix(kept[1]), kept[2]
	var routes []kernelRoute
	kernelJSON(ctx, t, e, node, &routes, "ip", "-4", "-j", "route", "show", "table", "main")
	i := slices.IndexFunc(routes, func(r kernelRoute) bool { return r.Dst == prefix.String() })
	if i < 0 {
		t.Fatalf("%s holds no route to %s after the fault", node, prefix)
	}
	hops := routes[i].Nexthops
	if len(hops) == 0 {
		hops = []kernelHop{routes[i].kernelHop}
	}
	if j := slices.IndexFunc(hops, func(h kernelHop) bool { return h.Gateway == gateway }); j < 0 ||
		slices.Contains(hops[j].Flags, "dead") || slices.Contains(hops[j].Flags, "linkdown") {
		t.Errorf("%s no longer lists %s as a usable next hop of %s after the fault: %+v", node, gateway, prefix, hops)
	}
	neigh := e.Exec(ctx, node, []string{"ip", "-4", "neigh", "show", gateway}, nil)
	t.Logf("%s neighbor entry for %s after the fault: %s", node, gateway, strings.TrimSpace(string(neigh.Stdout)))
	for _, d := range dests {
		if !prefix.Contains(netip.MustParseAddr(d)) {
			continue
		}
		if got := cmp.Or(rated[d].Impact, routepath.ImpactNone); got != routepath.ImpactUnknown {
			t.Errorf("%s: predicted %s, want unknown while %s keeps %s in its route", d, got, node, gateway)
		}
		res := e.Exec(ctx, node, []string{"ip", "-4", "route", "get", d}, nil)
		t.Logf("%s ip route get %s after the fault, one lookup selection: %s", node, d, strings.TrimSpace(string(res.Stdout)))
	}
}

// delivers reports whether some branch of a walk still ends at the destination.
func delivers(h *routepath.Hop) bool {
	if h == nil {
		return false
	}
	if h.Decision.Kind == routepath.KindLocal {
		return true
	}
	return slices.ContainsFunc(h.Next, func(c routepath.Hop) bool { return delivers(&c) })
}

func dialDelivers(ctx context.Context, t *testing.T, from *nodeProc, dest string) bool {
	t.Helper()
	outcome, err := from.probeTCP(ctx, dest, failureDialPort, failureDialTimeout)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", dest, from.node.Name, err)
	}
	return outcome == FamilyStateReachable || outcome == TargetStateRefused
}

// addMultipath installs one ECMP route through Env.Exec, the way the PMTU
// remediation test adds its clamp, so the scenario schema gains nothing. Each
// gateway's leg leaves by the interface on its subnet.
func addMultipath(ctx context.Context, t *testing.T, e *netnsEnv, node, dest string, vias ...string) {
	t.Helper()
	np := e.byName[node]
	argv := []string{"ip", "-4", "route", "add", dest}
	for _, via := range vias {
		segment, _ := nodeSegmentForAddress(np.node, netip.MustParseAddr(via))
		argv = append(argv, "nexthop", "via", via, "dev", np.interfaceForSegment(segment).iface)
	}
	if res := e.Exec(ctx, node, argv, nil); res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("add multipath route on %s: %v", node, execResultError(res))
	}
}

// kernelRoute is the part of one `ip -j route` row the topology file needs.
// A row with one next hop carries it inline, and an ECMP row lists them.
type kernelRoute struct {
	Type     string      `json:"type"`
	Dst      string      `json:"dst"`
	Protocol string      `json:"protocol"`
	Metric   uint32      `json:"metric"`
	Nexthops []kernelHop `json:"nexthops"`
	kernelHop
}

type kernelHop struct {
	Gateway string   `json:"gateway"`
	Dev     string   `json:"dev"`
	Flags   []string `json:"flags"`
}

// kernelObservations reads every node's IPv4 addresses and main table out of
// its own namespace, after the network is built and before any fault, as one
// complete fib observation per node. Kernel device names become logical
// segment names, the mapping the route evidence already uses, so a failure
// names an interface the way the scenario does. Loopback is on no segment and
// is left out. Nothing here reads the scenario's routes. The tables are
// complete because the backend adds no policy rule, so the main table is the
// one every lookup ends in.
func kernelObservations(ctx context.Context, t *testing.T, e *netnsEnv) []netmodel.Observation {
	t.Helper()
	at := time.Now().UTC()
	var out []netmodel.Observation
	for _, np := range e.nodes {
		segment := func(dev string) string {
			for _, iface := range np.ifaces {
				if iface.iface == dev {
					return iface.logical.Segment
				}
			}
			return ""
		}
		o := netmodel.Observation{
			Provenance: netmodel.Provenance{Source: "kernel:" + np.node.Name, CollectedAt: at},
			Plane:      netmodel.PlaneFIB, Node: np.node.Name, VRF: "default", RoutesComplete: true,
		}
		var links []struct {
			Ifname   string `json:"ifname"`
			AddrInfo []struct {
				Local     string `json:"local"`
				Prefixlen int    `json:"prefixlen"`
			} `json:"addr_info"`
		}
		kernelJSON(ctx, t, e, np.node.Name, &links, "ip", "-4", "-j", "addr", "show")
		for _, l := range links {
			name := segment(l.Ifname)
			if name == "" {
				continue
			}
			i := netmodel.Interface{Name: name}
			for _, a := range l.AddrInfo {
				addr, err := netip.ParseAddr(a.Local)
				if err != nil {
					t.Fatalf("%s %s: %v", np.node.Name, name, err)
				}
				i.Addresses = append(i.Addresses, netip.PrefixFrom(addr, a.Prefixlen))
			}
			o.Interfaces = append(o.Interfaces, i)
		}
		var routes []kernelRoute
		kernelJSON(ctx, t, e, np.node.Name, &routes, "ip", "-4", "-j", "route", "show", "table", "main")
		for _, r := range routes {
			if r.Type != "" && r.Type != "unicast" {
				t.Fatalf("%s holds a %s route to %s, which these topologies never install", np.node.Name, r.Type, r.Dst)
			}
			prefix := netip.MustParsePrefix("0.0.0.0/0")
			if r.Dst != "default" {
				var err error
				if prefix, err = parseRoutePrefix(r.Dst); err != nil {
					t.Fatalf("%s route %q: %v", np.node.Name, r.Dst, err)
				}
			}
			route := netmodel.Route{Prefix: prefix, Origin: cmp.Or(r.Protocol, "boot"), Metric: r.Metric, MetricKnown: true}
			hops := r.Nexthops
			if len(hops) == 0 {
				hops = []kernelHop{r.kernelHop}
			}
			for _, h := range hops {
				name := segment(h.Dev)
				if name == "" || slices.Contains(h.Flags, "dead") || slices.Contains(h.Flags, "linkdown") {
					t.Fatalf("%s route %s leaves by %q with flags %v before any fault", np.node.Name, r.Dst, h.Dev, h.Flags)
				}
				hop := netmodel.NextHop{Interface: name}
				if h.Gateway != "" {
					addr, err := netip.ParseAddr(h.Gateway)
					if err != nil {
						t.Fatalf("%s route %s: %v", np.node.Name, r.Dst, err)
					}
					hop.Addr = addr
				}
				route.NextHops = append(route.NextHops, hop)
			}
			// The model holds one route per prefix and origin, so of two
			// metrics the file keeps the one the kernel forwards by. The
			// other cannot be recorded, so the table is no longer complete.
			if i := slices.IndexFunc(o.Routes, func(r netmodel.Route) bool { return r.Prefix == route.Prefix && r.Origin == route.Origin }); i >= 0 {
				if route.Metric < o.Routes[i].Metric {
					o.Routes[i] = route
				}
				o.RoutesComplete = false
				continue
			}
			o.Routes = append(o.Routes, route)
		}
		out = append(out, o)
	}
	return out
}

func kernelJSON(ctx context.Context, t *testing.T, e *netnsEnv, node string, into any, argv ...string) {
	t.Helper()
	res := e.Exec(ctx, node, argv, nil)
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("%s: %s: %v", node, strings.Join(argv, " "), execResultError(res))
	}
	if err := json.Unmarshal(res.Stdout, into); err != nil {
		t.Fatalf("%s: %s: %v\n%s", node, strings.Join(argv, " "), err, res.Stdout)
	}
}

func topologyFile(t *testing.T, source string, obs []netmodel.Observation) routepath.File {
	t.Helper()
	m, err := netmodel.New(obs...)
	if err != nil {
		t.Fatal(err)
	}
	return routepath.File{Source: routepath.Start{Node: source, VRF: "default"}, Model: m}
}

// heldAddresses lists every address an interface holds, which is the set the
// simulation considers when no extra destination is named.
func heldAddresses(obs []netmodel.Observation) []string {
	var out []netip.Addr
	for _, o := range obs {
		for _, i := range o.Interfaces {
			for _, p := range i.Addresses {
				if !slices.Contains(out, p.Addr()) {
					out = append(out, p.Addr())
				}
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	texts := make([]string, len(out))
	for i, a := range out {
		texts[i] = a.String()
	}
	return texts
}
