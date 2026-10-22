//go:build netns_integration && linux

package simulation

import (
	"bytes"
	"cmp"
	"context"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// tunnelImportDirector is set only on the copy of this test binary that
// TestTunnelImportAgainstLiveNamespaces launches as its director.
var tunnelImportDirector = flag.Bool("tunnel-import-director", false, "internal: run the live tunnel import cases inside a director")

// tunnelImportEvidence, when set, receives each case's captures, metadata, outcome,
// and a SHA-256 manifest of them. The director receives it as an argument.
var tunnelImportEvidence = flag.String("tunnel-import-evidence", "", "write each live tunnel import case's captures, metadata, outcome, and a SHA-256 manifest to this directory")

// tunnelOverlay is the overlay address r3 holds on its gre1 device. It is the
// destination each case grades, since only a dial across the tunnel reaches it.
const tunnelOverlay = "172.31.0.2"

// tunnelFallback is one kernel fallback device a live node carries: the kind the
// import reads it as, and the reason that kind has always drawn when the device is
// not inert.
type tunnelFallback struct{ kind, reason string }

// tunnelFallbacks are the four fallback devices. The kernel creates them in every
// network namespace once their modules load, so a live node always carries all four.
// The captures show each one inert on a node whose policy rules are the default set.
var tunnelFallbacks = map[string]tunnelFallback{
	"gre0":    {"gre", "remote any is a multipoint tunnel, which names no single remote"},
	"gretap0": {"gretap", `has kind "gretap", which the import does not read`},
	"erspan0": {"erspan", `has kind "erspan", which the import does not read`},
	"tunl0":   {"ipip", "remote any is a multipoint tunnel, which names no single remote"},
}

// tunnelSteeredRules is the refusal of r1's rules capture once r1 holds a policy
// rule with a selector the import does not read. The rule's dst key is refused,
// so the whole capture is, and r1's gre1 is refused for it.
const tunnelSteeredRules = "a rule has a key the import does not read, so it cannot be a kernel default rule"

// tunnelSteeredRefusal is the refusal r1's gre1 draws for the same rules capture.
const tunnelSteeredRefusal = "the underlay routing table is not proven: node r1: " + tunnelSteeredRules

// tunnelSteeredFallback is what a fallback of r1 draws once r1's rules are refused:
// the reason its kind has always drawn, then why it is not inert.
const tunnelSteeredFallback = "; it is not an inert fallback: node r1: " + tunnelSteeredRules

// tunnelImportCase is one live diamond with a GRE tunnel from r1 to r3's LAN.
// r1's outer packets are pinned to its s14 leg by dev, while the route to r3's
// LAN is ECMP over s12 and s14.
type tunnelImportCase struct {
	name string
	// segment is the scenario fault on r1. When empty, the fault is r1's gre1
	// device brought down, which a scenario cannot express.
	segment   string
	fault     routepath.Failure
	impact    routepath.Impact
	delivered bool
	// bare is the prediction for the overlay with no tunnel record, the same
	// file with the tunnel left out. It is graded too, so the record's effect
	// on the answer is on the page, and not only the answer with it.
	bare routepath.Impact
	// unaffected, when set, is a destination that must be predicted none and be
	// delivered both before and after the fault.
	unaffected string
	// steer installs a policy rule on r1 that the import must refuse. No fault
	// is applied and no simulation runs.
	steer bool
}

var tunnelImportCases = []tunnelImportCase{{
	// The tunnel's outer packets are pinned to s14, and s12 is the other ECMP
	// leg. Losing s12 leaves the pinned leg up, so the overlay still delivers.
	// A prediction of loss here would be contradicted by the dial.
	name:      "underlay leg down unpinned",
	segment:   "s12",
	fault:     routepath.Failure{Node: "r1", Interface: "s12"},
	impact:    routepath.ImpactUnknown,
	delivered: true,
	bare:      routepath.ImpactNone,
	// r1's own s14 neighbor sits on the pinned leg, so it still answers.
	unaffected: "10.71.14.4",
}, {
	// The pinned leg goes down with the tunnel still pinned to it. The outer route
	// lookup, with the pinned leg as its output device, then has no route. gre1
	// counts one transmit error and one carrier error, and it sends no outer
	// packet. The plain route to r3's LAN moves to the other leg, which the tunnel
	// does not use. The walk does not model the pin, so the cut underlay claims
	// only unknown. Without the record the overlay is predicted none, and the dial
	// contradicts that.
	name:      "underlay leg down pinned",
	segment:   "s14",
	fault:     routepath.Failure{Node: "r1", Interface: "s14"},
	impact:    routepath.ImpactUnknown,
	delivered: false,
	bare:      routepath.ImpactNone,
}, {
	// The tunnel device itself goes down. That is a fault in r1's own table, so
	// the overlay is lost and the prediction is reachability_lost.
	name:      "tunnel device down",
	fault:     routepath.Failure{Node: "r1", Interface: "gre1"},
	impact:    routepath.ImpactReachabilityLost,
	delivered: false,
	// The device is down with or without a record, so this case says nothing
	// about the import. It is here to show the record does not change it.
	bare:       routepath.ImpactReachabilityLost,
	unaffected: "10.71.14.4",
}, {
	name:  "steering rule refuses the tunnel",
	steer: true,
}}

// TestTunnelImportAgainstLiveNamespaces builds the diamond with a GRE tunnel,
// captures each node's devices, addresses, routes, and rules with the commands an
// operator would run, and imports them. The import records the tunnel only when
// its underlay is proven, and the simulation of the proven record must never claim
// a loss the kernel contradicts.
//
// Inert fallbacks are accepted. A non-steering case must pass the completeness
// gate: no refusal, no unproven record, and no uncovered node. The records it
// proved are read back through the same Encode and Decode a written topology
// takes. The steering case must not pass the gate. Its steering rule refuses r1's
// fallbacks, rules, and gre device, so the case checks those refusals and the
// gate's refusal, and writes no topology.
func TestTunnelImportAgainstLiveNamespaces(t *testing.T) {
	if *tunnelImportDirector {
		for _, c := range tunnelImportCases {
			t.Run(c.name, func(t *testing.T) { runTunnelImportCase(t, c) })
		}
		return
	}
	t.Parallel()
	requireBackend(t)
	requireIPIPFallback(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestTunnelImportAgainstLiveNamespaces$", "-test.v", "-tunnel-import-director"}
	if *tunnelImportEvidence != "" {
		args = append(args, "-tunnel-import-evidence", *tunnelImportEvidence)
	}
	var log bytes.Buffer
	code, err := LaunchDirector(context.Background(), self, args, nil, &log, &log)
	if err != nil || code != 0 {
		t.Fatalf("director exit %d (%v):\n%s", code, err, log.String())
	}
	// A director that matched no test exits 0 too, so each case has to be seen
	// passing, or a renamed test would pass here having run nothing.
	for _, c := range tunnelImportCases {
		if name := strings.ReplaceAll(c.name, " ", "_"); !strings.Contains(log.String(), "--- PASS: TestTunnelImportAgainstLiveNamespaces/"+name) {
			t.Errorf("case %q did not run in the director:\n%s", c.name, log.String())
		}
	}
	t.Log(log.String())
}

func runTunnelImportCase(t *testing.T, c tunnelImportCase) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := ParseScenario(strings.NewReader(tunnelScenario(c.segment)))
	if err != nil {
		t.Fatal(err)
	}
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
	// The scenario routes r1 nowhere past its links, so r1 gets the ECMP underlay
	// route to r3's LAN that the tunnel's remote is looked up in.
	addMultipath(ctx, t, e, "r1", "10.71.30.0/24", "10.71.12.2", "10.71.14.4")
	addGRE(ctx, t, e, "r1", "10.71.14.1", "10.71.30.1", "172.31.0.1/30", e.byName["r1"].interfaceForSegment("s14").iface)
	addGRE(ctx, t, e, "r3", "10.71.30.1", "10.71.14.1", tunnelOverlay+"/30", e.byName["r3"].interfaceForSegment("s43").iface)
	awaitSettled(ctx, t, e)

	// The model is read before any steering rule, so the import's underlay proof
	// is taken from the same moment the dials are graded against.
	obs := kernelObservations(ctx, t, e, "gre1")
	file := topologyFile(t, src.node.Name, obs)
	if c.steer {
		steerR1(ctx, t, e)
	}
	captures := tunnelCaptures(ctx, t, e)
	dir := tunnelEvidenceDir(c.name)
	imp, err := routepath.ImportTunnels(file.Model, captures)
	if err != nil {
		t.Fatal(err)
	}
	checkTunnelImport(t, e, imp, c.steer)
	_, mergeErr := routepath.MergeTunnelImport(file, imp)
	switch {
	case c.steer && (mergeErr == nil || !strings.Contains(mergeErr.Error(), "the import is incomplete")):
		t.Errorf("MergeTunnelImport: %v, want the completeness gate to refuse the steered import", mergeErr)
	case !c.steer && mergeErr != nil:
		t.Errorf("MergeTunnelImport refused a complete live import: %v", mergeErr)
	}
	if c.steer {
		keepTunnelEvidence(t, dir, captures, file, tunnelImportSummary(imp))
		return
	}

	// The records the import proved are written the way a topology file takes
	// them, and read back, so the simulation sees exactly what a file would hold.
	merged := file
	merged.Tunnels = imp.Tunnels
	data, err := routepath.Encode(merged)
	if err != nil {
		t.Fatal(err)
	}
	written, err := routepath.Decode(data)
	if err != nil {
		t.Fatalf("the proven tunnel records do not decode: %v", err)
	}

	var outcome strings.Builder
	outcome.WriteString(tunnelImportSummary(imp))
	dests := heldAddresses(obs)
	before := map[string]bool{}
	for _, d := range dests {
		before[d] = dialDelivers(ctx, t, src, d)
	}
	if !before[tunnelOverlay] {
		t.Fatalf("the overlay %s is not up before the fault", tunnelOverlay)
	}
	tunnelPathState(ctx, t, e, &outcome, "before the fault")

	// The same file with no tunnel record is the answer the simulation gives when
	// the import is not believed. Both answers are graded.
	bare, err := routepath.Simulate(file, c.fault)
	if err != nil {
		t.Fatal(err)
	}

	if c.segment != "" {
		if _, err := e.ApplyFaults(ctx, s.Faults); err != nil {
			t.Fatal(err)
		}
	} else if res := e.Exec(ctx, "r1", []string{"ip", "link", "set", "dev", "gre1", "down"}, nil); res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("bring r1 gre1 down: %v", execResultError(res))
	}
	device := "gre1"
	if c.segment != "" {
		device = e.byName["r1"].interfaceForSegment(c.segment).iface
	}
	link := e.Exec(ctx, "r1", []string{"ip", "-o", "link", "show", "dev", device}, nil)
	if link.Err != nil || link.ExitCode != 0 || parseLinkUp(string(link.Stdout)) {
		t.Fatalf("r1 %s is not down in the kernel after the fault: %s %v", device, link.Stdout, execResultError(link))
	}
	after := map[string]bool{}
	for _, d := range dests {
		after[d] = dialDelivers(ctx, t, src, d)
	}
	tunnelPathState(ctx, t, e, &outcome, "after the fault")

	sim, err := routepath.Simulate(written, c.fault)
	if err != nil {
		t.Fatal(err)
	}
	if sim.Considered != len(dests) || sim.Truncated {
		t.Fatalf("simulation considered %d destinations (truncated %t), want all %d held", sim.Considered, sim.Truncated, len(dests))
	}
	rated := ratedAffected(sim)
	bareRated := ratedAffected(bare)
	for _, d := range dests {
		a, ok := rated[d]
		if !ok {
			a.Impact = routepath.ImpactNone
		}
		line := fmt.Sprintf("%-12s recorded %-17s without record %-17s dialed before %-5t after %t", d, a.Impact, impactOr(bareRated, d), before[d], after[d])
		t.Log(line)
		outcome.WriteString(line + "\n")
		if why := disagreement(ctx, e, src, a, before[d], after[d]); why != "" {
			t.Errorf("%s: predicted %s, but %s (%s)", d, a.Impact, why, a.Reason)
		}
	}
	if got := impactOr(rated, tunnelOverlay); got != c.impact || after[tunnelOverlay] != c.delivered {
		t.Errorf("%s: predicted %s and delivered %t after the fault, want %s and %t: the case no longer exercises what it is for",
			tunnelOverlay, got, after[tunnelOverlay], c.impact, c.delivered)
	}
	if got := impactOr(bareRated, tunnelOverlay); got != c.bare {
		t.Errorf("%s: predicted %s without the tunnel record, want %s", tunnelOverlay, got, c.bare)
	}
	if why := disagreement(ctx, e, src, routepath.Affected{Destination: tunnelOverlay, Impact: impactOr(bareRated, tunnelOverlay)}, before[tunnelOverlay], after[tunnelOverlay]); why != "" {
		line := fmt.Sprintf("without the record, %s is contradicted: %s", tunnelOverlay, why)
		t.Log(line)
		outcome.WriteString(line + "\n")
	}
	if d := c.unaffected; d != "" {
		if got := impactOr(rated, d); got != routepath.ImpactNone || !before[d] || !after[d] {
			t.Errorf("%s: predicted %s and delivered %t then %t, want none and delivered both times", d, got, before[d], after[d])
		}
	}
	keepTunnelEvidence(t, dir, captures, file, outcome.String())
}

// ratedAffected indexes a simulation's affected destinations by address.
func ratedAffected(sim routepath.Simulation) map[string]routepath.Affected {
	rated := map[string]routepath.Affected{}
	for _, a := range sim.Affected {
		rated[a.Destination] = a
	}
	return rated
}

// impactOr is the impact rated for dest, or none when the simulation rated nothing.
func impactOr(rated map[string]routepath.Affected, dest string) routepath.Impact {
	return cmp.Or(rated[dest].Impact, routepath.ImpactNone)
}

// tunnelPathState logs what the kernel does with the tunnel at one moment: the
// route each direction takes, the lookup r1's outer packets make with gre1's
// pinned device as oif, and the full link counters of gre1 on both ends and of
// the pinned leg. Plain routes and the counters of shared links also carry the
// dials' own traffic, so the gre1 counters and the pinned lookup are the ones read
// as the tunnel's. The lines also go to the outcome, so the evidence holds them
// beside each dial.
func tunnelPathState(ctx context.Context, t *testing.T, e *netnsEnv, outcome *strings.Builder, when string) {
	t.Helper()
	var lines []string
	for _, route := range []struct {
		node, dst, from string
	}{
		{"r1", "10.71.30.1", "10.71.14.1"},
		{"r3", "10.71.14.1", "10.71.30.1"},
	} {
		res := e.Exec(ctx, route.node, []string{"ip", "-o", "route", "get", route.dst, "from", route.from}, nil)
		if res.Err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: route get %s from %s: %v", route.node, route.dst, route.from, execResultError(res))
		}
		lines = append(lines, fmt.Sprintf("  %s route get %s from %s: %s", route.node, route.dst, route.from, strings.TrimSpace(string(res.Stdout))))
	}

	pinned := e.byName["r1"].interfaceForSegment("s14").iface
	outer := e.Exec(ctx, "r1", []string{"ip", "-o", "route", "get", "10.71.30.1", "from", "10.71.14.1", "oif", pinned}, nil)
	if outer.Err != nil {
		t.Fatalf("r1: outer route get with oif %s: %v", pinned, outer.Err)
	}
	lines = append(lines, fmt.Sprintf("  r1 outer route get 10.71.30.1 from 10.71.14.1 oif %s: exit %d %s%s", pinned, outer.ExitCode, strings.TrimSpace(string(outer.Stdout)), strings.TrimSpace(string(outer.Stderr))))

	for _, dev := range []struct {
		node, name string
	}{
		{"r1", "gre1"},
		{"r1", pinned},
		{"r3", "gre1"},
	} {
		res := e.Exec(ctx, dev.node, []string{"ip", "-s", "-s", "link", "show", "dev", dev.name}, nil)
		if res.Err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: link show %s: %v", dev.node, dev.name, execResultError(res))
		}
		lines = append(lines, fmt.Sprintf("  %s %s:", dev.node, dev.name))
		for _, l := range strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n") {
			lines = append(lines, "    "+l)
		}
	}

	fmt.Fprintf(outcome, "path %s at %s\n", when, time.Now().UTC().Format(time.RFC3339))
	for _, line := range lines {
		t.Log(line)
		outcome.WriteString(line + "\n")
	}
}

// tunnelScenario is diamondScenario with its fault replaced. An empty segment
// writes no fault at all, since the gre1 case brings its tunnel device down.
func tunnelScenario(segment string) string {
	faults := "faults: []"
	if segment != "" {
		faults = "faults:\n  - {type: link_down, node: r1, segment: " + segment + "}"
	}
	return strings.Replace(fmt.Sprintf(diamondScenario, ""), "faults:\n  - {type: link_down, node: r1, segment: s12}", faults, 1)
}

// addGRE creates a gre device on node, pinned by dev to the segment interface that
// carries its outer packets, and gives it its overlay address. Each command runs
// through Env.Exec, the way the other live cases build their topology.
func addGRE(ctx context.Context, t *testing.T, e *netnsEnv, node, local, remote, overlay, dev string) {
	t.Helper()
	for _, argv := range [][]string{
		{"ip", "link", "add", "gre1", "type", "gre", "local", local, "remote", remote, "dev", dev},
		{"ip", "addr", "add", overlay, "dev", "gre1"},
		{"ip", "link", "set", "dev", "gre1", "up"},
	} {
		if res := e.Exec(ctx, node, argv, nil); res.Err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: %s: %v", node, strings.Join(argv, " "), execResultError(res))
		}
	}
}

// requireIPIPFallback stops the live tunnel import cases unless the ipip kernel
// module is loaded. The kernel creates the tunl0 fallback device in a network
// namespace only while that module is loaded, and every case expects tunl0 on each
// node. Without the module the cases fail on the missing device rather than on the
// import, so this names what is missing instead. It fails under RequireNetnsEnv and
// skips otherwise.
func requireIPIPFallback(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/sys/module/ipip"); err == nil {
		return
	}
	const msg = "the ipip kernel module is not loaded, so new namespaces get no tunl0 fallback device; run: sudo modprobe ipip"
	if os.Getenv(RequireNetnsEnv) != "" {
		t.Fatalf("%s is set, so these tests must run, but %s", RequireNetnsEnv, msg)
	}
	t.Skip(msg)
}

// steerR1 installs the policy rule the import must refuse: lookups for the
// tunnel's remote go to table 100, which holds one route through the other leg.
func steerR1(ctx context.Context, t *testing.T, e *netnsEnv) {
	t.Helper()
	s12 := e.byName["r1"].interfaceForSegment("s12").iface
	for _, argv := range [][]string{
		{"ip", "rule", "add", "to", "10.71.30.1", "lookup", "100"},
		{"ip", "route", "add", "10.71.30.0/24", "via", "10.71.12.2", "dev", s12, "table", "100"},
	} {
		if res := e.Exec(ctx, "r1", argv, nil); res.Err != nil || res.ExitCode != 0 {
			t.Fatalf("r1: %s: %v", strings.Join(argv, " "), execResultError(res))
		}
	}
}

// tunnelCaptures reads each node's device list, addresses, IPv4 and IPv6 routes, and
// IPv4 policy rules out of its own namespace, with the commands the import reads.
func tunnelCaptures(ctx context.Context, t *testing.T, e *netnsEnv) []routepath.TunnelCapture {
	t.Helper()
	var out []routepath.TunnelCapture
	for _, np := range e.nodes {
		for _, c := range []struct {
			kind, command string
			argv          []string
		}{
			{"ip-link", routepath.TunnelCommandIPLink, []string{"ip", "-d", "-j", "link"}},
			{"ip-rule", routepath.TunnelCommandRules, []string{"ip", "-j", "rule", "show"}},
			{"ip-addr", routepath.TunnelCommandAddr, []string{"ip", "-j", "addr", "show"}},
			{"ip-route4", routepath.TunnelCommandRoute4, []string{"ip", "-4", "-j", "route", "show", "table", "all"}},
			{"ip-route6", routepath.TunnelCommandRoute6, []string{"ip", "-6", "-j", "route", "show", "table", "all"}},
		} {
			if got := strings.Join(c.argv, " "); got != c.command {
				t.Fatalf("%s: argv %q does not match the command %q the import reads", np.node.Name, got, c.command)
			}
			at := time.Now().UTC()
			res := e.Exec(ctx, np.node.Name, c.argv, nil)
			if res.Err != nil || res.ExitCode != 0 {
				t.Fatalf("%s: %s: %v", np.node.Name, c.command, execResultError(res))
			}
			out = append(out, routepath.TunnelCapture{
				Source:      c.kind + "-" + np.node.Name,
				Node:        np.node.Name,
				Command:     c.command,
				CollectedAt: at,
				Data:        res.Stdout,
			})
		}
	}
	return out
}

// checkTunnelImport asserts what the live import proves, refuses, and lists as
// inert. Every fallback device is inert on a node whose rules are the default set,
// and the import proves those rules, which every node but a steered one holds. When
// steer is set, r1's rules are refused: its fallbacks are refused for them, and its
// gre1 is refused and not recorded.
func checkTunnelImport(t *testing.T, e *netnsEnv, imp routepath.TunnelImport, steer bool) {
	t.Helper()
	want := map[string]string{}
	wantInert := map[string]string{}
	var rules []string
	for _, np := range e.nodes {
		node := np.node.Name
		steered := steer && node == "r1"
		for dev, fb := range tunnelFallbacks {
			if steered {
				want[node+" "+dev] = fb.reason + tunnelSteeredFallback
			} else {
				wantInert[node+" "+dev] = fb.kind
			}
		}
		if steered {
			want["r1 "] = tunnelSteeredRules
			want["r1 gre1"] = tunnelSteeredRefusal
			continue
		}
		rules = append(rules, node)
	}
	got := map[string]string{}
	for _, r := range imp.Refused {
		got[r.Node+" "+r.Interface] = r.Reason
	}
	if len(got) != len(imp.Refused) || !maps.Equal(got, want) {
		t.Errorf("refusals:\n%s\nwant:\n%s", tunnelLines(got), tunnelLines(want))
	}
	if len(imp.Unproven) != 0 || len(imp.Uncovered) != 0 {
		t.Errorf("unproven %d, without a usable capture %v; want neither", len(imp.Unproven), imp.Uncovered)
	}

	gotInert := map[string]string{}
	for _, d := range imp.Inert {
		gotInert[d.Node+" "+d.Interface] = d.Kind
		if d.From.IsZero() || d.Until.Before(d.From) || len(d.Sources) == 0 {
			t.Errorf("inert %s %s has no usable collection window: %+v", d.Node, d.Interface, d)
		}
	}
	if !maps.Equal(gotInert, wantInert) {
		t.Errorf("inert devices:\n%s\nwant:\n%s", tunnelLines(gotInert), tunnelLines(wantInert))
	}

	var proven []string
	for _, p := range imp.Rules {
		proven = append(proven, p.Node)
	}
	slices.Sort(rules)
	if !slices.Equal(proven, rules) {
		t.Errorf("rules proven on %v, want %v", proven, rules)
	}

	var records []string
	for _, r := range imp.Tunnels {
		records = append(records, fmt.Sprintf("%s %s %s remote %s underlay %s", r.Node, r.VRF, r.Interface, r.Remote, r.UnderlayVRF))
	}
	wantRecords := []string{
		"r1 default gre1 remote 10.71.30.1 underlay default",
		"r3 default gre1 remote 10.71.14.1 underlay default",
	}
	if steer {
		wantRecords = wantRecords[1:]
	}
	if !slices.Equal(records, wantRecords) {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(records, "\n"), strings.Join(wantRecords, "\n"))
	}
}

// tunnelImportSummary states what the import decided, read from the import
// itself. It heads each outcome, so the evidence records the decision the captures
// produced rather than the one a case expected.
func tunnelImportSummary(imp routepath.TunnelImport) string {
	var b strings.Builder
	b.WriteString("import refusals:\n")
	for _, r := range imp.Refused {
		what := r.Interface
		if what == "" {
			what = "rules"
		}
		fmt.Fprintf(&b, "  %s %s: %s\n", r.Node, what, r.Reason)
	}
	b.WriteString("rules proven:")
	for _, p := range imp.Rules {
		fmt.Fprintf(&b, " %s", p.Node)
	}
	b.WriteString("\ntunnels recorded:\n")
	for _, t := range imp.Tunnels {
		fmt.Fprintf(&b, "  %s %s %s remote %s underlay %s\n", t.Node, t.VRF, t.Interface, t.Remote, t.UnderlayVRF)
	}
	b.WriteString("inert fallbacks:\n")
	for _, d := range imp.Inert {
		fmt.Fprintf(&b, "  %s %s (%s) from %s until %s, by %s\n", d.Node, d.Interface, d.Kind, d.From.Format(time.RFC3339Nano), d.Until.Format(time.RFC3339Nano), strings.Join(d.Sources, ", "))
	}
	fmt.Fprintf(&b, "unproven: %d\nwithout a usable capture: %v\n", len(imp.Unproven), imp.Uncovered)
	return b.String()
}

// tunnelLines prints a map one key per line, in key order, for a failure message.
func tunnelLines(m map[string]string) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		fmt.Fprintf(&b, "%s: %s\n", k, m[k])
	}
	return b.String()
}

// tunnelEvidenceDir is the directory one case writes its evidence to, or "" when
// no evidence is asked for.
func tunnelEvidenceDir(name string) string {
	if *tunnelImportEvidence == "" {
		return ""
	}
	return filepath.Join(*tunnelImportEvidence, strings.ReplaceAll(name, " ", "-"))
}

// keepTunnelEvidence writes one case's evidence to dir when evidence is asked for,
// with the base topology the import merged onto. It runs last, so a failure before
// it leaves no manifest behind.
func keepTunnelEvidence(t *testing.T, dir string, captures []routepath.TunnelCapture, base routepath.File, outcome string) {
	t.Helper()
	if dir == "" {
		return
	}
	topology, err := routepath.Encode(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTunnelEvidence(dir, captures, topology, outcome); err != nil {
		t.Fatal(err)
	}
}
