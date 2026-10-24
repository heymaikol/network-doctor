//go:build netns_integration && linux

package simulation

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
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

// tunnelFallbacks are the four fallback devices. The kernel creates each in every
// network namespace once its module loads: the GRE case loads the GRE modules by
// creating gre1, while a WireGuard case may carry only tunl0. A run expects the
// fallbacks its node carries, and each is inert on a node with default rules.
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
	// wg builds the tunnel as a WireGuard device wg1 over a plain underlay route,
	// instead of the pinned gre1 device over an ECMP route.
	wg bool
	// ecmp replaces the WireGuard endpoint route with two paths and checks the
	// full FIB capture leaves that endpoint unproven.
	ecmp bool
}

// device is the name of the tunnel device the case builds on r1 and r3.
func (c tunnelImportCase) device() string {
	if c.wg {
		return "wg1"
	}
	return "gre1"
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
	runTunnelImportDirector(t, "TestTunnelImportAgainstLiveNamespaces", tunnelImportCases, requireIPIPFallback)
}

// wireGuardImportCases cover the two #406 fault grades and the live ECMP proof
// refusal, in a diamond whose underlay route from r1 to r3 is one plain route
// over s14, so the endpoint lookup the import reads names the only leg the tunnel can
// use. Without a record the overlay is not predicted lost by an underlay fault, and
// the dial contradicts that, so the record's effect is the unknown it adds.
var wireGuardImportCases = []tunnelImportCase{{
	// The underlay leg goes down. The wg1 device stays up and has no carrier to
	// lose, the encapsulated packets have no route, and the dial fails. The walk
	// does not model the loss inside the underlay, so it claims unknown.
	name:      "wireguard underlay leg down",
	wg:        true,
	segment:   "s14",
	fault:     routepath.Failure{Node: "r1", Interface: "s14"},
	impact:    routepath.ImpactUnknown,
	delivered: false,
}, {
	// The tunnel device itself goes down. That is a fault in r1's own table, so
	// the overlay is lost.
	name:       "wireguard tunnel interface down",
	wg:         true,
	fault:      routepath.Failure{Node: "r1", Interface: "wg1"},
	impact:     routepath.ImpactReachabilityLost,
	delivered:  false,
	unaffected: "10.71.14.4",
}, {
	name: "wireguard ECMP route remains unproven",
	wg:   true,
	ecmp: true,
}}

// TestWireGuardImportAgainstLiveNamespaces builds the diamond with a WireGuard
// tunnel between r1 and r3, captures each node with the commands an operator would
// run, including the WireGuard dump and the lookup of each peer endpoint, and imports
// them. The import must record both ends with their evidence and refuse nothing. The
// kernel state of the faulted device is read before and after each fault, and the
// simulation of the proven record is graded against the dials: an underlay link_down
// is unknown, and the tunnel interface down is reachability_lost.
func TestWireGuardImportAgainstLiveNamespaces(t *testing.T) {
	runTunnelImportDirector(t, "TestWireGuardImportAgainstLiveNamespaces", wireGuardImportCases, func(t *testing.T) {
		t.Helper()
		requireIPIPFallback(t)
		requireWireGuard(t)
	})
}

// runTunnelImportDirector runs cases inside a director of this test binary, the way
// every live tunnel import test does. require stops the test when the lab lacks what
// the cases build, and it runs only outside the director.
func runTunnelImportDirector(t *testing.T, name string, cases []tunnelImportCase, require func(*testing.T)) {
	if *tunnelImportDirector {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) { runTunnelImportCase(t, c) })
		}
		return
	}
	t.Parallel()
	requireBackend(t)
	require(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^" + name + "$", "-test.v", "-tunnel-import-director"}
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
	for _, c := range cases {
		if sub := strings.ReplaceAll(c.name, " ", "_"); !strings.Contains(log.String(), "--- PASS: "+name+"/"+sub) {
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
	if c.wg {
		addWireGuardOverlay(ctx, t, e)
		if c.ecmp {
			if res := e.Exec(ctx, "r1", []string{"ip", "route", "del", "10.71.30.0/24"}, nil); res.Err != nil || res.ExitCode != 0 {
				t.Fatalf("r1: remove single-path endpoint route: %v", execResultError(res))
			}
			addMultipath(ctx, t, e, "r1", "10.71.30.0/24", "10.71.12.2", "10.71.14.4")
		}
	} else {
		// The scenario routes r1 nowhere past its links, so r1 gets the ECMP underlay
		// route to r3's LAN that the tunnel's remote is looked up in.
		addMultipath(ctx, t, e, "r1", "10.71.30.0/24", "10.71.12.2", "10.71.14.4")
		addGRE(ctx, t, e, "r1", "10.71.14.1", "10.71.30.1", "172.31.0.1/30", e.byName["r1"].interfaceForSegment("s14").iface)
		addGRE(ctx, t, e, "r3", "10.71.30.1", "10.71.14.1", tunnelOverlay+"/30", e.byName["r3"].interfaceForSegment("s43").iface)
	}
	awaitSettled(ctx, t, e)

	// The model is read before any steering rule, so the import's underlay proof
	// is taken from the same moment the dials are graded against.
	obs := kernelObservations(ctx, t, e, c.device())
	file := topologyFile(t, src.node.Name, obs)
	if c.steer {
		steerR1(ctx, t, e)
	}
	captures := tunnelCaptures(ctx, t, e)
	if c.wg {
		captures = append(captures, wireGuardCaptures(ctx, t, e)...)
	}
	dir := tunnelEvidenceDir(c.name)
	imp, err := routepath.ImportTunnels(file.Model, captures)
	if err != nil {
		t.Fatal(err)
	}
	if c.ecmp {
		ordinary := e.Exec(ctx, "r1", []string{"ip", "-j", "route", "get", wireGuardEndpoints["r1"]}, nil)
		if ordinary.Err != nil || ordinary.ExitCode != 0 {
			t.Fatalf("r1: ordinary route get: %v", execResultError(ordinary))
		}
		if err := checkWireGuardECMP(t, e, imp, captures, ordinary.Stdout); err != nil {
			t.Fatal(err)
		}
		if _, mergeErr := routepath.MergeTunnelImport(file, imp); mergeErr == nil || !strings.Contains(mergeErr.Error(), "the import is incomplete") {
			t.Fatalf("MergeTunnelImport = %v, want incomplete because the ECMP endpoint is unproven", mergeErr)
		}
		outcome := "ordinary route get: " + strings.TrimSpace(string(ordinary.Stdout)) + "\n"
		for _, capture := range captures {
			if capture.Node == "r1" && capture.Command == routepath.TunnelCommandRouteGetFibmatchPrefix+wireGuardEndpoints["r1"] {
				outcome += "fibmatch route: " + strings.TrimSpace(string(capture.Data)) + "\n"
			}
		}
		keepTunnelEvidence(t, dir, captures, file, outcome)
		return
	}
	checkTunnelImport(ctx, t, e, imp, c)
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
	if c.wg {
		// The first packet over a WireGuard peer starts the handshake, and the dial
		// that carries it can time out inside it. One unmeasured dial settles it.
		dialDelivers(ctx, t, src, tunnelOverlay)
	}
	before := map[string]bool{}
	for _, d := range dests {
		before[d] = dialDelivers(ctx, t, src, d)
	}
	if !before[tunnelOverlay] {
		t.Fatalf("the overlay %s is not up before the fault", tunnelOverlay)
	}
	tunnelPathState(ctx, t, e, &outcome, "before the fault", c.device())

	// The same file with no tunnel record is the answer the simulation gives when
	// the import is not believed. Both answers are graded.
	bare, err := routepath.Simulate(file, c.fault)
	if err != nil {
		t.Fatal(err)
	}

	device := c.device()
	if c.segment != "" {
		device = e.byName["r1"].interfaceForSegment(c.segment).iface
	}
	// The kernel is read on both sides of the fault, so the case grades a fault it
	// saw happen: the device is up before it, and down after it.
	linkState := func(when string, wantUp bool) {
		t.Helper()
		link := e.Exec(ctx, "r1", []string{"ip", "-o", "link", "show", "dev", device}, nil)
		if link.Err != nil || link.ExitCode != 0 || parseLinkUp(string(link.Stdout)) != wantUp {
			t.Fatalf("r1 %s is not up=%t in the kernel %s: %s %v", device, wantUp, when, link.Stdout, execResultError(link))
		}
		fmt.Fprintf(&outcome, "kernel %s: r1 %s up=%t\n", when, device, wantUp)
	}
	linkState("before the fault", true)
	if c.segment != "" {
		if _, err := e.ApplyFaults(ctx, s.Faults); err != nil {
			t.Fatal(err)
		}
	} else if res := e.Exec(ctx, "r1", []string{"ip", "link", "set", "dev", c.device(), "down"}, nil); res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("bring r1 %s down: %v", c.device(), execResultError(res))
	}
	linkState("after the fault", false)
	after := map[string]bool{}
	for _, d := range dests {
		after[d] = dialDelivers(ctx, t, src, d)
	}
	tunnelPathState(ctx, t, e, &outcome, "after the fault", c.device())

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
	if got := impactOr(bareRated, tunnelOverlay); c.bare != "" && got != c.bare {
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
// route each direction takes, the outer lookup when the tunnel pins one, and the
// full link counters of the tunnel device on both ends and of the pinned leg.
// Plain routes and the counters of shared links also carry the dials' own traffic,
// so the tunnel device's counters and the outer lookup are the ones read as the
// tunnel's. The lines also go to the outcome, so the evidence holds them beside
// each dial.
func tunnelPathState(ctx context.Context, t *testing.T, e *netnsEnv, outcome *strings.Builder, when, tunnel string) {
	t.Helper()
	var lines []string
	for _, route := range []struct {
		node, dst, from string
	}{
		{"r1", "10.71.30.1", "10.71.14.1"},
		{"r3", "10.71.14.1", "10.71.30.1"},
	} {
		res := e.Exec(ctx, route.node, []string{"ip", "-o", "route", "get", route.dst, "from", route.from}, nil)
		// A lookup that finds no route after the fault is the state being recorded,
		// so only a failure to run the command stops the case.
		if res.Err != nil {
			t.Fatalf("%s: route get %s from %s: %v", route.node, route.dst, route.from, res.Err)
		}
		lines = append(lines, fmt.Sprintf("  %s route get %s from %s: exit %d %s%s", route.node, route.dst, route.from, res.ExitCode, strings.TrimSpace(string(res.Stdout)), strings.TrimSpace(string(res.Stderr))))
	}

	pinned := e.byName["r1"].interfaceForSegment("s14").iface
	if tunnel == "gre1" {
		outer := e.Exec(ctx, "r1", []string{"ip", "-o", "route", "get", "10.71.30.1", "from", "10.71.14.1", "oif", pinned}, nil)
		if outer.Err != nil {
			t.Fatalf("r1: outer route get with oif %s: %v", pinned, outer.Err)
		}
		lines = append(lines, fmt.Sprintf("  r1 outer route get 10.71.30.1 from 10.71.14.1 oif %s: exit %d %s%s", pinned, outer.ExitCode, strings.TrimSpace(string(outer.Stdout)), strings.TrimSpace(string(outer.Stderr))))
	}

	for _, dev := range []struct {
		node, name string
	}{
		{"r1", tunnel},
		{"r1", pinned},
		{"r3", tunnel},
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

// liveFallbacks returns the fallback devices the node's kernel created. The GRE,
// gretap, and erspan modules are loaded by the GRE case but not by the WireGuard
// case, so a run only proves or refuses the fallbacks the node actually carries.
func liveFallbacks(ctx context.Context, t *testing.T, e *netnsEnv, node string) map[string]bool {
	t.Helper()
	res := e.Exec(ctx, node, []string{"ip", "-j", "link", "show"}, nil)
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("%s: ip -j link show: %v", node, execResultError(res))
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(res.Stdout, &links); err != nil {
		t.Fatalf("%s: ip -j link show: %v", node, err)
	}
	present := make(map[string]bool, len(links))
	for _, l := range links {
		present[l.Name] = true
	}
	return present
}

// checkTunnelImport asserts what the live import proves, refuses, and lists as
// inert. A fallback device the node carries is inert when the node's rules are the
// default set, and the import proves those rules, which every node but a steered one
// holds. When steer is set, r1's rules are refused: its fallbacks are refused for
// them, and its gre1 is refused and not recorded.
func checkTunnelImport(ctx context.Context, t *testing.T, e *netnsEnv, imp routepath.TunnelImport, c tunnelImportCase) {
	t.Helper()
	steer, dev := c.steer, c.device()
	want := map[string]string{}
	wantInert := map[string]string{}
	var rules []string
	for _, np := range e.nodes {
		node := np.node.Name
		present := liveFallbacks(ctx, t, e, node)
		steered := steer && node == "r1"
		for dev, fb := range tunnelFallbacks {
			if !present[dev] {
				continue
			}
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
		"r1 default " + dev + " remote 10.71.30.1 underlay default",
		"r3 default " + dev + " remote 10.71.14.1 underlay default",
	}
	if steer {
		wantRecords = wantRecords[1:]
	}
	if !slices.Equal(records, wantRecords) {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(records, "\n"), strings.Join(wantRecords, "\n"))
	}
	if c.wg {
		checkWireGuardEvidence(t, e, imp)
	}
}

// checkWireGuardEvidence asserts that each WireGuard record names the four captures it
// rests on, each with a source and a collection time, and the underlay device the
// endpoint lookup left by: s14 for r1, which reaches r3 through r4, and s43 for r3,
// which returns the same way.
func checkWireGuardEvidence(t *testing.T, e *netnsEnv, imp routepath.TunnelImport) {
	t.Helper()
	want := map[string]string{
		"r1": e.byName["r1"].interfaceForSegment("s14").iface,
		"r3": e.byName["r3"].interfaceForSegment("s43").iface,
	}
	got := map[string]string{}
	for _, w := range imp.WireGuard {
		got[w.Node] = w.Egress
		for what, p := range map[string]struct {
			Source string
			At     time.Time
		}{
			"device":   {w.Device.Source, w.Device.CollectedAt},
			"endpoint": {w.Endpoint.Source, w.Endpoint.CollectedAt},
			"lookup":   {w.Lookup.Source, w.Lookup.CollectedAt},
			"rules":    {w.Rules.Source, w.Rules.CollectedAt},
		} {
			if p.Source == "" || p.At.IsZero() {
				t.Errorf("%s %s evidence has no source or collection time: %+v", w.Node, what, w)
			}
		}
	}
	if !maps.Equal(got, want) {
		t.Errorf("underlay devices the lookups left by:\n%s\nwant:\n%s", tunnelLines(got), tunnelLines(want))
	}
}

// checkWireGuardECMP uses the ordinary lookup to show the kernel selected one
// device, then checks that fibmatch exposed both FIB paths and the importer did not
// mistake the selected device for a unique underlay.
func checkWireGuardECMP(t *testing.T, e *netnsEnv, imp routepath.TunnelImport, captures []routepath.TunnelCapture, ordinary []byte) error {
	t.Helper()
	var selected []struct {
		Dev      string            `json:"dev"`
		Nexthops []json.RawMessage `json:"nexthops"`
	}
	if err := json.Unmarshal(ordinary, &selected); err != nil || len(selected) != 1 || selected[0].Dev == "" || len(selected[0].Nexthops) != 0 {
		return fmt.Errorf("ordinary route get = %s; want one resolved device with no full nexthop list (decode error %v)", ordinary, err)
	}
	wantDevices := []string{
		e.byName["r1"].interfaceForSegment("s12").iface,
		e.byName["r1"].interfaceForSegment("s14").iface,
	}
	if !slices.Contains(wantDevices, selected[0].Dev) {
		return fmt.Errorf("ordinary route get selected %q, want one of %v", selected[0].Dev, wantDevices)
	}
	var fib []struct {
		Nexthops []struct {
			Dev string `json:"dev"`
		} `json:"nexthops"`
	}
	var fibSource string
	for _, c := range captures {
		if c.Node == "r1" && c.Command == routepath.TunnelCommandRouteGetFibmatchPrefix+wireGuardEndpoints["r1"] {
			fibSource = c.Source
			if err := json.Unmarshal(c.Data, &fib); err != nil {
				return fmt.Errorf("fibmatch output %s is not JSON: %w", c.Data, err)
			}
		}
	}
	if fibSource == "" || len(fib) != 1 || len(fib[0].Nexthops) != 2 {
		return fmt.Errorf("fibmatch output = %+v; want the complete route with two nexthops", fib)
	}
	fibDevices := []string{fib[0].Nexthops[0].Dev, fib[0].Nexthops[1].Dev}
	slices.Sort(fibDevices)
	slices.Sort(wantDevices)
	if !slices.Equal(fibDevices, wantDevices) {
		return fmt.Errorf("fibmatch devices = %v, want %v", fibDevices, wantDevices)
	}
	if len(imp.Unproven) != 1 || imp.Unproven[0].Node != "r1" || imp.Unproven[0].Interface != "wg1" {
		return fmt.Errorf("unproven endpoints = %+v; want r1 wg1", imp.Unproven)
	}
	if len(imp.Tunnels) != 1 || imp.Tunnels[0].Node != "r3" || imp.Tunnels[0].Interface != "wg1" {
		return fmt.Errorf("tunnel records = %+v; want only r3 wg1", imp.Tunnels)
	}
	if !slices.ContainsFunc(imp.Refused, func(r routepath.TunnelRefusal) bool {
		return r.Source == fibSource && strings.Contains(r.Reason, "multiple nexthops")
	}) {
		return fmt.Errorf("refusals = %+v; want the ECMP FIB capture refused by source %s", imp.Refused, fibSource)
	}
	return nil
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

// wireGuardEndpoints are the peer endpoints each end of the tunnel looks up: the
// underlay address of the other end.
var wireGuardEndpoints = map[string]string{"r1": "10.71.30.1", "r3": "10.71.14.1"}

// addWireGuardOverlay builds the WireGuard tunnel from r1 to r3's LAN address. r1
// reaches r3 through one plain route via r4, which r3 answers over the route the
// scenario already gives it, so each direction has exactly one underlay path and the
// lookup the import reads names it. Keys are made in memory with the wg tool and
// passed through the environment, so none reaches a file or a log.
func addWireGuardOverlay(ctx context.Context, t *testing.T, e *netnsEnv) {
	t.Helper()
	run := func(node, script string, env ...string) string {
		t.Helper()
		res := e.Exec(ctx, node, []string{"sh", "-c", script}, env)
		if res.Err != nil || res.ExitCode != 0 {
			t.Fatalf("%s: wireguard setup step failed: %v", node, execResultError(res))
		}
		return strings.TrimSpace(string(res.Stdout))
	}
	run("r1", "ip route add 10.71.30.0/24 via 10.71.14.4")
	type end struct{ node, overlay, peerOverlay, peerEndpoint string }
	ends := []end{
		{"r1", "172.31.0.1/30", "172.31.0.2/32", "10.71.30.1"},
		{"r3", tunnelOverlay + "/30", "172.31.0.1/32", "10.71.14.1"},
	}
	priv, pub := map[string]string{}, map[string]string{}
	for _, n := range ends {
		priv[n.node] = run(n.node, "wg genkey")
		pub[n.node] = run(n.node, `printf '%s\n' "$WG_PRIV" | wg pubkey`, "WG_PRIV="+priv[n.node])
	}
	peerOf := map[string]string{"r1": "r3", "r3": "r1"}
	// Both ends are configured before either comes up, and r3 comes up first, so
	// r1's first handshake cannot race the peer's listener.
	for _, n := range ends {
		run(n.node, "ip link add wg1 type wireguard")
		run(n.node, `printf '%s\n' "$WG_PRIV" | wg set wg1 private-key /dev/stdin listen-port 51820 peer "$WG_PEER" endpoint "$WG_ENDPOINT" allowed-ips "$WG_ALLOWED" persistent-keepalive 1`,
			"WG_PRIV="+priv[n.node], "WG_PEER="+pub[peerOf[n.node]], "WG_ENDPOINT="+n.peerEndpoint+":51820", "WG_ALLOWED="+n.peerOverlay)
		run(n.node, "ip addr add "+n.overlay+" dev wg1")
	}
	run("r3", "ip link set dev wg1 up")
	run("r1", "ip link set dev wg1 up")
}

// wireGuardCaptures reads, on each end of the tunnel, the dump of its WireGuard device
// and the lookup of its peer endpoint, with the commands the import reads. The dump
// carries keys, which the import never keeps and this test never logs.
func wireGuardCaptures(ctx context.Context, t *testing.T, e *netnsEnv) []routepath.TunnelCapture {
	t.Helper()
	var out []routepath.TunnelCapture
	for _, node := range slices.Sorted(maps.Keys(wireGuardEndpoints)) {
		for _, c := range []struct {
			kind, command string
			argv          []string
		}{
			{"wg", routepath.TunnelCommandWireGuard, []string{"wg", "show", "all", "dump"}},
			{"ip-route-fibmatch", routepath.TunnelCommandRouteGetFibmatchPrefix + wireGuardEndpoints[node], []string{"ip", "-j", "route", "get", "fibmatch", wireGuardEndpoints[node]}},
		} {
			if got := strings.Join(c.argv, " "); got != c.command {
				t.Fatalf("%s: argv %q does not match the command %q the import reads", node, got, c.command)
			}
			at := time.Now().UTC()
			res := e.Exec(ctx, node, c.argv, nil)
			if res.Err != nil || res.ExitCode != 0 {
				t.Fatalf("%s: %s: %v", node, c.command, execResultError(res))
			}
			out = append(out, routepath.TunnelCapture{Source: c.kind + "-" + node, Node: node, Command: c.command, CollectedAt: at, Data: res.Stdout})
		}
	}
	return out
}

// requireWireGuard stops the live WireGuard cases unless the lab can create a
// WireGuard device and has the wg tool. The kernel module may be built in, so the
// device is created in a throwaway namespace rather than looked for in /sys. It fails
// under RequireNetnsEnv and skips otherwise.
func requireWireGuard(t *testing.T) {
	t.Helper()
	missing := ""
	if _, err := exec.LookPath("wg"); err != nil {
		missing = "the wg tool is not installed; run: sudo apt-get install wireguard-tools"
	} else if err := exec.Command("unshare", "-Urn", "ip", "link", "add", "wgprobe", "type", "wireguard").Run(); err != nil {
		missing = "the kernel cannot create a WireGuard device; run: sudo modprobe wireguard"
	}
	if missing == "" {
		return
	}
	if os.Getenv(RequireNetnsEnv) != "" {
		t.Fatalf("%s is set, so these tests must run, but %s", RequireNetnsEnv, missing)
	}
	t.Skip(missing)
}
