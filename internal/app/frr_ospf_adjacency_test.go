package app

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/routepath"
)

// frrAdjacencyDir holds the live FRR OSPF adjacency-loss runs of
// lab/ospf-adjacency.sh, one directory per arm.
const frrAdjacencyDir = "../../testdata/frr/10.7.0/adjacency"

// adjacencyWant pins what one destination of an arm exercises: the predicted
// impact and whether r1's ping delivered it after the fault. A run that no
// longer shows it fails instead of grading nothing. Every destination is
// graded against the observations, whatever an arm pins.
type adjacencyWant struct {
	impact    routepath.Impact
	delivered bool
}

var adjacencyArms = []struct {
	arm, iface, peer, peerIface, dest string
	want                              map[string]adjacencyWant
}{{
	// r1 keeps a second adjacency with r2 on e3, so the ECMP leg on e3 survives.
	arm: "ecmp", iface: "e1", peer: "r2", peerIface: "e2", dest: "10.10.2.1",
	want: map[string]adjacencyWant{
		"10.10.2.1": {routepath.ImpactRedundancyLost, true},
		"10.0.1.2":  {routepath.ImpactNone, true},
	},
}, {
	// r3 has no other path: OSPF withdraws the route, and the destination is
	// lost, which unknown does not contradict. The static and connected routes
	// over the same link keep forwarding.
	arm: "single", iface: "e5", peer: "r3", peerIface: "e6", dest: "10.10.3.1",
	want: map[string]adjacencyWant{
		"10.10.3.1": {routepath.ImpactUnknown, false},
		"10.30.0.1": {routepath.ImpactNone, true},
		"10.0.5.2":  {routepath.ImpactNone, true},
	},
}, {
	// The recorded FIB holds one path to stub3, and SPF finds another through
	// r2 that no recorded row holds, so reachability_lost would be wrong.
	arm: "backup", iface: "e5", peer: "r3", peerIface: "e6", dest: "10.10.3.1",
	want: map[string]adjacencyWant{
		"10.10.3.1": {routepath.ImpactUnknown, true},
		"10.0.7.2":  {routepath.ImpactRedundancyLost, true},
		"10.30.0.1": {routepath.ImpactNone, true},
		"10.0.5.2":  {routepath.ImpactNone, true},
	},
}}

// TestFRRAdjacencyLossAgainstLiveRuns holds --fail-ospf to real FRR 10.7.0
// adjacency losses. The prediction is made from the captures taken before the
// fault only: the neighbor and interface captures go through --import-frr-ospf
// --write-topology, and each node's kernel addresses and main table are added
// as fib rows, which is the one step this test supplies by hand (kernelFIB).
// Then --explain --fail-ospf runs on that file, and every destination it
// considers is graded against what the run observed after the fault: r1's
// pings, its route lookups, and its main table. The arm's own claims, that the
// adjacency left Full on both ends while both interfaces stayed up and both
// drop filters dropped OSPF packets, are checked from the captures too.
func TestFRRAdjacencyLossAgainstLiveRuns(t *testing.T) {
	for _, arm := range adjacencyArms {
		t.Run(arm.arm, func(t *testing.T) {
			src := filepath.Join(frrAdjacencyDir, arm.arm)
			var specs []frrStage
			for _, n := range []string{"r1", "r2", "r3"} {
				for _, c := range []string{"show ip ospf neighbor detail json", "show ip ospf interface json"} {
					specs = append(specs, frrStage{n + "-before-" + strings.ReplaceAll(c, " ", "_"), n + "-" + strings.Fields(c)[3] + ".json", n + " " + c, n, c})
				}
			}
			dir, manifest := stageFRR(t, src, specs)
			topology := filepath.Join(dir, "topology.json")
			if code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--write-topology", topology); code != 0 {
				t.Fatalf("import exit %d\n%s\n%s", code, stdout, stderr)
			}
			editFRRJSON(t, topology, func(m map[string]any) {
				for _, n := range []string{"r1", "r2", "r3"} {
					m["observations"] = append(m["observations"].([]any), kernelFIB(t, src, n))
				}
			})
			var dests []string
			for _, n := range []string{"r1", "r2", "r3"} {
				dests = append(dests, heldIPv4(t, filepath.Join(src, n+"-before-ip_addr.json"))...)
			}
			selector := "r1:" + arm.iface + ":" + arm.peer
			code, stdout, stderr := runNetdoc(t, "--explain", topology, arm.dest, "--fail-ospf", selector)
			if code != 0 {
				t.Fatalf("--explain exit %d: %s", code, stderr)
			}
			t.Logf("netdoc --explain topology.json %s --fail-ospf %s\n%s", arm.dest, selector, stdout)
			code, stdout, stderr = runNetdoc(t, "--explain", "--json", topology, arm.dest, "--fail-ospf", selector)
			if code != 0 {
				t.Fatalf("--explain --json exit %d: %s", code, stderr)
			}
			var out struct{ Failure *routepath.Simulation }
			if err := json.Unmarshal([]byte(stdout), &out); err != nil || out.Failure == nil {
				t.Fatalf("no failure in the output (%v):\n%s", err, stdout)
			}
			sim := out.Failure
			if sim.Adjacency == nil || !sim.Adjacency.Proven {
				t.Fatalf("adjacency %+v, want the transit dependency proven", sim.Adjacency)
			}
			if sim.Considered != len(dests) || sim.Truncated {
				t.Fatalf("considered %d destinations (truncated %t), want all %d held", sim.Considered, sim.Truncated, len(dests))
			}

			checkAdjacencyFault(t, src, arm.iface, arm.peer, arm.peerIface)
			before, after := probes(t, src, "before"), probes(t, src, "after")
			table := kernelTable(t, filepath.Join(src, "r1-after-ip_route.json"))
			rated := map[string]routepath.Affected{}
			for _, a := range sim.Affected {
				rated[a.Destination] = a
			}
			for _, d := range dests {
				a, ok := rated[d]
				if !ok {
					a.Impact = routepath.ImpactNone
				}
				b, okb := before[d]
				f, oka := after[d]
				if !okb || !oka {
					t.Fatalf("%s: probed before %t and after %t, want both: the run is missing data", d, okb, oka)
				}
				t.Logf("%-10s predicted %-16s delivered before %-5t after %-5t %s", d, a.Impact, b.delivered, f.delivered, a.Reason)
				if !b.delivered {
					t.Errorf("%s: not delivered before the fault, so the run grades nothing for it", d)
				}
				switch a.Impact {
				case routepath.ImpactNone:
					if b.delivered != f.delivered {
						t.Errorf("%s: predicted none, but delivery went from %t to %t", d, b.delivered, f.delivered)
					}
				case routepath.ImpactReachabilityLost:
					t.Errorf("%s: an adjacency loss is never reachability_lost: %s", d, a.Reason)
				case routepath.ImpactRedundancyLost:
					if why := survivorsDisagree(a, table, f); why != "" {
						t.Errorf("%s: predicted redundancy_lost, but %s", d, why)
					}
				case routepath.ImpactUnknown:
					// Unknown claims nothing, so nothing contradicts it. What
					// OSPF installed instead is logged as the outcome.
					t.Logf("%s: r1 installed %s for %s after the fault", d, legsText(table[a.After.Decision.Prefix]), a.After.Decision.Prefix)
				}
				if w, ok := arm.want[d]; ok && (a.Impact != w.impact || f.delivered != w.delivered) {
					t.Errorf("%s: predicted %s and delivered %t after the fault, want %s and %t: the arm no longer exercises what it is for", d, a.Impact, f.delivered, w.impact, w.delivered)
				}
			}
		})
	}
}

// survivorsDisagree says how r1's main table and route lookup after the fault
// contradict a redundancy_lost walk, or returns "". The walk's surviving first
// hops must be exactly the next hops r1 installed for the walk's prefix, so
// each cut leg is gone and each survivor stays, and the lookup must select a
// survivor. A ping follows one leg, so delivery says only that one survives.
func survivorsDisagree(a routepath.Affected, table map[string][]kernelLeg, f labProbe) string {
	if !f.delivered {
		return "it was not delivered after the fault"
	}
	var kept []kernelLeg
	for _, h := range a.After.Next {
		if h.Decision.Kind != routepath.KindFailed {
			kept = append(kept, kernelLeg{h.Via.NextHop, h.Via.Interface})
		}
	}
	installed := table[a.After.Decision.Prefix]
	slices.SortFunc(kept, compareLegs)
	slices.SortFunc(installed, compareLegs)
	switch {
	case !slices.Equal(kept, installed):
		return "r1 installed " + legsText(installed) + " for " + a.After.Decision.Prefix + ", not the surviving legs " + legsText(kept)
	case !slices.Contains(kept, f.selected):
		return "r1 selects " + legsText([]kernelLeg{f.selected}) + ", which is not a surviving leg"
	}
	return ""
}

// kernelLeg is one next hop in r1's main table or route lookup.
type kernelLeg struct{ gateway, dev string }

func compareLegs(a, b kernelLeg) int {
	return strings.Compare(a.gateway+" "+a.dev, b.gateway+" "+b.dev)
}

func legsText(legs []kernelLeg) string {
	var s []string
	for _, l := range legs {
		s = append(s, l.gateway+" dev "+l.dev)
	}
	return "[" + strings.Join(s, ", ") + "]"
}

// ipRoute is the part of one "ip -j route" row read here. A row with one next
// hop carries it inline, and an ECMP row lists them.
type ipRoute struct {
	Type     string   `json:"type"`
	Dst      string   `json:"dst"`
	Protocol string   `json:"protocol"`
	Scope    string   `json:"scope"`
	Metric   *uint32  `json:"metric"`
	Nexthops []ipHop  `json:"nexthops"`
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	Flags    []string `json:"flags"`
}

type ipHop struct {
	Gateway string   `json:"gateway"`
	Dev     string   `json:"dev"`
	Flags   []string `json:"flags"`
}

func (r ipRoute) hops() []ipHop {
	if len(r.Nexthops) > 0 {
		return r.Nexthops
	}
	return []ipHop{{r.Gateway, r.Dev, r.Flags}}
}

func readJSONFile(t *testing.T, path string, into any) {
	t.Helper()
	// #nosec G304 -- path names a committed capture.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func stampOf(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- path names a committed capture.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// kernelTable reads a main table as prefix to next hops.
func kernelTable(t *testing.T, path string) map[string][]kernelLeg {
	t.Helper()
	var routes []ipRoute
	readJSONFile(t, path, &routes)
	out := map[string][]kernelLeg{}
	for _, r := range routes {
		for _, h := range r.hops() {
			out[r.Dst] = append(out[r.Dst], kernelLeg{h.Gateway, h.Dev})
		}
	}
	return out
}

// kernelFIB is node's fib observation, in the topology file's wire form, from
// its kernel captures before the fault. No adapter in netdoc reads ip -j, so
// these facts are supplied here: protocol kernel, which the kernel uses for the
// scope link route of an interface's own subnet, is written as origin
// connected, and static and ospf keep their names. The lab installs no policy
// rule, so the main table is the one every lookup ends in, and the table is
// written complete. Any other protocol, a route that is not unicast, or a next
// hop the kernel flags fails the test, since the lab installs none.
func kernelFIB(t *testing.T, src, node string) map[string]any {
	t.Helper()
	var links []struct {
		Ifname   string `json:"ifname"`
		AddrInfo []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	readJSONFile(t, filepath.Join(src, node+"-before-ip_addr.json"), &links)
	var ifaces []any
	for _, l := range links {
		if l.Ifname == "lo" {
			continue
		}
		var addrs []string
		for _, a := range l.AddrInfo {
			addrs = append(addrs, a.Local+"/"+strconv.Itoa(a.Prefixlen))
		}
		ifaces = append(ifaces, map[string]any{"name": l.Ifname, "addresses": addrs})
	}
	var routes []ipRoute
	readJSONFile(t, filepath.Join(src, node+"-before-ip_route.json"), &routes)
	var rows []any
	for _, r := range routes {
		origin := r.Protocol
		switch {
		case r.Type != "" && r.Type != "unicast":
			t.Fatalf("%s holds a %s route to %s", node, r.Type, r.Dst)
		case r.Protocol == "kernel" && r.Scope == "link" && r.Gateway == "" && len(r.Nexthops) == 0:
			origin = "connected"
		case r.Protocol != "static" && r.Protocol != "ospf":
			t.Fatalf("%s route %s has protocol %q, which the lab never installs", node, r.Dst, r.Protocol)
		}
		var hops []any
		for _, h := range r.hops() {
			if len(h.Flags) > 0 {
				t.Fatalf("%s route %s leaves by %s with flags %v before the fault", node, r.Dst, h.Dev, h.Flags)
			}
			hop := map[string]any{"interface": h.Dev}
			if h.Gateway != "" {
				hop["addr"] = h.Gateway
			}
			hops = append(hops, hop)
		}
		row := map[string]any{"prefix": r.Dst, "origin": origin, "next_hops": hops}
		if r.Metric != nil {
			row["metric"] = *r.Metric
		}
		rows = append(rows, row)
	}
	return map[string]any{
		"source":          "kernel:" + node + " before",
		"collected_at":    stampOf(t, filepath.Join(src, node+"-before-ip_route.collected_at")),
		"plane":           "fib",
		"node":            node,
		"vrf":             "default",
		"routes_complete": true,
		"interfaces":      ifaces,
		"routes":          rows,
	}
}

// heldIPv4 lists the IPv4 addresses an addr capture holds off lo, the set the
// lab's probes cover.
func heldIPv4(t *testing.T, path string) []string {
	t.Helper()
	var links []struct {
		Ifname   string `json:"ifname"`
		AddrInfo []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	readJSONFile(t, path, &links)
	var out []string
	for _, l := range links {
		for _, a := range l.AddrInfo {
			if l.Ifname != "lo" {
				out = append(out, a.Local)
			}
		}
	}
	return out
}

// labProbe is what r1 observed for one destination: whether its ping got a reply,
// and the leg its route lookup selected. A lookup is one hash selection, never
// the leg a flow took.
type labProbe struct {
	delivered bool
	selected  kernelLeg
}

func probes(t *testing.T, src, phase string) map[string]labProbe {
	t.Helper()
	var rows []struct {
		Destination string          `json:"destination"`
		PingExit    *int            `json:"ping_exit"`
		RouteGet    json.RawMessage `json:"route_get"`
	}
	readJSONFile(t, filepath.Join(src, "r1-"+phase+"-probes.json"), &rows)
	out := map[string]labProbe{}
	for _, r := range rows {
		p := labProbe{delivered: r.PingExit != nil && *r.PingExit == 0}
		var sel []ipHop
		if json.Unmarshal(r.RouteGet, &sel) == nil && len(sel) == 1 {
			p.selected = kernelLeg{sel[0].Gateway, sel[0].Dev}
		}
		out[r.Destination] = p
	}
	return out
}

// ipLink is the part of one "ip -j link" row read here.
type ipLink struct {
	Ifname    string   `json:"ifname"`
	Operstate string   `json:"operstate"`
	Flags     []string `json:"flags"`
}

// checkAdjacencyFault checks that the run injected what the arm says: r1's
// adjacency on iface and peer's on peerIface were Full before the fault and
// are not Full after it, both interfaces stayed up with carrier in both
// phases, and both of r1's drop filters dropped OSPF packets.
func checkAdjacencyFault(t *testing.T, src, iface, peer, peerIface string) {
	t.Helper()
	for _, end := range [][2]string{{"r1", iface}, {peer, peerIface}} {
		for _, phase := range []string{"before", "after"} {
			const cmd = "show ip ospf neighbor detail json"
			stem := end[0] + "-" + phase + "-" + strings.ReplaceAll(cmd, " ", "_")
			// #nosec G304 -- stem names a committed capture.
			raw, err := os.ReadFile(filepath.Join(src, stem+".raw"))
			if err != nil {
				t.Fatal(err)
			}
			var d struct {
				Neighbors map[string][]struct{ IfaceName, NbrState string }
			}
			if err := json.Unmarshal([]byte(unframeFRR(t, stem, cmd, raw)), &d); err != nil {
				t.Fatalf("%s: %v", stem, err)
			}
			full := false
			for _, ns := range d.Neighbors {
				for _, n := range ns {
					full = full || n.IfaceName == end[1] && strings.HasPrefix(n.NbrState, "Full")
				}
			}
			if full != (phase == "before") {
				t.Errorf("%s %s: Full neighbor on %s is %t", end[0], phase, end[1], full)
			}
			var links []ipLink
			readJSONFile(t, filepath.Join(src, end[0]+"-"+phase+"-ip_link.json"), &links)
			if i := slices.IndexFunc(links, func(l ipLink) bool { return l.Ifname == end[1] }); i < 0 || links[i].Operstate != "UP" || !slices.Contains(links[i].Flags, "LOWER_UP") {
				t.Errorf("%s %s: %s is not up with carrier", end[0], phase, end[1])
			}
		}
	}
	var captures [][]tcFilter
	for _, dir := range []string{"ingress", "egress"} {
		var fs []tcFilter
		readJSONFile(t, filepath.Join(src, "r1-after-tc_"+dir+".json"), &fs)
		captures = append(captures, fs)
	}
	if why := ospfDropsDisagree(captures...); why != "" {
		t.Errorf("r1 OSPF drop filters on %s: %s", iface, why)
	}
}

// tcFilter is the part of one "tc -s -j filter show" row read here. The rows
// without actions are u32 hash tables.
type tcFilter struct {
	Options struct {
		Fh    string
		Match struct {
			Value, Mask string
			Off         int
		}
		Actions []tcAction
	}
}

type tcAction struct {
	Kind          string
	ControlAction struct{ Type string } `json:"control_action"`
	Index         int
	Stats         struct{ Drops int }
}

// ospfDropsDisagree says how r1's filter captures fail to show the lab's two
// OSPF drop filters each dropping packets, or returns "". u32 keeps one set of
// hash tables per qdisc, so a dump of either clsact direction lists both
// filters, in hash tables 800: and 801:. The ingress and egress captures are
// that one listing taken twice and do not say which filter serves which
// direction, so no capture is read as one direction's. Each capture must hold
// exactly two actions, each the only action on its own filter, with its own
// index, matching IP protocol 89, dropping, and with a positive drop count, and
// both captures must put each action on the same filter.
func ospfDropsDisagree(captures ...[]tcFilter) string {
	var first map[int]string
	for _, fs := range captures {
		on := map[int]string{}
		for _, f := range fs {
			o := f.Options
			for _, a := range o.Actions {
				switch {
				// The u32 key matches the protocol byte, 8 bytes into the IPv4
				// header, against 0x59, which is 89, OSPF.
				case o.Match.Value != "590000" || o.Match.Mask != "ff0000" || o.Match.Off != 8:
					return "filter " + o.Fh + " does not match IP protocol 89"
				case a.Kind != "gact" || a.ControlAction.Type != "drop":
					return fmt.Sprintf("filter %s acts by %s %s, not a drop", o.Fh, a.Kind, a.ControlAction.Type)
				case a.Index <= 0 || o.Fh == "":
					return fmt.Sprintf("action %d on filter %q has no index or no filter", a.Index, o.Fh)
				case on[a.Index] != "":
					return fmt.Sprintf("action %d is on filters %s and %s", a.Index, on[a.Index], o.Fh)
				case slices.Contains(slices.Collect(maps.Values(on)), o.Fh):
					return "filter " + o.Fh + " holds more than one action"
				case a.Stats.Drops <= 0:
					return fmt.Sprintf("action %d on filter %s dropped nothing", a.Index, o.Fh)
				}
				on[a.Index] = o.Fh
			}
		}
		switch {
		case len(on) != 2:
			return fmt.Sprintf("a capture holds %d drop actions, want the 2 the lab installs", len(on))
		case first == nil:
			first = on
		case !maps.Equal(on, first):
			return fmt.Sprintf("the captures put the actions on filters %v and %v, so which action is which is ambiguous", first, on)
		}
	}
	return ""
}

// TestFRRAdjacencyDropCheckRefusesGaps edits fresh copies of the ecmp arm's
// filter captures in each way they could fail to show both OSPF drop filters
// at work, and ospfDropsDisagree must refuse every one. The check once summed
// the drops of every OSPF action, so a filter that dropped nothing passed
// whenever the other one dropped.
func TestFRRAdjacencyDropCheckRefusesGaps(t *testing.T) {
	read := func() [][]tcFilter {
		var c [][]tcFilter
		for _, dir := range []string{"ingress", "egress"} {
			var fs []tcFilter
			readJSONFile(t, filepath.Join(frrAdjacencyDir, "ecmp", "r1-after-tc_"+dir+".json"), &fs)
			c = append(c, fs)
		}
		return c
	}
	if why := ospfDropsDisagree(read()...); why != "" {
		t.Fatalf("the committed captures are refused: %s", why)
	}
	filter := func(fs []tcFilter, index int) *tcFilter {
		for i := range fs {
			if slices.ContainsFunc(fs[i].Options.Actions, func(a tcAction) bool { return a.Index == index }) {
				return &fs[i]
			}
		}
		t.Fatalf("no filter holds action %d", index)
		return nil
	}
	// both makes one edit to each capture, so the two still agree and only the
	// check of each capture on its own can refuse it.
	both := func(edit func(fs []tcFilter)) func(c [][]tcFilter) {
		return func(c [][]tcFilter) {
			for _, fs := range c {
				edit(fs)
			}
		}
	}
	edits := map[string]func(c [][]tcFilter){
		"action 1 has no index":         both(func(fs []tcFilter) { filter(fs, 1).Options.Actions[0].Index = 0 }),
		"action 1 has no filter handle": both(func(fs []tcFilter) { filter(fs, 1).Options.Fh = "" }),
		"action 2 renumbered to 1":      both(func(fs []tcFilter) { filter(fs, 2).Options.Actions[0].Index = 1 }),
		"both actions on one filter":    both(func(fs []tcFilter) { filter(fs, 2).Options.Fh = filter(fs, 1).Options.Fh }),
		"action 2 missing":              both(func(fs []tcFilter) { filter(fs, 2).Options.Actions = nil }),
		"action 2 matches TCP":          both(func(fs []tcFilter) { filter(fs, 2).Options.Match.Value = "060000" }),
		"action 2 passes":               both(func(fs []tcFilter) { filter(fs, 2).Options.Actions[0].ControlAction.Type = "pass" }),
		"a third filter repeats action 1": func(c [][]tcFilter) {
			for i := range c {
				f := *filter(c[i], 1)
				f.Options.Fh = "802::800"
				c[i] = append(c[i], f)
			}
		},
		"egress swaps the two filters": func(c [][]tcFilter) {
			f1, f2 := filter(c[1], 1), filter(c[1], 2)
			f1.Options.Fh, f2.Options.Fh = f2.Options.Fh, f1.Options.Fh
		},
	}
	for i, dir := range []string{"ingress", "egress"} {
		for _, index := range []int{1, 2} {
			edits[fmt.Sprintf("%s capture action %d dropped nothing", dir, index)] = func(c [][]tcFilter) {
				filter(c[i], index).Options.Actions[0].Stats.Drops = 0
			}
		}
	}
	for name, edit := range edits {
		c := read()
		edit(c)
		if why := ospfDropsDisagree(c...); why == "" {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("%s: %s", name, why)
		}
	}
}
