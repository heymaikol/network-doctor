package ospf

import (
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// The healthy node is r1 of the steady LSDB lab. Its captures bracket one stable
// state: A at lsdbT0, B at lsdbT0+3s, E at lsdbT0+6s, D at lsdbT0+15s. Its
// counters and checksums reconcile exactly.

var lsdbT0 = time.Date(2026, 10, 11, 2, 35, 0, 0, time.UTC)

func at(sec int) time.Time { return lsdbT0.Add(time.Duration(sec) * time.Second) }

func processState(source string, when time.Time) Process {
	return Process{
		Source: source, CollectedAt: when, RouterID: "1.1.1.1",
		HoldtimeMaxMs: 5000, SPFDelayMs: 0,
		External: Count{Number: 1, Checksum: 64412},
		Areas: map[string]Area{"0.0.0.0": {SPFExecuted: 5, Counts: map[LSAType]Count{
			LSARouter:  {Number: 2, Checksum: 52508},
			LSANetwork: {Number: 2, Checksum: 69491},
		}}},
	}
}

func routerLSA(adv string, age, checksum uint64, stubs ...string) LSA {
	l := LSA{Area: "0.0.0.0", Type: LSARouter, LinkStateID: adv, AdvertisingRouter: adv,
		Age: age, Sequence: "80000008", Checksum: checksum}
	for _, s := range stubs {
		l.Prefixes = append(l.Prefixes, Prefix{Prefix: netip.MustParsePrefix(s)})
	}
	return l
}

func networkLSA(lsid, adv string, age, checksum uint64) LSA {
	return LSA{Area: "0.0.0.0", Type: LSANetwork, LinkStateID: lsid, AdvertisingRouter: adv,
		Age: age, Sequence: "80000001", Checksum: checksum}
}

func externalLSA(prefix, adv string, age, checksum, metric uint64) LSA {
	p := netip.MustParsePrefix(prefix)
	m := metric
	return LSA{Type: LSAExternal, LinkStateID: p.Addr().String(), AdvertisingRouter: adv,
		Age: age, Sequence: "80000001", Checksum: checksum, Metric: &m,
		Prefixes: []Prefix{{Prefix: p}}}
}

func route(prefix, kind string, cost uint64) Route {
	return Route{Prefix: netip.MustParsePrefix(prefix), RouteType: kind, Cost: cost, NextHops: 1}
}

// healthy is the steady r1 bracket.
func healthy() NodeInput {
	return NodeInput{
		Node: "r1", VRF: "default",
		Processes: []Process{processState("r1-A", at(0)), processState("r1-D", at(15))},
		LSDB: &LSDB{Source: "r1-B", CollectedAt: at(3), RouterID: "1.1.1.1", LSAs: []LSA{
			routerLSA("1.1.1.1", 49, 0xad52, "10.0.1.0/24", "10.10.1.0/24"),
			routerLSA("2.2.2.2", 110, 0x1fca, "10.10.2.0/24"),
			networkLSA("10.0.1.1", "1.1.1.1", 49, 0xe564),
			networkLSA("10.0.1.2", "2.2.2.2", 110, 0x2a0f),
			externalLSA("10.20.0.0/24", "2.2.2.2", 150, 0xfb9c, 20),
		}},
		Routes: &Routes{Source: "r1-E", CollectedAt: at(6), Known: true, Routers: 1, Entries: []Route{
			route("10.0.1.0/24", "N", 10),
			route("10.10.1.0/24", "N", 10),
			route("10.10.2.0/24", "N", 20),
			{Prefix: netip.MustParsePrefix("10.20.0.0/24"), RouteType: "N E2", Cost: 10, Type2Cost: ptr(20), NextHops: 1},
		}},
	}
}

func ptr(v uint64) *uint64 { return &v }

// killed is the kill9 bracket of r1, after r2 was SIGKILLed. r2's router and
// network LSAs stay in the LSDB, but its prefixes are gone from the route table.
// The network LSA 10.0.1.1 of r1 is at MaxAge and still counted.
func killed() NodeInput {
	n := healthy()
	n.LSDB.LSAs[2] = networkLSA("10.0.1.1", "1.1.1.1", 3600, 0xe564)
	n.Routes.Entries = n.Routes.Entries[:2]
	return n
}

// TestHugeTimersCannotWrapTheWindowBound checks a capture whose timers would
// wrap the window bound. Both holdtimes at MaxUint64 plus a 2ms SPF delay sum to
// 1ms in uint64. An unclamped bound would fall to the one-second floor, and the
// 15-second window would pass the guard.
func TestHugeTimersCannotWrapTheWindowBound(t *testing.T) {
	n := killed()
	for i := range n.Processes {
		n.Processes[i].HoldtimeMaxMs = math.MaxUint64
		n.Processes[i].SPFDelayMs = 2
	}
	rep := findingsOf(t, n)
	if rep.Guard.Passed {
		t.Fatal("guard passed with timers that wrap the window bound")
	}
	if got := strings.Join(rep.Guard.Reasons, "; "); !strings.Contains(got, "does not exceed") {
		t.Fatalf("reasons = %q; want the window bound named", got)
	}
}

// findingsOf returns the report's findings for node r1, or fails the test if the
// report holds a different node.
func findingsOf(t *testing.T, in NodeInput) NodeReport {
	t.Helper()
	rep := CompareLSDB([]NodeInput{in})
	if len(rep.Nodes) != 1 {
		t.Fatalf("got %d nodes; want 1", len(rep.Nodes))
	}
	return rep.Nodes[0]
}

// kinds lists each finding as its kind, then the area, scope, type, and prefix
// it has, skipping the empty ones, for exact comparison.
func kinds(fs []LSDBFinding) []string {
	var out []string
	for _, f := range fs {
		var parts []string
		for _, v := range []string{string(f.Kind), f.Area, f.Scope, string(f.Type), f.Prefix} {
			if v != "" {
				parts = append(parts, v)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func TestHealthyBracketHasNoFindings(t *testing.T) {
	rep := findingsOf(t, healthy())
	if !rep.Guard.Passed {
		t.Fatalf("guard failed: %v", rep.Guard.Reasons)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("findings = %v; want none", kinds(rep.Findings))
	}
	for _, r := range rep.Reconciliation {
		if !r.Matched {
			t.Errorf("reconciliation %s %s did not match", r.Area, r.Type)
		}
	}
}

func TestKilledNeighborGivesExactFindingSet(t *testing.T) {
	rep := findingsOf(t, killed())
	if !rep.Guard.Passed {
		t.Fatalf("guard failed: %v", rep.Guard.Reasons)
	}
	want := []string{
		"lsdb_prefix_not_calculated external 10.20.0.0/24",
		"lsdb_prefix_not_calculated 0.0.0.0 router 10.10.2.0/24",
	}
	if got := kinds(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings = %q; want %q", got, want)
	}
	for _, f := range rep.Findings {
		if f.Strength != ConsistentWith {
			t.Errorf("%s strength = %s; want %s", f.Prefix, f.Strength, ConsistentWith)
		}
		if f.AdvertisingRouter != "2.2.2.2" {
			t.Errorf("%s advertised by %s; want 2.2.2.2", f.Prefix, f.AdvertisingRouter)
		}
		if f.Source != "r1-B" {
			t.Errorf("%s source = %q; want the LSDB capture", f.Prefix, f.Source)
		}
	}
}

func TestMaxAgeStubAndExternalAreNotCompared(t *testing.T) {
	n := killed()
	// 2.2.2.2's stub and external are withdrawn: MaxAge, so not compared.
	n.LSDB.LSAs[1] = routerLSA("2.2.2.2", 3600, 0x1fca, "10.10.2.0/24")
	n.LSDB.LSAs[4] = externalLSA("10.20.0.0/24", "2.2.2.2", 3600, 0xfb9c, 20)
	rep := findingsOf(t, n)
	if len(rep.Findings) != 0 {
		t.Fatalf("findings = %v; want none for MaxAge advertisements", kinds(rep.Findings))
	}
	var facts []string
	for _, l := range rep.LSAs {
		facts = append(facts, l.Use)
	}
	if !slices.Contains(facts, "not compared: MaxAge") {
		t.Fatalf("uses = %q; want MaxAge exclusion recorded as a fact", facts)
	}
}

func TestSelfOriginatedExternalIsNotCompared(t *testing.T) {
	n := healthy()
	// r1's own AS-external LSA is not in its route table, and must not be a finding.
	n.LSDB.LSAs[4] = externalLSA("10.30.0.0/24", "1.1.1.1", 150, 0xfb9c, 20)
	rep := findingsOf(t, n)
	if len(rep.Findings) != 0 {
		t.Fatalf("findings = %v; want none for a self-originated Type 5", kinds(rep.Findings))
	}
	for _, f := range rep.LSAs {
		if f.Type == LSAExternal && !strings.Contains(f.Use, "self-originated") {
			t.Fatalf("use = %q; want the self-originated exclusion", f.Use)
		}
	}
}

func TestInfiniteMetricExternalIsNotCompared(t *testing.T) {
	n := killed()
	n.LSDB.LSAs[4] = externalLSA("10.20.0.0/24", "2.2.2.2", 150, 0xfb9c, 0xffffff)
	rep := findingsOf(t, n)
	for _, f := range rep.Findings {
		if f.Type == LSAExternal {
			t.Fatalf("finding %v for an LSInfinity Type 5; want none", f)
		}
	}
}

func TestOwnStubMissingFromRoutesIsAFinding(t *testing.T) {
	// A router's own stub links are directly attached routes. Missing one is a
	// finding, and so is a missing one from another router.
	n := healthy()
	n.Routes.Entries = n.Routes.Entries[1:]
	rep := findingsOf(t, n)
	if got := kinds(rep.Findings); !slices.Contains(got, "lsdb_prefix_not_calculated 0.0.0.0 router 10.0.1.0/24") {
		t.Fatalf("findings = %q; want the missing own stub", got)
	}
}

func TestType2Type3Type4AreReportedButNotCompared(t *testing.T) {
	n := healthy()
	n.LSDB.LSAs = append(n.LSDB.LSAs,
		LSA{Area: "0.0.0.0", Type: LSASummary, LinkStateID: "10.30.0.0", AdvertisingRouter: "2.2.2.2",
			Age: 30, Sequence: "80000001", Checksum: 0x1, Prefixes: []Prefix{{Prefix: netip.MustParsePrefix("10.30.0.0/24")}}},
		LSA{Area: "0.0.0.0", Type: LSAASBRSummary, LinkStateID: "2.2.2.2", AdvertisingRouter: "2.2.2.2", Age: 30, Sequence: "80000001", Checksum: 0x2},
	)
	// Summary and ASBR-summary sections are counted by the process state too.
	n.Processes[0].Areas["0.0.0.0"] = Area{SPFExecuted: 5, Counts: map[LSAType]Count{
		LSARouter: {2, 52508}, LSANetwork: {2, 69491}, LSASummary: {1, 1}, LSAASBRSummary: {1, 2},
	}}
	n.Processes[1].Areas["0.0.0.0"] = n.Processes[0].Areas["0.0.0.0"]
	rep := findingsOf(t, n)
	if len(rep.Findings) != 0 {
		t.Fatalf("findings = %v; want none from Type 3 or Type 4", kinds(rep.Findings))
	}
	for _, f := range rep.LSAs {
		if f.Type == LSASummary && f.Use != "reported only: this type is not compared" {
			t.Fatalf("summary use = %q", f.Use)
		}
	}
}

func TestGuardRefusesCounterChangeAndNamesSPFOnlyWhenItMoved(t *testing.T) {
	n := healthy()
	n.Processes[1].Areas["0.0.0.0"] = Area{SPFExecuted: 6, Counts: n.Processes[0].Areas["0.0.0.0"].Counts}
	rep := findingsOf(t, n)
	if rep.Guard.Passed {
		t.Fatal("guard passed with a changed SPF counter")
	}
	joined := strings.Join(rep.Guard.Reasons, "; ")
	if !strings.Contains(joined, "the SPF counter of area 0.0.0.0 changed from 5 to 6") {
		t.Fatalf("reasons = %q; want the SPF counter change", joined)
	}
	if got := kinds(rep.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "ospf_comparison_unverified") {
		t.Fatalf("findings = %q; want only ospf_comparison_unverified", got)
	}
}

func TestGuardChecksLinkChangeWithoutCallingItSPF(t *testing.T) {
	n := healthy()
	n.Processes[1].Areas["0.0.0.0"] = Area{SPFExecuted: 5, Counts: map[LSAType]Count{
		LSARouter: {2, 1}, LSANetwork: {2, 69491},
	}}
	rep := findingsOf(t, n)
	joined := strings.Join(rep.Guard.Reasons, "; ")
	if strings.Contains(joined, "SPF counter") {
		t.Fatalf("reasons = %q; the SPF counter did not move, so it must not be named", joined)
	}
	if !strings.Contains(joined, "the router LSA count or checksum of area 0.0.0.0 changed") {
		t.Fatalf("reasons = %q; want the checksum change", joined)
	}
}

func TestGuardOrderAndTies(t *testing.T) {
	cases := map[string]func(*NodeInput){
		"B tied with A": func(n *NodeInput) { n.LSDB.CollectedAt = at(0) },
		"E before B":    func(n *NodeInput) { n.Routes.CollectedAt = at(2) },
		"E after D":     func(n *NodeInput) { n.Routes.CollectedAt = at(20) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			n := healthy()
			edit(&n)
			rep := findingsOf(t, n)
			if rep.Guard.Passed || !strings.Contains(strings.Join(rep.Guard.Reasons, ";"), "out of order or tied") {
				t.Fatalf("guard = %+v; want an order failure", rep.Guard)
			}
		})
	}
}

func TestGuardWindowMustExceedTheLargerTimerBound(t *testing.T) {
	n := healthy()
	n.Processes[1].CollectedAt = at(5) // window 5s, bound 5000ms: not longer
	n.Routes.CollectedAt = at(2)
	rep := findingsOf(t, n)
	if rep.Guard.Passed || !strings.Contains(strings.Join(rep.Guard.Reasons, ";"), "does not exceed the 5000ms timer bound") {
		t.Fatalf("guard = %+v; want a window failure", rep.Guard)
	}

	// A and D hold the same timers, so the bound is their 20000 ms holdtime. The
	// timers are equal, so only the bound is in question.
	m := healthy()
	m.Processes[0].HoldtimeMaxMs = 20000
	m.Processes[1].HoldtimeMaxMs = 20000
	m.Processes[1].CollectedAt = at(15)
	m.Processes[0].Areas = m.Processes[1].Areas
	rep = findingsOf(t, m)
	if rep.Guard.Passed || !strings.Contains(strings.Join(rep.Guard.Reasons, ";"), "20000ms timer bound") {
		t.Fatalf("guard = %+v; want D's larger timer used", rep.Guard)
	}
}

// TestGuardWithholdsOnChangedTimers changes one timer between A and D. The window
// is longer than both bounds, and the counters and checksums match, so the timer
// change is the only reason to withhold. The reason names the timer. It does not
// say that SPF ran, because a configuration change alone does not show that.
func TestGuardWithholdsOnChangedTimers(t *testing.T) {
	cases := map[string]struct {
		edit   func(*Process)
		reason string
	}{
		"holdtime maximum": {
			func(d *Process) { d.HoldtimeMaxMs = 10000 },
			"the holdtime maximum changed from 5000 ms to 10000 ms between A and D",
		},
		"SPF delay": {
			func(d *Process) { d.SPFDelayMs = 200 },
			"the SPF delay changed from 0 ms to 200 ms between A and D",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			n := healthy()
			c.edit(&n.Processes[1])
			rep := findingsOf(t, n)
			if rep.Guard.Passed {
				t.Fatal("guard passed with a changed timer")
			}
			if got := strings.Join(rep.Guard.Reasons, "; "); !strings.Contains(got, c.reason) {
				t.Fatalf("reasons = %q; want %q", got, c.reason)
			}
			if got := kinds(rep.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "ospf_comparison_unverified") {
				t.Fatalf("findings = %q; want only ospf_comparison_unverified", got)
			}
		})
	}
}

func TestGuardNotRunningIsUnknownNotEmpty(t *testing.T) {
	n := healthy()
	n.Processes[0].RouterID = ""
	n.Processes[0].Areas = nil
	rep := findingsOf(t, n)
	if rep.Guard.Passed {
		t.Fatal("guard passed for a process state with no router ID")
	}
	if got := kinds(rep.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "ospf_comparison_unverified") {
		t.Fatalf("findings = %q; want only the unverified finding", got)
	}
	if len(rep.LSAs) == 0 {
		t.Fatal("LSA facts dropped with the guard; they are still evidence")
	}
}

func TestGuardNeedsTwoProcessStates(t *testing.T) {
	for name, procs := range map[string][]Process{
		"none": nil,
		"one":  {processState("r1-A", at(0))},
	} {
		t.Run(name, func(t *testing.T) {
			n := healthy()
			n.Processes = procs
			rep := findingsOf(t, n)
			if rep.Guard.Passed {
				t.Fatal("guard passed without two process states")
			}
			if len(rep.Reconciliation) != 0 {
				t.Fatal("reconciled against a process state that is missing")
			}
			if got := kinds(rep.Findings); len(got) != 1 || !strings.HasPrefix(got[0], "ospf_comparison_unverified") {
				t.Fatalf("findings = %q", got)
			}
		})
	}
}

func TestSameTimeProcessPairHasNoOrder(t *testing.T) {
	n := healthy()
	n.Processes[1].CollectedAt = at(0)
	rep := findingsOf(t, n)
	if rep.Guard.Passed || !strings.Contains(strings.Join(rep.Guard.Reasons, ";"), "order is unknown") {
		t.Fatalf("guard = %+v", rep.Guard)
	}
	if len(rep.Reconciliation) != 0 {
		t.Fatal("reconciled against one of two captures whose order is unknown")
	}
}

func TestMismatchScopesToItsAreaAndType(t *testing.T) {
	n := killed()
	// Drop one router LSA from area 0.0.0.0: the router type no longer matches.
	// External still matches, so its finding remains.
	n.LSDB.LSAs = slices.DeleteFunc(n.LSDB.LSAs, func(l LSA) bool { return l.LinkStateID == "2.2.2.2" && l.Type == LSARouter })
	rep := findingsOf(t, n)
	got := kinds(rep.Findings)
	if !slices.Contains(got, "lsdb_incomplete 0.0.0.0 router") {
		t.Fatalf("findings = %q; want lsdb_incomplete for router in 0.0.0.0", got)
	}
	if slices.Contains(got, "lsdb_prefix_not_calculated 0.0.0.0 router 10.10.2.0/24") {
		t.Fatal("a router finding survived its reconciliation mismatch")
	}
	if !slices.Contains(got, "lsdb_prefix_not_calculated external 10.20.0.0/24") {
		t.Fatalf("findings = %q; the external finding must survive an unrelated mismatch", got)
	}
}

func TestAreaMissingFromProcessStateIsIncomplete(t *testing.T) {
	n := healthy()
	n.LSDB.LSAs = append(n.LSDB.LSAs, LSA{Area: "0.0.0.1", Type: LSANetwork, LinkStateID: "10.40.0.1",
		AdvertisingRouter: "3.3.3.3", Age: 20, Sequence: "80000001", Checksum: 0x9})
	rep := findingsOf(t, n)
	if got := kinds(rep.Findings); !slices.Contains(got, "lsdb_incomplete 0.0.0.1 network") {
		t.Fatalf("findings = %q; want lsdb_incomplete for the unknown area", got)
	}
}

func TestRouterIDMismatchBlocksTheNode(t *testing.T) {
	n := killed()
	n.LSDB.RouterID = "9.9.9.9"
	rep := findingsOf(t, n)
	got := kinds(rep.Findings)
	if !slices.Contains(got, "lsdb_incomplete router-id") {
		t.Fatalf("findings = %q; want the router ID mismatch", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "lsdb_prefix_not_calculated") {
			t.Fatalf("findings = %q; no prefix finding may come from a mismatched LSDB", got)
		}
	}
}

func TestUnknownContentBlocksItsScope(t *testing.T) {
	n := killed()
	n.LSDB.Unknown = []UnknownContent{{Section: "futureLsa"}}
	rep := findingsOf(t, n)
	got := kinds(rep.Findings)
	if !slices.Contains(got, "lsdb_incomplete futureLsa") {
		t.Fatalf("findings = %q; want lsdb_incomplete for the unknown section", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "lsdb_prefix_not_calculated") {
			t.Fatalf("findings = %q; a VRF-wide unknown section must block prefix findings", got)
		}
	}
}

func TestEmptyRouteTableIsUnknownNotAbsent(t *testing.T) {
	n := killed()
	n.Routes = &Routes{Source: "r1-E", CollectedAt: at(6), Known: false}
	rep := findingsOf(t, n)
	got := kinds(rep.Findings)
	if !slices.Contains(got, "lsdb_incomplete routes") {
		t.Fatalf("findings = %q; want lsdb_incomplete for the empty table", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "lsdb_prefix_not_calculated") {
			t.Fatalf("findings = %q; an empty object must not make every prefix absent", got)
		}
	}
}

func TestMissingRouteCaptureWithdrawsComparison(t *testing.T) {
	n := killed()
	n.Routes = nil
	rep := findingsOf(t, n)
	if rep.Guard.Passed || !strings.Contains(strings.Join(rep.Guard.Reasons, ";"), "no readable calculated-route capture") {
		t.Fatalf("guard = %+v", rep.Guard)
	}
	for _, f := range rep.Findings {
		if f.Kind == KindPrefixNotCalculated {
			t.Fatalf("finding %v without a route capture", f)
		}
	}
}

func TestRefusedCapturesBecomeIncompleteEvidence(t *testing.T) {
	n := killed()
	n.Refused = []Refusal{{Kind: "lsdb", Source: "r1-B", Reason: "malformed"}}
	n.LSDB = nil
	rep := findingsOf(t, n)
	got := kinds(rep.Findings)
	if !slices.Contains(got, "lsdb_incomplete lsdb") {
		t.Fatalf("findings = %q; want lsdb_incomplete for the refused LSDB", got)
	}
}

func TestOutputDoesNotDependOnInputOrder(t *testing.T) {
	a := killed()
	b := killed()
	b.Node, b.VRF = "r2", "default"
	b.Processes[0], b.Processes[1] = b.Processes[1], b.Processes[0]
	slices.Reverse(b.LSDB.LSAs)

	first := mustJSON(t, CompareLSDB([]NodeInput{a, b}))
	second := mustJSON(t, CompareLSDB([]NodeInput{b, a}))
	if first != second {
		t.Fatalf("report depends on input order:\n%s\n---\n%s", first, second)
	}
}

func TestFindingTextNamesNoCause(t *testing.T) {
	rep := CompareLSDB([]NodeInput{killed()})
	for _, n := range rep.Nodes {
		for _, f := range n.Findings {
			for _, banned := range []string{"installed", "FIB", "unreachable", "filter", "stale", "down"} {
				if strings.Contains(f.Detail+f.Limit, banned) {
					t.Errorf("finding text %q names %q", f.Detail, banned)
				}
			}
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
