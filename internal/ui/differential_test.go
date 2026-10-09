// Differential oracle: headless diagnostic.RunAll and TUI Update/scheduleStep
// are two executors of the same probe-DAG semantics. This file sends identical synthetic graphs through both
// and compares the finalized diagnostic results, so the two can never drift
// apart unnoticed. It compares outcomes only, never queues, counters,
// goroutines, launch order, or tea messages.

package ui

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// diffProbe is a deterministic in-memory probe: no network, no subprocess, no
// clock. Its Detail records the exact dependency snapshot the executor handed
// it, so an executor that passed different dep results, or a different number
// of them, shows up as a compared-output difference instead of hiding behind
// an identical status.
func diffProbe(id diagnostic.ProbeID, status diagnostic.Status, deps ...diagnostic.ProbeID) diagnostic.Probe {
	return diagnostic.Probe{
		ID:   id,
		Name: string(id),
		Deps: deps,
		Run: func(_ context.Context, snap map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			seen := make([]string, 0, len(deps))
			for _, d := range deps {
				seen = append(seen, fmt.Sprintf("%s=%v", d, snap[d].Status))
			}
			return diagnostic.ProbeResult{
				Status: status,
				Detail: fmt.Sprintf("%s ran with %d dep(s) [%s]", id, len(snap), strings.Join(seen, " ")),
				Fix:    "fix-" + string(id),
			}
		},
	}
}

// canonicalResults renders finalized results as stable text keyed by probe ID.
// Sorting by ID normalizes the one genuinely non-semantic difference between
// the executors, the order results land in a map, and nothing else: every
// remaining field of every ProbeResult is printed, unexported fields included
// (%+v reaches them), so a real disagreement cannot be normalized away.
//
// Dur is the only excluded field: it is measured wall time, not a diagnostic
// outcome. Families/Portal are printed through their pointers because %+v
// would otherwise render nondeterministic addresses.
func canonicalResults(res map[diagnostic.ProbeID]diagnostic.ProbeResult) string {
	var b strings.Builder
	for _, id := range slices.Sorted(maps.Keys(res)) {
		r := res[id]
		r.Dur = 0
		families, portal := r.Families, r.Portal
		r.Families, r.Portal = nil, nil
		fmt.Fprintf(&b, "%s %+v families=%+v portal=%+v\n", id, r, families, portal)
	}
	return b.String()
}

// runTUIScheduler drives the real TUI scheduler to completion through its
// narrowest real entry point: the scheduleMsg that Init sends, then Update on
// every message the resulting commands produce. Commands are drained
// synchronously, so completion is reached by running out of work rather than
// by sleeping, with no timing, no extra synchronization, and no copy of the
// scheduling algorithm.
//
// lifo picks which pending command runs next. Real Bubble Tea runs a batch's
// commands on their own goroutines, so probes may finish in any order; draining
// oldest-first makes completion order equal dispatch order, while newest-first
// reaches the orders dispatch order cannot produce: a probe finishing ahead of
// an earlier-launched straggler. Both are legal executions of the same batch,
// and both are deterministic.
func runTUIScheduler(t *testing.T, probes []diagnostic.Probe, lifo bool) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	t.Helper()
	m := newModel(nil, false)
	m.probes = probes
	m.results = map[diagnostic.ProbeID]diagnostic.ProbeResult{}
	m.started = map[diagnostic.ProbeID]bool{}

	return driveTUIScheduler(t, m, lifo).results
}

func driveTUIScheduler(t *testing.T, m model, lifo bool) model {
	t.Helper()
	var cur tea.Model = m
	queue := []tea.Cmd{func() tea.Msg { return scheduleMsg{gen: m.generation} }}
	for len(queue) > 0 {
		i := 0
		if lifo {
			i = len(queue) - 1
		}
		cmd := queue[i]
		queue = slices.Delete(queue, i, i+1)
		if cmd == nil {
			continue
		}
		switch msg := cmd().(type) {
		case nil:
		case tea.BatchMsg:
			queue = append(queue, msg...)
		default:
			var next tea.Cmd
			cur, next = cur.Update(msg)
			queue = append(queue, next)
		}
	}
	return asModel(t, cur)
}

// TestExecutorsAgree is the regression oracle. Every case is a probe graph both
// executors must finalize identically. Real probe IDs are used so Finalize's
// cross-probe passes (the egress downgrade in particular) are live rather than
// no-ops on invented IDs.
func TestExecutorsAgree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probes []diagnostic.Probe
	}{
		// Linear iface -> dns -> target_tcp: results flow down a chain and both
		// executors unlock each rung only after the one above it has a result.
		{"linear", []diagnostic.Probe{
			diffProbe(diagnostic.ProbeIface, diagnostic.StatusPass),
			diffProbe(diagnostic.ProbeDNS, diagnostic.StatusPass, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeTargetTCP, diagnostic.StatusPass, diagnostic.ProbeDNS),
		}},

		// Diamond: iface fans out to two arms that rejoin at target_tcp, which
		// must wait for both. The arms also carry the two non-blocking statuses
		// (WARN, N/A), so the join proves neither prunes the shared dependent.
		{"diamond shared prerequisite", []diagnostic.Probe{
			diffProbe(diagnostic.ProbeIface, diagnostic.StatusPass),
			diffProbe(diagnostic.ProbeInternet, diagnostic.StatusWarn, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeDNS, diagnostic.StatusNA, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeTargetTCP, diagnostic.StatusPass, diagnostic.ProbeInternet, diagnostic.ProbeDNS),
		}},

		// A prerequisite FAILs: its dependents must reach SkipPrereq, and the
		// grandchild must too, without either executor running them.
		{"failed prerequisite", []diagnostic.Probe{
			diffProbe(diagnostic.ProbeIface, diagnostic.StatusPass),
			diffProbe(diagnostic.ProbeDNS, diagnostic.StatusFail, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeTargetTCP, diagnostic.StatusPass, diagnostic.ProbeDNS),
			diffProbe(diagnostic.ProbeTLS, diagnostic.StatusPass, diagnostic.ProbeTargetTCP),
		}},

		// Skip, the repository's own meaning: the probe itself reports SKIP
		// (nothing to measure) rather than failing a diagnosis. That blocks
		// dependents exactly like a failure, and the cascade must reach three
		// levels down in one pass in both executors.
		{"skip cascade", []diagnostic.Probe{
			diffProbe(diagnostic.ProbeIface, diagnostic.StatusPass),
			diffProbe(diagnostic.ProbeDNS, diagnostic.StatusSkip, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeTargetTCP, diagnostic.StatusPass, diagnostic.ProbeDNS),
			diffProbe(diagnostic.ProbeTLS, diagnostic.StatusPass, diagnostic.ProbeTargetTCP),
			diffProbe(diagnostic.ProbeHTTPS, diagnostic.StatusPass, diagnostic.ProbeTLS),
		}},

		// One arm fails while an independent arm stays runnable and completes.
		// This graph is also the live Finalize case: internet_tcp FAILs but
		// target_tcp works, so the egress downgrade must rewrite it to WARN in
		// both executors, not just in whichever one remembered to call
		// Finalize.
		{"independent failure", []diagnostic.Probe{
			diffProbe(diagnostic.ProbeIface, diagnostic.StatusPass),
			diffProbe(diagnostic.ProbeInternet, diagnostic.StatusFail, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeQUIC, diagnostic.StatusPass, diagnostic.ProbeInternet),
			diffProbe(diagnostic.ProbeDNS, diagnostic.StatusPass, diagnostic.ProbeIface),
			diffProbe(diagnostic.ProbeTargetTCP, diagnostic.StatusPass, diagnostic.ProbeDNS),
		}},

		{"mixed successful parents", []diagnostic.Probe{
			diffProbe("pass", diagnostic.StatusPass),
			diffProbe("warn", diagnostic.StatusWarn),
			diffProbe("na", diagnostic.StatusNA),
			diffProbe("join", diagnostic.StatusPass, "pass", "warn", "na"),
		}},
		{"multiple parents with failure", []diagnostic.Probe{
			diffProbe("pass", diagnostic.StatusPass),
			diffProbe("warn", diagnostic.StatusWarn),
			diffProbe("na", diagnostic.StatusNA),
			diffProbe("fail", diagnostic.StatusFail),
			diffProbe("join", diagnostic.StatusPass, "pass", "warn", "na", "fail"),
			diffProbe("tail", diagnostic.StatusPass, "join"),
		}},
		{"unknown dependency", []diagnostic.Probe{
			diffProbe("root", diagnostic.StatusPass),
			diffProbe("pending", diagnostic.StatusPass, "missing"),
		}},
		{"cycle", []diagnostic.Probe{
			diffProbe("root", diagnostic.StatusPass),
			diffProbe("a", diagnostic.StatusPass, "b"),
			diffProbe("b", diagnostic.StatusPass, "a"),
		}},
		{"duplicate ID and edge", []diagnostic.Probe{
			diffProbe("a", diagnostic.StatusFail, "missing"),
			diffProbe("a", diagnostic.StatusWarn),
			diffProbe("b", diagnostic.StatusPass, "a", "a"),
		}},
		// Nothing selected: both executors must finalize an empty run without
		// hanging or inventing a result.
		{"empty selection", nil},
	} {
		// Each graph runs in two probe orders and two completion orders.
		//
		// Reversed probe order is what makes both executors' scheduling
		// readiness propagation load-bearing: topological order already cascades
		// in one pass, so broken propagation would go unnoticed. Slice order is not
		// itself a result contract; it is an input both executors receive
		// identically.
		//
		// The drain order varies which probe finishes first, since RunAll's
		// goroutines and the TUI's batched commands both complete in an order
		// neither executor controls. It is currently non-semantic, since DepsState
		// reports a probe ready only once every dependency has a result, so no
		// dispatch or skip decision can be made from a partial view, but that
		// is the property being pinned, not assumed.
		reversed := slices.Clone(tc.probes)
		slices.Reverse(reversed)
		for _, order := range []struct {
			name   string
			probes []diagnostic.Probe
		}{{"declared", tc.probes}, {"reversed", reversed}} {
			for _, drain := range []struct {
				name string
				lifo bool
			}{{"oldest-first", false}, {"newest-first", true}} {
				t.Run(tc.name+"/"+order.name+"/"+drain.name, func(t *testing.T) {
					headless := canonicalResults(diagnostic.RunAll(context.Background(), order.probes, diagnostic.DefaultProbeTimeout))
					tui := canonicalResults(runTUIScheduler(t, order.probes, drain.lifo))
					if headless != tui {
						t.Errorf("executors disagree on %q (%s probe order, %s completion)\nRunAll:\n%s\nTUI:\n%s",
							tc.name, order.name, drain.name, headless, tui)
					}
				})
			}
		}
	}
}
