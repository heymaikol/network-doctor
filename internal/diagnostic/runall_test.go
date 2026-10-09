// Headless RunAll: DAG completion with the skip cascade, and the egress
// downgrade applied at the end.

package diagnostic

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func staticProbe(id ProbeID, deps []ProbeID, status Status) Probe {
	return Probe{ID: id, Name: string(id), Deps: deps, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		return ProbeResult{Status: status}
	}}
}

func TestRunAll(t *testing.T) {
	probes := []Probe{
		staticProbe("a", nil, StatusPass),
		staticProbe("b", []ProbeID{"a"}, StatusFail),
		staticProbe("c", []ProbeID{"b"}, StatusPass), // must be skipped: b failed
		staticProbe("d", []ProbeID{"a"}, StatusPass),
	}
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	if len(res) != len(probes) {
		t.Fatalf("got %d results, want %d", len(res), len(probes))
	}
	want := map[ProbeID]Status{"a": StatusPass, "b": StatusFail, "c": StatusSkip, "d": StatusPass}
	for id, st := range want {
		if res[id].Status != st {
			t.Errorf("probe %s = %v, want %v", id, res[id].Status, st)
		}
	}
	if res["c"].ID != "c" {
		t.Errorf("skip result ID = %q, want c", res["c"].ID)
	}
}

// blockUntilDone stands in for a probe that never returns on its own: it
// reports whether the runner handed it a deadline, then waits for the context
// to end the run for it. Every probe in the real DAG trusts the runner for this
// bound, so a runner that forgot to set one would hang here instead of passing.
func blockUntilDone(id ProbeID, deps []ProbeID) Probe {
	return Probe{ID: id, Name: string(id), Deps: deps, Run: func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		if _, ok := ctx.Deadline(); !ok {
			return ProbeResult{Status: StatusFail, Detail: "no deadline"}
		}
		<-ctx.Done()
		return ProbeResult{Status: StatusFail, Detail: ctx.Err().Error()}
	}}
}

// The bounded-time guarantee, headless half: every probe runs under its own
// timeout, dependents included: they get a fresh deadline, not what's left of
// their parent's.
func TestRunAllBoundsEveryProbe(t *testing.T) {
	const timeout = 20 * time.Millisecond
	// "b" depends on a WARN so it runs rather than skipping: only a probe that
	// actually starts can prove it got a deadline of its own.
	probes := []Probe{
		blockUntilDone("a", nil),
		staticProbe("warn", nil, StatusWarn),
		blockUntilDone("b", []ProbeID{"warn"}),
	}
	start := time.Now()
	res := RunAll(context.Background(), probes, timeout)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("RunAll took %v with a %v probe timeout", elapsed, timeout)
	}
	for _, id := range []ProbeID{"a", "b"} {
		if got := res[id].Detail; got != context.DeadlineExceeded.Error() {
			t.Errorf("probe %s detail = %q, want %q", id, got, context.DeadlineExceeded)
		}
	}
}

// A cancelled parent (Ctrl-C, or -json watch shutting down) must reach the
// probes: the per-probe timeout is a child of it, never a detached context.
func TestRunAllPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := RunAll(ctx, []Probe{blockUntilDone("a", nil)}, DefaultProbeTimeout)
	if got := res["a"].Detail; got != context.Canceled.Error() {
		t.Errorf("detail = %q, want %q", got, context.Canceled)
	}
}

// RunAll runs Finalize on its way out, so the egress downgrade reaches --json
// and the TUI through it. What it takes to earn one is the interesting half: a
// public address answered a direct connection, and a resolver answering did
// not.
func TestRunAllDowngradesEgress(t *testing.T) {
	base := []Probe{
		staticProbe(ProbeIface, nil, StatusPass),
		staticProbe(ProbeInternet, []ProbeID{ProbeIface}, StatusFail),
		staticProbe(ProbeDNS, []ProbeID{ProbeIface}, StatusPass),
	}
	reached := Probe{ID: ProbeTargetTCP, Deps: []ProbeID{ProbeIface}, Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		return ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP("93.184.216.34")}
	}}
	res := RunAll(context.Background(), append(append([]Probe(nil), base...), reached), DefaultProbeTimeout)
	if res[ProbeInternet].Status != StatusWarn {
		t.Errorf("internet = %v, want WARN (a public address answered directly)", res[ProbeInternet].Status)
	}
	res = RunAll(context.Background(), base, DefaultProbeTimeout)
	if res[ProbeInternet].Status != StatusFail {
		t.Errorf("internet = %v, want FAIL (a resolver answering is not egress)", res[ProbeInternet].Status)
	}
}

// The probe budget belongs to the RunAll call, not to the package. The measured
// probe in each run is a dependent, so its context is built only after both runs
// are already underway: that is the window a package-level timeout leaks
// through, since the second run's value would be the one standing when the first
// run's dependent is finally launched. Nothing here sleeps, the barrier is what
// makes the overlap deterministic.
func TestRunAllTimeoutIsPerRun(t *testing.T) {
	const short, long = 2 * time.Second, time.Hour

	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()

	run := func(timeout time.Duration, budget chan<- time.Duration) {
		gate := Probe{ID: "gate", Name: "gate", Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			arrived.Done()
			<-both
			return ProbeResult{Status: StatusPass}
		}}
		measure := Probe{ID: "measure", Name: "measure", Deps: []ProbeID{"gate"}, Run: func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
			dl, ok := ctx.Deadline()
			if !ok {
				budget <- 0 // no deadline at all fails both bounds below
				return ProbeResult{Status: StatusFail}
			}
			budget <- time.Until(dl)
			return ProbeResult{Status: StatusPass}
		}}
		RunAll(context.Background(), []Probe{gate, measure}, timeout)
	}
	shortBudget, longBudget := make(chan time.Duration, 1), make(chan time.Duration, 1)
	go run(short, shortBudget)
	go run(long, longBudget)

	if got := <-shortBudget; got <= 0 || got > short {
		t.Errorf("short run's probe budget = %v, want (0, %v]", got, short)
	}
	if got := <-longBudget; got <= time.Minute {
		t.Errorf("long run's probe budget = %v, want well over a minute", got)
	}
}

// Malformed graphs previously finish only the reachable probes. Preserve that
// behavior without inventing results or waiting for dependencies that never run.
func TestRunAllMalformedGraphs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probes []Probe
		want   map[ProbeID]Status
	}{
		{"unknown dependency", []Probe{staticProbe("root", nil, StatusPass), staticProbe("unknown", []ProbeID{"missing"}, StatusPass)}, map[ProbeID]Status{"root": StatusPass}},
		{"cycle", []Probe{staticProbe("root", nil, StatusPass), staticProbe("a", []ProbeID{"b"}, StatusPass), staticProbe("b", []ProbeID{"a"}, StatusPass)}, map[ProbeID]Status{"root": StatusPass}},
		{"duplicate ID", []Probe{staticProbe("a", []ProbeID{"missing"}, StatusFail), staticProbe("a", nil, StatusWarn), staticProbe("b", []ProbeID{"a", "a"}, StatusPass)}, map[ProbeID]Status{"a": StatusWarn, "b": StatusPass}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RunAll(t.Context(), tc.probes, DefaultProbeTimeout)
			if len(got) != len(tc.want) {
				t.Fatalf("results=%v, want %v", got, tc.want)
			}
			for id, status := range tc.want {
				if got[id].ID != id || got[id].Status != status {
					t.Errorf("%s=%+v, want %v", id, got[id], status)
				}
			}
		})
	}
}

// Reuse the same graph in repeated and concurrent calls. Probe IDs and map
// snapshots belong to each execution, regardless of the probe's returned ID.
func TestRunAllSchedulerPassIsolation(t *testing.T) {
	const runs = 8
	var calls [3]atomic.Int64
	probes := []Probe{
		{ID: "root", Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			calls[0].Add(1)
			return ProbeResult{ID: "wrong", Status: StatusWarn}
		}},
	}
	for i, id := range []ProbeID{"left", "right"} {
		probes = append(probes, Probe{ID: id, Deps: []ProbeID{"root"}, Run: func(_ context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
			calls[i+1].Add(1)
			if len(deps) != 1 || deps["root"].ID != "root" || deps["root"].Status != StatusWarn {
				return ProbeResult{Status: StatusFail, Detail: "wrong dependency snapshot"}
			}
			deps["root"] = ProbeResult{Status: StatusFail}
			return ProbeResult{ID: "wrong", Status: StatusPass}
		}})
	}
	run := func() {
		res := RunAll(t.Context(), probes, DefaultProbeTimeout)
		if len(res) != len(probes) {
			t.Errorf("results=%d, want %d", len(res), len(probes))
		}
		for _, p := range probes {
			want := StatusPass
			if p.ID == "root" {
				want = StatusWarn
			}
			if res[p.ID].ID != p.ID || res[p.ID].Status != want {
				t.Errorf("%s=%+v", p.ID, res[p.ID])
			}
		}
	}
	run()
	run()
	var group sync.WaitGroup
	for range runs - 2 {
		group.Go(run)
	}
	group.Wait()
	for i := range calls {
		if got := calls[i].Load(); got != runs {
			t.Errorf("probe %d ran %d times, want %d", i, got, runs)
		}
	}
}
