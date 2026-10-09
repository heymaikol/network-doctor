package diagnostic

import (
	"context"
	"time"
)

// DepsState reports whether all deps completed (ready) and whether any completed
// dep blocks this probe. A dep blocks on Fail or Skip (no output); a Pass, a
// Warn (degraded but produced output), or an applicable NotApplicable satisfies.
func DepsState(deps []ProbeID, res map[ProbeID]ProbeResult) (ready, blocked bool) {
	for _, d := range deps {
		r, ok := res[d]
		if !ok {
			return false, false
		}
		if r.Status == StatusFail || r.Status == StatusSkip {
			blocked = true
		}
	}
	return true, blocked
}

// SkipPrereq is the result recorded for a probe DepsState reports as blocked.
func SkipPrereq(id ProbeID) ProbeResult {
	return ProbeResult{ID: id, Status: StatusSkip, Detail: "skipped: a prerequisite failed"}
}

// RunAll executes the probe DAG headlessly with the same semantics as the TUI
// scheduler: every ready probe runs in parallel under its own timeout, a
// failed or skipped prerequisite skips its dependents, and the egress
// downgrade is applied once every probe has a result.
//
// timeout bounds one probe and belongs to this call alone, so a concurrent
// RunAll with a different budget cannot shorten or stretch this one. Anything
// non-positive means DefaultProbeTimeout.
//
// When RunAll returns it releases the probes' target links (see ReleaseProbes).
// A rerun of the same slice still runs, but every row dials its own socket.
func RunAll(ctx context.Context, probes []Probe, timeout time.Duration) map[ProbeID]ProbeResult {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	results := make(map[ProbeID]ProbeResult, len(probes))
	scheduler := NewProbeScheduler(probes, nil, nil)
	done := make(chan ProbeResult)
	running := 0
	// Runs on every return, after the loop below has received every worker's
	// result, so no row is still holding the target socket.
	defer ReleaseProbes(probes)

	// Drain ready probes and synchronous skips. Completing a skip enqueues its
	// dependents without spawning a worker or scanning unrelated probes.
	schedule := func() {
		for {
			i, blocked, ok := scheduler.Next()
			if !ok {
				return
			}
			p := probes[i]
			if blocked {
				res := SkipPrereq(p.ID)
				results[p.ID] = res
				scheduler.Complete(res)
				continue
			}
			// Workers never touch the scheduling loop's live results map.
			deps := make(map[ProbeID]ProbeResult, len(p.Deps))
			for _, d := range p.Deps {
				deps[d] = results[d]
			}
			running++
			go func(p Probe, deps map[ProbeID]ProbeResult) {
				pctx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				res := p.Run(pctx, deps)
				res.ID = p.ID
				done <- res
			}(p, deps)
		}
	}

	// Seed the roots, then drain: each finished probe may unlock more, so
	// reschedule after every receive. running is our only bookkeeping: when
	// it hits zero there's nothing in flight and nothing left to start, since
	// the ready queue was drained after the final result. Timed-out probes still
	// send a result; ctx cancellation just makes everyone
	// finish early and grumpy.
	schedule()
	for running > 0 {
		res := <-done
		results[res.ID] = res
		running--
		scheduler.Complete(res)
		schedule()
	}
	Finalize(results)
	return results
}
