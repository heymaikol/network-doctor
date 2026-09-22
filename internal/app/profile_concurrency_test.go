// How a profile acquires its components over SSH: which acquisitions may
// overlap, which must not, and what happens to the ones that fail. The
// overlapping is proved by what the transport observed about itself rather than
// by elapsed time, so these tests say the same thing on a loaded machine.

package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// viaCall is one remote acquisition as the transport saw it start.
type viaCall struct {
	target string
	batch  bool
	// active is how many acquisitions were in flight including this one, and
	// finished is how many had already returned. Together they say whether an
	// acquisition was alone and whether it waited for the one before it.
	active   int
	finished int
}

// viaTrace records the shape of a profile's remote acquisitions.
type viaTrace struct {
	mu sync.Mutex
	// calls is in start order, which is deliberately not result order.
	calls []viaCall
	// peak is the most acquisitions ever in flight at once, and peakOrdinary
	// the most of them that were the transport still able to ask the user a
	// question. The second number is the prompt-safety property: above one,
	// two prompts could have arrived on one terminal together.
	active, peak, ordinary, peakOrdinary, finished int
}

func (tr *viaTrace) enter(req remote.Request, batch bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.active++
	tr.peak = max(tr.peak, tr.active)
	if !batch {
		tr.ordinary++
		tr.peakOrdinary = max(tr.peakOrdinary, tr.ordinary)
	}
	tr.calls = append(tr.calls, viaCall{target: req.Target, batch: batch, active: tr.active, finished: tr.finished})
}

func (tr *viaTrace) leave(batch bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.active--
	tr.finished++
	if !batch {
		tr.ordinary--
	}
}

// errTransport is the shape of a failed acquisition: no diagnosis came back at
// all, which is what both a refused noninteractive login and an unreachable
// host look like to the caller.
var errTransport = errors.New("ideapad: ssh could not open the connection")

func (tr *viaTrace) snapshot() viaTrace {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return viaTrace{calls: append([]viaCall(nil), tr.calls...), active: tr.active,
		peak: tr.peak, peakOrdinary: tr.peakOrdinary, finished: tr.finished}
}

func (tr *viaTrace) targets() []string {
	names := make([]string, len(tr.calls))
	for i, call := range tr.calls {
		names[i] = call.target
	}
	return names
}

// traceProfileVia replaces the remote transport with one that records how the
// acquisitions overlapped and holds each one open long enough for an overlap to
// be observable. reply answers one component; it is called with the request and
// the transport variant that carried it.
func traceProfileVia(t *testing.T, hold time.Duration, reply func(remote.Request, bool) (remote.Response, error)) *viaTrace {
	t.Helper()
	tr := &viaTrace{}
	original := remoteRun
	t.Cleanup(func() { remoteRun = original })
	stubRemoteDirect(t, true)
	remoteRun = func(ctx context.Context, _, _ string, req remote.Request, batch bool) (remote.Response, error) {
		tr.enter(req, batch)
		select {
		case <-time.After(hold):
		case <-ctx.Done():
		}
		resp, err := reply(req, batch)
		tr.leave(batch)
		return resp, err
	}
	return tr
}

// profileComponentAnswer is what a healthy remote netdoc sends back for one
// profile component: the component's own focus check, on the target the
// request named.
func profileComponentAnswer(t *testing.T, req remote.Request, ok bool) remote.Response {
	t.Helper()
	target, err := diagnostic.ParseTarget(req.Target)
	if err != nil {
		t.Fatal(err)
	}
	status := profile.StatusPass
	if !ok {
		status = profile.StatusFail
	}
	rep := &report.Report{
		Version: remoteTool.Version, OK: ok, Verdict: diagnostic.VerdictOK,
		Target:  &report.Target{Host: target.Host, Port: target.Port, Protocol: target.Proto.String()},
		Checks:  []report.Check{{ID: req.Check[len(req.Check)-1], Name: "focus", Status: status, Detail: "observed"}},
		Summary: "The selected service path was checked.",
	}
	snap := &snapshot.Snapshot{
		Schema: snapshot.Schema, Tool: remoteTool, OK: ok,
		Target: &snapshot.Target{Raw: target.Raw, Host: target.Host, Port: target.Port, Protocol: target.Proto.String()},
		Checks: []snapshot.Check{},
	}
	return remote.Response{Protocol: remote.Protocol, Tool: remoteTool, Report: rep, Snapshot: snap}
}

func githubPlan(t *testing.T) profile.Plan {
	t.Helper()
	definition, ok := profile.Builtins().Lookup("github")
	if !ok {
		t.Fatal("the github profile is missing")
	}
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func viaBase() headless {
	return headless{via: "ideapad", publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}
}

// A: the first component is acquired alone over the transport that cannot
// prompt. Once it lands, the rest overlap, and the result stays in plan order
// however they finish.
func TestProfileViaOverlapsAfterANoninteractiveFirstComponent(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 40*time.Millisecond, func(req remote.Request, _ bool) (remote.Response, error) {
		return profileComponentAnswer(t, req, true), nil
	})
	result, _, tools, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	got := tr.snapshot()
	if len(got.calls) != len(plan.Runs) {
		t.Fatalf("%d acquisitions, want one per component: %v", len(got.calls), tr.targets())
	}
	for i, call := range got.calls {
		if !call.batch {
			t.Errorf("acquisition %d used the transport that can prompt", i)
		}
	}
	if got.peakOrdinary != 0 {
		t.Errorf("peak interactively capable acquisitions = %d, want none", got.peakOrdinary)
	}
	// The first one was by itself, and nothing else had finished ahead of it.
	if got.calls[0].active != 1 || got.calls[0].finished != 0 {
		t.Errorf("first acquisition was not alone: %+v", got.calls[0])
	}
	// None of the rest started before it established the path.
	for i, call := range got.calls[1:] {
		if call.finished < 1 {
			t.Errorf("acquisition %d started before the first one landed: %+v", i+1, call)
		}
	}
	if got.peak < 2 {
		t.Errorf("peak concurrent acquisitions = %d, want the remaining components to overlap", got.peak)
	}
	if len(tools) != len(plan.Runs) {
		t.Errorf("%d tool records, want one per component", len(tools))
	}
	for i, component := range result.Components {
		if component.ID != plan.Runs[i].ID {
			t.Errorf("component %d is %q, want registry order %q", i, component.ID, plan.Runs[i].ID)
		}
	}
}

// Result order is the plan's even when the transport deliberately finishes the
// components backwards.
func TestProfileViaKeepsPlanOrderWhenCompletionOrderIsReversed(t *testing.T) {
	plan := githubPlan(t)
	last := plan.Runs[len(plan.Runs)-1].Target.Raw
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		// The plan's last component answers first; every earlier one waits.
		if req.Target != last {
			time.Sleep(40 * time.Millisecond)
		}
		return profileComponentAnswer(t, req, true), nil
	})
	result, snapshots, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	if tr.snapshot().peak < 2 {
		t.Fatal("the components did not overlap, so the ordering was never at risk")
	}
	for i, component := range result.Components {
		if component.ID != plan.Runs[i].ID || component.Target.Host != plan.Runs[i].Target.Host {
			t.Errorf("component %d = %s/%v, want %s", i, component.ID, component.Target, plan.Runs[i].ID)
		}
		if snapshots[i].Target.Raw != plan.Runs[i].Target.Raw {
			t.Errorf("snapshot %d is %q, want %q", i, snapshots[i].Target.Raw, plan.Runs[i].Target.Raw)
		}
	}
}

// B: the destination wants to ask something. The batch acquisition cannot
// establish, and the pass falls back to what netdoc has always done: one
// interactively capable ssh at a time, in plan order.
func TestProfileViaFallsBackToSequentialWhenBatchCannotBeEstablished(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 20*time.Millisecond, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch {
			return remote.Response{}, errTransport
		}
		return profileComponentAnswer(t, req, true), nil
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	got := tr.snapshot()
	if got.peakOrdinary != 1 {
		t.Errorf("peak interactively capable acquisitions = %d, want exactly one at a time", got.peakOrdinary)
	}
	if got.peak != 1 {
		t.Errorf("peak concurrent acquisitions = %d, want the sequential fallback", got.peak)
	}
	batches := 0
	for _, call := range got.calls {
		if call.batch {
			batches++
		}
	}
	// One refused attempt on the first component, then one ordinary
	// acquisition per component. The extra process is the whole cost of asking.
	if batches != 1 || len(got.calls) != len(plan.Runs)+1 {
		t.Errorf("%d acquisitions, %d of them noninteractive; want %d + one refused attempt",
			len(got.calls), batches, len(plan.Runs))
	}
	for i, component := range result.Components {
		if component.ID != plan.Runs[i].ID {
			t.Errorf("component %d is %q, want registry order %q", i, component.ID, plan.Runs[i].ID)
		}
	}
}

// The destination is reached through a bastion. That path is the user's
// configuration, and netdoc keeps it: every acquisition is the ordinary one, it
// is one at a time, and no attempt is made over the transport that pins the
// proxy off.
func TestProfileViaKeepsAProxiedDestinationSequentialAndUnproxied(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 20*time.Millisecond, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch {
			t.Error("a proxied destination was acquired over the transport that pins the proxy off")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	stubRemoteDirect(t, false)
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	got := tr.snapshot()
	if got.peak != 1 {
		t.Errorf("peak concurrent acquisitions = %d, want the sequential path", got.peak)
	}
	// No refused attempt either: the gate answered before anything connected,
	// so a proxied destination costs one configuration read and no extra ssh.
	if len(got.calls) != len(plan.Runs) {
		t.Errorf("%d acquisitions, want %d", len(got.calls), len(plan.Runs))
	}
	for i, component := range result.Components {
		if component.ID != plan.Runs[i].ID {
			t.Errorf("component %d is %q, want registry order %q", i, component.ID, plan.Runs[i].ID)
		}
	}
}

// C: the fallback acquisition fails too. The pass stops on the first
// component, names it, and never reaches the second.
func TestProfileViaStopsAtTheFirstComponentWhenTheFallbackFailsToo(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 0, func(remote.Request, bool) (remote.Response, error) {
		return remote.Response{}, errTransport
	})
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil || !strings.HasPrefix(err.Error(), plan.Runs[0].Label+":") {
		t.Fatalf("error = %v, want it to name %q", err, plan.Runs[0].Label)
	}
	got := tr.snapshot()
	if len(got.calls) != 2 || !got.calls[0].batch || got.calls[1].batch {
		t.Fatalf("acquisitions = %+v, want one refused attempt and one ordinary retry", got.calls)
	}
	for _, call := range got.calls {
		if call.target != plan.Runs[0].Target.Raw {
			t.Errorf("acquisition reached %q, want only the first component", call.target)
		}
	}
}

// D: a component that fails while the others are in flight is still the one
// named, whichever of them finished first.
func TestProfileViaNamesTheConcurrentComponentThatFailed(t *testing.T) {
	plan := githubPlan(t)
	broken := plan.Runs[2]
	traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		if req.Target == broken.Target.Raw {
			// The failing component answers last, so completion order cannot
			// be what attributed it.
			time.Sleep(40 * time.Millisecond)
			return remote.Response{}, errTransport
		}
		return profileComponentAnswer(t, req, true), nil
	})
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil || !strings.HasPrefix(err.Error(), broken.Label+":") {
		t.Fatalf("error = %v, want it to name %q", err, broken.Label)
	}
	for _, other := range []profile.Run{plan.Runs[0], plan.Runs[1], plan.Runs[3]} {
		if strings.Contains(err.Error(), other.Label) {
			t.Errorf("error = %v, want it to name only the component that failed", err)
		}
	}
}

// E: cancelling the run ends every acquisition that is in flight, and the pass
// reports the context error rather than a diagnosis it did not finish.
func TestProfileViaCancellationEndsEveryConcurrentComponent(t *testing.T) {
	plan := githubPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := plan.Runs[0].Target.Raw
	// ready closes once every component after the first is acquiring, so the
	// cancellation lands while they all overlap rather than at a lucky moment.
	ready := make(chan struct{})
	var mu sync.Mutex
	waiting := 0
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		if req.Target == first {
			return profileComponentAnswer(t, req, true), nil
		}
		mu.Lock()
		waiting++
		if waiting == len(plan.Runs)-1 {
			close(ready)
		}
		mu.Unlock()
		<-ctx.Done()
		return remote.Response{}, ctx.Err()
	})
	go func() {
		<-ready
		cancel()
	}()
	_, _, _, err := runProfilePass(ctx, viaBase(), plan)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("error = %v, want the cancellation", err)
	}
	got := tr.snapshot()
	if got.active != 0 {
		t.Errorf("%d acquisitions still in flight after the pass returned", got.active)
	}
	if len(got.calls) != len(plan.Runs) {
		t.Errorf("%d acquisitions, want every component to have been started and ended", len(got.calls))
	}
}

// F: a component that completed and found the remote network unhealthy is not
// a transport failure. The path was established, so the rest still overlap.
func TestProfileViaTreatsAnUnhealthyFirstComponentAsEstablished(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 40*time.Millisecond, func(req remote.Request, _ bool) (remote.Response, error) {
		return profileComponentAnswer(t, req, req.Target != plan.Runs[0].Target.Raw), nil
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	got := tr.snapshot()
	if len(got.calls) != len(plan.Runs) || got.peakOrdinary != 0 {
		t.Fatalf("%d acquisitions, %d of them interactively capable; want one per component and none",
			len(got.calls), got.peakOrdinary)
	}
	if got.peak < 2 {
		t.Errorf("peak concurrent acquisitions = %d, want the remaining components to overlap", got.peak)
	}
	if len(result.Components) != len(plan.Runs) || result.Components[0].Status != profile.StatusFail {
		t.Errorf("first component = %s/%s over %d components, want a completed failure beside the rest",
			result.Components[0].ID, result.Components[0].Status, len(result.Components))
	}
}

// The measurement behind this issue, with the SSH setup cost simulated so it is
// the same on every machine. It asserts only the overlap, which is
// deterministic; the timings are recorded for the change's write-up.
func TestProfileViaLatencyUnderSimulatedSSHSetup(t *testing.T) {
	plan := githubPlan(t)
	for _, setup := range []time.Duration{50 * time.Millisecond, 200 * time.Millisecond} {
		for _, noninteractive := range []bool{false, true} {
			tr := traceProfileVia(t, setup, func(req remote.Request, batch bool) (remote.Response, error) {
				if batch && !noninteractive {
					// A destination that wants a password, a jump, an agent,
					// or a hardware key: the transport that cannot ask is
					// refused, and the ordinary one carries every component.
					return remote.Response{}, errTransport
				}
				return profileComponentAnswer(t, req, true), nil
			})
			start := time.Now()
			if _, _, _, err := runProfilePass(context.Background(), viaBase(), plan); err != nil {
				t.Fatalf("profile pass: %v", err)
			}
			elapsed := time.Since(start)
			got := tr.snapshot()
			t.Logf("ssh setup %v, %d components, noninteractive=%t: peak concurrent %d, one --via %v, profile %v",
				setup, len(plan.Runs), noninteractive, got.peak, setup, elapsed.Round(time.Millisecond))
			if noninteractive != (got.peak > 1) {
				t.Errorf("peak concurrent acquisitions = %d with noninteractive=%t", got.peak, noninteractive)
			}
		}
	}
}
