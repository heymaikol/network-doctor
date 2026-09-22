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
	// barrier, when a test installs one, holds every acquisition after the
	// first inside the transport until all of them have arrived. It is set
	// before the pass starts and read only from the acquisitions the pass
	// then makes.
	barrier *viaBarrier
	// calls is in start order, which is deliberately not result order.
	calls []viaCall
	// peak is the most acquisitions ever in flight at once, and peakOrdinary
	// the most of them that were the transport still able to ask the user a
	// question. The second number is the prompt-safety property: above one,
	// two prompts could have arrived on one terminal together.
	active, peak, ordinary, peakOrdinary, finished int
}

// enter records one acquisition and reports whether it was the pass's first,
// which is the one that establishes the batch path by itself.
func (tr *viaTrace) enter(req remote.Request, batch bool) bool {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.active++
	tr.peak = max(tr.peak, tr.active)
	if !batch {
		tr.ordinary++
		tr.peakOrdinary = max(tr.peakOrdinary, tr.ordinary)
	}
	tr.calls = append(tr.calls, viaCall{target: req.Target, batch: batch, active: tr.active, finished: tr.finished})
	return len(tr.calls) == 1
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

// viaBarrier makes an overlap a property of the test rather than of the
// scheduler. Every acquisition after the first parks in the transport until
// the expected number of them have arrived, so a pass that overlaps its
// components cannot be observed not overlapping them, and one that serializes
// them cannot slip past by being quick.
type viaBarrier struct {
	mu       sync.Mutex
	entered  int
	expected int
	open     bool
	stuck    bool
	// released closes once every expected acquisition is inside. Tests that
	// need to act while they all overlap wait on it too.
	released chan struct{}
	// abandoned ends the wait when the test is over, so a failed expectation
	// leaves no acquisition parked here.
	abandoned chan struct{}
}

// viaBarrierStuck bounds the wait. It is not how the overlap is established,
// which is what the count is for; it is how a pass that acquires its components
// one at a time is reported as the failure it is rather than parked until the
// whole test binary times out. Nothing reaches it on a passing run, so it is far
// longer than any machine needs.
const viaBarrierStuck = 10 * time.Second

// awaitVia receives one signal from ch, or reports the wait as the failure it
// is. Like the barrier's own bound, it is not how the overlap is arranged: it
// is what turns a pass that acquired its components one at a time into a failed
// test rather than a parked one.
func awaitVia(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(viaBarrierStuck):
		t.Errorf("%s did not happen within %v", what, viaBarrierStuck)
	}
}

// overlap installs a barrier for the acquisitions after the first. expected is
// how many of them the pass should have in flight together, which for a profile
// acquired over one established path is every component but the first.
func (tr *viaTrace) overlap(t *testing.T, expected int) *viaBarrier {
	t.Helper()
	b := &viaBarrier{expected: expected, released: make(chan struct{}), abandoned: make(chan struct{})}
	t.Cleanup(func() {
		close(b.abandoned)
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.stuck {
			t.Errorf("%d of %d acquisitions reached the barrier within %v, so they never overlapped",
				b.entered, b.expected, viaBarrierStuck)
		}
	})
	tr.barrier = b
	return b
}

// wait holds this acquisition until every expected one has entered.
func (b *viaBarrier) wait(ctx context.Context) {
	b.mu.Lock()
	b.entered++
	if b.entered == b.expected {
		b.release(false)
	}
	b.mu.Unlock()
	select {
	case <-b.released:
	case <-ctx.Done():
	case <-b.abandoned:
	case <-time.After(viaBarrierStuck):
		b.mu.Lock()
		b.release(true)
		b.mu.Unlock()
	}
}

// release opens the barrier once, and records whether it was opened because the
// acquisitions never arrived. The caller holds b.mu.
func (b *viaBarrier) release(stuck bool) {
	b.stuck = b.stuck || stuck
	if !b.open {
		b.open = true
		close(b.released)
	}
}

// traceProfileVia replaces the remote transport with one that records how the
// acquisitions overlapped. reply answers one component; it is called with the
// request and the transport variant that carried it. hold is a simulated setup
// cost, not a synchronizer: a test that needs its components to overlap says so
// with tr.overlap instead.
func traceProfileVia(t *testing.T, hold time.Duration, reply func(remote.Request, bool) (remote.Response, error)) *viaTrace {
	t.Helper()
	tr := &viaTrace{}
	original := remoteRun
	t.Cleanup(func() { remoteRun = original })
	stubRemoteDirect(t, true)
	remoteRun = func(ctx context.Context, _, _ string, req remote.Request, batch bool) (remote.Response, error) {
		first := tr.enter(req, batch)
		if !first && tr.barrier != nil {
			tr.barrier.wait(ctx)
		}
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
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		return profileComponentAnswer(t, req, true), nil
	})
	tr.overlap(t, len(plan.Runs)-1)
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
	// Every one of them, not merely two: the barrier held each until all had
	// arrived, so a pass that acquired any of them in turn could not get here.
	if got.peak != len(plan.Runs)-1 {
		t.Errorf("peak concurrent acquisitions = %d, want the remaining %d components to overlap",
			got.peak, len(plan.Runs)-1)
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
	first := plan.Runs[0].Target.Raw
	last := plan.Runs[len(plan.Runs)-1].Target.Raw
	// The plan's last component answers first and the concurrent ones before it
	// wait for it, so completion order is the reverse of plan order by
	// construction. The first component is not among them: it establishes the
	// path alone, ahead of all of this.
	answered := make(chan struct{})
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		switch req.Target {
		case first:
		case last:
			close(answered)
		default:
			awaitVia(t, answered, "the plan's last component answering first")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	tr.overlap(t, len(plan.Runs)-1)
	result, snapshots, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	if got := tr.snapshot().peak; got != len(plan.Runs)-1 {
		t.Fatalf("peak concurrent acquisitions = %d, want %d: the ordering was never at risk",
			got, len(plan.Runs)-1)
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
	// The failing component answers after every other one has, so completion
	// order cannot be what attributed it, and it does so while they all overlap:
	// the barrier below put them in flight together before any of them replied.
	answered := make(chan struct{}, len(plan.Runs))
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		if req.Target == broken.Target.Raw {
			for range len(plan.Runs) - 1 {
				awaitVia(t, answered, "every other component answering first")
			}
			return remote.Response{}, errTransport
		}
		defer func() { answered <- struct{}{} }()
		return profileComponentAnswer(t, req, true), nil
	})
	tr.overlap(t, len(plan.Runs)-1)
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil || !strings.HasPrefix(err.Error(), broken.Label+":") {
		t.Fatalf("error = %v, want it to name %q", err, broken.Label)
	}
	for _, other := range []profile.Run{plan.Runs[0], plan.Runs[1], plan.Runs[3]} {
		if strings.Contains(err.Error(), other.Label) {
			t.Errorf("error = %v, want it to name only the component that failed", err)
		}
	}
	if got := tr.snapshot().peak; got != len(plan.Runs)-1 {
		t.Errorf("peak concurrent acquisitions = %d, want %d: the failure was not a concurrent one",
			got, len(plan.Runs)-1)
	}
}

// E: cancelling the run ends every acquisition that is in flight, and the pass
// reports the context error rather than a diagnosis it did not finish.
func TestProfileViaCancellationEndsEveryConcurrentComponent(t *testing.T) {
	plan := githubPlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := plan.Runs[0].Target.Raw
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		if req.Target == first {
			return profileComponentAnswer(t, req, true), nil
		}
		<-ctx.Done()
		return remote.Response{}, ctx.Err()
	})
	// The barrier's release is also the moment every component after the first
	// is acquiring, so the cancellation lands while they all overlap rather
	// than at a lucky moment.
	released := tr.overlap(t, len(plan.Runs)-1).released
	go func() {
		<-released
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
	tr := traceProfileVia(t, 0, func(req remote.Request, _ bool) (remote.Response, error) {
		return profileComponentAnswer(t, req, req.Target != plan.Runs[0].Target.Raw), nil
	})
	tr.overlap(t, len(plan.Runs)-1)
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("profile pass: %v", err)
	}
	got := tr.snapshot()
	if len(got.calls) != len(plan.Runs) || got.peakOrdinary != 0 {
		t.Fatalf("%d acquisitions, %d of them interactively capable; want one per component and none",
			len(got.calls), got.peakOrdinary)
	}
	if got.peak != len(plan.Runs)-1 {
		t.Errorf("peak concurrent acquisitions = %d, want the remaining %d components to overlap",
			got.peak, len(plan.Runs)-1)
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
			if noninteractive {
				// The setup cost stays because it is what is being measured.
				// The overlap is not measured from it: the barrier holds the
				// components after the first until all of them are in flight.
				tr.overlap(t, len(plan.Runs)-1)
			}
			start := time.Now()
			if _, _, _, err := runProfilePass(context.Background(), viaBase(), plan); err != nil {
				t.Fatalf("profile pass: %v", err)
			}
			elapsed := time.Since(start)
			got := tr.snapshot()
			t.Logf("ssh setup %v, %d components, noninteractive=%t: peak concurrent %d, one --via %v, profile %v",
				setup, len(plan.Runs), noninteractive, got.peak, setup, elapsed.Round(time.Millisecond))
			want := 1
			if noninteractive {
				want = len(plan.Runs) - 1
			}
			if got.peak != want {
				t.Errorf("peak concurrent acquisitions = %d with noninteractive=%t, want %d",
					got.peak, noninteractive, want)
			}
		}
	}
}
