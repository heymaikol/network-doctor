package simulation

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// tolerance is what the scheduler promises: the requested timeline, applied by
// an ordinary OS scheduler. Not nanosecond-perfect, and never asserted as such.
const tolerance = 400 * time.Millisecond

func TestScheduledFaultValidationRejectsBadTimelines(t *testing.T) {
	base := `name: t
topology:
  subnet: 10.77.0.0/24
  nodes:
    - {name: client, role: client, address: 10.77.0.10, gateway: 10.77.0.1}
    - name: server
      address: 10.77.0.1
      services:
        - {name: resolver-service, type: dns, zone: {example.test: 10.77.0.1}}
faults:
%s
tests:
  - {node: client, target: example.test:80}
expect: {verdict: ok}
`
	for name, faults := range map[string]string{
		"negative offset":    "  - {type: scheduled_netem, node: client, events: [{at: -1ms, latency: 10ms}]}",
		"descending offsets": "  - {type: scheduled_netem, node: client, events: [{at: 500ms}, {at: 100ms}]}",
		"duplicate offsets":  "  - {type: scheduled_netem, node: client, events: [{at: 500ms}, {at: 500ms}]}",
		"offset overflow":    "  - {type: scheduled_netem, node: client, events: [{at: 5000h}]}",
		"no events":          "  - {type: scheduled_netem, node: client, events: []}",
		"loss above 100":     "  - {type: scheduled_netem, node: client, events: [{at: 0s, loss_percent: 140}]}",
		"loss below zero":    "  - {type: scheduled_netem, node: client, events: [{at: 0s, loss_percent: -1}]}",
		"latency too large":  "  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 11s}]}",
		"jitter without any": "  - {type: scheduled_netem, node: client, events: [{at: 0s, jitter: 5ms}]}",
		"netem takes state":  "  - {type: scheduled_netem, node: client, events: [{at: 0s, state: down}]}",
		"unknown outcome":    "  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: maybe}]}",
		"unknown service":    "  - {type: scheduled_dns, service: nope, events: [{at: 0s, outcome: answer}]}",
		"delay too long":     "  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: delay, delay: 30s}]}",
		"delay without one":  "  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: delay}]}",
		"delay on answer":    "  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: answer, delay: 1s}]}",
		"unknown link state": "  - {type: scheduled_link, node: client, events: [{at: 0s, state: sideways}]}",
		"unknown segment":    "  - {type: scheduled_link, node: client, segment: wan, events: [{at: 0s, state: up}]}",
		"events on netem":    "  - {type: netem, node: client, delay: 1ms, events: [{at: 0s}]}",
		"service on netem":   "  - {type: netem, node: client, delay: 1ms, service: resolver-service}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScenario(strings.NewReader(strings.Replace(base, "%s", faults, 1))); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
	ok := "  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 10ms, jitter: 2ms}, {at: 700ms, loss_percent: 100}]}\n" +
		"  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: answer}, {at: 300ms, outcome: drop}, {at: 900ms, outcome: delay, delay: 50ms}]}\n" +
		"  - {type: scheduled_link, node: client, events: [{at: 400ms, state: down}, {at: 800ms, state: up}]}"
	s, err := ParseScenario(strings.NewReader(strings.Replace(base, "%s", ok, 1)))
	if err != nil {
		t.Fatalf("rejected a valid timeline: %v", err)
	}
	timeline := timelineFrom(s.Faults)
	if len(timeline) != 7 {
		t.Fatalf("timeline = %+v", timeline)
	}
	// Canonical order: offset first, then the event's own stable key.
	for i := 1; i < len(timeline); i++ {
		if timeline[i-1].Offset > timeline[i].Offset {
			t.Errorf("timeline is not ordered by offset: %+v", timeline)
		}
	}
	// The DNS fault's node is derived from the service, never written down.
	for _, event := range timeline {
		if event.Type == FaultScheduledDNS && event.Node != "server" {
			t.Errorf("dns event node = %q, want server", event.Node)
		}
	}
}

func TestScenarioRejectsAnOversizedTimeline(t *testing.T) {
	var events []ScheduledEvent
	for i := 0; i < maxScheduledEvents+1; i++ {
		events = append(events, ScheduledEvent{At: (time.Duration(i) * time.Millisecond).String()})
	}
	f := Fault{Type: FaultScheduledNetem, Node: "client", Segment: "lan", Events: events}
	if err := f.validateEvents(validateNetemEvent); err == nil {
		t.Error("accepted more events than the per-fault maximum")
	}
}

func TestTimelineFingerprintIgnoresApplicationTiming(t *testing.T) {
	a := []TimedEvent{
		{Offset: 700 * time.Millisecond, Type: FaultScheduledDNS, Service: "r", Outcome: DNSOutcomeDrop},
		{Offset: 0, Type: FaultScheduledNetem, Node: "client", Segment: "lan", Latency: 20 * time.Millisecond},
	}
	b := []TimedEvent{a[1], a[0]}
	if timelineFingerprint(sorted(a)) != timelineFingerprint(sorted(b)) {
		t.Error("equivalent timelines hash differently")
	}
	c := sorted(a)
	c[0].Latency = 21 * time.Millisecond
	if timelineFingerprint(sorted(a)) == timelineFingerprint(c) {
		t.Error("a parameter change did not change the fingerprint")
	}
	// The evidence carries applied offsets and error text; the fingerprint is
	// computed from the requested timeline and never sees either.
	if strings.Contains(a[0].key(), "applied") {
		t.Error("fingerprint key mentions application state")
	}
}

func sorted(in []TimedEvent) []TimedEvent {
	out := append([]TimedEvent(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func TestSchedulerAppliesEveryEventInOrder(t *testing.T) {
	env := &fakeEnv{}
	events := []TimedEvent{
		{Offset: 0, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
		{Offset: 60 * time.Millisecond, Type: FaultScheduledNetem, Node: "client", Segment: "lan", LossPercent: 100},
		{Offset: 120 * time.Millisecond, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
	}
	s := startScheduler(context.Background(), env, events, time.Now())
	evidence := s.wait()
	if len(evidence) != 3 {
		t.Fatalf("evidence = %+v", evidence)
	}
	previous := time.Duration(-1)
	for i, item := range evidence {
		if item.Result != EventApplied {
			t.Fatalf("event %d = %+v", i, item)
		}
		if item.AppliedOffset < item.ScheduledOffset || item.AppliedOffset > item.ScheduledOffset+tolerance {
			t.Errorf("event %d applied at %s, scheduled %s", i, item.AppliedOffset, item.ScheduledOffset)
		}
		if item.AppliedOffset < previous {
			t.Errorf("applied offsets are not monotonic: %+v", evidence)
		}
		previous = item.AppliedOffset
	}
	if len(env.appliedEvents()) != 3 {
		t.Errorf("environment saw %d events", len(env.appliedEvents()))
	}
}

func TestSchedulerWithNoEventsFinishesImmediately(t *testing.T) {
	if got := startScheduler(context.Background(), &fakeEnv{}, nil, time.Now()).wait(); len(got) != 0 {
		t.Errorf("evidence = %+v", got)
	}
}

func TestSchedulerSkipsEverythingAfterCancellation(t *testing.T) {
	// Cancel at a spread of positions across the timeline: before the first
	// event, while the timer is sleeping, and around the moment the first event
	// applies. Whatever the position, everything the scheduler did not reach is
	// recorded as skipped and the environment saw exactly what it claims.
	for name, at := range map[string]time.Duration{
		"before the first event": 0,
		"during the first sleep": 20 * time.Millisecond,
		"at the first event":     50 * time.Millisecond,
		"between events":         80 * time.Millisecond,
		"well after the first":   200 * time.Millisecond,
	} {
		t.Run(name, func(t *testing.T) {
			env := &fakeEnv{}
			events := []TimedEvent{
				{Offset: 50 * time.Millisecond, Type: FaultScheduledLink, Node: "client", Segment: "lan", State: LinkStateDown},
				{Offset: 5 * time.Second, Type: FaultScheduledLink, Node: "client", Segment: "lan", State: LinkStateUp},
			}
			ctx, cancel := context.WithCancel(context.Background())
			s := startScheduler(ctx, env, events, time.Now())
			time.Sleep(at)
			cancel()
			evidence := s.wait()
			if len(evidence) != 2 {
				t.Fatalf("evidence = %+v", evidence)
			}
			if evidence[1].Result != EventSkipped {
				t.Errorf("the late event was not skipped: %+v", evidence[1])
			}
			// Whatever happened, the scheduler is joined and the environment
			// saw no more events than the evidence claims.
			applied := 0
			for _, item := range evidence {
				if item.Result == EventApplied {
					applied++
				}
			}
			if len(env.appliedEvents()) != applied {
				t.Errorf("environment saw %d events, evidence claims %d", len(env.appliedEvents()), applied)
			}
		})
	}
}

func TestSchedulerRecordsAFailedApplication(t *testing.T) {
	env := &fakeEnv{applyErr: errors.New("tc exploded")}
	events := []TimedEvent{
		{Offset: 0, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
		{Offset: 20 * time.Millisecond, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
	}
	evidence := startScheduler(context.Background(), env, events, time.Now()).wait()
	if len(evidence) != 2 {
		t.Fatalf("evidence = %+v", evidence)
	}
	for _, item := range evidence {
		// A failed event is recorded, not fatal: the rest of the timeline still
		// runs, and the report says which one did not take.
		if item.Result != EventFailed || !strings.Contains(item.Error, "tc exploded") {
			t.Errorf("event = %+v", item)
		}
	}
}

func TestSchedulerCancelledDuringApplyStillJoins(t *testing.T) {
	hold := make(chan struct{})
	env := &fakeEnv{applyHold: hold}
	events := []TimedEvent{
		{Offset: 10 * time.Millisecond, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
		{Offset: 20 * time.Millisecond, Type: FaultScheduledNetem, Node: "client", Segment: "lan"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := startScheduler(ctx, env, events, time.Now())
	time.Sleep(20 * time.Millisecond)
	cancel()
	close(hold)
	done := make(chan []FaultEventEvidence, 1)
	go func() { done <- s.wait() }()
	select {
	case evidence := <-done:
		if len(evidence) != 2 {
			t.Fatalf("evidence = %+v", evidence)
		}
		if evidence[1].Result != EventSkipped {
			t.Errorf("an event ran after cancellation: %+v", evidence[1])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not join after cancellation during an apply")
	}
}

func TestRunAppliesOffsetZeroBeforeStartingNetdoc(t *testing.T) {
	raw := strings.Replace(minimalScenario, "tests:",
		"faults:\n  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 5ms}, {at: 20s, latency: 5ms}]}\ntests:", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport}
	rep := Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if env.execBeforeInitial {
		t.Error("netdoc started before the offset-zero scheduled state was applied")
	}
	if len(rep.Timeline) != 2 || rep.Timeline[0].AppliedOffset > rep.Tests[0].StartOffset {
		t.Errorf("timeline = %+v, test window = %s..%s", rep.Timeline, rep.Tests[0].StartOffset, rep.Tests[0].EndOffset)
	}
}

func TestRunJoinsSchedulerAfterProbePanic(t *testing.T) {
	raw := strings.Replace(minimalScenario, "tests:",
		"faults:\n  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 5ms}, {at: 20s, latency: 5ms}]}\ntests:", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport, panicOnExec: true}
	rep := Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if env.lateEvents != 0 || env.cleanups != 1 {
		t.Fatalf("late events = %d, cleanups = %d", env.lateEvents, env.cleanups)
	}
	if len(rep.Timeline) != 2 || rep.Timeline[1].Result != EventSkipped {
		t.Errorf("timeline after panic = %+v", rep.Timeline)
	}
	if rep.Result != ResultError || !strings.Contains(rep.Error, "probe exploded") {
		t.Errorf("result = %s, error = %q", rep.Result, rep.Error)
	}
}

// The lifecycle guarantee the whole design rests on: Run joins the scheduler
// before teardown, so no scheduled event can touch an environment that Cleanup
// is dismantling.
func TestRunJoinsTheSchedulerBeforeCleanup(t *testing.T) {
	raw := strings.Replace(minimalScenario, "tests:",
		"faults:\n  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 5ms}, {at: 30ms, loss_percent: 100}, {at: 20s, latency: 5ms}]}\ntests:", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport}
	rep := Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if env.lateEvents != 0 {
		t.Errorf("%d scheduled events ran after cleanup", env.lateEvents)
	}
	if len(rep.Timeline) != 3 {
		t.Fatalf("timeline evidence = %+v", rep.Timeline)
	}
	// The 20s event cannot have been applied: the tests took milliseconds, and
	// the run ending is what stops the scheduler.
	if rep.Timeline[2].Result != EventSkipped {
		t.Errorf("late event = %+v", rep.Timeline[2])
	}
	if rep.TimelineID == "" || rep.Tests[0].EndOffset < rep.Tests[0].StartOffset {
		t.Errorf("timeline id %q, test window %s..%s", rep.TimelineID, rep.Tests[0].StartOffset, rep.Tests[0].EndOffset)
	}
}

// No scheduler goroutine outlives its simulation. Run joins it, so a repeated
// Run must not accumulate goroutines even though every one of those runs left a
// 20-second event unreached.
func TestSchedulerGoroutinesDoNotAccumulate(t *testing.T) {
	raw := strings.Replace(minimalScenario, "tests:",
		"faults:\n  - {type: scheduled_netem, node: client, events: [{at: 0s, latency: 5ms}, {at: 20s, latency: 5ms}]}\ntests:", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	run := func() {
		Run(context.Background(), s, &fakeBackend{caps: supported(), env: &fakeEnv{stdout: okReport}}, Options{Netdoc: "netdoc"})
	}
	run()
	runtime.GC()
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		run()
	}
	runtime.GC()
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines grew from %d to %d across 20 runs", before, after)
	}
}

func TestTransitionsDuringAWindow(t *testing.T) {
	timeline := []FaultEventEvidence{
		{Event: TimedEvent{Type: FaultScheduledDNS, Outcome: DNSOutcomeAnswer}, AppliedOffset: 0, Result: EventApplied},
		{Event: TimedEvent{Type: FaultScheduledDNS, Outcome: DNSOutcomeDrop}, AppliedOffset: 500 * time.Millisecond, Result: EventApplied},
		{Event: TimedEvent{Type: FaultScheduledDNS, Outcome: DNSOutcomeAnswer}, AppliedOffset: 1500 * time.Millisecond, Result: EventApplied},
		{Event: TimedEvent{Type: FaultScheduledDNS, Outcome: DNSOutcomeDrop}, ScheduledOffset: 9 * time.Second, Result: EventSkipped},
	}
	if got := transitionsDuring(timeline, 400*time.Millisecond, 1600*time.Millisecond); len(got) != 2 {
		t.Errorf("transitions = %+v", got)
	}
	if got := transitionsDuring(timeline, 2*time.Second, 3*time.Second); len(got) != 0 {
		t.Errorf("transitions after the last applied event = %+v", got)
	}
}

// TestDNSResponseDelayMinimum pins the lower bound a scheduled DNS delay has to
// clear. The holder is told the delay in whole milliseconds, so anything under
// one would reach it as 0 and be refused there, long after the file validated.
func TestDNSResponseDelayMinimum(t *testing.T) {
	base := `name: t
topology:
  subnet: 10.77.0.0/24
  nodes:
    - {name: client, role: client, address: 10.77.0.10, gateway: 10.77.0.1}
    - name: server
      address: 10.77.0.1
      services:
        - {name: resolver-service, type: dns, zone: {example.test: 10.77.0.1}}
%s
tests:
  - {node: client, target: example.test:80}
expect: {verdict: ok}
`
	dnsFault := func(delay string) string {
		return "faults:\n  - {type: scheduled_dns, service: resolver-service, events: [{at: 0s, outcome: delay, delay: " + delay + "}]}"
	}
	dnsDelayCampaign := func(min string) string {
		return "campaign:\n  runs: 2\n  dns_delay: {service: resolver-service, delay: {min: " + min + ", max: 2s}}"
	}
	resolverHoldCampaign := func(hold string) string {
		return "campaign:\n  runs: 2\n  timeline:\n" +
			"    node: client\n    segment: lan\n    service: resolver-service\n" +
			"    resolver_hold: " + hold + "\n    latency: 10ms\n" +
			"    degrade_at: {min: 150ms, max: 350ms}\n" +
			"    degrade_loss_percent: {min: 10, max: 60}\n" +
			"    outage_for: {min: 300ms, max: 700ms}"
	}
	for name, tc := range map[string]struct {
		spec string
		ok   bool
	}{
		"scheduled_dns 500us":  {dnsFault("500us"), false},
		"scheduled_dns 999us":  {dnsFault("999us"), false},
		"scheduled_dns 1ms":    {dnsFault("1ms"), true},
		"scheduled_dns 5s":     {dnsFault("5s"), true},
		"scheduled_dns 5001ms": {dnsFault("5001ms"), false},
		"dns_delay min 500us":  {dnsDelayCampaign("500us"), false},
		"dns_delay min 999us":  {dnsDelayCampaign("999us"), false},
		"dns_delay min 1ms":    {dnsDelayCampaign("1ms"), true},
		"resolver_hold 500us":  {resolverHoldCampaign("500us"), false},
		"resolver_hold 999us":  {resolverHoldCampaign("999us"), false},
		"resolver_hold 1ms":    {resolverHoldCampaign("1ms"), true},
		"resolver_hold 5s":     {resolverHoldCampaign("5s"), true},
		"resolver_hold 5001ms": {resolverHoldCampaign("5001ms"), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseScenario(strings.NewReader(strings.Replace(base, "%s", tc.spec, 1)))
			if tc.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("accepted a delay the holder cannot be told")
			}
		})
	}
}
