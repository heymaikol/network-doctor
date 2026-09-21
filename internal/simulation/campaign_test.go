package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func campaignScenario(t *testing.T) *Scenario {
	t.Helper()
	s, err := LibraryScenario("unstable-connectivity")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRandomSeed(t *testing.T) {
	if _, err := RandomSeed(); err != nil {
		t.Fatal(err)
	}
}

func TestCampaignResultWriteJSON(t *testing.T) {
	want := CampaignResult{
		Scenario: "unstable-connectivity",
		Seed:     -42,
		Runs:     3,
		Result:   ResultFail,
		FirstFailure: &Reproduction{
			Scenario:  "unstable-connectivity",
			Seed:      -42,
			Iteration: 2,
		},
	}
	var buf bytes.Buffer
	if err := want.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got CampaignResult
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Scenario != want.Scenario || got.Seed != want.Seed || got.Runs != want.Runs || got.Result != want.Result || !reflect.DeepEqual(got.FirstFailure, want.FirstFailure) {
		t.Fatalf("round trip = %+v", got)
	}
}

func TestCampaignResultWriteJSONReturnsWriterError(t *testing.T) {
	if err := new(CampaignResult).WriteJSON(failingWriter{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error = %v, want %v", err, io.ErrClosedPipe)
	}
}

func TestIterationSeedDerivationIsIndependent(t *testing.T) {
	const seed int64 = -9223372036854775000
	want := DeriveIterationSeed(seed, "unstable-connectivity", 37)
	for i := 0; i < 37; i++ {
		_ = DeriveIterationSeed(seed, "unstable-connectivity", i)
	}
	if got := DeriveIterationSeed(seed, "unstable-connectivity", 37); got != want {
		t.Fatalf("iteration 37 changed after deriving predecessors: %d != %d", got, want)
	}
	if DeriveIterationSeed(seed+1, "unstable-connectivity", 37) == want {
		t.Error("different campaign seed produced the same iteration seed")
	}
}

func TestCampaignScheduleDeterminismAndBounds(t *testing.T) {
	s := campaignScenario(t)
	seed := DeriveIterationSeed(12345, s.Name, 7)
	_, first, err := compileCampaignIteration(s, seed)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := compileCampaignIteration(s, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same seed schedule differs:\n%+v\n%+v", first, second)
	}
	if scheduleFingerprint(first) != scheduleFingerprint(second) {
		t.Error("same schedule has different fingerprint")
	}
	for _, event := range first {
		if event.Type == FaultNetem {
			if event.LossPercent < 0 || event.LossPercent > 20 || event.Latency < 0 || event.Jitter < 0 || event.NetemSeed == 0 {
				t.Errorf("out-of-range netem event: %+v", event)
			}
		}
	}
	_, different, err := compileCampaignIteration(s, seed+1)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, different) {
		t.Error("different iteration seed produced the same full schedule")
	}
}

func TestDiagnosisFingerprintCanonicalizesProbeOrder(t *testing.T) {
	checks := []DiagnosisCheck{
		{ID: "dns", Status: "PASS"},
		{ID: "internet_tcp", Status: "WARN", Cause: "ipv6_unreachable", Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"}},
	}
	a := &Report{Tests: []TestOutcome{{Name: "one", Diagnosis: &Diagnosis{Verdict: "degraded", Checks: checks}}}}
	b := &Report{Tests: []TestOutcome{{Name: "one", Diagnosis: &Diagnosis{Verdict: "degraded", Checks: []DiagnosisCheck{checks[1], checks[0]}}}}}
	fa, fb := diagnosisFingerprint(a), diagnosisFingerprint(b)
	if fa.ID != fb.ID || !reflect.DeepEqual(fa, fb) {
		t.Fatalf("order changed fingerprint: %+v != %+v", fa, fb)
	}
	blob, err := json.Marshal(fa)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip DiagnosisFingerprint
	if err := json.Unmarshal(blob, &roundTrip); err != nil || roundTrip.ID != fa.ID {
		t.Fatalf("JSON changed fingerprint: %v %+v", err, roundTrip)
	}
}

func TestCampaignFailFastAndReproduction(t *testing.T) {
	s := campaignScenario(t)
	created := 0
	result := RunCampaign(context.Background(), s, func() Backend {
		created++
		return &fakeBackend{caps: supported(), env: &fakeEnv{stdout: okReport}}
	}, CampaignOptions{Seed: 12345, Runs: 5, FailFast: true, Run: Options{Netdoc: "netdoc"}})
	if created != 1 || result.Runs != 1 || result.FirstFailure == nil {
		t.Fatalf("created=%d result=%+v", created, result)
	}
	if result.FirstFailure.Seed != 12345 || result.FirstFailure.Iteration != 0 {
		t.Errorf("reproduction = %+v", result.FirstFailure)
	}
	var text bytes.Buffer
	result.WriteText(&text)
	if !bytes.Contains(text.Bytes(), []byte("--seed 12345 --iteration 0")) {
		t.Errorf("no direct reproduction command:\n%s", text.String())
	}
}

func TestCampaignCancellationStartsNoIteration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	created := 0
	result := RunCampaign(ctx, campaignScenario(t), func() Backend { created++; return nil }, CampaignOptions{Seed: 1, Runs: 3})
	if created != 0 || !result.Cancelled || result.Result != ResultError {
		t.Fatalf("created=%d result=%+v", created, result)
	}
}

func TestCampaignAggregateCountsDivergentEquivalentSchedules(t *testing.T) {
	r := &CampaignResult{Runs: 2, Failed: 1, Outcomes: []IterationResult{
		{ScheduleID: "same", Fingerprint: DiagnosisFingerprint{ID: "a"}, Report: &Report{Duration: 3}},
		{ScheduleID: "same", Fingerprint: DiagnosisFingerprint{ID: "b"}, Report: &Report{Duration: 7}},
	}}
	r.finish()
	if r.DivergentRuns != 2 || r.StableRuns != 0 || len(r.Fingerprints) != 2 || r.Result != ResultFail {
		t.Fatalf("aggregate = %+v", r)
	}
}

func flappingScenario(t *testing.T) *Scenario {
	t.Helper()
	s, err := LibraryScenario("flapping-connectivity")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFlappingTimelineIsDeterministicOrderedAndBounded(t *testing.T) {
	s := flappingScenario(t)
	for iteration := 0; iteration < 6; iteration++ {
		seed := DeriveIterationSeed(12345, s.Name, iteration)
		first, firstSchedule, err := compileCampaignIteration(s, seed)
		if err != nil {
			t.Fatal(err)
		}
		second, secondSchedule, err := compileCampaignIteration(s, seed)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(firstSchedule, secondSchedule) {
			t.Fatalf("iteration %d schedule differs across compilations", iteration)
		}
		timeline := timelineFrom(first.Faults)
		if timelineFingerprint(timeline) != timelineFingerprint(timelineFrom(second.Faults)) {
			t.Fatalf("iteration %d timeline fingerprint differs across compilations", iteration)
		}
		// Five netem phases and three resolver phases, every offset inside the
		// declared bound and strictly increasing within each fault.
		if len(timeline) != 8 {
			t.Fatalf("iteration %d timeline = %+v", iteration, timeline)
		}
		perFault := map[string]time.Duration{}
		for _, event := range timeline {
			if event.Offset < 0 || event.Offset > maxScheduledOffset {
				t.Errorf("iteration %d offset out of range: %+v", iteration, event)
			}
			if event.LossPercent < 0 || event.LossPercent > 100 {
				t.Errorf("iteration %d loss out of range: %+v", iteration, event)
			}
			key := event.Type + event.Service
			if previous, seen := perFault[key]; seen && event.Offset <= previous {
				t.Errorf("iteration %d offsets not increasing for %s: %+v", iteration, key, timeline)
			}
			perFault[key] = event.Offset
		}
	}
}

func TestFlappingIterationsAreIndependentAndDistinct(t *testing.T) {
	s := flappingScenario(t)
	fingerprints := map[string]int{}
	for iteration := 0; iteration < 6; iteration++ {
		compiled, _, err := compileCampaignIteration(s, DeriveIterationSeed(999, s.Name, iteration))
		if err != nil {
			t.Fatal(err)
		}
		fingerprints[timelineFingerprint(timelineFrom(compiled.Faults))]++
	}
	if len(fingerprints) < 5 {
		t.Errorf("six iterations produced only %d distinct timelines", len(fingerprints))
	}
	// Iteration 4 does not depend on 0..3 having been compiled first.
	want, _, err := compileCampaignIteration(s, DeriveIterationSeed(999, s.Name, 4))
	if err != nil {
		t.Fatal(err)
	}
	fresh, _, err := compileCampaignIteration(flappingScenario(t), DeriveIterationSeed(999, s.Name, 4))
	if err != nil {
		t.Fatal(err)
	}
	if timelineFingerprint(timelineFrom(want.Faults)) != timelineFingerprint(timelineFrom(fresh.Faults)) {
		t.Error("iteration 4 depends on its predecessors")
	}
}

func TestBoundarySweepVariesOnlyTheDelay(t *testing.T) {
	s, err := LibraryScenario("dns-timeout-boundary")
	if err != nil {
		t.Fatal(err)
	}
	delays := map[time.Duration]bool{}
	for iteration := 0; iteration < 6; iteration++ {
		compiled, schedule, err := compileCampaignIteration(s, DeriveIterationSeed(12345, s.Name, iteration))
		if err != nil {
			t.Fatal(err)
		}
		timeline := timelineFrom(compiled.Faults)
		if len(timeline) != 1 || timeline[0].Outcome != DNSOutcomeDelay || timeline[0].Offset != 0 {
			t.Fatalf("iteration %d timeline = %+v", iteration, timeline)
		}
		if timeline[0].Delay < 800*time.Millisecond || timeline[0].Delay > 1300*time.Millisecond {
			t.Errorf("iteration %d delay %s is outside the declared range", iteration, timeline[0].Delay)
		}
		if len(schedule) != 1 || schedule[0].Delay != timeline[0].Delay {
			t.Errorf("iteration %d schedule does not carry the delay: %+v", iteration, schedule)
		}
		delays[timeline[0].Delay] = true
	}
	if len(delays) < 4 {
		t.Errorf("the sweep only reached %d distinct delays", len(delays))
	}
}

// Repeating one iteration is what gives the divergence check something to
// compare: without it every schedule fingerprint is a group of one.
func TestRunCampaignRepeatsASingleIteration(t *testing.T) {
	s := campaignScenario(t)
	iteration := 3
	result := RunCampaign(context.Background(), s, func() Backend {
		return &fakeBackend{caps: supported(), env: &fakeEnv{stdout: okReport}}
	}, CampaignOptions{Seed: 12345, Runs: 4, Iteration: &iteration, Run: Options{Netdoc: "netdoc"}})
	if len(result.Outcomes) != 4 {
		t.Fatalf("outcomes = %d, want 4", len(result.Outcomes))
	}
	for _, outcome := range result.Outcomes {
		if outcome.Iteration != 3 || outcome.ScheduleID != result.Outcomes[0].ScheduleID {
			t.Fatalf("repeat drew a different schedule: %+v", outcome)
		}
	}
	// One schedule shared by every run, all reaching the same diagnosis.
	if result.DivergentRuns != 0 || result.StableRuns != 4 {
		t.Errorf("stability = %d stable / %d divergent", result.StableRuns, result.DivergentRuns)
	}
}

// The diagnosis fingerprint is what a hunt compares two runs by, so anything in
// it that a rerun cannot repeat would make every case look unstable. These are
// the fields a real run varies without the network varying: elapsed
// milliseconds, the addresses that happened to be dialed, the prose netdoc
// wrote about them, and the run's own identity and clock. None may reach the
// fingerprint; the classification fields must.
func TestDiagnosisFingerprintIgnoresRuntimeOnlyValues(t *testing.T) {
	classified := []DiagnosisCheck{
		{ID: "dns", Name: "DNS", Status: "PASS"},
		{ID: "internet_tcp", Name: "Internet", Status: "WARN", Cause: "ipv6_unreachable",
			Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"}},
	}
	steady := &Report{ID: "run-a", StartedAt: time.Unix(1, 0), Duration: time.Second,
		Tests: []TestOutcome{{Name: "one", Duration: 300 * time.Millisecond, ExitCode: 1,
			StartOffset: 10 * time.Millisecond, EndOffset: 900 * time.Millisecond,
			Diagnosis: &Diagnosis{Verdict: "degraded", Summary: "example.test is slow", Checks: classified}}}}

	noisy := []DiagnosisCheck{
		{ID: "dns", Name: "DNS", Status: "PASS", Ms: 412, Detail: "resolved via 10.77.0.53 in 412ms",
			Attempts: []DiagnosisAttempt{{IP: "10.77.0.53", Ms: 412}}},
		{ID: "internet_tcp", Name: "Internet", Status: "WARN", Cause: "ipv6_unreachable", Ms: 3001,
			Detail: "connected to 10.77.0.20:80 from 10.77.0.10:54321", Fix: "check the upstream link",
			Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"},
			Attempts: []DiagnosisAttempt{{IP: "2001:db8::20", Ms: 3000, Error: "network is unreachable"}}},
	}
	rerun := &Report{ID: "run-b", StartedAt: time.Unix(999999, 0), Duration: 7 * time.Second,
		Tests: []TestOutcome{{Name: "one", Duration: 4 * time.Second, ExitCode: 3,
			StartOffset: 77 * time.Millisecond, EndOffset: 6 * time.Second,
			Diagnosis: &Diagnosis{Verdict: "degraded", Summary: "example.test is very slow", Checks: noisy}}}}

	if a, b := diagnosisFingerprint(steady), diagnosisFingerprint(rerun); a.ID != b.ID {
		t.Fatalf("runtime-only values changed the fingerprint:\n %+v\n %+v", a, b)
	}
	// The converse, so this is not passing because the fingerprint ignores
	// everything: a status change is a different diagnosis.
	changed := *rerun.Tests[0].Diagnosis
	changed.Checks = []DiagnosisCheck{noisy[0], {ID: "internet_tcp", Name: "Internet", Status: "FAIL",
		Cause: "ipv6_unreachable", Families: noisy[1].Families}}
	worse := &Report{Tests: []TestOutcome{{Name: "one", Diagnosis: &changed}}}
	if diagnosisFingerprint(steady).ID == diagnosisFingerprint(worse).ID {
		t.Fatal("a changed probe status left the fingerprint alone")
	}
}

// TestTimelineLatencyRangeMatchesScheduledNetem pins #162: Scenario.Validate
// accepts exactly the timeline latencies campaign compilation can turn into a
// legal scheduled_netem event, so validate can no longer pass a scenario the
// compiler rejects.
func TestTimelineLatencyRangeMatchesScheduledNetem(t *testing.T) {
	blob, err := library.ReadFile("scenarios/flapping-connectivity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		latency string
		valid   bool
	}{
		{"-1ms", false},
		{(maxNetemDuration + time.Millisecond).String(), false},
		{"0s", true},
		{"1ms", true},
		{maxNetemDuration.String(), true},
	} {
		text := strings.Replace(string(blob), "latency: 10ms", "latency: "+tc.latency, 1)
		if text == string(blob) {
			t.Fatal("the bundled flapping timeline no longer declares latency: 10ms")
		}
		s, err := ParseScenario(bytes.NewReader([]byte(text)))
		if !tc.valid {
			if err == nil {
				t.Errorf("latency %s validated", tc.latency)
			} else if !strings.Contains(err.Error(), "timeline.latency must satisfy 0 <= latency <= 10s") {
				t.Errorf("latency %s: %v", tc.latency, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("latency %s: %v", tc.latency, err)
		}
		// The other half of the disagreement: a latency validation accepts
		// must still survive the scheduled_netem revalidation compilation runs.
		if _, _, err := compileCampaignIteration(s, DeriveIterationSeed(1, s.Name, 0)); err != nil {
			t.Errorf("latency %s compiled: %v", tc.latency, err)
		}
	}
}
