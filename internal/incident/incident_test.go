package incident

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func observed(at time.Time, health Health, iface string) snapshot.Snapshot {
	status, ok, verdict, failedStage := snapshot.StatusPass, true, "ok", ""
	if health == Degraded {
		status, verdict = snapshot.StatusWarn, "degraded"
	}
	if health == Failing {
		status, ok, verdict, failedStage = snapshot.StatusFail, false, "network", "target_tcp"
	}
	return snapshot.Snapshot{Tool: snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		Schema: snapshot.Schema, CreatedAt: stamp(at), OK: ok,
		Target: &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []snapshot.Check{{
			ID: "target_tcp", Name: "Target TCP", Status: status, Ran: true, DurationMs: 1,
			Observed: &snapshot.Observed{SelectedIP: "198.51.100.7", Routes: []snapshot.Route{{
				Destination: "198.51.100.7", Family: "ipv4", Interface: iface,
			}}},
		}},
		Diagnosis: snapshot.Diagnosis{Verdict: verdict, Summary: string(health), FailedStage: failedStage},
	}
}

func TestTimelineLifecycleAndRepeatedIncidents(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 3, 41, 0, time.UTC)
	var timeline Timeline
	steps := []struct {
		after  time.Duration
		health Health
		iface  string
		want   Transition
	}{
		{0, Healthy, "wlan0", TransitionNone},
		{5 * time.Second, Healthy, "wlan0", TransitionNone},
		{10 * time.Second, Failing, "wg0", TransitionBegan},
		{15 * time.Second, Failing, "wg0", TransitionFailing},
		{20 * time.Second, Failing, "wg1", TransitionChanged},
		{25 * time.Second, Healthy, "wlan0", TransitionRecovered},
		{30 * time.Second, Degraded, "wlan0", TransitionNone},
		{35 * time.Second, Failing, "wlan0", TransitionBegan},
	}
	for _, step := range steps {
		at := start.Add(step.after)
		if got := timeline.Observe(at, observed(at, step.health, step.iface)); got != step.want {
			t.Fatalf("Observe(%s, %s) = %s, want %s", step.after, step.health, got, step.want)
		}
	}

	incidents := timeline.Incidents()
	if len(incidents) != 2 {
		t.Fatalf("incidents = %d, want 2", len(incidents))
	}
	first := incidents[0]
	if first.Active() || first.Passes != 3 || first.Duration(start.Add(25*time.Second)) != 15*time.Second {
		t.Errorf("first incident = active:%v passes:%d duration:%s", first.Active(), first.Passes, first.Duration(start.Add(25*time.Second)))
	}
	if first.Before == nil || first.Before.At != start.Add(5*time.Second) {
		t.Errorf("first baseline = %+v, want last healthy pass", first.Before)
	}
	if first.During == nil || first.During.Snap.Checks[0].Observed.Routes[0].Interface != "wg1" || len(first.Steps) != 1 {
		t.Errorf("first evolving state = during:%+v steps:%+v", first.During, first.Steps)
	}
	if first.Recovered == nil || first.Recovered.At != start.Add(25*time.Second) || len(first.RecoveryChanges) == 0 {
		t.Errorf("first recovery = recovered:%+v changes:%+v", first.Recovered, first.RecoveryChanges)
	}
	second := incidents[1]
	if !second.Active() || second.Passes != 1 || second.Before == nil || second.Before.At != start.Add(30*time.Second) {
		t.Errorf("second incident = %+v", second)
	}
}

func TestTimelineSeparatesEnvironmentalChangesFromOutcomes(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	var changed Timeline
	changed.Observe(start, observed(start, Healthy, "wlan0"))
	changed.Observe(start.Add(time.Second), observed(start.Add(time.Second), Failing, "wg0"))
	incident, _ := changed.Latest()

	environment := Environment(incident.OnsetChanges)
	if len(environment) == 0 || environment[0].Path != "paths.target.interface" {
		t.Fatalf("environment changes = %+v, want canonical path change first", environment)
	}
	if incident.Coincidence() != CoincidenceEnvironmentChanged || !strings.Contains(incident.Note(), "does not establish") {
		t.Errorf("changed coincidence/note = %s / %q", incident.Coincidence(), incident.Note())
	}
	if outcome := Outcome(incident.OnsetChanges); !slices.ContainsFunc(outcome, func(c compare.Change) bool {
		return c.Path == "checks.target_tcp.status"
	}) {
		t.Errorf("outcome changes do not include failed check: %+v", outcome)
	}

	var steady Timeline
	steady.Observe(start, observed(start, Healthy, "wlan0"))
	steady.Observe(start.Add(time.Second), observed(start.Add(time.Second), Failing, "wlan0"))
	incident, _ = steady.Latest()
	if got := Environment(incident.OnsetChanges); len(got) != 0 {
		t.Errorf("steady environment produced changes: %+v", got)
	}
	if incident.Coincidence() != CoincidenceEnvironmentSteady || strings.Contains(incident.Note(), "more likely") {
		t.Errorf("steady coincidence/note = %s / %q", incident.Coincidence(), incident.Note())
	}
}

func TestTimelineIsBounded(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	var timeline Timeline
	for n := 0; n < 1000; n++ {
		at := start.Add(time.Duration(n) * time.Second)
		timeline.Observe(at, observed(at, Healthy, "wlan0"))
	}
	if len(timeline.Incidents()) != 0 || timeline.baseline == nil || timeline.baseline.At != start.Add(999*time.Second) {
		t.Errorf("long healthy session retained more than its latest baseline: incidents=%d baseline=%+v", len(timeline.Incidents()), timeline.baseline)
	}

	for n := 0; n < maxIncidents+3; n++ {
		failedAt := start.Add(time.Duration(100+n*2) * time.Second)
		timeline.Observe(failedAt, observed(failedAt, Failing, "wg0"))
		recoveredAt := failedAt.Add(time.Second)
		timeline.Observe(recoveredAt, observed(recoveredAt, Healthy, "wlan0"))
	}
	if len(timeline.Incidents()) != maxIncidents || timeline.Dropped() != 3 {
		t.Errorf("incidents/dropped = %d/%d, want %d/3", len(timeline.Incidents()), timeline.Dropped(), maxIncidents)
	}

	failedAt := start.Add(200 * time.Second)
	timeline.Observe(failedAt, observed(failedAt, Failing, "wg0"))
	for n := 0; n < maxSteps+3; n++ {
		at := failedAt.Add(time.Duration(n+1) * time.Second)
		timeline.Observe(at, observed(at, Failing, fmt.Sprintf("wg%d", n+1)))
	}
	active, ok := timeline.Active()
	if !ok || len(active.Steps) != maxSteps || active.StepsDropped != 3 {
		t.Errorf("active steps/dropped = %d/%d, want %d/3", len(active.Steps), active.StepsDropped, maxSteps)
	}
}

func TestActiveIncidentDurationAndArtifactAreDeterministic(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.FixedZone("test", -5*60*60))
	var timeline Timeline
	timeline.Observe(start, observed(start, Failing, "wg0"))
	timeline.Observe(start.Add(5*time.Second), observed(start.Add(5*time.Second), Failing, "wg0"))
	active, ok := timeline.Active()
	if !ok || active.Duration(start.Add(17*time.Second)) != 17*time.Second {
		t.Fatalf("active duration = %s, want 17s", active.Duration(start.Add(17*time.Second)))
	}
	artifact := active.Artifact()
	if artifact.Incident == nil || artifact.Incident.StartedAt != "2026-08-25T17:00:00Z" || artifact.Incident.Passes != 2 || artifact.Incident.EndedAt != "" {
		t.Errorf("active artifact incident = %+v", artifact.Incident)
	}
	if _, err := snapshot.Encode(artifact); err != nil {
		t.Fatalf("active incident artifact does not encode: %v", err)
	}
}

// A timeline is one watch session, and a pass that cannot belong to it starts
// a new one rather than being folded into the incident already open. Nothing
// in production reaches this without also rebuilding the model, so what this
// pins is that the state machine cannot hold the impossible artifact even when
// driven directly.
func TestTimelineStartsOverOnAPassFromAnotherSession(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	var timeline Timeline
	timeline.Observe(start, observed(start, Healthy, "wg0"))
	timeline.Observe(start.Add(5*time.Second), observed(start.Add(5*time.Second), Failing, "wg0"))
	if _, open := timeline.Active(); !open {
		t.Fatal("the failing pass did not open an incident")
	}

	elsewhere := observed(start.Add(10*time.Second), Failing, "wg0")
	elsewhere.Target = &snapshot.Target{Raw: "other.example.net", Host: "other.example.net", Port: 443, Protocol: "tls+http"}
	if got := timeline.Observe(start.Add(10*time.Second), elsewhere); got != TransitionBegan {
		t.Errorf("transition = %q, want %q: a foreign pass opens its own incident", got, TransitionBegan)
	}
	if n := len(timeline.Incidents()); n != 1 {
		t.Fatalf("incidents = %d, want 1: the old session was not discarded", n)
	}
	if opened, _ := timeline.Latest(); opened.Before != nil {
		t.Error("the new session inherited a baseline from the old one")
	}

	// The new session keeps folding in, so the guard costs a legitimate pass
	// nothing, and the artifact it produces carries a nested state that has to
	// satisfy the same rule at the file boundary.
	recovery := observed(start.Add(15*time.Second), Healthy, "wg0")
	recovery.Target = elsewhere.Target
	if got := timeline.Observe(start.Add(15*time.Second), recovery); got != TransitionRecovered {
		t.Fatalf("transition = %q, want %q: a pass of the new session was treated as foreign", got, TransitionRecovered)
	}
	fresh, _ := timeline.Latest()
	if fresh.Recovered == nil {
		t.Fatal("the recovering pass was not retained")
	}
	if _, err := snapshot.Encode(fresh.Artifact()); err != nil {
		t.Fatalf("the artifact of the new session does not encode: %v", err)
	}
}

// withResolverTargets puts a system DNS row in front of the pass, carrying the
// resolver service addresses that row's lookup dialed. That row is where a
// change of nameserver reaches a comparison: Observed.Resolver names the
// second-opinion server a run was told to ask and nothing else.
func withResolverTargets(s snapshot.Snapshot, targets ...string) snapshot.Snapshot {
	s.Checks = append([]snapshot.Check{{
		ID: "dns", Name: "DNS", Status: snapshot.StatusPass, Ran: true, DurationMs: 1,
		Observed: &snapshot.Observed{ResolverTargets: targets},
	}}, s.Checks...)
	return s
}

func TestResolverTargetChangeIsEnvironmentalAtOnset(t *testing.T) {
	start := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	onset := start.Add(5 * time.Second)

	var timeline Timeline
	timeline.Observe(start, withResolverTargets(observed(start, Healthy, "wlan0"), "192.168.1.1:53"))
	timeline.Observe(onset, withResolverTargets(observed(onset, Failing, "wlan0"), "10.0.0.53:53"))
	i, ok := timeline.Latest()
	if !ok {
		t.Fatal("no incident was opened")
	}

	// The interface is the same in both passes, so the resolver targets are
	// the only thing about the path that moved.
	targets := func(changes []compare.Change) []string {
		var paths []string
		for _, c := range changes {
			if strings.Contains(c.Path, ".observed.resolver_targets.") {
				paths = append(paths, c.Path)
			}
		}
		return paths
	}
	want := []string{
		"checks.dns.observed.resolver_targets.10.0.0.53:53",
		"checks.dns.observed.resolver_targets.192.168.1.1:53",
	}
	if got := targets(i.OnsetChanges); !slices.Equal(got, want) {
		t.Fatalf("comparison reported resolver target changes %v, want %v", got, want)
	}
	if got := targets(Environment(i.OnsetChanges)); !slices.Equal(got, want) {
		t.Errorf("environment changes = %v, want the resolver targets %v", got, want)
	}
	if got := targets(Outcome(i.OnsetChanges)); len(got) != 0 {
		t.Errorf("resolver targets counted as diagnostic outcomes too: %v", got)
	}
	if i.Coincidence() != CoincidenceEnvironmentChanged {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
	}
	if note := i.Note(); !strings.Contains(note, "in how this machine reaches the network") ||
		strings.Contains(note, "No recorded change") {
		t.Errorf("note = %q, want one that reports the recorded path change", note)
	}
	// The failure itself stays where it was.
	if !slices.ContainsFunc(Outcome(i.OnsetChanges), func(c compare.Change) bool {
		return c.Path == "checks.target_tcp.status"
	}) {
		t.Errorf("outcome changes do not include the failed check: %+v", Outcome(i.OnsetChanges))
	}
}

func TestSteadyResolverTargetsLeaveTheEnvironmentSteady(t *testing.T) {
	start := time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)
	onset := start.Add(5 * time.Second)

	var timeline Timeline
	timeline.Observe(start, withResolverTargets(observed(start, Healthy, "wlan0"), "192.168.1.1:53"))
	timeline.Observe(onset, withResolverTargets(observed(onset, Failing, "wlan0"), "192.168.1.1:53"))
	i, _ := timeline.Latest()

	if got := Environment(i.OnsetChanges); len(got) != 0 {
		t.Errorf("environment changes = %+v, want none when only the outcome moved", got)
	}
	if len(Outcome(i.OnsetChanges)) == 0 {
		t.Error("the failure produced no outcome changes")
	}
	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
	if note := i.Note(); !strings.Contains(note, "No recorded change") {
		t.Errorf("note = %q, want the steady-environment sentence", note)
	}
}
