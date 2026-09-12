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
	return snapshot.Snapshot{
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
