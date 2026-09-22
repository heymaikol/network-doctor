package incident

import (
	"fmt"
	"reflect"
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

// The bounds above are on what the lists show. This pins what they hold: an
// entry the bound discards must not stay reachable through a slot of the
// backing array the timeline keeps, or every run it points to stays live for
// the rest of the session. The array is captured before each eviction, from
// the list's first slot to its capacity, so a head left behind by reslicing is
// inside what is inspected.
func TestTimelineReleasesWhatItsBoundsDiscard(t *testing.T) {
	start := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	var timeline Timeline
	var targets []*snapshot.Target
	evictions := 0
	for n := 0; n < 4*maxIncidents; n++ {
		failedAt := start.Add(time.Duration(n*2) * time.Second)
		failing := observed(failedAt, Failing, "wg0")
		targets = append(targets, failing.Target)
		// A full list with spare capacity evicts without reallocating, so
		// the array captured here is the one the timeline goes on holding.
		inPlace := len(timeline.incidents) == maxIncidents && cap(timeline.incidents) > maxIncidents
		array := timeline.incidents[:cap(timeline.incidents)]
		timeline.Observe(failedAt, failing)
		if inPlace {
			evictions++
			for slot := range array {
				if slot >= maxIncidents {
					if !reflect.ValueOf(array[slot]).IsZero() {
						t.Fatalf("pass %d: slot %d past the bound still holds the incident started %s", n, slot, array[slot].Started)
					}
					continue
				}
				if want := n - maxIncidents + 1 + slot; array[slot].Onset.Snap.Target != targets[want] {
					t.Fatalf("pass %d: slot %d holds the incident started %s, want incident %d", n, slot, array[slot].Started, want)
				}
			}
		}
		recoveredAt := failedAt.Add(time.Second)
		timeline.Observe(recoveredAt, observed(recoveredAt, Healthy, "wlan0"))
	}
	if evictions < 2*maxIncidents {
		t.Fatalf("only %d evictions were checked in place", evictions)
	}
	if len(timeline.Incidents()) != maxIncidents || timeline.Dropped() != 3*maxIncidents {
		t.Errorf("incidents/dropped = %d/%d, want %d/%d", len(timeline.Incidents()), timeline.Dropped(), maxIncidents, 3*maxIncidents)
	}

	failedAt := start.Add(time.Hour)
	timeline.Observe(failedAt, observed(failedAt, Failing, "wg0"))
	var changes [][]compare.Change
	evictions = 0
	for n := 0; n < 4*maxSteps; n++ {
		at := failedAt.Add(time.Duration(n+1) * time.Second)
		active := &timeline.incidents[len(timeline.incidents)-1]
		inPlace := len(active.Steps) == maxSteps && cap(active.Steps) > maxSteps
		array := active.Steps[:cap(active.Steps)]
		if got := timeline.Observe(at, observed(at, Failing, fmt.Sprintf("wg%d", n+1))); got != TransitionChanged {
			t.Fatalf("pass %d: transition = %s, want %s", n, got, TransitionChanged)
		}
		changes = append(changes, active.Steps[len(active.Steps)-1].Changes)
		if inPlace {
			evictions++
			for slot := range array {
				if slot >= maxSteps {
					if array[slot].Changes != nil || !array[slot].At.IsZero() {
						t.Fatalf("step %d: slot %d past the bound still holds the step at %s", n, slot, array[slot].At)
					}
					continue
				}
				if want := n - maxSteps + 1 + slot; &array[slot].Changes[0] != &changes[want][0] {
					t.Fatalf("step %d: slot %d holds the step at %s, want step %d", n, slot, array[slot].At, want)
				}
			}
		}
	}
	if evictions < 2*maxSteps {
		t.Fatalf("only %d step evictions were checked in place", evictions)
	}
	active, ok := timeline.Active()
	if !ok || len(active.Steps) != maxSteps || active.StepsDropped != 3*maxSteps {
		t.Fatalf("active steps/dropped = %d/%d, want %d/%d", len(active.Steps), active.StepsDropped, maxSteps, 3*maxSteps)
	}
	for slot, step := range active.Steps {
		if want := failedAt.Add(time.Duration(3*maxSteps+slot+1) * time.Second); !step.At.Equal(want) {
			t.Errorf("step %d at %s, want %s", slot, step.At, want)
		}
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

// pass is one watch pass as the two clocks saw it. at is the observation time
// the timeline is given, which in a real session carries the monotonic reading
// that keeps its order and spacing right. wall is what the machine's clock
// said, which is all the pass's own CreatedAt can publish. A test cannot build
// a time.Time whose wall half steps backwards while its monotonic half moves
// on, so the two are supplied separately: at only ever moves forward, and wall
// moves however the clock was set.
type pass struct {
	at, wall time.Duration
	health   Health
	iface    string
}

func observeClocks(start time.Time, passes []pass) Incident {
	var timeline Timeline
	for _, p := range passes {
		timeline.Observe(start.Add(p.at), observed(start.Add(p.wall), p.health, p.iface))
	}
	i, _ := timeline.Latest()
	return i
}

// artifactTimes is every timestamp an incident artifact publishes about its
// own chronology, in observation order.
type artifactTimes struct {
	created, started, ended, before, during, recovered string
}

func timesOf(s snapshot.Snapshot) artifactTimes {
	got := artifactTimes{created: s.CreatedAt, started: s.Incident.StartedAt, ended: s.Incident.EndedAt}
	for _, nested := range []struct {
		from *snapshot.Snapshot
		into *string
	}{{s.Incident.Before, &got.before}, {s.Incident.During, &got.during}, {s.Incident.Recovered, &got.recovered}} {
		if nested.from != nil {
			*nested.into = nested.from.CreatedAt
		}
	}
	return got
}

// Ordinary clocks must publish exactly the timestamps each pass was stamped
// with. Nothing is reprojected when the chronology already holds, including
// the sub-second spacing a projection would otherwise round differently.
func TestArtifactKeepsForwardClockTimestamps(t *testing.T) {
	start := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	passes := []pass{
		{0, 0, Healthy, "wlan0"},
		{5300 * time.Millisecond, 5300 * time.Millisecond, Failing, "wg0"},
		{10900 * time.Millisecond, 10900 * time.Millisecond, Failing, "wg1"},
		{15100 * time.Millisecond, 15100 * time.Millisecond, Healthy, "wlan0"},
	}
	i := observeClocks(start, passes)
	artifact := i.Artifact()
	want := artifactTimes{
		created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z", ended: "2026-09-22T12:00:15Z",
		before: "2026-09-22T12:00:00Z", during: "2026-09-22T12:00:10Z", recovered: "2026-09-22T12:00:15Z",
	}
	if got := timesOf(artifact); got != want {
		t.Fatalf("forward clock artifact times = %+v, want %+v", got, want)
	}
	if _, err := snapshot.Encode(artifact); err != nil {
		t.Fatalf("forward clock artifact does not encode: %v", err)
	}
}

// A backwards wall clock step leaves the passes' own timestamps out of order,
// while the observation times the timeline holds are still right. The artifact
// has to carry a chronology the file validator accepts, derived from the
// order and spacing the session actually observed, without the validator
// relaxing anything and without touching the runs the timeline retains.
func TestArtifactSurvivesBackwardsClock(t *testing.T) {
	start := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	s := time.Second
	tests := []struct {
		name string
		// naive is the rule the passes' own timestamps break.
		naive    string
		passes   []pass
		want     artifactTimes
		duration time.Duration
	}{
		{
			name:  "at onset",
			naive: "before state was observed after the incident started",
			passes: []pass{
				{0, time.Hour, Healthy, "wlan0"},
				{5 * s, 5 * s, Failing, "wg0"},
				{10 * s, 10 * s, Failing, "wg1"},
				{15 * s, 15 * s, Healthy, "wlan0"},
			},
			want: artifactTimes{
				created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z", ended: "2026-09-22T12:00:15Z",
				before: "2026-09-22T12:00:00Z", during: "2026-09-22T12:00:10Z", recovered: "2026-09-22T12:00:15Z",
			},
			duration: 10 * s,
		},
		{
			name:  "at onset while active",
			naive: "before state was observed after the incident started",
			passes: []pass{
				{0, time.Hour, Healthy, "wlan0"},
				{5 * s, 5 * s, Failing, "wg0"},
			},
			want: artifactTimes{
				created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z",
				before: "2026-09-22T12:00:00Z",
			},
		},
		{
			name:  "during failure",
			naive: "during state falls outside the incident",
			passes: []pass{
				{0, 0, Healthy, "wlan0"},
				{5 * s, 5 * s, Failing, "wg0"},
				{10 * s, 10*s - time.Hour, Failing, "wg1"},
				{15 * s, 15 * s, Healthy, "wlan0"},
			},
			want: artifactTimes{
				created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z", ended: "2026-09-22T12:00:15Z",
				before: "2026-09-22T12:00:00Z", during: "2026-09-22T12:00:10Z", recovered: "2026-09-22T12:00:15Z",
			},
			duration: 10 * s,
		},
		{
			name:  "during failure while active",
			naive: "during state falls outside the incident",
			passes: []pass{
				{5 * s, 5 * s, Failing, "wg0"},
				{10 * s, 10*s - time.Hour, Failing, "wg1"},
			},
			want: artifactTimes{
				created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z",
				during: "2026-09-22T12:00:10Z",
			},
		},
		{
			name:  "at recovery",
			naive: "ended before it started",
			passes: []pass{
				{0, 0, Healthy, "wlan0"},
				{5 * s, 5 * s, Failing, "wg0"},
				{10 * s, 10 * s, Failing, "wg1"},
				{15 * s, 15*s - time.Hour, Healthy, "wlan0"},
			},
			want: artifactTimes{
				created: "2026-09-22T12:00:05Z", started: "2026-09-22T12:00:05Z", ended: "2026-09-22T12:00:15Z",
				before: "2026-09-22T12:00:00Z", during: "2026-09-22T12:00:10Z", recovered: "2026-09-22T12:00:15Z",
			},
			duration: 10 * s,
		},
		{
			// A step before every pass, with sub-second spacing, so the
			// projection is exercised across more than one jump and has to
			// survive the second precision the file publishes. The onset
			// keeps its own stamp, and the rest follow from it.
			name:  "repeatedly",
			naive: "ended before it started",
			passes: []pass{
				{200 * time.Millisecond, 2 * time.Hour, Healthy, "wlan0"},
				{5700 * time.Millisecond, time.Hour + 5700*time.Millisecond, Failing, "wg0"},
				{5900 * time.Millisecond, 5900 * time.Millisecond, Failing, "wg1"},
				{16200 * time.Millisecond, 16200*time.Millisecond - time.Hour, Healthy, "wlan0"},
			},
			want: artifactTimes{
				created: "2026-09-22T13:00:05Z", started: "2026-09-22T13:00:05Z", ended: "2026-09-22T13:00:15Z",
				before: "2026-09-22T12:59:59Z", during: "2026-09-22T13:00:05Z", recovered: "2026-09-22T13:00:15Z",
			},
			duration: 10500 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := observeClocks(start, tt.passes)
			recovered := tt.want.ended != ""
			if i.Active() == recovered {
				t.Fatalf("incident active = %v, want %v", i.Active(), !recovered)
			}
			published := map[*State]string{&i.Onset: i.Onset.Snap.CreatedAt}
			for _, state := range []*State{i.Before, i.During, i.Recovered} {
				if state != nil {
					published[state] = state.Snap.CreatedAt
				}
			}

			// The runs as retained are what the old artifact published, and
			// the file validator rejects them. That rule stays as it is.
			naive := i.Onset.Snap
			naive.Incident = &snapshot.Incident{StartedAt: naive.CreatedAt, Passes: i.Passes}
			if i.Before != nil {
				naive.Incident.Before = &i.Before.Snap
			}
			if i.During != nil {
				naive.Incident.During = &i.During.Snap
			}
			if i.Recovered != nil {
				naive.Incident.Recovered, naive.Incident.EndedAt = &i.Recovered.Snap, i.Recovered.Snap.CreatedAt
			}
			if _, err := snapshot.Encode(naive); err == nil || !strings.Contains(err.Error(), tt.naive) {
				t.Fatalf("retained runs encode with error %v, want %q", err, tt.naive)
			}

			artifact := i.Artifact()
			data, err := snapshot.Encode(artifact)
			if err != nil {
				t.Fatalf("artifact does not encode: %v", err)
			}
			decoded, err := snapshot.Decode(data)
			if err != nil {
				t.Fatalf("artifact does not decode: %v", err)
			}
			got := timesOf(decoded)
			if got != tt.want {
				t.Fatalf("artifact times = %+v, want %+v", got, tt.want)
			}
			if got.created != got.started {
				t.Errorf("onset run %s does not match start %s", got.created, got.started)
			}
			if got.recovered != got.ended {
				t.Errorf("recovered run %s does not match end %s", got.recovered, got.ended)
			}
			var order []string
			for _, at := range []string{got.before, got.started, got.during, got.ended} {
				if at != "" {
					order = append(order, at)
				}
			}
			if !slices.IsSorted(order) {
				t.Errorf("artifact chronology is out of order: %v", order)
			}
			if recovered {
				if d := i.Duration(time.Time{}); d != tt.duration {
					t.Errorf("duration = %s, want %s from the observation clock", d, tt.duration)
				}
			}

			// Only the published times moved: every run is the one retained,
			// and nothing the timeline holds was rewritten to get there.
			for state, stamp := range published {
				if state.Snap.CreatedAt != stamp {
					t.Errorf("Artifact rewrote a retained run's CreatedAt from %s to %s", stamp, state.Snap.CreatedAt)
				}
			}
			root := artifact
			root.Incident = nil
			if !reflect.DeepEqual(root, i.Onset.Snap) {
				t.Error("onset run differs from the retained one")
			}
			for _, nested := range []struct {
				from *State
				into *snapshot.Snapshot
			}{{i.Before, artifact.Incident.Before}, {i.During, artifact.Incident.During}, {i.Recovered, artifact.Incident.Recovered}} {
				if (nested.from == nil) != (nested.into == nil) {
					t.Fatalf("artifact state present = %v, retained = %v", nested.into != nil, nested.from != nil)
				}
				if nested.from == nil {
					continue
				}
				run := *nested.into
				run.CreatedAt = nested.from.Snap.CreatedAt
				if !reflect.DeepEqual(run, nested.from.Snap) {
					t.Errorf("artifact run differs from the retained one beyond its timestamp")
				}
			}
			if again := i.Artifact(); !reflect.DeepEqual(again, artifact) {
				t.Error("a second Artifact call differs from the first")
			}
		})
	}
}
