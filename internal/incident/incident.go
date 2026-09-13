// Package incident reconstructs what a watch session saw around a failure.
//
// Watch mode reruns the same checks every few seconds. On its own that is a
// stream of passes the reader has to hold in their head: something broke a
// minute ago, something else looked different just before it, and by the time
// the failure is on screen the state it started in is gone. This package keeps
// that state instead, and answers the question the stream cannot: what the
// network looked like before the failure, what changed when it began, whether
// it stayed the same while it lasted, and what changed when it recovered.
//
// It introduces no state of its own. A pass is one snapshot, the same artifact
// --save writes, and the difference between two of them is one comparison, the
// same one --compare reports. What this package adds is the lifecycle: which
// passes are worth keeping, which failing passes belong to the same incident,
// and when one ends.
//
// Nothing here reaches the network, reads a clock, or renders anything. The
// caller supplies both the pass and the time it was observed, so a session can
// be replayed exactly in a test, and the sentences below are the same on every
// machine.
//
// On causality: a change seen in the pass a failure began is a coincidence in
// time. It is evidence and it is worth putting in front of a reader, and it is
// not proof that the change caused the failure. Every sentence this package
// produces is written to say the first thing and not the second.
package incident

import (
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Retention. A watch session runs for as long as someone leaves it running, so
// everything kept here is capped, and what is dropped is dropped explicitly
// rather than by being overwritten in place.
//
// Only four runs are ever retained per incident, and only one outside of them:
// the last pass that was not failing, which is the state an incident is opened
// against.
const (
	// maxIncidents caps the session's list. Each one retains up to four runs,
	// so this is the ceiling on everything the timeline holds.
	maxIncidents = 10
	// maxSteps caps the recorded moves within one incident. A failure that
	// keeps changing shape is exactly the case that would otherwise grow
	// without limit, so the newest are kept and the rest are counted.
	maxSteps = 8
)

// Health is what one watch pass saw, in the vocabulary the run itself uses:
// ok is the same rule as the exit code, and a warn is a check that worked in a
// degraded way rather than one that failed.
type Health string

const (
	Healthy  Health = "healthy"
	Degraded Health = "degraded"
	Failing  Health = "failing"
)

// Classify reads one pass's health off the run it recorded. Failing is the
// snapshot's own ok, so an incident opens on exactly the condition that makes
// netdoc exit 1, and a warn is reported for what it is rather than promoted to
// a failure or hidden behind a pass.
func Classify(s snapshot.Snapshot) Health {
	if !s.OK {
		return Failing
	}
	for _, c := range s.Checks {
		if c.Status == snapshot.StatusWarn {
			return Degraded
		}
	}
	return Healthy
}

// Transition is what one observed pass did to the timeline. The caller uses it
// to decide whether anything is worth acting on, such as rewriting a recording.
type Transition string

const (
	// TransitionNone is a pass outside any incident: nothing was failing
	// before it and nothing is failing now.
	TransitionNone Transition = "none"
	// TransitionBegan is the first failing pass of an incident.
	TransitionBegan Transition = "began"
	// TransitionFailing is another failing pass of the incident already open,
	// describing the same state as the last one recorded.
	TransitionFailing Transition = "failing"
	// TransitionChanged is a failing pass whose state moved.
	TransitionChanged Transition = "changed"
	// TransitionRecovered is the first pass after an incident that is not
	// failing, which is what closes it.
	TransitionRecovered Transition = "recovered"
)

// State is one retained run and when it was observed.
type State struct {
	At   time.Time
	Snap snapshot.Snapshot
}

// Step is one move a failure made while it lasted: when the failing state
// stopped describing what the previous recorded one did, and what differed.
type Step struct {
	At      time.Time
	Changes []compare.Change
}

// Incident is one failure, from the pass it began in to the pass that ended
// it, with the runs on either side of both.
//
// The changes are computed once, when the pass that produced them is observed,
// and kept: they are a comparison of two runs this incident holds, so they say
// the same thing whenever they are read.
type Incident struct {
	Started time.Time
	// Ended is the zero time while the incident is still open.
	Ended time.Time
	// Passes counts the failing passes observed, the onset included.
	Passes int
	// Before is the last pass that was not failing, absent when the session
	// began during this failure. There is then no earlier state, and none is
	// invented for the comparison's sake.
	Before *State
	// Onset is the first failing pass.
	Onset State
	// During is the most recent failing pass, kept only once it differs from
	// the onset.
	During *State
	// Recovered is the pass that ended the incident, absent while it is open.
	Recovered *State
	// OnsetChanges is what differed between Before and Onset, empty when there
	// was no earlier pass to compare against or when nothing differed.
	OnsetChanges []compare.Change
	// Steps are the moves within the failure, oldest first, capped.
	Steps []Step
	// StepsDropped counts moves the cap discarded, so a truncated list says so
	// rather than reading as the whole of what happened.
	StepsDropped int
	// RecoveryChanges is what differed between the last failing pass and the
	// pass that ended the incident.
	RecoveryChanges []compare.Change
}

// Active reports whether this incident was still failing when last observed.
func (i Incident) Active() bool { return i.Ended.IsZero() }

// Duration is how long the incident lasted, measured between the passes that
// opened and closed it. While one is open it is measured against now, so a
// caller has to supply the same clock it observes with.
//
// It is a span between two observations and not a measurement of the outage:
// the failure started at some point in the gap before the pass that saw it.
func (i Incident) Duration(now time.Time) time.Duration {
	end := i.Ended
	if end.IsZero() {
		end = now
	}
	if end.Before(i.Started) {
		return 0
	}
	return end.Sub(i.Started)
}

// Latest is the most recent failing run of this incident: the onset until the
// failure's state moves, and what it moved to afterwards.
func (i Incident) Latest() State {
	if i.During != nil {
		return *i.During
	}
	return i.Onset
}

// Coincidence is what the passes on either side of the onset support, and
// deliberately not what caused the failure.
type Coincidence string

const (
	// CoincidenceUnknown is an incident with no earlier pass to compare
	// against, because the session began inside the failure.
	CoincidenceUnknown Coincidence = "unknown"
	// CoincidenceEnvironmentChanged is a failure that began in the same pass
	// as a change in how this machine reaches the network.
	CoincidenceEnvironmentChanged Coincidence = "environment_changed"
	// CoincidenceEnvironmentSteady is a failure that began while how this
	// machine reaches the network stayed as it was.
	CoincidenceEnvironmentSteady Coincidence = "environment_steady"
)

// Coincidence reads the onset comparison for what it can support.
func (i Incident) Coincidence() Coincidence {
	if i.Before == nil {
		return CoincidenceUnknown
	}
	if len(Environment(i.OnsetChanges)) > 0 {
		return CoincidenceEnvironmentChanged
	}
	return CoincidenceEnvironmentSteady
}

// Note is the sentence to print under an incident: what the onset supports,
// stated as a coincidence in time. Nothing here claims a cause, because two
// things happening in the same five second pass is evidence of that and of
// nothing more.
func (i Incident) Note() string {
	switch i.Coincidence() {
	case CoincidenceUnknown:
		return "This watch session began during the failure, so there is no earlier pass to compare it with."
	case CoincidenceEnvironmentChanged:
		n := len(Environment(i.OnsetChanges))
		return "The failure began in the same pass as " + strconv.Itoa(n) + " " +
			plural(n, "change") + " in how this machine reaches the network. " +
			"Sharing a pass places them within seconds of each other; it does not establish that one caused the other."
	default:
		return "No recorded change in how this machine reaches the network coincided with the failure. " +
			"The failure's own diagnostic evidence remains the basis for its diagnosis."
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// Environment keeps the changes that describe how this machine reaches the
// network: the derived paths reading, and the route, interface, source
// address, resolvers named and dialed, network name and resolved addresses a
// check recorded.
//
// The rest of a comparison is what the checks made of that environment, which
// is the failure itself rather than a candidate explanation for it. The split
// is what lets an incident say "the route moved when this broke" and "nothing
// moved when this broke" as two different answers.
//
// Order is the comparison's own, so the same two runs always produce the same
// list. A change this does not recognize counts as an outcome, which is the
// reading that claims less.
func Environment(changes []compare.Change) []compare.Change {
	return filter(changes, true)
}

// Outcome is every change Environment leaves behind: what the checks reported,
// and what the diagnosis made of it.
func Outcome(changes []compare.Change) []compare.Change {
	return filter(changes, false)
}

func filter(changes []compare.Change, want bool) []compare.Change {
	var out []compare.Change
	for _, c := range changes {
		if environmental(c) == want {
			out = append(out, c)
		}
	}
	return out
}

// environmentalFields are the observed fields on a check row that describe the
// path traffic took rather than what happened on it. They are matched against
// the stable path a comparison gives every change, which is the identity that
// exists to be keyed on.
//
// The scalar ones end the path, so they are matched at its end. A field the
// comparison reports per member does not: its path carries the member after
// the field name, and those are listed separately below.
var environmentalFields = []string{
	".observed.interface", ".observed.source_ip", ".observed.ssid",
	".observed.resolver", ".observed.selected_ip",
}

// environmentalCollections are the observed fields a comparison reports one
// member at a time, so the field name sits in the middle of the path and the
// member the run recorded follows it. The trailing dot is what keeps a
// prefix from matching a longer field name that starts the same way.
//
// resolver_targets is here because it is where a system resolver's identity
// now lives. Observed.Resolver is only ever the second-opinion server this run
// was told to ask, so the nameserver the machine itself was handed reaches a
// comparison through this field and through no other.
var environmentalCollections = []string{
	".observed.routes.", ".observed.addresses.", ".observed.resolver_targets.",
}

func environmental(c compare.Change) bool {
	switch c.Section {
	case compare.SectionPaths:
		return true
	case compare.SectionCheck:
		for _, collection := range environmentalCollections {
			if strings.Contains(c.Path, collection) {
				return true
			}
		}
		for _, field := range environmentalFields {
			if strings.HasSuffix(c.Path, field) {
				return true
			}
		}
	}
	return false
}

// Artifact is this incident as a portable snapshot: the onset run, which is
// the failure the file is about, carrying the runs around it.
//
// The comparisons are not written into the file. A reader derives them from
// the records the same way this package did, so the artifact cannot hold an
// answer that disagrees with the states it also holds.
func (i Incident) Artifact() snapshot.Snapshot {
	s := i.Onset.Snap
	record := &snapshot.Incident{
		StartedAt: stamp(i.Started),
		Passes:    i.Passes,
	}
	if !i.Ended.IsZero() {
		record.EndedAt = stamp(i.Ended)
	}
	for _, state := range []struct {
		from *State
		into **snapshot.Snapshot
	}{
		{i.Before, &record.Before},
		{i.During, &record.During},
		{i.Recovered, &record.Recovered},
	} {
		if state.from != nil {
			nested := state.from.Snap
			nested.Incident = nil // a run record is one run
			*state.into = &nested
		}
	}
	s.Incident = record
	return s
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Timeline is one watch session's incident history. It owns everything it
// retains and holds nothing else: when the session ends the whole of it goes
// with the process, and a new target starts a new one, because incidents are
// about the endpoint that was being watched.
//
// The zero value is a session that has observed nothing.
type Timeline struct {
	incidents []Incident
	// open says the last incident in the list is still failing. It is a flag
	// rather than a pointer so a Timeline can be copied without two of them
	// writing through to the same incident.
	open bool
	// baseline is the last pass that was not failing, the state the next
	// incident will be opened against.
	baseline *State
	// dropped counts incidents the cap discarded.
	dropped int
}

// Observe records one finished watch pass and reports what it did to the
// session. at is when the pass completed; s is the run it produced.
//
// The pass is compared against at most one retained run, so the work here is
// one comparison whatever the session's length, and what is retained is capped
// whatever its shape.
func (t *Timeline) Observe(at time.Time, s snapshot.Snapshot) Transition {
	// A pass that disagrees with the retained ones about the target, the tool,
	// the run options or the check graph is not a later pass of this session,
	// and folding it in would produce an incident claiming two sessions were
	// one. Production reaches this only through a target switch, which already
	// discards the timeline, so this is the same rule stated where the state
	// lives rather than a second policy: what cannot be the same session
	// starts a new one, and nothing incompatible is ever compared or retained.
	if held, ok := t.held(); ok && snapshot.WatchSessionMismatch(held, s) != "" {
		*t = Timeline{}
	}
	health := Classify(s)
	state := State{At: at, Snap: s}
	if health == Failing {
		if !t.open {
			t.begin(state)
			return TransitionBegan
		}
		return t.continued(state)
	}
	// Not failing: this pass ends whatever was open and becomes the state the
	// next incident is opened against. A degraded pass counts for both, since
	// a warn is a working network and the last of those is the most useful
	// thing to compare a later failure with.
	transition := TransitionNone
	if t.open {
		t.recover(state)
		transition = TransitionRecovered
	}
	baseline := state
	t.baseline = &baseline
	return transition
}

// held is any run this timeline still retains, which is enough to decide
// session compatibility: everything retained was already checked against
// everything else retained, so one is representative of all of them.
func (t *Timeline) held() (snapshot.Snapshot, bool) {
	if t.baseline != nil {
		return t.baseline.Snap, true
	}
	if len(t.incidents) > 0 {
		return t.incidents[len(t.incidents)-1].Onset.Snap, true
	}
	return snapshot.Snapshot{}, false
}

func (t *Timeline) begin(state State) {
	incident := Incident{Started: state.At, Onset: state, Passes: 1, Before: t.baseline}
	if t.baseline != nil {
		incident.OnsetChanges = compare.Snapshots(t.baseline.Snap, state.Snap).Changes
	}
	t.incidents = append(t.incidents, incident)
	if len(t.incidents) > maxIncidents {
		t.dropped += len(t.incidents) - maxIncidents
		t.incidents = t.incidents[len(t.incidents)-maxIncidents:]
	}
	t.open = true
}

// continued folds another failing pass into the open incident. The pass is
// compared against the last failing state recorded, so a failure that holds
// still costs one comparison and retains nothing, and only a failure that
// moves replaces the state and records the move.
func (t *Timeline) continued(state State) Transition {
	active := &t.incidents[len(t.incidents)-1]
	active.Passes++
	changes := compare.Snapshots(active.Latest().Snap, state.Snap).Changes
	if len(changes) == 0 {
		return TransitionFailing
	}
	during := state
	active.During = &during
	active.Steps = append(active.Steps, Step{At: state.At, Changes: changes})
	if len(active.Steps) > maxSteps {
		active.StepsDropped += len(active.Steps) - maxSteps
		active.Steps = active.Steps[len(active.Steps)-maxSteps:]
	}
	return TransitionChanged
}

func (t *Timeline) recover(state State) {
	active := &t.incidents[len(t.incidents)-1]
	active.Ended = state.At
	recovered := state
	active.Recovered = &recovered
	active.RecoveryChanges = compare.Snapshots(active.Latest().Snap, state.Snap).Changes
	t.open = false
}

// Incidents is the session's incidents, oldest first, with the open one last
// when there is one. The slice is the timeline's own; callers read it.
func (t *Timeline) Incidents() []Incident { return t.incidents }

// Active is the incident still failing, and false when the last pass observed
// was not a failing one.
func (t *Timeline) Active() (Incident, bool) {
	if !t.open {
		return Incident{}, false
	}
	return t.incidents[len(t.incidents)-1], true
}

// Latest is the most recent incident, open or closed.
func (t *Timeline) Latest() (Incident, bool) {
	if len(t.incidents) == 0 {
		return Incident{}, false
	}
	return t.incidents[len(t.incidents)-1], true
}

// Dropped is how many incidents the retention cap discarded, oldest first.
func (t *Timeline) Dropped() int { return t.dropped }
