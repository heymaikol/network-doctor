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
	"slices"
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
// A reading that is simply gone is not always a move. Some of the fields above
// are recorded off a connection the probe established, so a probe that stopped
// establishing one stops recording them, and the comparison reports that as a
// value becoming absent. That absence is the failure's own shadow rather than
// a second event beside it, so it is read as an outcome. The rest are read off
// the machine, survive their probe failing, and stay environmental. See
// unreadable.
//
// changes must be one whole comparison and not a subset of one: which side a
// check was working on is read from that check's own row in the same list.
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
	producers := producerOutcomes(changes)
	var out []compare.Change
	for _, c := range changes {
		if (environmental(c) && !unreadable(c, producers)) == want {
			out = append(out, c)
		}
	}
	return out
}

// producerOutcome is what one check's own row did between the two runs. Both
// ends of the status are kept rather than the direction, because the question
// here is not which way the row moved but whether it was in a position to
// record anything on each side.
type producerOutcome struct {
	before, after string
	// known is false for a check whose status is the same in both runs, which
	// a comparison does not report at all. Nothing is then suppressed on its
	// behalf: an observation that went missing while its check kept reporting
	// the same outcome is a change this package has no reason to explain away.
	known bool
	// dark is a row the comparison says did not run on one of the two sides.
	// It recorded nothing there, so every reading it would have taken is
	// missing for that reason and for no other, whether the reading was one it
	// had to connect for or one it would have read off the machine.
	dark bool
	// negativeBefore and negativeAfter are the row's own statement, on each
	// side, that the resolver answered and the answer was no records. A
	// resolver row spells that out rather than leaving it to be guessed from an
	// empty address list, and it is the difference between a lookup that
	// completed with nothing to report and one that never got an answer.
	negativeBefore, negativeAfter bool
}

// producerOutcomes reads each check's own status and whether it ran out of the
// comparison. It is the comparison's own statement about the row and not a
// second reading of the snapshots, so it cannot describe a run the changes
// beside it do not.
func producerOutcomes(changes []compare.Change) map[string]producerOutcome {
	out := make(map[string]producerOutcome)
	for _, c := range changes {
		if c.Section != compare.SectionCheck || c.Check == "" {
			continue
		}
		p := out[c.Check]
		switch c.Path {
		case "checks." + c.Check + ".status":
			p.before, p.after, p.known = c.Before, c.After, true
		case "checks." + c.Check + ".ran":
			p.dark = c.Before == "no" || c.After == "no"
		case "checks." + c.Check + ".observed.dns_not_found":
			p.negativeBefore, p.negativeAfter = c.Before == "yes", c.After == "yes"
		default:
			continue
		}
		out[c.Check] = p
	}
	return out
}

// unreadable reports that a change describes evidence going missing with the
// check that records it, rather than the environment moving.
//
// Three kinds of evidence answer that question differently, and the difference
// is what a probe had to do to obtain the value rather than how its row's
// status moved:
//
// A connection reading exists only because the probe did the work. The address
// it settled on and the local end of the socket it opened are readings off a
// connection, so a row that stopped opening one stops reporting them, and the
// comparison spells that as a value becoming absent. That absence is the
// failure's own shadow rather than a second event beside it.
//
// A system reading is taken off the machine instead: the routing table, the
// interface list, the configured nameservers, the network the radio is joined
// to. A failing probe can still read all of those, and does, so if one is gone
// it is gone because the machine changed. It stays an environment change
// however badly the row that reported it did.
//
// A derived paths reading is neither, being synthesized from the rows named in
// pathProducers. It is only as good as its inputs, so it is read as evidence
// only while every row it is read from ran.
//
// Which of the three a reading is settles most of this, but not whether the
// two runs even recorded the same things. A check that publishes a field on
// some of its branches and not others is not comparable across them at all,
// whatever kind of reading the field holds: see conditionallyPublished. And a
// reading the probe reports as absent because it asked and the answer was
// nothing is not a reading it failed to take: see answeredNothing.
//
// A reading that changed from one observed value to another is none of this.
// An interface, source address or selected address that genuinely moved was
// recorded on both sides, so it stays an environment change whatever its check
// reported.
func unreadable(c compare.Change, producers map[string]producerOutcome) bool {
	if c.Section == compare.SectionPaths {
		return slices.ContainsFunc(pathProducers[c.Path], func(id string) bool { return producers[id].dark })
	}
	if c.Kind != compare.KindAdded && c.Kind != compare.KindRemoved {
		return false
	}
	producer := producers[c.Check]
	if producer.dark {
		return true
	}
	if conditionallyPublished(c) {
		return true
	}
	if !producer.known || !connectionReading(c) || answeredNothing(c, producer) {
		return false
	}
	// The two edges a comparison spells for absence are what this turns on, so
	// it never has to decide what an empty string meant. A removal is a reading
	// the later run does not have, and it is explained when the later run is
	// where that check stopped working. An addition is the mirror image, which
	// is what a recovery comparison is full of: the socket came back and
	// brought its readings with it, and that is the failure ending rather than
	// the network moving.
	if c.Kind == compare.KindRemoved {
		return working(producer.before) && !working(producer.after)
	}
	return working(producer.after) && !working(producer.before)
}

// working reports whether a check's outcome is one a probe reached by doing its
// work. PASS and WARN both mean the probe got its answer, a warn being a
// degraded answer rather than no answer. Every other outcome is a row that
// failed, was skipped for a prerequisite, did not apply, or never reported.
//
// This is deliberately not "the status got worse". SKIP, N/A and INCOMPLETE
// have no rank to move along. It is also asked only of a connection reading:
// what a row reads off the machine it reads whatever its status, so the answer
// here says nothing about those.
func working(status string) bool {
	return status == snapshot.StatusPass || status == snapshot.StatusWarn
}

// connectionReadings are the observed fields a probe fills in from the socket
// it opened: the address it settled on, the local address the kernel gave that
// socket, and the interface that address belongs to. Addresses are here for the
// same reason one step earlier, being the answer a lookup returned rather than
// a property of the machine.
//
// Every other environmental field is read off the machine's own state and
// survives its probe failing, which is what makes this a list of fields rather
// than a rule about status.
var connectionReadings = []string{".observed.selected_ip", ".observed.source_ip", ".observed.interface"}

// systemObservers are the checks that fill the fields above by reading the
// machine rather than by connecting. The interface row walks the interface
// list: the interface it names and the source address on it are what the
// machine has assigned, so losing them is the environment moving and not a
// socket that failed to open. Its FAIL cases are exactly that event, "no
// interface up" and "selected source address is no longer assigned".
var systemObservers = map[string]bool{"iface": true}

func connectionReading(c compare.Change) bool {
	if systemObservers[c.Check] {
		return false
	}
	if strings.Contains(c.Path, ".observed.addresses.") {
		return true
	}
	return slices.ContainsFunc(connectionReadings, func(f string) bool { return strings.HasSuffix(c.Path, f) })
}

// conditionalPublications are the observed fields a check attaches on some of
// its branches and not on others. The reading is the same on both, so the
// comparison reporting it arriving or leaving is the producer having taken a
// different branch rather than the machine having changed.
//
// Two rows do this, and both of them publish the field off the outcome of the
// work rather than off the status the row ends on.
//
// internet_tcp starts its route lookup on every run, but attaches the answer
// only where no address in either family completed a handshake, so a pass
// records no route to the connectivity endpoint and the failure beside it
// records the unchanged one. Every other row that records routes records them
// on all of its branches: the interface row takes its reference paths outside
// the probe entirely, and the DNS and target rows assign theirs on each branch
// they can return from. Route evidence from those rows stays environmental
// however their own check fared.
//
// dns_public names the second-opinion server on the branches that have an
// answer to attribute to it, and on two N/A branches it has none: the one where
// this machine resolves the name without DNS, which leaves the public server's
// answer unprovable, and the one where no query left the machine at all. The
// resolver did not move in either case, and the row is still querying whatever
// --public-dns or the candidate list named. What that run dialed is a separate
// reading with its own meaning, so resolver_targets is not covered here: a
// branch that stops dialing anything is the machine declining to ask, and it
// stays an environment change.
var conditionalPublications = map[string]string{
	"internet_tcp": ".observed.routes",
	"dns_public":   ".observed.resolver",
}

// conditionallyPublished reports that a reading appearing or disappearing is
// the branch its check took and not the value moving. Two runs that both
// recorded the field were both on the branch that publishes it, so a value that
// differs between them differs for real, and only the added and removed edges
// reach this at all.
//
// The field is matched whole: a scalar ends the path, and a collection is
// followed by the member it names. Nothing else under the same prefix is
// covered, which is what keeps observed.resolver_targets out of the resolver
// entry.
func conditionallyPublished(c compare.Change) bool {
	field, ok := conditionalPublications[c.Check]
	return ok && (strings.HasSuffix(c.Path, field) || strings.Contains(c.Path, field+"."))
}

// answeredNothing reports that the resolver answered on the side the addresses
// are missing from, and that the answer was no records.
//
// An empty address list means two different things, and the row does not leave
// which one to be guessed: it records whether the lookup came back with no
// records at all. A completed negative answer is the answer set moving from
// some records to none, which is a real change in what this machine resolves,
// and it stays environmental however the row's own status reads. An address
// list emptied by a lookup that never came back is the failure's own shadow and
// is suppressed like any other reading the probe did not get to take.
func answeredNothing(c compare.Change, p producerOutcome) bool {
	if !strings.Contains(c.Path, ".observed.addresses.") {
		return false
	}
	if c.Kind == compare.KindRemoved {
		return p.negativeAfter
	}
	return p.negativeBefore
}

// pathProducers names the check rows each derived paths field is read from.
// The comparison derives that section on both sides from the routes those rows
// recorded and attributes it to no check, because it is a reading of the run
// rather than of any one row. That leaves nothing on the change itself to say
// whose evidence went quiet, so the ownership is stated here, on the side that
// needs it, rather than by widening the published comparison.
//
// agreement is read from two rows at once: it compares where the resolver
// traffic went with where the application traffic went, and a row that did not
// run leaves its half empty, which reads as a disagreement that nothing
// observed. So it is only as good as the weaker of the two.
var pathProducers = map[string][]string{
	"paths.target.interface":    {"target_tcp"},
	"paths.target.prefix":       {"target_tcp"},
	"paths.target.reason":       {"target_tcp"},
	"paths.target.tunnel":       {"target_tcp"},
	"paths.reference.interface": {"iface"},
	"paths.resolver.interface":  {"dns"},
	"paths.resolver.agreement":  {"dns", "target_tcp"},
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
	var dropped int
	t.incidents, dropped = keepNewest(append(t.incidents, incident), maxIncidents)
	t.dropped += dropped
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
	var dropped int
	active.Steps, dropped = keepNewest(append(active.Steps, Step{At: state.At, Changes: changes}), maxSteps)
	active.StepsDropped += dropped
	return TransitionChanged
}

// keepNewest bounds items to its newest limit entries, oldest first, and
// reports how many older ones it dropped. The survivors move to the front of
// the backing array and the slots they vacate are zeroed, so the array holds
// nothing the bound discarded. Reslicing the tail instead would leave dropped
// entries, and every run they point to, reachable through the array's head.
//
// Every slot past len is therefore zero: append only writes at len, and this
// is the only place a retained list shrinks.
func keepNewest[T any](items []T, limit int) ([]T, int) {
	dropped := len(items) - limit
	if dropped <= 0 {
		return items, 0
	}
	copy(items, items[dropped:])
	clear(items[limit:])
	return items[:limit], dropped
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
