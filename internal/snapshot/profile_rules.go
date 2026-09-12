package snapshot

import "slices"

// This file holds the profile semantics that both a producer and a reader have
// to agree on, written once and in primitives.
//
// A profile artifact states its conclusions twice: once as the envelope's
// component statuses, aggregate status and aggregate finding, and once as the
// complete ordinary runs nested inside it. The envelope is the layer a script
// reads first and the nested runs are the evidence, so the two contradicting
// each other is the artifact answering one question two ways.
//
// The rules live here, in the package that owns the file format, because that
// is the only place both callers can reach: internal/profile is a higher layer
// and builds the envelope from reports, this package validates it from
// snapshots, and neither may import the other. They take strings rather than
// either package's structs for the same reason. Nothing here knows what a
// probe or a report is, and nothing here writes prose: the summary sentences
// stay with the package that has the labels to write them.

// VerdictDegraded is the one diagnosis verdict a profile's reading of a
// component turns on: a run where everything asked for works but some rung is
// impaired is not a clean component. The word is written down here rather than
// imported because this package cannot see internal/diagnostic, which is where
// a live run spells it. TestProfileRulesMatchTheDiagnosisVocabulary in
// internal/profile fails if the two ever part company.
const VerdictDegraded = "degraded"

// Profile conclusions, which are also the suffixes of the aggregate finding
// ids a profile publishes. Each one is a different thing to tell a person, and
// the id is how automation branches on which.
const (
	ProfileAllReachable        = "all_reachable"
	ProfileNoneReachable       = "unreachable"
	ProfileFallbackAvailable   = "fallback_available"
	ProfileFallbackUnavailable = "fallback_unavailable"
	ProfilePartialReachability = "partial_reachability"
)

// ProfileComponentStatus is a profile's reading of one whole component run.
//
// focusStatus is the status of the row the component was about, and empty
// means the run carries no such row: a component whose service check never
// appeared was not tested, which is a skip rather than a pass. INCOMPLETE
// falls through to the same place a pass with an unclean run does, because a
// run that never finished reporting took its own ok down with it.
//
// The status a component can hold is the ordinary vocabulary minus INCOMPLETE.
// A check row is one probe's outcome and can be left unreported; a component
// status is a reading of an entire run, and there is always a reading.
func ProfileComponentStatus(focusStatus, verdict string, ok bool) string {
	switch focusStatus {
	case "":
		return StatusSkip
	case StatusFail, StatusSkip, StatusNA, StatusWarn:
		return focusStatus
	}
	if !ok || verdict == VerdictDegraded {
		return StatusWarn
	}
	return StatusPass
}

// ProfileComponentOutcome is everything the aggregation reads off one
// component: who it is, how it came out, and which component it stands in for.
type ProfileComponentOutcome struct {
	ID       string
	Status   string
	Fallback string
}

// ProfileAggregation is what a profile's components add up to. Unavailable and
// Available name the two components a fallback conclusion is about, and are
// empty for every other conclusion; the package that has the labels turns them
// into a sentence.
type ProfileAggregation struct {
	Conclusion string
	Status     string
	Affected   []string
	Working    []string

	Unavailable string
	Available   string
}

// FindingID is the identity this conclusion publishes, or empty when a profile
// whose components all passed has nothing to name.
func (a ProfileAggregation) FindingID(profileName string) string {
	if a.Conclusion == ProfileAllReachable {
		return ""
	}
	return profileName + "_" + a.Conclusion
}

// AggregateProfile reduces the components to the profile's own conclusion.
//
// A component that warns is working: the service answered, and something about
// the path to it was worth saying. Anything else is affected, so a component
// can be both working and affected, which is the honest reading of a degraded
// path and is why the two lists are published rather than derived from each
// other.
func AggregateProfile(components []ProfileComponentOutcome) ProfileAggregation {
	a := ProfileAggregation{Conclusion: ProfileAllReachable, Status: StatusPass}
	for _, component := range components {
		if component.Status == StatusPass || component.Status == StatusWarn {
			a.Working = append(a.Working, component.ID)
		}
		if component.Status != StatusPass {
			a.Affected = append(a.Affected, component.ID)
		}
	}
	if len(a.Affected) == 0 {
		return a
	}
	if len(a.Working) == 0 {
		a.Conclusion, a.Status = ProfileNoneReachable, StatusFail
		return a
	}
	a.Conclusion, a.Status = ProfilePartialReachability, StatusWarn
	// A fallback conclusion is only honest about a single affected component.
	// With two of them down, naming one as covered by its stand-in would be
	// describing a working service.
	if len(a.Affected) != 1 {
		return a
	}
	down := a.Affected[0]
	for _, component := range components {
		if component.Fallback == down && slices.Contains(a.Working, component.ID) {
			a.Conclusion = ProfileFallbackAvailable
			a.Unavailable, a.Available = down, component.ID
			return a
		}
	}
	for _, component := range components {
		if component.ID == down && component.Fallback != "" && slices.Contains(a.Working, component.Fallback) {
			a.Conclusion = ProfileFallbackUnavailable
			a.Unavailable, a.Available = down, component.Fallback
			return a
		}
	}
	return a
}
