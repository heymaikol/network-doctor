package simulation

import (
	"testing"
	"time"
)

func applied(offset time.Duration, e TimedEvent) FaultEventEvidence {
	return FaultEventEvidence{Event: e, ScheduledOffset: offset, AppliedOffset: offset,
		State: e.summary(), Result: EventApplied}
}

func dnsEvent(outcome string) TimedEvent {
	return TimedEvent{Type: FaultScheduledDNS, Service: "r", Outcome: outcome}
}

func timedReport(timeline []FaultEventEvidence, tests ...TestOutcome) *Report {
	return &Report{Timeline: timeline, Tests: tests}
}

func codes(in []Suggestion) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s.Code] = true
	}
	return out
}

// dropped is the trace a query leaves at a silenced resolver: it arrived, and
// the service chose not to answer. Its presence is what proves the client had a
// path to the resolver at all.
func dropped(offset time.Duration) DNSQueryEvidence {
	return DNSQueryEvidence{Service: "r", Offset: offset, ActualOutcome: "DROPPED", OffsetKnown: true}
}

func TestResamplingGapNeedsRecoveryInsideTheRunAndNoLaterQuery(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(0, dnsEvent(DNSOutcomeAnswer)),
		applied(100*time.Millisecond, dnsEvent(DNSOutcomeDrop)),
		applied(500*time.Millisecond, dnsEvent(DNSOutcomeAnswer)),
	}
	failing := TestOutcome{Name: "t", StartOffset: 50 * time.Millisecond, EndOffset: 2 * time.Second,
		Diagnosis: diag("dns", DiagnosisCheck{ID: "dns", Status: "FAIL", Cause: "dns_timeout"})}

	rep := timedReport(timeline, failing)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{dropped(150 * time.Millisecond)}
	if !codes(rep.timelineSuggestions())[SuggestTransientNotResampled] {
		t.Errorf("no resampling gap where the resolver recovered mid-run: %+v", rep.timelineSuggestions())
	}

	// A query that reached the recovered resolver inside the same run means
	// netdoc did resample; there is no gap to report.
	rep = timedReport(timeline, failing)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{dropped(150 * time.Millisecond),
		{Service: "r", Offset: 600 * time.Millisecond, ActualOutcome: "ANSWER", OffsetKnown: true}}
	if codes(rep.timelineSuggestions())[SuggestTransientNotResampled] {
		t.Errorf("resampling gap reported although a later query was answered: %+v", rep.timelineSuggestions())
	}

	// Recovery after the run ended is not something netdoc could have seen.
	late := failing
	late.EndOffset = 200 * time.Millisecond
	rep = timedReport(timeline, late)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{dropped(150 * time.Millisecond)}
	if codes(rep.timelineSuggestions())[SuggestTransientNotResampled] {
		t.Errorf("resampling gap reported for a recovery outside the run: %+v", rep.timelineSuggestions())
	}
}

// A resolver that netdoc's queries never reached is not evidence about
// resampling. When the path to it is blackholed, by a route fault the resolver
// schedule knows nothing about, the resolver records no query before the
// outage and none after it recovers, and that second silence is the path
// rather than a sample netdoc declined to take. Reading it as a coverage gap
// accuses netdoc of skipping a query it did send and that never arrived, and
// it also has nothing left to call transient: the failure outlives the run.
func TestTimelineSuggestionsIgnoreAResolverNoQueryReached(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(0, dnsEvent(DNSOutcomeAnswer)),
		applied(150*time.Millisecond, dnsEvent(DNSOutcomeDrop)),
		applied(770*time.Millisecond, dnsEvent(DNSOutcomeAnswer)),
	}
	blackholed := TestOutcome{Name: "t", EndOffset: 4 * time.Second,
		Diagnosis: diag("Offline: neither direct egress nor DNS is working.",
			DiagnosisCheck{ID: "dns", Status: "FAIL", Cause: "dns_timeout"})}

	rep := timedReport(timeline, blackholed)
	got := codes(rep.timelineSuggestions())
	if got[SuggestTransientNotResampled] || got[SuggestTransientReportedPermanent] {
		t.Errorf("transient reported for a resolver no query reached: %+v", rep.timelineSuggestions())
	}

	// The only difference that matters: one query got through before the
	// outage healed. Now the silence afterwards is netdoc's to answer for.
	rep = timedReport(timeline, blackholed)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{dropped(200 * time.Millisecond)}
	if !codes(rep.timelineSuggestions())[SuggestTransientNotResampled] {
		t.Errorf("no resampling gap although a query reached the resolver: %+v", rep.timelineSuggestions())
	}

	// Timing the director could not place is not proof of a reachable path.
	rep = timedReport(timeline, blackholed)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{{Service: "r", ActualOutcome: "DROPPED"}}
	got = codes(rep.timelineSuggestions())
	if got[SuggestTransientNotResampled] || got[SuggestTransientReportedPermanent] {
		t.Errorf("transient reported from a query with no known offset: %+v", rep.timelineSuggestions())
	}

	// Another resolver's traffic proves nothing about the path to this one.
	// The premise is checked before the later-query loop, so a scenario with a
	// second resolver cannot borrow its way into either finding.
	rep = timedReport(timeline, blackholed)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{{Service: "other", Offset: 200 * time.Millisecond,
		ActualOutcome: "DROPPED", OffsetKnown: true}}
	got = codes(rep.timelineSuggestions())
	if got[SuggestTransientNotResampled] || got[SuggestTransientReportedPermanent] {
		t.Errorf("transient reported from another resolver's queries: %+v", rep.timelineSuggestions())
	}

	// A query that only arrives after the recovery is not a gap either: it is
	// netdoc resampling, and it still says nothing about a path that was
	// carrying nothing while the resolver was silent.
	rep = timedReport(timeline, blackholed)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{{Service: "r", Offset: 900 * time.Millisecond,
		ActualOutcome: "ANSWER", OffsetKnown: true}}
	if codes(rep.timelineSuggestions())[SuggestTransientNotResampled] {
		t.Errorf("resampling gap reported although the only query landed after recovery: %+v", rep.timelineSuggestions())
	}
}

func TestPermanentWordingRespectsAPointInTimeClaim(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(0, TimedEvent{Type: FaultScheduledLink, Node: "target", Segment: "lan", State: LinkStateDown}),
		applied(400*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "target", Segment: "lan", State: LinkStateUp}),
	}
	blunt := TestOutcome{Name: "t", EndOffset: time.Second,
		Diagnosis: &Diagnosis{Summary: "the target is unreachable: remote port closed or firewalled",
			Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Detail: "port 80 unreachable"}}}}
	if !codes(timedReport(timeline, blunt).timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Error("a healed failure described as a lasting state was not reported")
	}

	// A diagnosis that says it is describing a moment is not wrong merely
	// because the network recovered afterwards.
	careful := blunt
	careful.Diagnosis = &Diagnosis{Summary: "the target was unreachable at the time of this check",
		Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Detail: "port 80 unreachable"}}}
	if codes(timedReport(timeline, careful).timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Error("a point-in-time claim was reported as overstating a transient failure")
	}
}

// A resolver outage that healed mid-run explains a DNS failure, not whatever
// unrelated check happens to fail first in the same diagnosis.
func TestPermanentWordingPairsTheRecoveryWithTheFailureItExplains(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(100*time.Millisecond, dnsEvent(DNSOutcomeDrop)),
		applied(500*time.Millisecond, dnsEvent(DNSOutcomeAnswer)),
	}
	unrelated := TestOutcome{Name: "t", EndOffset: time.Second,
		Diagnosis: diag("no HTTP response from the target: application-layer or proxy block",
			DiagnosisCheck{ID: "dns", Status: "PASS"},
			DiagnosisCheck{ID: "http", Status: "FAIL", Detail: "connection reset"})}
	if codes(timedReport(timeline, unrelated).timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a healed DNS outage was pinned to an unrelated HTTP failure: %+v",
			timedReport(timeline, unrelated).timelineSuggestions())
	}

	dnsFailed := unrelated
	dnsFailed.Diagnosis = diag("DNS is not resolving", DiagnosisCheck{ID: "dns", Status: "FAIL"})
	// The resample happened, so only the wording is at issue here.
	rep := timedReport(timeline, dnsFailed)
	rep.Evidence.DNSQueries = []DNSQueryEvidence{{Service: "r", Offset: 600 * time.Millisecond, ActualOutcome: "ANSWER", OffsetKnown: true}}
	if !codes(rep.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Error("a healed DNS outage was not paired with the DNS failure it explains")
	}
}

// A dropped query followed by an answered one is a resolver that recovered and
// a netdoc that resampled it, so PASS is the truth, not a missed failure.
func TestDNSFailureDuringJudgesTheLastQueryPerService(t *testing.T) {
	test := TestOutcome{EndOffset: time.Second}
	recovered := []DNSQueryEvidence{
		{Service: "r", Offset: 200 * time.Millisecond, ActualOutcome: "DROPPED", OffsetKnown: true},
		{Service: "r", Offset: 700 * time.Millisecond, ActualOutcome: "ANSWER", OffsetKnown: true},
	}
	if dnsFailureDuring(test, recovered) {
		t.Error("a resolver that answered the resample was reported as still failing")
	}
	if !dnsFailureDuring(test, append(recovered,
		DNSQueryEvidence{Service: "public", Offset: 800 * time.Millisecond, ActualOutcome: "SERVFAIL", OffsetKnown: true})) {
		t.Error("a second resolver still failing at the end of the run was not reported")
	}
}

// unrelatedSpike is a netem spike on a segment the failed probe does not sit
// behind, cleared again inside the run. It starts from the unimpaired state the
// recorded timelines begin with.
func unrelatedSpike(node, segment string, at, cleared, latency time.Duration, loss float64) []FaultEventEvidence {
	return []FaultEventEvidence{
		applied(0, TimedEvent{Type: FaultScheduledNetem, Node: node, Segment: segment}),
		applied(at, TimedEvent{Type: FaultScheduledNetem, Node: node, Segment: segment, Latency: latency, LossPercent: loss}),
		applied(cleared, TimedEvent{Type: FaultScheduledNetem, Node: node, Segment: segment}),
	}
}

// targetDial is the simulator's own dial from the client to one endpoint after
// the run ended. Every scheduled event has been applied or skipped by then, so
// it says whether the endpoint is still down once the recovery has happened.
func targetDial(to, outcome string) ControlledTargetEvidence {
	return ControlledTargetEvidence{From: "client", To: to, Reachable: outcome == FamilyStateReachable, Outcome: outcome}
}

// The four Hunt cases recorded in #437, rebuilt from their stored reports. Each
// has a target fault that stays in place for the whole run and an unrelated
// netem spike that clears inside it. The diagnosis and the dials are the
// recorded values; the offsets are rounded to the millisecond. Each attempt list is
// rebuilt from the address list in its Detail, because stored hunt reports drop
// attempts in canonicalization and the live report carries them.
func TestPermanentWordingIgnoresAnUnrelatedRecoveryOfAPersistentTargetFault(t *testing.T) {
	refused := "refused"
	for _, tc := range []struct {
		name     string
		timeline []FaultEventEvidence
		test     TestOutcome
		dials    []ControlledTargetEvidence
	}{
		{
			name:     "dual-stack refusal, stress case 6",
			timeline: unrelatedSpike("gateway", "upstream", 164*time.Millisecond, 1145*time.Millisecond, 401*time.Millisecond, 15.18),
			test: TestOutcome{Name: "both address families cross the router", Node: "client", Target: "dual-target.test:80",
				StartOffset: 4 * time.Millisecond, EndOffset: 2077 * time.Millisecond,
				Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Cause: "connection_refused",
					Attempts: []DiagnosisAttempt{{IP: "10.78.2.20", Cause: "refused"}, {IP: "2001:db8:77:2::20", Cause: "refused"}}, Detail: "connection to port 80 was refused on all 2 attempted address(es): 10.78.2.20, 2001:db8:77:2::20"}}}},
			dials: []ControlledTargetEvidence{targetDial("10.78.2.20:80", refused), targetDial("[2001:db8:77:2::20]:80", refused)},
		},
		{
			name:     "dual-stack refusal, stress case 9",
			timeline: unrelatedSpike("gateway", "upstream", 189*time.Millisecond, 1052*time.Millisecond, 485*time.Millisecond, 18.07),
			test: TestOutcome{Name: "both address families cross the router", Node: "client", Target: "dual-target.test:80",
				StartOffset: 6 * time.Millisecond, EndOffset: 2078 * time.Millisecond,
				Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Cause: "connection_refused",
					Attempts: []DiagnosisAttempt{{IP: "10.78.2.20", Cause: "refused"}, {IP: "2001:db8:77:2::20", Cause: "refused"}}, Detail: "connection to port 80 was refused on all 2 attempted address(es): 10.78.2.20, 2001:db8:77:2::20"}}}},
			dials: []ControlledTargetEvidence{targetDial("10.78.2.20:80", refused), targetDial("[2001:db8:77:2::20]:80", refused)},
		},
		{
			name:     "single-family refusal, stress case 17",
			timeline: unrelatedSpike("gateway", "upstream", 237*time.Millisecond, 1178*time.Millisecond, 643*time.Millisecond, 21.67),
			test: TestOutcome{Name: "healthy traffic crosses the router", Node: "client", Target: "routed-target.test:80",
				StartOffset: 6 * time.Millisecond, EndOffset: 1405 * time.Millisecond,
				Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Cause: "connection_refused",
					Attempts: []DiagnosisAttempt{{IP: "10.77.2.20", Cause: "refused"}}, Detail: "connection to port 80 was refused on all 1 attempted address(es): 10.77.2.20"}}}},
			dials: []ControlledTargetEvidence{targetDial("10.77.2.20:80", refused)},
		},
		{
			// The filtered port reads as unreachable, not refused, and its spike is
			// on the client's own segment, which is on the path to the target. Only
			// the endpoint's own dial separates this from a genuine path failure.
			name:     "silently blocked port, two-router case 0",
			timeline: unrelatedSpike("client", "client-lan", 170*time.Millisecond, 961*time.Millisecond, 743*time.Millisecond, 29.89),
			test: TestOutcome{Name: "the target subnet and the internet are both routed", Node: "client", Target: "subnet-target.test:80",
				StartOffset: 4 * time.Millisecond, EndOffset: 4327 * time.Millisecond,
				Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL",
					Attempts: []DiagnosisAttempt{{IP: "10.80.3.20", Cause: "timeout"}}, Detail: "port 80 unreachable on all 1 address(es): 10.80.3.20"}}}},
			dials: []ControlledTargetEvidence{targetDial("10.80.3.20:80", FamilyStateUnreachable), targetDial("10.80.2.20:80", FamilyStateReachable)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := &Report{Timeline: tc.timeline, Tests: []TestOutcome{tc.test}, Evidence: Evidence{ControlledTargets: tc.dials}}
			if codes(rep.timelineSuggestions())[SuggestTransientReportedPermanent] {
				t.Errorf("an unrelated netem recovery was reported as healing a target that is still down: %+v", rep.timelineSuggestions())
			}
		})
	}
}

// The recovery that does heal the endpoint still makes the permanent wording a
// transient finding, so the fix is not a blanket suppression of link and netem
// recoveries.
func TestPermanentWordingKeepsARecoveryThatHealedTheEndpoint(t *testing.T) {
	healedNetem := &Report{
		Timeline: unrelatedSpike("gateway", "upstream", 237*time.Millisecond, 1178*time.Millisecond, 643*time.Millisecond, 21.67),
		Tests: []TestOutcome{{Name: "healthy traffic crosses the router", Node: "client", Target: "routed-target.test:80",
			StartOffset: 6 * time.Millisecond, EndOffset: 1405 * time.Millisecond,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL",
				Attempts: []DiagnosisAttempt{{IP: "10.77.2.20", Cause: "timeout"}}, Detail: "port 80 unreachable on all 1 address(es): 10.77.2.20"}}}}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{targetDial("10.77.2.20:80", FamilyStateReachable)}},
	}
	if !codes(healedNetem.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a netem recovery that healed the endpoint was not reported: %+v", healedNetem.timelineSuggestions())
	}

	// A link that drops on the client's own segment and comes back is the
	// genuine single-fault transient: the endpoint answers again after the run.
	link := &Report{
		Timeline: []FaultEventEvidence{
			applied(100*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateDown}),
			applied(500*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateUp}),
		},
		Tests: []TestOutcome{{Name: "t", Node: "client", Target: "routed-target.test:80", EndOffset: time.Second,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL",
				Attempts: []DiagnosisAttempt{{IP: "10.77.2.20", Cause: "timeout"}}, Detail: "port 80 unreachable on all 1 address(es): 10.77.2.20"}}}}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{targetDial("10.77.2.20:80", FamilyStateReachable)}},
	}
	if !codes(link.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a link that dropped and came back was not reported as a transient: %+v", link.timelineSuggestions())
	}

	// The same link also takes internet_tcp down while the target is still
	// unreachable. Only target_tcp is the endpoint's to decide, so the internet
	// finding keeps its pairing.
	overTarget := &Report{
		Timeline: []FaultEventEvidence{
			applied(4*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "gateway", Segment: "upstream", State: LinkStateDown}),
			applied(629*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "gateway", Segment: "upstream", State: LinkStateUp}),
		},
		Tests: []TestOutcome{{Name: "t", Node: "client", Target: "dual-target.test:80", StartOffset: 4 * time.Millisecond, EndOffset: 4024 * time.Millisecond,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{
				{ID: "internet_tcp", Status: "FAIL", Detail: "no direct TCP egress to 1.1.1.1"},
				{ID: "target_tcp", Status: "FAIL", Attempts: []DiagnosisAttempt{{IP: "10.78.2.20", Cause: "timeout"}, {IP: "2001:db8:77:2::20", Cause: "timeout"}}, Detail: "port 80 unreachable on all 2 address(es): 10.78.2.20, 2001:db8:77:2::20"},
			}}}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{
			targetDial("10.78.2.20:80", FamilyStateUnreachable), targetDial("[2001:db8:77:2::20]:80", FamilyStateUnreachable)}},
	}
	if !codes(overTarget.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a link that dropped internet_tcp was not reported because the target stayed down: %+v", overTarget.timelineSuggestions())
	}

	// A resolver check is not an endpoint check. A netem recovery may heal DNS
	// while the target stays refused, so DNS keeps the pairing the endpoint loses.
	dnsWhileRefused := &Report{
		Timeline: unrelatedSpike("gateway", "upstream", 237*time.Millisecond, 1178*time.Millisecond, 643*time.Millisecond, 21.67),
		Tests: []TestOutcome{{Name: "t", Node: "client", Target: "routed-target.test:80", EndOffset: 1405 * time.Millisecond,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{
				{ID: "dns", Status: "FAIL", Detail: "resolver did not answer"},
				{ID: "target_tcp", Status: "FAIL", Cause: "connection_refused", Attempts: []DiagnosisAttempt{{IP: "10.77.2.20", Cause: "refused"}}, Detail: "connection to port 80 was refused on all 1 attempted address(es): 10.77.2.20"},
			}}}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{targetDial("10.77.2.20:80", "refused")}},
	}
	if !codes(dnsWhileRefused.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a DNS failure healed by a netem recovery was not paired with DNS: %+v", dnsWhileRefused.timelineSuggestions())
	}
}

// target_tcp tried two addresses on port 80. One recovered during the run and
// the other is still down afterwards. The recovery is real, so another endpoint
// on the same port staying down must not hide it.
func TestPermanentWordingKeepsARecoveryWhenAnotherEndpointStaysDown(t *testing.T) {
	rep := &Report{
		Timeline: []FaultEventEvidence{
			applied(100*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateDown}),
			applied(500*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateUp}),
		},
		Tests: []TestOutcome{{Name: "t", Node: "client", Target: "pair-target.test:80", EndOffset: time.Second,
			Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL",
				Attempts: []DiagnosisAttempt{{IP: "10.78.2.20", Cause: "timeout"}, {IP: "10.78.3.21", Cause: "timeout"}},
				Detail:   "port 80 unreachable on all 2 address(es): 10.78.2.20, 10.78.3.21"}}}}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{
			targetDial("10.78.2.20:80", FamilyStateReachable), targetDial("10.78.3.21:80", FamilyStateUnreachable)}},
	}
	if !codes(rep.timelineSuggestions())[SuggestTransientReportedPermanent] {
		t.Errorf("a recovered endpoint was hidden by another endpoint on the same port that stayed down: %+v", rep.timelineSuggestions())
	}
}

// The suppression reads each address target_tcp tried, not every endpoint that
// shares its port. A record that is missing, duplicated or contradictory keeps the
// finding, and so does a recovered address beside one that stayed down.
func TestPermanentWordingReadsEveryAttemptedAddress(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(100*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateDown}),
		applied(500*time.Millisecond, TimedEvent{Type: FaultScheduledLink, Node: "client", Segment: "client-lan", State: LinkStateUp}),
	}
	v4, v4Addr := "10.78.2.20", "10.78.2.20:80"
	v6, v6Addr := "2001:db8:77:2::20", "[2001:db8:77:2::20]:80"
	for _, tc := range []struct {
		name     string
		attempts []DiagnosisAttempt
		dials    []ControlledTargetEvidence
		kept     bool
	}{
		{
			name:     "IPv4-only client: a v6 record it never tried cannot veto a recovered v4 address",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateReachable), targetDial(v6Addr, FamilyStateUnreachable)},
			kept:     true,
		},
		{
			name:     "IPv4-only client: a v6 record it never tried cannot rescue a v4 address that stayed down",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable), targetDial(v6Addr, FamilyStateReachable)},
		},
		{
			name:     "dual-stack: one family recovered while the other stayed down",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "refused"}, {IP: v6, Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateReachable), targetDial(v6Addr, FamilyStateUnreachable)},
			kept:     true,
		},
		{
			name:     "dual-stack: both families still down",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "refused"}, {IP: v6, Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable), targetDial(v6Addr, FamilyStateUnreachable)},
		},
		{
			name:     "stale duplicate disagrees with a fresh reachable record",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable), targetDial(v4Addr, FamilyStateReachable)},
			kept:     true,
		},
		{
			name:     "aborted attempt whose address is still down",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout", Aborted: true}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable)},
		},
		{
			name:     "aborted attempt whose address recovered",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout", Aborted: true}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateReachable)},
			kept:     true,
		},
		{
			name:     "no attempts recorded",
			attempts: nil,
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable)},
			kept:     true,
		},
		{
			name:     "attempted address with no post-run record",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout"}, {IP: "10.78.3.21", Cause: "timeout"}},
			dials:    []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable)},
			kept:     true,
		},
		{
			name:     "another node's reachable record cannot rescue an attempted address",
			attempts: []DiagnosisAttempt{{IP: v4, Cause: "timeout"}},
			dials: []ControlledTargetEvidence{targetDial(v4Addr, FamilyStateUnreachable),
				{From: "gateway", To: v4Addr, Reachable: true, Outcome: FamilyStateReachable}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := &Report{Timeline: timeline, Evidence: Evidence{ControlledTargets: tc.dials},
				Tests: []TestOutcome{{Name: "t", Node: "client", Target: "pair-target.test:80", EndOffset: time.Second,
					Diagnosis: &Diagnosis{Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL", Attempts: tc.attempts}}}}}}
			if got := codes(rep.timelineSuggestions())[SuggestTransientReportedPermanent]; got != tc.kept {
				t.Errorf("transient finding = %v, want %v: %+v", got, tc.kept, rep.timelineSuggestions())
			}
		})
	}
}

func TestMissedWindowFiresOnlyWhenNothingWasFlagged(t *testing.T) {
	timeline := []FaultEventEvidence{
		applied(0, TimedEvent{Type: FaultScheduledNetem, Node: "client", Segment: "lan", Latency: 10 * time.Millisecond}),
		applied(100*time.Millisecond, TimedEvent{Type: FaultScheduledNetem, Node: "client", Segment: "lan", LossPercent: 100, Latency: 10 * time.Millisecond}),
		applied(300*time.Millisecond, TimedEvent{Type: FaultScheduledNetem, Node: "client", Segment: "lan", Latency: 10 * time.Millisecond}),
	}
	quiet := TestOutcome{Name: "t", EndOffset: time.Second,
		Diagnosis: diag("ok", DiagnosisCheck{ID: "dns", Status: "PASS"})}
	if !codes(timedReport(timeline, quiet).timelineSuggestions())[SuggestTransientMissed] {
		t.Error("an outage that opened and closed inside the run was not reported as missed")
	}
	noticed := quiet
	noticed.Diagnosis = diag("degraded", DiagnosisCheck{ID: "dns", Status: "WARN"})
	if codes(timedReport(timeline, noticed).timelineSuggestions())[SuggestTransientMissed] {
		t.Error("an outage netdoc did flag was reported as missed")
	}
}

func TestDependencyContradictionIsSuppressedByATransition(t *testing.T) {
	contradiction := TestOutcome{Name: "t", EndOffset: time.Second,
		Diagnosis: diag("ok",
			DiagnosisCheck{ID: "dns", Status: "FAIL", Detail: "cannot resolve"},
			DiagnosisCheck{ID: "http", Status: "PASS", Detail: "HTTP 200"})}

	// No timed faults at all: nothing to explain the impossible pair, and the
	// analysis has no timeline to reason from either, so it says nothing.
	if got := timedReport(nil, contradiction).timelineSuggestions(); len(got) != 0 {
		t.Errorf("suggestions without a timeline: %+v", got)
	}

	// A timeline whose transitions all landed outside this run: the network did
	// not change while it ran, so the pair is a real contradiction.
	outside := []FaultEventEvidence{applied(5*time.Second, dnsEvent(DNSOutcomeDrop))}
	if !codes(timedReport(outside, contradiction).timelineSuggestions())[SuggestTimelineInconsistent] {
		t.Error("a dependent PASS over a failed dependency was not reported")
	}

	// The same pair with a transition inside the run is temporally explainable.
	inside := []FaultEventEvidence{applied(500*time.Millisecond, dnsEvent(DNSOutcomeDrop))}
	if codes(timedReport(inside, contradiction).timelineSuggestions())[SuggestTimelineInconsistent] {
		t.Error("a pair explained by a transition during the run was called inconsistent")
	}
}

func TestTimelineSuggestionsAreStableAcrossRuns(t *testing.T) {
	timeline := []FaultEventEvidence{applied(5*time.Second, dnsEvent(DNSOutcomeDrop))}
	out := TestOutcome{Name: "t", EndOffset: time.Second,
		Diagnosis: diag("ok",
			DiagnosisCheck{ID: "dns", Status: "FAIL"},
			DiagnosisCheck{ID: "http", Status: "PASS"},
			DiagnosisCheck{ID: "target_tcp", Status: "PASS"})}
	first := timedReport(timeline, out).timelineSuggestions()
	for i := 0; i < 20; i++ {
		next := timedReport(timeline, out).timelineSuggestions()
		if len(next) != len(first) {
			t.Fatalf("suggestion count changed: %d != %d", len(next), len(first))
		}
		for j := range next {
			if next[j].Probe != first[j].Probe || next[j].Code != first[j].Code {
				t.Fatalf("suggestion order changed at %d: %+v != %+v", j, next[j], first[j])
			}
		}
	}
}

// The window predicate has to answer three different questions apart, and the
// one that matters most is the one production evidence collection cannot reach
// today: a query the director could not place must not be read as a query
// observed at T0. Offset carries zero in both cases, so only OffsetKnown keeps
// "not placed" from arguing that a resolver failed inside a window it was
// never located in.
func TestDNSFailureDuringSeparatesUnknownTimingFromOffsetZero(t *testing.T) {
	window := TestOutcome{StartOffset: 100 * time.Millisecond, EndOffset: 500 * time.Millisecond}
	fromZero := TestOutcome{StartOffset: 0, EndOffset: 500 * time.Millisecond}

	for _, tc := range []struct {
		name  string
		test  TestOutcome
		query DNSQueryEvidence
		want  bool
	}{
		{"known failure inside the window", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 300 * time.Millisecond, OffsetKnown: true}, true},
		{"known failure before the window", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 50 * time.Millisecond, OffsetKnown: true}, false},
		{"known failure after the window", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 900 * time.Millisecond, OffsetKnown: true}, false},
		{"start offset is inclusive", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "SERVFAIL", Offset: 100 * time.Millisecond, OffsetKnown: true}, true},
		{"end offset is exclusive", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "SERVFAIL", Offset: 500 * time.Millisecond, OffsetKnown: true}, false},
		// The pair this whole distinction exists for: identical Offset, opposite
		// answers, decided only by whether the observation was ever placed.
		{"a failure known to be at T0 is inside a window starting at T0", fromZero,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 0, OffsetKnown: true}, true},
		{"an unplaced failure does not match a window containing zero", fromZero,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 0}, false},
		{"an unplaced failure does not match a window starting later", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 0}, false},
		{"a served answer inside the window is not a failure", window,
			DNSQueryEvidence{Service: "r", ActualOutcome: "ANSWER", Offset: 300 * time.Millisecond, OffsetKnown: true}, false},
	} {
		if got := dnsFailureDuring(tc.test, []DNSQueryEvidence{tc.query}); got != tc.want {
			t.Errorf("%s: dnsFailureDuring = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// An unplaced query cannot clear a resolver either: the last-query-per-service
// rule needs to know which query was last, and an observation with no offset
// never earns that position.
func TestDNSFailureDuringIgnoresUnplacedQueriesForTheLastQueryRule(t *testing.T) {
	test := TestOutcome{EndOffset: time.Second}
	failing := DNSQueryEvidence{Service: "r", ActualOutcome: "DROPPED", Offset: 200 * time.Millisecond, OffsetKnown: true}

	if !dnsFailureDuring(test, []DNSQueryEvidence{failing, {Service: "r", ActualOutcome: "ANSWER"}}) {
		t.Error("an unplaced answer was allowed to exonerate a resolver that failed inside the run")
	}
	if !dnsFailureDuring(test, []DNSQueryEvidence{{Service: "r", ActualOutcome: "ANSWER", OffsetKnown: true, Offset: 100 * time.Millisecond}, failing}) {
		t.Error("a placed answer before the placed failure was read as a recovery")
	}
}
