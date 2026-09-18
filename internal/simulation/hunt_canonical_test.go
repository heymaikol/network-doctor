package simulation

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// huntSemanticView is everything a stored case is allowed to decide. It is the
// list #97 protects: the observed truth and its fingerprint, the diagnosis
// fingerprint, the case status, the findings, the conditions the oracle reads
// out of the pair, and the coverage the case contributes. Canonicalization may
// change anything a run wrote that is not in here; it may change nothing that
// is.
//
// Finding prose is deliberately excluded and compared separately below:
// huntFindingFingerprint is computed from the structured fields alone, so a
// clipped Summary can never move a finding, split an aggregate or change a
// suggestion's code.
type huntSemanticView struct {
	Truth                ObservedTruth
	TruthFingerprint     string
	DiagnosisFingerprint DiagnosisFingerprint
	Status               string
	Findings             []HuntCaseFinding
	Established          []NetworkCondition
	Recognized           []NetworkCondition
	Comparable           bool
	Coverage             HuntCoverage
}

func huntSemanticViewOf(manifest GeneratedCaseManifest, report *Report) huntSemanticView {
	item := huntCaseResultFrom(manifest, report)
	view := huntSemanticView{Truth: item.Truth, TruthFingerprint: item.TruthFingerprint,
		DiagnosisFingerprint: item.DiagnosisFingerprint, Status: item.Status,
		Findings: append([]HuntCaseFinding(nil), item.Findings...),
		Coverage: huntCoverageFor(HuntGeneratorVersion, HuntLaneBugOracle, manifest.BaseScenario, []HuntCaseResult{item})}
	for i := range view.Findings {
		view.Findings[i].Summary, view.Findings[i].Evidence = "", ""
	}
	if report != nil {
		view.Established, view.Recognized, view.Comparable = caseConditions(report, item.Truth)
	}
	return view
}

// canonicalKeepsHuntSemantics is the proof obligation itself, applied to one
// report: storing a run and reading it back answers every hunt question the way
// the live run did.
func canonicalKeepsHuntSemantics(t *testing.T, what string, manifest GeneratedCaseManifest, report *Report) {
	t.Helper()
	raw := huntSemanticViewOf(manifest, report)
	canonical := huntSemanticViewOf(manifest, canonicalHuntReport(report))
	if !reflect.DeepEqual(raw, canonical) {
		t.Errorf("%s: canonical storage changed hunt semantics\n raw:       %+v\n canonical: %+v",
			what, raw, canonical)
	}
	// Idempotence, because a merge canonicalizes a case that is already stored.
	if twice := canonicalHuntReport(canonicalHuntReport(report)); !reflect.DeepEqual(twice, canonicalHuntReport(report)) {
		t.Errorf("%s: canonicalization is not idempotent", what)
	}
}

// TestCanonicalStorageKeepsEverySemanticEvidenceCategory walks the independent
// evidence fixtures the oracle tests are built from, one per category a hunt
// can accuse netdoc over, and holds each one to the same obligation. These are
// the narrow cases: a single record in a single list, where dropping or
// reshaping that one row is the difference between a finding and silence.
func TestCanonicalStorageKeepsEverySemanticEvidenceCategory(t *testing.T) {
	internetFails := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeInternet), Status: "FAIL",
		Cause: diagnostic.RouteCauseNoDefaultRoute, Detail: "no default route",
		Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}})
	internetPasses := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeInternet), Status: "PASS",
		Detail: "reachable", Families: &DiagnosisFamilies{IPv4: FamilyStateReachable}})
	dnsFails := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeDNS), Status: "FAIL",
		Cause: "dns_failed", Detail: "no answer"})
	dnsPasses := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeDNS), Status: "PASS", Detail: "answered"})

	for _, tc := range []struct {
		name      string
		diagnosis *Diagnosis
		evidence  Evidence
	}{
		{"routes_no_default_seen", internetFails, noDefaultRouteEvidence()},
		{"routes_no_default_missed", internetPasses, noDefaultRouteEvidence()},
		{"connectivity_tcp_reset", internetPasses, resetTCPEvidence()},
		{"tls_certificate_expired", internetPasses, expiredTLSEvidence()},
		{"proxy_connect_refused", internetPasses, refusedProxyEvidence()},
		{"quic_dropped", internetPasses, droppedQUICEvidence()},
		{"encrypted_dns_invalid", internetPasses, invalidDoHEvidence()},
		{"http_service_unavailable", internetPasses, http503Evidence()},
		{"dns_queries_dropped", dnsFails, servedDNSEvidence("resolver", "DROPPED")},
		{"dns_queries_served", dnsPasses, servedDNSEvidence("resolver", "SERVED")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonicalKeepsHuntSemantics(t, tc.name, GeneratedCaseManifest{Case: 1, BaseScenario: "healthy"},
				oracleReport(tc.diagnosis, tc.evidence))
		})
	}
}

// TestCanonicalStorageKeepsTheTimelineRecoveryReading is the one reduction in
// canonicalHuntReport that is not a straight field projection: the DNS query
// log is the only evidence list whose length a run's duration decides, so it is
// reduced to the queries its readers can distinguish. Both readers are
// temporal, so the fixtures here are built around a recovery: a resolver that
// was moved into a state, queries on both sides of the change, and a diagnosis
// that did or did not resample.
func TestCanonicalStorageKeepsTheTimelineRecoveryReading(t *testing.T) {
	query := func(service, outcome string, offset time.Duration) DNSQueryEvidence {
		return DNSQueryEvidence{Node: "resolver", Service: service, Name: "example.com.", QueryType: "A",
			ActualOutcome: outcome, Offset: offset, OffsetKnown: true}
	}
	build := func(queries ...DNSQueryEvidence) *Report {
		report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeDNS), Status: "FAIL",
			Cause: "dns_failed", Detail: "no answer from the resolver"}), Evidence{DNSQueries: queries})
		report.Tests[0].StartOffset, report.Tests[0].EndOffset = 0, 10*time.Second
		report.Timeline = appliedDNSFault("resolver", "DROP", 1*time.Second)
		report.Timeline = append(report.Timeline, FaultEventEvidence{
			Event:  TimedEvent{Type: FaultScheduledDNS, Service: "resolver", Outcome: "SERVE", Offset: 5 * time.Second},
			Result: EventApplied, AppliedOffset: 5 * time.Second, State: "resolver serving"})
		report.Timeline[0].AppliedOffset, report.Timeline[0].State = 1*time.Second, "resolver dropping"
		report.Suggestions = append(report.Suggestions, report.timelineSuggestions()...)
		return report
	}
	for _, tc := range []struct {
		name    string
		queries []DNSQueryEvidence
	}{
		{"never_resampled", []DNSQueryEvidence{query("resolver", "DROPPED", 2*time.Second)}},
		{"resampled_after_recovery", []DNSQueryEvidence{
			query("resolver", "DROPPED", 2*time.Second), query("resolver", "SERVED", 7*time.Second)}},
		{"resampled_but_still_dropped", []DNSQueryEvidence{
			query("resolver", "DROPPED", 2*time.Second), query("resolver", "DROPPED", 7*time.Second)}},
		{"many_repeated_queries", func() []DNSQueryEvidence {
			var out []DNSQueryEvidence
			for i := 0; i < 200; i++ {
				out = append(out, query("resolver", "DROPPED", time.Duration(i)*20*time.Millisecond))
			}
			return append(out, query("resolver", "SERVED", 7*time.Second))
		}()},
		{"two_resolvers", []DNSQueryEvidence{
			query("resolver", "DROPPED", 2*time.Second), query("secondary", "SERVED", 2*time.Second),
			query("resolver", "DROPPED", 7*time.Second)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := build(tc.queries...)
			canonicalKeepsHuntSemantics(t, tc.name, GeneratedCaseManifest{Case: 1, BaseScenario: "healthy"}, report)
		})
	}
}

// TestCanonicalStorageKeepsTheDiagnosisProjection covers the other side of the
// case: what netdoc said. The diagnosis is kept as check rows and finding IDs,
// and the fingerprint derived from it is one of the fields a merge recomputes,
// so a dropped row or a reordered one would be visible here.
func TestCanonicalStorageKeepsTheDiagnosisProjection(t *testing.T) {
	var checks []DiagnosisCheck
	for _, probe := range diagnostic.StableProbes() {
		checks = append(checks, DiagnosisCheck{ID: string(probe.ID), Name: probe.Name, Status: "FAIL",
			Cause: "broken", Detail: "a long detail line that says what happened and what to look at next",
			Fix:      "a fix hint the hunt never reads",
			Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable, IPv6: FamilyStateUnavailable}})
	}
	diagnosis := &Diagnosis{Verdict: "network", Summary: "everything is broken", Checks: checks,
		Findings: []DiagnosisFinding{{ID: "no_default_route"}, {ID: "dns_failed"}}}
	report := oracleReport(diagnosis, noDefaultRouteEvidence())
	report.Tests = append(report.Tests, TestOutcome{Name: "final", Node: "client",
		ProcessOutcome: ProcessExited, Diagnosis: diagnosis})
	canonicalKeepsHuntSemantics(t, "full probe registry", GeneratedCaseManifest{Case: 1, BaseScenario: "healthy"}, report)

	stored := canonicalHuntReport(report)
	if len(stored.Tests[0].Diagnosis.Checks) != len(checks) {
		t.Fatalf("stored %d of %d check rows", len(stored.Tests[0].Diagnosis.Checks), len(checks))
	}
	for i, check := range stored.Tests[0].Diagnosis.Checks {
		if check.ID != checks[i].ID || check.Status != checks[i].Status || check.Cause != checks[i].Cause {
			t.Fatalf("check %d stored as %+v, want %+v", i, check, checks[i])
		}
	}
}

// everyCategoryEvidence is a node holder's notes with a row in every evidence
// list a hunt reads. A generated case draws its mutations from the whole
// operator set, so pairing a wide evidence record with a wide mutation set is
// what makes the property test below exercise the oracle rules rather than only
// the route rules one narrow fixture reaches.
func everyCategoryEvidence() Evidence {
	evidence := deadRouteEvidence()
	evidence.TLS = expiredTLSEvidence().TLS
	evidence.SOCKSRequests = refusedProxyEvidence().SOCKSRequests
	evidence.PacketDrops = droppedQUICEvidence().PacketDrops
	evidence.TCPResets = resetTCPEvidence().TCPResets
	evidence.ServiceReplies = append(invalidDoHEvidence().ServiceReplies, http503Evidence().ServiceReplies...)
	evidence.DNSQueries = servedDNSEvidence("resolver", "DROPPED").DNSQueries
	evidence.Routes = []RouteEvidence{{Node: "client", Family: "ipv4", Destination: "default",
		Via: "10.77.0.1", Segment: "lan", Selected: true}}
	evidence.Links = []LinkEvidence{{Node: "client", Segment: "lan", MTU: 1500, Up: true}}
	evidence.Routers = []RouterEvidence{{Node: "router", IPv4Forwarding: true, IPv6Forwarding: true}}
	evidence.PacketConditions = []PacketConditionEvidence{{Node: "client", Segment: "lan", RTTSamples: 1,
		Active: true, DroppedPackets: 2}}
	evidence.ControlledTargets = []ControlledTargetEvidence{
		{From: "client", To: "10.77.0.9:443", Family: "ipv4", Via: []string{"lan"}, Reachable: false},
		{From: "client", To: "10.77.0.9:80", Family: "ipv4", Via: []string{"lan"}, Reachable: true}}
	return evidence
}

// TestCanonicalStorageKeepsTheSemanticsOfEveryGeneratedCase is the property
// this whole design exists for, run over the shapes a hunt really produces:
// every base, both released lanes, and a netdoc whose report is wrong in a way
// the oracle catches, so the findings under comparison are not empty.
func TestCanonicalStorageKeepsTheSemanticsOfEveryGeneratedCase(t *testing.T) {
	const cases = 25
	for _, name := range HuntBaseNames() {
		base := loadHuntBase(t, name)
		for _, lane := range []HuntLane{HuntLaneBugOracle, HuntLaneStress} {
			t.Run(name+"/"+string(lane), func(t *testing.T) {
				stream := newHuntCaseStream(HuntGeneratorVersion, lane, name, base, 12345, cases, HuntMaxFaults, nil)
				for {
					generated, err := stream.next()
					if err != nil {
						t.Fatal(err)
					}
					if generated == nil {
						return
					}
					backend := &clientRoleBackend{env: &fakeEnv{stdout: blamesTheGatewayReport,
						evidence: everyCategoryEvidence()}}
					report := Run(context.Background(), generated.Scenario, backend, Options{})
					canonicalKeepsHuntSemantics(t, generated.Manifest.CaseFingerprint, generated.Manifest, report)
				}
			})
		}
	}
}

// TestCanonicalStorageKeepsTheFinalStateGate covers Report.Faults, the one
// field of a fault a hunt reads. A netem fault makes the final state
// incomparable, which silences the whole final-state oracle, so losing the
// fault list would turn a case the hunt refuses to judge into one it judges.
func TestCanonicalStorageKeepsTheFinalStateGate(t *testing.T) {
	for _, faultType := range []string{FaultNetem, FaultLinkDown} {
		t.Run(faultType, func(t *testing.T) {
			report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS"}), expiredTLSEvidence())
			report.Faults = []FaultInfo{{Type: faultType, Node: "client"}}
			if got := finalStateComparable(report); got != (faultType != FaultNetem) {
				t.Fatalf("finalStateComparable with a %s fault = %t", faultType, got)
			}
			canonicalKeepsHuntSemantics(t, faultType, GeneratedCaseManifest{Case: 1, BaseScenario: "healthy"}, report)
		})
	}
}

// TestCanonicalStorageKeepsTheSemanticsOfTheRecordedCase runs the same
// obligation over the one report in this repository that a real hunt wrote.
func TestCanonicalStorageKeepsTheSemanticsOfTheRecordedCase(t *testing.T) {
	recorded := recordedHuntCase(t)
	canonicalKeepsHuntSemantics(t, "case 116", recorded.Manifest, recorded.Report)
}
