package simulation

import (
	"fmt"
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// The six families this file covers are the ones a person is most likely to
// confuse with the family next to them, which is why the tests below are almost
// all negative: it is easy to make "the target did not answer" observable, and
// the whole value is in refusing to call that a refusal, a filter, a missing
// route, or a wrong one.

// newChallengeFamilies are the conditions added with challenge id version V3.
var newChallengeFamilies = []string{"service.connection_refused", "service.tcp_port_blocked",
	"service.tls_hostname_mismatch", "routing.no_default_route", "routing.wrong_default_route",
	"routing.missing_subnet_route"}

// TestEveryChallengeConditionIsReachableFromRealIDs is the reachability proof,
// and it goes through the real id path rather than through the registry: an
// answer that only exists in a table is not playable. It is deterministic,
// since these ids are fixed rather than sampled, so a family that becomes unreachable fails
// here every time rather than one run in ten.
func TestEveryChallengeConditionIsReachableFromRealIDs(t *testing.T) {
	first := map[string]string{}
	for i := 0; i < 2000; i++ {
		id := fmt.Sprintf("%s-%06X", ChallengeIDVersion, i*7919%0xFFFFFF)
		challenge, err := BuildChallenge(id)
		if err != nil {
			continue
		}
		if _, seen := first[challenge.condition.mutation]; !seen {
			first[challenge.condition.mutation] = id
		}
	}
	for _, condition := range challengeConditions {
		id, ok := first[condition.mutation]
		if !ok {
			t.Errorf("no %s id in the scanned range resolves to %q, so its answer %s is not playable",
				ChallengeIDVersion, condition.mutation, condition.answer)
			continue
		}
		t.Logf("%-32s %s answer=%s", nameOrHealthy(condition.mutation), id, condition.answer)
	}
	// And the same scan proves the new families are not merely present in the
	// range but reachable through the id the CLI actually mints.
	for _, mutation := range newChallengeFamilies {
		if _, ok := first[mutation]; !ok {
			t.Errorf("%s is not reachable from any %s id", mutation, ChallengeIDVersion)
		}
	}
}

func nameOrHealthy(mutation string) string {
	if mutation == "" {
		return "(healthy)"
	}
	return mutation
}

// TestAdvertisedChallengeAnswersAreProducible pins the menu to the contract: an
// answer a player can pick has to be one a challenge can actually set, unless
// it is one of the three the contract excludes on purpose and says why.
func TestAdvertisedChallengeAnswersAreProducible(t *testing.T) {
	// Excluded by the challenge contract, each for a test it fails; see the
	// comment on challengeConditions. They stay on the menu so that a menu of
	// only the possible faults is not most of the answer.
	deliberatelyUnproducible := []ChallengeAnswer{AnswerHTTPService, AnswerProxy, AnswerQUICBlocked}
	producible := map[ChallengeAnswer]bool{}
	for _, condition := range challengeConditions {
		producible[condition.answer] = true
	}
	for _, item := range ChallengeAnswerMenu {
		if producible[item.ID] == slices.Contains(deliberatelyUnproducible, item.ID) {
			t.Errorf("menu answer %s: producible=%t, which contradicts the excluded list",
				item.ID, producible[item.ID])
		}
	}
	for _, answer := range deliberatelyUnproducible {
		if _, ok := ChallengeAnswerByID(string(answer)); !ok {
			t.Errorf("%s is listed as a deliberate exclusion but is not on the menu", answer)
		}
	}
}

// refusedOrBlockedTruth runs the observation half for one of the two
// target-port families against one piece of dial and counter evidence.
func refusedOrBlockedTruth(t *testing.T, mutation, outcome string, counted bool) []string {
	t.Helper()
	m := GeneratedMutation{ID: mutation, Node: "target", TargetPort: 80, TargetEndpoint: "10.77.0.20:80"}
	report := &Report{
		Topology: []NodeInfo{{Name: "client", Role: "client"}},
		Evidence: Evidence{ControlledTargets: []ControlledTargetEvidence{
			{From: "client", To: "10.77.0.20:80", Family: "ipv4", Outcome: outcome,
				Reachable: outcome == FamilyStateReachable}}},
	}
	if counted {
		report.Evidence.PacketDrops = []PacketDropEvidence{{Node: "target", Protocol: "tcp", Port: 80,
			Direction: DirectionInbound, Packets: 4}}
	}
	return collectObservedTruth(GeneratedCaseManifest{Mutations: []GeneratedMutation{m}}, report).ObservedFaults
}

// TestRefusalAndFilterAreEachOthersNegative is the distinction the whole pair
// of families rests on. Both end with a connection that did not work, and only
// the dialing end can say which: a reset came back, or nothing did. Neither
// family may be established by the evidence that establishes the other, and
// neither may be established by a dial that merely failed.
func TestRefusalAndFilterAreEachOthersNegative(t *testing.T) {
	for _, tt := range []struct {
		name     string
		mutation string
		outcome  string
		counted  bool
		want     bool
	}{
		{"a refusal is a reset from a live host", "service.connection_refused", TargetStateRefused, false, true},
		{"a refused port that also counted drops is a filter", "service.connection_refused", TargetStateRefused, true, false},
		{"a refusal is not a timeout", "service.connection_refused", FamilyStateUnreachable, false, false},
		{"a refusal is not a working port", "service.connection_refused", FamilyStateReachable, false, false},
		{"a filter is a counted drop and a timeout", "service.tcp_port_blocked", FamilyStateUnreachable, true, true},
		{"a filter is not a refusal", "service.tcp_port_blocked", TargetStateRefused, true, false},
		{"a filter needs its counter, not just a timeout", "service.tcp_port_blocked", FamilyStateUnreachable, false, false},
		{"a filter that matched no packet blocked nobody", "service.tcp_port_blocked", FamilyStateReachable, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Contains(refusedOrBlockedTruth(t, tt.mutation, tt.outcome, tt.counted), tt.mutation)
			if got != tt.want {
				t.Fatalf("observed=%t, want %t", got, tt.want)
			}
		})
	}
}

// TestTargetPortFamiliesNeedTheDialToHaveHappened closes the other door: an
// absent observation is not a failed one. Without the dial there is nothing
// that could distinguish the two families, so neither may be established.
func TestTargetPortFamiliesNeedTheDialToHaveHappened(t *testing.T) {
	for _, mutation := range []string{"service.connection_refused", "service.tcp_port_blocked"} {
		m := GeneratedMutation{ID: mutation, Node: "target", TargetPort: 80, TargetEndpoint: "10.77.0.20:80"}
		report := &Report{
			Topology: []NodeInfo{{Name: "client", Role: "client"}},
			Evidence: Evidence{PacketDrops: []PacketDropEvidence{{Node: "target", Protocol: "tcp", Port: 80,
				Direction: DirectionInbound, Packets: 4}}},
		}
		truth := collectObservedTruth(GeneratedCaseManifest{Mutations: []GeneratedMutation{m}}, report)
		if slices.Contains(truth.ObservedFaults, mutation) {
			t.Errorf("%s was observed with no dial of the target at all", mutation)
		}
	}
}

// routeFamilyReport is a healthy two-router run, which each case below then
// breaks in exactly one way. Starting from a working network is what makes the
// negative cases mean something: they are one field away from the real thing.
func routeFamilyReport() *Report {
	return &Report{
		Topology: []NodeInfo{{Name: "client", Role: "client"}},
		Evidence: Evidence{
			RouteTables: []RouteTableEvidence{{Node: "client", Family: "ipv4", Routes: []KernelRoute{
				{Destination: "default", Via: "10.80.1.1", Segment: "client-lan"},
				{Destination: "10.80.1.0/24", Segment: "client-lan"},
				{Destination: "10.80.2.0/24", Via: "10.80.1.1", Segment: "client-lan"},
				{Destination: "10.80.3.0/24", Via: "10.80.1.254", Segment: "client-lan"},
			}}},
			Routes: []RouteEvidence{
				{Node: "client", Destination: "1.1.1.1", Family: "ipv4", Via: "10.80.1.1",
					Segment: "client-lan", Selected: true, GatewayReachable: boolPointer(true)},
			},
			ControlledTargets: []ControlledTargetEvidence{
				{From: "client", To: "10.80.2.20:80", Family: "ipv4", Via: []string{"client-lan", "10.80.1.1"},
					Reachable: true, Outcome: FamilyStateReachable},
				{From: "client", To: "10.80.3.20:80", Family: "ipv4", Via: []string{"client-lan", "10.80.1.254"},
					Reachable: true, Outcome: FamilyStateReachable},
			},
			FamilyReachability: []FamilyReachabilityEvidence{
				{Node: "client", Family: "ipv4", State: FamilyStateReachable}},
		},
	}
}

func observedFamily(mutation GeneratedMutation, report *Report) bool {
	truth := collectObservedTruth(GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}, report)
	return slices.Contains(truth.ObservedFaults, mutation.ID)
}

func noDefaultRouteMutation() GeneratedMutation {
	return GeneratedMutation{ID: "routing.no_default_route", Node: "client", Family: "ipv4",
		RouteDestination: "default", PreferredVia: "10.80.1.1", PreferredSegment: "client-lan"}
}

func wrongDefaultRouteMutation() GeneratedMutation {
	return GeneratedMutation{ID: "routing.wrong_default_route", Node: "client", Family: "ipv4",
		RouteDestination: "default", PreferredVia: "10.80.1.1", PreferredSegment: "client-lan",
		RouteVia: "10.80.1.254", ControlTarget: "10.80.2.20:80"}
}

func missingSubnetRouteMutation() GeneratedMutation {
	return GeneratedMutation{ID: "routing.missing_subnet_route", Node: "client", Family: "ipv4",
		RouteDestination: "10.80.3.0/24", PreferredVia: "10.80.1.254", PreferredSegment: "client-lan",
		ControlTarget: "10.80.2.20:80", TargetEndpoint: "10.80.3.20:80"}
}

// dropDefaults rewrites the client's table to hold no default route.
func dropDefaults(report *Report) {
	table := &report.Evidence.RouteTables[0]
	table.Routes = slices.DeleteFunc(table.Routes, func(r KernelRoute) bool {
		return defaultDestination(r.Destination)
	})
}

// TestNoDefaultRouteNeedsTheTableAndTheConsequence keeps the family from being
// either a configuration reading nobody felt or a generic outage.
func TestNoDefaultRouteNeedsTheTableAndTheConsequence(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(*Report)
		want  bool
	}{
		{"the table has no default and the family is dead", func(r *Report) {
			dropDefaults(r)
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}, true},
		{"a default is still installed", func(r *Report) {
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}, false},
		{"the route is gone but the family still works", dropDefaults, false},
		{"nobody read the table", func(r *Report) {
			r.Evidence.RouteTables = nil
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := routeFamilyReport()
			tt.setup(report)
			if got := observedFamily(noDefaultRouteMutation(), report); got != tt.want {
				t.Fatalf("observed=%t, want %t", got, tt.want)
			}
		})
	}
}

// TestWrongDefaultRouteIsNotADownstreamOutage is the hard one. From the client,
// a default that goes nowhere and a network that is simply broken past the
// gateway produce the same reading, so the family is only established when the
// original next hop is demonstrably still forwarding.
func TestWrongDefaultRouteIsNotADownstreamOutage(t *testing.T) {
	// The shape every case starts from: the default now points at the second
	// router, and the internet is gone.
	repoint := func(r *Report) {
		r.Evidence.RouteTables[0].Routes[0].Via = "10.80.1.254"
		r.Evidence.Routes[0].Via = "10.80.1.254"
		r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
	}
	for _, tt := range []struct {
		name  string
		setup func(*Report)
		want  bool
	}{
		{"the default moved and the old next hop still forwards", repoint, true},
		{"the old next hop stopped forwarding too, so this is an outage", func(r *Report) {
			repoint(r)
			r.Evidence.ControlledTargets[0].Reachable = false
			r.Evidence.ControlledTargets[0].Outcome = FamilyStateUnreachable
		}, false},
		{"the new next hop does not answer, which is an unreachable gateway", func(r *Report) {
			repoint(r)
			r.Evidence.Routes[0].GatewayReachable = boolPointer(false)
		}, false},
		{"the control was reached through the new next hop, not the old one", func(r *Report) {
			repoint(r)
			r.Evidence.ControlledTargets[0].Via = []string{"client-lan", "10.80.1.254"}
		}, false},
		{"a second default remains, which is a preferred-route question", func(r *Report) {
			repoint(r)
			r.Evidence.RouteTables[0].Routes = append(r.Evidence.RouteTables[0].Routes,
				KernelRoute{Destination: "default", Via: "10.80.1.1", Segment: "client-lan", Metric: 100})
		}, false},
		{"the default never moved", func(r *Report) {
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}, false},
		{"the family still works", func(r *Report) {
			r.Evidence.RouteTables[0].Routes[0].Via = "10.80.1.254"
			r.Evidence.Routes[0].Via = "10.80.1.254"
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := routeFamilyReport()
			tt.setup(report)
			if got := observedFamily(wrongDefaultRouteMutation(), report); got != tt.want {
				t.Fatalf("observed=%t, want %t", got, tt.want)
			}
		})
	}
}

// TestMissingSubnetRouteIsNotAnUnreachableTarget proves the route-specific
// defect rather than reducing it to the target not answering, and keeps it
// apart from the two default-route families on both sides.
func TestMissingSubnetRouteIsNotAnUnreachableTarget(t *testing.T) {
	removeRoute := func(r *Report) {
		r.Evidence.RouteTables[0].Routes = slices.DeleteFunc(r.Evidence.RouteTables[0].Routes,
			func(k KernelRoute) bool { return k.Destination == "10.80.3.0/24" })
		r.Evidence.ControlledTargets[1].Reachable = false
		r.Evidence.ControlledTargets[1].Outcome = FamilyStateUnreachable
	}
	for _, tt := range []struct {
		name  string
		setup func(*Report)
		want  bool
	}{
		{"the specific route is gone and only that target is dead", removeRoute, true},
		{"the route is still installed", func(r *Report) {
			r.Evidence.ControlledTargets[1].Reachable = false
			r.Evidence.ControlledTargets[1].Outcome = FamilyStateUnreachable
		}, false},
		{"the target is dead but the route covering it remains", func(r *Report) {
			removeRoute(r)
			r.Evidence.RouteTables[0].Routes = append(r.Evidence.RouteTables[0].Routes,
				KernelRoute{Destination: "10.80.0.0/16", Via: "10.80.1.254", Segment: "client-lan"})
		}, false},
		{"the internet went with it, so this is not route-shaped", func(r *Report) {
			removeRoute(r)
			r.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}, false},
		{"there is no default either, which is the other family", func(r *Report) {
			removeRoute(r)
			dropDefaults(r)
		}, false},
		{"the control behind the working gateway also died", func(r *Report) {
			removeRoute(r)
			r.Evidence.ControlledTargets[0].Reachable = false
			r.Evidence.ControlledTargets[0].Outcome = FamilyStateUnreachable
		}, false},
		{"the target answers anyway", func(r *Report) {
			r.Evidence.RouteTables[0].Routes = slices.DeleteFunc(r.Evidence.RouteTables[0].Routes,
				func(k KernelRoute) bool { return k.Destination == "10.80.3.0/24" })
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := routeFamilyReport()
			tt.setup(report)
			if got := observedFamily(missingSubnetRouteMutation(), report); got != tt.want {
				t.Fatalf("observed=%t, want %t", got, tt.want)
			}
		})
	}
}

// TestHostnameMismatchIsReadOffTheHandshake keeps the certificate families
// apart at the evidence layer, not only at the recognition layer: the mode a
// service was configured with is not the fault, being shown to somebody is.
func TestHostnameMismatchIsReadOffTheHandshake(t *testing.T) {
	mismatch := TLSEvidence{Node: "target", Service: "tls-target",
		CertificateMode: TLSCertificateHostnameMismatch, RequestedServer: "secure-target.test",
		CertificateDNS: []string{"not-the-requested-name.test"}, CertificatePresented: true,
		Result: "client_rejected_certificate", Count: 1}
	for _, tt := range []struct {
		name   string
		change func(*TLSEvidence)
		want   bool
	}{
		{"a name the certificate does not carry", nil, true},
		{"the certificate does carry the requested name", func(e *TLSEvidence) {
			e.CertificateDNS = []string{"secure-target.test"}
		}, false},
		{"nobody asked for a name", func(e *TLSEvidence) { e.RequestedServer = "" }, false},
		{"the client accepted it", func(e *TLSEvidence) { e.Result = "passed" }, false},
		{"the handshake never got to a certificate", func(e *TLSEvidence) {
			e.CertificatePresented, e.Result = false, "handshake_failure"
		}, false},
		{"nobody ever connected", func(e *TLSEvidence) { e.Count = 0 }, false},
		{"an expired certificate is a different fault", func(e *TLSEvidence) {
			e.CertificateMode = TLSCertificateExpired
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handshake := mismatch
			handshake.CertificateDNS = slices.Clone(mismatch.CertificateDNS)
			if tt.change != nil {
				tt.change(&handshake)
			}
			report := &Report{Topology: []NodeInfo{{Name: "client", Role: "client"}},
				Evidence: Evidence{TLS: []TLSEvidence{handshake}}}
			m := GeneratedMutation{ID: "service.tls_hostname_mismatch", Node: "target", Service: "tls-target"}
			if got := observedFamily(m, report); got != tt.want {
				t.Fatalf("observed=%t, want %t", got, tt.want)
			}
			// And the two certificate conditions never both fire on one run.
			if anyExpiredCertificateRejected(report.Evidence) && anyMismatchedCertificateRejected(report.Evidence) {
				t.Fatal("one handshake established both certificate conditions")
			}
		})
	}
}

// TestHumanAnswersRejectTheNeighbouringFault grades the human half of each new
// family against the answer next to it. The pairs are the ones a player really
// hesitates between, and every one of them has a different fix.
func TestHumanAnswersRejectTheNeighbouringFault(t *testing.T) {
	for _, tt := range []struct {
		mutation string
		right    ChallengeAnswer
		wrong    []ChallengeAnswer
	}{
		{"service.connection_refused", AnswerRefused,
			[]ChallengeAnswer{AnswerPortBlocked, AnswerReset, AnswerHealthy, AnswerMissingRoute}},
		{"service.tcp_port_blocked", AnswerPortBlocked,
			[]ChallengeAnswer{AnswerRefused, AnswerReset, AnswerMissingRoute}},
		{"service.tls_hostname_mismatch", AnswerTLSHostname,
			[]ChallengeAnswer{AnswerTLSCertificate, AnswerRefused, AnswerHTTPService}},
		{"routing.no_default_route", AnswerNoDefaultRoute,
			[]ChallengeAnswer{AnswerWrongDefaultRoute, AnswerMissingRoute, AnswerPreferredRoute}},
		{"routing.wrong_default_route", AnswerWrongDefaultRoute,
			[]ChallengeAnswer{AnswerNoDefaultRoute, AnswerMissingRoute, AnswerPreferredRoute}},
		{"routing.missing_subnet_route", AnswerMissingRoute,
			[]ChallengeAnswer{AnswerNoDefaultRoute, AnswerWrongDefaultRoute, AnswerPortBlocked, AnswerRefused}},
	} {
		t.Run(tt.mutation, func(t *testing.T) {
			condition, ok := challengeConditionFor(tt.mutation)
			if !ok {
				t.Fatalf("%s is no longer a challenge condition", tt.mutation)
			}
			if condition.answer != tt.right {
				t.Fatalf("%s answers %s, not %s", tt.mutation, condition.answer, tt.right)
			}
			challenge := &Challenge{ID: "V3-000001", Node: "client", condition: condition,
				Manifest: GeneratedCaseManifest{Mutations: []GeneratedMutation{familyMutation(tt.mutation)}}}
			report := familyObservedReport(tt.mutation)
			if got := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: tt.right}); !got.Truth.Scoreable ||
				got.Truth.Answer != tt.right || got.Human.Score != ChallengeCorrect {
				t.Fatalf("the right answer scored %s against truth %+v", got.Human.Score, got.Truth)
			}
			for _, wrong := range tt.wrong {
				if got := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: wrong}); got.Human.Score != ChallengeIncorrect {
					t.Errorf("%s scored %s for a %s challenge", wrong, got.Human.Score, tt.right)
				}
			}
		})
	}
}

// TestFamiliesNetdocCannotStateScoreUnrecognized pins the other half of the
// contract for the two families netdoc has no words for. It must not be
// scored correct for the generic failure it does emit, and the loss has to say
// which kind of loss it is.
func TestFamiliesNetdocCannotStateScoreUnrecognized(t *testing.T) {
	// The row netdoc really produces for both: a failed target with no
	// cause at all.
	generic := &Diagnosis{Verdict: "service", Summary: "the target is unreachable",
		Checks: []DiagnosisCheck{{ID: "internet_tcp", Status: "PASS"}, {ID: "dns", Status: "PASS"},
			{ID: "target_tcp", Status: "FAIL"}}}
	for _, mutation := range []string{"service.tcp_port_blocked", "routing.missing_subnet_route"} {
		t.Run(mutation, func(t *testing.T) {
			condition, _ := challengeConditionFor(mutation)
			if _, known := challengeRecognition[condition.answer]; known {
				t.Fatalf("%s now has a recognition rule; grade it here instead of expecting unrecognized", condition.answer)
			}
			challenge := &Challenge{ID: "V3-000002", Node: "client", condition: condition,
				Manifest: GeneratedCaseManifest{Mutations: []GeneratedMutation{familyMutation(mutation)}}}
			report := familyObservedReport(mutation)
			report.Tests[0].Diagnosis = generic
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: condition.answer})
			if result.NetworkDoctor.Score != ChallengeUnrecognized {
				t.Fatalf("netdoc scored %s on a condition its vocabulary cannot state", result.NetworkDoctor.Score)
			}
			if result.Result != ChallengeHumanWins {
				t.Fatalf("a correct human against an unrecognized condition = %s", result.Result)
			}
		})
	}
}

func TestConnectionRefusedScoresRecognized(t *testing.T) {
	condition, _ := challengeConditionFor("service.connection_refused")
	challenge := &Challenge{ID: "V3-000002", Node: "client", condition: condition,
		Manifest: GeneratedCaseManifest{Mutations: []GeneratedMutation{familyMutation(condition.mutation)}}}
	report := familyObservedReport(condition.mutation)
	report.Tests[0].Diagnosis.Checks[0].Cause = diagnostic.ConnectionCauseRefused
	result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: condition.answer})
	if !result.Truth.Scoreable || result.Truth.Answer != AnswerRefused {
		t.Fatalf("observed refusal truth = %+v", result.Truth)
	}
	if result.NetworkDoctor.Score != ChallengeCorrect || result.Result != ChallengeDraw {
		t.Fatalf("classified refusal scored %s with result %s", result.NetworkDoctor.Score, result.Result)
	}
}

// familyMutation is the manifest entry each new family's observation rules are
// written against, matching what its generator really emits for the controls it
// is applicable to.
func familyMutation(mutation string) GeneratedMutation {
	switch mutation {
	case "service.connection_refused", "service.tcp_port_blocked":
		return GeneratedMutation{ID: mutation, Node: "target", TargetPort: 80, TargetEndpoint: "10.80.3.20:80"}
	case "service.tls_hostname_mismatch":
		return GeneratedMutation{ID: mutation, Node: "target", Service: "tls-target"}
	case "routing.no_default_route":
		return noDefaultRouteMutation()
	case "routing.wrong_default_route":
		return wrongDefaultRouteMutation()
	case "routing.missing_subnet_route":
		return missingSubnetRouteMutation()
	}
	panic("no manifest entry for " + mutation)
}

// familyObservedReport is a complete run in which exactly this family's
// condition is independently observed. It carries a real diagnosis because a
// challenge with no diagnosis for the primary test is not scoreable at all.
func familyObservedReport(mutation string) *Report {
	report := routeFamilyReport()
	report.Cleanup = CleanupInfo{Done: true}
	report.Tests = []TestOutcome{{Node: "client", Diagnosis: &Diagnosis{Verdict: "network",
		Summary: "something is wrong", Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "FAIL"}}}}}
	switch mutation {
	case "service.connection_refused":
		report.Evidence.ControlledTargets[1].Reachable = false
		report.Evidence.ControlledTargets[1].Outcome = TargetStateRefused
	case "service.tcp_port_blocked":
		report.Evidence.ControlledTargets[1].Reachable = false
		report.Evidence.ControlledTargets[1].Outcome = FamilyStateUnreachable
		report.Evidence.PacketDrops = []PacketDropEvidence{{Node: "target", Protocol: "tcp", Port: 80,
			Direction: DirectionInbound, Packets: 4}}
	case "service.tls_hostname_mismatch":
		report.Evidence.TLS = []TLSEvidence{{Node: "target", Service: "tls-target",
			CertificateMode: TLSCertificateHostnameMismatch, RequestedServer: "secure-target.test",
			CertificateDNS: []string{"not-the-requested-name.test"}, CertificatePresented: true,
			Result: "client_rejected_certificate", Count: 1}}
	case "routing.no_default_route":
		dropDefaults(report)
		report.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
	case "routing.wrong_default_route":
		report.Evidence.RouteTables[0].Routes[0].Via = "10.80.1.254"
		report.Evidence.Routes[0].Via = "10.80.1.254"
		report.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
	case "routing.missing_subnet_route":
		report.Evidence.RouteTables[0].Routes = slices.DeleteFunc(report.Evidence.RouteTables[0].Routes,
			func(k KernelRoute) bool { return k.Destination == "10.80.3.0/24" })
		report.Evidence.ControlledTargets[1].Reachable = false
		report.Evidence.ControlledTargets[1].Outcome = FamilyStateUnreachable
	}
	return report
}

// TestNewFamiliesNeedIndependentEvidenceToScore is the safeguard the whole
// contract rests on, restated for the families added with it: scheduling a
// fault establishes nothing. Each case here is the real manifest against a run
// in which nothing happened, and every one has to be unscoreable rather than a
// free win over Network Doctor.
func TestNewFamiliesNeedIndependentEvidenceToScore(t *testing.T) {
	for _, mutation := range newChallengeFamilies {
		t.Run(mutation, func(t *testing.T) {
			condition, ok := challengeConditionFor(mutation)
			if !ok {
				t.Fatalf("%s is no longer a challenge condition", mutation)
			}
			challenge := &Challenge{ID: "V3-000003", Node: "client", condition: condition,
				Manifest: GeneratedCaseManifest{Mutations: []GeneratedMutation{familyMutation(mutation)}}}
			// The healthy run, with the mutation in the manifest and nowhere else.
			report := routeFamilyReport()
			report.Cleanup = CleanupInfo{Done: true}
			report.Tests = []TestOutcome{{Node: "client", Diagnosis: &Diagnosis{
				Verdict: diagnostic.VerdictOK, OK: true,
				Checks: []DiagnosisCheck{{ID: "target_tcp", Status: "PASS"}}}}}
			result := ScoreChallenge(challenge, report, ChallengeSubmission{Answer: condition.answer})
			if result.Truth.Scoreable {
				t.Fatalf("a fault nobody observed was scoreable as %s", result.Truth.Answer)
			}
			if result.Result != ChallengeNoResult || result.Human.Score != ChallengeUnscoreable {
				t.Fatalf("result=%s human=%s, want a void round", result.Result, result.Human.Score)
			}
		})
	}
}
