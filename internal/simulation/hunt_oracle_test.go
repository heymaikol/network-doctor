package simulation

import (
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// oracleReport is a finished run on a stable path: one client node, one netdoc
// process, and whatever independent evidence the caller attaches. The two
// halves are supplied separately on purpose: no fixture here derives evidence
// from a diagnosis or a diagnosis from evidence.
func oracleReport(diagnosis *Diagnosis, evidence Evidence) *Report {
	return &Report{Cleanup: CleanupInfo{Done: true}, Topology: []NodeInfo{{Name: "client", Role: "client"}},
		Tests:    []TestOutcome{{Name: "netdoc", Node: "client", ProcessOutcome: ProcessExited, Diagnosis: diagnosis}},
		Evidence: evidence, Suggestions: []Suggestion{}}
}

func oracleDiagnosis(checks ...DiagnosisCheck) *Diagnosis { return &Diagnosis{Checks: checks} }

func TestOracleAndDiagnosisChecksShareTheFinalClientTest(t *testing.T) {
	first := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeInternet), Status: "WARN",
		Cause:    diagnostic.RouteCausePreferredPathFailed,
		Families: &DiagnosisFamilies{IPv4: FamilyStateReachable}})
	final := oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeInternet), Status: "FAIL",
		Cause:    diagnostic.RouteCauseNoDefaultRoute,
		Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}})
	report := oracleReport(first, noDefaultRouteEvidence())
	report.Tests = append(report.Tests, TestOutcome{Name: "final", Node: "client", ProcessOutcome: ProcessExited, Diagnosis: final})

	authoritative := finalClientTest(report)
	if authoritative != &report.Tests[1] || finalClientDiagnosis(report) != authoritative.Diagnosis {
		t.Fatalf("authoritative test = %p diagnosis=%p, want final test %p diagnosis=%p",
			authoritative, finalClientDiagnosis(report), &report.Tests[1], final)
	}
	check := checkByID(authoritative.Diagnosis, string(diagnostic.ProbeInternet))
	if check == nil || check.Cause != diagnostic.RouteCauseNoDefaultRoute ||
		diagnosedFamily(authoritative.Diagnosis, "ipv4") != FamilyStateUnreachable {
		t.Fatalf("authoritative diagnosis check = %+v diagnosis=%+v", check, authoritative.Diagnosis)
	}
	established, recognized, comparable := caseConditions(report, ObservedTruth{IPv4: FamilyStateUnreachable})
	if !comparable || !slices.Contains(established, ConditionNoDefaultRoute) ||
		!slices.Contains(recognized, ConditionNoDefaultRoute) ||
		!slices.Contains(recognized, ConditionIPv4InternetUnreachable) ||
		slices.Contains(recognized, ConditionPreferredRouteFailed) {
		t.Fatalf("oracle established=%v recognized=%v comparable=%t", established, recognized, comparable)
	}
}

// Independent evidence fixtures. Each one is what a node holder would have
// written down; none of them can be produced by reading netdoc's report.
func expiredTLSEvidence() Evidence {
	return Evidence{TLS: []TLSEvidence{{Node: "target", Service: "web", CertificateMode: TLSCertificateExpired,
		CertificatePresented: true, Result: "client_rejected_certificate", Count: 1}}}
}

func refusedProxyEvidence() Evidence {
	return Evidence{SOCKSRequests: []SOCKSEvidence{{Node: "proxy", Service: "socks", Event: "connect",
		Destination: proxyCONNECTTarget, Port: 443, Result: "connection_refused", Count: 1}}}
}

func droppedQUICEvidence() Evidence {
	return Evidence{PacketDrops: []PacketDropEvidence{{Node: "target", Protocol: "udp", Port: 443,
		Direction: DirectionInbound, Packets: 4}}}
}

func resetTCPEvidence() Evidence {
	return Evidence{TCPResets: []TCPResetEvidence{{Node: "target", Service: "http-target", Event: "reset",
		Result: "connection_reset", Count: 1}}}
}

func invalidDoHEvidence() Evidence {
	return Evidence{ServiceReplies: []ServiceReplyEvidence{{Node: "resolver", Service: encryptedDNSProbeService,
		Type: ServiceEncryptedDNS, Port: 443, Result: DoHResponseInvalid, Count: 1}}}
}

// noDefaultRouteEvidence is the client's own routing table, read back from its
// kernel, holding on-link routes and no default. The absence is the whole
// observation, which is why the record has to exist and be empty of defaults
// rather than simply be missing.
func noDefaultRouteEvidence() Evidence {
	return Evidence{RouteTables: []RouteTableEvidence{{Node: "client", Family: "ipv4",
		Routes: []KernelRoute{{Destination: "10.77.0.0/24", Segment: "lan"}}}}}
}

func http503Evidence() Evidence {
	return Evidence{ServiceReplies: []ServiceReplyEvidence{{Node: "target", Type: ServiceHTTP, Port: 80,
		Status: http.StatusServiceUnavailable, Result: replyResponded, Count: 1}}}
}

// servedDNSEvidence is one query a client really sent and the answer the
// resolver really gave it, which is a different record from the scheduler's
// note that the resolver was moved into that state.
func servedDNSEvidence(service, outcome string) Evidence {
	return Evidence{DNSQueries: []DNSQueryEvidence{{Node: "resolver", Service: service, Name: "example.com.",
		QueryType: "A", Sequence: 1, ActualOutcome: outcome}}}
}

func appliedDNSFault(service, outcome string, offset time.Duration) []FaultEventEvidence {
	return []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledDNS, Service: service,
		Outcome: outcome, Offset: offset}, Result: EventApplied}}
}

func unrecognizedConditions(findings []HuntCaseFinding) []string {
	var out []string
	for _, finding := range findings {
		if finding.Category == FindingFalseNegative && finding.Code == "unrecognized_network_condition" {
			out = append(out, finding.Expected)
		}
	}
	return out
}

func analyzedConditions(t *testing.T, manifest GeneratedCaseManifest, report *Report, truth ObservedTruth) []string {
	t.Helper()
	return unrecognizedConditions(analyzeHuntCase(manifest, report, truth))
}

// TestHuntOracleAccusesOnlyUnrecognizedObservedConditions is the core contract:
// independently observed truth implies a semantic condition, and a diagnosis
// that does not communicate it is a false negative. Each case pairs one
// evidence fixture with two diagnoses that differ in nothing but whether they
// say what the network is doing.
func TestHuntOracleAccusesOnlyUnrecognizedObservedConditions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		evidence   Evidence
		truth      ObservedTruth
		condition  NetworkCondition
		missed     *Diagnosis
		recognized *Diagnosis
	}{
		{
			name: "TLS certificate expired", evidence: expiredTLSEvidence(), condition: ConditionTLSCertificateExpired,
			// A bare handshake failure is deliberately not equivalent: the user
			// is sent to look for a MITM proxy instead of at the clock.
			missed:     oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "FAIL", Cause: diagnostic.TLSCauseHandshake}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "FAIL", Cause: diagnostic.TLSCauseCertificateExpired}),
		},
		{
			name: "proxy refused its destination", evidence: refusedProxyEvidence(), condition: ConditionProxyDestinationRefused,
			// Being unable to reach the proxy is a different fault from the
			// proxy answering and declining, so it does not recognize this one.
			missed:     oracleDiagnosis(DiagnosisCheck{ID: "proxy_connect", Status: "FAIL", Cause: diagnostic.ProxyCauseUnreachable}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: "proxy_connect", Status: "FAIL", Cause: diagnostic.ProxyCauseDestinationUnreachable}),
		},
		{
			name: "QUIC UDP/443 dropped", evidence: droppedQUICEvidence(), condition: ConditionQUICUDP443Blocked,
			missed: oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeQUIC), Status: "PASS"}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeQUIC), Status: "FAIL",
				Cause: diagnostic.QUICCauseTimeout}),
		},
		{
			name: "IPv4 internet reachability lost", truth: ObservedTruth{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable},
			condition: ConditionIPv4InternetUnreachable,
			missed: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "PASS",
				Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateReachable}}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable}}),
		},
		{
			// The sharp one: "the internet is unreachable" is true here and
			// netdoc says it, but the route is simply gone and netdoc has its
			// own cause with its own fix. A diagnosis that reports only the lost
			// reachability is stable, structurally valid and materially wrong,
			// which is exactly the class this rule exists to catch.
			name: "client left with no default route", evidence: noDefaultRouteEvidence(),
			truth: ObservedTruth{IPv4: FamilyStateUnreachable}, condition: ConditionNoDefaultRoute,
			missed: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Cause:    diagnostic.RouteCauseGatewayUnreachable,
				Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Cause:    diagnostic.RouteCauseNoDefaultRoute,
				Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}}),
		},
		{
			name: "IPv6 internet reachability lost", truth: ObservedTruth{IPv4: FamilyStateReachable, IPv6: FamilyStateUnreachable},
			condition: ConditionIPv6InternetUnreachable,
			missed: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "PASS",
				Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateReachable}}),
			recognized: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateUnreachable}}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			missed := analyzedConditions(t, huntManifest(), oracleReport(tc.missed, tc.evidence), tc.truth)
			if !slices.Equal(missed, []string{string(tc.condition)}) {
				t.Fatalf("unrecognized observed condition = %v, want %q", missed, tc.condition)
			}
			seen := analyzedConditions(t, huntManifest(), oracleReport(tc.recognized, tc.evidence), tc.truth)
			if len(seen) != 0 {
				t.Fatalf("recognized condition still accused: %v", seen)
			}
		})
	}
}

func TestUnrecognizedConditionFinding(t *testing.T) {
	got := unrecognizedConditionFindings(oracleReport(
		oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS"}), expiredTLSEvidence()), ObservedTruth{})
	want := []HuntCaseFinding{{
		Category: FindingFalseNegative, Severity: SeverityHigh, Code: "unrecognized_network_condition",
		Expected: string(ConditionTLSCertificateExpired), Actual: "unrecognized",
		Summary:  "The simulator independently observed a target serving an expired TLS certificate, but the diagnosis did not recognize it.",
		Evidence: "a controlled TLS service presented an expired certificate and watched a client refuse it",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unrecognized condition finding = %+v, want %+v", got, want)
	}
}

// An absent default route is only a condition when the table was actually read,
// really held no default, and the family really stopped working. Each negative
// below breaks exactly one of those, so the rule cannot quietly widen into
// "netdoc did not mention routing".
func TestNoDefaultRouteConditionNeedsTheTableAndTheConsequence(t *testing.T) {
	table := func(node, family string, routes ...KernelRoute) Evidence {
		return Evidence{RouteTables: []RouteTableEvidence{{Node: node, Family: family, Routes: routes}}}
	}
	onLink := KernelRoute{Destination: "10.77.0.0/24", Segment: "lan"}
	for _, tc := range []struct {
		name     string
		evidence Evidence
		truth    ObservedTruth
		want     bool
	}{
		{
			name:     "read, empty of defaults, and the family is gone",
			evidence: table("client", "ipv4", onLink), truth: ObservedTruth{IPv4: FamilyStateUnreachable}, want: true,
		},
		{
			// Nobody looked. A table that was never read cannot be called empty,
			// which is the difference between an observation and an assumption.
			name: "no table was read", truth: ObservedTruth{IPv4: FamilyStateUnreachable},
		},
		{
			// Another node's table says nothing about the client's.
			name:     "the table belongs to a different node",
			evidence: table("gateway", "ipv4", onLink), truth: ObservedTruth{IPv4: FamilyStateUnreachable},
		},
		{
			name:     "a default route is still there",
			evidence: table("client", "ipv4", onLink, KernelRoute{Destination: "default", Via: "10.77.0.1", Segment: "lan"}),
			truth:    ObservedTruth{IPv4: FamilyStateUnreachable},
		},
		{
			// The route is gone and the internet is fine anyway, over something
			// specific. Nothing was lost, so there is nothing to accuse.
			name: "the family still reaches the internet", evidence: table("client", "ipv4", onLink),
			truth: ObservedTruth{IPv4: FamilyStateReachable},
		},
		{
			// A family the client never had an address in is not a family whose
			// route went missing.
			name: "the family was never available", evidence: table("client", "ipv4", onLink),
			truth: ObservedTruth{IPv4: FamilyStateUnavailable},
		},
		{
			// The same reading on the other family, so the rule is not quietly
			// hard-wired to IPv4.
			name: "IPv6 loses its default too", evidence: table("client", "ipv6",
				KernelRoute{Destination: "2001:db8::/64", Segment: "lan"}),
			truth: ObservedTruth{IPv6: FamilyStateUnreachable}, want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observedConditions(observation{Evidence: tc.evidence, Truth: tc.truth, Client: "client"})
			if slices.Contains(got, ConditionNoDefaultRoute) != tc.want {
				t.Fatalf("observed conditions = %v, want ConditionNoDefaultRoute present = %t", got, tc.want)
			}
		})
	}
}

// TestHuntOracleAcceptsEquivalentRecognition proves the oracle asks whether the
// condition was communicated, not which row communicated it. Both alternatives
// are things netdoc genuinely produces.
func TestHuntOracleAcceptsEquivalentRecognition(t *testing.T) {
	for _, tc := range []struct {
		name      string
		evidence  Evidence
		truth     ObservedTruth
		diagnosis *Diagnosis
	}{
		{
			// The expiry cause on a different row than the one the current
			// probe graph happens to put it on.
			name: "expiry named by a different row", evidence: expiredTLSEvidence(),
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "https", Status: "FAIL", Cause: diagnostic.TLSCauseCertificateExpired}),
		},
		{
			// The family stated as a cause rather than as a structured
			// address_families verdict.
			name:  "family named by cause rather than the families block",
			truth: ObservedTruth{IPv4: FamilyStateReachable, IPv6: FamilyStateUnreachable},
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Cause: diagnostic.FamilyCauseIPv6Unreachable}),
		},
		{
			// A QUIC block that shows up as a handshake failure instead of the
			// timeout the control scenario records.
			name: "QUIC block reported as a handshake failure", evidence: droppedQUICEvidence(),
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: string(diagnostic.ProbeQUIC), Status: "FAIL",
				Cause: diagnostic.QUICCauseHandshake}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := analyzedConditions(t, huntManifest(), oracleReport(tc.diagnosis, tc.evidence), tc.truth); len(got) != 0 {
				t.Fatalf("equivalent recognition accused anyway: %v", got)
			}
		})
	}
}

// TestHuntOracleRejectsUnrelatedFailures is the guard against a permissive
// oracle: netdoc failing loudly about something else is not recognition. The
// QUIC case is the sharp one, because "timeout" is not a unique cause in
// netdoc's vocabulary and TLS spends it too.
func TestHuntOracleRejectsUnrelatedFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		evidence  Evidence
		truth     ObservedTruth
		diagnosis *Diagnosis
		want      NetworkCondition
	}{
		{
			name: "observed TLS expiry with an unrelated DNS failure", evidence: expiredTLSEvidence(),
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "dns", Status: "FAIL", Cause: diagnostic.DNSCauseTimeout}),
			want:      ConditionTLSCertificateExpired,
		},
		{
			name: "observed QUIC block with an unrelated TLS timeout", evidence: droppedQUICEvidence(),
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "FAIL", Cause: diagnostic.TLSCauseTimeout}),
			want:      ConditionQUICUDP443Blocked,
		},
		{
			name:  "observed IPv4 loss with the other family reported unreachable",
			truth: ObservedTruth{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable},
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
				Cause: diagnostic.FamilyCauseIPv6Unreachable}),
			want: ConditionIPv4InternetUnreachable,
		},
		{
			// A cause on a passing row is context, not netdoc raising its hand.
			name: "expiry cause carried by a passing row", evidence: expiredTLSEvidence(),
			diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS", Cause: diagnostic.TLSCauseCertificateExpired}),
			want:      ConditionTLSCertificateExpired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzedConditions(t, huntManifest(), oracleReport(tc.diagnosis, tc.evidence), tc.truth)
			if !slices.Contains(got, string(tc.want)) {
				t.Fatalf("unrelated failure satisfied %q; accusations = %v", tc.want, got)
			}
		})
	}
}

// TestHuntOracleIgnoresTheMutationSchedule is requirement zero: a manifest is
// intent. Every mutation below claims to have been generated and applied, and
// the run recorded no independent evidence that any of them reached the
// network, so nothing may be said about the diagnosis.
func TestHuntOracleIgnoresTheMutationSchedule(t *testing.T) {
	manifest := huntManifest(
		GeneratedMutation{ID: "service.tls_expired", Node: "target", Service: "web"},
		GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", Service: "socks", TargetPort: 443},
		GeneratedMutation{ID: "quic.udp_443_block", Node: "target", TargetPort: 443},
		GeneratedMutation{ID: "family.ipv4_drop", Node: "gateway", Family: "ipv4"},
	)
	report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "PASS",
		Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateReachable}}), Evidence{})
	truth := collectObservedTruth(manifest, report)
	if len(truth.ObservedFaults) != 0 {
		t.Fatalf("scheduled mutations were treated as observed: %v", truth.ObservedFaults)
	}
	if got := analyzedConditions(t, manifest, report, truth); len(got) != 0 {
		t.Fatalf("mutation schedule alone produced false-negative accusations: %v", got)
	}
}

// TestHuntOracleRequiresTheFaultToHaveReachedTheWire separates a fault that was
// configured from one that did something. Each fixture is the near miss of a
// real observation: a certificate nobody was shown, a rule that matched no
// packet, a proxy that answered normally.
func TestHuntOracleRequiresTheFaultToHaveReachedTheWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence Evidence
	}{
		{"expired certificate never presented", Evidence{TLS: []TLSEvidence{{Node: "target", Service: "web",
			CertificateMode: TLSCertificateExpired, CertificatePresented: false, Result: "no_handshake", Count: 1}}}},
		{"expired certificate the client accepted", Evidence{TLS: []TLSEvidence{{Node: "target", Service: "web",
			CertificateMode: TLSCertificateExpired, CertificatePresented: true, Result: "passed", Count: 1}}}},
		{"service configured but never reached", Evidence{ServiceStates: []ServiceStateEvidence{{Node: "target",
			Service: "web", Type: ServiceTLS, Mode: TLSCertificateExpired}}}},
		{"drop rule that matched no packet", Evidence{PacketDrops: []PacketDropEvidence{{Node: "target",
			Protocol: "udp", Port: 443, Direction: DirectionInbound, Packets: 0}}}},
		{"proxy that connected normally", Evidence{SOCKSRequests: []SOCKSEvidence{{Node: "proxy", Service: "socks",
			Event: "connect", Destination: proxyCONNECTTarget, Port: 443, Result: "connected", Count: 1}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS"}), tc.evidence)
			if got := observedConditions(observation{Evidence: report.Evidence}); len(got) != 0 {
				t.Fatalf("unobserved effect established %v", got)
			}
		})
	}
}

// TestHuntEvidenceScopeIsRequiredNotWildcarded pins the one place where two
// different questions share an evidence reader. The oracle asks whether a
// condition happened at all, which is unscoped by design because a network fact
// is not owned by a node. Per-mutation observation asks whether one mutation
// took effect where it said it would, which a manifest that names no place
// cannot answer. Neither missing half may quietly widen into "matches
// anything": a mutation would confirm itself from a fault someone else caused,
// and a record from nowhere would establish a condition nobody observed.
func TestHuntEvidenceScopeIsRequiredNotWildcarded(t *testing.T) {
	// Controls first. Same evidence, fully scoped mutations, all observed;
	// without these the cases below would pass on a reader that always says no.
	for _, tc := range []struct {
		name     string
		mutation GeneratedMutation
		evidence Evidence
	}{
		{"expired TLS", GeneratedMutation{ID: "service.tls_expired", Node: "target", Service: "web"}, expiredTLSEvidence()},
		{"proxy refusal", GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", Service: "socks", TargetPort: 443}, refusedProxyEvidence()},
		{"QUIC block", GeneratedMutation{ID: "quic.udp_443_block", Node: "target", TargetPort: 443}, droppedQUICEvidence()},
	} {
		t.Run("scoped "+tc.name, func(t *testing.T) {
			if !mutationObserved(tc.mutation, oracleReport(nil, tc.evidence), ObservedTruth{}) {
				t.Fatal("a fully scoped mutation was not observed in its own evidence")
			}
		})
	}

	// A hand-built manifest that forgot to say where its effect belongs. The
	// evidence is the genuine article in every case; only the scope is missing.
	for _, tc := range []struct {
		name     string
		mutation GeneratedMutation
		evidence Evidence
	}{
		{"expired TLS naming no node", GeneratedMutation{ID: "service.tls_expired", Service: "web"}, expiredTLSEvidence()},
		{"expired TLS naming no service", GeneratedMutation{ID: "service.tls_expired", Node: "target"}, expiredTLSEvidence()},
		{"expired TLS naming nothing", GeneratedMutation{ID: "service.tls_expired"}, expiredTLSEvidence()},
		{"proxy refusal naming no node", GeneratedMutation{ID: "proxy.connect_refused", Service: "socks", TargetPort: 443}, refusedProxyEvidence()},
		{"proxy refusal naming no service", GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", TargetPort: 443}, refusedProxyEvidence()},
		{"proxy refusal naming no port", GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", Service: "socks"}, refusedProxyEvidence()},
		{"QUIC block naming no node", GeneratedMutation{ID: "quic.udp_443_block", TargetPort: 443}, droppedQUICEvidence()},
		{"QUIC block naming no port", GeneratedMutation{ID: "quic.udp_443_block", Node: "target"}, droppedQUICEvidence()},
		{"QUIC block naming nothing", GeneratedMutation{ID: "quic.udp_443_block"}, droppedQUICEvidence()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if mutationObserved(tc.mutation, oracleReport(nil, tc.evidence), ObservedTruth{}) {
				t.Fatal("a mutation that never said where its effect belongs was counted as observed")
			}
			// The oracle's own question is unchanged by any of this: it never
			// read the manifest, so an incomplete manifest cannot silence it.
			if got := observedConditions(observation{Evidence: tc.evidence}); len(got) != 1 {
				t.Fatalf("independently observed conditions = %v, want exactly one", got)
			}
		})
	}

	// The case where the two blanks would have met: a manifest that names no
	// service and a record that names none either. Exact comparison alone would
	// call that a match, which is why the scope is required rather than merely
	// compared.
	t.Run("blank scope must not meet blank evidence", func(t *testing.T) {
		anonymous := expiredTLSEvidence()
		anonymous.TLS[0].Service = ""
		if mutationObserved(GeneratedMutation{ID: "service.tls_expired", Node: "target"},
			oracleReport(nil, anonymous), ObservedTruth{}) {
			t.Fatal("a mutation naming no service was confirmed by evidence naming no service")
		}
	})

	// Evidence that does not say which node produced it. A holder stamps its own
	// name on every record it writes, so these are hand-built; a record from
	// nowhere must not establish a condition merely because no scope disagrees
	// with it.
	unstampedTLS, unstampedProxy, unstampedQUIC := expiredTLSEvidence(), refusedProxyEvidence(), droppedQUICEvidence()
	unstampedTLS.TLS[0].Node = ""
	unstampedProxy.SOCKSRequests[0].Node = ""
	unstampedQUIC.PacketDrops[0].Node = ""
	for _, tc := range []struct {
		name     string
		evidence Evidence
	}{
		{"handshake from no node", unstampedTLS},
		{"CONNECT refusal from no node", unstampedProxy},
		{"packet drop from no node", unstampedQUIC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := observedConditions(observation{Evidence: tc.evidence}); len(got) != 0 {
				t.Fatalf("unattributable evidence established %v", got)
			}
		})
	}
}

// TestHuntOracleKeepsFamilyStatesDistinct is the unavailable-versus-unreachable
// contract at the semantic layer: only a family that was dialed and did not
// answer expects recognition, and neither family's state may leak into the
// other's expectation.
func TestHuntOracleKeepsFamilyStatesDistinct(t *testing.T) {
	for _, tc := range []struct {
		name       string
		ipv4, ipv6 string
		want       []NetworkCondition
	}{
		{"both reachable", FamilyStateReachable, FamilyStateReachable, nil},
		{"IPv4 unreachable alone", FamilyStateUnreachable, FamilyStateReachable, []NetworkCondition{ConditionIPv4InternetUnreachable}},
		{"IPv6 unreachable alone", FamilyStateReachable, FamilyStateUnreachable, []NetworkCondition{ConditionIPv6InternetUnreachable}},
		{"both unreachable", FamilyStateUnreachable, FamilyStateUnreachable,
			[]NetworkCondition{ConditionIPv4InternetUnreachable, ConditionIPv6InternetUnreachable}},
		// A family the node never had an address in was not tested, and an
		// absent measurement is not a network fact either. Neither may become
		// an expectation, and neither may satisfy the other family's.
		{"IPv6 unavailable", FamilyStateReachable, FamilyStateUnavailable, nil},
		{"IPv4 unavailable", FamilyStateUnavailable, FamilyStateReachable, nil},
		{"IPv4 unavailable while IPv6 is lost", FamilyStateUnavailable, FamilyStateUnreachable,
			[]NetworkCondition{ConditionIPv6InternetUnreachable}},
		{"unmeasured", "unknown", "unknown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observedConditions(observation{Truth: ObservedTruth{IPv4: tc.ipv4, IPv6: tc.ipv6}})
			if !slices.Equal(got, tc.want) {
				t.Fatalf("observed conditions = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHuntOracleHoldsItsDirection pins the dependency arrows. The observed side
// cannot reach a diagnosis at all, since it takes Evidence and the compiler holds
// that half, and this covers the two the compiler cannot: recognition must not
// move with the evidence, and the reconciler, which does see the whole report,
// must let the diagnosis change only the accusation.
func TestHuntOracleHoldsItsDirection(t *testing.T) {
	truth := ObservedTruth{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable}
	blind := oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "PASS",
		Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateReachable}})
	naming := oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
		Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable, IPv6: FamilyStateReachable}})
	// Recognition is a function of the diagnosis alone: the same diagnosis read
	// beside contradicting evidence answers the same way.
	withTLS := recognizedConditions(naming)
	if !slices.Equal(withTLS, recognizedConditions(naming)) ||
		!slices.Equal(withTLS, []NetworkCondition{ConditionIPv4InternetUnreachable}) {
		t.Fatalf("recognition = %v, want only the reported family loss", withTLS)
	}
	// Same evidence, same truth, two diagnoses: what was observed is identical
	// either way, and only the finding differs.
	evidence := expiredTLSEvidence()
	if !slices.Equal(observedConditions(observation{Evidence: evidence, Truth: truth}),
		[]NetworkCondition{ConditionIPv4InternetUnreachable, ConditionTLSCertificateExpired}) {
		t.Fatalf("observed conditions = %v", observedConditions(observation{Evidence: evidence, Truth: truth}))
	}
	missed := unrecognizedConditions(unrecognizedConditionFindings(oracleReport(blind, evidence), truth))
	seen := unrecognizedConditions(unrecognizedConditionFindings(oracleReport(naming, evidence), truth))
	if !slices.Equal(missed, []string{string(ConditionIPv4InternetUnreachable), string(ConditionTLSCertificateExpired)}) {
		t.Fatalf("blind diagnosis accusations = %v", missed)
	}
	if !slices.Equal(seen, []string{string(ConditionTLSCertificateExpired)}) {
		t.Fatalf("family-naming diagnosis accusations = %v", seen)
	}
}

// TestHuntOracleStaysQuietOnUnstablePaths keeps the final-state comparison out
// of runs where the simulator's last sample and netdoc's last probe could
// legitimately describe different networks.
func TestHuntOracleStaysQuietOnUnstablePaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"netem", func(report *Report) { report.Faults = []FaultInfo{{Type: FaultNetem, LossPercent: 20}} }},
		{"timed netem", func(report *Report) {
			report.Timeline = []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledNetem, LossPercent: 100}, Result: EventApplied}}
		}},
		{"transient link", func(report *Report) {
			report.Timeline = []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledLink, State: LinkStateDown}, Result: EventApplied}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS"}), expiredTLSEvidence())
			tc.change(report)
			if got := analyzedConditions(t, huntManifest(), report, ObservedTruth{}); len(got) != 0 {
				t.Fatalf("unstable path produced accusations: %v", got)
			}
		})
	}
}

// TestHuntOracleWithoutAClientDiagnosis covers the runs that have truth but
// nothing to reconcile it against.
func TestHuntOracleWithoutAClientDiagnosis(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Report)
	}{
		{"netdoc produced no diagnosis", func(report *Report) { report.Tests[0].Diagnosis = nil }},
		{"no client node", func(report *Report) { report.Topology[0].Role = "router" }},
		{"two client nodes", func(report *Report) {
			report.Topology = append(report.Topology, NodeInfo{Name: "second", Role: "client"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "tls", Status: "PASS"}), expiredTLSEvidence())
			tc.change(report)
			if got := analyzedConditions(t, huntManifest(), report, ObservedTruth{}); len(got) != 0 {
				t.Fatalf("reconciliation ran without a client diagnosis: %v", got)
			}
		})
	}
}

// TestHuntOracleClaimsNothingAboutUndiagnosedFaults documents the deliberate
// gaps. Both faults are independently observed, and neither implies a condition
// Network Doctor claims to report: an HTTP error status is a working service
// answering, and DoH failing while DoT still resolves is encrypted DNS
// working. Turning either into an expectation would invent a contract the
// probes never made, which is what the `http-error` and encrypted-DNS controls
// exist to pin down.
func TestHuntOracleClaimsNothingAboutUndiagnosedFaults(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutation GeneratedMutation
		evidence Evidence
	}{
		{"HTTP 503", GeneratedMutation{ID: "http.status_503", Node: "target", TargetPort: 80,
			Status: http.StatusServiceUnavailable}, http503Evidence()},
		{"invalid DoH while DoT resolves", GeneratedMutation{ID: "encrypted_dns.doh_invalid", Node: "resolver",
			Service: encryptedDNSProbeService}, invalidDoHEvidence()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "http", Status: "PASS"},
				DiagnosisCheck{ID: "dns_encrypted", Status: "PASS"}), tc.evidence)
			if got := observedConditions(observation{Evidence: report.Evidence}); len(got) != 0 {
				t.Fatalf("a fault netdoc does not diagnose became an expectation: %v", got)
			}
			// The fault really did reach the wire, since this is the observed case
			// rather than the unobserved one, and it still accuses nobody.
			manifest := huntManifest(tc.mutation)
			truth := collectObservedTruth(manifest, report)
			if !slices.Equal(truth.ObservedFaults, []string{tc.mutation.ID}) {
				t.Fatalf("observed faults = %v, want %q", truth.ObservedFaults, tc.mutation.ID)
			}
			for _, finding := range analyzeHuntCase(manifest, report, truth) {
				if finding.Category == FindingFalseNegative {
					t.Fatalf("an undiagnosed fault produced %s", finding.Code)
				}
			}
		})
	}
}

// scopedFamilyCase is one mutation family's observation contract: the run that
// proves the fault reached somebody, the fully scoped manifest entry that owns
// it, and the manifest entries that left a scope key blank. Every blanked entry
// is paired with the same genuine evidence, so the only thing under test is
// whether an unanswerable question can confirm itself.
type scopedFamilyCase struct {
	name     string
	report   Report
	mutation GeneratedMutation
	blanked  []GeneratedMutation
}

// TestMutationScopeIsRequiredForEveryFamily extends the scope rule past the
// three families the condition oracle also asks about. A manifest that does not
// say where its effect belongs establishes nothing, and a blank key must not
// meet a record that happens to be blank in the same place: otherwise a
// half-filled manifest confirms itself from a fault some other node produced.
func TestMutationScopeIsRequiredForEveryFamily(t *testing.T) {
	for _, tc := range []scopedFamilyCase{
		{
			name:     "TCP reset",
			report:   Report{Evidence: resetTCPEvidence()},
			mutation: GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 80},
			blanked:  []GeneratedMutation{{ID: "service.tcp_reset", TargetPort: 80}, {ID: "service.tcp_reset"}},
		},
		{
			name:     "invalid DoH",
			report:   Report{Evidence: invalidDoHEvidence()},
			mutation: GeneratedMutation{ID: "encrypted_dns.doh_invalid", Node: "resolver", Service: encryptedDNSProbeService},
			blanked: []GeneratedMutation{
				{ID: "encrypted_dns.doh_invalid", Service: encryptedDNSProbeService},
				{ID: "encrypted_dns.doh_invalid", Node: "resolver"},
				{ID: "encrypted_dns.doh_invalid"},
			},
		},
		{
			name:     "HTTP 503",
			report:   Report{Evidence: http503Evidence()},
			mutation: GeneratedMutation{ID: "http.status_503", Node: "target", TargetPort: 80, Status: http.StatusServiceUnavailable},
			blanked: []GeneratedMutation{
				{ID: "http.status_503", TargetPort: 80, Status: http.StatusServiceUnavailable},
				{ID: "http.status_503", Node: "target", Status: http.StatusServiceUnavailable},
				{ID: "http.status_503", Node: "target", TargetPort: 80},
				{ID: "http.status_503"},
			},
		},
		{
			name: "DNS SERVFAIL",
			report: Report{Timeline: appliedDNSFault("resolver", DNSOutcomeSERVFAIL, 0),
				Evidence: servedDNSEvidence("resolver", dnsServedSERVFAIL)},
			mutation: GeneratedMutation{ID: "dns.servfail", Service: "resolver"},
			blanked:  []GeneratedMutation{{ID: "dns.servfail"}},
		},
		{
			name: "DNS drop",
			report: Report{Timeline: appliedDNSFault("resolver", DNSOutcomeDrop, 0),
				Evidence: servedDNSEvidence("resolver", dnsServedDropped)},
			mutation: GeneratedMutation{ID: "dns.drop", Service: "resolver"},
			blanked:  []GeneratedMutation{{ID: "dns.drop"}},
		},
		{
			name: "timeline DNS outage",
			report: Report{Timeline: appliedDNSFault("resolver", DNSOutcomeDrop, 150*time.Millisecond),
				Evidence: servedDNSEvidence("resolver", dnsServedDropped)},
			mutation: GeneratedMutation{ID: "timeline.dns_outage", Service: "resolver", StartMS: 150},
			blanked:  []GeneratedMutation{{ID: "timeline.dns_outage", StartMS: 150}},
		},
		{
			name: "persistent loss",
			report: Report{Evidence: Evidence{PacketConditions: []PacketConditionEvidence{{Node: "gateway",
				Segment: "upstream", Active: true, LossPercent: 17, Seed: 11}}}},
			mutation: GeneratedMutation{ID: "netem.loss", Node: "gateway", Segment: "upstream", LossPercent: 17, NetemSeed: 11},
			blanked: []GeneratedMutation{
				{ID: "netem.loss", Segment: "upstream", LossPercent: 17, NetemSeed: 11},
				{ID: "netem.loss", Node: "gateway", LossPercent: 17, NetemSeed: 11},
			},
		},
		{
			name:   "path-MTU black hole",
			report: pmtuLinks(minBlackholeMTU, 1500),
			mutation: GeneratedMutation{ID: "pmtu.blackhole", Node: "gateway", Segment: "upstream",
				TargetNode: "client", MTU: minBlackholeMTU},
			blanked: []GeneratedMutation{
				{ID: "pmtu.blackhole", Segment: "upstream", TargetNode: "client", MTU: minBlackholeMTU},
				{ID: "pmtu.blackhole", Node: "gateway", TargetNode: "client", MTU: minBlackholeMTU},
				{ID: "pmtu.blackhole", Node: "gateway", Segment: "upstream", MTU: minBlackholeMTU},
				{ID: "pmtu.blackhole", Node: "gateway", Segment: "upstream", TargetNode: "client"},
			},
		},
		{
			name: "transient link down",
			report: Report{Timeline: []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledLink,
				Node: "gateway", Segment: "upstream", State: LinkStateDown}, Result: EventApplied}}},
			mutation: GeneratedMutation{ID: "link.transient_down", Node: "gateway", Segment: "upstream"},
			blanked: []GeneratedMutation{
				{ID: "link.transient_down", Segment: "upstream"},
				{ID: "link.transient_down", Node: "gateway"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Control: without this the blanked cases would pass on a reader that
			// always says no.
			if !mutationObserved(tc.mutation, &tc.report, ObservedTruth{}) {
				t.Fatal("a fully scoped mutation was not observed in its own evidence")
			}
			for _, mutation := range tc.blanked {
				if mutationObserved(mutation, &tc.report, ObservedTruth{}) {
					t.Errorf("a mutation that never said where its effect belongs was counted as observed: %+v", mutation)
				}
			}
			// The other half of the same rule: a holder-written record that nobody
			// stamped is not an observation, so it cannot answer a fully scoped
			// question either. Families scoped entirely on the fault scheduler's
			// own timeline have no such record to strip.
			unstamped := tc.report
			unstamped.Evidence = unstampEvidence(tc.report.Evidence)
			if reflect.DeepEqual(unstamped.Evidence, tc.report.Evidence) {
				return
			}
			if mutationObserved(tc.mutation, &unstamped, ObservedTruth{}) {
				t.Error("evidence from no node satisfied a node-scoped mutation")
			}
		})
	}
}

// unstampEvidence removes the node every holder writes on its own records. Real
// evidence always carries one, so these reports are only reachable by hand. The
// point is that a record from nowhere stays worthless rather than matching
// whatever asks for it.
func unstampEvidence(evidence Evidence) Evidence {
	out := evidence
	out.TLS = append([]TLSEvidence(nil), evidence.TLS...)
	out.SOCKSRequests = append([]SOCKSEvidence(nil), evidence.SOCKSRequests...)
	out.PacketDrops = append([]PacketDropEvidence(nil), evidence.PacketDrops...)
	out.TCPResets = append([]TCPResetEvidence(nil), evidence.TCPResets...)
	out.ServiceReplies = append([]ServiceReplyEvidence(nil), evidence.ServiceReplies...)
	out.DNSQueries = append([]DNSQueryEvidence(nil), evidence.DNSQueries...)
	out.PacketConditions = append([]PacketConditionEvidence(nil), evidence.PacketConditions...)
	out.Links = append([]LinkEvidence(nil), evidence.Links...)
	for i := range out.TLS {
		out.TLS[i].Node = ""
	}
	for i := range out.SOCKSRequests {
		out.SOCKSRequests[i].Node = ""
	}
	for i := range out.PacketDrops {
		out.PacketDrops[i].Node = ""
	}
	for i := range out.TCPResets {
		out.TCPResets[i].Node = ""
	}
	for i := range out.ServiceReplies {
		out.ServiceReplies[i].Node = ""
	}
	for i := range out.DNSQueries {
		out.DNSQueries[i].Node = ""
	}
	for i := range out.PacketConditions {
		out.PacketConditions[i].Node = ""
	}
	for i := range out.Links {
		out.Links[i].Node = ""
	}
	return out
}

// TestScheduledFaultThatReachedNobodyIsNotObserved is the regression the whole
// oracle rests on: the manifest is intact and the simulator's own record that
// the fault was configured, installed or applied is present, and the one thing
// missing is evidence that a client was ever made to live with it. Nothing may
// be claimed about netdoc for a fault that happened to nobody: not an observed
// fault, and not a false negative.
func TestScheduledFaultThatReachedNobodyIsNotObserved(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutation GeneratedMutation
		report   Report
	}{
		{
			name:     "resolver moved to SERVFAIL that nobody queried",
			mutation: GeneratedMutation{ID: "dns.servfail", Service: "resolver"},
			report:   Report{Timeline: appliedDNSFault("resolver", DNSOutcomeSERVFAIL, 0)},
		},
		{
			name:     "resolver moved to drop that nobody queried",
			mutation: GeneratedMutation{ID: "dns.drop", Service: "resolver"},
			report:   Report{Timeline: appliedDNSFault("resolver", DNSOutcomeDrop, 0)},
		},
		{
			name:     "outage window that opened and closed empty",
			mutation: GeneratedMutation{ID: "timeline.dns_outage", Service: "resolver", StartMS: 150},
			report:   Report{Timeline: appliedDNSFault("resolver", DNSOutcomeDrop, 150*time.Millisecond)},
		},
		{
			name:     "reset service that was never dialed",
			mutation: GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 80},
			report: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "target",
				Service: "http-target", Type: ServiceTCPReset, Port: 80}}}},
		},
		{
			name:     "expired certificate nobody was shown",
			mutation: GeneratedMutation{ID: "service.tls_expired", Node: "target", Service: "web"},
			report: Report{Evidence: Evidence{TLS: []TLSEvidence{{Node: "target", Service: "web",
				CertificateMode: TLSCertificateExpired, CertificatePresented: false, Result: "no_handshake", Count: 1}}}},
		},
		{
			name:     "proxy reached and never asked to CONNECT",
			mutation: GeneratedMutation{ID: "proxy.connect_refused", Node: "proxy", Service: "socks", TargetPort: 443},
			report: Report{Evidence: Evidence{SOCKSRequests: []SOCKSEvidence{{Node: "proxy", Service: "socks",
				Event: "greeting", Result: "accepted", Count: 1}}}},
		},
		{
			name:     "drop rule installed that matched no packet",
			mutation: GeneratedMutation{ID: "quic.udp_443_block", Node: "target", TargetPort: 443},
			report: Report{Faults: []FaultInfo{{Type: FaultDrop, Node: "target", Protocol: "udp", Port: 443,
				Direction: DirectionInbound}},
				Evidence: Evidence{PacketDrops: []PacketDropEvidence{{Node: "target", Protocol: "udp", Port: 443,
					Direction: DirectionInbound, Packets: 0}}}},
		},
		{
			name:     "DoH service in invalid mode that answered nobody",
			mutation: GeneratedMutation{ID: "encrypted_dns.doh_invalid", Node: "resolver", Service: encryptedDNSProbeService},
			report: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "resolver",
				Service: encryptedDNSProbeService, Type: ServiceEncryptedDNS, Port: 443, Mode: DoHResponseInvalid}}}},
		},
		{
			name:     "HTTP service configured to 503 that answered nobody",
			mutation: GeneratedMutation{ID: "http.status_503", Node: "target", TargetPort: 80, Status: http.StatusServiceUnavailable},
			report: Report{Evidence: Evidence{ServiceStates: []ServiceStateEvidence{{Node: "target", Type: ServiceHTTP,
				Port: 80, Status: http.StatusServiceUnavailable}}}},
		},
		{
			name:     "IPv4 drop with no reachability measurement",
			mutation: GeneratedMutation{ID: "family.ipv4_drop", Node: "gateway", Family: "ipv4"},
			report:   Report{},
		},
		{
			name:     "IPv6 drop on a family the node never had",
			mutation: GeneratedMutation{ID: "family.ipv6_drop", Node: "gateway", Family: "ipv6"},
			report: Report{Topology: []NodeInfo{{Name: "client", Role: "client"}},
				Evidence: Evidence{FamilyReachability: []FamilyReachabilityEvidence{
					{Node: "client", Family: "ipv6", State: FamilyStateUnavailable}}}},
		},
		{
			name:     "link fault the kernel refused",
			mutation: GeneratedMutation{ID: "link.transient_down", Node: "gateway", Segment: "upstream"},
			report: Report{Timeline: []FaultEventEvidence{{Event: TimedEvent{Type: FaultScheduledLink,
				Node: "gateway", Segment: "upstream", State: LinkStateDown}, Result: EventFailed}}},
		},
		{
			name:     "netem qdisc that is not in force",
			mutation: GeneratedMutation{ID: "netem.loss", Node: "gateway", Segment: "upstream", LossPercent: 17, NetemSeed: 11},
			report: Report{Evidence: Evidence{PacketConditions: []PacketConditionEvidence{{Node: "gateway",
				Segment: "upstream", Active: false, LossPercent: 17, Seed: 11}}}},
		},
		{
			name: "black hole whose hop the kernel never narrowed",
			mutation: GeneratedMutation{ID: "pmtu.blackhole", Node: "gateway", Segment: "upstream",
				TargetNode: "client", MTU: minBlackholeMTU},
			report: Report{Faults: []FaultInfo{{Type: FaultPMTUBlackhole, Node: "gateway",
				Summary: "gateway carries upstream at a 576-byte MTU"}},
				Evidence: pmtuLinks(1500, 1500).Evidence},
		},
		{
			name: "preferred path failure with no path consequence",
			mutation: GeneratedMutation{ID: "routing.preferred_path_failure", Node: "preferred-gateway",
				TargetNode: "client", Segment: "preferred-upstream", Family: "ipv4"},
			report: Report{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := huntManifest(tc.mutation)
			report := tc.report
			report.Cleanup = CleanupInfo{Done: true}
			if len(report.Topology) == 0 {
				report.Topology = []NodeInfo{{Name: "client", Role: "client"}}
			}
			// A diagnosis that noticed nothing at all, so any accusation the
			// analyzer could make would be made.
			report.Tests = []TestOutcome{{Name: "netdoc", Node: "client", ProcessOutcome: ProcessExited,
				Diagnosis: oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "PASS",
					Families: &DiagnosisFamilies{IPv4: FamilyStateReachable, IPv6: FamilyStateReachable}})}}
			truth := collectObservedTruth(manifest, &report)
			if len(truth.ObservedFaults) != 0 {
				t.Fatalf("a fault that reached nobody was recorded as observed: %v", truth.ObservedFaults)
			}
			for _, finding := range analyzeHuntCase(manifest, &report, truth) {
				if finding.Category == FindingFalseNegative || finding.Category == FindingDiagnosticContradiction {
					t.Fatalf("mutation intent alone produced %s/%s", finding.Category, finding.Code)
				}
			}
		})
	}
}

// TestEveryMutationFamilyDeclaresItsHuntPath checks the production registry,
// which is the authoritative classification. A missing decision is invalid, a
// bug-oracle decision must name analyzer code that exists, and every generic
// condition must remain reachable from at least one operator.
func TestEveryMutationFamilyDeclaresItsHuntPath(t *testing.T) {
	contracts := map[huntFindingContract]bool{
		huntDNSFailureContract: true,
		huntTCPResetContract:   true,
	}
	wantContracts := map[string]huntFindingContract{
		"dns.servfail":                   huntDNSFailureContract,
		"dns.drop":                       huntDNSFailureContract,
		"timeline.dns_outage":            huntDNSFailureContract,
		"service.tcp_reset":              huntTCPResetContract,
		"service.tls_expired":            huntFindingContract(ConditionTLSCertificateExpired),
		"service.tls_hostname_mismatch":  huntFindingContract(ConditionTLSHostnameMismatch),
		"proxy.connect_refused":          huntFindingContract(ConditionProxyDestinationRefused),
		"quic.udp_443_block":             huntFindingContract(ConditionQUICUDP443Blocked),
		"routing.preferred_path_failure": huntFindingContract(ConditionPreferredRouteFailed),
		"family.ipv4_drop":               huntFindingContract(ConditionIPv4InternetUnreachable),
		"family.ipv6_drop":               huntFindingContract(ConditionIPv6InternetUnreachable),
		"routing.no_default_route":       huntFindingContract(ConditionNoDefaultRoute),
	}
	for _, rule := range conditionOracle {
		contract := huntFindingContract(rule.condition)
		if contracts[contract] {
			t.Errorf("oracle condition %q is defined more than once", rule.condition)
		}
		contracts[contract] = true
	}
	claimed := map[huntFindingContract]bool{}
	var bug, stress []string
	for _, operator := range huntMutationRegistry {
		if operator.findingContract == "" {
			t.Errorf("mutation %q has no explicit finding-contract decision", operator.id)
			continue
		}
		contract := operator.contractFor(HuntGeneratorVersion)
		want, oracleBacked := wantContracts[operator.id]
		if oracleBacked && contract != want {
			t.Errorf("mutation %q contract = %q, want %q", operator.id, contract, want)
		}
		if !oracleBacked && contract != huntNoFindingContract {
			t.Errorf("stress mutation %q unexpectedly claims contract %q", operator.id, contract)
		}
		if operator.laneFor(HuntGeneratorVersion) == HuntLaneStress {
			stress = append(stress, operator.id)
			continue
		}
		bug = append(bug, operator.id)
		if !contracts[contract] {
			t.Errorf("bug-oracle mutation %q names unknown contract %q", operator.id, contract)
		}
		claimed[contract] = true
	}
	for contract := range contracts {
		if !claimed[contract] {
			t.Errorf("finding contract %q is claimed by no mutation family", contract)
		}
	}
	wantBug := []string{"dns.servfail", "dns.drop", "timeline.dns_outage", "service.tcp_reset",
		"service.tls_expired", "proxy.connect_refused", "quic.udp_443_block", "family.ipv4_drop",
		"family.ipv6_drop", "routing.preferred_path_failure", "service.tls_hostname_mismatch",
		"routing.no_default_route"}
	wantStress := []string{"netem.loss", "netem.latency", "netem.jitter", "timeline.netem_spike",
		"encrypted_dns.doh_invalid", "http.status_503", "link.transient_down",
		"service.connection_refused", "service.tcp_port_blocked", "routing.wrong_default_route",
		"routing.missing_subnet_route", "pmtu.blackhole"}
	if !slices.Equal(bug, wantBug) {
		t.Errorf("bug-oracle operators = %v, want %v", bug, wantBug)
	}
	if !slices.Equal(stress, wantStress) {
		t.Errorf("stress operators = %v, want %v", stress, wantStress)
	}
}

// preferredRouteEvidence is what a node holder writes down on a client whose
// lower-metric default goes nowhere while the higher-metric one still carries a
// controlled target. Every field is the holder's own reading: the routing table
// came off the client's kernel and the dial was performed from inside the
// client's namespace, so nothing here can be produced by reading a diagnosis.
func preferredRouteEvidence() Evidence {
	return Evidence{
		RouteTables: []RouteTableEvidence{{Node: "client", Family: "ipv4", Routes: []KernelRoute{
			{Destination: "default", Via: "10.79.1.1", Segment: "preferred-lan", Metric: 50},
			{Destination: "default", Via: "10.79.3.1", Segment: "alternate-lan", Metric: 100},
		}}},
		ControlledTargets: []ControlledTargetEvidence{{From: "client", To: "9.9.9.9:80", Family: "ipv4",
			Via: []string{"alternate-lan", "10.79.3.1"}, Reachable: true, Outcome: FamilyStateReachable}},
	}
}

// TestPreferredRouteFailureIsEstablishedOnlyByAllThreeHalves pins the condition
// to the sentence its name makes. A preference that does not exist, a family
// that still works, and an alternate nobody reached each leave the condition
// unestablished, because each one alone would let a different fault wear this
// name: one dead route with no backup is no_default_route's story, a healthy
// family is nobody's, and two dead paths are a network that is simply down.
func TestPreferredRouteFailureIsEstablishedOnlyByAllThreeHalves(t *testing.T) {
	unreachable := ObservedTruth{IPv4: FamilyStateUnreachable}
	tied := preferredRouteEvidence()
	tied.RouteTables[0].Routes[1].Metric = 50
	single := preferredRouteEvidence()
	single.RouteTables[0].Routes = single.RouteTables[0].Routes[:1]
	unreadable := preferredRouteEvidence()
	unreadable.RouteTables = nil
	alternateDead := preferredRouteEvidence()
	alternateDead.ControlledTargets[0].Reachable = false
	otherVia := preferredRouteEvidence()
	otherVia.ControlledTargets[0].Via = []string{"preferred-lan", "10.79.1.1"}
	otherNode := preferredRouteEvidence()
	otherNode.ControlledTargets[0].From = "someone-else"
	otherFamily := preferredRouteEvidence()
	otherFamily.ControlledTargets[0].Family = "ipv6"
	for _, tc := range []struct {
		name     string
		evidence Evidence
		truth    ObservedTruth
		want     bool
	}{
		{"all three halves", preferredRouteEvidence(), unreachable, true},
		{"no strict preference between the defaults", tied, unreachable, false},
		{"only one default to prefer", single, unreachable, false},
		{"the table was never read", unreadable, unreachable, false},
		{"the family still reaches the internet", preferredRouteEvidence(), ObservedTruth{IPv4: FamilyStateReachable}, false},
		{"the family was never dialed", preferredRouteEvidence(), ObservedTruth{}, false},
		{"the alternate does not carry the target either", alternateDead, unreachable, false},
		{"the target was reached over the failed path", otherVia, unreachable, false},
		{"somebody else's dial", otherNode, unreachable, false},
		{"the alternate was proven in the other family", otherFamily, unreachable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Contains(observedConditions(observation{Evidence: tc.evidence, Truth: tc.truth, Client: "client"}),
				ConditionPreferredRouteFailed)
			if got != tc.want {
				t.Fatalf("established = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestPreferredRouteFailureAndNoDefaultRouteCannotBothBeEstablished holds the
// two route conditions apart at the evidence layer rather than by convention.
// They read the same table and disagree about it, so a run that established
// both would mean the oracle had stopped describing one network.
func TestPreferredRouteFailureAndNoDefaultRouteCannotBothBeEstablished(t *testing.T) {
	empty := preferredRouteEvidence()
	empty.RouteTables[0].Routes = nil
	for _, tc := range []struct {
		name     string
		evidence Evidence
	}{
		{"two defaults", preferredRouteEvidence()},
		{"no defaults", empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observedConditions(observation{Evidence: tc.evidence,
				Truth: ObservedTruth{IPv4: FamilyStateUnreachable}, Client: "client"})
			if slices.Contains(got, ConditionPreferredRouteFailed) && slices.Contains(got, ConditionNoDefaultRoute) {
				t.Fatalf("one routing table established both route conditions: %v", got)
			}
		})
	}
}

// Selection metadata names no causal preferred-route fault, even on a failing
// row. Only the simulator has the controlled alternate-path measurement.
func TestPreferredRouteFailureIsNotRecognizedFromSelectionMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks []DiagnosisCheck
		want   bool
	}{
		{"its own cause on a failing row", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Cause: diagnostic.RouteCausePreferredPathFailed}}, false},
		{"its own cause on a warning row", []DiagnosisCheck{{ID: "internet_tcp", Status: "WARN",
			Cause: diagnostic.RouteCausePreferredPathFailed}}, false},
		{"its own cause on a passing row", []DiagnosisCheck{{ID: "internet_tcp", Status: "PASS",
			Cause: diagnostic.RouteCausePreferredPathFailed}}, false},
		{"no default route", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Cause: diagnostic.RouteCauseNoDefaultRoute}}, false},
		{"selected path failed", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Cause: diagnostic.RouteCauseSelectedPathFailed}}, false},
		{"gateway unreachable", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Cause: diagnostic.RouteCauseGatewayUnreachable}}, false},
		{"the family is merely unreachable", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL",
			Cause: diagnostic.FamilyCauseIPv4Unreachable}}, false},
		{"a bare failing row with no cause", []DiagnosisCheck{{ID: "internet_tcp", Status: "FAIL"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Contains(recognizedConditions(oracleDiagnosis(tc.checks...)), ConditionPreferredRouteFailed)
			if got != tc.want {
				t.Fatalf("recognized = %t, want %t", got, tc.want)
			}
		})
	}
}

// TestPreferredRouteFailureMissReportsOneHighConfidenceFinding is the pair
// joined up: independent truth that the diagnosis answered with a neighbouring
// route cause is exactly the false negative a hunt exists to file, and a
// mutation that was scheduled but never manifested is not.
func TestPreferredRouteFailureMissReportsOneHighConfidenceFinding(t *testing.T) {
	truth := ObservedTruth{IPv4: FamilyStateUnreachable}
	// The family verdict is present and correct, which is what isolates the
	// accusation: netdoc did see that IPv4 lost the internet, and still named
	// the wrong route cause for why. This is the shape the live
	// two-path-ipv6-healthy run produces.
	missed := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
		Cause:    diagnostic.RouteCauseNoDefaultRoute,
		Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}}), preferredRouteEvidence())
	findings := unrecognizedConditionFindings(missed, truth)
	if len(findings) != 1 || findings[0].Expected != string(ConditionPreferredRouteFailed) ||
		findings[0].Severity != SeverityHigh || findings[0].Category != FindingFalseNegative {
		t.Fatalf("missed preferred-route failure produced %+v", findings)
	}
	named := oracleReport(oracleDiagnosis(DiagnosisCheck{ID: "internet_tcp", Status: "WARN",
		Cause:    diagnostic.RouteCausePreferredPathFailed,
		Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}}), preferredRouteEvidence())
	if got := unrecognizedConditionFindings(named, truth); len(got) != 1 || got[0].Expected != string(ConditionPreferredRouteFailed) {
		t.Fatalf("selection metadata hid the unrecognized route condition: %+v", got)
	}
	// Intent is not truth: the same diagnosis over a network where nothing was
	// observed accuses nobody, however loudly a manifest names the operator.
	if got := unrecognizedConditionFindings(oracleReport(oracleDiagnosis(
		DiagnosisCheck{ID: "internet_tcp", Status: "PASS"}), Evidence{}), ObservedTruth{}); len(got) != 0 {
		t.Fatalf("an unobserved mutation produced %+v", got)
	}
}

func TestPreferredRouteFailureRecognizesOnlyMeasuredCause(t *testing.T) {
	for _, tc := range []struct {
		row, status string
		want        bool
	}{
		{"internet_tcp", "WARN", true}, {"internet_tcp", "FAIL", true},
		{"internet_tcp", "PASS", false}, {"target_tcp", "WARN", false},
	} {
		d := oracleDiagnosis(DiagnosisCheck{ID: tc.row, Status: tc.status, Cause: diagnostic.RouteCausePreferredPathAlternateReachable})
		if got := slices.Contains(recognizedConditions(d), ConditionPreferredRouteFailed); got != tc.want {
			t.Errorf("%s/%s recognized = %v, want %v", tc.row, tc.status, got, tc.want)
		}
	}
}
