package diagnostic

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// Issue #109: the scope of a downstream unavailability claim.
//
// A protocol or endpoint check resolves through the system resolver, so a
// failure there is a failure of the addresses that resolver supplied. When the
// independent resolver answered the same name in the same family with
// addresses this run never tried, the run has observed one thing (those
// addresses did not answer) and was concluding another (the protocol, or the
// endpoint, is unavailable).
//
// The two states behind that are not separable from anything a run records: a
// rewritten record and a healthy CDN or anycast node that was not answering
// leave the same evidence under a renaming of addresses. #108 proved that, and
// nothing here tries to undo it. What changes is only how far the conclusion is
// carried, so the run reports the failure it measured without deciding which
// resolver was right.
//
// The rule never reads the resolver comparison and never touches the DNS rows,
// which is what keeps ordinary CDN divergence out of dns_disagreement, and what
// leaves the established disagreement of #105 exactly where it was.
//
// Everything runs through Interpret over the production probe plan.

// quicFailureOn is the QUIC row as the probe leaves it when nothing it tried
// answered, with the typed per-attempt cause a real row carries.
func quicFailureOn(cause string, ips ...net.IP) ProbeResult {
	r := ProbeResult{Status: StatusFail, Cause: QUICCauseTimeout}
	for _, ip := range ips {
		r.Attempts = append(r.Attempts, Attempt{IP: ip, Cause: cause})
	}
	return r
}

// targetFailureOn is the same for the endpoint row.
func targetFailureOn(cause string, ips ...net.IP) ProbeResult {
	r := ProbeResult{Status: StatusFail}
	for _, ip := range ips {
		r.Attempts = append(r.Attempts, Attempt{IP: ip, Cause: cause})
	}
	return r
}

// overclaimPhrases are the statements this diagnosis is not allowed to make.
// They are checked as prose because the overclaim in #109 reached the user as a
// sentence, and an identity check alone would pass on a reworded one.
var overclaimPhrases = []string{
	"udp/443 is unavailable",
	"udp/443 may be filtered",
	"applications can fall back",
	"is unreachable",
	"poison",
	"dns is failing",
	"dns failure",
	"public dns is right",
	"the system resolver is wrong",
}

func assertNoOverclaim(t *testing.T, summary string) {
	t.Helper()
	for _, phrase := range overclaimPhrases {
		if strings.Contains(strings.ToLower(summary), strings.ToLower(phrase)) {
			t.Errorf("summary = %q: it claims %q, which this run did not observe", summary, phrase)
		}
	}
}

// TestGenericQUICFailureOnSystemOnlyAddressesIsNotUDPUnavailability is the
// #109 reproducer as it was measured on a real client: the system resolver's
// A record was rewritten, UDP/443 to that one address was dropped, the AAAA
// answers stayed inside one allocation so the resolver comparison recorded
// agreement, and the run answered with quic_unavailable.
func TestGenericQUICFailureOnSystemOnlyAddressesIsNotUDPUnavailability(t *testing.T) {
	for _, tc := range []struct {
		name   string
		system []net.IP
		public []net.IP
		tried  net.IP
	}{
		{
			name:   "IPv4 attempted, public DNS answers elsewhere in IPv4",
			system: []net.IP{poisoned4, sharedSystem6},
			public: []net.IP{controlPublic4, sharedPublic6},
			tried:  poisoned4,
		},
		{
			name:   "IPv6 attempted, public DNS answers elsewhere in IPv6",
			system: []net.IP{shared4, poisoned6},
			public: []net.IP{shared4, controlPublic6},
			tried:  poisoned6,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, res := genericRun(t, map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: tc.system},
				ProbeDNSPublic: {Status: StatusPass, Addrs: tc.public, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, tc.tried),
			})
			// The fixture has to reach the masked state, or it is testing
			// something else: this is the run whose resolvers were compared
			// and found to agree.
			if got := res[ProbeDNSPublic].answerComparison; got != comparisonAgree {
				t.Fatalf("answer comparison = %v, want %v", got, comparisonAgree)
			}
			ids := findingIDs(d)
			if slices.Contains(ids, DiagnosisQUICUnavailable) {
				t.Errorf("findings = %v: the run concluded UDP/443 is unavailable from one failed attempt "+
					"against an address only the system resolver returned (summary: %s)", ids, d.Summary)
			}
			if slices.Contains(ids, DiagnosisDNSDisagreement) {
				t.Errorf("findings = %v: the resolvers agreed, so nothing here is a DNS disagreement "+
					"(summary: %s)", ids, d.Summary)
			}
			if len(ids) == 0 || ids[0] != DiagnosisUncorroboratedEndpointFailure {
				t.Fatalf("findings = %v, want %q first (summary: %s)", ids, DiagnosisUncorroboratedEndpointFailure, d.Summary)
			}
			if d.Blamed != ProbeQUIC {
				t.Errorf("blamed = %q, want %q: the row that failed is still where to look", d.Blamed, ProbeQUIC)
			}
			if d.Verdict != VerdictDegraded {
				t.Errorf("verdict = %q, want %q", d.Verdict, VerdictDegraded)
			}
			assertNoOverclaim(t, d.Summary)
			// The DNS rows keep the state reconcileDNS left them in. This
			// changes what the run concludes, never what it measured.
			if got := res[ProbeDNSPublic].Status; got != StatusPass {
				t.Errorf("dns_public status = %v, want %v: the comparison is untouched", got, StatusPass)
			}
			if got := res[ProbeQUIC]; got.Status != StatusFail || got.Cause != QUICCauseTimeout {
				t.Errorf("quic row = %+v, want its own failure left alone", got)
			}
		})
	}
}

// TestUncorroboratedScopeRule is the evidence rule as a table of network
// states. Each case names the finding the run may reach, and every case that
// keeps the broad conclusion is a state where the rule must not fire.
func TestUncorroboratedScopeRule(t *testing.T) {
	for _, tc := range []struct {
		name string
		// why says what the case proves, and is printed on failure.
		why    string
		given  map[ProbeID]ProbeResult
		skip   []ProbeID
		expect DiagnosisID
	}{
		{
			name: "an exactly corroborated address failed",
			why:  "both resolvers returned the address this check tried, so the failure is the ordinary one",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{shared4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{shared4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, shared4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "one corroborated failure beside an uncorroborated one",
			why:  "a corroborated address that failed is evidence about the protocol, and another attempt cannot hide it",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, shared4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, shared4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4, shared4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "every failed attempt is uncorroborated",
			why:  "nothing both resolvers named was ever tried, in either family",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, poisoned6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4, poisoned6),
			},
			// Disjoint in every family, so the resolvers are recorded as
			// disagreeing and #105 answers first. The scope rule agrees with
			// it; the established disagreement is the stronger statement.
			expect: DiagnosisDNSDisagreement,
		},
		{
			name: "several attempts, all of them uncorroborated",
			why:  "two families, nothing both resolvers named tried in either, and an untried alternative in each",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4, sharedSystem6),
			},
			expect: DiagnosisUncorroboratedEndpointFailure,
		},
		{
			// The QUIC probe resolves the connectivity host itself and dials
			// what that lookup returned, so an address missing from the DNS
			// row is a later system answer for the same name, not an address
			// of unknown origin. A name that rotates between two lookups a
			// moment apart is ordinary, and reading the rotation as "no system
			// answer was used" would reinstate the whole overclaim.
			name: "a later system lookup returned an address the DNS row never recorded",
			why:  "the QUIC row's own lookup is the system resolver, whatever the separate DNS row saw",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, net.ParseIP("203.0.113.77")),
			},
			expect: DiagnosisUncorroboratedEndpointFailure,
		},
		{
			name: "the failed row recorded no attempts",
			why:  "an inferred attempt is not an observed one",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout},
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "public DNS is unavailable",
			why:  "no second opinion means no corroboration either way, so nothing is manufactured",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusNA, Detail: "no public resolver reachable"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "public DNS answered no records",
			why:  "a negative answer names no address that was not tried",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, DNSNotFound: true, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "public DNS has no answer in the attempted family",
			why:  "the second opinion offered no alternative in the family that failed",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "system DNS recorded no answers",
			why:  "without the system answers nothing says the attempted address came from that resolver",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "only one address family is usable",
			why:  "family usability is not an input to the rule, exactly as it is not an input to the comparison",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisUncorroboratedEndpointFailure,
		},
		{
			name: "family usability is unknown",
			why:  "an egress row that tested neither family adds nothing and takes nothing away",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  {Status: StatusPass},
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			expect: DiagnosisUncorroboratedEndpointFailure,
		},
		{
			name: "a canceled attempt is not a failed one",
			why:  "an attempt the run abandoned tested nothing, so it cannot be the whole of the evidence",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC: {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{
					{IP: poisoned4, Cause: ConnectionCauseCanceled, Aborted: true},
				}},
			},
			expect: DiagnosisQUICUnavailable,
		},
		{
			name: "public DNS was not selected",
			why:  "a run without the second opinion keeps the only conclusion it can support",
			given: map[ProbeID]ProbeResult{
				ProbeInternet: egress(FamilyReachable, FamilyReachable),
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeQUIC:     quicFailureOn(ConnectionCauseTimeout, poisoned4),
			},
			skip:   []ProbeID{ProbeDNSPublic},
			expect: DiagnosisQUICUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order := planOrder(t, nil, tc.skip...)
			res := settle(t, nil, order, tc.given)
			d := Interpret(nil, order, res)
			got := findingIDs(d)
			if len(got) == 0 || got[0] != tc.expect {
				t.Fatalf("findings = %v, want %q first (%s) (summary: %s)", got, tc.expect, tc.why, d.Summary)
			}
		})
	}
}

// TestQUICPassingOrAbsentInventsNothing holds the other half of the rule: it
// needs a failure to reason from, and a resolver difference alone is not one.
func TestQUICPassingOrAbsentInventsNothing(t *testing.T) {
	given := func(quic ProbeResult) map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
			ProbeQUIC:      quic,
		}
	}
	for _, tc := range []struct {
		name string
		quic ProbeResult
	}{
		{"QUIC works", ProbeResult{Status: StatusPass}},
		{"QUIC did not apply", ProbeResult{Status: StatusNA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := genericRun(t, given(tc.quic))
			if got := findingIDs(d); len(got) != 0 {
				t.Fatalf("findings = %v, want none (summary: %s)", got, d.Summary)
			}
			if d.Verdict != VerdictOK {
				t.Fatalf("verdict = %q, want %q (summary: %s)", d.Verdict, VerdictOK, d.Summary)
			}
		})
	}
	t.Run("QUIC is not in the plan", func(t *testing.T) {
		order := planOrder(t, nil, ProbeQUIC)
		res := settle(t, nil, order, given(ProbeResult{}))
		d := Interpret(nil, order, res)
		if got := findingIDs(d); len(got) != 0 {
			t.Fatalf("findings = %v, want none (summary: %s)", got, d.Summary)
		}
	})
}

// TestTargetedModeScopesTheTargetConclusion is the same rule where the DNS
// rows and the failed connection are about one hostname: the user's target.
func TestTargetedModeScopesTheTargetConclusion(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
			resolver: "8.8.8.8"},
		ProbeTargetTCP: targetFailureOn(ConnectionCauseTimeout, poisoned4, sharedSystem6),
	})
	if got := res[ProbeDNSPublic].answerComparison; got != comparisonAgree {
		t.Fatalf("answer comparison = %v, want %v: the AAAA answers still share an allocation", got, comparisonAgree)
	}
	d := Interpret(tg, order, res)
	ids := findingIDs(d)
	if slices.Contains(ids, DiagnosisTargetUnreachable) {
		t.Errorf("findings = %v: the run called the target unreachable from attempts against addresses "+
			"only the system resolver returned (summary: %s)", ids, d.Summary)
	}
	if len(ids) == 0 || ids[0] != DiagnosisUncorroboratedEndpointFailure {
		t.Fatalf("findings = %v, want %q first (summary: %s)", ids, DiagnosisUncorroboratedEndpointFailure, d.Summary)
	}
	if d.Blamed != ProbeTargetTCP {
		t.Errorf("blamed = %q, want %q", d.Blamed, ProbeTargetTCP)
	}
	assertNoOverclaim(t, d.Summary)
}

// TestTargetedModeKeepsTheBroadConclusionWhereItIsEarned mirrors the generic
// table for the endpoint row, on the two states that matter most.
func TestTargetedModeKeepsTheBroadConclusionWhereItIsEarned(t *testing.T) {
	tg := mustTarget(t, "example.com")
	for _, tc := range []struct {
		name   string
		given  map[ProbeID]ProbeResult
		expect DiagnosisID
	}{
		{
			name: "a corroborated address failed too",
			given: map[ProbeID]ProbeResult{
				ProbeInternet: egress(FamilyReachable, FamilyReachable),
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, shared4}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, shared4},
					resolver: "8.8.8.8"},
				ProbeTargetTCP: targetFailureOn(ConnectionCauseTimeout, poisoned4, shared4),
			},
			expect: DiagnosisTargetUnreachable,
		},
		{
			name: "every attempt was refused",
			given: map[ProbeID]ProbeResult{
				ProbeInternet: egress(FamilyReachable, FamilyReachable),
				ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
					resolver: "8.8.8.8"},
				ProbeTargetTCP: func() ProbeResult {
					r := targetFailureOn(ConnectionCauseRefused, poisoned4)
					r.Cause = ConnectionCauseRefused
					return r
				}(),
			},
			// A refusal is a peer answering for that address, and the sentence
			// it produces is already scoped to the attempts that were made.
			expect: DiagnosisTCPConnectionRefused,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order := planOrder(t, tg)
			res := settle(t, tg, order, tc.given)
			d := Interpret(tg, order, res)
			if got := findingIDs(d); len(got) == 0 || got[0] != tc.expect {
				t.Fatalf("findings = %v, want %q first (summary: %s)", got, tc.expect, d.Summary)
			}
		})
	}
}

// TestGenericQUICSurvivesASystemAnswerThatRotated is the second half of #109,
// on the generic rung where the failed row resolved the name itself.
//
// The QUIC probe calls the system resolver for ConnectivityProbeHost and dials
// what came back. The DNS row is a separate lookup of that same name, and a
// rotating name answers two lookups a moment apart with different addresses,
// so the address QUIC tried can be absent from the DNS row while still being
// the system resolver's answer. Requiring membership in that row would send
// exactly this run back to the unavailability claim the issue is about: the
// only thing that changed is which of the system resolver's answers arrived
// first, and public DNS still holds an address in the same family that nothing
// here ever tried.
func TestGenericQUICSurvivesASystemAnswerThatRotated(t *testing.T) {
	var (
		earlierSystem4 = net.ParseIP("192.0.2.10")  // what the DNS row recorded
		laterSystem4   = net.ParseIP("192.0.2.200") // what the QUIC probe's own lookup returned
		public4        = net.ParseIP("198.51.100.10")
	)
	d, res := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{earlierSystem4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{public4, sharedPublic6}, resolver: "8.8.8.8"},
		ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, laterSystem4),
	})
	if containsResolvedIP(res[ProbeDNS].Addrs, laterSystem4) {
		t.Fatalf("fixture: the attempted address is in the DNS row, so this is not the rotation case")
	}
	ids := findingIDs(d)
	if slices.Contains(ids, DiagnosisQUICUnavailable) {
		t.Errorf("findings = %v: an address that rotated between two system lookups was read as having no "+
			"system origin, and the run went back to claiming UDP/443 is unavailable (summary: %s)", ids, d.Summary)
	}
	if slices.Contains(ids, DiagnosisDNSDisagreement) {
		t.Errorf("findings = %v: rotation is not a resolver disagreement (summary: %s)", ids, d.Summary)
	}
	if len(ids) == 0 || ids[0] != DiagnosisUncorroboratedEndpointFailure {
		t.Fatalf("findings = %v, want %q first (summary: %s)", ids, DiagnosisUncorroboratedEndpointFailure, d.Summary)
	}
	assertNoOverclaim(t, d.Summary)
}

// TestTargetAttemptOfUnknownOriginKeepsTheBroadConclusion is the guard on the
// other side of that. Probe-derived provenance is granted to the generic QUIC
// row because that probe resolves its own hostname; the endpoint row dials the
// addresses the system DNS row resolved, so there membership in that row is
// what says an attempt used a system answer, and an address in neither
// resolver's answers is of unknown origin. Nothing may quietly read it as one
// the system resolver gave.
func TestTargetAttemptOfUnknownOriginKeepsTheBroadConclusion(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyReachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
			resolver: "8.8.8.8"},
		ProbeTargetTCP: targetFailureOn(ConnectionCauseTimeout, net.ParseIP("203.0.113.77")),
	})
	d := Interpret(tg, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisTargetUnreachable {
		t.Fatalf("findings = %v, want %q first: the attempted address is in neither resolver's answers, so "+
			"nothing observed says the endpoint row used a system answer (summary: %s)", got, DiagnosisTargetUnreachable, d.Summary)
	}
}

// TestTargetDNSDoesNotScopeTheGenericQUICEndpoint keeps hostname provenance
// straight. In targeted mode the DNS rows are about the user's target and the
// QUIC row keeps its own fixed endpoint, so an uncorroborated target answer
// says nothing about the addresses the QUIC check tried.
func TestTargetDNSDoesNotScopeTheGenericQUICEndpoint(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyReachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
			resolver: "8.8.8.8"},
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: poisoned4},
		// The QUIC row tried an address the target's DNS rows never mention,
		// because it resolved a different name.
		ProbeQUIC: quicFailureOn(ConnectionCauseTimeout, net.ParseIP("142.250.9.94")),
	})
	d := Interpret(tg, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
}

// TestQUICAttemptsOnTheTargetsAnswersStayUnrelatedInTargetedMode is the same
// point from the other side, and the harder half: the QUIC row happened to try
// an address that is also one of the target's system-only answers. In targeted
// mode that is a coincidence between two hostnames, not evidence that the QUIC
// check used the target's disputed answer.
func TestQUICAttemptsOnTheTargetsAnswersStayUnrelatedInTargetedMode(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyReachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
			resolver: "8.8.8.8"},
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: poisoned4},
		ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, poisoned4),
	})
	d := Interpret(tg, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
}

// TestSplitDNSRemainsRepresentable holds the shape #108 asked to keep. An
// internal answer and an external one disagree over every family, so the run
// reports the difference rather than the scope of a downstream attempt.
func TestSplitDNSRemainsRepresentable(t *testing.T) {
	d, res := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("10.1.2.3")}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4}, resolver: "8.8.8.8"},
	})
	if got := res[ProbeDNSPublic].answerComparison; got != comparisonDisagree {
		t.Fatalf("answer comparison = %v, want %v", got, comparisonDisagree)
	}
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisDNSDisagreement {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisDNSDisagreement, d.Summary)
	}
	if !strings.Contains(d.Summary, "split DNS or filtering may be intentional") {
		t.Fatalf("summary = %q, want the unchanged split-DNS sentence", d.Summary)
	}
}

// TestHealthyDefaultRunStaysHealthy is the false-positive floor: the ordinary
// run, with two resolvers answering from one allocation and nothing failing.
func TestHealthyDefaultRunStaysHealthy(t *testing.T) {
	d, _ := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("142.250.9.94")}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("142.250.189.99")}, resolver: "8.8.8.8"},
	})
	if got := findingIDs(d); len(got) != 0 {
		t.Fatalf("findings = %v, want none (summary: %s)", got, d.Summary)
	}
	if d.Verdict != VerdictOK {
		t.Fatalf("verdict = %q, want %q (summary: %s)", d.Verdict, VerdictOK, d.Summary)
	}
}

// uncorroboratedRun is the #109 generic reproducer as rows, shared by the two
// persistence tests below so both prove the same state survives. attempted is
// the address the QUIC row tried, which is either one the DNS row also
// recorded or a later system answer for the same name that it did not.
func uncorroboratedRun(attempted net.IP) ([]ProbeID, map[ProbeID]ProbeResult) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeDNS, ProbeDNSPublic}
	return order, map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
		ProbeQUIC:      quicFailureOn(ConnectionCauseTimeout, attempted),
	}
}

// TestUncorroboratedScopeSurvivesASnapshotRoundTrip proves the distinction is
// made from evidence a snapshot carries: the answers of both resolvers and the
// addresses the failed row tried.
//
// Both shapes are replayed, including the rotated one, because that shape rests
// on the QUIC row having resolved its own hostname rather than on anything in
// the file. A snapshot records which check a row is, so the invariant arrives
// with the artifact and needs nothing persisted beside it.
func TestUncorroboratedScopeSurvivesASnapshotRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		attempted net.IP
	}{
		{"the attempted address is in the system DNS row", poisoned4},
		{"a later system lookup answered the QUIC probe", net.ParseIP("192.0.2.200")},
	} {
		t.Run(tc.name, func(t *testing.T) { uncorroboratedRoundTrip(t, tc.attempted) })
	}
}

func uncorroboratedRoundTrip(t *testing.T, attempted net.IP) {
	t.Helper()
	order, res := uncorroboratedRun(attempted)
	Finalize(res)
	live := Interpret(nil, order, res)
	if got := findingIDs(live); len(got) == 0 || got[0] != DiagnosisUncorroboratedEndpointFailure {
		t.Fatalf("live findings = %v, want %q first", got, DiagnosisUncorroboratedEndpointFailure)
	}
	probes := make([]Probe, len(order))
	for i, id := range order {
		probes[i] = Probe{ID: id, Name: string(id)}
	}
	data, err := snapshot.Encode(withSnapshotProvenance(BuildSnapshot(nil, probes, timedResults(res))))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	artifact, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	replayed, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatalf("replay refused an artifact this producer wrote: %v", err)
	}
	if !slices.Equal(findingIDs(replayed), findingIDs(live)) {
		t.Fatalf("replayed findings = %v, want the live %v", findingIDs(replayed), findingIDs(live))
	}
	if replayed.Summary != live.Summary || replayed.Verdict != live.Verdict || replayed.Blamed != live.Blamed {
		t.Fatalf("replayed diagnosis = (%q, %q, %q), want the live (%q, %q, %q)",
			replayed.Summary, replayed.Verdict, replayed.Blamed, live.Summary, live.Verdict, live.Blamed)
	}
}

// TestUncorroboratedScopeSurvivesSanitization is the half worth proving rather
// than assuming. A support capture pseudonymizes every address, so the rule
// cannot depend on what an address is, only on whether two rows name the same
// one. That holds because one address keeps one pseudonym across the file, and
// this test fails if it ever stops holding.
func TestUncorroboratedScopeSurvivesSanitization(t *testing.T) {
	order, res := uncorroboratedRun(poisoned4)
	want, artifact := sanitizedReplayInput(t, nil, order, res)
	if got := findingIDs(want); len(got) == 0 || got[0] != DiagnosisUncorroboratedEndpointFailure {
		t.Fatalf("live findings = %v, want %q first", got, DiagnosisUncorroboratedEndpointFailure)
	}
	// The fixture has to be pseudonymized, or this proves nothing about
	// sanitized artifacts.
	for _, check := range artifact.Checks {
		if check.ID != string(ProbeDNS) || check.Observed == nil {
			continue
		}
		if slices.Contains(check.Observed.Addresses, poisoned4.String()) {
			t.Fatal("the sanitized artifact still holds the original address, so this test is not about a redacted file")
		}
	}
	// The membership the rule reads has to have survived: the address the QUIC
	// row tried is still one of the system row's answers and none of the
	// public row's.
	var system, public, quic snapshot.Check
	for _, check := range artifact.Checks {
		switch ProbeID(check.ID) {
		case ProbeDNS:
			system = check
		case ProbeDNSPublic:
			public = check
		case ProbeQUIC:
			quic = check
		}
	}
	if quic.Observed == nil || len(quic.Observed.Attempts) == 0 {
		t.Fatal("the sanitized artifact kept no QUIC attempt to reason from")
	}
	tried := quic.Observed.Attempts[0].IP
	if system.Observed == nil || !slices.Contains(system.Observed.Addresses, tried) {
		t.Fatalf("the attempted pseudonym %q is no longer one of the system row's answers", tried)
	}
	if public.Observed != nil && slices.Contains(public.Observed.Addresses, tried) {
		t.Fatalf("the attempted pseudonym %q collided with a public answer, so membership no longer survives", tried)
	}
	replayed, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatalf("replay refused a sanitized artifact this producer wrote: %v", err)
	}
	if !slices.Equal(findingIDs(replayed), findingIDs(want)) {
		t.Fatalf("replayed findings = %v, want the live %v", findingIDs(replayed), findingIDs(want))
	}
	if replayed.Blamed != want.Blamed || replayed.Summary != want.Summary {
		t.Fatalf("replayed diagnosis = (%q, %q), want the live (%q, %q)",
			replayed.Blamed, replayed.Summary, want.Blamed, want.Summary)
	}
}
