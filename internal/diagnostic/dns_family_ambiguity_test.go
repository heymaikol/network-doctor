package diagnostic

import (
	"net"
	"slices"
	"testing"
)

// The usable-family resolver ambiguity from issue #108, made executable.
//
// #108 asks whether a run can tell a poisoned answer in the address family
// that carries traffic from ordinary CDN, anycast, or geo-DNS divergence in
// that same family. These tests answer it with observations rather than with a
// rule: they pin what the resolver comparison does today, and the last two
// prove why nothing built on the recorded evidence can separate the two.
//
// What each case asserts depends on its role, and every case states one.
//
// An invariant is behavior a fix may not change. Those are the healthy shapes
// and the genuine disagreements, and they assert the whole conclusion. A run
// whose resolvers diverge across prefixes because a CDN answered two vantage
// points differently has to stay ok, because a warning there is a false report
// about a working network. The live control in #108 is one of them, kept with
// the addresses it was measured with.
//
// A known limitation is the false negative #108 is about. Those cases assert
// the resolver evidence and the absence of a disagreement finding, and nothing
// more. What the run concludes instead is an overclaim about a downstream
// protocol rather than a contract, so it is described in the note and left
// unasserted on purpose. Freezing it here would make a sentence we already
// know to be wrong expensive to correct.
//
// Everything runs through Interpret over the production probe plan, because
// what is under test is what a run concludes, not what a helper returns.

// ambiguityRole says how a case's expectations must be read.
type ambiguityRole int

const (
	// roleInvariant marks behavior a fix may not change. Asserts the verdict
	// and the findings in full.
	roleInvariant ambiguityRole = iota
	// roleKnownLimitation marks a state #108 is about. Asserts only the
	// resolver evidence and that the run does not report the difference.
	roleKnownLimitation
)

// Addresses used across these cases. The two Google answers are the live
// healthy control recorded in #108: one name, one anycast service, two
// resolvers, two different /16 allocations and therefore two different
// routePrefix values. They are what makes "different prefix" unusable as
// evidence of anything on its own.
var (
	// The live control from #108, both legitimate Google front ends.
	controlSystem4 = net.ParseIP("172.253.124.94")
	controlPublic4 = net.ParseIP("142.251.215.131")
	// Two legitimate answers inside one allocation, which is what agreement
	// over routePrefix is meant to recognize.
	sharedSystem6 = net.ParseIP("2607:f8b0:4002:c00::5e")
	sharedPublic6 = net.ParseIP("2607:f8b0:4004:800::200e")
	// A system answer that leads nowhere, standing in for a rewritten record.
	poisoned4 = net.ParseIP("192.0.2.123")
	poisoned6 = net.ParseIP("2001:db8::123")
	// A legitimate IPv6 pair in two different allocations, the IPv6 mirror of
	// the control above.
	controlSystem6 = net.ParseIP("2600:1901:1::10")
	controlPublic6 = net.ParseIP("2a00:1450:4001::20")
	// One shared IPv4 answer, for cases where IPv6 is the family under test.
	shared4 = net.ParseIP("142.251.215.131")
)

// quicTimeoutOn is the QUIC row as the probe leaves it when the address it was
// given never answers, which is what both a rewritten record and an unhealthy
// CDN node look like from UDP/443.
func quicTimeoutOn(ips ...net.IP) ProbeResult {
	r := ProbeResult{Status: StatusFail, Cause: QUICCauseTimeout}
	for _, ip := range ips {
		r.Attempts = append(r.Attempts, Attempt{IP: ip, Cause: ConnectionCauseTimeout})
	}
	return r
}

// attemptedSystemOnlyAddress reports whether any of the named probes tried an
// address that only the system resolver returned. That attempt is the shared
// observation a rewritten record and an unhealthy CDN node both leave behind,
// and it is the fact worth asserting about a failed run here. Which diagnosis
// the run draws from it is a separate question these tests do not settle.
func attemptedSystemOnlyAddress(res map[ProbeID]ProbeResult, probes ...ProbeID) bool {
	system, public := res[ProbeDNS], res[ProbeDNSPublic]
	for _, id := range probes {
		for _, attempt := range res[id].Attempts {
			if containsResolvedIP(system.Addrs, attempt.IP) && !containsResolvedIP(public.Addrs, attempt.IP) {
				return true
			}
		}
	}
	return false
}

// TestUsableFamilyResolverEvidence is the scenario matrix #108 asks for. Each
// case is a network state, not a code path.
func TestUsableFamilyResolverEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		role ambiguityRole
		// note says what the role means for this case, and is printed on
		// failure so a future change reads its own intent.
		note       string
		given      map[ProbeID]ProbeResult
		comparison answerComparison
		public     Status
		// verdict and findings are read only for roleInvariant.
		verdict  string
		findings []DiagnosisID
	}{
		{
			// #108's headline case. IPv4 is the only family that can carry
			// traffic and its answers are disjoint, but the IPv6 answers the
			// host cannot use share an allocation, and one shared prefix
			// anywhere in the pool is what the comparison asks for. The run
			// records agreement, and then explains the failed handshake with a
			// statement about UDP/443 that it has no evidence for.
			name: "poisoned IPv4 with usable IPv4 and unusable IPv6",
			role: roleKnownLimitation,
			note: "a fix records something other than plain agreement here; what the run currently says " +
				"about UDP/443 instead is an overclaim and is not asserted",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicTimeoutOn(poisoned4),
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// The mirror, which has to be stated separately: nothing in the
			// comparison is written per family, so the symmetry is a claim
			// about the code rather than something it is built from.
			name: "poisoned IPv6 with usable IPv6 and unusable IPv4",
			role: roleKnownLimitation,
			note: "the IPv6 mirror of the case above, and it has to fail the same way",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyUnreachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{shared4, poisoned6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{shared4, controlPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicTimeoutOn(poisoned6),
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// The masking is not a property of family usability at all. Both
			// families carry traffic here and the false negative is the same,
			// because the comparison never consults reachability.
			name: "poisoned IPv4 with both families usable",
			role: roleKnownLimitation,
			note: "the mask is the shared prefix, not the unusable family",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicTimeoutOn(poisoned4),
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// An egress row that tested neither family leaves usability
			// unknown, and the comparison is unchanged, which is the same
			// point from the other side.
			name: "poisoned IPv4 with family usability unknown",
			role: roleKnownLimitation,
			note: "family usability is not an input to the comparison",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  {Status: StatusPass},
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      quicTimeoutOn(poisoned4),
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// A poisoned usable family that nothing downstream tried. There is
			// no failed connection anywhere in the run, so no observation
			// distinguishes this from a healthy network at all.
			name: "poisoned IPv4 that no downstream probe failed against",
			role: roleKnownLimitation,
			note: "with no downstream failure there is no evidence to reason from",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      {Status: StatusPass},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// The same state with QUIC not applicable, which is what a host
			// with UDP/443 unavailable to the probe looks like. Any rule that
			// needs a QUIC failure has nothing here either.
			name: "poisoned IPv4 with QUIC not applicable",
			role: roleKnownLimitation,
			note: "the conclusion must not depend on QUIC being selected",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
				ProbeQUIC:      {Status: StatusNA},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
		},
		{
			// The live control from #108, and the reason the family-restricted
			// comparison was rejected. Two legitimate Google front ends in
			// different /16 allocations, on a host with no IPv6 egress.
			// Comparing only the family with egress warns about this network.
			name: "legitimate IPv4 anycast divergence with unusable IPv6",
			role: roleInvariant,
			note: "the live healthy control from #108 stays ok",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{controlSystem4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			name: "legitimate IPv6 anycast divergence with unusable IPv4",
			role: roleInvariant,
			note: "the IPv6 mirror of the healthy control stays ok",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyUnreachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{shared4, controlSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{shared4, controlPublic6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			// A resolver that answers only in the family the host cannot use
			// is ordinary: v4-only and v6-only deployments, and resolvers that
			// filter AAAA, both produce it. The overlap that remains is real.
			name: "system resolver answers only in the unusable family",
			role: roleInvariant,
			note: "a missing answer in one family is not a disagreement",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			name: "public resolver answers only in the unusable family",
			role: roleInvariant,
			note: "the same, from the second opinion's side",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{controlSystem4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{sharedPublic6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			// Ordinary split DNS: the system resolver answers from inside the
			// network and the public one from outside. It stays a warning
			// whose sentence says the difference may be intentional, which is
			// the representation #108 asks to keep.
			name: "ordinary split DNS",
			role: roleInvariant,
			note: "split DNS stays a representable warning, never an error",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("10.1.2.3")}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4}, resolver: "8.8.8.8"},
			},
			comparison: comparisonDisagree,
			public:     StatusWarn,
			verdict:    VerdictDegraded,
			findings:   []DiagnosisID{DiagnosisDNSDisagreement},
		},
		{
			name: "both resolvers return the same answers",
			role: roleInvariant,
			note: "identical answers are agreement",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{controlSystem4, sharedSystem6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlSystem4, sharedSystem6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			// The default healthy run, which is what most of the false
			// positive risk is measured against.
			name: "healthy run with agreeing answers in one allocation",
			role: roleInvariant,
			note: "the ordinary healthy default",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("142.250.9.94")}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("142.250.189.99")}, resolver: "8.8.8.8"},
			},
			comparison: comparisonAgree,
			public:     StatusPass,
			verdict:    VerdictOK,
		},
		{
			// A real disagreement with no family to hide behind: every family
			// both resolvers answered in is disjoint. This is the case the
			// current comparison was built for and it still works.
			name: "disagreement in every family",
			role: roleInvariant,
			note: "a whole-pool disagreement keeps its warning",
			given: map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, poisoned6}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
			},
			comparison: comparisonDisagree,
			public:     StatusWarn,
			verdict:    VerdictDegraded,
			findings:   []DiagnosisID{DiagnosisDNSDisagreement},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, res := genericRun(t, tc.given)
			public := res[ProbeDNSPublic]
			if public.answerComparison != tc.comparison {
				t.Errorf("answer comparison = %v, want %v (%s) (detail: %s)",
					public.answerComparison, tc.comparison, tc.note, public.Detail)
			}
			if public.Status != tc.public {
				t.Errorf("dns_public status = %v, want %v (%s) (detail: %s)",
					public.Status, tc.public, tc.note, public.Detail)
			}
			switch tc.role {
			case roleInvariant:
				if d.Verdict != tc.verdict {
					t.Errorf("verdict = %q, want %q (%s) (summary: %s)", d.Verdict, tc.verdict, tc.note, d.Summary)
				}
				if got := findingIDs(d); !slices.Equal(got, tc.findings) {
					t.Errorf("findings = %v, want %v (%s) (summary: %s)", got, tc.findings, tc.note, d.Summary)
				}
			case roleKnownLimitation:
				// Only the absent disagreement is asserted. The rest of the
				// conclusion is what #108 leaves wrong, and pinning it would
				// make correcting it a test change first.
				if got := findingIDs(d); slices.Contains(got, DiagnosisDNSDisagreement) {
					t.Errorf("findings = %v: the run now reports the resolver difference, so this is no longer "+
						"a known limitation (%s) (summary: %s)", got, tc.note, d.Summary)
				}
			}
		})
	}
}

// TestQUICAbsentFromThePlanLeavesTheComparisonAlone covers the case where the
// QUIC row does not exist rather than failing or being skipped. The resolver
// comparison is made from the DNS rows alone and owes nothing to the plan, so
// removing the probe adds no information about the answers.
func TestQUICAbsentFromThePlanLeavesTheComparisonAlone(t *testing.T) {
	order := planOrder(t, nil, ProbeQUIC)
	res := settle(t, nil, order, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
	})
	if got := res[ProbeDNSPublic].answerComparison; got != comparisonAgree {
		t.Fatalf("answer comparison = %v, want %v with no QUIC row in the plan", got, comparisonAgree)
	}
	if got := findingIDs(Interpret(nil, order, res)); slices.Contains(got, DiagnosisDNSDisagreement) {
		t.Fatalf("findings = %v: the disputed answers are reported without a QUIC row, so #108 may be addressed", got)
	}
}

// TestTargetedModeCarriesTheSameUsableFamilyAmbiguity moves the same state to
// targeted mode, where the DNS rows are about the target and the connection
// that used their answers is the target probe rather than the QUIC row.
//
// The evidence differs between the two modes, so the case is stated for both.
// The assertions stay on the resolver comparison and on the observation the
// run actually holds, which is a failed attempt against an address the second
// opinion never returned. What targeted mode concludes from that failure is
// the same overclaim in a different sentence, so it is not pinned here.
func TestTargetedModeCarriesTheSameUsableFamilyAmbiguity(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6},
			resolver: "8.8.8.8"},
		ProbeTargetTCP: {Status: StatusFail, Attempts: []Attempt{
			{IP: poisoned4, Cause: ConnectionCauseTimeout},
			{IP: sharedSystem6, Cause: ConnectionCauseUnreachable},
		}},
	})
	if got := res[ProbeDNSPublic].answerComparison; got != comparisonAgree {
		t.Fatalf("answer comparison = %v, want %v: the AAAA answers still share an allocation", got, comparisonAgree)
	}
	if !attemptedSystemOnlyAddress(res, ProbeTargetTCP) {
		t.Fatal("the target connection did not try an address only the system resolver returned, " +
			"so this fixture no longer states the case")
	}
	if got := findingIDs(Interpret(tg, order, res)); slices.Contains(got, DiagnosisDNSDisagreement) {
		t.Fatalf("findings = %v: targeted mode now reports the resolver difference, so #108 may be addressed", got)
	}
}

// TestPoisonedAndHealthyDivergenceAreIndistinguishable is the finding #108
// turns on, and the reason this file records observations rather than a rule.
//
// The two runs below differ in exactly one way: the IPv4 address the system
// resolver returned. In the first it leads nowhere because the record was
// rewritten. In the second it is a legitimate front end of the same anycast
// service whose node was not answering at that moment. Everything a run
// records is otherwise the same shape: the same answer counts, the same
// families, the same disjoint IPv4 prefixes, the same shared IPv6 allocation,
// and the same timed-out attempt against the address only the system resolver
// returned.
//
// Because the two states are the same evidence under a renaming of addresses,
// and Network Doctor holds no map from an address to who was allocated it, no
// function of that evidence can answer differently for them. Telling them apart
// needs an RIR, BGP, or ownership source, which a probe that must stay offline
// and time-bounded cannot consult, and provider ranges are not something to
// hard-code. So a rule that reports the first as a resolver fault reports the
// second the same way, and the second is a healthy network.
//
// What is asserted is that the two conclusions match, never that either one is
// right. The conclusion they share is an overclaim about UDP/443, and it stays
// free to change as long as it changes for both.
//
// This test fails if the two states ever stop matching, which is the signal
// that a discriminator has become available and #108 can be reconsidered.
func TestPoisonedAndHealthyDivergenceAreIndistinguishable(t *testing.T) {
	run := func(system4 net.IP) (Diagnosis, map[ProbeID]ProbeResult) {
		return genericRun(t, map[ProbeID]ProbeResult{
			ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{system4, sharedSystem6}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
			ProbeQUIC:      quicTimeoutOn(system4),
		})
	}
	// A rewritten record that leads nowhere.
	poisonedDiagnosis, poisonedRes := run(poisoned4)
	// A legitimate answer from the same service, whose node did not answer.
	healthyDiagnosis, healthyRes := run(controlSystem4)
	poisonedPublic, healthyPublic := poisonedRes[ProbeDNSPublic], healthyRes[ProbeDNSPublic]

	if poisonedPublic.answerComparison != healthyPublic.answerComparison {
		t.Fatalf("answer comparison differs: poisoned %v, healthy %v",
			poisonedPublic.answerComparison, healthyPublic.answerComparison)
	}
	if poisonedPublic.Status != healthyPublic.Status {
		t.Fatalf("dns_public status differs: poisoned %v, healthy %v", poisonedPublic.Status, healthyPublic.Status)
	}
	if !slices.Equal(findingIDs(poisonedDiagnosis), findingIDs(healthyDiagnosis)) {
		t.Fatalf("findings differ: poisoned %v, healthy %v",
			findingIDs(poisonedDiagnosis), findingIDs(healthyDiagnosis))
	}
	if poisonedDiagnosis.Verdict != healthyDiagnosis.Verdict ||
		poisonedDiagnosis.Summary != healthyDiagnosis.Summary ||
		poisonedDiagnosis.Blamed != healthyDiagnosis.Blamed {
		t.Fatalf("diagnosis differs: poisoned (%q, %q, %q), healthy (%q, %q, %q)",
			poisonedDiagnosis.Verdict, poisonedDiagnosis.Blamed, poisonedDiagnosis.Summary,
			healthyDiagnosis.Verdict, healthyDiagnosis.Blamed, healthyDiagnosis.Summary)
	}
	// Guard against a vacuous pass. Both runs have to reach the state the
	// comparison is about, and both have to hold the observation the two
	// states share, rather than match by having recorded nothing.
	if poisonedPublic.answerComparison != comparisonAgree {
		t.Fatalf("answer comparison = %v, want %v: the pair has to reach the masked state",
			poisonedPublic.answerComparison, comparisonAgree)
	}
	for _, c := range []struct {
		name string
		res  map[ProbeID]ProbeResult
	}{{"poisoned", poisonedRes}, {"healthy", healthyRes}} {
		if !attemptedSystemOnlyAddress(c.res, ProbeQUIC) {
			t.Fatalf("the %s run holds no failed attempt against an address only the system resolver "+
				"returned, so the pair no longer states the case", c.name)
		}
	}
}

// TestUnusableFamilyAgreementIsWhatMasksTheDisagreement isolates the mechanism,
// so a future fix has the cause pinned and not only the symptom. The masking is
// the shared IPv6 allocation: remove it and the same IPv4 answers are reported
// as the disagreement they are.
func TestUnusableFamilyAgreementIsWhatMasksTheDisagreement(t *testing.T) {
	// With the shared IPv6 answers present, the disjoint IPv4 answers are not
	// what the comparison reports.
	_, masked := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4, sharedSystem6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4, sharedPublic6}, resolver: "8.8.8.8"},
	})
	if got := masked[ProbeDNSPublic].answerComparison; got != comparisonAgree {
		t.Fatalf("answer comparison = %v, want %v while the IPv6 answers overlap", got, comparisonAgree)
	}
	// The same IPv4 answers with no IPv6 answers at all.
	_, bare := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poisoned4}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4}, resolver: "8.8.8.8"},
	})
	if got := bare[ProbeDNSPublic].answerComparison; got != comparisonDisagree {
		t.Fatalf("answer comparison = %v, want %v once the overlapping family is gone", got, comparisonDisagree)
	}
	// And the healthy control takes the identical path, which is why the
	// overlap cannot simply be dropped: the same removal turns a working
	// network into a warning.
	_, control := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{controlSystem4}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{controlPublic4}, resolver: "8.8.8.8"},
	})
	if got := control[ProbeDNSPublic].answerComparison; got != comparisonDisagree {
		t.Fatalf("answer comparison = %v, want %v: the healthy control is the same shape, which is the whole problem",
			got, comparisonDisagree)
	}
}
