package diagnostic

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// The resolver-comparison tests for the QUIC failure in issue #105.
//
// A QUIC check that failed against an address only the system resolver
// returned has established nothing about UDP/443. It resolves its endpoint
// through the same system resolver the DNS rows found disagreeing, so the
// failure and the disputed answer are not separable from the QUIC row alone,
// and the run may say only what it saw.
//
// The comparison behind that stays over the complete answer sets. Nothing a
// run records separates a poisoned answer from ordinary anycast divergence in
// the family it uses, so narrowing the comparison to the family with working
// egress turns a healthy split-prefix answer into a warning. The last test
// here holds that shape healthy.
//
// Everything runs through the production functions, reconcileDNS and Interpret,
// over the production probe plan, because the ordering of the truth table is
// half of what is being tested here.

// egress builds the direct-egress row the way internetProbe leaves it, with the
// per-family result that row records: a completed TCP connection to that
// family's fixed reference addresses.
func egress(v4, v6 string) ProbeResult {
	return ProbeResult{Status: StatusPass, Families: &FamilyConnectivity{IPv4: v4, IPv6: v6}}
}

// genericRun settles the production generic probe plan with the rows a caller
// supplies, which includes running Finalize, and interprets it.
func genericRun(t *testing.T, given map[ProbeID]ProbeResult) (Diagnosis, map[ProbeID]ProbeResult) {
	t.Helper()
	order := planOrder(t, nil)
	res := settle(t, nil, order, given)
	return Interpret(nil, order, res), res
}

// TestQUICFailureOnADisagreeingAnswerIsNotUDPUnavailability is issue #105's
// QUIC failure. The QUIC check resolved the same name through the same system
// resolver the DNS rows found disagreeing, and tried an address only that
// resolver returned, so "UDP/443 may be filtered" is not what this run saw.
func TestQUICFailureOnADisagreeingAnswerIsNotUDPUnavailability(t *testing.T) {
	poison4, poison6 := net.ParseIP("192.0.2.123"), net.ParseIP("2001:db8::123")
	real4, real6 := net.ParseIP("142.250.9.94"), net.ParseIP("2607:f8b0:4002:c00::5e")
	d, res := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4, poison6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4, real6}, resolver: "8.8.8.8"},
		ProbeQUIC: {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{
			{IP: poison6}, {IP: poison4},
		}},
	})
	if res[ProbeDNSPublic].answerComparison != comparisonDisagree {
		t.Fatalf("answerComparison = %v, want disagree", res[ProbeDNSPublic].answerComparison)
	}
	ids := findingIDs(d)
	if slices.Contains(ids, DiagnosisQUICUnavailable) {
		t.Fatalf("findings = %v, want the resolver disagreement rather than generic QUIC unavailability (summary: %s)", ids, d.Summary)
	}
	if len(ids) == 0 || ids[0] != DiagnosisDNSDisagreement {
		t.Fatalf("findings = %v, want %q first (summary: %s)", ids, DiagnosisDNSDisagreement, d.Summary)
	}
	if d.Blamed != ProbeDNSPublic {
		t.Fatalf("blamed = %q, want %q", d.Blamed, ProbeDNSPublic)
	}
	if d.Verdict != VerdictDegraded {
		t.Fatalf("verdict = %q, want %q", d.Verdict, VerdictDegraded)
	}
	// The sentence has to carry both halves: a reader sent to the DNS rows
	// still needs to know the QUIC row is where the disagreement showed up.
	for _, want := range []string{"DNS", "UDP/443"} {
		if !strings.Contains(d.Summary, want) {
			t.Fatalf("summary = %q, want it to mention %q", d.Summary, want)
		}
	}
	// The QUIC row keeps its own observation. Nothing here rewrites what the
	// probe measured; only what the run concludes from it changes.
	if res[ProbeQUIC].Status != StatusFail || res[ProbeQUIC].Cause != QUICCauseTimeout {
		t.Fatalf("quic row = %+v, want its own failure left alone", res[ProbeQUIC])
	}
}

// The regression that matters most: an ordinary QUIC failure on a run whose
// resolvers agree must keep the diagnosis it has always had.
func TestQUICFailureWithAgreeingDNSKeepsItsDiagnosis(t *testing.T) {
	real4, real4b := net.ParseIP("142.250.9.94"), net.ParseIP("142.250.189.99")
	d, _ := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{real4}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4b}, resolver: "8.8.8.8"},
		ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{{IP: real4}}},
	})
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
	if d.Blamed != ProbeQUIC {
		t.Fatalf("blamed = %q, want %q", d.Blamed, ProbeQUIC)
	}
}

// The linkage is evidence, not an assumption about probe order: a QUIC failure
// on a run with a resolver disagreement still reports QUIC unless the run
// observed that this failure used the disputed answer. Two shapes have to keep
// the ordinary diagnosis, and each one fails a different half of the linkage.
func TestQUICFailureOnACorroboratedAddressKeepsItsDiagnosis(t *testing.T) {
	var (
		poison4 = net.ParseIP("192.0.2.123")
		real4   = net.ParseIP("198.51.100.10")
		real6   = net.ParseIP("2001:db8:1::10")
		other4  = net.ParseIP("203.0.113.10")
	)
	t.Run("the attempted address came from neither resolver", func(t *testing.T) {
		// The QUIC check made its own lookup and won an answer in neither
		// recorded answer set, so nothing observed says it used the disputed
		// one.
		d, res := genericRun(t, map[ProbeID]ProbeResult{
			ProbeInternet:  egress(FamilyReachable, FamilyReachable),
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4}, resolver: "8.8.8.8"},
			ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{{IP: other4}}},
		})
		if got := res[ProbeDNSPublic].answerComparison; got != comparisonDisagree {
			t.Fatalf("answerComparison = %v, want disagree", got)
		}
		if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
			t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
		}
	})
	t.Run("both resolvers returned the attempted address", func(t *testing.T) {
		// A recorded disagreement whose disputed answer is elsewhere in the
		// set: the address this check tried is one both resolvers gave, so the
		// failure is the ordinary one.
		//
		// The disagreement is stamped on rather than computed, because the live
		// comparison cannot reach this state: a shared address is a shared
		// prefix, and a shared prefix is agreement. Replay restores the
		// recorded outcome and the addresses separately, so an artifact can
		// carry the pair, and the clause that tells them apart has to hold.
		order := planOrder(t, nil)
		res := settle(t, nil, order, map[ProbeID]ProbeResult{
			ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4, real6}},
			ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4, real6}, resolver: "8.8.8.8"},
			ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{{IP: real6}}},
		})
		public := res[ProbeDNSPublic]
		public.Status, public.answerComparison = StatusWarn, comparisonDisagree
		res[ProbeDNSPublic] = public
		d := Interpret(nil, order, res)
		if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
			t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
		}
	})
}

// A QUIC row that never ran, or that passed, leaves the plain resolver
// disagreement exactly as it was.
func TestResolverDisagreementWithoutAQUICFailureIsUnchanged(t *testing.T) {
	poison4, real4 := net.ParseIP("192.0.2.123"), net.ParseIP("142.250.9.94")
	for _, tc := range []struct {
		name string
		quic ProbeResult
	}{
		{"QUIC works", ProbeResult{Status: StatusPass}},
		{"QUIC did not apply", ProbeResult{Status: StatusNA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := genericRun(t, map[ProbeID]ProbeResult{
				ProbeInternet:  egress(FamilyReachable, FamilyReachable),
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4}},
				ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4}, resolver: "8.8.8.8"},
				ProbeQUIC:      tc.quic,
			})
			if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisDNSDisagreement {
				t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisDNSDisagreement, d.Summary)
			}
			if !strings.Contains(d.Summary, "Online, but system DNS and public DNS disagree") {
				t.Fatalf("summary = %q, want the unchanged disagreement sentence", d.Summary)
			}
		})
	}
}

// Interception is answered before anything below it, and a disagreement read
// off intercepted rows describes the interceptor. The portal has to keep the
// headline whatever the rows under it say.
func TestCaptivePortalStillOutranksTheDisagreement(t *testing.T) {
	poison4, real4 := net.ParseIP("192.0.2.123"), net.ParseIP("142.250.9.94")
	d, _ := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  {Status: StatusFail, Portal: &Portal{RedirectURL: "http://portal.example/login"}},
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4}, resolver: "8.8.8.8"},
		ProbeQUIC:      {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{{IP: poison4}}},
	})
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisCaptivePortal {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisCaptivePortal, d.Summary)
	}
}

// A selection that leaves out the second opinion has no disagreement to reason
// from, so the QUIC failure keeps the only diagnosis the run can support.
func TestQUICFailureWithoutTheSecondOpinionKeepsItsDiagnosis(t *testing.T) {
	poison4 := net.ParseIP("192.0.2.123")
	order := planOrder(t, nil, ProbeDNSPublic)
	res := settle(t, nil, order, map[ProbeID]ProbeResult{
		ProbeInternet: egress(FamilyReachable, FamilyReachable),
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{poison4}},
		ProbeQUIC:     {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{{IP: poison4}}},
	})
	d := Interpret(nil, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
}

// In targeted mode the DNS rows are about the target while the QUIC row is
// about its own fixed endpoint, so a disagreement over the target name proves
// nothing about the addresses the QUIC check tried. The run must keep saying
// what it observed on each.
func TestTargetDisagreementDoesNotExplainAnUnrelatedQUICFailure(t *testing.T) {
	tg := mustTarget(t, "example.com")
	order := planOrder(t, tg)
	res := settle(t, tg, order, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.123")}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}, resolver: "8.8.8.8"},
		ProbeTargetTCP: {Status: StatusPass},
		ProbeQUIC: {Status: StatusFail, Cause: QUICCauseTimeout,
			Attempts: []Attempt{{IP: net.ParseIP("142.250.9.94")}}},
	})
	if res[ProbeDNSPublic].answerComparison != comparisonDisagree {
		t.Fatalf("answerComparison = %v, want disagree", res[ProbeDNSPublic].answerComparison)
	}
	d := Interpret(tg, order, res)
	if got := findingIDs(d); len(got) == 0 || got[0] != DiagnosisQUICUnavailable {
		t.Fatalf("findings = %v, want %q first (summary: %s)", got, DiagnosisQUICUnavailable, d.Summary)
	}
}

// The conclusion has to survive the artifact. Replay recomputes a diagnosis
// from a stored run with no probes, so anything the new arm reads has to be
// something a snapshot carries: the recorded comparison, and the addresses the
// QUIC row tried.
func TestTheDisagreementLinkageSurvivesASnapshotRoundTrip(t *testing.T) {
	poison4, poison6 := net.ParseIP("192.0.2.123"), net.ParseIP("2001:db8::123")
	real4, real6 := net.ParseIP("142.250.9.94"), net.ParseIP("2607:f8b0:4002:c00::5e")
	order := planOrder(t, nil)
	res := settle(t, nil, order, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4, poison6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4, real6}, resolver: "8.8.8.8"},
		ProbeQUIC: {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{
			{IP: poison6, Cause: ConnectionCauseTimeout}, {IP: poison4, Cause: ConnectionCauseTimeout},
		}},
	})
	live := Interpret(nil, order, res)
	// Guard against a vacuous pass: both sides agreeing on the wrong answer
	// would satisfy every assertion below.
	if got := findingIDs(live); len(got) == 0 || got[0] != DiagnosisDNSDisagreement {
		t.Fatalf("live findings = %v, want %q first", got, DiagnosisDNSDisagreement)
	}
	probes := ProbePlan(nil, DefaultPublicDNS, true)
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
	if replayed.Summary != live.Summary || replayed.Verdict != live.Verdict {
		t.Fatalf("replayed diagnosis = (%q, %q), want the live (%q, %q)",
			replayed.Summary, replayed.Verdict, live.Summary, live.Verdict)
	}
}

// The same conclusion from a sanitized artifact, which is the harder half. A
// support capture pseudonymizes every address, so the prefix comparison behind
// the disagreement cannot be remade from what it stores; the recorded outcome
// is. One address keeps one pseudonym across the file, so which answer the QUIC
// row tried still reads correctly, which is what the linkage is built on.
func TestTheDisagreementLinkageSurvivesSanitization(t *testing.T) {
	poison4, poison6 := net.ParseIP("192.0.2.123"), net.ParseIP("2001:db8::123")
	real4, real6 := net.ParseIP("142.250.9.94"), net.ParseIP("2607:f8b0:4002:c00::5e")
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeDNS, ProbeDNSPublic}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  egress(FamilyReachable, FamilyReachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{poison4, poison6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{real4, real6}, resolver: "8.8.8.8"},
		ProbeQUIC: {Status: StatusFail, Cause: QUICCauseTimeout, Attempts: []Attempt{
			{IP: poison6, Cause: ConnectionCauseTimeout}, {IP: poison4, Cause: ConnectionCauseTimeout},
		}},
	}
	want, artifact := sanitizedReplayInput(t, nil, order, res)
	if got := findingIDs(want); len(got) == 0 || got[0] != DiagnosisDNSDisagreement {
		t.Fatalf("live findings = %v, want %q first", got, DiagnosisDNSDisagreement)
	}
	replayed, err := ReplaySnapshot(artifact)
	if err != nil {
		t.Fatalf("replay refused a sanitized artifact this producer wrote: %v", err)
	}
	if !slices.Equal(findingIDs(replayed), findingIDs(want)) {
		t.Fatalf("replayed findings = %v, want the live %v", findingIDs(replayed), findingIDs(want))
	}
	if replayed.Blamed != want.Blamed {
		t.Fatalf("replayed blame = %q, want the live %q", replayed.Blamed, want.Blamed)
	}
}

// The shape a family-restricted comparison broke, measured on a real client
// during review: IPv4 egress only, IPv6 addresses with nowhere to go, and one
// anycast service answering both resolvers from different IPv4 prefixes while
// their AAAA answers share an allocation. Comparing only the family with
// egress calls that a disagreement and warns about a network that is working,
// so the comparison stays over everything both resolvers returned.
func TestAnycastAcrossPrefixesWithOneUsableFamilyStaysHealthy(t *testing.T) {
	var (
		system4 = net.ParseIP("198.51.100.10")
		public4 = net.ParseIP("203.0.113.10")
		system6 = net.ParseIP("2001:db8:1::10")
		public6 = net.ParseIP("2001:db8:2::20")
	)
	d, res := genericRun(t, map[ProbeID]ProbeResult{
		ProbeInternet:  egress(FamilyReachable, FamilyUnreachable),
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{system4, system6}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{public4, public6}, resolver: "8.8.8.8"},
	})
	public := res[ProbeDNSPublic]
	if public.answerComparison != comparisonAgree {
		t.Fatalf("answerComparison = %v, want agree: the AAAA answers share 2001:db8::/32 (detail: %s)",
			public.answerComparison, public.Detail)
	}
	if public.Status != StatusPass {
		t.Fatalf("public DNS status = %v, want pass (detail: %s)", public.Status, public.Detail)
	}
	if got := findingIDs(d); len(got) != 0 {
		t.Fatalf("findings = %v, want none (summary: %s)", got, d.Summary)
	}
	if d.Verdict != VerdictOK {
		t.Fatalf("verdict = %q, want %q (summary: %s)", d.Verdict, VerdictOK, d.Summary)
	}
}
