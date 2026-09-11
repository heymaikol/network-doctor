package diagnostic

import (
	"go/ast"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// confidenceOf runs one matrix case and returns the primary finding's
// confidence, failing the test when the case produces no finding at all.
func confidenceOf(t *testing.T, name string) Confidence {
	t.Helper()
	c := matrixCaseNamed(t, name)
	d := Interpret(c.target, c.order, c.res)
	if len(d.Findings) == 0 {
		t.Fatalf("case %q produced no finding", name)
	}
	return d.Findings[0].Confidence
}

// TestConfidenceOfRepresentativeFindings pins one run per level against the
// current truth table, choosing the arms where the reason for the level is the
// point rather than an accident of the fixture.
func TestConfidenceOfRepresentativeFindings(t *testing.T) {
	tests := []struct {
		matrixCase string
		want       Confidence
		why        string
	}{
		{
			matrixCase: "generic captive portal", want: ConfidenceHigh,
			why: "the egress probe observed the interception itself, and nothing else explains a portal redirect",
		},
		{
			matrixCase: "target refuses the connection", want: ConfidenceHigh,
			why: "a peer sent a refusal, which is a packet rather than an inference, and both silence explanations are ruled out",
		},
		{
			matrixCase: "generic name has no records", want: ConfidenceHigh,
			why: "two independent resolvers were asked the same question and agreed, which is the differential observation itself",
		},
		{
			matrixCase: "TLS expiry explained by a fast clock", want: ConfidenceHigh,
			why: "an independently measured offset points the same way as the certificate rejection",
		},
		{
			matrixCase: "target reachable over IPv4 only", want: ConfidenceHigh,
			why: "the measured family contrast is specific, without claiming why IPv6 failed",
		},
		{
			matrixCase: "target reachable over IPv6 only", want: ConfidenceHigh,
			why: "the measured family contrast is specific, without claiming why IPv4 failed",
		},
		{
			matrixCase: "one target address fails before another succeeds", want: ConfidenceHigh,
			why: "individual attempts establish partial reachability without blaming a server or path",
		},
		{
			matrixCase: "generic system resolver failing", want: ConfidenceMedium,
			why: "one query each, at one moment, does not separate a resolver that is broken from a name whose own servers were briefly failing for everyone",
		},
		{
			matrixCase: "path MTU black hole", want: ConfidenceMedium,
			why: "two stalls that correlate are evidence for a black hole and equally consistent with a slow server, which is why the identity says probable",
		},
		{
			matrixCase: "generic resolvers disagree", want: ConfidenceMedium,
			why: "a difference between resolvers is as often a deliberate split as a fault, and no observation here separates the two",
		},
		{
			matrixCase: "local device silent while this machine works", want: ConfidenceLow,
			why: "a silent device is powered off, moved, or filtering, and none of those is distinguishable from this machine",
		},
		{
			matrixCase: "targeted DNS failure", want: ConfidenceLow,
			why: "resolution failed with no second opinion to separate a broken resolver from a name that does not exist",
		},
		{
			matrixCase: "TLS handshake failure", want: ConfidenceLow,
			why: "the handshake failed with no cause the client could classify, so a bad certificate, a wrong clock and interception all remain",
		},
		{
			matrixCase: "target unreachable with egress unchecked", want: ConfidenceInsufficientEvidence,
			why: "the finding's own meaning is that the observation separating a local path problem from a remote one was never made",
		},
		{
			matrixCase: "selected service check failed", want: ConfidenceInsufficientEvidence,
			why: "a selection removed the rungs that would have explained the failure, so there is no causal claim to be confident about",
		},
	}
	for _, test := range tests {
		t.Run(test.matrixCase, func(t *testing.T) {
			if got := confidenceOf(t, test.matrixCase); got != test.want {
				t.Errorf("confidence = %q, want %q: %s", got, test.want, test.why)
			}
		})
	}
}

// TestEveryCompletedFindingHasValidConfidence holds the two halves of the
// contract at once: a finished finding always carries one of the four values,
// and a run that reached no finding invents nothing to be confident about.
func TestEveryCompletedFindingHasValidConfidence(t *testing.T) {
	valid := map[Confidence]bool{
		ConfidenceHigh: true, ConfidenceMedium: true,
		ConfidenceLow: true, ConfidenceInsufficientEvidence: true,
	}
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			if d.Verdict == VerdictIncomplete && len(d.Findings) > 0 {
				t.Fatalf("an unfinished run produced findings: %+v", d.Findings)
			}
			for _, f := range d.Findings {
				if !valid[f.Confidence] {
					t.Errorf("finding %q has confidence %q, which is outside the vocabulary", f.ID, f.Confidence)
				}
			}
		})
	}
}

// TestConfidenceIsDeterministic reads the same run repeatedly. Confidence is
// meant to be measured against the field corpus later, and a value that moves
// between identical interpretations could not be calibrated against anything.
func TestConfidenceIsDeterministic(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		first := Interpret(c.target, c.order, c.res)
		for range 5 {
			again := Interpret(c.target, c.order, c.res)
			if len(again.Findings) != len(first.Findings) {
				t.Fatalf("case %q returned a different number of findings", c.name)
			}
			for i, f := range again.Findings {
				if f.Confidence != first.Findings[i].Confidence {
					t.Errorf("case %q finding %q: confidence %q then %q", c.name, f.ID, first.Findings[i].Confidence, f.Confidence)
				}
			}
		}
	}
}

// TestConfidenceIsDescriptiveOnly is the invariant that makes the field safe to
// add. Remediate is the only exported function that takes a whole Diagnosis, so
// it is the one that could quietly start branching on strength of evidence:
// forcing every level in turn onto the same findings must not move its answer.
// The matrix test beside this one already pins the identity, sentence, verdict
// and blamed row of every arm, so those cannot have moved either.
func TestConfidenceIsDescriptiveOnly(t *testing.T) {
	levels := []Confidence{"", ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceInsufficientEvidence}
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			d := Interpret(c.target, c.order, c.res)
			if len(d.Findings) == 0 {
				return
			}
			base, baseOK := Remediate(d, c.res, "linux")
			for _, level := range levels {
				forced := d
				forced.Findings = append([]DiagnosisFinding(nil), d.Findings...)
				for i := range forced.Findings {
					forced.Findings[i].Confidence = level
				}
				got, ok := Remediate(forced, c.res, "linux")
				if ok != baseOK || !reflect.DeepEqual(got, base) {
					t.Errorf("remediation moved when confidence was forced to %q: %+v/%v, want %+v/%v",
						level, got, ok, base, baseOK)
				}
			}
		})
	}
}

// TestMaterialContradictionPreventsHighConfidence states the contradiction rule
// on its own. A contradiction in this model weakens a named alternative without
// excluding it, so that alternative is still standing; the same evidence with
// the alternative ruled out instead is what earns the strongest claim.
func TestMaterialContradictionPreventsHighConfidence(t *testing.T) {
	base := DiagnosisFinding{
		ID:    DiagnosisTCPConnectionRefused,
		Focus: ProbeTargetTCP,
		Evidence: []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationCause},
			{Kind: EvidenceRuledOut, Check: ProbeInternet, Observation: ObservationStatusPass, Candidate: DiagnosisLocalEgressFailure},
		},
	}
	if got := confidenceFor(base); got != ConfidenceHigh {
		t.Fatalf("observed conclusion with a finished differential = %q, want %q", got, ConfidenceHigh)
	}

	contradicted := base
	contradicted.Evidence = append(append([]CausalEvidence(nil), base.Evidence...),
		CausalEvidence{Kind: EvidenceContradiction, Check: ProbeInternet, Observation: ObservationStatusPass, Candidate: DiagnosisTargetUnreachable})
	if got := confidenceFor(contradicted); got != ConfidenceMedium {
		t.Errorf("surviving alternative = %q, want %q", got, ConfidenceMedium)
	}

	// The same candidate excluded elsewhere in the list settles it, which is
	// the difference between an alternative that is merely weakened and one
	// that is gone.
	resolved := contradicted
	resolved.Evidence = append(append([]CausalEvidence(nil), contradicted.Evidence...),
		CausalEvidence{Kind: EvidenceRuledOut, Check: ProbeTargetTCP, Observation: ObservationCause, Candidate: DiagnosisTargetUnreachable})
	if got := confidenceFor(resolved); got != ConfidenceHigh {
		t.Errorf("excluded alternative = %q, want %q", got, ConfidenceHigh)
	}

	// Repetition is not strength. Three copies of the same finished differential
	// say exactly what one of them said.
	repeated := base
	for range 3 {
		repeated.Evidence = append(repeated.Evidence, base.Evidence[1])
	}
	if got := confidenceFor(repeated); got != ConfidenceHigh {
		t.Errorf("repeated evidence = %q, want %q", got, ConfidenceHigh)
	}
}

// TestCertificateDateFindingsNeedTheClockRuledOut is the rule mustRuleOut
// exists for. A certificate-date rejection is measured against this machine's
// own clock, so it is the same rejection whether the certificate expired or the
// clock ran ahead, and netdoc has a separate identity for the second. The truth
// table only separates them when the egress probe took a reading, and a run
// with no reading has not looked: it must not read the same as one that looked
// and settled it.
func TestCertificateDateFindingsNeedTheClockRuledOut(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	// The clock reading comes from the egress probe, and TLS does not depend on
	// it, so --check tls or --skip internet_tcp produces exactly this run.
	unchecked := []ProbeID{ProbeIface, ProbeDNS, ProbeTargetTCP, ProbeTLS}
	measured := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS}
	for _, cause := range []string{TLSCauseCertificateExpired, TLSCauseCertificateNotYet} {
		t.Run(cause, func(t *testing.T) {
			base := map[ProbeID]ProbeResult{
				ProbeIface: {Status: StatusPass}, ProbeDNS: {Status: StatusPass},
				ProbeTargetTCP: {Status: StatusPass}, ProbeTLS: {Status: StatusFail, Cause: cause},
			}
			blind := Interpret(target, unchecked, base)
			if got := blind.Findings[0].Confidence; got != ConfidenceMedium {
				t.Errorf("no clock reading in the run = %q, want %q: the alternative was never looked at",
					got, ConfidenceMedium)
			}

			// The same rejection with an offset that runs the wrong way to have
			// caused it. Now the run has looked, and the identity is earned.
			withClock := map[ProbeID]ProbeResult{ProbeInternet: {Status: StatusPass, clockOffset: skewAgainst(cause)}}
			for id, r := range base {
				withClock[id] = r
			}
			looked := Interpret(target, measured, withClock)
			if looked.Findings[0].ID != blind.Findings[0].ID {
				t.Fatalf("the clock reading changed the identity to %q", looked.Findings[0].ID)
			}
			if got := looked.Findings[0].Confidence; got != ConfidenceHigh {
				t.Errorf("clock measured and excluded = %q, want %q", got, ConfidenceHigh)
			}
		})
	}
}

// skewAgainst is an offset large enough to act on that points away from the
// rejection, which is what takes the clock off the list of explanations.
func skewAgainst(cause string) time.Duration {
	if cause == TLSCauseCertificateExpired {
		return -2 * time.Hour
	}
	return 2 * time.Hour
}

// TestConfidenceDoesNotDependOnWhichPassBuiltTheFinding is the invariant the
// evidence rules cannot supply on their own. Both rules read what a branch
// wrote down, so a branch that records nothing about an alternative reads as
// settled, and the counterfactual pass records less than the truth table does.
// The same identity, on the same observations, must not be more confident for
// having been assembled by the shorter path.
func TestConfidenceDoesNotDependOnWhichPassBuiltTheFinding(t *testing.T) {
	target := &Target{Host: "example.com", Port: 9000}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP}
	// One question, two resolvers, answers in different blocks: the comparison
	// both passes are about. The outcome is the one the run recorded, so this
	// reads the same live and replayed.
	resolvers := map[ProbeID]ProbeResult{
		ProbeDNS: {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
		ProbeDNSPublic: {Status: StatusWarn, Addrs: []net.IP{net.ParseIP("198.51.100.1")},
			answerComparison: comparisonDisagree},
	}
	// A working target leaves the truth table free to reach the resolver
	// comparison itself.
	fromTable := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("192.0.2.1")},
	}
	// A silent target is decided ahead of it, so here the same comparison
	// arrives only as a counterfactual finding appended afterwards.
	fromCounterfactual := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusFail, Cause: ConnectionCauseTimeout},
	}
	confidence := func(res map[ProbeID]ProbeResult) Confidence {
		t.Helper()
		for id, r := range resolvers {
			res[id] = r
		}
		for _, f := range Interpret(target, order, res).Findings {
			if f.ID == DiagnosisDNSDisagreement {
				return f.Confidence
			}
		}
		t.Fatalf("run produced no %s finding", DiagnosisDNSDisagreement)
		return ""
	}
	table, counterfactual := confidence(fromTable), confidence(fromCounterfactual)
	if table != counterfactual {
		t.Errorf("%s = %q from the truth table but %q from the counterfactual pass",
			DiagnosisDNSDisagreement, table, counterfactual)
	}
	if table != ConfidenceMedium {
		t.Errorf("%s = %q, want %q", DiagnosisDNSDisagreement, table, ConfidenceMedium)
	}
}

// TestNotEvaluatedIsReadByReason is the other half of the evidence rule, and
// the one that is easy to get crudely wrong: a check skipped behind the very
// failure being diagnosed is a consequence of the conclusion, and treating it
// as a gap would lower confidence precisely because the diagnosis was right.
func TestNotEvaluatedIsReadByReason(t *testing.T) {
	base := DiagnosisFinding{
		ID:    DiagnosisDNSNameNotFound,
		Focus: ProbeDNS,
		Evidence: []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeDNS, Observation: ObservationDNSNotFound},
			{Kind: EvidenceRuledOut, Check: ProbeDNSPublic, Observation: ObservationDNSNotFound, Candidate: DiagnosisSystemDNSFailure},
		},
	}
	consequences := []NotEvaluatedReason{NotEvaluatedPrerequisite, NotEvaluatedNotApplicable}
	for _, reason := range consequences {
		f := base
		f.Evidence = append(append([]CausalEvidence(nil), base.Evidence...),
			CausalEvidence{Kind: EvidenceNotEvaluated, Check: ProbeTargetTCP, Reason: reason})
		if got := confidenceFor(f); got != ConfidenceHigh {
			t.Errorf("downstream %s lowered confidence to %q", reason, got)
		}
	}
	gaps := []NotEvaluatedReason{NotEvaluatedNotSelected, NotEvaluatedIncomplete}
	for _, reason := range gaps {
		f := base
		f.Evidence = append(append([]CausalEvidence(nil), base.Evidence...),
			CausalEvidence{Kind: EvidenceNotEvaluated, Check: ProbeInternet, Reason: reason})
		if got := confidenceFor(f); got != ConfidenceMedium {
			t.Errorf("missing observation %s left confidence at %q, want %q", reason, got, ConfidenceMedium)
		}
	}
}

// TestSkippedDownstreamRungsKeepDNSConfidence is the same rule read off a real
// run rather than a hand-built finding: a DNS conclusion with the whole target
// path skipped behind it must not be punished for the skips it caused.
func TestSkippedDownstreamRungsKeepDNSConfidence(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSPublic, ProbeTargetTCP, ProbeTLS}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  {Status: StatusPass},
		ProbeDNS:       {Status: StatusFail, DNSNotFound: true},
		ProbeDNSPublic: {Status: StatusPass, DNSNotFound: true},
		ProbeTargetTCP: SkipPrereq(ProbeTargetTCP),
		ProbeTLS:       SkipPrereq(ProbeTLS),
	}
	d := Interpret(target, order, res)
	if len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisDNSNameNotFound {
		t.Fatalf("diagnosis = %+v", d)
	}
	finding := d.Findings[0]
	skipped := false
	for _, e := range finding.Evidence {
		if e.Kind == EvidenceNotEvaluated && e.Reason == NotEvaluatedPrerequisite {
			skipped = true
		}
	}
	if !skipped {
		t.Fatal("fixture no longer carries a prerequisite-blocked check, so it cannot test this rule")
	}
	if finding.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want %q: the skipped rungs are consequences of the DNS answer, not gaps in it",
			finding.Confidence, ConfidenceHigh)
	}
}

// TestUnresolvedFindingsAreNeverConfident guards the trap the vocabulary
// invites: netdoc can be entirely certain that it did not test something, and
// that certainty is not evidence for a cause.
func TestUnresolvedFindingsAreNeverConfident(t *testing.T) {
	for _, id := range []DiagnosisID{
		DiagnosisReachabilityUntested,
		DiagnosisSelectedDNSCheckFailed,
		DiagnosisSelectedServiceCheckFailed,
		DiagnosisSelectedNetworkCheckFailed,
	} {
		f := DiagnosisFinding{ID: id, Evidence: []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationStatusFail},
			{Kind: EvidenceRuledOut, Check: ProbeInternet, Observation: ObservationStatusPass, Candidate: DiagnosisOffline},
		}}
		if got := confidenceFor(f); got != ConfidenceInsufficientEvidence {
			t.Errorf("%s with supporting evidence piled on = %q, want %q", id, got, ConfidenceInsufficientEvidence)
		}
	}
}

// TestEveryDiagnosisIDHasAConfidenceClass makes the policy table total. An
// identity nobody classified would silently answer insufficient_evidence, which
// reads as a considered judgment rather than as the omission it is.
func TestEveryDiagnosisIDHasAConfidenceClass(t *testing.T) {
	declared := map[DiagnosisID]string{}
	for _, spec := range declaredConstants(t, "finding.go", "DiagnosisID") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			declared[DiagnosisID(value)] = name.Name
			if _, classified := diagnosisConfidence[DiagnosisID(value)]; !classified {
				t.Errorf("%s (%q) has no entry in diagnosisConfidence", name.Name, value)
			}
		}
	}
	for id := range diagnosisConfidence {
		if _, exists := declared[id]; !exists {
			t.Errorf("diagnosisConfidence classifies %q, which is not a declared diagnosis ID", id)
		}
	}
	if got := confidenceFor(DiagnosisFinding{ID: "not_a_real_identity"}); got != ConfidenceInsufficientEvidence {
		t.Errorf("unclassified identity = %q, want the conservative %q", got, ConfidenceInsufficientEvidence)
	}
}

// TestConfidenceIsDocumented keeps the published vocabulary and its
// documentation in step, for the same reason the diagnosis IDs are: these words
// reach a consumer through the JSON report and the .ndoc file.
func TestConfidenceIsDocumented(t *testing.T) {
	docs, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range declaredConstants(t, "confidence.go", "Confidence") {
		for i, name := range spec.Names {
			value, err := strconv.Unquote(spec.Values[i].(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			if !stableIDRe.MatchString(value) {
				t.Errorf("%s = %q is not stable lower_snake_case", name.Name, value)
			}
			if !strings.Contains(string(docs), "`"+value+"`") {
				t.Errorf("%s (%q) is not documented in docs/reference.md", name.Name, value)
			}
		}
	}
}

// Independent of the lab: reference success cannot distinguish a target
// filter, a silent peer or a broken return path. Refusal is a distinct observed
// condition and must keep high confidence on otherwise identical evidence.
func TestTargetSilenceConfidence(t *testing.T) {
	target, err := ParseTarget("https://app.test")
	if err != nil {
		t.Fatal(err)
	}
	results := map[ProbeID]ProbeResult{
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
		ProbeInternet:  {Status: StatusPass},
		ProbeTargetTCP: {Status: StatusFail},
	}
	order := []ProbeID{ProbeDNS, ProbeInternet, ProbeTargetTCP}
	got := Interpret(target, order, results)
	if len(got.Findings) != 1 || got.Findings[0].ID != DiagnosisTargetUnreachable || got.Findings[0].Confidence != ConfidenceLow {
		t.Fatalf("silent failure must retain its finding with low causal confidence: %+v", got)
	}
	results[ProbeTargetTCP] = ProbeResult{Status: StatusFail, Cause: ConnectionCauseRefused}
	got = Interpret(target, order, results)
	if len(got.Findings) != 1 || got.Findings[0].ID != DiagnosisTCPConnectionRefused || got.Findings[0].Confidence != ConfidenceHigh {
		t.Fatalf("explicit refusal must retain high confidence: %+v", got)
	}
}
