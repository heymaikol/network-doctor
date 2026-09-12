package diagnostic

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func matrixCaseNamed(t *testing.T, name string) matrixCase {
	t.Helper()
	for _, c := range diagnosisMatrix() {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("diagnosis matrix has no case %q", name)
	return matrixCase{}
}

func TestCausalEvidenceRecordsTheSelectingBranch(t *testing.T) {
	tests := []struct {
		name string
		want []CausalEvidence
	}{
		{
			name: "generic system resolver failing",
			want: []CausalEvidence{
				{Kind: EvidenceSupport, Check: ProbeDNS, Observation: ObservationStatusFail},
				{Kind: EvidenceSupport, Check: ProbeDNSPublic, Observation: ObservationDNSAnswers},
				{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationStatusPass},
				{Kind: EvidenceContradiction, Check: ProbeDNSPublic, Observation: ObservationDNSAnswers, Candidate: DiagnosisDNSFailure},
				{Kind: EvidenceRuledOut, Check: ProbeDNSPublic, Observation: ObservationDNSAnswers, Candidate: DiagnosisDNSNameNotFound},
				{Kind: EvidenceRuledOut, Check: ProbeInternet, Observation: ObservationStatusPass, Candidate: DiagnosisOffline},
			},
		},
		{
			name: "target refuses the connection",
			want: []CausalEvidence{
				{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationCause},
				{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationStatusPass},
				{Kind: EvidenceRuledOut, Check: ProbeTargetTCP, Observation: ObservationCause, Candidate: DiagnosisTargetUnreachable},
				{Kind: EvidenceRuledOut, Check: ProbeInternet, Observation: ObservationStatusPass, Candidate: DiagnosisLocalEgressFailure},
			},
		},
		{
			name: "TLS expiry explained by a fast clock",
			want: []CausalEvidence{
				{Kind: EvidenceSupport, Check: ProbeTLS, Observation: ObservationCause},
				{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationStatusPass},
				{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationStatusPass},
				{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationClockOffset},
				{Kind: EvidenceRuledOut, Check: ProbeTargetTCP, Observation: ObservationStatusPass, Candidate: DiagnosisTLSTCPUnreachable},
			},
		},
		{
			name: "TLS expiry with the clock ruled out",
			want: []CausalEvidence{
				{Kind: EvidenceSupport, Check: ProbeTLS, Observation: ObservationCause},
				{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationStatusPass},
				{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationStatusPass},
				{Kind: EvidenceRuledOut, Check: ProbeInternet, Observation: ObservationClockOffset, Candidate: DiagnosisTLSClockSkew},
				{Kind: EvidenceRuledOut, Check: ProbeTargetTCP, Observation: ObservationStatusPass, Candidate: DiagnosisTLSTCPUnreachable},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := matrixCaseNamed(t, tt.name)
			got := Interpret(c.target, c.order, c.res)
			if len(got.Findings) != 1 {
				t.Fatalf("findings = %+v", got.Findings)
			}
			if !reflect.DeepEqual(got.Findings[0].Evidence, tt.want) {
				t.Errorf("causal evidence =\n%+v\nwant\n%+v", got.Findings[0].Evidence, tt.want)
			}
		})
	}
}

func TestCausalEvidenceKeepsNotEvaluatedDistinct(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  {Status: StatusPass},
		ProbeDNS:       {Status: StatusFail},
		ProbeTargetTCP: SkipPrereq(ProbeTargetTCP),
	}
	finding := Interpret(target, order, res).Findings[0]
	want := CausalEvidence{Kind: EvidenceNotEvaluated, Check: ProbeTargetTCP,
		Observation: ObservationStatusSkip, Reason: NotEvaluatedPrerequisite}
	if !slices.Contains(finding.Evidence, want) {
		t.Fatalf("evidence = %+v, want prerequisite item %+v", finding.Evidence, want)
	}
	for _, evidence := range finding.Evidence {
		if evidence.Check == ProbeTargetTCP && evidence.Kind == EvidenceRuledOut {
			t.Errorf("skipped target check was represented as ruled out: %+v", evidence)
		}
	}

	c := matrixCaseNamed(t, "target unreachable with egress unchecked")
	finding = Interpret(c.target, c.order, c.res).Findings[0]
	want = CausalEvidence{Kind: EvidenceNotEvaluated, Check: ProbeInternet, Reason: NotEvaluatedNotSelected}
	if !slices.Contains(finding.Evidence, want) {
		t.Fatalf("evidence = %+v, want not-selected item %+v", finding.Evidence, want)
	}
}

func TestEveryActionableDiagnosisHasObservedSupport(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			for _, finding := range Interpret(c.target, c.order, c.res).Findings {
				hasSupport := false
				for _, evidence := range finding.Evidence {
					if evidence.Kind == EvidenceSupport {
						hasSupport = true
					}
					assertEvidenceObservation(t, finding.ID, evidence, c.order, c.res)
				}
				if !hasSupport {
					t.Errorf("actionable diagnosis %q has no supporting observation", finding.ID)
				}
			}
		})
	}
}

func TestCausalEvidenceOrderingIsDeterministic(t *testing.T) {
	c := matrixCaseNamed(t, "generic system resolver failing")
	want := Interpret(c.target, c.order, c.res)
	for range 20 {
		if got := Interpret(c.target, c.order, c.res); !reflect.DeepEqual(got.Findings, want.Findings) {
			t.Fatalf("evidence order changed:\n%+v\nwant\n%+v", got.Findings, want.Findings)
		}
	}
}

func assertEvidenceObservation(t *testing.T, selected DiagnosisID, evidence CausalEvidence, order []ProbeID, res map[ProbeID]ProbeResult) {
	t.Helper()
	r, exists := res[evidence.Check]
	if evidence.Kind == EvidenceNotEvaluated && evidence.Reason == NotEvaluatedNotSelected {
		if exists || slices.Contains(order, evidence.Check) || evidence.Observation != "" {
			t.Errorf("not-selected evidence has an observation or a result: %+v", evidence)
		}
		return
	}
	if !exists || !slices.Contains(order, evidence.Check) {
		t.Errorf("evidence references a check that did not report: %+v", evidence)
		return
	}
	if (evidence.Kind == EvidenceRuledOut || evidence.Kind == EvidenceContradiction) &&
		(evidence.Candidate == "" || evidence.Candidate == selected || r.Status == StatusSkip || r.Status == StatusNA) {
		t.Errorf("alternative relationship lacks independent positive evidence: %+v from %+v", evidence, r)
	}
	assertEvidenceValueArity(t, evidence)
	observed := false
	switch evidence.Observation {
	case ObservationStatusPass:
		observed = r.Status == StatusPass
	case ObservationStatusWarn:
		observed = r.Status == StatusWarn && !r.downgraded
	case ObservationStatusFail:
		observed = r.Status == StatusFail
	case ObservationStatusSkip:
		observed = r.Status == StatusSkip && evidence.Kind == EvidenceNotEvaluated && evidence.Reason == NotEvaluatedPrerequisite
	case ObservationStatusNA:
		observed = r.Status == StatusNA && evidence.Kind == EvidenceNotEvaluated && evidence.Reason == NotEvaluatedNotApplicable
	case ObservationCause:
		observed = r.Cause != "" && evidence.Value == r.causeFamily
	case ObservationDNSAnswers:
		observed = len(r.Addrs) > 0 && (evidence.Value == "" || slices.ContainsFunc(r.Addrs, func(ip net.IP) bool {
			return ip.String() == evidence.Value
		}))
	case ObservationDNSNotFound:
		observed = r.DNSNotFound
	case ObservationCaptivePortal:
		observed = r.Portal != nil
	case ObservationTimeout:
		observed = r.timedOut || r.Cause == TLSCauseTimeout
	case ObservationClockOffset:
		observed = r.clockOffset.Abs() >= 5*time.Minute
	case ObservationStatusDowngraded:
		observed = r.downgraded
	case ObservationFamilyReachable:
		observed = r.Families != nil && (evidence.Value == "ipv4" && r.Families.IPv4 == FamilyReachable ||
			evidence.Value == "ipv6" && r.Families.IPv6 == FamilyReachable)
	case ObservationFamilyFailed:
		observed = r.Families != nil && (evidence.Value == "ipv4" && r.Families.IPv4 == FamilyUnreachable ||
			evidence.Value == "ipv6" && r.Families.IPv6 == FamilyUnreachable)
	case ObservationAddressSucceeded:
		for _, attempt := range r.Attempts {
			observed = observed || attempt.IP.String() == evidence.Value && attempt.Err == nil
		}
	case ObservationAddressFailed:
		for _, attempt := range r.Attempts {
			observed = observed || attempt.IP.String() == evidence.Value && attempt.Err != nil && !isCanceledAttempt(attempt)
		}
	// Every route observation is a fact about this row's own recorded
	// decisions. A cross-row claim has to be spelled as one item per row, so
	// there is nothing here that reaches into another result to be verified.
	case ObservationRouteTunneled:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Iface == evidence.Value && d.Tunneled()
		})
	case ObservationRouteDirect:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Iface == evidence.Value && d.Tunnel == TunnelDirect
		})
	case ObservationRouteUnreachable:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Unreachable && d.Destination.String() == evidence.Value
		})
	case ObservationRoutePathDiffers:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Iface != "" && d.Iface != evidence.Value
		})
	case ObservationRouteNextHopDiffers:
		observed = evidence.Value != "" && slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Gateway != nil && d.Gateway.String() != evidence.Value
		})
	case ObservationRouteTableDiffers:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.TableKnown && d.Table != ""
		})
	case ObservationRouteFamilySplit:
		split, known := familyPathsDiffer(r.Routes)
		observed = known && split
	case ObservationRouteInterfaceMTU:
		observed = slices.ContainsFunc(r.Routes, func(d RouteDecision) bool {
			return d.Iface == evidence.Value && d.MTU > 0
		})
	}
	if !observed {
		t.Errorf("evidence references an observation that did not occur: %+v from %+v", evidence, r)
	}
}

func TestRoutingCauseRemainsTheSupportingObservation(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  {Status: StatusFail, Cause: RouteCauseNoDefaultRoute},
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
		ProbeTargetTCP: {Status: StatusFail},
	}
	d := Interpret(target, order, res)
	if len(d.Findings) != 1 || d.Findings[0].ID != DiagnosisLocalEgressFailure {
		t.Fatalf("diagnosis = %+v", d)
	}
	want := CausalEvidence{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationCause}
	if len(d.Findings[0].Evidence) == 0 || d.Findings[0].Evidence[0] != want {
		t.Errorf("first evidence = %+v, want %+v", d.Findings[0].Evidence, want)
	}
}

// This ledger is the producer's half of the causal-evidence contract, written
// from what emits each item rather than from what accepts it: observed and
// supportObservation in the truth table, relation for the alternatives it
// contradicts or rules out, routeEvidence, and the three counterfactuals.
//
// Each entry names how a producer uses CausalEvidence.Value and why, in the
// same vocabulary internal/snapshot validates with. "absent" is an observation
// that is the whole claim, "optional" one a producer may narrow to a single
// recorded value, "required" one that is unreadable without the value it is
// about. A new observation cannot land without an entry here, and an entry
// that disagrees with the validator fails below, so the two halves cannot
// drift apart in silence.
var producerEvidenceValues = map[ObservationID]string{
	ObservationStatusPass:          "absent: a row's outcome is the whole observation",
	ObservationStatusWarn:          "absent: a row's outcome is the whole observation",
	ObservationStatusFail:          "absent: a row's outcome is the whole observation",
	ObservationStatusSkip:          "absent: a prerequisite-blocked row has nothing else to name",
	ObservationStatusNA:            "absent: a row that did not apply has nothing else to name",
	ObservationCause:               "optional: observed names the family that supplied the cause; every other producer leaves it empty",
	ObservationDNSAnswers:          "optional: the address counterfactual names one recorded answer; every other producer leaves it empty",
	ObservationDNSNotFound:         "absent: the authoritative absence is the whole observation",
	ObservationCaptivePortal:       "absent: interception is the observation; the redirect stays on the row",
	ObservationTimeout:             "absent: the deadline is the observation, not a duration to name",
	ObservationClockOffset:         "absent: the offset stays on the row, and only one past clockSkewThreshold is evidence",
	ObservationStatusDowngraded:    "absent: later reasoning relaxed this row, which names nothing else",
	ObservationFamilyReachable:     "required: the address family the claim is about",
	ObservationFamilyFailed:        "required: the address family the claim is about",
	ObservationAddressSucceeded:    "required: the resolved address that was tried",
	ObservationAddressFailed:       "required: the resolved address that was tried",
	ObservationRouteTunneled:       "required: the interface the row left by; splitTunnelState reports nothing for an unnamed one",
	ObservationRouteDirect:         "required: the interface the row left by; splitTunnelState reports nothing for an unnamed one",
	ObservationRouteUnreachable:    "required: the destination the kernel refused to route",
	ObservationRoutePathDiffers:    "required: the other path's interface",
	ObservationRouteNextHopDiffers: "required: the other path's next hop, reported only where both sides have one",
	ObservationRouteTableDiffers:   "absent: the other row is the main table or unknown, and neither is a value a reader could check",
	ObservationRouteFamilySplit:    "absent: the split is stated about the row holding both families",
	ObservationRouteInterfaceMTU:   "required: the interface whose MTU this is",
}

// observationConstants reads the vocabulary out of finding.go rather than
// restating it, so a constant added without a ledger entry fails here.
func observationConstants(t *testing.T) map[string]ObservationID {
	t.Helper()
	// A constant so reading it needs no gosec exemption.
	const file = "finding.go"
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]ObservationID{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			name := value.Names[0].Name
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || !strings.HasPrefix(name, "Observation") {
				continue
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			out[name] = ObservationID(text)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no observation constants found in %s", file)
	}
	return out
}

// The producer and the artifact validator have to agree on what every
// observation's value means, in both directions. A validator that is broader
// than the producer accepts artifacts no run could have written; one that is
// narrower discards honest evidence. Neither is visible from inside either
// package, which is why the comparison lives here.
func TestCausalEvidenceValueSemanticsMatchTheValidator(t *testing.T) {
	validator := snapshot.CausalEvidenceValueSemantics()
	constants := observationConstants(t)
	for name, id := range constants {
		policy, ok := producerEvidenceValues[id]
		if !ok {
			t.Errorf("%s (%q) has no entry in producerEvidenceValues: state how the producer uses Value and why", name, id)
			continue
		}
		category, reason, ok := strings.Cut(policy, ": ")
		if !ok || reason == "" {
			t.Errorf("%s (%q) needs a value category and a rationale", name, id)
			continue
		}
		switch category {
		case snapshot.EvidenceValueAbsent, snapshot.EvidenceValueOptional, snapshot.EvidenceValueRequired:
		default:
			t.Errorf("%s (%q) has unrecognized value category %q", name, id, category)
			continue
		}
		if got, known := validator[string(id)]; !known {
			t.Errorf("%s (%q) is not in the snapshot causal-evidence vocabulary", name, id)
		} else if got != category {
			t.Errorf("%s (%q): producer says %q, snapshot validates %q", name, id, category, got)
		}
	}
	declared := map[ObservationID]bool{}
	for _, id := range constants {
		declared[id] = true
	}
	for id := range producerEvidenceValues {
		if !declared[id] {
			t.Errorf("stale producer value policy for %q", id)
		}
	}
	for id := range validator {
		if !declared[ObservationID(id)] {
			t.Errorf("snapshot validates observation %q, which this producer cannot name", id)
		}
	}
}

// assertEvidenceValueArity holds one produced item to its ledger entry. It
// runs from every suite that already verifies produced evidence, which is what
// makes the route pass and the counterfactuals covered without a second walk.
func assertEvidenceValueArity(t *testing.T, evidence CausalEvidence) {
	t.Helper()
	if evidence.Observation == "" {
		return
	}
	category, _, _ := strings.Cut(producerEvidenceValues[evidence.Observation], ": ")
	switch category {
	case snapshot.EvidenceValueAbsent:
		if evidence.Value != "" {
			t.Errorf("%s is declared to name no value but the producer wrote %q: %+v", evidence.Observation, evidence.Value, evidence)
		}
	case snapshot.EvidenceValueRequired:
		if evidence.Value == "" {
			t.Errorf("%s is declared to name a value but the producer wrote none: %+v", evidence.Observation, evidence)
		}
	case "":
		t.Errorf("producer emitted %q, which has no value policy: %+v", evidence.Observation, evidence)
	}
}

// The artifact validator carries its own copy of the threshold that decides
// when a measured clock offset is evidence, because internal/snapshot cannot
// import this package. The two have to stay the same number.
func TestClockSkewThresholdMatchesTheArtifactValidator(t *testing.T) {
	if got := clockSkewThreshold.Milliseconds(); got != snapshot.ClockOffsetEvidenceMs {
		t.Errorf("clockSkewThreshold = %dms, but snapshot.ClockOffsetEvidenceMs = %d", got, snapshot.ClockOffsetEvidenceMs)
	}
}

// Tightening what the artifact accepts is only correct if it still accepts
// everything a run writes, so every case in the matrix is taken through the
// real builder and every boundary an .ndoc crosses: validated, written, read
// back, and the same again after support sanitization, which rewrites the
// addresses and interface names the evidence names. Replay closes the loop by
// recomputing the diagnosis from the file the run produced.
func TestProducedArtifactsSurviveEveryEvidenceBoundary(t *testing.T) {
	for _, c := range diagnosisMatrix() {
		t.Run(c.name, func(t *testing.T) {
			probes := make([]Probe, 0, len(c.order))
			for _, id := range c.order {
				probes = append(probes, Probe{ID: id, Name: string(id)})
			}
			s := withSnapshotProvenance(BuildSnapshot(c.target, probes, timedResults(c.res)))
			if len(s.Diagnosis.Findings) == 0 {
				t.Skip("case reaches no finding, so it carries no causal evidence")
			}
			for _, artifact := range []struct {
				name string
				s    snapshot.Snapshot
			}{{"ordinary", s}, {"sanitized", snapshot.SanitizeForSupport(s)}} {
				if err := snapshot.Validate(artifact.s); err != nil {
					t.Fatalf("%s: Validate: %v", artifact.name, err)
				}
				data, err := snapshot.Encode(artifact.s)
				if err != nil {
					t.Fatalf("%s: Encode: %v", artifact.name, err)
				}
				decoded, err := snapshot.Decode(data)
				if err != nil {
					t.Fatalf("%s: Decode: %v", artifact.name, err)
				}
				if _, err := ReplaySnapshot(decoded); err != nil {
					t.Fatalf("%s: replay of a produced artifact failed: %v", artifact.name, err)
				}
			}
		})
	}
}
