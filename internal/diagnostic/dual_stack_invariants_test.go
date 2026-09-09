package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"testing"
)

type invariantConnectivity string

const (
	invariantWorks    invariantConnectivity = "works"
	invariantFails    invariantConnectivity = "fails"
	invariantUntested invariantConnectivity = "untested"
)

type invariantFamily string

const (
	invariantIPv4    invariantFamily = "ipv4"
	invariantIPv6    invariantFamily = "ipv6"
	invariantNeither invariantFamily = "neither"
)

type invariantTargets string

const (
	invariantTargetIPv4 invariantTargets = "ipv4"
	invariantTargetIPv6 invariantTargets = "ipv6"
	invariantTargetBoth invariantTargets = "both"
)

type dualStackInvariantState struct {
	default4, default6 bool
	connect4, connect6 invariantConnectivity
	preferred          invariantFamily
	targets            invariantTargets
}

func (s dualStackInvariantState) name() string {
	return fmt.Sprintf("v4_default=%t/v6_default=%t/v4=%s/v6=%s/preferred=%s/target=%s",
		s.default4, s.default6, s.connect4, s.connect6, s.preferred, s.targets)
}

func (s dualStackInvariantState) connectivity(family invariantFamily) invariantConnectivity {
	if family == invariantIPv4 {
		return s.connect4
	}
	return s.connect6
}

func (s dualStackInvariantState) hasDefault(family invariantFamily) bool {
	if family == invariantIPv4 {
		return s.default4
	}
	return s.default6
}

func (s dualStackInvariantState) hasTargetFamily(family invariantFamily) bool {
	return s.targets == invariantTargetBoth || s.targets == invariantTargets(family)
}

func (s dualStackInvariantState) swapped() dualStackInvariantState {
	s.default4, s.default6 = s.default6, s.default4
	s.connect4, s.connect6 = s.connect6, s.connect4
	s.preferred = swapInvariantFamily(s.preferred)
	switch s.targets {
	case invariantTargetIPv4:
		s.targets = invariantTargetIPv6
	case invariantTargetIPv6:
		s.targets = invariantTargetIPv4
	}
	return s
}

func dualStackInvariantStates() []dualStackInvariantState {
	var states []dualStackInvariantState
	for _, default4 := range []bool{false, true} {
		for _, default6 := range []bool{false, true} {
			for _, connect4 := range []invariantConnectivity{invariantWorks, invariantFails, invariantUntested} {
				for _, connect6 := range []invariantConnectivity{invariantWorks, invariantFails, invariantUntested} {
					for _, preferred := range []invariantFamily{invariantIPv4, invariantIPv6, invariantNeither} {
						for _, targets := range []invariantTargets{invariantTargetIPv4, invariantTargetIPv6, invariantTargetBoth} {
							states = append(states, dualStackInvariantState{
								default4: default4, default6: default6,
								connect4: connect4, connect6: connect6,
								preferred: preferred, targets: targets,
							})
						}
					}
				}
			}
		}
	}
	return states
}

type directInvariantResult struct {
	result ProbeResult
	asked  map[invariantFamily]int
}

func runDirectInvariantState(s dualStackInvariantState, reverseCandidates bool) directInvariantResult {
	original4, original6 := internetEndpoints4, internetEndpoints6
	internetEndpoints4, internetEndpoints6 = cloneIPs(original4), cloneIPs(original6)
	if reverseCandidates {
		slices.Reverse(internetEndpoints4)
		slices.Reverse(internetEndpoints6)
	}
	defer func() { internetEndpoints4, internetEndpoints6 = original4, original6 }()

	sources := &SourceAddresses{}
	if s.connect4 != invariantUntested {
		sources.IPv4 = net.ParseIP("192.0.2.10")
	}
	if s.connect6 != invariantUntested {
		sources.IPv6 = net.ParseIP("2001:db8::10")
	}
	asked := map[invariantFamily]int{}
	ops := &netops{
		sources: sources,
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network == "udp" || network == "udp4" || network == "udp6" {
				return fakeConn{}, nil
			}
			state := s.connect6
			if network == "tcp4" {
				state = s.connect4
			}
			if state == invariantWorks {
				return fakeConn{}, nil
			}
			return nil, errors.New("invariant path failure")
		},
		routeCause: func(ip net.IP) string {
			family := invariantIPv6
			if ip.To4() != nil {
				family = invariantIPv4
			}
			asked[family]++
			if !s.hasDefault(family) {
				return RouteCauseNoDefaultRoute
			}
			if s.preferred == family {
				return RouteCausePreferredPathFailed
			}
			return RouteCauseSelectedPathFailed
		},
	}
	return directInvariantResult{result: ops.internetProbe(context.Background(), nil), asked: asked}
}

type directInvariantSignature struct {
	status     Status
	cause      string
	ipv4, ipv6 string
}

func directSignature(r ProbeResult) directInvariantSignature {
	sig := directInvariantSignature{status: r.Status, cause: r.Cause}
	if r.Families != nil {
		sig.ipv4, sig.ipv6 = r.Families.IPv4, r.Families.IPv6
	}
	return sig
}

func invariantFamilyState(state invariantConnectivity) string {
	switch state {
	case invariantWorks:
		return FamilyReachable
	case invariantFails:
		return FamilyUnreachable
	default:
		return ""
	}
}

func expectedDirectInvariant(s dualStackInvariantState) (directInvariantSignature, invariantFamily) {
	sig := directInvariantSignature{ipv4: invariantFamilyState(s.connect4), ipv6: invariantFamilyState(s.connect6)}
	working, failed := 0, []invariantFamily{}
	for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
		switch s.connectivity(family) {
		case invariantWorks:
			working++
		case invariantFails:
			failed = append(failed, family)
		}
	}
	switch {
	case working > 0:
		sig.status = StatusPass
		if len(failed) == 1 {
			sig.status = StatusWarn
			if failed[0] == invariantIPv4 {
				sig.cause = FamilyCauseIPv4Unreachable
			} else {
				sig.cause = FamilyCauseIPv6Unreachable
			}
			return sig, failed[0]
		}
		return sig, invariantNeither
	case len(failed) == 0:
		sig.status = StatusNA
		return sig, invariantNeither
	}

	sig.status = StatusFail
	if s.preferred != invariantNeither && s.connectivity(s.preferred) == invariantFails && s.hasDefault(s.preferred) {
		sig.cause = RouteCausePreferredPathFailed
		return sig, s.preferred
	}
	var routed []invariantFamily
	for _, family := range failed {
		if s.hasDefault(family) {
			routed = append(routed, family)
		}
	}
	if len(routed) > 0 {
		sig.cause = RouteCauseSelectedPathFailed
		if len(routed) == 1 {
			return sig, routed[0]
		}
		return sig, invariantNeither
	}
	sig.cause = RouteCauseNoDefaultRoute
	if len(failed) == 1 {
		return sig, failed[0]
	}
	return sig, invariantNeither
}

func assertDirectCauseEvidence(t *testing.T, r ProbeResult, wantFamily invariantFamily) Diagnosis {
	t.Helper()
	res := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: r,
		ProbeDNS:      {Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.53")}},
	}
	d := Interpret(nil, []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}, res)
	found := false
	for _, finding := range d.Findings {
		for _, evidence := range finding.Evidence {
			if evidence.Kind != EvidenceSupport || evidence.Check != ProbeInternet || evidence.Observation != ObservationCause {
				continue
			}
			found = true
			if evidence.Value != stringOrEmpty(wantFamily) {
				t.Errorf("route cause %q evidence family = %q, want %q", r.Cause, evidence.Value, stringOrEmpty(wantFamily))
			}
		}
	}
	if r.Cause != "" && !found {
		t.Errorf("route cause %q has no supporting cause evidence: %+v", r.Cause, d.Findings)
	}
	if r.Cause == "" && found {
		t.Errorf("cause evidence exists for a result with no cause: %+v", d.Findings)
	}
	return d
}

func stringOrEmpty(family invariantFamily) string {
	if family == invariantNeither {
		return ""
	}
	return string(family)
}

func TestFailedRouteCauseIsFamilyAndOrderInvariant(t *testing.T) {
	v4, v6 := []net.IP{net.ParseIP("192.0.2.1")}, []net.IP{net.ParseIP("2001:db8::1")}
	causes := []string{RouteCauseNoDefaultRoute, RouteCauseSelectedPathFailed,
		RouteCauseGatewayUnreachable, RouteCausePreferredPathFailed}
	for _, cause4 := range causes {
		for _, cause6 := range causes {
			name := "ipv4=" + cause4 + "/ipv6=" + cause6
			t.Run(name, func(t *testing.T) {
				classify := func(ip net.IP) string {
					if ip.To4() != nil {
						return cause4
					}
					return cause6
				}
				got, family := failedRouteCause(classify, v4, v6)
				reversed, reversedFamily := failedRouteCause(classify, v6, v4)
				if got != reversed || family != reversedFamily {
					t.Fatalf("family order changed cause/provenance from %q/%q to %q/%q",
						got, family, reversed, reversedFamily)
				}
				if cause4 == cause6 && family != "" {
					t.Errorf("cause %q supported by both families was attributed only to %q", got, family)
				}
				if cause4 != cause6 && (got == cause4 && family != counterfactualIPv4 || got == cause6 && family != counterfactualIPv6) {
					t.Errorf("cause %q provenance = %q, want its originating family", got, family)
				}
				if localPathObserved(got) != (localPathObserved(cause4) && localPathObserved(cause6)) {
					t.Errorf("aggregate %q incorrectly localizes cause pair %q/%q", got, cause4, cause6)
				}
				assertDirectCauseEvidence(t, ProbeResult{Status: StatusFail, Cause: got, causeFamily: family}, invariantFamily(family))
			})
		}
	}
}

var invariantTargetAddresses = map[invariantFamily][]net.IP{
	invariantIPv4: {net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
	invariantIPv6: {net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")},
}

func selectedInvariantTargetFamily(s dualStackInvariantState) invariantFamily {
	if s.preferred != invariantNeither && s.hasTargetFamily(s.preferred) && s.connectivity(s.preferred) == invariantWorks {
		return s.preferred
	}
	// Equal target connections intentionally prefer IPv6 in targetTCPProbe.
	for _, family := range []invariantFamily{invariantIPv6, invariantIPv4} {
		if s.hasTargetFamily(family) && s.connectivity(family) == invariantWorks {
			return family
		}
	}
	return invariantNeither
}

func targetInvariantRun(s dualStackInvariantState, internet ProbeResult, reverse bool) (map[ProbeID]ProbeResult, Diagnosis) {
	selected := selectedInvariantTargetFamily(s)
	var addrs []net.IP
	target := ProbeResult{Status: StatusFail, Families: &FamilyConnectivity{}}
	for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
		if !s.hasTargetFamily(family) {
			continue
		}
		ips := invariantTargetAddresses[family]
		addrs = append(addrs, ips...)
		switch {
		case family == selected:
			if family == invariantIPv4 {
				target.Families.IPv4 = FamilyReachable
			} else {
				target.Families.IPv6 = FamilyReachable
			}
			target.SelectedIP = ips[1]
			target.Attempts = append(target.Attempts,
				Attempt{IP: ips[0], Err: errors.New("backend failure"), Cause: ConnectionCauseUnreachable},
				Attempt{IP: ips[1]})
		case s.connectivity(family) != invariantUntested:
			if family == invariantIPv4 {
				target.Families.IPv4 = FamilyUnreachable
			} else {
				target.Families.IPv6 = FamilyUnreachable
			}
			for _, ip := range ips {
				target.Attempts = append(target.Attempts, Attempt{IP: ip, Err: errors.New("target family failure"), Cause: ConnectionCauseUnreachable})
			}
		}
	}
	if selected != invariantNeither {
		target.Status = StatusWarn
	}
	if reverse {
		slices.Reverse(addrs)
		slices.Reverse(target.Attempts)
	}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     {Status: StatusPass},
		ProbeInternet:  internet,
		ProbeDNS:       {Status: StatusPass, Addrs: addrs},
		ProbeTargetTCP: target,
	}
	Finalize(res)
	return res, Interpret(&Target{Host: "example.com", Port: 443, Proto: ProtoNone},
		[]ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}, res)
}

func targetFamilyStateFrom(res map[ProbeID]ProbeResult, family invariantFamily) string {
	families := res[ProbeTargetTCP].Families
	if families == nil {
		return ""
	}
	if family == invariantIPv4 {
		return families.IPv4
	}
	return families.IPv6
}

func expectedEffectiveTargetFamily(s dualStackInvariantState, family, selected invariantFamily) string {
	if !s.hasTargetFamily(family) || s.connectivity(family) == invariantUntested {
		return ""
	}
	if family == selected {
		return FamilyReachable
	}
	if s.connectivity(family) == invariantWorks {
		return FamilyUnreachable
	}
	return ""
}

func assertTargetCounterfactuals(t *testing.T, s dualStackInvariantState, res map[ProbeID]ProbeResult, d Diagnosis) {
	t.Helper()
	selected := selectedInvariantTargetFamily(s)
	for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
		want := expectedEffectiveTargetFamily(s, family, selected)
		if got := targetFamilyStateFrom(res, family); got != want {
			t.Errorf("effective target %s = %q, want %q", family, got, want)
		}
		if s.connectivity(family) == invariantUntested {
			for _, finding := range d.Findings {
				for _, evidence := range finding.Evidence {
					if (evidence.Observation == ObservationFamilyReachable || evidence.Observation == ObservationFamilyFailed) &&
						evidence.Value == string(family) {
						t.Errorf("untested %s became causal family evidence: %+v", family, evidence)
					}
				}
			}
		}
	}

	wantFailedFamily := invariantNeither
	if selected != invariantNeither {
		other := swapInvariantFamily(selected)
		if s.hasTargetFamily(other) && s.connectivity(other) == invariantWorks {
			wantFailedFamily = other
		}
	}
	for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
		id := DiagnosisIPv6TargetUnreachable
		if family == invariantIPv4 {
			id = DiagnosisIPv4TargetUnreachable
		}
		finding, found := findingByID(d, id)
		want := family == wantFailedFamily
		if found != want {
			t.Errorf("%s family finding present = %t, want %t: %+v", family, found, want, d.Findings)
			continue
		}
		if !found {
			continue
		}
		for _, evidence := range []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationFamilyFailed, Value: string(family)},
			{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationFamilyReachable, Value: string(selected)},
			{Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationFamilyReachable, Value: string(family)},
		} {
			if !slices.Contains(finding.Evidence, evidence) {
				t.Errorf("%s family finding lacks matching evidence %+v: %+v", family, evidence, finding.Evidence)
			}
		}
	}

	addressFinding, hasAddressFinding := findingByID(d, DiagnosisPartialReachability)
	wantAddressFinding := selected != invariantNeither
	if hasAddressFinding != wantAddressFinding {
		t.Errorf("address counterfactual present = %t, want %t: %+v", hasAddressFinding, wantAddressFinding, d.Findings)
		return
	}
	if !hasAddressFinding {
		return
	}
	if addressFinding.Counterfactual == nil {
		t.Fatal("partial reachability finding has no counterfactual")
	}
	failed := []CounterfactualAlternative{}
	for _, alternative := range addressFinding.Counterfactual.Alternatives {
		if alternative.Outcome == CounterfactualFailed {
			failed = append(failed, alternative)
		}
	}
	if len(failed) != 1 {
		t.Fatalf("failed backend alternatives = %+v, want only the failed address in the reachable selected family", failed)
	}
	ip := net.ParseIP(failed[0].Value)
	if invariantFamilyOfIP(ip) != selected || targetFamilyStateFrom(res, selected) != FamilyReachable {
		t.Errorf("working backend alternative %s belongs to %s with state %q, want selected reachable %s",
			failed[0].Value, invariantFamilyOfIP(ip), targetFamilyStateFrom(res, selected), selected)
	}
}

func invariantFamilyOfIP(ip net.IP) invariantFamily {
	if ip != nil && ip.To4() != nil {
		return invariantIPv4
	}
	return invariantIPv6
}

type diagnosisInvariantSignature struct {
	verdict                  string
	internetCause            string
	internet4, internet6     string
	target4, target6         string
	selected                 invariantFamily
	findings, evidence, alts []string
}

func diagnosisSignature(res map[ProbeID]ProbeResult, d Diagnosis) diagnosisInvariantSignature {
	sig := diagnosisInvariantSignature{verdict: d.Verdict, internetCause: res[ProbeInternet].Cause,
		selected: invariantNeither}
	if families := res[ProbeInternet].Families; families != nil {
		sig.internet4, sig.internet6 = families.IPv4, families.IPv6
	}
	if families := res[ProbeTargetTCP].Families; families != nil {
		sig.target4, sig.target6 = families.IPv4, families.IPv6
	}
	if ip := res[ProbeTargetTCP].SelectedIP; ip != nil {
		sig.selected = invariantFamilyOfIP(ip)
	}
	for _, finding := range d.Findings {
		sig.findings = append(sig.findings, string(finding.ID))
		for _, evidence := range finding.Evidence {
			sig.evidence = append(sig.evidence, fmt.Sprintf("%s|%s|%s|%s|%s|%s",
				evidence.Kind, evidence.Check, evidence.Observation, evidence.Value, evidence.Candidate, evidence.Reason))
		}
		if finding.Counterfactual != nil {
			for _, alternative := range finding.Counterfactual.Alternatives {
				sig.alts = append(sig.alts, fmt.Sprintf("%s|%s|%s", finding.Counterfactual.Variable, alternative.Outcome, alternative.Value))
			}
		}
	}
	sort.Strings(sig.findings)
	sort.Strings(sig.evidence)
	sort.Strings(sig.alts)
	return sig
}

func swapInvariantFamily(family invariantFamily) invariantFamily {
	switch family {
	case invariantIPv4:
		return invariantIPv6
	case invariantIPv6:
		return invariantIPv4
	default:
		return family
	}
}

func swapInvariantCause(cause string) string {
	switch cause {
	case FamilyCauseIPv4Unreachable:
		return FamilyCauseIPv6Unreachable
	case FamilyCauseIPv6Unreachable:
		return FamilyCauseIPv4Unreachable
	default:
		return cause
	}
}

func familyFinding(d Diagnosis) invariantFamily {
	for _, finding := range d.Findings {
		switch finding.ID {
		case DiagnosisIPv4TargetUnreachable:
			return invariantIPv4
		case DiagnosisIPv6TargetUnreachable:
			return invariantIPv6
		}
	}
	return invariantNeither
}

func causeEvidenceFamily(d Diagnosis) invariantFamily {
	for _, finding := range d.Findings {
		for _, evidence := range finding.Evidence {
			if evidence.Kind == EvidenceSupport && evidence.Check == ProbeInternet && evidence.Observation == ObservationCause {
				if evidence.Value == "" {
					return invariantNeither
				}
				return invariantFamily(evidence.Value)
			}
		}
	}
	return invariantNeither
}

func TestDualStackDiagnosisInvariantMatrix(t *testing.T) {
	states := dualStackInvariantStates()
	if len(states) != 324 {
		t.Fatalf("dual-stack matrix has %d states, want 324", len(states))
	}
	preferredTargetUnavailable, asymmetricTargetTie := 0, 0
	for _, state := range states {
		s := state
		preferredTargetUnavailableState := s.preferred != invariantNeither && !s.hasTargetFamily(s.preferred)
		asymmetricTargetTieState := s.preferred == invariantNeither && s.targets == invariantTargetBoth &&
			s.connect4 == invariantWorks && s.connect6 == invariantWorks
		if preferredTargetUnavailableState {
			preferredTargetUnavailable++
		}
		if asymmetricTargetTieState {
			asymmetricTargetTie++
		}
		t.Run(s.name(), func(t *testing.T) {
			wantDirect, wantCauseFamily := expectedDirectInvariant(s)
			normal := runDirectInvariantState(s, false)
			if got := directSignature(normal.result); got != wantDirect {
				t.Errorf("direct egress = %+v, want %+v", got, wantDirect)
			}
			if wantDirect.status != StatusFail && len(normal.asked) != 0 {
				t.Errorf("route classifier was called for a working or untested result: %v", normal.asked)
			}
			if wantDirect.status == StatusFail && wantCauseFamily != invariantNeither && normal.asked[wantCauseFamily] == 0 {
				t.Errorf("route cause %q never inspected its responsible %s family: calls=%v", wantDirect.cause, wantCauseFamily, normal.asked)
			}
			if wantDirect.cause == RouteCauseNoDefaultRoute {
				for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
					if s.connectivity(family) == invariantFails && normal.asked[family] == 0 {
						t.Errorf("no_default_route was selected without inspecting failed %s routing: calls=%v", family, normal.asked)
					}
				}
			}
			directDiagnosis := assertDirectCauseEvidence(t, normal.result, wantCauseFamily)

			reversed := runDirectInvariantState(s, true)
			if got, want := directSignature(reversed.result), directSignature(normal.result); got != want {
				t.Errorf("reversing direct candidates changed semantics: got %+v, want %+v", got, want)
			}

			res, diagnosis := targetInvariantRun(s, normal.result, false)
			assertTargetCounterfactuals(t, s, res, diagnosis)
			reversedRes, reversedDiagnosis := targetInvariantRun(s, reversed.result, true)
			if got, want := diagnosisSignature(reversedRes, reversedDiagnosis), diagnosisSignature(res, diagnosis); !reflect.DeepEqual(got, want) {
				t.Errorf("reversing target candidates and attempts changed semantics:\n got %+v\nwant %+v", got, want)
			}

			if s.preferred != invariantNeither && s.connectivity(s.preferred) == invariantFails &&
				s.connectivity(swapInvariantFamily(s.preferred)) == invariantWorks {
				if normal.result.Status != StatusWarn || causeEvidenceFamily(directDiagnosis) != s.preferred {
					t.Errorf("working alternate erased the preferred %s failure: result=%+v findings=%+v",
						s.preferred, normal.result, directDiagnosis.Findings)
				}
			}

			mirror := s.swapped()
			mirrorDirect := runDirectInvariantState(mirror, false)
			if normal.result.Status != mirrorDirect.result.Status || normal.result.Cause != swapInvariantCause(mirrorDirect.result.Cause) ||
				directSignature(normal.result).ipv4 != directSignature(mirrorDirect.result).ipv6 ||
				directSignature(normal.result).ipv6 != directSignature(mirrorDirect.result).ipv4 {
				t.Errorf("family swap changed symmetric direct semantics: original=%+v mirror=%+v",
					directSignature(normal.result), directSignature(mirrorDirect.result))
			}
			mirrorDirectDiagnosis := assertDirectCauseEvidence(t, mirrorDirect.result, swapInvariantFamily(wantCauseFamily))
			if got := swapInvariantFamily(causeEvidenceFamily(mirrorDirectDiagnosis)); got != causeEvidenceFamily(directDiagnosis) {
				t.Errorf("family swap changed route-cause provenance: original=%s mirror=%s", causeEvidenceFamily(directDiagnosis), got)
			}

			mirrorRes, mirrorDiagnosis := targetInvariantRun(mirror, mirrorDirect.result, false)
			// targetTCPProbe deliberately prefers IPv6 when both families finish
			// together, so this one tie is not a symmetric contract.
			if !asymmetricTargetTieState {
				if targetFamilyStateFrom(res, invariantIPv4) != targetFamilyStateFrom(mirrorRes, invariantIPv6) ||
					targetFamilyStateFrom(res, invariantIPv6) != targetFamilyStateFrom(mirrorRes, invariantIPv4) ||
					familyFinding(diagnosis) != swapInvariantFamily(familyFinding(mirrorDiagnosis)) {
					t.Errorf("family swap changed symmetric target semantics: original=%+v mirror=%+v",
						diagnosisSignature(res, diagnosis), diagnosisSignature(mirrorRes, mirrorDiagnosis))
				}
				if got := swapInvariantFamily(selectedInvariantTargetFamily(mirror)); got != selectedInvariantTargetFamily(s) {
					t.Errorf("family swap changed selected target family: original=%s mirror=%s",
						selectedInvariantTargetFamily(s), got)
				}
			}
		})
	}
	if preferredTargetUnavailable != 72 {
		t.Errorf("states without an address in the preferred target family = %d, want 72", preferredTargetUnavailable)
	}
	if asymmetricTargetTie != 4 {
		t.Errorf("intentional IPv6 target-selection ties = %d, want 4", asymmetricTargetTie)
	}
}

type invariantAttemptOutcome string

const (
	invariantAttemptSucceeded invariantAttemptOutcome = "succeeded"
	invariantAttemptFailed    invariantAttemptOutcome = "failed"
	invariantAttemptAborted   invariantAttemptOutcome = "aborted"
	invariantAttemptCanceled  invariantAttemptOutcome = "canceled"
)

func TestAddressCounterfactualEligibilityMatrix(t *testing.T) {
	// resolved=false models a stale attempt at this interpretation boundary.
	// It cannot come from the current probe, but the membership guard exists
	// specifically so such an inconsistent result cannot become evidence.
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}
	states := []string{FamilyReachable, FamilyUnreachable, ""}
	count, invalid := 0, 0
	for _, family := range []invariantFamily{invariantIPv4, invariantIPv6} {
		for _, resolved := range []bool{false, true} {
			for _, alreadySelected := range []bool{false, true} {
				for _, outcome := range []invariantAttemptOutcome{
					invariantAttemptSucceeded, invariantAttemptFailed, invariantAttemptAborted, invariantAttemptCanceled,
				} {
					for _, familyState := range states {
						count++
						// A selected address belongs to the resolved set, and both selected
						// and successful addresses prove their family reachable. Other
						// combinations cannot be emitted by targetTCPProbe, so keep them
						// out rather than manufacture contradictory rows.
						if alreadySelected && (!resolved || familyState != FamilyReachable) ||
							outcome == invariantAttemptSucceeded && familyState != FamilyReachable {
							invalid++
							continue
						}
						familyStateName := familyState
						if familyStateName == "" {
							familyStateName = "untested"
						}
						name := fmt.Sprintf("family=%s/resolved=%t/already_selected=%t/attempt=%s/family_state=%s",
							family, resolved, alreadySelected, outcome, familyStateName)
						t.Run(name, func(t *testing.T) {
							candidate := net.ParseIP("192.0.2.1")
							selected, filler := net.ParseIP("198.51.100.1"), net.ParseIP("203.0.113.1")
							if family == invariantIPv6 {
								candidate = net.ParseIP("2001:db8::1")
								selected, filler = net.ParseIP("2001:db8:1::1"), net.ParseIP("2001:db8:2::1")
							}
							if familyState != FamilyReachable {
								if family == invariantIPv4 {
									selected, filler = net.ParseIP("2001:db8:1::1"), net.ParseIP("2001:db8:2::1")
								} else {
									selected, filler = net.ParseIP("198.51.100.1"), net.ParseIP("203.0.113.1")
								}
							}
							if alreadySelected {
								selected = candidate
							}
							addrs := []net.IP{selected, filler}
							if resolved && !alreadySelected {
								addrs[1] = candidate
								if familyState == "" {
									sibling := net.ParseIP("192.0.2.2")
									if family == invariantIPv6 {
										sibling = net.ParseIP("2001:db8::2")
									}
									addrs = append(addrs, sibling)
								}
							}
							attempt := Attempt{IP: candidate}
							switch outcome {
							case invariantAttemptFailed:
								attempt.Err, attempt.Cause = errors.New("backend failure"), ConnectionCauseUnreachable
							case invariantAttemptAborted:
								attempt.Err, attempt.Cause, attempt.Aborted = context.DeadlineExceeded, ConnectionCauseTimeout, true
							case invariantAttemptCanceled:
								attempt.Err, attempt.Cause = context.Canceled, ConnectionCauseCanceled
							}
							targetFamilies := &FamilyConnectivity{}
							internetFamilies := &FamilyConnectivity{}
							if family == invariantIPv4 {
								targetFamilies.IPv4 = familyState
								if familyState == FamilyUnreachable {
									internetFamilies.IPv4 = FamilyReachable
								}
							} else {
								targetFamilies.IPv6 = familyState
								if familyState == FamilyUnreachable {
									internetFamilies.IPv6 = FamilyReachable
								}
							}
							res := map[ProbeID]ProbeResult{
								ProbeInternet: {Status: StatusPass, Families: internetFamilies},
								ProbeDNS:      {Status: StatusPass, Addrs: addrs},
								ProbeTargetTCP: {Status: StatusWarn, SelectedIP: selected, Families: targetFamilies,
									Attempts: []Attempt{attempt, {IP: selected}}},
							}
							_, found := addressCounterfactual(target, res)
							want := resolved && !alreadySelected && outcome == invariantAttemptFailed && familyState == FamilyReachable
							if found != want {
								t.Fatalf("address counterfactual present = %t, want %t", found, want)
							}
						})
					}
				}
			}
		}
	}
	if count != 96 {
		t.Fatalf("address counterfactual matrix has %d states, want 96", count)
	}
	if invalid != 48 {
		t.Fatalf("structurally invalid address states = %d, want 48", invalid)
	}
}
