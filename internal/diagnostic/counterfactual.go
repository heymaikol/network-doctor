package diagnostic

import (
	"context"
	"errors"
	"net"
	"slices"
)

const (
	counterfactualSystemDNS      = "system"
	counterfactualIndependentDNS = "independent"
	counterfactualIPv4           = "ipv4"
	counterfactualIPv6           = "ipv6"
)

// counterfactualFindings derives the three bounded comparisons Network Doctor
// currently supports. Interpret is its only caller and remains authoritative.
func counterfactualFindings(t *Target, res map[ProbeID]ProbeResult) []DiagnosisFinding {
	var findings []DiagnosisFinding
	if finding, ok := dnsCounterfactual(t, res); ok {
		findings = append(findings, finding)
	}
	if t == nil {
		return findings
	}
	if finding, ok := familyCounterfactual(t, res); ok {
		findings = append(findings, finding)
	}
	if finding, ok := addressCounterfactual(t, res); ok {
		findings = append(findings, finding)
	}
	return findings
}

func dnsCounterfactual(t *Target, res map[ProbeID]ProbeResult) (DiagnosisFinding, bool) {
	system, systemOK := res[ProbeDNS]
	independent, independentOK := res[ProbeDNSPublic]
	if !systemOK || !independentOK || independent.Status == StatusNA || independent.Status == StatusSkip {
		return DiagnosisFinding{}, false
	}
	name := "the name"
	if t != nil {
		name = t.Host
	}
	alternative := func(value string, outcome CounterfactualOutcome, check ProbeID, observation ObservationID) CounterfactualAlternative {
		e := CausalEvidence{Kind: EvidenceSupport, Check: check, Observation: observation}
		return CounterfactualAlternative{Value: value, Outcome: outcome, Evidence: []CausalEvidence{e}}
	}
	makeFinding := func(id DiagnosisID, verdict, summary string, alternatives ...CounterfactualAlternative) DiagnosisFinding {
		var evidence []CausalEvidence
		for _, item := range alternatives {
			evidence = append(evidence, item.Evidence...)
		}
		return DiagnosisFinding{ID: id, Verdict: verdict, Summary: summary, Focus: ProbeDNS,
			Evidence: evidence, Counterfactual: &Counterfactual{Variable: CounterfactualDNSResolver, Alternatives: alternatives}}
	}

	switch {
	case system.DNSNotFound && independent.DNSNotFound:
		return makeFinding(DiagnosisDNSNameNotFound, VerdictDNS,
			name+" has no A/AAAA records according to either system or public DNS.",
			alternative(counterfactualSystemDNS, CounterfactualNotFound, ProbeDNS, ObservationDNSNotFound),
			alternative(counterfactualIndependentDNS, CounterfactualNotFound, ProbeDNSPublic, ObservationDNSNotFound)), true
	case (system.Status == StatusFail || system.DNSNotFound) && len(independent.Addrs) > 0:
		observation, outcome := ObservationCause, CounterfactualFailed
		if system.DNSNotFound {
			observation, outcome = ObservationDNSNotFound, CounterfactualNotFound
		} else if system.Cause == "" {
			observation = ObservationStatusFail
		}
		return makeFinding(DiagnosisSystemDNSFailure, VerdictDNS,
			"System DNS cannot resolve "+name+", but independent DNS can.",
			alternative(counterfactualSystemDNS, outcome, ProbeDNS, observation),
			alternative(counterfactualIndependentDNS, CounterfactualSucceeded, ProbeDNSPublic, ObservationDNSAnswers)), true
	case len(system.Addrs) > 0 && independent.DNSNotFound:
		return makeFinding(DiagnosisDNSDisagreement, VerdictDegraded,
			"System DNS resolves "+name+", but independent DNS reports no records; split DNS or filtering may be intentional.",
			alternative(counterfactualSystemDNS, CounterfactualSucceeded, ProbeDNS, ObservationDNSAnswers),
			alternative(counterfactualIndependentDNS, CounterfactualNotFound, ProbeDNSPublic, ObservationDNSNotFound)), true
	case len(system.Addrs) > 0 && len(independent.Addrs) > 0 && dnsAnswersDisagree(system, independent):
		return makeFinding(DiagnosisDNSDisagreement, VerdictDegraded,
			"System and independent DNS return materially different addresses for "+name+"; split DNS or filtering may be intentional.",
			alternative(counterfactualSystemDNS, CounterfactualSucceeded, ProbeDNS, ObservationDNSAnswers),
			alternative(counterfactualIndependentDNS, CounterfactualSucceeded, ProbeDNSPublic, ObservationDNSAnswers)), true
	}
	return DiagnosisFinding{}, false
}

// dnsAnswersDisagree prefers the comparison the run recorded over one made
// here. Both reach the same answer on live results; they diverge on a replayed
// support artifact, where the addresses have been pseudonymized and the
// recorded outcome is the only one made from what the resolvers actually said.
// The fallback is for results that carry no recorded outcome at all, which is
// every artifact written before the field existed.
func dnsAnswersDisagree(system, independent ProbeResult) bool {
	switch independent.answerComparison {
	case comparisonAgree:
		return false
	case comparisonDisagree:
		return true
	}
	return !answersAgree(system.Addrs, independent.Addrs)
}

func familyCounterfactual(t *Target, res map[ProbeID]ProbeResult) (DiagnosisFinding, bool) {
	r, ok := res[ProbeTargetTCP]
	if !ok || r.Families == nil {
		return DiagnosisFinding{}, false
	}
	states := effectiveTargetFamilies(res)
	succeeded, failed, id := "", "", DiagnosisID("")
	switch {
	case states.IPv4 == FamilyReachable && states.IPv6 == FamilyUnreachable:
		succeeded, failed, id = counterfactualIPv4, counterfactualIPv6, DiagnosisIPv6TargetUnreachable
	case states.IPv6 == FamilyReachable && states.IPv4 == FamilyUnreachable:
		succeeded, failed, id = counterfactualIPv6, counterfactualIPv4, DiagnosisIPv4TargetUnreachable
	default:
		return DiagnosisFinding{}, false
	}
	successEvidence := CausalEvidence{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationFamilyReachable, Value: succeeded}
	failureEvidence := CausalEvidence{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: ObservationFamilyFailed, Value: failed}
	failureAlternativeEvidence := []CausalEvidence{failureEvidence}
	if internet := res[ProbeInternet]; internet.Families != nil &&
		(failed == counterfactualIPv4 && internet.Families.IPv4 == FamilyReachable ||
			failed == counterfactualIPv6 && internet.Families.IPv6 == FamilyReachable) {
		failureAlternativeEvidence = append(failureAlternativeEvidence, CausalEvidence{
			Kind: EvidenceSupport, Check: ProbeInternet, Observation: ObservationFamilyReachable, Value: failed,
		})
	}
	evidence := append(append([]CausalEvidence{}, failureAlternativeEvidence...), successEvidence)
	summary := familyLabel(failed) + " connectivity to " + t.Host + " is failing, but " + familyLabel(succeeded) + " works."
	return DiagnosisFinding{
		ID: id, Verdict: VerdictDegraded, Summary: summary, Focus: ProbeTargetTCP,
		Evidence: evidence,
		Counterfactual: &Counterfactual{Variable: CounterfactualAddressFamily, Alternatives: []CounterfactualAlternative{
			{Value: failed, Outcome: CounterfactualFailed, Evidence: failureAlternativeEvidence},
			{Value: succeeded, Outcome: CounterfactualSucceeded, Evidence: []CausalEvidence{successEvidence}},
		}},
	}, true
}

func addressCounterfactual(t *Target, res map[ProbeID]ProbeResult) (DiagnosisFinding, bool) {
	r, ok := res[ProbeTargetTCP]
	if !ok || r.SelectedIP == nil || len(r.Attempts) < 2 {
		return DiagnosisFinding{}, false
	}
	resolved := res[ProbeDNS].Addrs
	if len(resolved) < 2 {
		return DiagnosisFinding{}, false
	}
	addressEvidence := func(ip net.IP, observation ObservationID) []CausalEvidence {
		return []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeTargetTCP, Observation: observation, Value: ip.String()},
			{Kind: EvidenceSupport, Check: ProbeDNS, Observation: ObservationDNSAnswers, Value: ip.String()},
		}
	}
	success := addressEvidence(r.SelectedIP, ObservationAddressSucceeded)
	var alternatives []CounterfactualAlternative
	var evidence []CausalEvidence
	states := effectiveTargetFamilies(res)
	for _, attempt := range r.Attempts {
		if attempt.Err == nil || attempt.Aborted || attemptCause(attempt) == ConnectionCauseCanceled ||
			attempt.IP.Equal(r.SelectedIP) || !containsResolvedIP(resolved, attempt.IP) || !attemptFamilyReachable(states, attempt.IP) {
			continue
		}
		alternativeEvidence := addressEvidence(attempt.IP, ObservationAddressFailed)
		evidence = append(evidence, alternativeEvidence...)
		alternatives = append(alternatives, CounterfactualAlternative{Value: attempt.IP.String(), Outcome: CounterfactualFailed, Evidence: alternativeEvidence})
	}
	if len(alternatives) == 0 {
		return DiagnosisFinding{}, false
	}
	evidence = append(evidence, success...)
	alternatives = append(alternatives, CounterfactualAlternative{Value: r.SelectedIP.String(), Outcome: CounterfactualSucceeded, Evidence: success})
	summary := "A connection to one address for " + t.Host + " fails, but another succeeds."
	if len(alternatives) > 2 {
		summary = "Connections to multiple addresses for " + t.Host + " fail, but another succeeds."
	}
	return DiagnosisFinding{
		ID: DiagnosisPartialReachability, Verdict: VerdictDegraded, Summary: summary, Focus: ProbeTargetTCP,
		Evidence:       evidence,
		Counterfactual: &Counterfactual{Variable: CounterfactualResolvedAddress, Alternatives: alternatives},
	}, true
}

func familyLabel(family string) string {
	if family == counterfactualIPv4 {
		return "IPv4"
	}
	return "IPv6"
}

// attemptFamilyReachable reports whether the attempt's address family is proved
// reachable. A failure inside a family that is itself down is explained by the
// family counterfactual, so it must not also surface as a sick backend address.
func attemptFamilyReachable(families FamilyConnectivity, ip net.IP) bool {
	if ip.To4() != nil {
		return families.IPv4 == FamilyReachable
	}
	return families.IPv6 == FamilyReachable
}

func containsResolvedIP(ips []net.IP, want net.IP) bool {
	return slices.ContainsFunc(ips, func(ip net.IP) bool { return ip.Equal(want) })
}

func attemptCause(a Attempt) string {
	if a.Cause != "" {
		return a.Cause
	}
	return ConnectionFailureCause(a.Err)
}

func familyAttemptsAllRefused(r ProbeResult, ipv4 bool) bool {
	seen := false
	for _, attempt := range r.Attempts {
		if (attempt.IP.To4() != nil) != ipv4 || attempt.Err == nil || attempt.Aborted {
			continue
		}
		seen = true
		if attemptCause(attempt) != ConnectionCauseRefused {
			return false
		}
	}
	return seen
}

// effectiveTargetFamilies suppresses an apparent target-family failure when
// the independent egress probe did not prove that the host has a usable path
// for that family. A refusal is the exception because a peer answered it.
func effectiveTargetFamilies(res map[ProbeID]ProbeResult) FamilyConnectivity {
	target := res[ProbeTargetTCP]
	if target.Families == nil {
		return FamilyConnectivity{}
	}
	out := *target.Families
	internet := res[ProbeInternet].Families
	if out.IPv4 == FamilyUnreachable && (internet == nil || internet.IPv4 != FamilyReachable) && !familyAttemptsAllRefused(target, true) {
		out.IPv4 = ""
	}
	if out.IPv6 == FamilyUnreachable && (internet == nil || internet.IPv6 != FamilyReachable) && !familyAttemptsAllRefused(target, false) {
		out.IPv6 = ""
	}
	return out
}

// reconcileCounterfactuals makes only proved target-family degradation visible
// on the existing target row. It never changes a total failure into a warning.
func reconcileCounterfactuals(res map[ProbeID]ProbeResult) {
	r, ok := res[ProbeTargetTCP]
	if !ok || r.Families == nil {
		return
	}
	states := effectiveTargetFamilies(res)
	if states.IPv4 == "" && states.IPv6 == "" {
		r.Families = nil
	} else {
		r.Families = &states
	}
	if r.SelectedIP != nil && ((states.IPv4 == FamilyReachable && states.IPv6 == FamilyUnreachable) ||
		(states.IPv6 == FamilyReachable && states.IPv4 == FamilyUnreachable)) {
		failed, succeeded := counterfactualIPv6, counterfactualIPv4
		if states.IPv4 == FamilyUnreachable {
			failed, succeeded = counterfactualIPv4, counterfactualIPv6
		}
		r.Status = StatusWarn
		r.Detail += "; warning: " + familyLabel(failed) + " target connectivity failed while " + familyLabel(succeeded) + " succeeded"
	}
	res[ProbeTargetTCP] = r
}

func isCanceledAttempt(a Attempt) bool {
	return a.Aborted || errors.Is(a.Err, context.Canceled) || attemptCause(a) == ConnectionCauseCanceled
}
