package simulation

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func semanticObservation() observation {
	return observation{Client: "client", Target: "example.test:80", StableDNS: true, Evidence: Evidence{
		ResolverLookups: []ResolverLookupEvidence{
			{Node: "client", Name: "example.test.", Resolver: "system", State: lookupAnswered, Addresses: []string{"10.77.0.20"}, Stable: true},
			{Node: "client", Name: "example.test.", Resolver: "1.1.1.1", State: lookupAnswered, Addresses: []string{"10.77.0.20"}, Stable: true},
		},
		ControlledTargets:  []ControlledTargetEvidence{{From: "client", To: "10.77.0.20:80", Family: "ipv4", Outcome: FamilyStateReachable, Reachable: true}},
		FamilyReachability: []FamilyReachabilityEvidence{{Node: "client", Family: "ipv4", State: FamilyStateReachable}, {Node: "client", Family: "ipv6", State: FamilyStateReachable}},
	}}
}

func setLookup(o *observation, index int, state string, addresses ...string) {
	o.Evidence.ResolverLookups[index].State = state
	o.Evidence.ResolverLookups[index].Addresses = addresses
}

func setTarget(o *observation, outcome string) {
	o.Evidence.ControlledTargets[0].Outcome = outcome
	o.Evidence.ControlledTargets[0].Reachable = outcome == FamilyStateReachable
}

func addTarget(o *observation, ip, family, outcome string) {
	o.Evidence.ResolverLookups[0].Addresses = append(o.Evidence.ResolverLookups[0].Addresses, ip)
	slices.Sort(o.Evidence.ResolverLookups[0].Addresses)
	endpoint := ip + ":80"
	if family == "ipv6" {
		endpoint = "[" + ip + "]:80"
	}
	o.Evidence.ControlledTargets = append(o.Evidence.ControlledTargets, ControlledTargetEvidence{From: "client", To: endpoint, Family: family, Outcome: outcome, Reachable: outcome == FamilyStateReachable})
}

func semanticRule(t *testing.T, condition NetworkCondition) conditionRule {
	t.Helper()
	for _, r := range conditionOracle {
		if r.condition == condition {
			return r
		}
	}
	t.Fatalf("missing condition %s", condition)
	return conditionRule{}
}

func TestSemanticOraclePositiveAndRecognitionIsolation(t *testing.T) {
	cases := []struct {
		condition NetworkCondition
		id        diagnostic.DiagnosisID
		setup     func(*observation)
	}{
		{ConditionSystemDNSFailure, diagnostic.DiagnosisSystemDNSFailure, func(o *observation) { setLookup(o, 0, lookupFailed) }},
		{ConditionDNSNameNotFound, diagnostic.DiagnosisDNSNameNotFound, func(o *observation) { setLookup(o, 0, lookupNotFound); setLookup(o, 1, lookupNotFound) }},
		{ConditionDNSDisagreement, diagnostic.DiagnosisDNSDisagreement, func(o *observation) { setLookup(o, 1, lookupAnswered, "10.77.0.21") }},
		{ConditionTargetTCPRefused, diagnostic.DiagnosisTCPConnectionRefused, func(o *observation) { setTarget(o, TargetStateRefused) }},
		{ConditionTargetTCPUnreachable, diagnostic.DiagnosisTargetUnreachable, func(o *observation) { setTarget(o, FamilyStateUnreachable) }},
		{ConditionIPv4TargetUnreachable, diagnostic.DiagnosisIPv4TargetUnreachable, func(o *observation) {
			setTarget(o, FamilyStateUnreachable)
			addTarget(o, "fd77::20", "ipv6", FamilyStateReachable)
		}},
		{ConditionIPv6TargetUnreachable, diagnostic.DiagnosisIPv6TargetUnreachable, func(o *observation) { addTarget(o, "fd77::20", "ipv6", FamilyStateUnreachable) }},
		{ConditionPartialReachability, diagnostic.DiagnosisPartialReachability, func(o *observation) { addTarget(o, "10.77.0.21", "ipv4", TargetStateRefused) }},
	}
	for _, tc := range cases {
		t.Run(string(tc.condition), func(t *testing.T) {
			o := semanticObservation()
			tc.setup(&o)
			rule := semanticRule(t, tc.condition)
			if !rule.observed(o) || rule.contradicted(o) {
				t.Fatal("positive not established, or contradicts itself")
			}
			if !rule.recognized(&Diagnosis{Findings: []DiagnosisFinding{{ID: string(tc.id)}}}) {
				t.Fatal("stable finding not recognized")
			}
			if rule.recognized(nil) || rule.recognized(&Diagnosis{Checks: []DiagnosisCheck{{Status: "FAIL", Cause: string(tc.id)}}}) {
				t.Fatal("probe failure substituted for diagnosis")
			}
			for _, other := range cases {
				if other.id == tc.id {
					continue
				}
				if rule.recognized(&Diagnosis{Findings: []DiagnosisFinding{{ID: string(other.id)}}}) {
					t.Fatalf("different diagnosis %s recognized", other.id)
				}
			}
			for _, id := range []diagnostic.DiagnosisID{diagnostic.DiagnosisOffline, diagnostic.DiagnosisDNSFailure, diagnostic.DiagnosisTLSHandshakeFailure, diagnostic.DiagnosisSelectedNetworkCheckFailed} {
				if rule.recognized(&Diagnosis{Findings: []DiagnosisFinding{{ID: string(id)}}}) {
					t.Fatalf("weaker diagnosis %s recognized", id)
				}
			}
			for _, alter := range []func(*observation){
				func(o *observation) { o.Evidence = Evidence{} },
				func(o *observation) { o.Client = "other" },
				func(o *observation) { o.Target = "other.test:80" },
				func(o *observation) { o.StableDNS = false },
				func(o *observation) { o.SourceSegment = "alternate" },
				func(o *observation) {
					o.Evidence.ResolverLookups[0].Stable = false
					o.Evidence.ResolverLookups[1].Stable = false
				},
			} {
				copy := cloneObservation(t, o)
				alter(&copy)
				if rule.observed(copy) || rule.contradicted(copy) {
					t.Fatal("missing, wrong-scope, or unstable evidence classified")
				}
			}
			report := oracleReport(&Diagnosis{}, o.Evidence)
			report.Tests[0].Target = o.Target
			if !slices.Contains(unrecognizedConditions(unrecognizedConditionFindings(report, ObservedTruth{})), string(tc.condition)) {
				t.Fatal("analyzer did not report missed condition")
			}
			report.Tests[0].Diagnosis = &Diagnosis{Findings: []DiagnosisFinding{{ID: string(tc.id)}}}
			if slices.Contains(unrecognizedConditions(unrecognizedConditionFindings(report, ObservedTruth{})), string(tc.condition)) {
				t.Fatal("recognized condition reported missed")
			}
		})
	}
}

func cloneObservation(t *testing.T, o observation) observation {
	t.Helper()
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var out observation
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSemanticOracleConfounders(t *testing.T) {
	cases := []struct {
		name      string
		condition NetworkCondition
		setup     func(*observation)
	}{
		{"DNS timeout is not absence", ConditionDNSNameNotFound, func(o *observation) { setLookup(o, 0, lookupFailed); setLookup(o, 1, lookupFailed) }},
		{"one negative resolver", ConditionDNSNameNotFound, func(o *observation) { setLookup(o, 0, lookupNotFound) }},
		{"both resolvers fail", ConditionSystemDNSFailure, func(o *observation) { setLookup(o, 0, lookupFailed); setLookup(o, 1, lookupFailed) }},
		{"mismatch does not blame system", ConditionSystemDNSFailure, func(o *observation) { setLookup(o, 1, lookupAnswered, "10.77.0.21") }},
		{"overlap not material disagreement", ConditionDNSDisagreement, func(o *observation) { setLookup(o, 1, lookupAnswered, "10.77.0.20", "10.77.0.21") }},
		{"independent resolver unavailable", ConditionDNSDisagreement, func(o *observation) { setLookup(o, 1, lookupFailed) }},
		{"refusal is not silence", ConditionTargetTCPUnreachable, func(o *observation) { setTarget(o, TargetStateRefused) }},
		{"timeout is not refusal", ConditionTargetTCPRefused, func(o *observation) { setTarget(o, FamilyStateUnreachable) }},
		{"dead family not target silence", ConditionTargetTCPUnreachable, func(o *observation) {
			setTarget(o, FamilyStateUnreachable)
			o.Evidence.FamilyReachability[0].State = FamilyStateUnreachable
		}},
		{"uninspected family not target silence", ConditionTargetTCPUnreachable, func(o *observation) { setTarget(o, FamilyStateUnreachable); o.Evidence.FamilyReachability = nil }},
		{"one refusal among successes", ConditionTargetTCPRefused, func(o *observation) {
			setTarget(o, TargetStateRefused)
			addTarget(o, "10.77.0.21", "ipv4", FamilyStateReachable)
		}},
		{"missing dial cannot prove all refused", ConditionTargetTCPRefused, func(o *observation) {
			setTarget(o, TargetStateRefused)
			setLookup(o, 0, lookupAnswered, "10.77.0.20", "10.77.0.21")
		}},
		{"duplicate dial ambiguous", ConditionTargetTCPRefused, func(o *observation) {
			setTarget(o, TargetStateRefused)
			o.Evidence.ControlledTargets = append(o.Evidence.ControlledTargets, o.Evidence.ControlledTargets[0])
		}},
		{"wrong port", ConditionTargetTCPRefused, func(o *observation) { setTarget(o, TargetStateRefused); o.Target = "example.test:81" }},
		{"inconsistent reachable flag", ConditionTargetTCPRefused, func(o *observation) {
			setTarget(o, TargetStateRefused)
			o.Evidence.ControlledTargets[0].Reachable = true
		}},
		{"cross family not backend failure", ConditionPartialReachability, func(o *observation) { addTarget(o, "fd77::20", "ipv6", FamilyStateUnreachable) }},
		{"failed family never usable", ConditionIPv6TargetUnreachable, func(o *observation) {
			addTarget(o, "fd77::20", "ipv6", FamilyStateUnreachable)
			o.Evidence.FamilyReachability[1].State = FamilyStateUnreachable
		}},
		{"wrong family", ConditionIPv4TargetUnreachable, func(o *observation) { addTarget(o, "fd77::20", "ipv6", FamilyStateUnreachable) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := semanticObservation()
			tc.setup(&o)
			if semanticRule(t, tc.condition).observed(o) {
				t.Fatal("confounder established condition")
			}
		})
	}
}

func TestUnsupportedDiagnosesRequirePositiveContradictions(t *testing.T) {
	for _, rule := range semanticOracle {
		t.Run(string(rule.condition), func(t *testing.T) {
			o := semanticObservation()
			// A complete healthy dual-stack target disproves either family failure.
			addTarget(&o, "fd77::20", "ipv6", FamilyStateReachable)
			setLookup(&o, 1, lookupAnswered, "10.77.0.20", "fd77::20")
			if !rule.contradicted(o) {
				t.Fatal("healthy observation did not refute claim")
			}
			id := string(rule.condition)
			switch rule.condition {
			case ConditionTargetTCPRefused:
				id = string(diagnostic.DiagnosisTCPConnectionRefused)
			case ConditionTargetTCPUnreachable:
				id = string(diagnostic.DiagnosisTargetUnreachable)
			}
			report := oracleReport(&Diagnosis{Findings: []DiagnosisFinding{{ID: id}}}, o.Evidence)
			report.Tests[0].Target = o.Target
			got := unsupportedConditionFindings(report, ObservedTruth{})
			if !slices.ContainsFunc(got, func(f HuntCaseFinding) bool { return f.Actual == string(rule.condition) }) {
				t.Fatalf("missing contradiction: %+v", got)
			}
			report.Evidence = Evidence{}
			if got := unsupportedConditionFindings(report, ObservedTruth{}); len(got) != 0 {
				t.Fatalf("unknown accused diagnosis: %+v", got)
			}
		})
	}
}

func TestSemanticOracleTemporalAndFinalTargetScope(t *testing.T) {
	o := semanticObservation()
	setLookup(&o, 0, lookupFailed)
	report := oracleReport(&Diagnosis{}, o.Evidence)
	report.Tests[0].Target = o.Target
	for _, alter := range []func(*Report){
		func(r *Report) {
			r.Timeline = []FaultEventEvidence{{Result: EventApplied, Event: TimedEvent{Type: FaultScheduledDNS, Offset: 1}}}
		},
		func(r *Report) {
			r.Evidence.DNSQueries = []DNSQueryEvidence{{Node: "dns", Name: "x", QueryType: "A", ActualOutcome: "ANSWER"}, {Node: "dns", Name: "x", QueryType: "A", ActualOutcome: "SERVFAIL"}}
		},
		func(r *Report) {
			r.Tests = append(r.Tests, TestOutcome{Node: "client", Target: "other.test:80", Diagnosis: &Diagnosis{}})
		},
	} {
		data, _ := json.Marshal(report)
		var copy Report
		if err := json.Unmarshal(data, &copy); err != nil {
			t.Fatal(err)
		}
		alter(&copy)
		if slices.Contains(unrecognizedConditions(unrecognizedConditionFindings(&copy, ObservedTruth{})), string(ConditionSystemDNSFailure)) {
			t.Fatal("noncomparable DNS accused")
		}
	}
}

func TestInternetFamilyDoesNotReadTargetFamilies(t *testing.T) {
	d := &Diagnosis{Checks: []DiagnosisCheck{{ID: string(diagnostic.ProbeTargetTCP), Families: &DiagnosisFamilies{IPv4: FamilyStateUnreachable}}}}
	if diagnosedFamily(d, "ipv4") != "" {
		t.Fatal("target failure was promoted to internet failure")
	}
}

func TestReverseCoverageSeparatesUnknownFromContradicted(t *testing.T) {
	o := semanticObservation()
	diagnosis := &Diagnosis{Findings: []DiagnosisFinding{{ID: string(diagnostic.DiagnosisDNSNameNotFound)}}}
	report := oracleReport(diagnosis, o.Evidence)
	report.Tests[0].Target = o.Target
	unknown := oracleReport(diagnosis, Evidence{})
	unknown.Tests[0].Target = o.Target
	coverage := huntCoverageFor(HuntGeneratorVersion, HuntLaneBugOracle, "healthy", []HuntCaseResult{
		{Status: "findings", Report: report}, {Status: "clean", Report: unknown},
	})
	for _, c := range coverage.Conditions {
		if c.Condition != ConditionDNSNameNotFound {
			continue
		}
		if c.Claimed != 2 || c.Contradicted != 1 || c.Unverified != 1 || c.Established != 0 {
			t.Fatalf("reverse coverage %+v", c)
		}
		return
	}
	t.Fatal("condition absent from coverage")
}

func TestResolverHistoryDetectsExhaustedSchedules(t *testing.T) {
	history := []DNSQueryEvidence{{Node: "r", Service: "dns", Name: "example.test", QueryType: "A", ActualOutcome: "WRONG_ANSWER"}}
	if !resolverHistoryStable(history, "example.test") {
		t.Fatal("stable history rejected")
	}
	history = append(history, DNSQueryEvidence{Node: "r", Service: "dns", Name: "example.test", QueryType: "A", ActualOutcome: "ANSWER"})
	if resolverHistoryStable(history, "example.test") {
		t.Fatal("exhausted schedule compared as permanent split DNS")
	}
	if !resolverHistoryStable(history, "other.test") {
		t.Fatal("unrelated name poisoned history")
	}
}

func TestSemanticDNSNegativeAndSplitDistinctions(t *testing.T) {
	o := semanticObservation()
	setLookup(&o, 0, lookupNotFound)
	if !semanticRule(t, ConditionSystemDNSFailure).observed(o) {
		t.Fatal("system negative versus public success missed")
	}
	setLookup(&o, 0, lookupAnswered, "10.77.0.20")
	setLookup(&o, 1, lookupNotFound)
	if !semanticRule(t, ConditionDNSDisagreement).observed(o) || semanticRule(t, ConditionSystemDNSFailure).observed(o) {
		t.Fatal("split DNS blamed system")
	}
	for _, bad := range []ResolverLookupEvidence{
		{Stable: true, State: lookupAnswered},
		{Stable: true, State: lookupNotFound, Addresses: []string{"10.77.0.20"}},
		{Stable: true, State: lookupAnswered, Addresses: []string{"not-an-address"}},
		{Stable: true, State: lookupAnswered, Addresses: []string{"10.77.0.20", "10.77.0.20"}},
		{Stable: true, State: "unknown"},
	} {
		if validLookup(bad) {
			t.Fatalf("malformed evidence accepted: %+v", bad)
		}
	}
}

func TestHolderLookupRejectsMalformedRequestsWithoutNetworking(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"Name":"x","Resolver":"hostname"}`, `{"Name":"x\nprobe","Resolver":"system"}`, `{"Name":"x","Resolver":"fe80::1%eth0"}`} {
		if got := holderLookupReply(raw); got != "lookup-result error" {
			t.Fatalf("request %q accepted: %s", raw, got)
		}
	}
}

func TestRefusedAttemptsAreNotRefutedByAnUnrelatedSuccessfulAddress(t *testing.T) {
	o := semanticObservation()
	addTarget(&o, "10.77.0.21", "ipv4", TargetStateRefused)
	if semanticRule(t, ConditionTargetTCPRefused).contradicted(o) {
		t.Fatal("a successful address outside a possibly refused attempted subset is not a contradiction")
	}
}
