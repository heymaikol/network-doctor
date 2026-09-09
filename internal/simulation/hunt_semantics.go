package simulation

import (
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

const (
	ConditionSystemDNSFailure      NetworkCondition = "system_dns_failure"
	ConditionDNSNameNotFound       NetworkCondition = "dns_name_not_found"
	ConditionDNSDisagreement       NetworkCondition = "dns_disagreement"
	ConditionTargetTCPRefused      NetworkCondition = "target_tcp_refused"
	ConditionTargetTCPUnreachable  NetworkCondition = "target_tcp_unreachable"
	ConditionIPv4TargetUnreachable NetworkCondition = "ipv4_target_unreachable"
	ConditionIPv6TargetUnreachable NetworkCondition = "ipv6_target_unreachable"
	ConditionPartialReachability   NetworkCondition = "partial_endpoint_reachability"
)

var semanticOracle = []conditionRule{
	{
		condition: ConditionSystemDNSFailure,
		summary:   "system DNS failing to resolve a name that independent DNS resolves",
		evidence:  "two stable client-side lookups through each resolver, for the same test name",
		observed: func(o observation) bool {
			s, p := resolverPair(o)
			return s != nil && p != nil && s.State != lookupAnswered && p.State == lookupAnswered
		},
		recognized:   findingRecognizes(diagnostic.DiagnosisSystemDNSFailure),
		contradicted: func(o observation) bool { s, _ := resolverPair(o); return s != nil && s.State == lookupAnswered },
	},
	{
		condition: ConditionDNSNameNotFound,
		summary:   "both resolvers explicitly reporting no address records for the test name",
		evidence:  "both client-side resolvers returned stable negative answers, not timeouts or SERVFAIL",
		observed: func(o observation) bool {
			s, p := resolverPair(o)
			return s != nil && p != nil && s.State == lookupNotFound && p.State == lookupNotFound
		},
		recognized: findingRecognizes(diagnostic.DiagnosisDNSNameNotFound),
		contradicted: func(o observation) bool {
			s, p := resolverPair(o)
			return s != nil && s.State == lookupAnswered || p != nil && p.State == lookupAnswered
		},
	},
	{
		condition: ConditionDNSDisagreement,
		summary:   "resolvers returning disjoint address answers, or system answers versus independent name absence",
		evidence:  "stable client-side answers for the same name disagree; neither resolver is declared wrong",
		observed: func(o observation) bool {
			s, p := resolverPair(o)
			return s != nil && p != nil && s.State == lookupAnswered && (p.State == lookupNotFound || p.State == lookupAnswered && !overlappingAddresses(s.Addresses, p.Addresses))
		},
		recognized: findingRecognizes(diagnostic.DiagnosisDNSDisagreement),
		contradicted: func(o observation) bool {
			s, p := resolverPair(o)
			return s != nil && p != nil && (s.State == lookupAnswered && p.State == lookupAnswered && slices.Equal(s.Addresses, p.Addresses) || s.State == lookupNotFound && p.State == lookupNotFound)
		},
	},
	{
		condition:  ConditionTargetTCPRefused,
		summary:    "every resolved target address explicitly refusing TCP connections",
		evidence:   "the client's own dials received connection refusals at every address of the target port",
		observed:   func(o observation) bool { return allTargetOutcomes(o, "", TargetStateRefused) },
		recognized: findingRecognizes(diagnostic.DiagnosisTCPConnectionRefused),
		// The finding describes attempted connections. One other successful
		// address need not have been attempted; complete success refutes any
		// subset without borrowing the diagnosis's own address evidence.
		contradicted: func(o observation) bool { return allTargetOutcomes(o, "", FamilyStateReachable) },
	},
	{
		condition: ConditionTargetTCPUnreachable,
		summary:   "all target TCP addresses failing without a refusal while their reference paths work",
		evidence:  "complete client target dials failed without refusal, and independent reference connections succeeded in each target family",
		observed: func(o observation) bool {
			targets := observedTarget(o)
			if len(targets) == 0 {
				return false
			}
			for _, t := range targets {
				if t.Outcome != FamilyStateUnreachable || referenceState(o, t.Family) != FamilyStateReachable {
					return false
				}
			}
			return true
		},
		recognized:   findingRecognizes(diagnostic.DiagnosisTargetUnreachable, diagnostic.DiagnosisLocalDeviceUnreachable),
		contradicted: func(o observation) bool { return targetHasOutcome(o, "", FamilyStateReachable) },
	},
	targetFamilyRule("ipv4", ConditionIPv4TargetUnreachable, diagnostic.DiagnosisIPv4TargetUnreachable),
	targetFamilyRule("ipv6", ConditionIPv6TargetUnreachable, diagnostic.DiagnosisIPv6TargetUnreachable),
	{
		condition: ConditionPartialReachability,
		summary:   "one resolved address failing while another address in the same family accepts TCP",
		evidence:  "complete independent client dials show success and failure among the same target's addresses within one family",
		observed: func(o observation) bool {
			for _, family := range []string{"ipv4", "ipv6"} {
				if targetHasOutcome(o, family, FamilyStateReachable) && (targetHasOutcome(o, family, FamilyStateUnreachable) || targetHasOutcome(o, family, TargetStateRefused)) {
					return true
				}
			}
			return false
		},
		recognized:   findingRecognizes(diagnostic.DiagnosisPartialReachability),
		contradicted: func(o observation) bool { return allTargetOutcomes(o, "", FamilyStateReachable) },
	},
}

func findingRecognizes(ids ...diagnostic.DiagnosisID) func(*Diagnosis) bool {
	return func(d *Diagnosis) bool {
		if d == nil {
			return false
		}
		return slices.ContainsFunc(d.Findings, func(f DiagnosisFinding) bool { return slices.Contains(ids, diagnostic.DiagnosisID(f.ID)) })
	}
}

func caseObservation(report *Report, truth ObservedTruth) observation {
	o := observation{Evidence: report.Evidence, Truth: truth, Client: observedClient(report), StableDNS: true}
	test := finalClientTest(report)
	if test != nil {
		o.Target = test.Target
		o.SourceSegment = test.SourceSegment
	}
	// Repeated final queries cannot reconstruct a changing resolver during the
	// diagnosis. Even a recovered transition leaves that comparison unknown.
	for _, event := range report.Timeline {
		if event.Result == EventApplied && event.Event.Type == FaultScheduledDNS && (test == nil || event.Event.Offset > test.StartOffset) {
			o.StableDNS = false
		}
	}
	outcomes := map[string]string{}
	for _, query := range report.Evidence.DNSQueries {
		key := query.Node + "\x00" + query.Service + "\x00" + query.Name + "\x00" + query.QueryType
		if previous, ok := outcomes[key]; ok && previous != query.ActualOutcome {
			o.StableDNS = false
		}
		outcomes[key] = query.ActualOutcome
	}
	return o
}

func resolverPair(o observation) (system, independent *ResolverLookupEvidence) {
	if !o.StableDNS || o.Client == "" || o.SourceSegment != "" {
		return nil, nil
	}
	name := "connectivitycheck.gstatic.com"
	if o.Target != "" {
		target, err := diagnostic.ParseTarget(o.Target)
		if err != nil || target.IP != nil {
			return nil, nil
		}
		name = target.Host
	}
	get := func(resolver string) *ResolverLookupEvidence {
		var found *ResolverLookupEvidence
		for i := range o.Evidence.ResolverLookups {
			item := &o.Evidence.ResolverLookups[i]
			if item.Node != o.Client || dnsKey(item.Name) != dnsKey(name) || item.Resolver != resolver {
				continue
			}
			if found != nil || !validLookup(*item) {
				return nil
			}
			found = item
		}
		return found
	}
	return get("system"), get("1.1.1.1")
}

func validLookup(item ResolverLookupEvidence) bool {
	if !item.Stable {
		return false
	}
	if item.State == lookupFailed || item.State == lookupNotFound {
		return len(item.Addresses) == 0
	}
	if item.State != lookupAnswered || len(item.Addresses) == 0 {
		return false
	}
	for i, raw := range item.Addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.Zone() != "" || addr.Unmap().String() != raw || i > 0 && item.Addresses[i-1] >= raw {
			return false
		}
	}
	return true
}

func overlappingAddresses(a, b []string) bool {
	return slices.ContainsFunc(a, func(addr string) bool { return slices.Contains(b, addr) })
}

// Complete coverage of the actual system-resolved target is required. Zone
// configuration only selects which controlled ports to dial; it cannot supply
// the addresses a client actually received. Missing or duplicate dials abstain.
func observedTarget(o observation) []ControlledTargetEvidence {
	if o.Client == "" || o.Target == "" || !o.StableDNS || o.SourceSegment != "" {
		return nil
	}
	target, err := diagnostic.ParseTarget(o.Target)
	if err != nil {
		return nil
	}
	var addresses []string
	if target.IP != nil {
		addresses = []string{target.IP.String()}
	} else {
		system, _ := resolverPair(o)
		if system == nil || system.State != lookupAnswered {
			return nil
		}
		addresses = system.Addresses
	}
	var out []ControlledTargetEvidence
	for _, addr := range addresses {
		endpoint := net.JoinHostPort(addr, strconv.Itoa(target.Port))
		var found *ControlledTargetEvidence
		for i := range o.Evidence.ControlledTargets {
			item := &o.Evidence.ControlledTargets[i]
			if item.From != o.Client || item.To != endpoint {
				continue
			}
			ip, err := netip.ParseAddr(addr)
			family := "ipv6"
			if ip.Is4() {
				family = "ipv4"
			}
			if err != nil || found != nil || item.Family != family || (item.Outcome != FamilyStateReachable && item.Outcome != FamilyStateUnreachable && item.Outcome != TargetStateRefused) || item.Reachable != (item.Outcome == FamilyStateReachable) {
				return nil
			}
			found = item
		}
		if found == nil {
			return nil
		}
		out = append(out, *found)
	}
	return out
}

func targetHasOutcome(o observation, family, outcome string) bool {
	return slices.ContainsFunc(observedTarget(o), func(t ControlledTargetEvidence) bool {
		return (family == "" || t.Family == family) && t.Outcome == outcome
	})
}

func allTargetOutcomes(o observation, family, outcome string) bool {
	seen := false
	for _, t := range observedTarget(o) {
		if family != "" && t.Family != family {
			continue
		}
		seen = true
		if t.Outcome != outcome {
			return false
		}
	}
	return seen
}

func referenceState(o observation, family string) string {
	state := ""
	seen := false
	for _, r := range o.Evidence.FamilyReachability {
		if r.Node == o.Client && r.Family == family {
			if seen {
				return ""
			}
			seen = true
			state = r.State
		}
	}
	return state
}

func targetFamilyRule(family string, condition NetworkCondition, id diagnostic.DiagnosisID) conditionRule {
	other := "ipv4"
	if family == other {
		other = "ipv6"
	}
	return conditionRule{condition: condition, family: family,
		summary:  family + " target connections failing while " + other + " succeeds",
		evidence: "complete client target dials show a family contrast; failed-family reference success or explicit refusals establish a usable path",
		observed: func(o observation) bool {
			return targetHasOutcome(o, other, FamilyStateReachable) && !targetHasOutcome(o, family, FamilyStateReachable) &&
				(allTargetOutcomes(o, family, TargetStateRefused) || referenceState(o, family) == FamilyStateReachable && (targetHasOutcome(o, family, FamilyStateUnreachable) || targetHasOutcome(o, family, TargetStateRefused)))
		},
		recognized:   findingRecognizes(id),
		contradicted: func(o observation) bool { return allTargetOutcomes(o, family, FamilyStateReachable) },
	}
}

func unsupportedConditionFindings(report *Report, truth ObservedTruth) []HuntCaseFinding {
	if report == nil || !finalStateComparable(report) {
		return nil
	}
	diagnosis := finalClientDiagnosis(report)
	if diagnosis == nil {
		return nil
	}
	o := caseObservation(report, truth)
	var out []HuntCaseFinding
	for _, rule := range conditionOracle {
		if rule.contradicted == nil || !rule.recognized(diagnosis) || !rule.contradicted(o) {
			continue
		}
		out = append(out, HuntCaseFinding{Category: FindingDiagnosticContradiction, Severity: SeverityHigh, Code: "unsupported_network_condition", Family: rule.family,
			Expected: "independently contradicted", Actual: string(rule.condition), Summary: "The diagnosis claims " + rule.summary + ", but independent client observations contradict that claim.",
			Evidence: "Stable client-side resolver exchanges and complete scoped target dials; missing evidence never establishes a contradiction."})
	}
	return out
}
