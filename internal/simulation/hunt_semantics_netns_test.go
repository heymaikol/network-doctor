//go:build netns_integration

package simulation

import (
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func TestSemanticOracleNamespaceEvidence(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	for _, tc := range []struct {
		scenario   string
		conditions []NetworkCondition
	}{
		{"healthy", nil},
		{"broken-dns", nil},
		{"dns-nxdomain", []NetworkCondition{ConditionDNSNameNotFound}},
		{"dns-hijacking", []NetworkCondition{ConditionDNSDisagreement}},
		{"connection-refused", []NetworkCondition{ConditionTargetTCPRefused}},
		{"tcp-port-blocked", []NetworkCondition{ConditionTargetTCPUnreachable}},
		{"same-family-failover", []NetworkCondition{ConditionPartialReachability}},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			scenario, err := LibraryScenario(tc.scenario)
			if err != nil {
				t.Fatal(err)
			}
			if tc.scenario == "connection-refused" {
				scenario.Tests = scenario.Tests[:1]
			}
			if tc.scenario == "dns-hijacking" {
				for i := range scenario.Topology.Nodes {
					for j := range scenario.Topology.Nodes[i].Services {
						svc := &scenario.Topology.Nodes[i].Services[j]
						if svc.Name == "hijacking-resolver" {
							// A static split zone remains different after any number of queries.
							svc.DNSFault = nil
							svc.Zone["hijacked-target.test"] = "192.0.2.20"
						}
					}
				}
			}
			report := runScenarioDefinition(t, sim, netdoc, scenario)
			if report.Error != "" {
				t.Fatal(report.Error)
			}
			o := caseObservation(&report, collectObservedTruth(GeneratedCaseManifest{}, &report))
			established := observedConditions(o)
			for _, want := range tc.conditions {
				if !slices.Contains(established, want) {
					t.Fatalf("missing %s in %v; lookups %+v; targets %+v", want, established, report.Evidence.ResolverLookups, report.Evidence.ControlledTargets)
				}
			}
			t.Logf("established=%v recognized=%v missed=%v", established, recognizedConditions(finalClientDiagnosis(&report)), unrecognizedConditions(unrecognizedConditionFindings(&report, o.Truth)))
			if tc.scenario == "healthy" && len(established) > 0 {
				t.Fatalf("healthy condition false positive: %v", established)
			}
			for _, r := range semanticOracle {
				if r.observed(o) && r.contradicted(o) {
					t.Fatalf("self contradiction: %s", r.condition)
				}
			}
		})
	}
}

func TestSemanticOracleScopedFailuresInNamespaces(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	for _, family := range []string{"ipv4", "ipv6", "dns"} {
		t.Run(family, func(t *testing.T) {
			scenario, err := LibraryScenario("dual-stack-healthy")
			if err != nil {
				t.Fatal(err)
			}
			var want NetworkCondition
			switch family {
			case "dns":
				scenario.Faults = []Fault{{Type: FaultScheduledDNS, Service: "dual-resolver", Events: []ScheduledEvent{{At: "0ms", Outcome: DNSOutcomeSERVFAIL}}}}
				want = ConditionSystemDNSFailure
			default:
				address := "10.78.2.20"
				want = ConditionIPv4TargetUnreachable
				if family == "ipv6" {
					address = "2001:db8:77:2::20"
					want = ConditionIPv6TargetUnreachable
				}
				scenario.Faults = []Fault{{Type: FaultDrop, Node: "target", Direction: DirectionInbound, Family: family, To: address, Protocol: "tcp", Port: 80}}
			}
			report := runScenarioDefinition(t, sim, netdoc, scenario)
			truth := collectObservedTruth(GeneratedCaseManifest{}, &report)
			established, recognized, comparable := caseConditions(&report, truth)
			if !comparable || !slices.Contains(established, want) {
				t.Fatalf("not established: %s %v; lookups %+v; targets %+v", want, established, report.Evidence.ResolverLookups, report.Evidence.ControlledTargets)
			}
			t.Logf("established=%v recognized=%v missed=%v", established, recognized, unrecognizedConditions(unrecognizedConditionFindings(&report, truth)))
			// The producer evidence is also capable of rejecting an invented diagnosis,
			// regardless of what the real Network Doctor happened to conclude.
			report.Tests[len(report.Tests)-1].Diagnosis = &Diagnosis{Findings: []DiagnosisFinding{{ID: string(diagnostic.DiagnosisDNSNameNotFound)}}}
			if len(unsupportedConditionFindings(&report, truth)) == 0 {
				t.Fatal("positive DNS answers failed to contradict fabricated name absence")
			}
		})
	}
}
