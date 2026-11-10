package simulation

import (
	"context"
	"testing"

	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// The healthy dual-stack lab with a target that has addresses in one family
// only, and optionally a gateway that drops one family. The target server is
// healthy in every one of these worlds.
func singleFamilyTargetLab(t *testing.T, target, dropped string) LabScenario {
	t.Helper()
	s, err := FindLabScenario("healthy-dual-stack")
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.Network.Topology.Nodes {
		for j := range s.Network.Topology.Nodes[i].Services {
			svc := &s.Network.Topology.Nodes[i].Services[j]
			if len(svc.Records) == 0 {
				continue
			}
			records := []DNSRecord{{Name: labHost, Address: target}}
			for _, r := range svc.Records {
				if r.Name != labHost {
					records = append(records, r)
				}
			}
			svc.Records = records
		}
	}
	if dropped != "" {
		s.Faults = []LabFault{{ID: "family-drop", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultDrop, Node: "gateway", Direction: DirectionInbound, Family: dropped}}}
	}
	return s
}

// Through the production runner, not a hand-built result map: when the only
// family a target has is the one the gateway drops, egress in the other family
// is no control for it, and a healthy server must not be named as the fault.
func TestLabDoesNotBlameATargetWhoseOnlyFamilyHasNoEgress(t *testing.T) {
	for _, tc := range []struct {
		name, target, dropped, verdict string
		finding                        d.DiagnosisID
	}{
		{"IPv4-only target, IPv4 dropped", labTarget4, "ipv4", d.VerdictNetwork, d.DiagnosisFamilyReachabilityUnlocalized},
		{"IPv6-only target, IPv6 dropped", labTarget6, "ipv6", d.VerdictNetwork, d.DiagnosisFamilyReachabilityUnlocalized},
		{"IPv4-only target, nothing dropped", labTarget4, "", d.VerdictOK, ""},
		{"IPv6-only target, nothing dropped", labTarget6, "", d.VerdictOK, ""},
		{"IPv4-only target, IPv6 dropped", labTarget4, "ipv6", d.VerdictDegraded, d.DiagnosisDirectEgressDegraded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := RunLab(context.Background(), singleFamilyTargetLab(t, tc.target, tc.dropped))
			if err != nil {
				t.Fatal(err)
			}
			snap := r.Views[0].Snapshot
			got, err := d.ReplaySnapshot(snap)
			if err != nil {
				t.Fatal(err)
			}
			var finding d.DiagnosisID
			if len(got.Findings) > 0 {
				finding = got.Findings[0].ID
			}
			if got.Verdict != tc.verdict || finding != tc.finding {
				t.Errorf("verdict = %s, finding = %q, want %s and %q (summary: %s)", got.Verdict, finding, tc.verdict, tc.finding, got.Summary)
			}
			// The sibling QUIC row fails first in this world, and is not the
			// row the sentence is about.
			if tc.finding == d.DiagnosisFamilyReachabilityUnlocalized && got.Blamed != d.ProbeTargetTCP {
				t.Errorf("blamed = %s, want %s", got.Blamed, d.ProbeTargetTCP)
			}
			if problems := ValidateLabEvidence(snap, got); len(problems) > 0 {
				t.Errorf("evidence problems: %v", problems)
			}
		})
	}
}
