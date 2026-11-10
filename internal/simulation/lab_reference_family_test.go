package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
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
			// The published artifact: valid as written, and the same answer
			// after support sanitization, a JSON round trip and a replay.
			if err := snapshot.Validate(snap); err != nil {
				t.Fatalf("snapshot: %v", err)
			}
			clean := snapshot.SanitizeForSupport(snap)
			if err := snapshot.Validate(clean); err != nil {
				t.Fatalf("sanitized snapshot: %v", err)
			}
			data, err := json.Marshal(clean)
			if err != nil {
				t.Fatal(err)
			}
			var back snapshot.Snapshot
			if err := json.Unmarshal(data, &back); err != nil {
				t.Fatal(err)
			}
			replayed, err := d.ReplaySnapshot(back)
			if err != nil {
				t.Fatalf("sanitized replay: %v", err)
			}
			if replayed.Verdict != got.Verdict || replayed.Blamed != got.Blamed || len(replayed.Findings) != len(got.Findings) ||
				len(got.Findings) > 0 && replayed.Findings[0].ID != got.Findings[0].ID {
				t.Errorf("sanitized replay = %s %s %+v, want %s %s %+v", replayed.Verdict, replayed.Blamed, replayed.Findings, got.Verdict, got.Blamed, got.Findings)
			}
		})
	}
}

// The oracle is held to hand-written findings and not to whatever the engine
// produces today, so it keeps failing the claim it exists to catch after the
// engine has stopped making it.
func TestLabOracleRejectsAControlFromAnotherFamily(t *testing.T) {
	failed := func(cause string, addrs ...string) []d.Attempt {
		var out []d.Attempt
		for _, addr := range addrs {
			out = append(out, d.Attempt{IP: net.ParseIP(addr), Err: errors.New(cause), Cause: cause})
		}
		return out
	}
	v4Dead := &d.FamilyConnectivity{IPv4: d.FamilyUnreachable, IPv6: d.FamilyReachable}
	bothUp := &d.FamilyConnectivity{IPv4: d.FamilyReachable, IPv6: d.FamilyReachable}
	egressAsAWhole := []d.CausalEvidence{
		{Kind: d.EvidenceSupport, Check: d.ProbeInternet, Observation: d.ObservationStatusPass},
		{Kind: d.EvidenceRuledOut, Check: d.ProbeInternet, Observation: d.ObservationStatusPass, Candidate: d.DiagnosisLocalEgressFailure},
	}
	perFamily := []d.CausalEvidence{
		{Kind: d.EvidenceSupport, Check: d.ProbeInternet, Observation: d.ObservationFamilyFailed, Value: "ipv4"},
		{Kind: d.EvidenceSupport, Check: d.ProbeInternet, Observation: d.ObservationFamilyReachable, Value: "ipv6"},
	}
	for _, tc := range []struct {
		name     string
		focus    d.ProbeID
		row      d.ProbeResult
		families *d.FamilyConnectivity
		evidence []d.CausalEvidence
		rejected bool
		answered string // the address the target's plain-HTTP row reached, if it passed
	}{
		{"silent IPv4-only target read against IPv6-only egress", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, egressAsAWhole, true, ""},
		{"silent IPv4-only QUIC endpoint read against IPv6-only egress", d.ProbeQUIC, d.ProbeResult{Status: d.StatusFail, Cause: d.QUICCauseTimeout, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, egressAsAWhole, true, ""},
		{"the same silence as a real dialer records it, cut off at the probe deadline", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: []d.Attempt{{IP: net.ParseIP("203.0.113.10"), Err: context.DeadlineExceeded, Cause: d.ConnectionCauseTimeout, Aborted: true}}}, v4Dead, egressAsAWhole, true, ""},
		{"an explicitly canceled attempt in the other family is not a second family tried", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: append(failed(d.ConnectionCauseTimeout, "203.0.113.10"), d.Attempt{IP: net.ParseIP("2001:db8::10"), Err: context.Canceled, Cause: d.ConnectionCauseCanceled, Aborted: true})}, v4Dead, egressAsAWhole, true, ""},
		{"the same target, citing what egress measured per family", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, perFamily, false, ""},
		{"a refusal is a peer answering in that family", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Cause: d.ConnectionCauseRefused, Attempts: failed(d.ConnectionCauseRefused, "203.0.113.10")}, v4Dead, egressAsAWhole, false, ""},
		{"one refused address beside a silent one is a peer answering too", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: append(failed(d.ConnectionCauseRefused, "203.0.113.10"), failed(d.ConnectionCauseTimeout, "203.0.113.11")...)}, v4Dead, egressAsAWhole, false, ""},
		{"the target answering plain HTTP in that family is a reference too", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, egressAsAWhole, false, "203.0.113.10"},
		{"plain HTTP answering in the other family is not", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, egressAsAWhole, true, "2001:db8::10"},
		{"plain HTTP says nothing about a QUIC endpoint", d.ProbeQUIC, d.ProbeResult{Status: d.StatusFail, Cause: d.QUICCauseTimeout, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, v4Dead, egressAsAWhole, true, "203.0.113.10"},
		{"a target tried in both families has a reference in one", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10", "2001:db8::10")}, v4Dead, egressAsAWhole, false, ""},
		{"egress reached the target's family", d.ProbeTargetTCP, d.ProbeResult{Status: d.StatusFail, Attempts: failed(d.ConnectionCauseTimeout, "203.0.113.10")}, bothUp, egressAsAWhole, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := map[d.ProbeID]d.ProbeResult{
				d.ProbeInternet: {Status: d.StatusPass, Families: tc.families},
				tc.focus:        tc.row,
			}
			probes := []d.Probe{{ID: d.ProbeInternet}, {ID: tc.focus}}
			if tc.answered != "" {
				res[d.ProbeHTTP] = d.ProbeResult{Status: d.StatusPass, SelectedIP: net.ParseIP(tc.answered)}
				probes = append(probes, d.Probe{ID: d.ProbeHTTP})
			}
			snap := d.BuildSnapshot(nil, probes, res)
			finding := d.DiagnosisFinding{ID: d.DiagnosisTargetUnreachable, Verdict: d.VerdictService, Focus: tc.focus, Evidence: tc.evidence}
			rejected := false
			for _, p := range ValidateLabEvidence(snap, d.Diagnosis{Verdict: d.VerdictService, Blamed: tc.focus, Findings: []d.DiagnosisFinding{finding}}) {
				rejected = rejected || strings.Contains(p, "against egress that failed over ipv4")
			}
			if rejected != tc.rejected {
				t.Errorf("rejected = %v, want %v", rejected, tc.rejected)
			}
		})
	}
}
