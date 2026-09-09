// The direct-egress row dials a fixed pair of anycast reference addresses. What
// it can prove is therefore a statement about those addresses, and these tests
// hold the interpretation pass to it: a reference failure may not be promoted
// into a claim about egress in general that another observation in the same run
// contradicts, nor into a claim about where a path breaks that no observation
// supports. The conclusions local route state genuinely does prove are pinned
// here too, so correcting the overreach cannot quietly cost them.

package diagnostic

import (
	"net"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// blanketClaims are the sentences a failed reference sample cannot carry:
// egress as a whole, or a located break. The prose is checked as well as the
// finding because the summary is the surface most users read, and a correct
// identity underneath does not excuse a sentence that says more than the run
// observed.
var blanketClaims = []string{
	"direct internet egress is blocked",
	"the general internet is",
	"no working network egress",
	"local egress problem",
}

func assertNoBlanketClaim(t *testing.T, where, summary string) {
	t.Helper()
	lower := strings.ToLower(summary)
	for _, claim := range blanketClaims {
		if strings.Contains(lower, claim) {
			t.Errorf("%s: %q asserts %q, which failing to reach the reference endpoints does not establish", where, summary, claim)
		}
	}
}

func hasEvidenceItem(evidence []CausalEvidence, want CausalEvidence) bool {
	for _, e := range evidence {
		if e == want {
			return true
		}
	}
	return false
}

// TestReachedTargetRefutesABlockedEgressVerdict is the counterexample the whole
// distinction rests on: the fixed reference endpoints are unreachable while an
// unrelated public destination answers a direct connection on the same run.
// That success is not a mitigating detail, it is a refutation, so the run may
// report the reference endpoints as unreachable and nothing more.
func TestReachedTargetRefutesABlockedEgressVerdict(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTP, ProbeHTTPS}
	build := func() map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeIface: {Status: StatusPass},
			ProbeInternet: {
				Status: StatusFail,
				Detail: "no direct TCP egress to 1.1.1.1, 8.8.8.8 (port 443)",
				Fix:    egressFix,
			},
			ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
			ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("93.184.216.34")},
			ProbeTLS:       {Status: StatusPass},
			ProbeHTTP:      {Status: StatusPass},
			ProbeHTTPS:     {Status: StatusPass},
		}
	}

	// Both shapes of the same run: the raw failure, and the WARN the
	// cross-probe pass leaves once another path has proved the network usable.
	// The verdict must not depend on which pass a caller looks at.
	for _, tc := range []struct {
		name string
		// finalize runs the cross-probe pass, which relaxes the egress failure
		// to a WARN once another path has proved the network usable. The
		// verdict must not depend on which pass a caller looks at.
		finalize bool
		// targetStatus is the state the endpoint row reported. A slow target
		// still answered, so it refutes the blocked reading just as a clean
		// one does, and the recorded evidence has to say so either way.
		targetStatus Status
	}{
		{"raw failure", false, StatusPass},
		{"after Finalize", true, StatusPass},
		{"target answered but degraded", true, StatusWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := build()
			endpoint := res[ProbeTargetTCP]
			endpoint.Status = tc.targetStatus
			res[ProbeTargetTCP] = endpoint
			if tc.finalize {
				Finalize(res)
			}
			d := Interpret(target, order, res)
			assertNoBlanketClaim(t, "summary", d.Summary)
			if len(d.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", d.Findings)
			}
			f := d.Findings[0]
			if f.ID == DiagnosisDirectEgressBlocked {
				t.Errorf("finding is %q while a public destination answered a direct connection in the same run", f.ID)
			}
			if f.Focus != ProbeInternet {
				t.Errorf("focus = %q, want the egress row that actually failed", f.Focus)
			}
			if d.Verdict != VerdictDegraded {
				t.Errorf("verdict = %q, want %q: the run is impaired, not broken", d.Verdict, VerdictDegraded)
			}
			// The refutation has to be recorded, not merely obeyed: the
			// evidence model is where a reader checks why the stronger
			// conclusion was not taken.
			reached := ObservationStatusPass
			if tc.targetStatus == StatusWarn {
				reached = ObservationStatusWarn
			}
			ruledOut := CausalEvidence{
				Kind: EvidenceRuledOut, Check: ProbeTargetTCP,
				Observation: reached, Candidate: DiagnosisDirectEgressBlocked,
			}
			if !hasEvidenceItem(f.Evidence, ruledOut) {
				t.Errorf("evidence %+v does not rule out %q from the target's success", f.Evidence, DiagnosisDirectEgressBlocked)
			}
			// Evidence must be narrowed, never dropped.
			if !strings.Contains(res[ProbeInternet].Detail, "1.1.1.1") {
				t.Errorf("egress detail lost the endpoints it tried: %q", res[ProbeInternet].Detail)
			}
			if strings.Contains(res[ProbeInternet].Fix, "no internet egress") {
				t.Errorf("egress row hint %q claims there is no internet egress, which this run refuted", res[ProbeInternet].Fix)
			}
		})
	}
}

// TestBothPathsFailingDoesNotLocateTheBreak is the ambiguous case. The
// reference endpoints and the endpoint under test both failed, and nothing
// looked at local routing state, so the run has a correlation and no location.
// It may say what did not answer; it may not say whose fault that is.
func TestBothPathsFailingDoesNotLocateTheBreak(t *testing.T) {
	remote := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	device := &Target{Host: "192.168.1.10", IP: net.ParseIP("192.168.1.10"), Port: 9100, Proto: ProtoNone}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}

	for _, tc := range []struct {
		name   string
		target *Target
		dns    ProbeResult
	}{
		{"public target", remote, ProbeResult{Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}}},
		{"device on the local network", device, ProbeResult{Status: StatusNA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				ProbeIface:     {Status: StatusPass},
				ProbeInternet:  {Status: StatusFail, Detail: "no direct TCP egress to 1.1.1.1, 8.8.8.8 (port 443)"},
				ProbeDNS:       tc.dns,
				ProbeTargetTCP: {Status: StatusFail},
			}
			d := Interpret(tc.target, order, res)
			assertNoBlanketClaim(t, "summary", d.Summary)
			if len(d.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", d.Findings)
			}
			f := d.Findings[0]
			if f.ID == DiagnosisLocalEgressFailure {
				t.Errorf("finding is %q, but nothing in this run observed where the path breaks", f.ID)
			}
			if f.Confidence == ConfidenceHigh {
				t.Errorf("confidence = %q for a conclusion with no localizing observation", f.Confidence)
			}
			// The observation itself still has to survive: both rows failed and
			// the report must keep saying so.
			for _, id := range []ProbeID{ProbeInternet, ProbeTargetTCP} {
				if !hasEvidenceItem(f.Evidence, CausalEvidence{Kind: EvidenceSupport, Check: id, Observation: ObservationStatusFail}) {
					t.Errorf("evidence %+v drops the observed failure of %q", f.Evidence, id)
				}
			}
			if rem, ok := Remediate(d, res, "linux"); ok && strings.Contains(rem.Why, "Nothing this machine sends is arriving anywhere") {
				t.Errorf("remediation states a located failure the run did not observe: %q", rem.Why)
			}
		})
	}
}

// TestObservedRouteStateStillLocatesTheBreak is the other half of the rule.
// A missing usable default or an unresolved gateway adds a local observation
// beyond route selection metadata and failed connections, so
// the stronger conclusion and its route-specific repair must both survive.
func TestObservedRouteStateStillLocatesTheBreak(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	for _, tc := range []struct {
		cause  string
		want   RemediationID
		routes []defaultRouteState
	}{
		{RouteCauseNoDefaultRoute, RemedyRestoreDefaultRoute, nil},
		{RouteCauseGatewayUnreachable, RemedyReachGateway, []defaultRouteState{{iface: "eth0", gateway: net.ParseIP("192.0.2.1"), metric: 100}}},
		{RouteCauseGatewayUnreachable, RemedyReachGateway, []defaultRouteState{{iface: "eth0", gateway: net.ParseIP("192.0.2.1"), metric: 100}, {iface: "eth1", gateway: net.ParseIP("192.0.2.2"), metric: 200}}},
	} {
		t.Run(tc.cause, func(t *testing.T) {
			cause := classifyDefaultRoutes(tc.routes, func(r defaultRouteState) bool { return r.gateway.Equal(net.ParseIP("192.0.2.1")) })
			if cause != tc.cause {
				t.Fatalf("cause = %q, want %q", cause, tc.cause)
			}
			res := map[ProbeID]ProbeResult{
				ProbeIface:     {Status: StatusPass},
				ProbeInternet:  {Status: StatusFail, Cause: cause},
				ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
				ProbeTargetTCP: {Status: StatusFail},
			}
			d := Interpret(target, order, res)
			if len(d.Findings) != 1 || d.Findings[0].ID != DiagnosisLocalEgressFailure {
				t.Fatalf("findings = %+v, want %q kept where route state proves it", d.Findings, DiagnosisLocalEgressFailure)
			}
			if rem, ok := Remediate(d, res, "linux"); !ok || rem.ID != tc.want {
				t.Errorf("remediation = %q (ok=%v), want %q", rem.ID, ok, tc.want)
			}
		})
	}
}

// Selection metadata must not change the conclusion without a new observation.
func TestRouteSelectionDoesNotLocateFailure(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		routes := []defaultRouteState{{iface: "eth0", gateway: net.ParseIP("192.0.2.1"), metric: 100}}
		wantCause := RouteCauseSelectedPathFailed
		if multiple {
			routes = append(routes, defaultRouteState{iface: "eth1", gateway: net.ParseIP("192.0.2.2"), metric: 200})
			wantCause = RouteCausePreferredPathFailed
		}
		cause := classifyDefaultRoutes(routes, func(defaultRouteState) bool { return false })
		if cause != wantCause {
			t.Fatalf("cause = %q, want %q", cause, wantCause)
		}
		for _, host := range []string{"example.com", "192.168.1.10"} {
			t.Run(cause+"/"+host, func(t *testing.T) {
				target := &Target{Host: host, IP: net.ParseIP(host), Port: 443, Proto: ProtoNone}
				order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
				probes := make([]Probe, len(order))
				for i, id := range order {
					probes[i] = Probe{ID: id, Name: string(id)}
				}
				var control Diagnosis
				for _, observed := range []string{"", cause} {
					res := map[ProbeID]ProbeResult{
						ProbeIface:     {Status: StatusPass},
						ProbeInternet:  {Status: StatusFail, Cause: observed, Fix: routeFix(cause)},
						ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
						ProbeTargetTCP: {Status: StatusFail},
					}
					d := Interpret(target, order, res)
					if len(d.Findings) != 1 || d.Findings[0].ID != DiagnosisReachabilityUnlocalized {
						t.Fatalf("cause %q: findings = %+v, want unlocalized", observed, d.Findings)
					}
					if d.Findings[0].Confidence != ConfidenceInsufficientEvidence {
						t.Fatalf("confidence = %s", d.Findings[0].Confidence)
					}
					assertNoBlanketClaim(t, "summary", d.Summary)
					if rem, ok := Remediate(d, res, "linux"); !ok || rem.ID != RemedyCheckLocalPath {
						t.Fatalf("remediation = %+v, ok=%v", rem, ok)
					}
					if observed == "" {
						control = d
					} else if d.Verdict != control.Verdict || d.Summary != control.Summary {
						t.Fatal("route metadata changed verdict or summary")
					}
					data, err := snapshot.Encode(BuildSnapshot(target, probes, res))
					if err != nil {
						t.Fatal(err)
					}
					artifact, err := snapshot.Decode(data)
					if err != nil {
						t.Fatal(err)
					}
					replay, err := ReplaySnapshot(artifact)
					if err != nil {
						t.Fatal(err)
					}
					assertDiagnosisSemantics(t, replay, d)
				}
			})
		}
	}
}

func TestFailedRouteFamiliesPreserveUncertaintyAndContext(t *testing.T) {
	target := &Target{Host: "example.com", Port: 443, Proto: ProtoNone}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP}
	probes := []Probe{{ID: ProbeIface}, {ID: ProbeInternet}, {ID: ProbeDNS}, {ID: ProbeTargetTCP}}
	causes := []string{RouteCauseNoDefaultRoute, RouteCauseGatewayUnreachable, RouteCauseSelectedPathFailed, RouteCausePreferredPathFailed, ""}
	strong := func(c string) bool { return c == RouteCauseNoDefaultRoute || c == RouteCauseGatewayUnreachable }
	for _, c4 := range causes {
		for _, c6 := range causes {
			for _, single := range []string{"", "ipv4", "ipv6"} {
				t.Run(c4+"/"+c6+"/only="+single, func(t *testing.T) {
					v4, v6 := []net.IP{net.ParseIP("1.1.1.1")}, []net.IP{net.ParseIP("2606:4700:4700::1111")}
					if single == "ipv4" {
						v6 = nil
					}
					if single == "ipv6" {
						v4 = nil
					}
					classify := func(ip net.IP) string {
						if ip.To4() != nil {
							return c4
						}
						return c6
					}
					cause, family := failedRouteCause(classify, v4, v6)
					reverse, reverseFamily := failedRouteCause(classify, v6, v4)
					if cause != reverse || family != reverseFamily {
						t.Fatal("family order changed aggregation")
					}
					res := map[ProbeID]ProbeResult{
						ProbeIface: {Status: StatusPass, Routes: []RouteDecision{
							{Destination: net.ParseIP("1.1.1.1"), Family: "ipv4", Unreachable: true},
							{Destination: net.ParseIP("2606:4700:4700::1111"), Family: "ipv6", Iface: "wg0", Tunnel: TunnelKnown},
						}},
						ProbeInternet:  {Status: StatusFail, Cause: cause, causeFamily: family},
						ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{net.ParseIP("93.184.216.34")}},
						ProbeTargetTCP: {Status: StatusFail},
					}
					d := Interpret(target, order, res)
					want, confidence := DiagnosisReachabilityUnlocalized, ConfidenceInsufficientEvidence
					if (len(v4) == 0 || strong(c4)) && (len(v6) == 0 || strong(c6)) {
						want, confidence = DiagnosisLocalEgressFailure, ConfidenceMedium
					}
					if len(d.Findings) != 1 || d.Findings[0].ID != want || d.Findings[0].Confidence != confidence {
						t.Fatalf("got %+v, want %s/%s", d.Findings, want, confidence)
					}
					for _, e := range []CausalEvidence{
						{Kind: EvidenceSupport, Check: ProbeIface, Observation: ObservationRouteUnreachable, Value: "1.1.1.1"},
						{Kind: EvidenceSupport, Check: ProbeIface, Observation: ObservationRouteTunneled, Value: "wg0"},
					} {
						if !hasEvidenceItem(d.Findings[0].Evidence, e) {
							t.Errorf("missing route context %+v", e)
						}
					}
					data, err := snapshot.Encode(BuildSnapshot(target, probes, res))
					if err != nil {
						t.Fatal(err)
					}
					stored, err := snapshot.Decode(data)
					if err != nil {
						t.Fatal(err)
					}
					replay, err := ReplaySnapshot(stored)
					if err != nil {
						t.Fatal(err)
					}
					assertDiagnosisSemantics(t, replay, d)
				})
			}
		}
	}
}
