package diagnostic

import (
	"net"
	"strings"
	"testing"
)

// Issue 438: the reference dials failed, the link recovered, and later checks
// passed. The run cannot see the recovery, so the summary must not call one
// failed sample a lasting block.
func TestDirectEgressFailureIsNotDescribedAsLasting(t *testing.T) {
	target := &Target{Raw: "routed-target.test", Host: "routed-target.test", Port: 80, Proto: ProtoHTTP}
	res := map[ProbeID]ProbeResult{
		ProbeIface:     ok(StatusPass),
		ProbeInternet:  {Status: StatusFail, Cause: RouteCauseSelectedPathFailed},
		ProbeDNS:       ok(StatusPass),
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: net.ParseIP("10.77.2.20")},
		ProbeHTTP:      ok(StatusPass),
		ProbeQUIC:      ok(StatusPass),
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeHTTP, ProbeQUIC}

	d := Interpret(target, order, res)
	if len(d.Findings) != 1 || d.Findings[0].ID != DiagnosisDirectEgressBlocked {
		t.Fatalf("findings: got %+v, want one %s finding", d.Findings, DiagnosisDirectEgressBlocked)
	}
	if strings.Contains(d.Summary, "is blocked") {
		t.Errorf("summary claims a lasting block from one observed failure: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "during this run") {
		t.Errorf("summary does not say when the failure was observed: %q", d.Summary)
	}
	if !strings.Contains(d.Summary, "again") {
		t.Errorf("summary does not say the state may change: %q", d.Summary)
	}
}
