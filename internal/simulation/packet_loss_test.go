package simulation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// packetLossProblem reports why rep is not a report the packet-loss scenario
// allows, or "" when it is. The scenario file says why which row the loss
// reaches is left open; this is what every run owes regardless.
//
// The netem proof is unconditional. The dns row is held to loss-resolver's
// query log both ways: an A answer there means the row must pass, and none
// means it must time out, with at least the two kernel drops that losing both
// of its queries takes. Every other row may be slowed or silenced, but never
// refused or answered wrongly: every row's timeout cause is "timeout" except
// the DNS one, and loss can produce no other. A run nothing degraded must be
// ok, and a DNS timeout with nothing else failing must be diagnosed as DNS.
func packetLossProblem(rep Report) string {
	if len(rep.Faults) != 1 || rep.Faults[0].Type != FaultNetem || rep.Faults[0].LossPercent != 10 || rep.Faults[0].Seed == 0 {
		return fmt.Sprintf("packet-loss qdisc evidence = %+v", rep.Faults)
	}
	if len(rep.Evidence.PacketConditions) != 1 || !rep.Evidence.PacketConditions[0].Active || rep.Evidence.PacketConditions[0].DroppedPackets == 0 {
		return fmt.Sprintf("tc did not report an active netem qdisc that dropped packets: %+v", rep.Evidence.PacketConditions)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		return fmt.Sprintf("tests = %+v", rep.Tests)
	}
	out := rep.Tests[0]
	dns := checkByID(out.Diagnosis, string(diagnostic.ProbeDNS))
	if dns == nil {
		return fmt.Sprintf("no dns row: %+v", out.Diagnosis.Checks)
	}
	answered := 0
	for _, q := range rep.Evidence.DNSQueries {
		if q.Service == "loss-resolver" && q.Name == "lossy-target.test" && q.QueryType == "A" && q.ActualOutcome == "ANSWER" {
			answered++
		}
	}
	var wrong []string
	dropped := rep.Evidence.PacketConditions[0].DroppedPackets
	switch {
	case answered > 0 && dns.Status != "PASS":
		wrong = append(wrong, fmt.Sprintf("loss-resolver answered %d A queries for the target, so dns must pass: %+v", answered, *dns))
	case answered == 0 && (dns.Status != "FAIL" || dns.Cause != diagnostic.DNSCauseTimeout):
		wrong = append(wrong, fmt.Sprintf("loss-resolver answered no A query for the target, so dns must time out: %+v", *dns))
	case answered == 0 && dropped < 2:
		wrong = append(wrong, fmt.Sprintf("dns timed out but netem dropped %d packets, too few to lose both A queries", dropped))
	}
	if iface := checkByID(out.Diagnosis, string(diagnostic.ProbeIface)); iface == nil || iface.Status != "PASS" {
		wrong = append(wrong, fmt.Sprintf("iface = %+v, want PASS", iface))
	}
	degraded, failing := false, 0
	for _, c := range out.Diagnosis.Checks {
		degraded = degraded || c.Status == "WARN" || c.Status == "FAIL"
		if c.Status == "FAIL" {
			failing++
		}
		if c.Cause != "" && c.Cause != diagnostic.DNSCauseTimeout && c.Cause != diagnostic.ConnectionCauseTimeout {
			wrong = append(wrong, fmt.Sprintf("%s %s with cause %s, which loss cannot produce", c.ID, c.Status, c.Cause))
		}
	}
	if !degraded && out.ActualVerdict != diagnostic.VerdictOK {
		wrong = append(wrong, "every row passed, but verdict = "+out.ActualVerdict)
	}
	if dns.Status == "FAIL" && failing == 1 && out.ActualVerdict != diagnostic.VerdictDNS {
		wrong = append(wrong, "only dns failed, but verdict = "+out.ActualVerdict)
	}
	return strings.Join(wrong, "; ")
}

// TestPacketLossProblem holds the packet-loss oracle to the reports loss can
// leave and to the ones it exists to catch, among them a dns row that received
// an answer and still reported a timeout.
func TestPacketLossProblem(t *testing.T) {
	row := func(id, status, cause string) DiagnosisCheck {
		return DiagnosisCheck{ID: id, Status: status, Cause: cause}
	}
	healthy := func() []DiagnosisCheck {
		return []DiagnosisCheck{row("iface", "PASS", ""), row("internet_tcp", "PASS", ""), row("quic_udp_443", "PASS", ""),
			row("dns", "PASS", ""), row("target_tcp", "PASS", "")}
	}
	answer := DNSQueryEvidence{Service: "loss-resolver", Name: "lossy-target.test", QueryType: "A", ActualOutcome: "ANSWER"}
	nodata := DNSQueryEvidence{Service: "loss-resolver", Name: "lossy-target.test", QueryType: "AAAA", ActualOutcome: "NODATA"}
	// The same name answered by the public resolver is not the dns row's answer.
	public := DNSQueryEvidence{Service: "", Name: "lossy-target.test", QueryType: "A", ActualOutcome: "ANSWER"}
	timedOut := func(checks []DiagnosisCheck) []DiagnosisCheck {
		checks[3], checks[4] = row("dns", "FAIL", diagnostic.DNSCauseTimeout), row("target_tcp", "SKIP", "")
		return checks
	}

	for _, tc := range []struct {
		name    string
		checks  []DiagnosisCheck
		verdict string
		dropped uint64
		queries []DNSQueryEvidence
		want    string
	}{
		{"healthy run", healthy(), "ok", 2, []DNSQueryEvidence{answer, nodata}, ""},
		{"both A queries lost", timedOut(healthy()), "dns", 2, []DNSQueryEvidence{nodata, public}, ""},
		{"lost SYN slows the target", func() []DiagnosisCheck { c := healthy(); c[4].Status = "WARN"; return c }(),
			"degraded", 2, []DNSQueryEvidence{answer}, ""},
		{"QUIC handshake runs out", func() []DiagnosisCheck { c := healthy(); c[2] = row("quic_udp_443", "FAIL", "timeout"); return c }(),
			"degraded", 2, []DNSQueryEvidence{answer}, ""},
		{"answer received but reported as a timeout", timedOut(healthy()), "dns", 2, []DNSQueryEvidence{nodata, answer},
			"so dns must pass"},
		{"no answer but dns passed", healthy(), "ok", 2, []DNSQueryEvidence{nodata, public}, "so dns must time out"},
		{"no answer but the wrong cause", func() []DiagnosisCheck {
			c := timedOut(healthy())
			c[3].Cause = diagnostic.DNSCauseTemporaryFailure
			return c
		}(), "dns", 2, nil, "so dns must time out"},
		{"no answer and too few drops", timedOut(healthy()), "dns", 1, nil, "too few to lose both"},
		{"a refusal under loss", func() []DiagnosisCheck {
			c := healthy()
			c[4] = row("target_tcp", "FAIL", diagnostic.ConnectionCauseRefused)
			return c
		}(), "service", 2, []DNSQueryEvidence{answer}, "loss cannot produce"},
		{"clean run not ok", healthy(), "degraded", 2, []DNSQueryEvidence{answer}, "every row passed"},
		{"DNS timeout diagnosed elsewhere", timedOut(healthy()), "network", 2, nil, "only dns failed"},
		{"interface down", func() []DiagnosisCheck { c := healthy(); c[0].Status = "FAIL"; return c }(),
			"network", 2, []DNSQueryEvidence{answer}, "iface"},
		{"nothing dropped", healthy(), "ok", 0, []DNSQueryEvidence{answer}, "active netem qdisc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := Report{
				Faults: []FaultInfo{{Type: FaultNetem, LossPercent: 10, Seed: 219540062}},
				Tests:  []TestOutcome{{ActualVerdict: tc.verdict, Diagnosis: &Diagnosis{Verdict: tc.verdict, Checks: tc.checks}}},
				Evidence: Evidence{
					PacketConditions: []PacketConditionEvidence{{Active: true, DroppedPackets: tc.dropped}},
					DNSQueries:       tc.queries,
				},
			}
			got := packetLossProblem(rep)
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Errorf("packetLossProblem = %q, want %q", got, tc.want)
			}
		})
	}
}
