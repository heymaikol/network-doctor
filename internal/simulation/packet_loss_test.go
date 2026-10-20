package simulation

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// packetLossProblem reports why rep is not a report the packet-loss scenario
// allows, or "" when it is. The scenario file says why which row the loss
// reaches is left open; this is what every run owes regardless.
//
// The run must have finished, on the client, under the seeded netem qdisc the
// scenario put on the client's egress and nowhere else, and it must report
// exactly the rows netdoc's probe plan has for the target. Netem shapes only
// that egress, so an answer a resolver logged sending is one the client got.
// The dns row must pass when the client's resolver answered an A query for the
// target and time out when it did not, QUIC may be not applicable only when
// its endpoint got no more answers than the egress row's portal check asked
// for, and public DNS may pass only on an answer. Any other row may be slowed
// or silenced, but a failure must carry a timeout, on the row or on one of its
// attempts, and no row may carry a cause loss cannot produce. Elapsed time is
// no evidence here: the egress row spends its whole budget even when it
// passes. Everything netdoc and the simulator derive from the rows must agree
// with them.
func packetLossProblem(rep Report) string {
	if rep.Error != "" || rep.Result == ResultError {
		return fmt.Sprintf("simulation did not run cleanly: result %s, error %q", rep.Result, rep.Error)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		return fmt.Sprintf("tests = %+v", rep.Tests)
	}
	out, d := rep.Tests[0], rep.Tests[0].Diagnosis
	if out.Error != "" || out.ProcessOutcome != ProcessExited || out.Signal != "" {
		return fmt.Sprintf("netdoc did not finish: %s, signal %q, error %q", out.ProcessOutcome, out.Signal, out.Error)
	}
	var client NodeInfo
	for _, n := range rep.Topology {
		if n.Name == out.Node {
			client = n
		}
	}
	nodeAt := func(address string) string {
		for _, n := range rep.Topology {
			if address != "" && (n.Address == address || slices.Contains(n.Aliases, address)) {
				return n.Name
			}
		}
		return ""
	}
	resolver, public := nodeAt(client.Resolver), nodeAt(diagnostic.DefaultPublicDNS)
	if client.Role != "client" || resolver == "" || resolver == client.Name || public == "" || public == resolver {
		return fmt.Sprintf("netdoc ran on %+v, which must be a client whose resolver (%q) is a node of its own, apart from public DNS (%q)",
			client, resolver, public)
	}
	fault, conditions := rep.Faults, rep.Evidence.PacketConditions
	if len(fault) != 1 || fault[0].Type != FaultNetem || fault[0].Node != client.Name || fault[0].LossPercent != 10 || fault[0].Seed == 0 {
		return fmt.Sprintf("packet-loss qdisc evidence = %+v, want seeded 10%% netem on the client", fault)
	}
	if len(conditions) != 1 || conditions[0].Node != client.Name || !conditions[0].Active || conditions[0].DroppedPackets == 0 {
		return fmt.Sprintf("tc did not report an active netem qdisc on the client that dropped packets: %+v", conditions)
	}
	if conditions[0].LossPercent != fault[0].LossPercent || conditions[0].Seed != fault[0].Seed {
		return fmt.Sprintf("the kernel's qdisc %+v is not the injected one %+v", conditions[0], fault[0])
	}
	target, err := diagnostic.ParseTarget(out.Target)
	if err != nil {
		return "target: " + err.Error()
	}
	plan := diagnostic.ProbePlan(target, diagnostic.DefaultPublicDNS, true)
	if !slices.EqualFunc(plan, d.Checks, func(p diagnostic.Probe, c DiagnosisCheck) bool { return string(p.ID) == c.ID }) {
		got := make([]string, len(d.Checks))
		for i, c := range d.Checks {
			got[i] = c.ID
		}
		return fmt.Sprintf("rows %v, want the planned rows %v", got, diagnostic.ProbeOrder(plan))
	}

	heard := func(node, name string) int {
		n := 0
		for _, q := range rep.Evidence.DNSQueries {
			if q.Node == node && q.Source == client.Address && q.Name == name && q.QueryType == "A" && q.ActualOutcome == "ANSWER" {
				n++
			}
		}
		return n
	}
	answered := heard(resolver, target.Host)
	status := map[diagnostic.ProbeID]string{}
	for i, p := range plan {
		status[p.ID] = d.Checks[i].Status
	}
	var wrong []string
	if dropped := conditions[0].DroppedPackets; answered == 0 && dropped < 2 {
		wrong = append(wrong, fmt.Sprintf("dns went unanswered but netem dropped %d packets, too few to lose both A queries", dropped))
	}
	degraded, failing, firstFail := false, 0, ""
	for i, p := range plan {
		c := d.Checks[i]
		var allowed, why string
		switch {
		case slices.ContainsFunc(p.Deps, func(dep diagnostic.ProbeID) bool { return status[dep] == "FAIL" || status[dep] == "SKIP" }):
			allowed, why = "SKIP", "a prerequisite failed"
		case p.ID == diagnostic.ProbeIface:
			allowed, why = "PASS", "the interface needs no packet"
		case p.ID == diagnostic.ProbeProxy || p.ID == diagnostic.ProbeSSID:
			allowed, why = "N/A", "the simulator clears proxy settings and a veth has no Wi-Fi"
		case p.ID == diagnostic.ProbeDNS && answered > 0:
			allowed, why = "PASS", fmt.Sprintf("%s answered %d A queries for the target, so dns must pass", resolver, answered)
		case p.ID == diagnostic.ProbeDNS:
			allowed, why = "FAIL", resolver+" answered no A query for the target, so dns must time out"
			if c.Status == "FAIL" && c.Cause != diagnostic.DNSCauseTimeout {
				wrong = append(wrong, fmt.Sprintf("dns failed with cause %q, but %s", c.Cause, why))
			}
		// The egress row's portal check asks for this name too, through the
		// system resolver, whose 5 s query timeout outlasts the run's 4 s: one
		// A query. A lone answer may be the portal check's, and any beyond it
		// went to QUIC.
		case p.ID == diagnostic.ProbeQUIC && heard(resolver, diagnostic.ConnectivityProbeHost) == 0:
			allowed, why = "N/A", "nobody got an answer for QUIC's endpoint"
		case p.ID == diagnostic.ProbeQUIC && heard(resolver, diagnostic.ConnectivityProbeHost) == 1:
			allowed, why = "PASS WARN FAIL N/A", "the one answer for QUIC's endpoint may have gone to the portal check"
		case p.ID == diagnostic.ProbeDNSPublic && heard(public, target.Host) > 0:
			// Not applicable as well: a lookup that lost its other family
			// reports the answer it did get as no second opinion.
			allowed, why = "PASS N/A", public+" answered the public DNS row"
		case p.ID == diagnostic.ProbeDNSPublic:
			allowed, why = "N/A", public+" answered no A query from the public DNS row"
		default:
			allowed, why = "PASS WARN FAIL", "loss can only slow or silence it"
		}
		if !slices.Contains(strings.Fields(allowed), c.Status) {
			wrong = append(wrong, fmt.Sprintf("%s %s, want %s: %s", c.ID, c.Status, allowed, why))
		}
		if c.Cause != "" && !timedOutCause(c.Cause) {
			wrong = append(wrong, fmt.Sprintf("%s %s with cause %s, which loss cannot produce", c.ID, c.Status, c.Cause))
		}
		if c.Status == "FAIL" && !timedOutCheck(c) {
			wrong = append(wrong, c.ID+" FAIL with no timeout on the row or its attempts")
		}
		degraded = degraded || c.Status == "WARN" || c.Status == "FAIL"
		if c.Status == "FAIL" {
			if failing == 0 {
				firstFail = c.ID
			}
			failing++
		}
	}

	if d.OK != (failing == 0) || d.FailedStage != firstFail {
		wrong = append(wrong, fmt.Sprintf("ok %t and failed stage %q, but %d rows failed, the first %q", d.OK, d.FailedStage, failing, firstFail))
	}
	wantExit := 1
	if d.OK {
		wantExit = 0
	}
	if out.ExitCode != wantExit {
		wrong = append(wrong, fmt.Sprintf("exit code %d, but ok %t means %d", out.ExitCode, d.OK, wantExit))
	}
	switch {
	case out.ActualVerdict != d.Verdict:
		wrong = append(wrong, "verdict recorded as "+out.ActualVerdict+", but netdoc said "+d.Verdict)
	case !degraded && d.Verdict != diagnostic.VerdictOK:
		wrong = append(wrong, "no row warned or failed, but verdict = "+d.Verdict)
	case degraded && d.Verdict == diagnostic.VerdictOK:
		wrong = append(wrong, "a row warned or failed, but verdict ok")
	case status[diagnostic.ProbeDNS] == "FAIL" && failing == 1 && d.Verdict != diagnostic.VerdictDNS:
		wrong = append(wrong, "only dns failed, but verdict = "+d.Verdict)
	}
	// The comparison flags every row that warned or failed, because the
	// scenario expects only the interface.
	wantResult := ResultPass
	if degraded {
		wantResult = ResultFail
	}
	if rep.Result != wantResult {
		wrong = append(wrong, fmt.Sprintf("result %s, want %s", rep.Result, wantResult))
	}
	return strings.Join(wrong, "; ")
}

// TestPacketLossProblem holds the packet-loss oracle to the reports loss can
// leave and to the ones it exists to catch, among them a dns row that received
// an answer and still reported a timeout. Every rejected case below differs
// from a report the oracle accepts in one thing only.
func TestPacketLossProblem(t *testing.T) {
	const target = "lossy-target.test:9999"
	services := map[string]string{"resolver": "loss-resolver", "internet": ""}
	answer := func(node, name string) DNSQueryEvidence {
		return DNSQueryEvidence{Node: node, Service: services[node], Source: "10.77.0.10", Name: name, QueryType: "A", ActualOutcome: "ANSWER"}
	}
	healthy := func() Report {
		parsed, err := diagnostic.ParseTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		var checks []DiagnosisCheck
		for _, p := range diagnostic.ProbePlan(parsed, diagnostic.DefaultPublicDNS, true) {
			status := "PASS"
			if p.ID == diagnostic.ProbeProxy || p.ID == diagnostic.ProbeSSID {
				status = "N/A"
			}
			checks = append(checks, DiagnosisCheck{ID: string(p.ID), Status: status})
		}
		return Report{
			Result: ResultPass,
			Topology: []NodeInfo{
				{Name: "client", Role: "client", Address: "10.77.0.10", Resolver: "10.77.0.53"},
				{Name: "resolver", Role: "server", Address: "10.77.0.53"},
				{Name: "internet", Role: "server", Address: "10.77.0.1", Aliases: []string{"1.1.1.1", "8.8.8.8"}},
			},
			Faults: []FaultInfo{{Type: FaultNetem, Node: "client", LossPercent: 10, Seed: 219540062}},
			Tests: []TestOutcome{{Node: "client", Target: target, ProcessOutcome: ProcessExited, ActualVerdict: "ok",
				Diagnosis: &Diagnosis{Verdict: "ok", OK: true, Checks: checks}}},
			Evidence: Evidence{
				PacketConditions: []PacketConditionEvidence{{Node: "client", LossPercent: 10, Seed: 219540062, Active: true, DroppedPackets: 4}},
				DNSQueries: []DNSQueryEvidence{
					answer("resolver", "lossy-target.test"), answer("internet", "lossy-target.test"),
					// The QUIC probe and the egress row's portal check each ask once.
					answer("resolver", diagnostic.ConnectivityProbeHost), answer("resolver", diagnostic.ConnectivityProbeHost),
					{Node: "resolver", Service: "loss-resolver", Source: "10.77.0.10", Name: "lossy-target.test", QueryType: "AAAA", ActualOutcome: "NODATA"},
				},
			},
		}
	}
	// rows edits the named rows, then restates what netdoc and the simulator
	// derive from them, so that a case differs from the healthy report only in
	// the rows it names and the verdict it gives.
	rows := func(verdict string, edit func(row func(id string) *DiagnosisCheck)) func(*Report) {
		return func(rep *Report) {
			out := &rep.Tests[0]
			d := out.Diagnosis
			edit(func(id string) *DiagnosisCheck {
				c := checkByID(d, id)
				if c == nil {
					t.Fatalf("no %s row to edit", id)
				}
				return c
			})
			d.OK, d.FailedStage, out.ExitCode, rep.Result = true, "", 0, ResultPass
			for _, c := range d.Checks {
				if c.Status == "FAIL" && d.OK {
					d.OK, d.FailedStage, out.ExitCode = false, c.ID, 1
				}
				if c.Status == "WARN" || c.Status == "FAIL" {
					rep.Result = ResultFail
				}
			}
			d.Verdict, out.ActualVerdict = verdict, verdict
		}
	}
	// silent drops every A answer node gave the client for name.
	silent := func(node, name string) func(*Report) {
		return func(rep *Report) {
			rep.Evidence.DNSQueries = slices.DeleteFunc(rep.Evidence.DNSQueries, func(q DNSQueryEvidence) bool {
				return q.Node == node && q.Name == name && q.QueryType == "A"
			})
		}
	}
	oneQUICHostAnswerLost := func(rep *Report) {
		q := rep.Evidence.DNSQueries
		i := slices.IndexFunc(q, func(q DNSQueryEvidence) bool { return q.Name == diagnostic.ConnectivityProbeHost })
		rep.Evidence.DNSQueries = slices.Delete(q, i, i+1)
	}
	dnsLost := func(rep *Report) {
		silent("resolver", "lossy-target.test")(rep)
		rows("dns", func(row func(string) *DiagnosisCheck) {
			*row("dns") = DiagnosisCheck{ID: "dns", Status: "FAIL", Cause: diagnostic.DNSCauseTimeout}
			row("target_tcp").Status = "SKIP"
		})(rep)
	}
	timedOutAttempt := []DiagnosisAttempt{{IP: "10.77.0.1", Cause: diagnostic.ConnectionCauseTimeout}}

	for _, tc := range []struct {
		name   string
		mutate func(*Report)
		want   string
	}{
		{"healthy run", func(*Report) {}, ""},

		// What loss may do to a run.
		{"both A queries lost", dnsLost, ""},
		{"lost SYN slows the target", rows("degraded", func(row func(string) *DiagnosisCheck) { row("target_tcp").Status = "WARN" }), ""},
		{"QUIC handshake runs out", rows("degraded", func(row func(string) *DiagnosisCheck) {
			row("quic_udp_443").Status, row("quic_udp_443").Cause = "FAIL", diagnostic.QUICCauseTimeout
		}), ""},
		{"QUIC's own lookup lost", func(rep *Report) {
			silent("resolver", diagnostic.ConnectivityProbeHost)(rep)
			checkByID(rep.Tests[0].Diagnosis, "quic_udp_443").Status = "N/A"
		}, ""},
		{"QUIC's own lookup lost while the portal check's was answered", func(rep *Report) {
			oneQUICHostAnswerLost(rep)
			checkByID(rep.Tests[0].Diagnosis, "quic_udp_443").Status = "N/A"
		}, ""},
		{"portal check's lookup lost while QUIC's was answered", oneQUICHostAnswerLost, ""},
		{"public DNS query lost", func(rep *Report) {
			silent("internet", "lossy-target.test")(rep)
			checkByID(rep.Tests[0].Diagnosis, "dns_public").Status = "N/A"
		}, ""},
		{"public DNS answered one family only", func(rep *Report) { checkByID(rep.Tests[0].Diagnosis, "dns_public").Status = "N/A" }, ""},
		{"egress timeout recorded only on its attempts", rows("degraded", func(row func(string) *DiagnosisCheck) {
			row("internet_tcp").Status, row("internet_tcp").Attempts = "FAIL", timedOutAttempt
		}), ""},

		// The dns row, held to the resolver's log.
		{"answer received but reported as a timeout", rows("dns", func(row func(string) *DiagnosisCheck) {
			*row("dns") = DiagnosisCheck{ID: "dns", Status: "FAIL", Cause: diagnostic.DNSCauseTimeout}
			row("target_tcp").Status = "SKIP"
		}), "so dns must pass"},
		{"no answer but dns passed", silent("resolver", "lossy-target.test"), "so dns must time out"},
		{"no answer but the wrong cause", func(rep *Report) {
			dnsLost(rep)
			checkByID(rep.Tests[0].Diagnosis, "dns").Cause = diagnostic.DNSCauseTemporaryFailure
		}, "so dns must time out"},
		{"no answer and too few drops", func(rep *Report) {
			dnsLost(rep)
			rep.Evidence.PacketConditions[0].DroppedPackets = 1
		}, "too few to lose both"},
		{"answer sent to another host", func(rep *Report) { rep.Evidence.DNSQueries[0].Source = "10.77.0.99" }, "so dns must time out"},

		// Every planned row, in the state its prerequisites allow.
		{"planned row missing", func(rep *Report) {
			d := rep.Tests[0].Diagnosis
			d.Checks = slices.DeleteFunc(d.Checks, func(c DiagnosisCheck) bool { return c.ID == "quic_udp_443" })
		}, "planned rows"},
		{"row the plan does not have", func(rep *Report) {
			d := rep.Tests[0].Diagnosis
			d.Checks = append(d.Checks, DiagnosisCheck{ID: "path_mtu", Status: "PASS"})
		}, "planned rows"},
		{"target skipped although dns passed", func(rep *Report) { checkByID(rep.Tests[0].Diagnosis, "target_tcp").Status = "SKIP" },
			"target_tcp SKIP"},
		{"target ran although dns failed", func(rep *Report) {
			dnsLost(rep)
			checkByID(rep.Tests[0].Diagnosis, "target_tcp").Status = "PASS"
		}, "target_tcp PASS"},
		{"target not applicable", func(rep *Report) { checkByID(rep.Tests[0].Diagnosis, "target_tcp").Status = "N/A" }, "target_tcp N/A"},
		{"row never reported", func(rep *Report) { checkByID(rep.Tests[0].Diagnosis, "dns_encrypted").Status = "INCOMPLETE" },
			"dns_encrypted INCOMPLETE"},
		{"QUIC not applicable although its lookup was answered", func(rep *Report) {
			checkByID(rep.Tests[0].Diagnosis, "quic_udp_443").Status = "N/A"
		}, "quic_udp_443 N/A"},
		{"QUIC passed with no answer for its endpoint", silent("resolver", diagnostic.ConnectivityProbeHost), "quic_udp_443 PASS"},
		{"public DNS passed with no answer", silent("internet", "lossy-target.test"), "dns_public PASS"},
		{"proxy row ran with no proxy configured", func(rep *Report) { checkByID(rep.Tests[0].Diagnosis, "proxy_connect").Status = "PASS" },
			"proxy_connect PASS"},
		{"interface down", rows("network", func(row func(string) *DiagnosisCheck) { row("iface").Status = "FAIL" }), "iface FAIL"},

		// The loss belongs to the client's egress.
		{"netem on the resolver", func(rep *Report) { rep.Faults[0].Node = "resolver" }, "client"},
		{"condition read from another node", func(rep *Report) { rep.Evidence.PacketConditions[0].Node = "internet" }, "client"},
		{"kernel qdisc differs from the injected one", func(rep *Report) { rep.Evidence.PacketConditions[0].Seed = 1 }, "injected"},
		{"client resolves through the public node", func(rep *Report) { rep.Topology[0].Resolver = "10.77.0.1" }, "resolver"},
		{"nothing dropped", func(rep *Report) { rep.Evidence.PacketConditions[0].DroppedPackets = 0 }, "active netem qdisc"},

		// A failure loss can explain is a timeout, and the run must say so.
		{"a refusal under loss", rows("service", func(row func(string) *DiagnosisCheck) {
			row("target_tcp").Status, row("target_tcp").Cause = "FAIL", diagnostic.ConnectionCauseRefused
		}), "loss cannot produce"},
		{"target failed with no timeout evidence", rows("service", func(row func(string) *DiagnosisCheck) {
			row("target_tcp").Status = "FAIL"
			row("target_tcp").Attempts = []DiagnosisAttempt{{IP: "10.77.0.1", Error: "connection refused"}}
		}), "target_tcp FAIL"},
		{"egress failed fast and spent its budget elsewhere", rows("degraded", func(row func(string) *DiagnosisCheck) {
			row("internet_tcp").Status, row("internet_tcp").Ms = "FAIL", 4003
		}), "internet_tcp FAIL"},

		// The run finished, and everything derived from its rows agrees with them.
		{"simulation setup failed", func(rep *Report) { rep.Error, rep.Result = "netns: setup failed", ResultError }, "simulation"},
		{"cleanup failed", func(rep *Report) { rep.Result = ResultError }, "simulation"},
		{"netdoc ran out its deadline", func(rep *Report) { rep.Tests[0].ProcessOutcome = ProcessTimedOut }, "netdoc did not finish"},
		{"netdoc killed by a signal", func(rep *Report) {
			rep.Tests[0].ProcessOutcome, rep.Tests[0].Signal = ProcessSignaled, "killed"
		}, "netdoc did not finish"},
		{"exit code disagrees with ok", func(rep *Report) { rep.Tests[0].ExitCode = 1 }, "exit code"},
		{"ok despite a failed row", func(rep *Report) {
			rows("degraded", func(row func(string) *DiagnosisCheck) {
				row("quic_udp_443").Status, row("quic_udp_443").Cause = "FAIL", diagnostic.QUICCauseTimeout
			})(rep)
			rep.Tests[0].Diagnosis.OK, rep.Tests[0].ExitCode = true, 0
		}, "ok"},
		{"failed stage names the wrong row", func(rep *Report) {
			dnsLost(rep)
			rep.Tests[0].Diagnosis.FailedStage = "target_tcp"
		}, "failed stage"},
		{"two verdicts for one run", func(rep *Report) { rep.Tests[0].ActualVerdict = "degraded" }, "verdict"},
		{"clean run not ok", rows("degraded", func(func(string) *DiagnosisCheck) {}), "no row warned or failed"},
		{"degraded run called ok", rows("ok", func(row func(string) *DiagnosisCheck) { row("target_tcp").Status = "WARN" }), "verdict ok"},
		{"DNS timeout diagnosed elsewhere", func(rep *Report) {
			dnsLost(rep)
			rep.Tests[0].Diagnosis.Verdict, rep.Tests[0].ActualVerdict = "network", "network"
		}, "only dns failed"},
		{"degraded run recorded as a pass", func(rep *Report) {
			rows("degraded", func(row func(string) *DiagnosisCheck) { row("target_tcp").Status = "WARN" })(rep)
			rep.Result = ResultPass
		}, "result"},
		{"clean run recorded as a failure", func(rep *Report) { rep.Result = ResultFail }, "result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := healthy()
			tc.mutate(&rep)
			got := packetLossProblem(rep)
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Errorf("packetLossProblem = %q, want %q", got, tc.want)
			}
		})
	}
}
