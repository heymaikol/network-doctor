//go:build netns_integration

// Opt-in (-tags netns_integration) tests that build real network namespaces.
//
//	go test -tags netns_integration -count=1 -v ./internal/simulation
//
// No root needed: the simulator runs in an unprivileged user namespace. The
// tests skip themselves on a host where that is unavailable, and nothing they
// create is reachable from, or visible to, the host network.

package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"gopkg.in/yaml.v3"
)

const proxyProbeName = diagnostic.ConnectivityProbeHost

// buildBinaries produces the two binaries an end-to-end run needs, from the
// tree under test rather than whatever is installed.
//
// CGO_ENABLED=0, which is how releases are built, and the only setting that
// simulates anything. A cgo build resolves through glibc's getaddrinfo, which
// inside a node namespace does not use the node's resolver: on a systemd-resolved
// host it reaches the host's resolver over a Unix socket in the shared /run, and
// where that is absent it blocks, ignoring the probe's context, until the probe
// deadline expires. Either way the run measures the host, not the simulation.
func buildBinaries(t *testing.T) (netdoc, sim string) {
	t.Helper()
	dir := t.TempDir()
	netdoc = filepath.Join(dir, "netdoc")
	sim = filepath.Join(dir, "netdoc-sim")
	for out, pkg := range map[string]string{
		netdoc: "github.com/heymaikol/network-doctor",
		sim:    "github.com/heymaikol/network-doctor/cmd/netdoc-sim",
	} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, msg)
		}
	}
	return netdoc, sim
}

// RequireNetnsEnv turns "this host cannot simulate" from a skip into a failure.
// A CI job that is supposed to exercise namespaces has to fail when it silently
// stops doing so: a green run full of skips is how a backend regression hides
// for a release cycle. Developers on a host without user namespaces leave it
// unset and get the skip.
const RequireNetnsEnv = "NETDOC_SIM_REQUIRE_NETNS"

func requireBackend(t *testing.T) {
	t.Helper()
	caps := DefaultBackend(false, nil).Capabilities(context.Background())
	if caps.Supported {
		return
	}
	if os.Getenv(RequireNetnsEnv) != "" {
		t.Fatalf("%s is set, so these tests must run, but the backend is unavailable: %s",
			RequireNetnsEnv, caps.Reason)
	}
	t.Skip("simulation backend unavailable: " + caps.Reason)
}

// requireNetemSeed skips a scenario that pins netem randomness to a seed when
// tc is too old to take one. RequireNetnsEnv deliberately does not force this
// the way it forces an unavailable backend: that flag guards the backend, and
// what is missing here is one tc keyword the runner image supplies, not
// anything the checkout controls.
func requireNetemSeed(t *testing.T) {
	t.Helper()
	if ok, version := tcSupportsNetemSeed(context.Background()); !ok {
		t.Skipf("seeded netem needs iproute2 %s or newer, this host has %s", netemSeedIproute2, version)
	}
}

// runScenario runs one scenario end to end and returns the parsed report.
func runScenario(t *testing.T, name string, extra ...string) Report {
	t.Helper()
	netdoc, sim := buildBinaries(t)
	cmd := exec.Command(sim, append([]string{"run", name, "-json", "-netdoc", netdoc}, extra...)...)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !asExitError(err, &exit) {
		t.Fatalf("run %s: %v", name, err)
	}
	var rep Report
	if jsonErr := json.Unmarshal(out, &rep); jsonErr != nil {
		t.Fatalf("run %s: report is not JSON (%v): %s", name, jsonErr, out)
	}
	noteNetnsScenarioExecution(name, &rep)
	return rep
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func hasSuggestion(suggestions []Suggestion, code string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Code == code {
			return true
		}
	}
	return false
}

// TestHealthyScenario is the control: netdoc must find nothing wrong with a
// network where nothing is wrong.
func TestHealthyScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "healthy")
	if rep.Result != ResultPass {
		t.Errorf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].ActualVerdict != "ok" {
		t.Fatalf("tests = %+v", rep.Tests)
	}
	if rep.Tests[0].FalsePositives != 0 {
		t.Errorf("netdoc flagged %d things in a healthy network", rep.Tests[0].FalsePositives)
	}
	// This topology is IPv4 only. The simulator dials the family the client
	// actually carries and records the one it does not have as unavailable:
	// untested is not an observed IPv6 outage, and it is not silence either.
	assertObservedFamily(t, rep, "ipv4", FamilyStateReachable)
	assertObservedFamily(t, rep, "ipv6", FamilyStateUnavailable)
	assertCleanedUp(t, rep)
}

func TestSameFamilyFailoverScenario(t *testing.T) {
	requireBackend(t)
	const (
		deadIP    = "10.77.0.20"
		healthyIP = "10.77.0.21"
	)
	scenario, err := LibraryScenario("same-family-failover")
	if err != nil {
		t.Fatal(err)
	}
	var ordered []string
	for _, node := range scenario.Topology.Nodes {
		for _, service := range node.Services {
			if service.Type != ServiceDNS {
				continue
			}
			for _, record := range service.Records {
				if record.Name == "failover-target.test" {
					ordered = append(ordered, record.Address)
				}
			}
		}
	}
	if !slices.Equal(ordered, []string{deadIP, healthyIP}) {
		t.Fatalf("ordered A records = %v, want [%s %s]", ordered, deadIP, healthyIP)
	}

	rep := runScenario(t, "same-family-failover")
	if rep.Result != ResultPass || len(rep.Tests) != 1 {
		t.Fatalf("result = %s (error %q); tests=%+v suggestions=%+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions)
	}
	out := rep.Tests[0]
	if dns := diagnosisCheck(out, string(diagnostic.ProbeDNS)); dns.Status != "PASS" {
		t.Errorf("dns = %+v, want both A records resolved", dns)
	}
	tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP))
	if tcp.Status != "PASS" || len(tcp.Attempts) != 2 {
		t.Fatalf("target_tcp = %+v, want successful two-address failover", tcp)
	}
	first, second := tcp.Attempts[0], tcp.Attempts[1]
	if first.IP != deadIP || first.Error == "" || !strings.Contains(strings.ToLower(first.Error), "cancel") {
		t.Errorf("first attempt = %+v, want cancelled black-holed address %s", first, deadIP)
	}
	if first.Ms < 200 {
		t.Errorf("first attempt = %dms, want evidence that the 250ms fallback stagger elapsed", first.Ms)
	}
	if second.IP != healthyIP || second.Error != "" {
		t.Errorf("second attempt = %+v, want successful address %s", second, healthyIP)
	}
	for _, attempt := range tcp.Attempts {
		if ip := net.ParseIP(attempt.IP); ip == nil || ip.To4() == nil {
			t.Errorf("attempt %q is not IPv4", attempt.IP)
		}
	}
	if httpCheck := diagnosisCheck(out, string(diagnostic.ProbeHTTP)); httpCheck.Status != "PASS" ||
		!hasServiceReply(rep, "healthy-target", "failover-http", ServiceHTTP, http.StatusOK) {
		t.Errorf("HTTP did not use the healthy selected address: check=%+v replies=%+v", httpCheck, rep.Evidence.ServiceReplies)
	}
	matchedDrop := false
	for _, drop := range rep.Evidence.PacketDrops {
		if drop.Node == "black-holed-target" && drop.Direction == DirectionInbound && drop.To == deadIP &&
			drop.Protocol == "tcp" && drop.Port == 80 && drop.Packets > 0 {
			matchedDrop = true
		}
	}
	if !matchedDrop {
		t.Errorf("black-hole rule did not count the first real SYN: %+v", rep.Evidence.PacketDrops)
	}
	if out.ActualVerdict != diagnostic.VerdictOK {
		t.Errorf("verdict = %s, want %s after successful fallback", out.ActualVerdict, diagnostic.VerdictOK)
	}
	for _, finding := range out.Diagnosis.Findings {
		if finding.ID == string(diagnostic.DiagnosisPartialReachability) {
			t.Errorf("a canceled black-holed attempt became a partial-reachability finding: %+v", finding)
		}
	}
	assertCleanedUp(t, rep)
}

// TestBrokenDNSScenario is the vertical slice: a fault that only breaks the
// name, with the path underneath left working, and a diagnosis that has to say
// which of the two it was.
func TestBrokenDNSScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "broken-dns")
	if rep.Result != ResultPass {
		t.Errorf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	out := rep.Tests[0]
	// Stable ids, never the prose: the wording is allowed to change.
	byID := map[string]string{}
	for _, c := range out.Diagnosis.Checks {
		byID[c.ID] = c.Status
	}
	if byID["dns"] != "FAIL" {
		t.Errorf("dns = %s, want FAIL", byID["dns"])
	}
	if byID["internet_tcp"] != "PASS" {
		t.Errorf("internet_tcp = %s, want PASS: the point is that the path still works", byID["internet_tcp"])
	}
	if out.ActualVerdict != "dns" {
		t.Errorf("verdict = %s, want dns", out.ActualVerdict)
	}
	if len(out.Diagnosis.Findings) != 1 || out.Diagnosis.Findings[0].ID != string(diagnostic.DiagnosisSystemDNSFailure) {
		t.Fatalf("finding = %+v, want %s", out.Diagnosis.Findings, diagnostic.DiagnosisSystemDNSFailure)
	}
	finding := out.Diagnosis.Findings[0]
	if finding.Counterfactual == nil || finding.Counterfactual.Variable != string(diagnostic.CounterfactualDNSResolver) ||
		len(finding.Counterfactual.Alternatives) != 2 {
		t.Errorf("DNS counterfactual = %+v", finding.Counterfactual)
	}
	wantSupport := map[string]string{
		string(diagnostic.ProbeDNS):       string(diagnostic.ObservationCause),
		string(diagnostic.ProbeDNSPublic): string(diagnostic.ObservationDNSAnswers),
		string(diagnostic.ProbeInternet):  string(diagnostic.ObservationStatusPass),
	}
	for check, observation := range wantSupport {
		if !hasDiagnosisCausalEvidence(finding, string(diagnostic.EvidenceSupport), check, observation, "", "") {
			t.Errorf("finding has no support from %s/%s: %+v", check, observation, finding.CausalEvidence)
		}
	}
	if !hasDiagnosisCausalEvidence(finding, string(diagnostic.EvidenceRuledOut), string(diagnostic.ProbeInternet),
		string(diagnostic.ObservationStatusPass), string(diagnostic.DiagnosisOffline), "") {
		t.Errorf("working internet did not rule out an outage: %+v", finding.CausalEvidence)
	}
	if !hasDiagnosisCausalEvidence(finding, string(diagnostic.EvidenceNotEvaluated), string(diagnostic.ProbeTargetTCP),
		string(diagnostic.ObservationStatusSkip), "", string(diagnostic.NotEvaluatedPrerequisite)) {
		t.Errorf("skipped target check did not stay not-evaluated: %+v", finding.CausalEvidence)
	}
	for _, evidence := range finding.CausalEvidence {
		if evidence.Check == string(diagnostic.ProbeTargetTCP) && evidence.Kind == string(diagnostic.EvidenceRuledOut) {
			t.Errorf("skipped target check was used to rule out a cause: %+v", evidence)
		}
	}
	publicAnswer := false
	for _, query := range rep.Evidence.DNSQueries {
		if query.Source == "10.77.0.10" && query.Name == "example.test" && query.QueryType == "A" && query.ActualOutcome == "ANSWER" {
			publicAnswer = true
		}
	}
	if !publicAnswer {
		t.Errorf("causal public-DNS support has no simulator answer: %+v", rep.Evidence.DNSQueries)
	}
	assertCleanedUp(t, rep)
}

func TestNoDefaultRouteScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "no-default-route")
	if rep.Result != ResultPass {
		t.Errorf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	if cause := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)).Cause; cause != diagnostic.RouteCauseNoDefaultRoute {
		t.Errorf("internet_tcp cause = %q, want %q", cause, diagnostic.RouteCauseNoDefaultRoute)
	}
	assertCleanedUp(t, rep)
}

// TestLinkDownScenario covers the first branch Diagnose takes. With the
// client's only link administratively down there is no interface to send from,
// and that has to be the whole answer rather than the pile of downstream
// failures it would otherwise be read as.
func TestLinkDownScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "link-down")
	if rep.Result != ResultPass {
		t.Errorf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	// The fault has to bite the client and only the client. A downed router
	// link is a different fault with a different diagnosis, and a client that
	// keeps a second usable link is not this case at all.
	clientLinks := 0
	for _, link := range rep.Evidence.Links {
		if link.Node != "client" {
			if !link.Up {
				t.Errorf("%s link to %s is down; only the client's may be", link.Node, link.Segment)
			}
			continue
		}
		clientLinks++
		if link.Up {
			t.Errorf("client link to %s is up; the client must be left with no usable link", link.Segment)
		}
	}
	if clientLinks != 1 {
		t.Errorf("client has %d links, want exactly one so nothing else can carry its traffic", clientLinks)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		t.Fatalf("tests = %+v", rep.Tests)
	}
	out := rep.Tests[0]
	if check := diagnosisCheck(out, string(diagnostic.ProbeIface)); check.Status != "FAIL" {
		t.Errorf("iface = %+v, want FAIL", check)
	}
	// The prose of the highest-priority branch, exactly. The verdict alone
	// would pass for any other dead network, which is the confusion this
	// scenario exists to rule out.
	if summary := out.Diagnosis.Summary; summary != "No usable network interface: the link is down." {
		t.Errorf("summary = %q, want the link-down diagnosis", summary)
	}
	if out.ActualVerdict != diagnostic.VerdictNetwork {
		t.Errorf("verdict = %s, want %s", out.ActualVerdict, diagnostic.VerdictNetwork)
	}
	assertCleanedUp(t, rep)
}

func TestHighLatencyScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "high-latency")
	if rep.Result != ResultPass {
		t.Errorf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	assertCleanedUp(t, rep)
}

func TestTierOneScenarios(t *testing.T) {
	requireBackend(t)
	for _, tc := range []struct {
		name      string
		testCount int
		extra     []string
	}{
		{name: "dns-nxdomain", testCount: 1, extra: []string{"-repeat", "3"}},
		{name: "tcp-port-blocked", testCount: 1, extra: []string{"-timeout", timedTimeout}},
		{name: "connection-refused", testCount: 2},
		{name: "packet-loss", testCount: 1},
		{name: "http-error", testCount: 1},
		{name: "missing-subnet-route", testCount: 1},
		{name: "quic-udp-443-blocked", testCount: 1, extra: []string{"-timeout", timedTimeout}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "packet-loss" {
				requireNetemSeed(t)
			}
			rep := runScenario(t, tc.name, tc.extra...)
			if rep.Result != ResultPass || len(rep.Tests) != tc.testCount {
				t.Fatalf("result = %s (error %q); tests=%+v suggestions=%+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions)
			}
			out := rep.Tests[0]
			switch tc.name {
			case "dns-nxdomain":
				if !hasDNSEvidence(rep, "internet", "10.77.0.10", "printer.office.test", "NXDOMAIN") {
					t.Errorf("configured resolver did not return NXDOMAIN: %+v", rep.Evidence.DNS)
				}
				for _, id := range []diagnostic.ProbeID{diagnostic.ProbeInternet, diagnostic.ProbeQUIC,
					diagnostic.ProbeDNSPublic, diagnostic.ProbeDNSEncrypted} {
					if check := diagnosisCheck(out, string(id)); check.Status != "PASS" {
						t.Errorf("%s = %+v, want PASS so DNS is the isolated failure", id, check)
					}
				}
				dns := diagnosisCheck(out, string(diagnostic.ProbeDNS))
				if dns.Status != "FAIL" {
					t.Errorf("dns = %+v, want the missing-record failure", dns)
				}
				if out.ExpectedSummary == "" || out.ExpectedSummary != out.Diagnosis.Summary {
					t.Errorf("expected summary = %q, actual = %q", out.ExpectedSummary, out.Diagnosis.Summary)
				}
				var dnsComparison CheckComparison
				for _, comparison := range out.Checks {
					if comparison.ID == string(diagnostic.ProbeDNS) {
						dnsComparison = comparison
					}
				}
				if dnsComparison.ExpectedFix == "" || dnsComparison.ExpectedFix != dns.Fix || dnsComparison.Outcome != OutcomeMatched {
					t.Errorf("DNS wording comparison = %+v, actual fix = %q", dnsComparison, dns.Fix)
				}
				if !slices.Equal(out.RepeatVerdicts, []string{"dns", "dns", "dns"}) {
					t.Errorf("repeat verdicts = %v, want three deterministic DNS diagnoses", out.RepeatVerdicts)
				}
			case "tcp-port-blocked":
				check := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP))
				if len(rep.Faults) != 1 || rep.Faults[0].Type != FaultDrop || rep.Faults[0].Node != "target" ||
					rep.Faults[0].Summary != "target swallows tcp traffic to 10.77.0.20 port 2222" ||
					!strings.Contains(strings.Join(out.TimedOut, ","), string(diagnostic.ProbeTargetTCP)) ||
					strings.Contains(strings.ToLower(check.Detail), "refused") {
					t.Errorf("silent TCP drop evidence: faults=%+v target=%+v", rep.Faults, check)
				}
			case "connection-refused":
				check := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP))
				if check.Cause != diagnostic.ConnectionCauseRefused || len(check.Attempts) != 1 ||
					!strings.Contains(strings.ToLower(check.Attempts[0].Error), "connection refused") {
					t.Errorf("active refusal evidence: %+v", check)
				}
				if control := rep.Tests[1]; diagnosisCheck(control, string(diagnostic.ProbeTargetTCP)).Status != "PASS" ||
					diagnosisCheck(control, string(diagnostic.ProbeHTTP)).Status != "PASS" {
					t.Errorf("same-node reachability control: %+v", control)
				}
			case "packet-loss":
				if len(rep.Faults) != 1 || rep.Faults[0].Type != FaultNetem || rep.Faults[0].LossPercent != 10 || rep.Faults[0].Seed == 0 {
					t.Fatalf("packet-loss qdisc evidence = %+v", rep.Faults)
				}
				if len(rep.Evidence.PacketConditions) != 1 || !rep.Evidence.PacketConditions[0].Active || rep.Evidence.PacketConditions[0].DroppedPackets == 0 {
					t.Fatalf("tc did not report an active netem qdisc: %+v", rep.Evidence.PacketConditions)
				}
			case "http-error":
				check := diagnosisCheck(out, string(diagnostic.ProbeHTTP))
				if check.Status != "PASS" || check.Detail != "HTTP 503 (responded)" {
					t.Errorf("HTTP error response = %+v", check)
				}
			case "missing-subnet-route":
				reachable := true
				if diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" || !hasDefaultRoute(rep, "client") ||
					!hasSelectedRoute(rep, "client", "10.77.3.20", "10.77.1.1", "client-lan", &reachable) {
					t.Errorf("healthy default selected for unrouted subnet: %+v", rep.Evidence.Routes)
				}
				for _, node := range rep.Topology {
					for _, route := range node.Routes {
						if node.Name == "client" && route.Destination == "10.77.3.0/24" {
							t.Errorf("client unexpectedly has target-subnet route: %+v", route)
						}
					}
				}
			case "quic-udp-443-blocked":
				quic := diagnosisCheck(out, string(diagnostic.ProbeQUIC))
				if diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" ||
					diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "PASS" ||
					quic.Status != "FAIL" || quic.Cause != diagnostic.QUICCauseTimeout ||
					!strings.Contains(strings.Join(out.TimedOut, ","), string(diagnostic.ProbeQUIC)) {
					t.Errorf("TCP-good/QUIC-bad evidence: %+v", out)
				}
			}
			assertCleanedUp(t, rep)
		})
	}
}

func TestStableCauseScenarios(t *testing.T) {
	requireBackend(t)
	for _, tc := range []struct {
		name  string
		tests int
	}{
		{name: "tls-failure-causes", tests: 4},
		{name: "secure-transport-failures", tests: 1},
		{name: "proxy-failure-causes", tests: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := runScenario(t, tc.name)
			if rep.Result != ResultPass {
				t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
			}
			if len(rep.Tests) != tc.tests {
				t.Fatalf("tests = %d, want %d", len(rep.Tests), tc.tests)
			}
			if tc.name == "tls-failure-causes" {
				closed := rep.Tests[3]
				closedTLS := diagnosisCheck(closed, string(diagnostic.ProbeTLS))
				if closed.Name != "peer resets during the TLS handshake" || closedTLS.Status != "FAIL" ||
					closedTLS.Cause != diagnostic.TLSCauseConnectionClosed {
					t.Errorf("resetting peer = name %q, TLS %+v", closed.Name, closedTLS)
				}
				out := rep.Tests[1]
				tls := diagnosisCheck(out, string(diagnostic.ProbeTLS))
				if out.Name != "trusted certificate is not valid yet" || tls.Status != "FAIL" ||
					tls.Cause != diagnostic.TLSCauseCertificateNotYet ||
					tls.Fix != "this machine's clock is about 3 days slow, so certificates that are already valid look not yet valid: set the clock (enable network time) and retry" {
					t.Errorf("clock-skew reconciliation = name %q, TLS %+v", out.Name, tls)
				}
				if summary := out.Diagnosis.Summary; summary != "TCP reaches future.test:9441 but the TLS handshake fails because this machine's clock is about 3 days slow, so certificates that are already valid look not yet valid." {
					t.Errorf("summary = %q, want the clock-skew explanation", summary)
				}
				if internet := diagnosisCheck(out, string(diagnostic.ProbeInternet)); internet.Status != "PASS" ||
					!hasServiceReply(rep, "internet", "portal", ServiceHTTP, http.StatusNoContent) ||
					!hasTLSEvidence(rep, TLSCertificateNotYetValid, "future.test", "future.test", true, "client_rejected_certificate") {
					t.Errorf("real HTTP/TLS path missing: internet=%+v HTTP=%+v TLS=%+v", internet, rep.Evidence.ServiceReplies, rep.Evidence.TLS)
				}
			}
			assertCleanedUp(t, rep)
		})
	}
}

func TestHighJitterScenario(t *testing.T) {
	requireBackend(t)
	requireNetemSeed(t)
	rep := runScenario(t, "high-jitter")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v suggestions=%+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions)
	}
	if len(rep.Faults) != 1 || rep.Faults[0].Jitter != 100000000 {
		t.Fatalf("jitter evidence = %+v", rep.Faults)
	}
	condition := rep.Evidence.PacketConditions[0]
	if condition.RTTSamples < 5 || condition.ObservedMaxRTT <= condition.ObservedMinRTT {
		t.Errorf("RTT observations did not vary: %+v", condition)
	}
	if !hasSuggestion(rep.Suggestions, "jitter_sampling_gap") {
		t.Errorf("no deterministic jitter coverage-gap suggestion: %+v", rep.Suggestions)
	}
	assertCleanedUp(t, rep)
}

func TestIntermittentDNSScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "intermittent-dns")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v DNS=%+v", rep.Result, rep.Error, rep.Tests, rep.Evidence.DNSQueries)
	}
	// Both outcomes have to belong to the target name, in that order: the point
	// of the scenario is that this name failed and then this name recovered.
	// Counting outcomes across every name the run happened to ask about is what
	// let unrelated queries decide when the recovery landed.
	servfail, answer := 0, 0
	for _, query := range rep.Evidence.DNSQueries {
		if query.Service != "intermittent-resolver" || query.Name != "flaky-target.test" ||
			query.QueryType != "A" {
			continue
		}
		switch {
		case query.ScheduledOutcome == DNSOutcomeSERVFAIL && query.ActualOutcome == "SERVFAIL":
			servfail = query.Sequence
		case query.ScheduledOutcome == DNSOutcomeAnswer && query.ActualOutcome == "ANSWER":
			if answer == 0 {
				answer = query.Sequence
			}
		}
	}
	if servfail == 0 || answer == 0 || servfail > answer {
		t.Errorf("target A queries did not fail and then recover (last servfail %d, first answer %d): %+v",
			servfail, answer, rep.Evidence.DNSQueries)
	}
	if cause := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeDNS)).Cause; cause != diagnostic.DNSCauseTemporaryFailure {
		t.Errorf("first DNS cause = %q", cause)
	}
	assertCleanedUp(t, rep)
}

func TestDNSHijackingScenarioReachesSplitDNSDiagnosis(t *testing.T) {
	requireBackend(t)
	const (
		wrongAddress  = "192.0.2.20"
		publicAddress = "10.77.0.20"
		targetName    = "hijacked-target.test"
	)
	rep := runScenario(t, "dns-hijacking")
	if rep.Result != ResultPass || len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		t.Fatalf("result = %s (error %q); tests=%+v DNS=%+v", rep.Result, rep.Error, rep.Tests, rep.Evidence.DNSQueries)
	}
	out := rep.Tests[0]
	if out.ProcessOutcome != ProcessExited {
		t.Fatalf("netdoc process outcome = %q, want %q", out.ProcessOutcome, ProcessExited)
	}

	system := diagnosisCheck(out, string(diagnostic.ProbeDNS))
	public := diagnosisCheck(out, string(diagnostic.ProbeDNSPublic))
	if system.Status != "PASS" || !strings.Contains(system.Detail, wrongAddress) {
		t.Errorf("system DNS = %+v, want wrong address %s", system, wrongAddress)
	}
	if public.Status != "WARN" || public.Cause != "" ||
		!strings.Contains(public.Detail, "answers point elsewhere; system: "+wrongAddress) ||
		!strings.Contains(public.Detail, "public "+diagnostic.PublicDNSCandidates(diagnostic.DefaultPublicDNS, true)[0]+": "+publicAddress) {
		t.Errorf("public DNS = %+v, want the split-DNS reconciliation detail", public)
	}
	if target := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); target.Status != "PASS" || !strings.Contains(target.Detail, wrongAddress) {
		t.Errorf("target TCP = %+v, want the system answer to carry the real target probe", target)
	}
	if out.ActualVerdict != diagnostic.VerdictDegraded ||
		out.Diagnosis.Summary != "The target works, but system DNS and public DNS disagree; split DNS or filtering may be intentional (see the DNS rows)." {
		t.Errorf("diagnosis = %q, %q", out.ActualVerdict, out.Diagnosis.Summary)
	}

	wrongObserved, publicObserved := false, false
	for _, query := range rep.Evidence.DNSQueries {
		if query.Source != "10.77.0.10" || query.Name != targetName || query.QueryType != "A" {
			continue
		}
		switch {
		case query.Service == "hijacking-resolver" && query.ScheduledOutcome == DNSOutcomeWrongAnswer && query.ActualOutcome == "WRONG_ANSWER":
			wrongObserved = true
		case query.Service == "public-resolver" && query.ScheduledOutcome == DNSOutcomeAnswer && query.ActualOutcome == "ANSWER":
			publicObserved = true
		}
	}
	if !wrongObserved || !publicObserved {
		t.Errorf("resolver-specific A answers were not both observed: %+v", rep.Evidence.DNSQueries)
	}
	assertCleanedUp(t, rep)
}

func TestTCPResetScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "tcp-reset")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v reset=%+v", rep.Result, rep.Error, rep.Tests, rep.Evidence.TCPResets)
	}
	if target := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeTargetTCP)); target.Status != "PASS" {
		t.Errorf("target TCP = %+v", target)
	}
	if banner := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeSSH)); banner.Status != "FAIL" || banner.Cause != diagnostic.ConnectionCauseReset {
		t.Errorf("SSH reset classification = %+v", banner)
	}
	accepted, reset := false, false
	for _, event := range rep.Evidence.TCPResets {
		accepted = accepted || event.Event == "accepted" && event.Count > 0
		reset = reset || event.Event == "reset" && event.Count > 0
	}
	if !accepted || !reset {
		t.Errorf("reset service evidence = %+v", rep.Evidence.TCPResets)
	}
	assertCleanedUp(t, rep)
}

func TestServiceBannerScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "service-banners")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v", rep.Result, rep.Error, rep.Tests)
	}
	if len(rep.Tests) != 4 {
		t.Fatalf("tests = %+v", rep.Tests)
	}

	checks := []struct {
		index  int
		id     diagnostic.ProbeID
		status string
		detail string
	}{
		{0, diagnostic.ProbeSSH, "PASS", "banner: SSH-2.0-NetworkDoctorSimulator"},
		{1, diagnostic.ProbeSMTP, "PASS", "banner: 220 mail.test ESMTP Network Doctor Simulator"},
		{2, diagnostic.ProbeSMTP, "FAIL", "unexpected service banner: 554 mail.test ESMTP unavailable"},
		{3, diagnostic.ProbeSSH, "FAIL", "unexpected service banner: 220 mail.test ESMTP Network Doctor Simulator"},
	}
	for _, want := range checks {
		out := rep.Tests[want.index]
		if out.FalsePositives != 0 || out.FalseNegatives != 0 {
			t.Errorf("%s: comparison fp=%d fn=%d: %+v", out.Name, out.FalsePositives, out.FalseNegatives, out.Checks)
		}
		if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
			t.Errorf("%s: target_tcp = %+v", out.Name, tcp)
		}
		if got := diagnosisCheck(out, string(want.id)); got.Status != want.status || got.Detail != want.detail {
			t.Errorf("%s: %s = %+v, want %s %q", out.Name, want.id, got, want.status, want.detail)
		}
	}
	assertCleanedUp(t, rep)
}

// timedTimeout keeps the timed scenarios short in CI. Their timelines are
// designed so the transitions land the same way at any probe timeout above a
// few hundred milliseconds; this only decides how long the run that waits out a
// dropped query takes.
const timedTimeout = "1s"

func appliedEvent(t *testing.T, rep Report, kind, state string) FaultEventEvidence {
	t.Helper()
	for _, item := range rep.Timeline {
		if item.Result == EventApplied && item.Event.Type == kind &&
			(item.Event.Outcome == state || item.Event.State == state) {
			return item
		}
	}
	t.Fatalf("no applied %s event reaching %q: %+v", kind, state, rep.Timeline)
	return FaultEventEvidence{}
}

func TestTransientDNSOutageScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "transient-dns-outage", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v timeline=%+v", rep.Result, rep.Error, rep.Tests, rep.Timeline)
	}
	drop := appliedEvent(t, rep, FaultScheduledDNS, DNSOutcomeDrop)
	recover := appliedEvent(t, rep, FaultScheduledDNS, DNSOutcomeAnswer)
	if !(drop.AppliedOffset < recover.AppliedOffset) {
		t.Fatalf("outage did not precede recovery: %+v %+v", drop, recover)
	}
	// The resolver answered before the outage, went silent during it, and the
	// silent query is the one that failed.
	before, during, after := 0, 0, 0
	for _, q := range rep.Evidence.DNSQueries {
		if q.Service != "outage-resolver" {
			continue
		}
		switch {
		case q.Offset < drop.AppliedOffset && q.ActualOutcome != "DROPPED":
			before++
		case q.Offset >= drop.AppliedOffset && q.Offset < recover.AppliedOffset && q.ActualOutcome == "DROPPED":
			during++
		case q.Offset >= recover.AppliedOffset && q.ActualOutcome == "ANSWER":
			after++
		}
	}
	if before == 0 || during == 0 || after == 0 {
		t.Fatalf("queries before/during/after the outage = %d/%d/%d: %+v", before, during, after, rep.Evidence.DNSQueries)
	}
	if got := diagnosisCheck(rep.Tests[1], string(diagnostic.ProbeDNS)); got.Status != "PASS" {
		t.Errorf("the outage run's DNS row = %+v", got)
	}
	if got := diagnosisCheck(rep.Tests[2], string(diagnostic.ProbeDNS)); got.Status != "PASS" {
		t.Errorf("the recovery run's DNS row = %+v", got)
	}
	// Recovery happened while that run was still waiting, and the query that
	// answered it is one netdoc sent afterwards: the resample, in the resolver's
	// own record, not inferred from the row above.
	if !(rep.Tests[1].StartOffset < recover.AppliedOffset && recover.AppliedOffset < rep.Tests[1].EndOffset) {
		t.Errorf("recovery at %s is outside the outage run %s..%s",
			recover.AppliedOffset, rep.Tests[1].StartOffset, rep.Tests[1].EndOffset)
	}
	resampled := false
	for _, q := range rep.Evidence.DNSQueries {
		resampled = resampled || q.Service == "outage-resolver" && q.Offset >= recover.AppliedOffset &&
			q.Offset < rep.Tests[1].EndOffset && q.ActualOutcome == "ANSWER"
	}
	if !resampled {
		t.Errorf("no query reached the recovered resolver before the run ended: %+v", rep.Evidence.DNSQueries)
	}
	if hasSuggestion(rep.Suggestions, SuggestTransientNotResampled) {
		t.Errorf("resampling gap reported for a run that resampled: %+v", rep.Suggestions)
	}
	assertCleanedUp(t, rep)
}

func TestLatencySpikeScenario(t *testing.T) {
	requireBackend(t)
	requireNetemSeed(t)
	rep := runScenario(t, "latency-spike", "-timeout", "4s")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v timeline=%+v", rep.Result, rep.Error, rep.Tests, rep.Timeline)
	}
	// The kernel's own view of the qdisc at each state, not just what we asked.
	var netem []FaultEventEvidence
	for _, item := range rep.Timeline {
		if item.Event.Type == FaultScheduledNetem && item.Result == EventApplied {
			netem = append(netem, item)
		}
	}
	if len(netem) != 3 {
		t.Fatalf("scheduled netem events applied = %+v", netem)
	}
	for i, want := range []string{"delay 10ms", "delay 700ms", "delay 10ms"} {
		if !strings.Contains(netem[i].Observed, want) {
			t.Errorf("qdisc after event %d = %q, want %q", i, netem[i].Observed, want)
		}
	}
	// The spike opened and closed inside the single run that spans it.
	run := rep.Tests[0]
	if !(run.StartOffset < netem[1].AppliedOffset && netem[2].AppliedOffset < run.EndOffset) {
		t.Errorf("the spike did not open and close inside the run %s..%s: %+v",
			run.StartOffset, run.EndOffset, netem)
	}
	// Baseline before, spike during: the same path measured at two speeds. The
	// egress attempt that completed before the spike is the baseline sample; the
	// target handshake happened after it and cost two orders of magnitude more.
	if len(rep.Evidence.PacketConditions) != 1 || !rep.Evidence.PacketConditions[0].Active ||
		rep.Evidence.PacketConditions[0].Latency != 10*time.Millisecond {
		t.Fatalf("the qdisc did not return to baseline: %+v", rep.Evidence.PacketConditions)
	}
	baseline := rep.Evidence.PacketConditions[0].ObservedMinRTT
	spiked := time.Duration(diagnosisCheck(run, string(diagnostic.ProbeTargetTCP)).Ms) * time.Millisecond
	if baseline <= 0 || baseline > 200*time.Millisecond || spiked < 500*time.Millisecond {
		t.Errorf("observed RTTs did not reflect the spike: baseline %s, during the spike %s", baseline, spiked)
	}
	assertCleanedUp(t, rep)
}

func TestTransientConnectivityLossScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "transient-connectivity-loss", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v timeline=%+v", rep.Result, rep.Error, rep.Tests, rep.Timeline)
	}
	down := appliedEvent(t, rep, FaultScheduledLink, LinkStateDown)
	up := appliedEvent(t, rep, FaultScheduledLink, LinkStateUp)
	if down.Observed != "kernel link up=false" || up.Observed != "kernel link up=true" {
		t.Errorf("kernel link evidence = %q / %q", down.Observed, up.Observed)
	}
	// Reachable before the outage, unreachable during it, reachable after.
	if got := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeTargetTCP)); got.Status != "PASS" {
		t.Errorf("target before the outage = %+v", got)
	}
	if got := diagnosisCheck(rep.Tests[1], string(diagnostic.ProbeTargetTCP)); got.Status != "FAIL" {
		t.Errorf("target during the outage = %+v", got)
	}
	if got := diagnosisCheck(rep.Tests[2], string(diagnostic.ProbeTargetTCP)); got.Status != "PASS" {
		t.Errorf("target after recovery = %+v", got)
	}
	// The first run's handshake happened milliseconds into it, well before the
	// link dropped; the second run's target probe is gated behind a delayed DNS
	// answer and so always starts after it.
	if !(rep.Tests[0].StartOffset < down.AppliedOffset && down.AppliedOffset < rep.Tests[1].EndOffset) {
		t.Errorf("the outage did not fall between the first and second runs: down at %s, runs %s..%s and %s..%s",
			down.AppliedOffset, rep.Tests[0].StartOffset, rep.Tests[0].EndOffset,
			rep.Tests[1].StartOffset, rep.Tests[1].EndOffset)
	}
	// The scenario breaks transport, never routing: the client's routes and its
	// own link are exactly as configured, and the target's link is back up.
	for _, link := range rep.Evidence.Links {
		if !link.Up {
			t.Errorf("link left down: %+v", link)
		}
	}
	routes := 0
	for _, route := range rep.Evidence.Routes {
		if route.Node == "client" && route.Destination == "default" && route.Via == "10.77.0.1" {
			routes++
		}
	}
	if routes != 1 {
		t.Errorf("the client's default route did not survive the outage: %+v", rep.Evidence.Routes)
	}
	if !hasSuggestion(rep.Suggestions, SuggestTransientReportedPermanent) {
		t.Errorf("no transient-versus-permanent suggestion: %+v", rep.Suggestions)
	}
	assertCleanedUp(t, rep)
}

func TestFaultDuringProbeScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "fault-during-probe", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v timeline=%+v", rep.Result, rep.Error, rep.Tests, rep.Timeline)
	}
	drop := appliedEvent(t, rep, FaultScheduledDNS, DNSOutcomeDrop)
	// The point of the scenario: the transition provably happened while an
	// answer was still being held, and that answer was still delivered. The
	// service's own record of when the query arrived and how long it was held
	// is the synchronisation, and nothing here waits and hopes.
	held := 0
	for _, q := range rep.Evidence.DNSQueries {
		if q.Service != "inflight-resolver" || q.ScheduledOutcome != DNSOutcomeDelay {
			continue
		}
		due := q.Offset + time.Duration(q.DelayMs)*time.Millisecond
		if q.Offset < drop.AppliedOffset && drop.AppliedOffset < due && q.ActualOutcome != "DROPPED" {
			held++
		}
	}
	if held == 0 {
		t.Fatalf("no answer was in flight across the transition at %s: %+v", drop.AppliedOffset, rep.Evidence.DNSQueries)
	}
	if got := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeDNS)); got.Status != "PASS" {
		t.Errorf("the held answer did not reach netdoc: %+v", got)
	}
	if got := diagnosisCheck(rep.Tests[1], string(diagnostic.ProbeDNS)); got.Status != "FAIL" || got.Cause != diagnostic.DNSCauseTimeout {
		t.Errorf("a query after the transition = %+v", got)
	}
	if got := diagnosisCheck(rep.Tests[2], string(diagnostic.ProbeDNS)); got.Status != "PASS" {
		t.Errorf("the run whose resample outlived the drop = %+v", got)
	}
	assertCleanedUp(t, rep)
}

// The flapping campaign's determinism guarantee is the requested timeline, not
// netdoc's answer to it: a transition that lands on a probe boundary is
// genuinely a coin flip, and the campaign exists to say so. So the seeds,
// schedules and timeline fingerprints must reproduce exactly, and the diagnosis
// is only compared where the campaign itself claims stability.
func TestFlappingCampaignTimelinesAreReproducible(t *testing.T) {
	requireBackend(t)
	requireNetemSeed(t)
	netdoc, sim := buildBinaries(t)
	run := func(args ...string) CampaignResult {
		base := []string{"campaign", "flapping-connectivity", "--json", "--seed", "4242",
			"--netdoc", netdoc, "-timeout", timedTimeout}
		cmd := exec.Command(sim, append(base, args...)...)
		out, err := cmd.Output()
		var exit *exec.ExitError
		if err != nil && !asExitError(err, &exit) {
			t.Fatalf("campaign: %v", err)
		}
		var result CampaignResult
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("campaign JSON: %v: %s", err, out)
		}
		noteNetnsCampaignExecution("flapping-connectivity", &result)
		return result
	}
	first, second := run("--runs", "3"), run("--runs", "3")
	if len(first.Outcomes) != 3 || len(second.Outcomes) != 3 {
		t.Fatalf("campaign lengths = %d/%d", len(first.Outcomes), len(second.Outcomes))
	}
	for i := range first.Outcomes {
		a, b := first.Outcomes[i], second.Outcomes[i]
		if a.IterationSeed != b.IterationSeed || a.ScheduleID != b.ScheduleID {
			t.Fatalf("iteration %d is not reproducible: %+v != %+v", i, a, b)
		}
		if a.Report.TimelineID != b.Report.TimelineID {
			t.Fatalf("iteration %d timeline fingerprint changed: %q != %q", i, a.Report.TimelineID, b.Report.TimelineID)
		}
		// Five netem phases and three resolver phases, every one of them either
		// applied or explicitly skipped, and none applied before its offset.
		if len(a.Report.Timeline) != 8 {
			t.Fatalf("iteration %d timeline = %+v", i, a.Report.Timeline)
		}
		for _, item := range a.Report.Timeline {
			switch item.Result {
			case EventApplied:
				if item.AppliedOffset < item.ScheduledOffset {
					t.Errorf("iteration %d applied %s early: %+v", i, item.State, item)
				}
			case EventSkipped:
			default:
				t.Errorf("iteration %d event failed: %+v", i, item)
			}
		}
		assertCleanedUp(t, *a.Report)
		assertCleanedUp(t, *b.Report)
	}
	// Direct reproduction of one iteration, by the documented command.
	direct := run("--iteration", "2")
	if len(direct.Outcomes) != 1 || direct.Outcomes[0].Iteration != 2 ||
		direct.Outcomes[0].IterationSeed != first.Outcomes[2].IterationSeed ||
		direct.Outcomes[0].ScheduleID != first.Outcomes[2].ScheduleID ||
		direct.Outcomes[0].Report.TimelineID != first.Outcomes[2].Report.TimelineID {
		t.Fatalf("direct reproduction differs: direct=%+v original=%+v", direct.Outcomes, first.Outcomes[2])
	}
	assertCleanedUp(t, *direct.Outcomes[0].Report)
}

func TestUnstableConnectivityCampaignIsReproducible(t *testing.T) {
	requireBackend(t)
	hostBefore := captureHostNetworkState(t)
	netdoc, sim := buildBinaries(t)
	run := func(iteration string) CampaignResult {
		args := []string{"campaign", "unstable-connectivity", "--json", "--seed", "12345", "--netdoc", netdoc}
		if iteration != "" {
			// The documented reproduction command: seed and iteration only.
			args = append(args, "--iteration", iteration)
		} else {
			args = append(args, "--runs", "5")
		}
		cmd := exec.Command(sim, args...)
		out, err := cmd.Output()
		var exit *exec.ExitError
		if err != nil && !asExitError(err, &exit) {
			t.Fatalf("campaign: %v", err)
		}
		var result CampaignResult
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("campaign JSON: %v: %s", err, out)
		}
		noteNetnsCampaignExecution("unstable-connectivity", &result)
		return result
	}
	first, second := run(""), run("")
	if len(first.Outcomes) != 5 || len(second.Outcomes) != 5 {
		t.Fatalf("campaign lengths = %d/%d", len(first.Outcomes), len(second.Outcomes))
	}
	for i := range first.Outcomes {
		a, b := first.Outcomes[i], second.Outcomes[i]
		if a.IterationSeed != b.IterationSeed || a.ScheduleID != b.ScheduleID || a.Fingerprint.ID != b.Fingerprint.ID {
			t.Fatalf("iteration %d is not reproducible: %+v != %+v", i, a, b)
		}
		assertCleanedUp(t, *a.Report)
		assertCleanedUp(t, *b.Report)
	}
	direct := run("3")
	if len(direct.Outcomes) != 1 || direct.Outcomes[0].Iteration != 3 ||
		direct.Outcomes[0].IterationSeed != first.Outcomes[3].IterationSeed ||
		direct.Outcomes[0].ScheduleID != first.Outcomes[3].ScheduleID ||
		direct.Outcomes[0].Fingerprint.ID != first.Outcomes[3].Fingerprint.ID {
		t.Fatalf("direct reproduction differs: direct=%+v original=%+v", direct.Outcomes, first.Outcomes[3])
	}
	assertCleanedUp(t, *direct.Outcomes[0].Report)
	hostAfter := captureHostNetworkState(t)
	if hostBefore != hostAfter {
		t.Errorf("host routes, interfaces, or forwarding changed across campaign\nbefore:\n%s\nafter:\n%s", hostBefore, hostAfter)
	}
}

// dns-timeout-boundary only exists as a campaign: the delay it walks is drawn
// per iteration, so `run` on the base scenario impairs nothing. Pinning one
// iteration makes the draw a constant, and then the deadline is the only thing
// left to move: the same held answer resolves under a timeout above the swept
// range and is classified as a DNS timeout under one below it.
func TestDNSTimeoutBoundaryCampaignCrossesTheDeadline(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	run := func(timeout string) IterationResult {
		cmd := exec.Command(sim, "campaign", "dns-timeout-boundary", "--json", "--seed", "12345",
			"--iteration", "3", "--netdoc", netdoc, "-timeout", timeout)
		out, err := cmd.Output()
		var exit *exec.ExitError
		if err != nil && !asExitError(err, &exit) {
			t.Fatalf("campaign: %v", err)
		}
		var result CampaignResult
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("campaign JSON: %v: %s", err, out)
		}
		noteNetnsCampaignExecution("dns-timeout-boundary", &result)
		if len(result.Outcomes) != 1 {
			t.Fatalf("outcomes = %+v", result.Outcomes)
		}
		outcome := result.Outcomes[0]
		if len(outcome.Schedule) != 1 || outcome.Schedule[0].Type != FaultScheduledDNS ||
			outcome.Schedule[0].ScheduledResult != DNSOutcomeDelay ||
			outcome.Schedule[0].Delay < 800*time.Millisecond || outcome.Schedule[0].Delay > 1300*time.Millisecond {
			t.Fatalf("schedule is not a single swept delay: %+v", outcome.Schedule)
		}
		return outcome
	}
	// Above the swept range, so the answer always arrives.
	slack := run("4s")
	delay := slack.Schedule[0].Delay
	if slack.Report.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests=%+v", slack.Report.Result, slack.Report.Error, slack.Report.Tests)
	}
	if got := diagnosisCheck(slack.Report.Tests[0], string(diagnostic.ProbeDNS)); got.Status != "PASS" {
		t.Errorf("a %s answer under a 4s deadline = %+v", delay, got)
	}
	applied := appliedEvent(t, *slack.Report, FaultScheduledDNS, DNSOutcomeDelay)
	if applied.Event.Delay != delay {
		t.Errorf("applied delay %s is not the drawn one %s: %+v", applied.Event.Delay, delay, applied)
	}
	// The resolver really held the answer rather than the scheduler recording
	// an intent nothing acted on.
	held := false
	for _, query := range slack.Report.Evidence.DNSQueries {
		held = held || query.Service == "boundary-dns" && query.DelayMs == delay.Milliseconds()
	}
	if !held {
		t.Errorf("no query held for %s: %+v", delay, slack.Report.Evidence.DNSQueries)
	}
	assertCleanedUp(t, *slack.Report)

	// Below it, so the same answer is always late.
	tight := run("300ms")
	if tight.ScheduleID != slack.ScheduleID || tight.Schedule[0].Delay != delay {
		t.Fatalf("the deadline changed the network too: %+v != %+v", tight.Schedule, slack.Schedule)
	}
	if got := diagnosisCheck(tight.Report.Tests[0], string(diagnostic.ProbeDNS)); got.Status != "FAIL" ||
		got.Cause != diagnostic.DNSCauseTimeout {
		t.Errorf("the same %s answer under a 300ms deadline = %+v", delay, got)
	}
	assertCleanedUp(t, *tight.Report)
}

func TestGeneratedHuntCasesAreReproducible(t *testing.T) {
	requireBackend(t)
	hostBefore := captureHostNetworkState(t)
	netdoc, sim := buildBinaries(t)
	run := func(args ...string) HuntResult {
		base := []string{"hunt", "healthy-routed-network", "--json", "--seed", "12345",
			"--netdoc", netdoc, "--timeout", timedTimeout}
		cmd := exec.Command(sim, append(base, args...)...)
		out, err := cmd.Output()
		var exit *exec.ExitError
		if err != nil && !asExitError(err, &exit) {
			t.Fatalf("hunt: %v", err)
		}
		var result HuntResult
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("hunt JSON: %v: %s", err, out)
		}
		return result
	}
	first, second := run("--cases", "6"), run("--cases", "6")
	if first.ExecutedCases != 6 || second.ExecutedCases != 6 || len(first.Cases) != 6 || len(second.Cases) != 6 {
		t.Fatalf("hunt lengths = %d/%d, cases %d/%d", first.ExecutedCases, second.ExecutedCases, len(first.Cases), len(second.Cases))
	}
	operators := make(map[string]bool)
	for i := range first.Cases {
		a, b := first.Cases[i], second.Cases[i]
		if a.Manifest.CaseFingerprint == "" || a.Manifest.CaseSeed != b.Manifest.CaseSeed ||
			a.Manifest.CaseFingerprint != b.Manifest.CaseFingerprint || !reflect.DeepEqual(a.Manifest.Mutations, b.Manifest.Mutations) {
			t.Fatalf("case %d is not reproducible: %+v != %+v", i, a.Manifest, b.Manifest)
		}
		for _, mutation := range a.Manifest.Mutations {
			operators[mutation.ID] = true
		}
		if a.Report == nil || b.Report == nil {
			t.Fatalf("case %d has no normal simulation report", i)
		}
		assertCleanedUp(t, *a.Report)
		assertCleanedUp(t, *b.Report)
	}
	if len(operators) < 2 {
		t.Fatalf("six cases exercised only %d operator(s): %v", len(operators), operators)
	}
	caseNumber := first.Cases[2].Manifest.Case
	direct := run("--case", strconv.Itoa(caseNumber))
	if len(direct.Cases) != 1 || direct.Cases[0].Manifest.CaseSeed != first.Cases[2].Manifest.CaseSeed ||
		direct.Cases[0].Manifest.CaseFingerprint != first.Cases[2].Manifest.CaseFingerprint ||
		!reflect.DeepEqual(direct.Cases[0].Manifest.Mutations, first.Cases[2].Manifest.Mutations) {
		t.Fatalf("direct reproduction differs: direct=%+v original=%+v", direct.Cases, first.Cases[2])
	}
	assertCleanedUp(t, *direct.Cases[0].Report)

	// A generated timed resolver case must rediscover the existing structured
	// resampling opportunity; assert the code, never the human wording.
	known := run("--case", "116")
	if len(known.Cases) != 1 || !hasHuntSuggestion(known.Suggestions, SuggestTransientNotResampled) {
		t.Fatalf("known hunt gap not rediscovered: %+v", known.Suggestions)
	}
	assertCleanedUp(t, *known.Cases[0].Report)
	hostAfter := captureHostNetworkState(t)
	if hostBefore != hostAfter {
		t.Errorf("host routes, interfaces, or forwarding changed across hunt\nbefore:\n%s\nafter:\n%s", hostBefore, hostAfter)
	}
}

func TestHuntProtocolServiceMutationsAreObserved(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	run := func(t *testing.T, scenario *Scenario) Report {
		t.Helper()
		return runScenarioDefinition(t, sim, netdoc, scenario, "-timeout", timedTimeout)
	}
	// conditions are the semantic facts the generic hunt oracle should establish
	// from this run's independent evidence, in registry order, and empty where
	// the fault deliberately implies nothing Network Doctor claims to report. A
	// list rather than one value because a fault can establish more than one:
	// deleting the client's only default route both takes the family away and
	// leaves the table without a default, and netdoc has a separate thing to
	// say about each.
	tests := []struct {
		id, base   string
		killed     bool
		conditions []NetworkCondition
		check      func(*testing.T, Report, Report)
	}{
		{"service.tcp_reset", "healthy", true, nil, func(t *testing.T, control, rep Report) {
			if http := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeHTTP)); http.Status != "PASS" {
				t.Errorf("working HTTP control = %+v", http)
			}
			if http := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeHTTP)); http.Status != "FAIL" || http.Cause != diagnostic.ConnectionCauseReset {
				t.Errorf("HTTP reset classification = %+v", http)
			}
			accepted, reset := false, false
			for _, event := range rep.Evidence.TCPResets {
				accepted = accepted || event.Event == "accepted" && event.Count > 0
				reset = reset || event.Event == "reset" && event.Result == "connection_reset" && event.Count > 0
			}
			if !accepted || !reset {
				t.Errorf("generated TCP reset evidence = %+v", rep.Evidence.TCPResets)
			}
		}},
		{"service.tls_expired", "tls-valid", true, []NetworkCondition{ConditionTLSCertificateExpired}, func(t *testing.T, control, rep Report) {
			if tls := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeTLS)); tls.Status != "PASS" ||
				!hasTLSEvidence(control, TLSCertificateValid, "secure-target.test", "secure-target.test", true, "passed") {
				t.Errorf("valid TLS control = %+v, evidence = %+v", tls, control.Evidence.TLS)
			}
			out := rep.Tests[0]
			if tls := diagnosisCheck(out, string(diagnostic.ProbeTLS)); tls.Status != "FAIL" || tls.Cause != diagnostic.TLSCauseCertificateExpired {
				t.Errorf("TLS mutation diagnosis = %+v", tls)
			}
			if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
				t.Errorf("TLS mutation also broke TCP: %+v", tcp)
			}
			if !hasTLSEvidence(rep, TLSCertificateExpired, "secure-target.test", "secure-target.test", true, "client_rejected_certificate") {
				t.Errorf("no expired certificate rejection evidence: %+v", rep.Evidence.TLS)
			}
		}},
		{"proxy.connect_refused", "socks5h-remote-dns-succeeds", true, []NetworkCondition{ConditionProxyDestinationRefused}, func(t *testing.T, control, rep Report) {
			if proxy := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeProxy)); proxy.Status != "PASS" ||
				!hasSOCKSEvidence(control, "connect", "domain", "connected") {
				t.Errorf("working proxy control = %+v, evidence = %+v", proxy, control.Evidence.SOCKSRequests)
			}
			proxy := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeProxy))
			if proxy.Status != "FAIL" || !strings.Contains(proxy.Detail, "refused CONNECT") ||
				!hasSOCKSEvidence(rep, "greeting", "", "accepted") {
				t.Errorf("reachable proxy refusal = %+v, evidence = %+v", proxy, rep.Evidence.SOCKSRequests)
			}
			connected := false
			refused := false
			for _, request := range rep.Evidence.SOCKSRequests {
				connected = connected || request.Event == "connect" && request.Result == "connected"
				refused = refused || request.Event == "connect" && request.Result == "connection_refused"
			}
			if connected {
				t.Error("mutated proxy completed CONNECT")
			}
			if !refused {
				t.Errorf("proxy did not record destination refusal: %+v", rep.Evidence.SOCKSRequests)
			}
		}},
		{"quic.udp_443_block", "healthy", true, []NetworkCondition{ConditionQUICUDP443Blocked}, func(t *testing.T, control, rep Report) {
			if quic := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeQUIC)); quic.Status != "PASS" {
				t.Errorf("working QUIC control = %+v", quic)
			}
			out := rep.Tests[0]
			quic := diagnosisCheck(out, string(diagnostic.ProbeQUIC))
			if quic.Status != "FAIL" || quic.Cause != diagnostic.QUICCauseTimeout ||
				diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" ||
				diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "PASS" ||
				diagnosisCheck(out, string(diagnostic.ProbeDNS)).Status != "PASS" {
				t.Errorf("UDP-only QUIC failure = %+v", out)
			}
		}},
		{"encrypted_dns.doh_invalid", "healthy", false, nil, func(t *testing.T, control, rep Report) {
			baseline := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeDNSEncrypted))
			if baseline.Status != "PASS" || !strings.Contains(baseline.Detail, "DoH and DoT both completed") {
				t.Errorf("working encrypted-DNS control = %+v", baseline)
			}
			check := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeDNSEncrypted))
			if check.Status != "PASS" || !strings.Contains(check.Detail, "DoT completed") ||
				!strings.Contains(check.Detail, "DoH unavailable") || !strings.Contains(check.Detail, "too short for a DNS header") {
				t.Errorf("DoH-invalid/DoT-valid diagnosis = %+v", check)
			}
		}},
		{"http.status_503", "healthy", false, nil, func(t *testing.T, control, rep Report) {
			if baseline := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeHTTP)); baseline.Status != "PASS" || baseline.Detail != "HTTP 200 (responded)" {
				t.Errorf("working HTTP control = %+v", baseline)
			}
			out := rep.Tests[0]
			http := diagnosisCheck(out, string(diagnostic.ProbeHTTP))
			if http.Status != "PASS" || http.Detail != "HTTP 503 (responded)" ||
				diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "PASS" || out.ActualVerdict != diagnostic.VerdictOK {
				t.Errorf("HTTP 503 diagnosis = %+v", out)
			}
		}},
		// The two target-port families, run against real kernels because that is
		// the only place the distinction exists: one host resets the SYN, the
		// other counts it and says nothing. Each case checks that it produced its
		// own evidence and that it did not produce the other's.
		{"service.connection_refused", "healthy", true, nil, func(t *testing.T, control, rep Report) {
			if tcp := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
				t.Errorf("working target control = %+v", tcp)
			}
			out := rep.Tests[0]
			if diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "FAIL" ||
				diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" ||
				diagnosisCheck(out, string(diagnostic.ProbeDNS)).Status != "PASS" {
				t.Errorf("a closed port took more than the target down: %+v", out)
			}
			if outcome, ok := controlledTargetOutcome(rep.Evidence, "client", "10.77.0.20:80"); !ok ||
				outcome != TargetStateRefused {
				t.Errorf("the closed port did not answer with a refusal: %+v", rep.Evidence.ControlledTargets)
			}
			if len(rep.Evidence.PacketDrops) != 0 {
				t.Errorf("a refusal counted discarded packets: %+v", rep.Evidence.PacketDrops)
			}
		}},
		{"service.tcp_port_blocked", "healthy", true, nil, func(t *testing.T, control, rep Report) {
			if tcp := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
				t.Errorf("working target control = %+v", tcp)
			}
			out := rep.Tests[0]
			if diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "FAIL" ||
				diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" {
				t.Errorf("a filtered port took more than the target down: %+v", out)
			}
			if !tcpPortDroppedAt(rep.Evidence, "server", 80) {
				t.Errorf("the filter's own counter stayed at zero: %+v", rep.Evidence.PacketDrops)
			}
			// The half that keeps it out of the refusal family: the dial timed
			// out, it was not answered.
			if outcome, ok := controlledTargetOutcome(rep.Evidence, "client", "10.77.0.20:80"); !ok ||
				outcome != FamilyStateUnreachable {
				t.Errorf("a filtered port answered: %+v", rep.Evidence.ControlledTargets)
			}
		}},
		{"service.tls_hostname_mismatch", "tls-valid", true, []NetworkCondition{ConditionTLSHostnameMismatch}, func(t *testing.T, control, rep Report) {
			if tls := diagnosisCheck(control.Tests[0], string(diagnostic.ProbeTLS)); tls.Status != "PASS" {
				t.Errorf("valid TLS control = %+v", tls)
			}
			out := rep.Tests[0]
			if tls := diagnosisCheck(out, string(diagnostic.ProbeTLS)); tls.Status != "FAIL" ||
				tls.Cause != diagnostic.TLSCauseHostnameMismatch {
				t.Errorf("name-mismatch diagnosis = %+v", tls)
			}
			if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
				t.Errorf("the certificate change also broke TCP: %+v", tcp)
			}
			if !hasTLSEvidence(rep, TLSCertificateHostnameMismatch, "secure-target.test", tlsMismatchedDNSName,
				true, "client_rejected_certificate") {
				t.Errorf("no name-mismatch rejection evidence: %+v", rep.Evidence.TLS)
			}
			if anyExpiredCertificateRejected(rep.Evidence) {
				t.Error("a name mismatch also established the expired condition")
			}
		}},
		// The three routing families, on the control that can express all of
		// them. Each one is checked against the kernel's own route table, which
		// is the only reading that can show a route is absent.
		{"routing.no_default_route", "two-router-healthy", true, []NetworkCondition{ConditionIPv4InternetUnreachable, ConditionNoDefaultRoute}, func(t *testing.T, control, rep Report) {
			if before, ok := kernelRouteTable(control.Evidence, "client", "ipv4"); !ok || len(defaultRoutesIn(before)) != 1 {
				t.Errorf("the control did not start with one default route: %+v", before)
			}
			after, ok := kernelRouteTable(rep.Evidence, "client", "ipv4")
			if !ok || len(defaultRoutesIn(after)) != 0 {
				t.Errorf("the default route survived: %+v", after)
			}
			if len(after) == 0 {
				t.Error("the whole table went, which is a dead link rather than a missing default")
			}
			if internet := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)); internet.Cause != diagnostic.RouteCauseNoDefaultRoute {
				t.Errorf("no-default-route diagnosis = %+v", internet)
			}
		}},
		{"routing.wrong_default_route", "two-router-healthy", true, []NetworkCondition{ConditionIPv4InternetUnreachable}, func(t *testing.T, control, rep Report) {
			after, ok := kernelRouteTable(rep.Evidence, "client", "ipv4")
			defaults := defaultRoutesIn(after)
			if !ok || len(defaults) != 1 || defaults[0].Via != "10.80.1.254" {
				t.Errorf("the default route did not move to the on-link router that goes nowhere: %+v", after)
			}
			// The control that separates this from an outage past the gateway.
			if outcome, ok := controlledTargetOutcome(rep.Evidence, "client", "10.80.2.20:80"); !ok ||
				outcome != FamilyStateReachable {
				t.Errorf("the original next hop stopped forwarding, so this run is an outage: %+v",
					rep.Evidence.ControlledTargets)
			}
			if internet := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)); internet.Cause != diagnostic.RouteCauseSelectedPathFailed {
				t.Errorf("wrong-default-route diagnosis = %+v", internet)
			}
		}},
		{"routing.missing_subnet_route", "two-router-healthy", true, nil, func(t *testing.T, control, rep Report) {
			if before, ok := kernelRouteTable(control.Evidence, "client", "ipv4"); !ok ||
				!specificRouteCovering(before, "10.80.3.20") {
				t.Errorf("the control did not start with the specific route: %+v", before)
			}
			after, ok := kernelRouteTable(rep.Evidence, "client", "ipv4")
			if !ok || specificRouteCovering(after, "10.80.3.20") || len(defaultRoutesIn(after)) != 1 {
				t.Errorf("the route-shaped hole is not what the table shows: %+v", after)
			}
			out := rep.Tests[0]
			if diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)).Status != "FAIL" ||
				diagnosisCheck(out, string(diagnostic.ProbeInternet)).Status != "PASS" ||
				diagnosisCheck(out, string(diagnostic.ProbeDNS)).Status != "PASS" {
				t.Errorf("a missing subnet route took the internet with it: %+v", out)
			}
		}},
	}
	controls := map[string]Report{}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			base := loadHuntBase(t, tc.base)
			control := cloneScenario(base)
			canonicalScenarioInput(control)
			if err := control.Validate(); err != nil {
				t.Fatal(err)
			}
			controlReport, ok := controls[tc.base]
			if !ok {
				controlReport = runLibraryScenarioDefinition(t, sim, netdoc, tc.base, "-timeout", timedTimeout)
				if controlReport.Result != ResultPass {
					t.Fatalf("control result = %s, suggestions = %+v", controlReport.Result, controlReport.Suggestions)
				}
				assertCleanedUp(t, controlReport)
				controls[tc.base] = controlReport
			}
			op := huntOperator(t, tc.id)
			mutation, err := op.generate(newTestRNG(), control)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = tc.id
			manifest := GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}
			controlTruth := collectObservedTruth(manifest, &controlReport)
			if len(controlTruth.ObservedFaults) != 0 || mutationObserved(mutation, &controlReport, controlTruth) {
				t.Fatalf("unmutated control observed %s: %+v", tc.id, controlTruth)
			}
			mutated := cloneScenario(control)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "test-" + strings.NewReplacer(".", "-", "_", "-").Replace(tc.id)
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}
			rep := run(t, mutated)
			if killed := rep.Result != ResultPass; killed != tc.killed {
				t.Errorf("mutation killed = %t, want %t; result = %s, suggestions = %+v", killed, tc.killed, rep.Result, rep.Suggestions)
			}
			truth := collectObservedTruth(manifest, &rep)
			if !reflect.DeepEqual(truth.ObservedFaults, []string{tc.id}) || !mutationObserved(mutation, &rep, truth) {
				t.Errorf("%s observation = faults %v, observed %t", tc.id, truth.ObservedFaults,
					mutationObserved(mutation, &rep, truth))
			}
			withoutObservation := truth
			withoutObservation.ObservedFaults = []string{}
			if truthFingerprint(truth) == truthFingerprint(withoutObservation) {
				t.Errorf("%s observation did not change truth fingerprint", tc.id)
			}
			// The generic oracle against a real run, in both directions: the
			// simulator's own evidence establishes exactly the expected semantic
			// condition, the real diagnosis recognizes it, and a diagnosis with
			// its semantics withdrawn does not.
			want := tc.conditions
			if got := observedConditions(observation{Evidence: rep.Evidence, Truth: truth, Client: observedClient(&rep)}); !slices.Equal(got, want) {
				t.Errorf("%s observed conditions = %v, want %v", tc.id, got, want)
			}
			if accused := unrecognizedConditionFindings(&rep, truth); len(accused) != 0 {
				t.Errorf("%s: netdoc recognized the condition and hunt accused it anyway: %+v", tc.id, accused)
			}
			blind := unrecognizedConditionFindings(withoutSemantics(rep), truth)
			var surfaced []NetworkCondition
			for _, finding := range blind {
				surfaced = append(surfaced, NetworkCondition(finding.Expected))
			}
			if !slices.Equal(surfaced, want) {
				t.Errorf("%s: withdrawing the diagnosis semantics surfaced %v, want %v", tc.id, surfaced, want)
			}
			tc.check(t, controlReport, rep)
			assertCleanedUp(t, rep)
		})
	}
}

func TestHuntNetemDNSTimelineAndLinkMutationsAreObserved(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	run := func(t *testing.T, scenario *Scenario) Report {
		t.Helper()
		return runScenarioDefinition(t, sim, netdoc, scenario, "-timeout", timedTimeout)
	}

	base := loadHuntBase(t, "healthy-routed-network")
	control := cloneScenario(base)
	canonicalScenarioInput(control)
	if err := control.Validate(); err != nil {
		t.Fatal(err)
	}
	controlReport := runLibraryScenarioDefinition(t, sim, netdoc, "healthy-routed-network", "-timeout", timedTimeout)
	for _, id := range []string{
		"netem.loss", "netem.latency", "netem.jitter", "timeline.netem_spike",
		"dns.servfail", "dns.drop", "timeline.dns_outage", "link.transient_down",
	} {
		t.Run(id, func(t *testing.T) {
			if id == "netem.loss" || id == "netem.jitter" || id == "timeline.netem_spike" {
				requireNetemSeed(t)
			}
			op := huntOperator(t, id)
			if !op.applicable(control) {
				t.Fatal("production applicability predicate rejected healthy-routed-network")
			}
			mutation, err := op.generate(newTestRNG(), control)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = op.id
			manifest := GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}
			controlTruth := collectObservedTruth(manifest, &controlReport)
			if len(controlTruth.ObservedFaults) != 0 || mutationObserved(mutation, &controlReport, controlTruth) {
				t.Fatalf("unmutated control observed %s: %+v", id, controlTruth)
			}

			mutated := cloneScenario(control)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "test-" + strings.NewReplacer(".", "-", "_", "-").Replace(id)
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}
			rep := run(t, mutated)
			truth := collectObservedTruth(manifest, &rep)
			if !reflect.DeepEqual(truth.ObservedFaults, []string{id}) || !mutationObserved(mutation, &rep, truth) {
				t.Fatalf("%s observation = faults %v, observed %t; faults=%+v timeline=%+v packet=%+v",
					id, truth.ObservedFaults, mutationObserved(mutation, &rep, truth), rep.Faults, rep.Timeline,
					rep.Evidence.PacketConditions)
			}
			withoutObservation := truth
			withoutObservation.ObservedFaults = []string{}
			if truthFingerprint(truth) == truthFingerprint(withoutObservation) {
				t.Fatal("observed mutation did not change truth fingerprint")
			}
			t.Logf("%s generated=%+v faults=%+v timeline=%+v packet=%+v mutationObserved=true",
				id, mutation, rep.Faults, rep.Timeline, rep.Evidence.PacketConditions)
		})
	}
	assertCleanedUp(t, controlReport)
}

func TestPreferredPathFailureMutationIsIndependentlyObserved(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	run := func(t *testing.T, scenario *Scenario) Report {
		t.Helper()
		return runScenarioDefinition(t, sim, netdoc, scenario)
	}
	targetObservation := func(t *testing.T, report Report, target string) ControlledTargetEvidence {
		t.Helper()
		for _, item := range report.Evidence.ControlledTargets {
			if item.From == "client" && item.To == target {
				return item
			}
		}
		t.Fatalf("controlled alternate-target observation absent: %+v", report.Evidence.ControlledTargets)
		return ControlledTargetEvidence{}
	}

	for _, tc := range []struct {
		name, base, family, preferredVia, endpoint, target string
	}{
		{"IPv4", "two-path-healthy", "ipv4", "10.79.1.1", "1.1.1.1", "9.9.9.9:80"},
		{"IPv6", "two-path-ipv6-healthy", "ipv6", "2001:db8:79:1::1", "2606:4700:4700::1111", "[2001:db8:79::99]:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := loadHuntBase(t, tc.base)
			op := huntOperator(t, "routing.preferred_path_failure")
			if !op.applicable(base) {
				t.Fatalf("production applicability rejected %s", tc.base)
			}
			mutation, err := op.generate(newTestRNG(), base)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = op.id
			manifest := GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}

			baseline := runLibraryScenarioDefinition(t, sim, netdoc, tc.base)
			if baseline.Result != ResultPass {
				t.Fatalf("baseline result = %s; tests=%+v suggestions=%+v", baseline.Result, baseline.Tests, baseline.Suggestions)
			}
			baselineFamily, count := familyReachability(baseline, "client", tc.family)
			if count != 1 || baselineFamily.State != FamilyStateReachable ||
				!reflect.DeepEqual(baselineFamily.Via, []string{"preferred-lan", tc.preferredVia}) {
				t.Fatalf("baseline preferred reachability = %+v count=%d", baselineFamily, count)
			}
			if alternate := targetObservation(t, baseline, tc.target); !alternate.Reachable || alternate.Family != tc.family ||
				!reflect.DeepEqual(alternate.Via, []string{"alternate-lan", mutation.AlternateVia}) {
				t.Fatalf("baseline alternate reachability = %+v", alternate)
			}
			baselineTruth := collectObservedTruth(manifest, &baseline)
			if len(baselineTruth.ObservedFaults) != 0 || mutationObserved(mutation, &baseline, baselineTruth) {
				t.Fatalf("healthy baseline observed routing failure: %+v", baselineTruth)
			}

			mutated := cloneScenario(base)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "test-routing-preferred-path-failure-" + tc.family
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}
			rep := run(t, mutated)
			mutatedFamily, count := familyReachability(rep, "client", tc.family)
			if count != 1 || mutatedFamily.State != FamilyStateUnreachable || !reflect.DeepEqual(mutatedFamily.Via, baselineFamily.Via) {
				t.Fatalf("mutated preferred reachability = %+v count=%d; baseline=%+v", mutatedFamily, count, baselineFamily)
			}
			if alternate := targetObservation(t, rep, tc.target); !alternate.Reachable || alternate.Family != tc.family ||
				!reflect.DeepEqual(alternate.Via, []string{"alternate-lan", mutation.AlternateVia}) {
				t.Fatalf("mutated alternate reachability = %+v", alternate)
			}
			if !hasSelectedRoute(rep, "client", tc.endpoint, tc.preferredVia, "preferred-lan", nil) ||
				!hasLink(rep, "preferred-gateway", "preferred-upstream", false) {
				t.Fatalf("preferred route was not retained over the failed path: routes=%+v links=%+v", rep.Evidence.Routes, rep.Evidence.Links)
			}
			truth := collectObservedTruth(manifest, &rep)
			if !reflect.DeepEqual(truth.ObservedFaults, []string{mutation.ID}) || !mutationObserved(mutation, &rep, truth) {
				t.Fatalf("routing consequence was not independently observed: truth=%+v mutation=%+v", truth, mutation)
			}
			if truthFingerprint(truth) == truthFingerprint(baselineTruth) {
				t.Fatal("routing consequence did not change truth fingerprint")
			}
			// Read the same authoritative run the oracle grades. Earlier client
			// tests can legitimately describe an older network state.
			final := finalClientTest(&rep)
			if final == nil {
				t.Fatal("final client test is absent")
			}
			check := diagnosisCheck(*final, string(diagnostic.ProbeInternet))
			if check.Cause != diagnostic.RouteCausePreferredPathFailed || diagnosedFamily(final.Diagnosis, tc.family) != FamilyStateUnreachable {
				t.Fatalf("diagnosis did not recognize %s preferred-path failure: %+v stderr=%s", tc.family, check, final.Stderr)
			}
			if findings := unrecognizedConditionFindings(&rep, truth); len(findings) != 1 || findings[0].Expected != string(ConditionPreferredRouteFailed) {
				t.Fatalf("selection metadata must leave the independently observed %s route fault unrecognized: %+v", tc.family, findings)
			}
			t.Logf("mutation=%+v baseline=%+v mutated=%+v diagnosis=%s/%s families=%+v mutationObserved=true",
				mutation, baselineFamily, mutatedFamily, check.Status, check.Cause, check.Families)
			assertCleanedUp(t, baseline)
			assertCleanedUp(t, rep)
		})
	}
}

// TestPreferredRouteFailureConditionIsEstablishedIndependently is the oracle
// half of the v7 promotion, on the two bases the promotion exists for. It
// asserts the condition the way a hunt establishes it, from the simulator's own
// evidence with the manifest nowhere in sight, and then reconciles that against
// whatever netdoc said.
//
// Deliberately not written as "netdoc gets this right". The reconciliation is
// asserted in both directions instead: a recognized condition must leave no
// finding, and an unrecognized one must leave exactly one high-severity
// finding naming it. That is the machinery being correct, which stays true
// whether or not a given base currently gets the right answer, so fixing a
// diagnosis this catches does not also break its test.
func TestPreferredRouteFailureConditionIsEstablishedIndependently(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	for _, tc := range []struct{ name, base, family string }{
		{"IPv4", "two-path-healthy", "ipv4"},
		{"IPv6", "two-path-ipv6-healthy", "ipv6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := loadHuntBase(t, tc.base)
			op := huntOperator(t, "routing.preferred_path_failure")
			if op.laneFor(HuntGeneratorVersion) != HuntLaneBugOracle {
				t.Fatalf("%s is not in the bug-oracle lane at %s", op.id, HuntGeneratorVersion)
			}
			mutation, err := op.generate(newTestRNG(), base)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = op.id
			manifest := GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}

			// The unmutated base must establish nothing. Two healthy defaults
			// with a strict preference between them is the shape this condition
			// keys on, and it is the shape this base always has, so a rule that
			// forgot to ask whether the path is dead would fire here.
			baseline := runLibraryScenarioDefinition(t, sim, netdoc, tc.base)
			baselineTruth := collectObservedTruth(manifest, &baseline)
			baselineEstablished, _, baselineComparable := caseConditions(&baseline, baselineTruth)
			if !baselineComparable {
				t.Fatalf("healthy %s was not a final-state comparison", tc.base)
			}
			if slices.Contains(baselineEstablished, ConditionPreferredRouteFailed) {
				t.Fatalf("a healthy multipath base established %s: %+v", ConditionPreferredRouteFailed, baselineEstablished)
			}

			mutated := cloneScenario(base)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "test-preferred-route-condition-" + tc.family
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}
			rep := runScenarioDefinition(t, sim, netdoc, mutated)
			truth := collectObservedTruth(manifest, &rep)
			established, recognized, comparable := caseConditions(&rep, truth)
			if !comparable {
				t.Fatalf("the mutated %s case was not a final-state comparison", tc.base)
			}
			if !slices.Contains(established, ConditionPreferredRouteFailed) {
				t.Fatalf("%s did not establish %s: established=%v faults=%v routes=%+v targets=%+v",
					tc.base, ConditionPreferredRouteFailed, established, truth.ObservedFaults,
					rep.Evidence.RouteTables, rep.Evidence.ControlledTargets)
			}
			// The two route conditions read the same table and disagree about
			// it, so one network can never be both.
			if slices.Contains(established, ConditionNoDefaultRoute) {
				t.Fatalf("%s established both route conditions: %v", tc.base, established)
			}
			findings := unrecognizedConditionFindings(&rep, truth)
			named := slices.ContainsFunc(findings, func(f HuntCaseFinding) bool {
				return f.Expected == string(ConditionPreferredRouteFailed) && f.Severity == SeverityHigh &&
					f.Category == FindingFalseNegative
			})
			switch {
			case slices.Contains(recognized, ConditionPreferredRouteFailed) && named:
				t.Fatalf("%s recognized the condition and was still accused: %+v", tc.base, findings)
			case !slices.Contains(recognized, ConditionPreferredRouteFailed) && !named:
				t.Fatalf("%s left the condition unrecognized and unreported: findings=%+v", tc.base, findings)
			}
			t.Logf("%s established=%v recognized=%v findings=%d diagnosis=%+v",
				tc.base, established, recognized, len(findings), finalClientDiagnosis(&rep).Checks)
			assertCleanedUp(t, baseline)
			assertCleanedUp(t, rep)
		})
	}
}

// TestFamilyDropMutationsMoveHolderSideObservation validates the family oracle
// on its own, before any hunt analysis is allowed to depend on it. It asserts
// two layers and nothing else: the raw observation the client holder produced by
// dialing the controlled endpoints from inside its own namespace, and the truth
// derived from it. No finding, no verdict and no expectation row is consulted,
// so a failure here is an oracle failure rather than an analysis failure.
func TestFamilyDropMutationsMoveHolderSideObservation(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	control := cloneScenario(loadHuntBase(t, "dual-stack-healthy"))
	canonicalScenarioInput(control)
	if err := control.Validate(); err != nil {
		t.Fatal(err)
	}
	// truthFamilies reads the two derived values without letting a test name a
	// family in one layer and check the other, which is how a swap hides.
	truthFamilies := func(truth ObservedTruth) map[string]string {
		return map[string]string{"ipv4": truth.IPv4, "ipv6": truth.IPv6}
	}

	baseline := runLibraryScenarioDefinition(t, sim, netdoc, "dual-stack-healthy")
	for _, family := range []string{"ipv4", "ipv6"} {
		if item := clientFamilyObservation(t, baseline, family); item.State != FamilyStateReachable {
			t.Fatalf("healthy dual-stack %s observation = %q, want %q", family, item.State, FamilyStateReachable)
		}
	}
	baselineTruth := truthFamilies(collectObservedTruth(GeneratedCaseManifest{}, &baseline))
	if baselineTruth["ipv4"] != FamilyStateReachable || baselineTruth["ipv6"] != FamilyStateReachable {
		t.Fatalf("healthy dual-stack truth = %v, want both %q", baselineTruth, FamilyStateReachable)
	}
	assertCleanedUp(t, baseline)

	for _, tc := range []struct{ id, dropped, intact string }{
		{id: "family.ipv4_drop", dropped: "ipv4", intact: "ipv6"},
		{id: "family.ipv6_drop", dropped: "ipv6", intact: "ipv4"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			op := huntOperator(t, tc.id)
			if !op.applicable(control) {
				t.Fatal("production applicability predicate rejected the dual-stack baseline")
			}
			mutation, err := op.generate(newTestRNG(), control)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = op.id
			if mutation.Family != tc.dropped {
				t.Fatalf("%s generated family %q, want %q", tc.id, mutation.Family, tc.dropped)
			}
			mutated := cloneScenario(control)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "oracle-" + strings.ReplaceAll(tc.id, ".", "-")
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}

			rep := runScenarioDefinition(t, sim, netdoc, mutated)
			// A generator that edits metadata without reaching the kernel would
			// leave both families reachable below; this says so directly.
			applied := false
			for _, fault := range rep.Faults {
				if fault.Type == FaultDrop && fault.Node == mutation.Node && fault.Family == tc.dropped &&
					slices.Contains(fault.Command, "nfproto") {
					applied = true
				}
			}
			if !applied {
				t.Fatalf("%s applied no %s drop rule at %s: %+v", tc.id, tc.dropped, mutation.Node, rep.Faults)
			}

			// The dropped family was dialed and refused. Unavailable would mean
			// the client lost its address in that family, which this mutation
			// does not do, and a missing record would mean nothing was measured.
			dropped := clientFamilyObservation(t, rep, tc.dropped)
			if dropped.State != FamilyStateUnreachable {
				t.Errorf("%s observation after %s = %q, want %q", tc.dropped, tc.id, dropped.State, FamilyStateUnreachable)
			}
			if intact := clientFamilyObservation(t, rep, tc.intact); intact.State != FamilyStateReachable {
				t.Errorf("%s observation after %s = %q, want %q (the topology still carries it)",
					tc.intact, tc.id, intact.State, FamilyStateReachable)
			}

			truth := collectObservedTruth(GeneratedCaseManifest{}, &rep)
			got := truthFamilies(truth)
			if got[tc.dropped] != FamilyStateUnreachable || got[tc.intact] != FamilyStateReachable {
				t.Fatalf("truth after %s = %v, want %s %q and %s %q",
					tc.id, got, tc.dropped, FamilyStateUnreachable, tc.intact, FamilyStateReachable)
			}

			// Rewrite what netdoc concluded, leaving the holder's observation
			// alone. Truth measured inside the namespace cannot move; truth
			// copied out of the diagnosis would flip to reachable.
			if fabricated := truthFamilies(collectObservedTruth(GeneratedCaseManifest{},
				claimingFamilies(rep, FamilyStateReachable, FamilyStateReachable))); !reflect.DeepEqual(fabricated, got) {
				t.Fatalf("%s truth followed a substituted diagnosis: %v, want the observed %v", tc.id, fabricated, got)
			}
			t.Logf("%s observed %s=%s %s=%s over %v", tc.id, tc.dropped, dropped.State, tc.intact,
				got[tc.intact], dropped.Via)
			assertCleanedUp(t, rep)
		})
	}
}

// claimingFamilies copies a report with netdoc's internet check rewritten to
// claim these two family states, so a caller can prove what does not read it.
func claimingFamilies(rep Report, ipv4, ipv6 string) *Report {
	out := rep
	out.Tests = append([]TestOutcome(nil), rep.Tests...)
	for i := range out.Tests {
		if out.Tests[i].Diagnosis == nil {
			continue
		}
		diagnosis := *out.Tests[i].Diagnosis
		diagnosis.Checks = append([]DiagnosisCheck(nil), diagnosis.Checks...)
		for c := range diagnosis.Checks {
			if diagnosis.Checks[c].ID == string(diagnostic.ProbeInternet) {
				diagnosis.Checks[c].Families = &DiagnosisFamilies{IPv4: ipv4, IPv6: ipv6}
			}
		}
		out.Tests[i].Diagnosis = &diagnosis
	}
	return &out
}

// withoutSemantics copies a real run with every diagnostic cause and per-family
// verdict withdrawn, leaving statuses alone. It is the diagnosis that noticed
// something broke and never said what, which is the shape a false negative has.
func withoutSemantics(rep Report) *Report {
	out := rep
	out.Tests = append([]TestOutcome(nil), rep.Tests...)
	for i := range out.Tests {
		if out.Tests[i].Diagnosis == nil {
			continue
		}
		diagnosis := *out.Tests[i].Diagnosis
		diagnosis.Checks = append([]DiagnosisCheck(nil), diagnosis.Checks...)
		for c := range diagnosis.Checks {
			diagnosis.Checks[c].Cause, diagnosis.Checks[c].Families = "", nil
		}
		out.Tests[i].Diagnosis = &diagnosis
	}
	return &out
}

// substituteFamilies copies a real run with the dropped family's structured
// verdict rewritten to reachable, optionally also withdrawing the cause that
// names the family. Only the diagnosis is touched, so the holder's own
// measurements stay exactly where they were.
func substituteFamilies(rep Report, mutationID string, withdrawCause bool) *Report {
	out := rep
	out.Tests = append([]TestOutcome(nil), rep.Tests...)
	diagnosis := *out.Tests[0].Diagnosis
	diagnosis.Checks = append([]DiagnosisCheck(nil), diagnosis.Checks...)
	for i := range diagnosis.Checks {
		if diagnosis.Checks[i].ID != string(diagnostic.ProbeInternet) {
			continue
		}
		families := *diagnosis.Checks[i].Families
		if mutationID == "family.ipv4_drop" {
			families.IPv4 = FamilyStateReachable
		} else {
			families.IPv6 = FamilyStateReachable
		}
		diagnosis.Checks[i].Families = &families
		if withdrawCause {
			diagnosis.Checks[i].Cause = ""
		}
	}
	out.Tests[0].Diagnosis = &diagnosis
	return &out
}

func familyCauseFor(family string) string {
	if family == "ipv4" {
		return diagnostic.FamilyCauseIPv4Unreachable
	}
	return diagnostic.FamilyCauseIPv6Unreachable
}

func TestHuntFamilyMutationsMoveIndependentReachability(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	base := loadHuntBase(t, "dual-stack-healthy")
	control := cloneScenario(base)
	canonicalScenarioInput(control)
	if err := control.Validate(); err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, scenario *Scenario) Report {
		t.Helper()
		return runScenarioDefinition(t, sim, netdoc, scenario)
	}
	observed := func(t *testing.T, rep Report, family string) FamilyReachabilityEvidence {
		t.Helper()
		return clientFamilyObservation(t, rep, family)
	}

	baseline := runLibraryScenarioDefinition(t, sim, netdoc, "dual-stack-healthy")
	baseline4, baseline6 := observed(t, baseline, "ipv4"), observed(t, baseline, "ipv6")
	if baseline4.State != FamilyStateReachable || baseline6.State != FamilyStateReachable {
		t.Fatalf("dual-stack baseline = IPv4 %q, IPv6 %q; want both reachable", baseline4.State, baseline6.State)
	}
	baselineTruth := collectObservedTruth(GeneratedCaseManifest{}, &baseline)
	baselineFingerprint := truthFingerprint(baselineTruth)
	if baselineTruth.IPv4 != "reachable" || baselineTruth.IPv6 != "reachable" {
		t.Fatalf("dual-stack baseline truth = IPv4 %q, IPv6 %q; want both reachable", baselineTruth.IPv4, baselineTruth.IPv6)
	}
	if len(baselineTruth.ObservedFaults) != 0 {
		t.Fatalf("unmutated baseline observed faults = %v, want none", baselineTruth.ObservedFaults)
	}
	if findings := familyMismatchFindings(analyzeHuntCase(GeneratedCaseManifest{}, &baseline, baselineTruth)); len(findings) != 0 {
		t.Fatalf("healthy dual-stack baseline produced a family mismatch: %+v", findings)
	}
	t.Logf("baseline truth IPv4=%s IPv6=%s fingerprint=%s", baselineTruth.IPv4, baselineTruth.IPv6, baselineFingerprint)

	for _, tc := range []struct {
		id         string
		ipv4, ipv6 bool
	}{
		{id: "family.ipv4_drop", ipv4: false, ipv6: true},
		{id: "family.ipv6_drop", ipv4: true, ipv6: false},
		{id: "quic.udp_443_block", ipv4: true, ipv6: true},
		{id: "encrypted_dns.doh_invalid", ipv4: true, ipv6: true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			if baseline4.State != FamilyStateReachable || baseline6.State != FamilyStateReachable {
				t.Fatal("mutation has no reachable dual-stack baseline")
			}
			op := huntOperator(t, tc.id)
			if !op.applicable(control) {
				t.Fatal("production applicability predicate rejected the dual-stack baseline")
			}
			mutation, err := op.generate(newTestRNG(), control)
			if err != nil {
				t.Fatal(err)
			}
			mutation.ID = op.id
			if mutation.ID != tc.id {
				t.Fatalf("generated mutation ID = %q, want %q", mutation.ID, tc.id)
			}
			if strings.HasPrefix(tc.id, "family.") {
				baselineWithManifest := collectObservedTruth(GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}, &baseline)
				if len(baselineWithManifest.ObservedFaults) != 0 || mutationObserved(mutation, &baseline, baselineWithManifest) {
					t.Fatalf("%s counted as observed against reachable baseline truth: %+v", tc.id, baselineWithManifest)
				}
			}
			mutated := cloneScenario(control)
			canonicalScenarioInput(mutated)
			if err := applyGeneratedMutation(mutated, mutation); err != nil {
				t.Fatal(err)
			}
			mutated.Name = "evidence-" + strings.ReplaceAll(tc.id, ".", "-")
			if err := mutated.Validate(); err != nil {
				t.Fatal(err)
			}

			rep := run(t, mutated)
			ipv4, ipv6 := observed(t, rep, "ipv4"), observed(t, rep, "ipv6")
			want4, want6 := familyState(tc.ipv4), familyState(tc.ipv6)
			if ipv4.State != want4 || ipv6.State != want6 {
				t.Errorf("independent reachability after %s = IPv4 %q, IPv6 %q; want %q, %q",
					tc.id, ipv4.State, ipv6.State, want4, want6)
			}
			// Checked for every mutation, not only the family ones: a mutation
			// that leaves both families working must not invent a family outage
			// in observed truth either.
			truth := collectObservedTruth(GeneratedCaseManifest{}, &rep)
			if truth.IPv4 != want4 || truth.IPv6 != want6 {
				t.Fatalf("truth after %s = IPv4 %q, IPv6 %q; want %q, %q", tc.id, truth.IPv4, truth.IPv6, want4, want6)
			}
			if strings.HasPrefix(tc.id, "family.") {
				equivalent := truth
				equivalent.IPv4, equivalent.IPv6 = baselineTruth.IPv4, baselineTruth.IPv6
				if !reflect.DeepEqual(equivalent, baselineTruth) {
					t.Fatalf("%s changed non-family truth:\nbaseline %+v\nmutated  %+v", tc.id, baselineTruth, truth)
				}
				if truthFingerprint(truth) == baselineFingerprint {
					t.Errorf("%s changed family truth without changing its truth fingerprint", tc.id)
				}
				observedTruth := collectObservedTruth(GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}, &rep)
				if !reflect.DeepEqual(observedTruth.ObservedFaults, []string{tc.id}) || !mutationObserved(mutation, &rep, observedTruth) {
					t.Fatalf("%s was not observed from independent family truth: %+v", tc.id, observedTruth)
				}
				manifest := GeneratedCaseManifest{Mutations: []GeneratedMutation{mutation}}
				check := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet))
				if check.Families == nil || check.Families.IPv4 != want4 || check.Families.IPv6 != want6 {
					t.Fatalf("%s diagnosis families = %+v, want IPv4=%s IPv6=%s", tc.id, check.Families, want4, want6)
				}
				if findings := familyMismatchFindings(analyzeHuntCase(manifest, &rep, observedTruth)); len(findings) != 0 {
					t.Fatalf("%s produced a mismatch despite agreeing diagnosis: %+v", tc.id, findings)
				}

				// Two substitutions against one real run, because a family loss
				// has two legitimate diagnostic representations. Dropping only
				// the structured verdict leaves netdoc's family cause standing,
				// which still tells the user which family is gone; only
				// withdrawing both is a genuine miss.
				keptCause := substituteFamilies(rep, tc.id, false)
				keptCauseTruth := collectObservedTruth(manifest, keptCause)
				if !reflect.DeepEqual(keptCauseTruth, observedTruth) || !mutationObserved(mutation, keptCause, keptCauseTruth) {
					t.Fatalf("substituted diagnosis changed simulator truth or mutation observation:\ntruth %+v\nwrong %+v", observedTruth, keptCauseTruth)
				}
				cause := diagnosisCheck(keptCause.Tests[0], string(diagnostic.ProbeInternet)).Cause
				if cause != familyCauseFor(mutation.Family) {
					t.Fatalf("%s diagnosis cause = %q, want %q", tc.id, cause, familyCauseFor(mutation.Family))
				}
				if findings := familyMismatchFindings(analyzeHuntCase(manifest, keptCause, keptCauseTruth)); len(findings) != 0 {
					t.Fatalf("%s equivalent recognition by cause was accused: %+v", tc.id, findings)
				}

				wrong := substituteFamilies(rep, tc.id, true)
				wrongTruth := collectObservedTruth(manifest, wrong)
				if !reflect.DeepEqual(wrongTruth, observedTruth) || !mutationObserved(mutation, wrong, wrongTruth) {
					t.Fatalf("substituted diagnosis changed simulator truth or mutation observation:\ntruth %+v\nwrong %+v", observedTruth, wrongTruth)
				}
				findings := familyMismatchFindings(analyzeHuntCase(manifest, wrong, wrongTruth))
				if len(findings) != 1 || findings[0].Category != FindingFalseNegative || findings[0].Family != mutation.Family {
					t.Fatalf("%s wrong diagnosis findings = %+v", tc.id, findings)
				}
				t.Logf("%s truth IPv4=%s IPv6=%s fingerprint=%s mutationObserved=true diagnosis=agree cause-only=recognized wrong-diagnosis=%s-miss",
					tc.id, truth.IPv4, truth.IPv6, truthFingerprint(truth), mutation.Family)
			}
			assertCleanedUp(t, rep)
		})
	}
	assertCleanedUp(t, baseline)
}

func hasHuntSuggestion(suggestions []HuntSuggestion, code string) bool {
	for _, suggestion := range suggestions {
		if suggestion.Code == code {
			return true
		}
	}
	return false
}

func TestSOCKS5LocalDNSScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "socks5-local-dns-fails")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; evidence: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Evidence)
	}
	out := rep.Tests[0]
	proxy := diagnosisCheck(out, string(diagnostic.ProbeProxy))
	if proxy.Status != "FAIL" || proxy.Cause != diagnostic.ProxyCauseClientDNS ||
		!strings.Contains(proxy.Detail, "is reachable, but local DNS cannot resolve") {
		t.Errorf("proxy_connect = %+v", proxy)
	}
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d", out.FalsePositives, out.FalseNegatives)
	}
	if !hasSOCKSEvidence(rep, "greeting", "", "accepted") {
		t.Errorf("no accepted SOCKS greeting evidence: %+v", rep.Evidence.SOCKSRequests)
	}
	if hasSOCKSEvidence(rep, "connect", "domain", "connected") {
		t.Errorf("local SOCKS unexpectedly sent a domain request: %+v", rep.Evidence.SOCKSRequests)
	}
	if !hasDNSEvidence(rep, "client-dns", "10.77.0.10", proxyProbeName, "NXDOMAIN") {
		t.Errorf("no client-side NXDOMAIN evidence: %+v", rep.Evidence.DNS)
	}
	if hasDNSEvidence(rep, "proxy", "10.77.0.30", proxyProbeName, "ANSWER") {
		t.Errorf("proxy resolved a name it never received: %+v", rep.Evidence.DNS)
	}
	assertCleanedUp(t, rep)
}

func TestSOCKS5hRemoteDNSScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "socks5h-remote-dns-succeeds")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; evidence: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Evidence)
	}
	out := rep.Tests[0]
	if proxy := diagnosisCheck(out, string(diagnostic.ProbeProxy)); proxy.Status != "PASS" {
		t.Errorf("proxy_connect = %+v", proxy)
	}
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d", out.FalsePositives, out.FalseNegatives)
	}
	if !hasSOCKSEvidence(rep, "connect", "domain", "connected") {
		t.Errorf("no successful domain CONNECT evidence: %+v", rep.Evidence.SOCKSRequests)
	}
	// The direct-egress row's captive-portal check asks the client's own
	// resolver for this name, and should: it is not the proxied path. What
	// socks5h promises is that the client never *learns* the address: the
	// client's view answers NXDOMAIN and only the proxy resolves it.
	if hasDNSEvidence(rep, "client-dns", "10.77.0.10", proxyProbeName, "ANSWER") {
		t.Errorf("the client's own resolver answered the proxied name: %+v", rep.Evidence.DNS)
	}
	if !hasDNSEvidence(rep, "client-dns", "10.77.0.10", proxyProbeName, "NXDOMAIN") {
		t.Errorf("the client's view of the proxied name is not absent: %+v", rep.Evidence.DNS)
	}
	if !hasDNSEvidence(rep, "proxy", "10.77.0.30", proxyProbeName, "ANSWER") {
		t.Errorf("no proxy-side answer evidence: %+v", rep.Evidence.DNS)
	}
	assertCleanedUp(t, rep)
}

// TestProxyOnlyNetworkScenario is the regression for netdoc's headline proxy
// claim: a machine with no direct TCP/443 egress and a working HTTP CONNECT
// proxy reads as online through that proxy, not as offline. Everything below
// the diagnosis is real: the client dials nothing but the proxy, the proxy
// speaks RFC 9110 CONNECT, and the production probe is handed the proxy the way
// a corporate network hands it over, through HTTPS_PROXY.
func TestProxyOnlyNetworkScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "proxy-only-network", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}
	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d: %+v", out.FalsePositives, out.FalseNegatives, out.Checks)
	}
	if out.Proxy != "http://10.77.0.30:3128" {
		t.Errorf("netdoc was handed proxy %q", out.Proxy)
	}

	// Half one of the claim, measured by the simulator rather than read off
	// netdoc's own report: from inside the client namespace, the fixed internet
	// endpoints on TCP/443 are unreachable.
	assertObservedFamily(t, rep, "ipv4", FamilyStateUnreachable)
	if !droppedOutbound(rep.Evidence, "client", "tcp", 443) {
		t.Errorf("the client's own TCP/443 filter never matched a packet: %+v", rep.Evidence.PacketDrops)
	}

	// Half two, measured by the fixture: the proxy answered a real CONNECT with
	// 200, which it sends only once it has the upstream connection open. That
	// is proxy-to-destination reachability, stated by the proxy.
	if !hasServiceReply(rep, "proxy", "connect-proxy", ServiceHTTPConnect, 200) {
		t.Errorf("the CONNECT proxy never established a tunnel: %+v", rep.Evidence.ServiceReplies)
	}
	for _, reply := range rep.Evidence.ServiceReplies {
		if reply.Type == ServiceHTTPConnect && reply.Status != 200 {
			t.Errorf("the CONNECT proxy also answered %d: %+v", reply.Status, reply)
		}
	}
	// The tunnel authority was resolved from the proxy's namespace, which is
	// what a CONNECT proxy does and what says the request reached it as a name.
	if !hasDNSEvidence(rep, "internet", "10.77.0.30", proxyProbeName, "ANSWER") {
		t.Errorf("no proxy-side lookup of the CONNECT authority: %+v", rep.Evidence.DNS)
	}

	// And the diagnosis those two halves have to produce.
	internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
	if internet.Status != "WARN" || !strings.Contains(internet.Detail, "no direct TCP egress") {
		t.Errorf("direct egress row = %+v", internet)
	}
	proxy := diagnosisCheck(out, string(diagnostic.ProbeProxy))
	if proxy.Status != "PASS" || !strings.Contains(proxy.Detail, "10.77.0.30:3128 tunnels to "+proxyProbeName+":443") {
		t.Errorf("proxy_connect = %+v", proxy)
	}
	if out.ActualVerdict != "degraded" {
		t.Errorf("verdict = %q, want degraded", out.ActualVerdict)
	}
	// The user-visible half of the claim. A proxy-only network that reads as an
	// outage is the regression this scenario exists to catch.
	if summary := out.Diagnosis.Summary; strings.Contains(summary, "Offline") {
		t.Errorf("proxy-only network diagnosed as offline: %q", summary)
	}
	assertCleanedUp(t, rep)
}

// TestProxyOnlyNetworkBrokenDNSScenario is the same proxy-only network with its
// configured resolver taken away as well. It is the regression for a summary
// that used to read a downgraded egress row as working egress: the direct route
// is dead, no name resolves, and the CONNECT proxy is the only thing carrying
// traffic, so the diagnosis has to say both halves and promise neither.
func TestProxyOnlyNetworkBrokenDNSScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "proxy-only-network-broken-dns", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}
	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d: %+v", out.FalsePositives, out.FalseNegatives, out.Checks)
	}

	// The three halves of the state, each measured rather than assumed. The
	// client's own filters matched real packets on TCP/443 and on both
	// transports port 53 runs on, and the proxy answered a real CONNECT with
	// the 200 it sends only once the upstream connection is open.
	if !droppedOutbound(rep.Evidence, "client", "tcp", 443) {
		t.Errorf("the client's own TCP/443 filter never matched a packet: %+v", rep.Evidence.PacketDrops)
	}
	if !droppedOutbound(rep.Evidence, "client", "udp", 53) {
		t.Errorf("the client's own UDP/53 filter never matched a packet: %+v", rep.Evidence.PacketDrops)
	}
	if !hasServiceReply(rep, "proxy", "connect-proxy", ServiceHTTPConnect, 200) {
		t.Errorf("the CONNECT proxy never established a tunnel: %+v", rep.Evidence.ServiceReplies)
	}
	// Resolved from the proxy's namespace, which is what keeps the tunnel
	// working while the client resolves nothing.
	if !hasDNSEvidence(rep, "internet", "10.77.0.30", proxyProbeName, "ANSWER") {
		t.Errorf("no proxy-side lookup of the CONNECT authority: %+v", rep.Evidence.DNS)
	}

	// The rows those measurements have to produce.
	internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
	if internet.Status != "WARN" || !strings.Contains(internet.Detail, "but the environment proxy works") {
		t.Errorf("direct egress row = %+v", internet)
	}
	if proxy := diagnosisCheck(out, string(diagnostic.ProbeProxy)); proxy.Status != "PASS" {
		t.Errorf("proxy_connect = %+v", proxy)
	}
	if dns := diagnosisCheck(out, string(diagnostic.ProbeDNS)); dns.Status != "FAIL" {
		t.Errorf("dns = %+v", dns)
	}
	if out.ActualVerdict != "network" {
		t.Errorf("verdict = %q, want network", out.ActualVerdict)
	}

	// And the user-visible claim. A WARN that downgradeEgress planted is a dead
	// direct route, so the summary may not open by saying egress works.
	summary := out.Diagnosis.Summary
	want := "Direct egress is blocked and DNS resolution is failing; only the environment proxy is carrying traffic."
	if summary != want {
		t.Errorf("summary = %q, want %q", summary, want)
	}
	assertCleanedUp(t, rep)
}

// TestEncryptedDNSBlockedScenario is one half of the README's independence
// claim: a network can carry ordinary DNS while blocking DoH and DoT. Both
// encrypted transports are cut off at the one bootstrap address the row dials,
// and nothing else is, so every plaintext row around it has to stay green. A
// FAIL here that came with a dead path or a dead resolver would prove nothing,
// which is what the passing rows are for.
func TestEncryptedDNSBlockedScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "encrypted-dns-blocked", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}
	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d: %+v", out.FalsePositives, out.FalseNegatives, out.Checks)
	}

	// Both filters bit. Without this a scenario whose rules never matched a
	// packet would still pass on the day the probe broke for its own reasons.
	for _, port := range []int{443, 853} {
		if !droppedOutbound(rep.Evidence, "client", "tcp", port) {
			t.Errorf("the client's outbound TCP/%d filter never matched a packet: %+v", port, rep.Evidence.PacketDrops)
		}
	}

	// The negative half, stated per transport. The row passes on either one, so
	// a DoT that stayed reachable would already have turned this scenario PASS
	// into a wrong_status; naming both here says which of them the detail
	// actually accounted for.
	encrypted := diagnosisCheck(out, string(diagnostic.ProbeDNSEncrypted))
	if encrypted.Status != "FAIL" || encrypted.Cause != diagnostic.EncryptedDNSCauseTimeout {
		t.Errorf("dns_encrypted = %+v", encrypted)
	}
	for _, transport := range []string{"DoH:", "DoT:"} {
		if !strings.Contains(encrypted.Detail, transport) {
			t.Errorf("dns_encrypted detail does not account for %s: %q", transport, encrypted.Detail)
		}
	}

	// The positive half, from three independent directions: netdoc resolved
	// through the plaintext resolver, the fixture recorded answering it, and
	// direct egress survived on the address the rules left alone. That last one
	// is what a rule that widened past 1.1.1.1 would break.
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeDNS, diagnostic.ProbeDNSPublic, diagnostic.ProbeQUIC} {
		if check := diagnosisCheck(out, string(id)); check.Status != "PASS" {
			t.Errorf("%s = %+v, want PASS while only encrypted DNS is blocked", id, check)
		}
	}
	if !hasDNSEvidence(rep, "internet", "10.77.0.10", proxyProbeName, "ANSWER") {
		t.Errorf("the plaintext resolver never answered the client: %+v", rep.Evidence.DNS)
	}
	internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
	if internet.Status != "PASS" || !strings.Contains(internet.Detail, "8.8.8.8") {
		t.Errorf("direct egress row = %+v, want PASS via the address the drop rules exclude", internet)
	}

	// The user-visible half. netdoc has to name encrypted DNS specifically
	// rather than call this an outage or a DNS failure.
	if out.ActualVerdict != "degraded" {
		t.Errorf("verdict = %q, want degraded", out.ActualVerdict)
	}
	summary := out.Diagnosis.Summary
	if !strings.HasPrefix(summary, "Plain DNS works, but encrypted DNS") {
		t.Errorf("summary = %q, want the encrypted-DNS-specific one", summary)
	}
	if !strings.Contains(encrypted.Detail, "specific to encrypted DNS") {
		t.Errorf("dns_encrypted detail does not reconcile against plain DNS: %q", encrypted.Detail)
	}
	assertCleanedUp(t, rep)
}

// TestPlainDNSBlockedScenario is the other half: encrypted DNS keeps working
// when plaintext DNS cannot. The encrypted row is the only name resolution left
// on the machine here, so a PASS is evidence of an independent path rather than
// the absence of an assertion.
func TestPlainDNSBlockedScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "plain-dns-blocked", "-timeout", timedTimeout)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}
	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d: %+v", out.FalsePositives, out.FalseNegatives, out.Checks)
	}

	// UDP is the only transport this run can observe being dropped, so it is
	// the only one asserted here. The TCP/53 rule beside it is the other half
	// of "plaintext DNS is blocked", but nothing in this scenario truncates an
	// answer, so the stub resolver never retries over TCP and that counter
	// stays at zero. Whether both rules exist is a property of the file, and
	// TestEncryptedDNSIsolationPair asserts it there.
	if !droppedOutbound(rep.Evidence, "client", "udp", 53) {
		t.Errorf("the client's outbound UDP/53 filter never matched a packet: %+v", rep.Evidence.PacketDrops)
	}
	// And the plaintext fixture, which is running and correct, never got to
	// answer. That is the difference between a blocked transport and a broken
	// resolver.
	if hasDNSQuery(rep, "10.77.0.10", proxyProbeName) {
		t.Errorf("a plaintext query from the client still reached the resolver: %+v", rep.Evidence.DNS)
	}

	// The positive half. "DoH and DoT both completed" is the only detail the
	// probe writes when neither transport had to cover for the other, so this
	// is what keeps one of them from being silently unreachable behind a row
	// that passes on either.
	encrypted := diagnosisCheck(out, string(diagnostic.ProbeDNSEncrypted))
	if encrypted.Status != "PASS" || !strings.Contains(encrypted.Detail, "DoH and DoT both completed") {
		t.Errorf("dns_encrypted = %+v, want both transports completing", encrypted)
	}
	// Stated by the fixture rather than by netdoc: the DoH endpoint served a
	// wire-format answer.
	if !hasServiceReply(rep, "internet", encryptedDNSProbeService, ServiceEncryptedDNS, 200) {
		t.Errorf("the encrypted-DNS fixture never answered: %+v", rep.Evidence.ServiceReplies)
	}

	// The negative half, and the diagnosis it has to produce: a name-resolution
	// failure, not an outage, and not something encrypted DNS papers over.
	if check := diagnosisCheck(out, string(diagnostic.ProbeDNS)); check.Status != "FAIL" {
		t.Errorf("dns = %+v, want FAIL", check)
	}
	if check := diagnosisCheck(out, string(diagnostic.ProbeInternet)); check.Status != "PASS" {
		t.Errorf("internet_tcp = %+v, want PASS", check)
	}
	if out.ActualVerdict != "dns" {
		t.Errorf("verdict = %q, want dns", out.ActualVerdict)
	}
	if summary := out.Diagnosis.Summary; !strings.Contains(summary, "DNS resolution is failing") || strings.Contains(summary, "Offline") {
		t.Errorf("summary = %q, want a DNS failure rather than an outage", summary)
	}
	assertCleanedUp(t, rep)
}

// TestCaptivePortalScenario is the end-to-end half of captive-portal detection:
// the simulator's own HTTP fixture intercepts the connectivity check, and a real
// netdoc run has to discover the portal from that alone. Nothing here constructs
// portal evidence; the 302 comes off a socket.
//
// The scenario is deliberately healthy everywhere else. DNS answers, TCP/443
// completes, QUIC handshakes, and the target replies over HTTP, so every
// cheaper explanation is available and the portal verdict has to beat all of
// them rather than win by default.
func TestCaptivePortalScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "captive-portal")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}
	if len(rep.Tests) != 2 {
		t.Fatalf("tests = %+v", rep.Tests)
	}

	// The fixture half, from the server's side of the wire. Without this a run
	// that failed egress for some unrelated reason could still satisfy every
	// assertion below.
	if !hasServiceReply(rep, "internet", "internet-portal", ServiceHTTP, http.StatusFound) {
		t.Errorf("the portal fixture never redirected the connectivity check: %+v", rep.Evidence.ServiceReplies)
	}
	if !hasServiceState(rep, "internet", "internet-portal", portalMode) {
		t.Errorf("the HTTP fixture did not come up in portal mode: %+v", rep.Evidence.ServiceStates)
	}

	generic, targeted := rep.Tests[0], rep.Tests[1]
	for _, out := range rep.Tests {
		if out.FalsePositives != 0 || out.FalseNegatives != 0 {
			t.Errorf("%s: comparison fp=%d fn=%d: %+v", out.Name, out.FalsePositives, out.FalseNegatives, out.Checks)
		}
		// FAIL rather than WARN is the downgradeEgress portal exemption holding.
		// Both runs hand it exactly the evidence it downgrades on: DNS passes in
		// each, and the targeted one adds a target connect that also succeeded.
		// Behind a portal both of those are the portal answering, so neither is
		// allowed to launder the intercepted path into a degradation.
		internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
		if internet.Status != "FAIL" {
			t.Errorf("%s: internet_tcp = %+v, want FAIL to survive a passing DNS and target", out.Name, internet)
		}
		if !strings.Contains(internet.Detail, "intercepted") || !strings.Contains(internet.Detail, "302") {
			t.Errorf("%s: internet_tcp detail does not name the interception: %q", out.Name, internet.Detail)
		}
		if !strings.Contains(internet.Fix, "sign in") {
			t.Errorf("%s: internet_tcp fix = %q, want the sign-in hint", out.Name, internet.Fix)
		}
		if out.ActualVerdict != diagnostic.VerdictNetwork {
			t.Errorf("%s: verdict = %q, want %q", out.Name, out.ActualVerdict, diagnostic.VerdictNetwork)
		}
	}

	// Precedence, stated as the two summaries netdoc reserves for a portal. The
	// generic run has a working resolver, so without the portal branch it would
	// read as a filtered network; the targeted run has every rung under the
	// target passing, so it would read as online.
	if summary := generic.Diagnosis.Summary; !strings.HasPrefix(summary, "Behind a captive portal") {
		t.Errorf("generic summary = %q, want the captive-portal one", summary)
	}
	if summary := targeted.Diagnosis.Summary; !strings.HasPrefix(summary, "Behind a captive portal") ||
		!strings.Contains(summary, "example.test") {
		t.Errorf("targeted summary = %q, want the captive-portal one naming the target", summary)
	}
	// The rungs the portal verdict outranked, named rather than implied.
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeHTTP} {
		if check := diagnosisCheck(targeted, string(id)); check.Status != "PASS" {
			t.Errorf("%s = %+v, want PASS: the portal verdict has to outrank a working rung, not replace it", id, check)
		}
	}
	assertCleanedUp(t, rep)
}

// TestSelectiveHTTPInterceptionScenario is the negative half of the same
// detection, over the same wires: one connectivity provider is redirected to a
// sign-in page and the other answers exactly what it documents. A run that
// promoted one provider's answer into a verdict would call this a captive
// portal; netdoc has to report the discrepancy and stop there.
func TestSelectiveHTTPInterceptionScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "selective-http-interception")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; tests: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Tests)
	}

	// Both halves of the fixture, from the servers' side of the wire, so the
	// verdict below rests on interception that really was selective rather than
	// on a second endpoint that simply never got asked.
	if !hasServiceReply(rep, "internet", "internet-intercepting-http", ServiceHTTP, http.StatusFound) {
		t.Errorf("the intercepting fixture never redirected its connectivity check: %+v", rep.Evidence.ServiceReplies)
	}
	if !hasServiceReply(rep, "server", "server-http", ServiceHTTP, http.StatusOK) {
		t.Errorf("the untouched provider never answered its connectivity check: %+v", rep.Evidence.ServiceReplies)
	}

	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d: %+v", out.FalsePositives, out.FalseNegatives, out.Checks)
	}
	internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
	if internet.Status != "WARN" {
		t.Errorf("internet_tcp = %+v, want WARN: one provider is not the network", internet)
	}
	if strings.Contains(internet.Fix, "sign in") {
		t.Errorf("internet_tcp fix = %q, want no sign-in hint from a single provider", internet.Fix)
	}
	if !strings.Contains(internet.Detail, "answered unexpectedly") || !strings.Contains(internet.Detail, "302") {
		t.Errorf("internet_tcp detail does not name what was observed: %q", internet.Detail)
	}
	for _, finding := range out.Diagnosis.Findings {
		if finding.ID == string(diagnostic.DiagnosisCaptivePortal) {
			t.Errorf("one intercepted provider produced the captive-portal finding: %+v", out.Diagnosis)
		}
	}
	if strings.Contains(out.Diagnosis.Summary, "captive portal") {
		t.Errorf("summary = %q, want no portal claim", out.Diagnosis.Summary)
	}
	assertCleanedUp(t, rep)
}

func TestTLSValidScenario(t *testing.T) {
	rep := runTLSScenario(t, "tls-valid")
	out := rep.Tests[0]
	assertTLSCheck(t, out, "PASS", "")
	if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
		t.Errorf("target_tcp = %+v", tcp)
	}
	if https := diagnosisCheck(out, string(diagnostic.ProbeHTTPS)); https.Status != "PASS" {
		t.Errorf("https = %+v", https)
	}
	if out.Trust != "tls-target" {
		t.Errorf("trusted service = %q", out.Trust)
	}
	if !hasTLSEvidence(rep, TLSCertificateValid, "secure-target.test", "secure-target.test", true, "passed") {
		t.Errorf("no successful valid handshake evidence: %+v", rep.Evidence.TLS)
	}
	assertCleanedUp(t, rep)
}

func TestTLSExpiredCertificateScenario(t *testing.T) {
	rep := runTLSScenario(t, "tls-expired-certificate")
	out := rep.Tests[0]
	assertTLSCheck(t, out, "FAIL", diagnostic.TLSCauseCertificateExpired)
	if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
		t.Errorf("target_tcp = %+v", tcp)
	}
	if !hasTLSEvidence(rep, TLSCertificateExpired, "secure-target.test", "secure-target.test", true, "client_rejected_certificate") {
		t.Errorf("no expired certificate rejection evidence: %+v", rep.Evidence.TLS)
	}
	if len(out.Diagnosis.Findings) != 1 || out.Diagnosis.Findings[0].ID != string(diagnostic.DiagnosisTLSCertificateExpired) {
		t.Fatalf("finding = %+v, want %s", out.Diagnosis.Findings, diagnostic.DiagnosisTLSCertificateExpired)
	}
	finding := out.Diagnosis.Findings[0]
	if !hasDiagnosisCausalEvidence(finding, string(diagnostic.EvidenceSupport), string(diagnostic.ProbeTLS),
		string(diagnostic.ObservationCause), "", "") {
		t.Errorf("TLS cause is absent from causal support: %+v", finding.CausalEvidence)
	}
	if !hasDiagnosisCausalEvidence(finding, string(diagnostic.EvidenceRuledOut), string(diagnostic.ProbeTargetTCP),
		string(diagnostic.ObservationStatusPass), string(diagnostic.DiagnosisTLSTCPUnreachable), "") {
		t.Errorf("working TCP did not rule out an unreachable TLS endpoint: %+v", finding.CausalEvidence)
	}
	for _, item := range rep.Evidence.TLS {
		if item.CertificateMode == TLSCertificateExpired && !item.NotAfter.Before(rep.StartedAt) {
			t.Errorf("expired NotAfter %s is not before evaluation %s", item.NotAfter, rep.StartedAt)
		}
	}
	assertCleanedUp(t, rep)
}

func TestTLSHostnameMismatchScenario(t *testing.T) {
	rep := runTLSScenario(t, "tls-hostname-mismatch")
	out := rep.Tests[0]
	assertTLSCheck(t, out, "FAIL", diagnostic.TLSCauseHostnameMismatch)
	if tcp := diagnosisCheck(out, string(diagnostic.ProbeTargetTCP)); tcp.Status != "PASS" {
		t.Errorf("target_tcp = %+v", tcp)
	}
	if !hasTLSEvidence(rep, TLSCertificateHostnameMismatch, "secure-target.test", "different-target.test", true, "client_rejected_certificate") {
		t.Errorf("no hostname mismatch evidence: %+v", rep.Evidence.TLS)
	}
	assertCleanedUp(t, rep)
}

func TestHealthyRoutedNetworkScenario(t *testing.T) {
	requireBackend(t)
	hostForwardingBefore, err := os.ReadFile(ipv4ForwardPath)
	if err != nil {
		t.Fatalf("read host forwarding before scenario: %v", err)
	}
	rep := runScenario(t, "healthy-routed-network")
	hostForwardingAfter, err := os.ReadFile(ipv4ForwardPath)
	if err != nil {
		t.Fatalf("read host forwarding after scenario: %v", err)
	}
	if string(hostForwardingBefore) != string(hostForwardingAfter) {
		t.Errorf("host IPv4 forwarding changed from %q to %q", hostForwardingBefore, hostForwardingAfter)
	}
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	if !hasLink(rep, "client", "client-lan", true) || !hasLink(rep, "target", "upstream", true) {
		t.Errorf("client and target were not proven on distinct live segments: %+v", rep.Evidence.Links)
	}
	if countNodeLinks(rep, "gateway") != 2 || !hasForwarding(rep, "gateway") {
		t.Errorf("gateway topology/forwarding evidence = links %+v routers %+v", rep.Evidence.Links, rep.Evidence.Routers)
	}
	if !hasSelectedRoute(rep, "client", "10.77.2.20", "10.77.1.1", "client-lan", nil) {
		t.Errorf("no selected routed target path: %+v", rep.Evidence.Routes)
	}
	if target := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeTargetTCP)); target.Status != "PASS" {
		t.Errorf("target_tcp = %+v", target)
	}
	if rep.Tests[0].FalsePositives != 0 || rep.Tests[0].FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d", rep.Tests[0].FalsePositives, rep.Tests[0].FalseNegatives)
	}
	assertCleanedUp(t, rep)
}

// Route intelligence has to answer for the network the probe is actually on.
// The routed scenario puts the client behind a gateway on a segment the host
// does not have, so a route decision naming that gateway can only have come
// from inside the namespace: a lookup that leaked to the host would answer
// with the developer's own default route instead.
func TestRouteDecisionsAnswerForTheNamespaceNotTheHost(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "healthy-routed-network")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v", rep.Result, rep.Error, rep.Suggestions)
	}
	target := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeTargetTCP))
	if len(target.Routes) == 0 {
		t.Fatalf("target_tcp recorded no route decision: %+v", target)
	}
	route := target.Routes[0]
	if route.Destination != "10.77.2.20" || route.Gateway != "10.77.1.1" {
		t.Errorf("route = %+v, want the target reached through the client's own gateway", route)
	}
	// The device name inside a namespace is generated, so what is asserted is
	// that there is one and that it is the same link the interface row picked.
	iface := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeIface))
	if len(iface.Routes) == 0 || route.Interface == "" || route.Interface != iface.Routes[0].Interface {
		t.Errorf("route interface = %q, want the same namespace link the interface row selected: %+v", route.Interface, iface.Routes)
	}
	if route.Unreachable {
		t.Errorf("a reachable target was recorded as having no route: %+v", route)
	}
	// Nothing in this scenario encapsulates, and netdoc must not say otherwise
	// merely because the links are virtual.
	for _, id := range []string{string(diagnostic.ProbeIface), string(diagnostic.ProbeDNS), string(diagnostic.ProbeTargetTCP)} {
		for _, r := range diagnosisCheck(rep.Tests[0], id).Routes {
			if r.Tunnel != "" && r.Tunnel != "direct" {
				t.Errorf("%s reported %q on a scenario with no tunnels: %+v", id, r.Tunnel, r)
			}
			// Against a real kernel, on the platform whose lookups name no
			// matched entry: a reason that says which entry won may only
			// appear beside the entry it names. This is what stops the
			// echoed request length, or a path that merely differs from the
			// general one, from being read back as a prefix decision.
			if r.Prefix == "" && (r.Reason == "default_route" || r.Reason == "more_specific_than_default" ||
				r.Reason == "host_route") {
				t.Errorf("%s claimed reason %q with no matched entry to support it: %+v", id, r.Reason, r)
			}
		}
	}
	assertCleanedUp(t, rep)
}

// A scenario with no default route is netdoc's own no-route case, and it has
// to be recorded as the kernel saying so rather than as an empty path.
func TestRouteDecisionsRecordAMissingDefaultRoute(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "no-default-route")
	iface := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeIface))
	if len(iface.Routes) == 0 {
		t.Skipf("this kernel reported no route decision for the general Internet endpoints: %+v", iface)
	}
	for _, r := range iface.Routes {
		if !r.Unreachable {
			t.Errorf("route = %+v, want the kernel reporting that there is none", r)
		}
		if r.Interface != "" || r.Gateway != "" {
			t.Errorf("an unreachable destination carries a path: %+v", r)
		}
	}
	assertCleanedUp(t, rep)
}

// The PMTU black hole is only a black hole if size is the only thing that
// decides whether a packet survives. This asserts that from netdoc's own
// output: the same client, the same two routers and the same destination, with
// small exchanges completing and full-size ones vanishing into a timeout.
//
// It also guards the probe end of the pair. path_mtu reads the socket's send
// queue rather than trusting a completed Write, which is the only way the stall
// is visible on Linux, and reconciliation turns that row plus the TLS timeout
// into a network verdict instead of blaming the certificate.
func TestPMTUBlackholeScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "pmtu-blackhole")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests: %+v; suggestions: %+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions)
	}
	if len(rep.Tests) != 2 {
		t.Fatalf("tests = %d, want 2", len(rep.Tests))
	}
	bulk, small := rep.Tests[0], rep.Tests[1]

	// Small packets cross the narrowed hop in both directions: the name
	// resolves, the handshake completes, and a whole HTTP exchange finishes.
	// Without these the scenario would only prove the path is broken.
	for _, c := range []struct {
		test TestOutcome
		id   diagnostic.ProbeID
	}{
		{bulk, diagnostic.ProbeDNS},
		{bulk, diagnostic.ProbeTargetTCP},
		{small, diagnostic.ProbeTargetTCP},
		{small, diagnostic.ProbeHTTP},
	} {
		if got := diagnosisCheck(c.test, string(c.id)); got.Status != "PASS" {
			t.Errorf("%s in %q = %+v, want PASS: small packets must still cross the black hole", c.id, c.test.Name, got)
		}
	}

	// The one full-size exchange netdoc does judge: the server's TLS flight is
	// larger than the hop carries and no router will say so, so it times out
	// rather than failing on anything about the certificate.
	tls := diagnosisCheck(bulk, string(diagnostic.ProbeTLS))
	if tls.Status != "FAIL" || tls.Cause != diagnostic.TLSCauseTimeout {
		t.Errorf("tls = %+v, want FAIL with cause %q: a size-selective stall, not a certificate problem",
			tls, diagnostic.TLSCauseTimeout)
	}
	if !strings.Contains(tls.Fix, "Path MTU") {
		t.Errorf("tls fix = %q, want it to send the reader to the Path MTU row", tls.Fix)
	}

	// The row the whole fault exists to exercise. The bulk write is black-holed
	// exactly like the TLS flight: the client's kernel takes all 24 KiB and the
	// peer acknowledges none of it. Both tests see it, because the black hole
	// is a property of the path and not of the port being checked.
	for _, out := range []TestOutcome{bulk, small} {
		got := diagnosisCheck(out, string(diagnostic.ProbePMTU))
		if got.Status != "WARN" {
			t.Errorf("path_mtu in %q = %+v, want WARN: 24 KiB written and none acknowledged", out.Name, got)
		}
		if !strings.Contains(got.Detail, "none of it acknowledged") {
			t.Errorf("path_mtu detail in %q = %q, want the unacknowledged payload named", out.Name, got.Detail)
		}
		// Acknowledgement is the measurement; a completed Write is what the old
		// inference mistook for it, and would put this row back at PASS.
		if strings.Contains(got.Detail, "drained past the measured") {
			t.Errorf("path_mtu detail in %q = %q, want the send-queue reading, not the send-buffer inference",
				out.Name, got.Detail)
		}
		if got.Fix == "" {
			t.Errorf("path_mtu in %q carries no fix hint", out.Name)
		}
	}

	// Reconciliation is where the evidence becomes an answer: a stalled bulk
	// write plus an independent protocol timeout is a path verdict, and the
	// generic "the TLS handshake fails" service answer must not win instead.
	if bulk.ActualVerdict != "network" {
		t.Errorf("verdict = %q, want network from the correlated path-MTU rule", bulk.ActualVerdict)
	}
	if !strings.Contains(bulk.Diagnosis.Summary, "path MTU black hole") {
		t.Errorf("summary = %q, want it to name the path MTU black hole", bulk.Diagnosis.Summary)
	}
	if strings.Contains(bulk.Diagnosis.Summary, "bad/expired cert") {
		t.Errorf("summary = %q, want the path answer rather than the service one", bulk.Diagnosis.Summary)
	}
	assertCleanedUp(t, rep)
	assertHostMTUAndFirewallUntouched(t)
}

// The whole point of putting the black hole in the hunt catalogue: a case the
// generator draws on its own has to reach the path-MTU probe, not merely carry
// a fault declaration nothing exercises. The authored pmtu-blackhole scenario
// proves the condition is modelable; this proves the generator can invent it.
func TestGeneratedStressHuntPMTUBlackholeCaseReachesThePathMTUProbe(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	const base = "healthy-routed-network"
	generated, err := generateHuntCaseInLane(HuntGeneratorVersion, HuntLaneStress, base, loadHuntBase(t, base), 20260102, 20, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Manifest.Mutations) != 1 || generated.Manifest.Mutations[0].ID != "pmtu.blackhole" {
		t.Fatalf("stress case 20 is no longer the black hole case: %+v", generated.Manifest.Mutations)
	}
	rep := runScenarioDefinition(t, sim, netdoc, generated.Scenario)
	if rep.Error != "" {
		t.Fatalf("run failed: %s", rep.Error)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		t.Fatalf("tests = %+v", rep.Tests)
	}
	out := rep.Tests[0]

	// Small packets still cross the narrowed hop in both directions. Without
	// these the case would only prove the path is broken, which is a different
	// fault with a different answer.
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeHTTP} {
		if got := diagnosisCheck(out, string(id)); got.Status != "PASS" {
			t.Errorf("%s = %+v, want PASS: small packets must still cross the black hole", id, got)
		}
	}
	// The row the mutation exists to exercise: the client's kernel takes the
	// whole 24 KiB and the peer acknowledges none of it.
	pmtu := diagnosisCheck(out, string(diagnostic.ProbePMTU))
	if pmtu.Status != "WARN" {
		t.Errorf("path_mtu = %+v, want WARN from a generated black hole", pmtu)
	}
	if !strings.Contains(pmtu.Detail, "none of it acknowledged") {
		t.Errorf("path_mtu detail = %q, want the unacknowledged payload named", pmtu.Detail)
	}
	if pmtu.Fix == "" {
		t.Error("path_mtu carries no fix hint")
	}

	// And the simulator's own independent reading of the same condition: the
	// hop really narrowed, the client really did not.
	truth := collectObservedTruth(generated.Manifest, &rep)
	if !slices.Contains(truth.ObservedFaults, "pmtu.blackhole") {
		t.Errorf("observed faults = %v, want the black hole; links were %+v", truth.ObservedFaults, rep.Evidence.Links)
	}
	for _, finding := range analyzeHuntCase(generated.Manifest, &rep, truth) {
		if finding.Category == FindingFalseNegative || finding.Category == FindingDiagnosticContradiction {
			t.Errorf("a correctly diagnosed black hole produced %s/%s: %s", finding.Category, finding.Code, finding.Summary)
		}
	}
	assertCleanedUp(t, rep)
	assertHostMTUAndFirewallUntouched(t)
}

// The fault narrows an interface and installs firewall rules, both of which
// exist only inside namespaces the simulator owns and both of which die with
// them. Nothing restores them, because nothing on this host was changed.
func assertHostMTUAndFirewallUntouched(t *testing.T) {
	t.Helper()
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		t.Skip("cannot list host links:", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, " mtu 576 ") {
			t.Errorf("a host interface is at the scenario's black-hole MTU: %s", line)
		}
	}
	// nft may be absent or refuse an unprivileged read; either way the host
	// ruleset was never reachable from the simulator's user namespace.
	if ruleset, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		if strings.Contains(string(ruleset), nftTable) {
			t.Errorf("the simulator's %s table is present in the host ruleset", nftTable)
		}
	}
}

// Two runs of the same black hole must reach the same diagnosis. A stall that
// is really a race would show up here as a status that moves between runs.
func TestPMTUBlackholeScenarioIsDeterministic(t *testing.T) {
	requireBackend(t)
	first, second := runScenario(t, "pmtu-blackhole"), runScenario(t, "pmtu-blackhole")
	if first.Result != ResultPass || second.Result != ResultPass {
		t.Fatalf("results = %s, %s (errors %q, %q)", first.Result, second.Result, first.Error, second.Error)
	}
	statuses := func(rep Report) map[string]string {
		out := map[string]string{}
		for _, test := range rep.Tests {
			for _, check := range test.Diagnosis.Checks {
				out[test.Name+"/"+check.ID] = check.Status
			}
		}
		return out
	}
	if a, b := statuses(first), statuses(second); !reflect.DeepEqual(a, b) {
		t.Errorf("diagnosis differed between runs:\n%v\n%v", a, b)
	}
	assertCleanedUp(t, first)
	assertCleanedUp(t, second)
}

func TestGatewayUnreachableScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "gateway-unreachable")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; routes: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Evidence.Routes)
	}
	unreachable := false
	if !hasSelectedRoute(rep, "client", "1.1.1.1", "10.77.1.254", "client-lan", &unreachable) {
		t.Errorf("dead gateway selection/neighbor failure not proven: %+v", rep.Evidence.Routes)
	}
	if !hasDefaultRoute(rep, "client") {
		t.Error("default route was absent from topology report")
	}
	if check := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)); check.Status != "FAIL" {
		t.Errorf("internet_tcp = %+v", check)
	} else if check.Cause != diagnostic.RouteCauseGatewayUnreachable {
		t.Errorf("internet_tcp cause = %q", check.Cause)
	}
	assertCleanedUp(t, rep)
}

func TestWrongDefaultRouteScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "wrong-default-route")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests: %+v; suggestions: %+v; routes: %+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions, rep.Evidence.Routes)
	}
	reachable := true
	if !hasSelectedRoute(rep, "client", "1.1.1.1", "10.77.1.254", "client-lan", &reachable) {
		t.Errorf("wrong but locally reachable gateway not selected: %+v", rep.Evidence.Routes)
	}
	if len(rep.Tests) != 2 || diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)).Status != "WARN" ||
		diagnosisCheck(rep.Tests[1], string(diagnostic.ProbeTargetTCP)).Status != "PASS" {
		t.Errorf("wrong/default and correct/specific paths were not distinguished: %+v", rep.Tests)
	}
	if cause := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)).Cause; cause != diagnostic.RouteCauseSelectedPathFailed {
		t.Errorf("wrong default cause = %q", cause)
	}
	assertCleanedUp(t, rep)
}

func TestMultipleInterfacesWrongPreferredRouteScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "multiple-interfaces-wrong-preferred-route")
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); tests: %+v; suggestions: %+v; routes: %+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions, rep.Evidence.Routes)
	}
	if countNodeLinks(rep, "client") != 2 || !hasLink(rep, "client", "working-lan", true) || !hasLink(rep, "client", "wrong-lan", true) {
		t.Errorf("client link evidence = %+v", rep.Evidence.Links)
	}
	reachable := true
	if !hasSelectedRoute(rep, "client", "1.1.1.1", "10.77.3.1", "wrong-lan", &reachable) {
		t.Errorf("lower-metric wrong route was not selected: %+v", rep.Evidence.Routes)
	}
	if !hasGatewayState(rep, "client", "10.77.1.1", true) || !hasGatewayState(rep, "client", "10.77.3.1", true) {
		t.Errorf("both gateway neighbor states were not reachable: %+v", rep.Evidence.Routes)
	}
	if len(rep.Tests) != 2 || diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)).Status != "WARN" ||
		diagnosisCheck(rep.Tests[1], string(diagnostic.ProbeTargetTCP)).Status != "PASS" || rep.Tests[1].SourceSegment != "working-lan" {
		t.Errorf("preferred failure/alternate success evidence missing: %+v", rep.Tests)
	}
	if cause := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet)).Cause; cause != diagnostic.RouteCausePreferredPathFailed {
		t.Errorf("preferred route cause = %q", cause)
	}
	assertCleanedUp(t, rep)
}

func TestDualStackHealthyScenario(t *testing.T) {
	requireBackend(t)
	before := captureHostNetworkState(t)
	rep := runScenario(t, "dual-stack-healthy")
	after := captureHostNetworkState(t)
	if before != after {
		t.Errorf("host network state changed across dual-stack run\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertDualStackScenario(t, rep, diagnostic.FamilyReachable, diagnostic.FamilyReachable, "",
		FamilyStateReachable, FamilyStateReachable)
	if !hasForwardingFamilies(rep, "gateway", true, true) {
		t.Errorf("dual forwarding evidence = %+v", rep.Evidence.Routers)
	}
	if !hasSelectedFamilyRoute(rep, "client", "1.1.1.1", "ipv4") ||
		!hasSelectedFamilyRoute(rep, "client", "2606:4700:4700::1111", "ipv6") {
		t.Errorf("family route selections = %+v", rep.Evidence.Routes)
	}
}

func TestTargetIPv6FailureProducesCounterfactualDiagnosis(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	scenario, err := LibraryScenario("dual-stack-healthy")
	if err != nil {
		t.Fatal(err)
	}
	scenario.Name = "target-ipv6-failure"
	scenario.Faults = []Fault{{
		Type: FaultDrop, Node: "target", Direction: DirectionInbound, Family: "ipv6",
		To: "2001:db8:77:2::20", Protocol: "tcp", Port: 80,
	}}
	scenario.Expect.Verdict = diagnostic.VerdictDegraded
	for i := range scenario.Expect.Checks {
		if scenario.Expect.Checks[i].ID == string(diagnostic.ProbeTargetTCP) {
			scenario.Expect.Checks[i].Status = "WARN"
		}
	}
	rep := runScenarioDefinition(t, sim, netdoc, scenario)
	if rep.Result != ResultPass || len(rep.Tests) != 1 {
		t.Fatalf("result = %s error=%q tests=%+v suggestions=%+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions)
	}
	out := rep.Tests[0]
	internet := diagnosisCheck(out, string(diagnostic.ProbeInternet))
	if internet.Families == nil || internet.Families.IPv6 != diagnostic.FamilyReachable {
		t.Fatalf("general IPv6 path did not remain reachable: %+v", out.Diagnosis.Checks)
	}
	finding, found := DiagnosisFinding{}, false
	for _, item := range out.Diagnosis.Findings {
		if item.ID == string(diagnostic.DiagnosisIPv6TargetUnreachable) {
			finding, found = item, true
		}
		if item.ID == string(diagnostic.DiagnosisPartialReachability) {
			t.Errorf("the probe-wide IPv6 timeout became a failed backend address: %+v", item)
		}
	}
	if !found || finding.Counterfactual == nil || finding.Counterfactual.Variable != string(diagnostic.CounterfactualAddressFamily) {
		t.Fatalf("findings = %+v, want IPv6 family counterfactual", out.Diagnosis.Findings)
	}
	assertCleanedUp(t, rep)
}

func TestIPv4WorksIPv6BrokenScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "ipv4-works-ipv6-broken")
	assertDualStackScenario(t, rep, diagnostic.FamilyReachable, diagnostic.FamilyUnreachable, diagnostic.FamilyCauseIPv6Unreachable,
		FamilyStateReachable, FamilyStateUnreachable)
	if len(rep.Faults) != 1 || rep.Faults[0].Family != "ipv6" {
		t.Errorf("IPv6 fault evidence = %+v", rep.Faults)
	}
}

func TestIPv6WorksIPv4BrokenScenario(t *testing.T) {
	requireBackend(t)
	rep := runScenario(t, "ipv6-works-ipv4-broken")
	assertDualStackScenario(t, rep, diagnostic.FamilyUnreachable, diagnostic.FamilyReachable, diagnostic.FamilyCauseIPv4Unreachable,
		FamilyStateUnreachable, FamilyStateReachable)
	if len(rep.Faults) != 1 || rep.Faults[0].Family != "ipv4" {
		t.Errorf("IPv4 fault evidence = %+v", rep.Faults)
	}
}

// ipv6OnlyScenario is a routed IPv6-only client: two segments, a forwarding
// router in between, and no IPv4 anywhere. It exists to separate the two states
// a broken family and an absent family would otherwise share. It lives here
// rather than in the shipped library because the assertion is about the
// simulator's own measurement, not about a diagnosis worth pinning.
const ipv6OnlyScenario = `name: ipv6-only-client
description: A routed IPv6-only client with no IPv4 address, route, or record.
topology:
  segments:
    - {name: client-lan, ipv6: "2001:db8:76:1::/64"}
    - {name: upstream, ipv6: "2001:db8:76:2::/64"}
  nodes:
    - name: client
      role: client
      resolver: "2001:db8:76:1::53"
      interfaces:
        - {segment: client-lan, ipv6: "2001:db8:76:1::10/64"}
    - name: resolver
      interfaces:
        - {segment: client-lan, ipv6: "2001:db8:76:1::53/64"}
      services:
        - name: v6-resolver
          type: dns
          records:
            - {name: v6-target.test, address: "2001:db8:76:2::20"}
            - {name: connectivitycheck.gstatic.com, address: "2001:db8:76:2::20"}
    - name: gateway
      role: router
      interfaces:
        - {segment: client-lan, ipv6: "2001:db8:76:1::1/64"}
        - {segment: upstream, ipv6: "2001:db8:76:2::1/64"}
    - name: target
      interfaces:
        - {segment: upstream, ipv6: "2001:db8:76:2::20/64"}
      aliases: ["2606:4700:4700::1111", "2001:4860:4860::8888"]
      services:
        - {name: v6-http, type: http, port: 80}
        - {name: v6-internet, type: http, port: 443}
  routes:
    - {node: client, destination: "::/0", via: "2001:db8:76:1::1"}
    - {node: gateway, destination: "2606:4700:4700::1111/128", via: "2001:db8:76:2::20"}
    - {node: gateway, destination: "2001:4860:4860::8888/128", via: "2001:db8:76:2::20"}
    - {node: target, destination: "2001:db8:76:1::/64", via: "2001:db8:76:2::1"}
tests:
  - {name: IPv6-only client reaches its target, node: client, target: "v6-target.test:80"}
expect:
  checks:
    - {id: iface, status: PASS}
`

// TestIPv6OnlyClientSeparatesUnavailableFromUnreachable is the case that fails
// if the two states are ever collapsed. The client has no IPv4 address at all,
// so IPv4 is unavailable: nothing was dialed, and no claim is made about a
// path that does not exist. IPv6 is reachable across a router, so the same run
// also shows the measurement is not merely "the neighbor answered".
//
// It doubles as the anti-circularity check: netdoc's family vocabulary has only
// reachable and unreachable, so an "unavailable" state cannot have come from a
// diagnosis, and whatever netdoc concluded about IPv4 here is required to be
// something else.
func TestIPv6OnlyClientSeparatesUnavailableFromUnreachable(t *testing.T) {
	requireBackend(t)
	path := filepath.Join(t.TempDir(), "ipv6-only-client.yaml")
	if err := os.WriteFile(path, []byte(ipv6OnlyScenario), 0o600); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	rep := runScenario(t, path)
	if rep.Error != "" || !rep.Cleanup.Done {
		t.Fatalf("run failed: error=%q cleanup=%+v", rep.Error, rep.Cleanup)
	}
	assertObservedFamily(t, rep, "ipv4", FamilyStateUnavailable)
	assertObservedFamily(t, rep, "ipv6", FamilyStateReachable)

	// The IPv6 record has to name the routed path, not a directly connected
	// one, or "reachable" would only mean the client-lan gateway answered.
	item, _ := familyReachability(rep, "client", "ipv6")
	if !reflect.DeepEqual(item.Via, []string{"client-lan", "2001:db8:76:1::1"}) {
		t.Errorf("IPv6 observation path = %v, want the routed client-lan gateway", item.Via)
	}

	truth := collectObservedTruth(GeneratedCaseManifest{}, &rep)
	if truth.IPv4 != "unavailable" || truth.IPv6 != "reachable" {
		t.Errorf("truth = IPv4 %q, IPv6 %q; want unavailable, reachable", truth.IPv4, truth.IPv6)
	}
	check := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet))
	if check.Families != nil && check.Families.IPv4 == FamilyStateUnavailable {
		t.Fatalf("netdoc published an %q family, so the simulator state could have been copied from it: %+v",
			FamilyStateUnavailable, check.Families)
	}
	t.Logf("simulator IPv4=%s IPv6=%s; netdoc families=%+v", truth.IPv4, truth.IPv6, check.Families)
	assertCleanedUp(t, rep)
}

// TestFamilyReachabilityIgnoresScenarioExpectations proves the observation is
// not read back out of the oracle it is meant to police. The IPv6 fault stays
// injected and the IPv6 expectation is inverted to claim the family works. The
// comparison must notice the lie, and the simulator's own observation, made by
// dialing the controlled endpoints from inside the client namespace, must not
// move with it.
func TestFamilyReachabilityIgnoresScenarioExpectations(t *testing.T) {
	requireBackend(t)
	raw, err := library.ReadFile("scenarios/ipv4-works-ipv6-broken.yaml")
	if err != nil {
		t.Fatalf("read base scenario: %v", err)
	}
	const truthful = "ipv4: reachable, ipv6: unreachable"
	if !bytes.Contains(raw, []byte(truthful)) {
		t.Fatalf("base scenario no longer expects %q", truthful)
	}
	lying := bytes.Replace(raw, []byte(truthful), []byte("ipv4: reachable, ipv6: reachable"), 1)
	path := filepath.Join(t.TempDir(), "lying-expectation.yaml")
	if err := os.WriteFile(path, lying, 0o600); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	rep := runScenario(t, path)
	if rep.Error != "" || !rep.Cleanup.Done {
		t.Fatalf("run failed: error=%q cleanup=%+v", rep.Error, rep.Cleanup)
	}
	if rep.Result == ResultPass {
		t.Errorf("an expectation that contradicts the injected fault was graded a pass: %+v", rep.Tests)
	}
	assertObservedFamily(t, rep, "ipv4", FamilyStateReachable)
	assertObservedFamily(t, rep, "ipv6", FamilyStateUnreachable)
}

func assertDualStackScenario(t *testing.T, rep Report, ipv4, ipv6, cause, observed4, observed6 string) {
	t.Helper()
	if rep.Result != ResultPass {
		t.Fatalf("result = %s error=%q tests=%+v suggestions=%+v evidence=%+v", rep.Result, rep.Error, rep.Tests, rep.Suggestions, rep.Evidence)
	}
	if !hasDualStackLink(rep, "client", "client-lan") || !hasDualStackLink(rep, "gateway", "upstream") {
		t.Errorf("dual-stack links = %+v", rep.Evidence.Links)
	}
	check := diagnosisCheck(rep.Tests[0], string(diagnostic.ProbeInternet))
	if check.Families == nil || check.Families.IPv4 != ipv4 || check.Families.IPv6 != ipv6 || check.Cause != cause {
		t.Errorf("internet family diagnosis = %+v, want IPv4=%s IPv6=%s cause=%q", check, ipv4, ipv6, cause)
	}
	dnsName := proxyProbeName
	if rep.Tests[0].Target != "" {
		dnsName = "dual-target.test"
	}
	if !hasDNSQueryType(rep, dnsName, "A") || !hasDNSQueryType(rep, dnsName, "AAAA") {
		t.Errorf("A/AAAA query evidence = %+v", rep.Evidence.DNS)
	}
	// The wanted simulator states are spelled out rather than derived from the
	// wanted diagnosis: the two sides have to be able to disagree, so the test
	// must not compute one from the other.
	assertObservedFamily(t, rep, "ipv4", observed4)
	assertObservedFamily(t, rep, "ipv6", observed6)
	if rep.Tests[0].FalsePositives != 0 || rep.Tests[0].FalseNegatives != 0 {
		t.Errorf("comparison fp=%d fn=%d", rep.Tests[0].FalsePositives, rep.Tests[0].FalseNegatives)
	}
	assertCleanedUp(t, rep)
}

func captureHostNetworkState(t *testing.T) string {
	t.Helper()
	var parts []string
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read host network setting %s: %v", path, err)
		}
		parts = append(parts, path+"="+string(raw))
	}
	for _, argv := range [][]string{{"ip", "-4", "route", "show"}, {"ip", "-6", "route", "show"}, {"ip", "-o", "link", "show"}} {
		out, err := exec.Command(argv[0], argv[1:]...).Output()
		if err != nil {
			t.Fatalf("capture host network state %v: %v", argv, err)
		}
		parts = append(parts, strings.Join(argv, " ")+"\n"+string(out))
	}
	return strings.Join(parts, "\n")
}

func runTLSScenario(t *testing.T, name string) Report {
	t.Helper()
	requireBackend(t)
	rep := runScenario(t, name)
	if rep.Result != ResultPass {
		t.Fatalf("result = %s (error %q); suggestions: %+v; evidence: %+v", rep.Result, rep.Error, rep.Suggestions, rep.Evidence)
	}
	if len(rep.Tests) != 1 {
		t.Fatalf("tests = %+v", rep.Tests)
	}
	out := rep.Tests[0]
	if out.FalsePositives != 0 || out.FalseNegatives != 0 {
		t.Fatalf("comparison fp=%d fn=%d", out.FalsePositives, out.FalseNegatives)
	}
	return rep
}

func assertTLSCheck(t *testing.T, out TestOutcome, status, cause string) {
	t.Helper()
	check := diagnosisCheck(out, string(diagnostic.ProbeTLS))
	if check.Status != status || check.Cause != cause {
		t.Errorf("tls = %+v, want status %s cause %q", check, status, cause)
	}
}

func hasTLSEvidence(rep Report, mode, requested, certName string, presented bool, result string) bool {
	for _, item := range rep.Evidence.TLS {
		if item.CertificateMode != mode || item.RequestedServer != requested || item.CertificatePresented != presented || item.Result != result || item.Count < 1 {
			continue
		}
		for _, name := range item.CertificateDNS {
			if name == certName {
				return true
			}
		}
	}
	return false
}

func diagnosisCheck(out TestOutcome, id string) DiagnosisCheck {
	if out.Diagnosis == nil {
		return DiagnosisCheck{}
	}
	for _, check := range out.Diagnosis.Checks {
		if check.ID == id {
			return check
		}
	}
	return DiagnosisCheck{}
}

func hasDiagnosisCausalEvidence(finding DiagnosisFinding, kind, check, observation, candidate, reason string) bool {
	return slices.ContainsFunc(finding.CausalEvidence, func(e DiagnosisCausalEvidence) bool {
		return e.Kind == kind && e.Check == check && e.Observation == observation && e.Candidate == candidate && e.Reason == reason
	})
}

func hasDNSEvidence(rep Report, node, source, name, result string) bool {
	for _, item := range rep.Evidence.DNS {
		if item.Node == node && item.Source == source && item.Name == name && item.Result == result && item.Count > 0 {
			return true
		}
	}
	return false
}

func hasDNSQuery(rep Report, source, name string) bool {
	for _, item := range rep.Evidence.DNS {
		if item.Source == source && item.Name == name && item.Count > 0 {
			return true
		}
	}
	return false
}

func hasSOCKSEvidence(rep Report, event, addressType, result string) bool {
	for _, item := range rep.Evidence.SOCKSRequests {
		if item.Event == event && item.AddressType == addressType && item.Result == result && item.Count > 0 {
			return true
		}
	}
	return false
}

// hasServiceState is the companion reader to hasServiceReply: it says the
// fixture came up in the mode the scenario asked for, where the reply says it
// then did something to a client.
func hasServiceState(rep Report, node, service, mode string) bool {
	for _, state := range rep.Evidence.ServiceStates {
		if state.Node == node && state.Service == service && state.Mode == mode {
			return true
		}
	}
	return false
}

func hasServiceReply(rep Report, node, service, serviceType string, status int) bool {
	for _, reply := range rep.Evidence.ServiceReplies {
		if reply.Node == node && reply.Service == service && reply.Type == serviceType &&
			reply.Status == status && reply.Result == replyResponded && reply.Count > 0 {
			return true
		}
	}
	return false
}

// droppedOutbound is the kernel's own count for a node's outbound filter.
// The oracle's readers cover inbound drops only, and the direction matters:
// these scenarios refuse the packet locally rather than black-holing it
// remotely. A zero count means the rule was installed but never bit, which is
// a scenario that proves nothing.
func droppedOutbound(evidence Evidence, node, protocol string, port int) bool {
	for _, drop := range evidence.PacketDrops {
		if drop.Node == node && drop.Direction == DirectionOutbound && drop.Protocol == protocol &&
			drop.Port == port && drop.Packets > 0 {
			return true
		}
	}
	return false
}

func hasLink(rep Report, node, segment string, up bool) bool {
	for _, item := range rep.Evidence.Links {
		if item.Node == node && item.Segment == segment && item.Up == up {
			return true
		}
	}
	return false
}

func countNodeLinks(rep Report, node string) int {
	count := 0
	for _, item := range rep.Evidence.Links {
		if item.Node == node {
			count++
		}
	}
	return count
}

func hasForwarding(rep Report, node string) bool {
	for _, item := range rep.Evidence.Routers {
		if item.Node == node && item.IPv4Forwarding {
			return true
		}
	}
	return false
}

func hasForwardingFamilies(rep Report, node string, ipv4, ipv6 bool) bool {
	for _, item := range rep.Evidence.Routers {
		if item.Node == node && item.IPv4Forwarding == ipv4 && item.IPv6Forwarding == ipv6 {
			return true
		}
	}
	return false
}

func hasDualStackLink(rep Report, node, segment string) bool {
	for _, item := range rep.Evidence.Links {
		if item.Node == node && item.Segment == segment && item.Up && item.IPv4 != "" && item.IPv6 != "" {
			return true
		}
	}
	return false
}

func hasSelectedFamilyRoute(rep Report, node, destination, family string) bool {
	for _, item := range rep.Evidence.Routes {
		if item.Node == node && item.Destination == destination && item.Family == family && item.Selected {
			return true
		}
	}
	return false
}

func hasDNSQueryType(rep Report, name, queryType string) bool {
	for _, item := range rep.Evidence.DNS {
		if item.Name == name && item.QueryType == queryType && item.Result == "ANSWER" && item.Count > 0 {
			return true
		}
	}
	return false
}

// familyReachability returns what the simulator independently observed for one
// address family from one node, and how many such observations it made. Exactly
// one is the contract: a family is either eligible and observed once, or absent
// from the topology and not observed at all.
// familyState names the state a reachable/unreachable expectation stands for.
// Unavailable has no boolean spelling on purpose: it is not an outcome a probe
// can return.
func familyState(reachable bool) string {
	if reachable {
		return FamilyStateReachable
	}
	return FamilyStateUnreachable
}

// runScenarioDefinition runs an in-memory scenario end to end through the real
// simulator binary, the same way the CLI does, and returns its report.
func runScenarioDefinition(t *testing.T, sim, netdoc string, scenario *Scenario, extra ...string) Report {
	t.Helper()
	definition := cloneScenario(scenario)
	canonicalScenarioInput(definition)
	blob, err := yaml.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mutation.yaml")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(sim, append([]string{"run", path, "-json", "-netdoc", netdoc}, extra...)...)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !asExitError(err, &exit) {
		t.Fatalf("run mutation: %v", err)
	}
	var rep Report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("mutation report is not JSON: %v: %s", err, out)
	}
	if rep.Error != "" || !rep.Cleanup.Done {
		t.Fatalf("run failed: error=%q cleanup=%+v", rep.Error, rep.Cleanup)
	}
	return rep
}

func runLibraryScenarioDefinition(t *testing.T, sim, netdoc, name string, extra ...string) Report {
	t.Helper()
	scenario, err := LibraryScenario(name)
	if err != nil {
		t.Fatal(err)
	}
	rep := runScenarioDefinition(t, sim, netdoc, scenario, extra...)
	noteNetnsScenarioExecution(name, &rep)
	return rep
}

// clientFamilyObservation returns the client's single holder-side answer for one
// address family. Exactly one record is required on purpose: a family with no
// record was never dialed, and no assertion may let that absence stand in for a
// measured state.
func clientFamilyObservation(t *testing.T, rep Report, family string) FamilyReachabilityEvidence {
	t.Helper()
	item, count := familyReachability(rep, "client", family)
	if count != 1 {
		t.Fatalf("%s observations = %d, want exactly 1: %+v", family, count, rep.Evidence.FamilyReachability)
	}
	if want := map[string]string{"ipv4": "IPv4 internet endpoints", "ipv6": "IPv6 internet endpoints"}[family]; item.Node != "client" || item.Target != want || len(item.Via) == 0 {
		t.Fatalf("%s observation = %+v, want client to %q over a selected path", family, item, want)
	}
	return item
}

func familyReachability(rep Report, node, family string) (FamilyReachabilityEvidence, int) {
	var found FamilyReachabilityEvidence
	count := 0
	for _, item := range rep.Evidence.FamilyReachability {
		if item.Node == node && item.Family == family {
			found, count = item, count+1
		}
	}
	return found, count
}

// assertObservedFamily checks the simulator's own observation, which is
// collected by dialing the controlled endpoints from inside the client
// namespace and never reads netdoc's verdict. Every family is expected to have
// exactly one record, including an unavailable one: a family with no record at
// all means the measurement never ran, which no caller should accept as an
// answer.
func assertObservedFamily(t *testing.T, rep Report, family, state string) {
	t.Helper()
	item, count := familyReachability(rep, "client", family)
	if count != 1 {
		t.Errorf("%s observations = %d, want exactly 1: %+v", family, count, rep.Evidence.FamilyReachability)
		return
	}
	if item.State != state {
		t.Errorf("simulator observed %s %q, want %q: %+v", family, item.State, state, item)
	}
	if item.State == FamilyStateUnavailable {
		// Nothing was dialed, so there is no endpoint and no path to name.
		if item.Target != "" || len(item.Via) != 0 {
			t.Errorf("unavailable %s observation claims a dialed path: %+v", family, item)
		}
		return
	}
	if want := map[string]string{"ipv4": "IPv4 internet endpoints", "ipv6": "IPv6 internet endpoints"}[family]; item.Target != want {
		t.Errorf("%s observation names %q, want %q", family, item.Target, want)
	}
	if len(item.Via) == 0 {
		t.Errorf("%s observation records no selected path: %+v", family, item)
	}
}

func hasSelectedRoute(rep Report, node, destination, via, segment string, gateway *bool) bool {
	for _, item := range rep.Evidence.Routes {
		if item.Node != node || item.Destination != destination || item.Via != via || item.Segment != segment || !item.Selected {
			continue
		}
		if gateway == nil || item.GatewayReachable != nil && *item.GatewayReachable == *gateway {
			return true
		}
	}
	return false
}

func hasGatewayState(rep Report, node, via string, want bool) bool {
	for _, item := range rep.Evidence.Routes {
		if item.Node == node && item.Via == via && item.GatewayReachable != nil && *item.GatewayReachable == want {
			return true
		}
	}
	return false
}

func hasDefaultRoute(rep Report, node string) bool {
	for _, item := range rep.Topology {
		if item.Name != node {
			continue
		}
		for _, route := range item.Routes {
			if route.Destination == "default" {
				return true
			}
		}
	}
	return false
}

// assertCleanedUp proves the run released everything, and, the part that
// matters, that the host never had any of it in the first place.
func assertCleanedUp(t *testing.T, rep Report) {
	t.Helper()
	if !rep.Cleanup.Done || len(rep.Cleanup.Errors) > 0 {
		t.Errorf("cleanup: done=%t errors=%v", rep.Cleanup.Done, rep.Cleanup.Errors)
	}
	out, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		t.Skip("cannot list host links:", err)
	}
	for _, name := range []string{"nb" + rep.ID, "np" + rep.ID, "ne" + rep.ID} {
		if strings.Contains(string(out), name) {
			t.Errorf("simulation interface %s is visible on the host", name)
		}
	}
}

// TestDryRunCreatesNothing checks the audit path: -dry-run has to print the
// privileged commands without making any of them happen.
func TestDryRunCreatesNothing(t *testing.T) {
	requireBackend(t)
	_, sim := buildBinaries(t)
	cmd := exec.Command(sim, "run", "healthy", "-dry-run")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	for _, want := range []string{"ip link add", "type veth peer name", "spawn node holder"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("dry run did not mention %q:\n%s", want, out)
		}
	}
}

// --- challenge ----------------------------------------------------------

// runChallenge plays one challenge end to end through the real binaries, with
// the human answer supplied on the command line instead of typed.
func runChallenge(t *testing.T, sim, netdoc string, extra ...string) ChallengeResult {
	t.Helper()
	cmd := exec.Command(sim, append([]string{"challenge", "-json", "-netdoc", netdoc}, extra...)...)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !asExitError(err, &exit) {
		t.Fatalf("challenge %v: %v", extra, err)
	}
	var result ChallengeResult
	if jsonErr := json.Unmarshal(out, &result); jsonErr != nil {
		t.Fatalf("challenge %v: result is not JSON (%v): %s", extra, jsonErr, out)
	}
	return result
}

// Every challengeable condition has to reach a scoreable truth through the
// real namespace backend, or the game would tell players "no result" for a
// fault the simulator did inject. This is also where the contract's first test
// is exercised for real: the evidence each condition rests on is read back off
// the live kernel, not assembled in a fixture.
func TestChallengeConditionsAreScoreableEndToEnd(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	for _, condition := range challengeConditions {
		name := condition.mutation
		if name == "" {
			name = "healthy"
		}
		t.Run(name, func(t *testing.T) {
			if condition.mutation == "netem.loss" {
				requireNetemSeed(t)
			}
			challenge := challengeWithMutation(t, condition.mutation)
			result := runChallenge(t, sim, netdoc, "-id", challenge.ID, "-answer", string(condition.answer))
			if !result.Truth.Scoreable {
				t.Fatalf("challenge %s is not scoreable: %s", challenge.ID, result.Truth.Reason)
			}
			if result.Truth.Answer != condition.answer {
				t.Fatalf("truth = %s, want %s", result.Truth.Answer, condition.answer)
			}
			if condition.mutation != "" && !slices.Contains(result.Truth.ObservedFaults, condition.mutation) {
				t.Fatalf("truth was scored without observing %s: %v", condition.mutation, result.Truth.ObservedFaults)
			}
			if condition.mutation == "" && len(result.Truth.ObservedFaults) != 0 {
				t.Fatalf("a healthy challenge observed faults: %v", result.Truth.ObservedFaults)
			}
			if result.Human.Score != ChallengeCorrect {
				t.Fatalf("the correct answer scored %s", result.Human.Score)
			}
			if result.Result != ChallengeDraw && result.Result != ChallengeHumanWins {
				t.Fatalf("result = %s with a correct human answer", result.Result)
			}
			if len(result.Truth.Evidence) == 0 {
				t.Fatal("a scored challenge has to show what the simulator measured")
			}
			// The contract, against the real binary: a condition netdoc has no
			// verdict for has to say so rather than read as a wrong answer.
			if _, known := challengeRecognition[condition.answer]; !known &&
				result.NetworkDoctor.Score != ChallengeUnrecognized {
				t.Fatalf("netdoc scored %s on a condition with no recognition rule",
					result.NetworkDoctor.Score)
			}
			t.Logf("%s: netdoc %s (%s)", name, result.NetworkDoctor.Score, result.NetworkDoctor.Detail)
		})
	}
}

// The same id twice is the same puzzle, and the human's answer is the only
// thing their answer changes.
func TestChallengeReplayIsStableAndHumanAnswerMovesNothingElse(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	challenge := challengeWithMutation(t, "dns.servfail")
	right := runChallenge(t, sim, netdoc, "-id", challenge.ID, "-answer", string(AnswerDNSFailure))
	wrong := runChallenge(t, sim, netdoc, "-id", challenge.ID, "-answer", string(AnswerHTTPService))

	if right.Human.Score != ChallengeCorrect || wrong.Human.Score != ChallengeIncorrect {
		t.Fatalf("human scores %s and %s", right.Human.Score, wrong.Human.Score)
	}
	if right.Truth.Answer != wrong.Truth.Answer || right.Truth.Scoreable != wrong.Truth.Scoreable ||
		!slices.Equal(right.Truth.ObservedFaults, wrong.Truth.ObservedFaults) {
		t.Fatalf("the human's answer moved the truth:\n%+v\n%+v", right.Truth, wrong.Truth)
	}
	if right.NetworkDoctor.Score != wrong.NetworkDoctor.Score {
		t.Fatalf("the human's answer moved Network Doctor's score: %s then %s",
			right.NetworkDoctor.Score, wrong.NetworkDoctor.Score)
	}
	if right.CaseFingerprint != wrong.CaseFingerprint || right.BaseScenario != wrong.BaseScenario ||
		right.Case != wrong.Case {
		t.Fatalf("one id ran two cases: %s/%d and %s/%d",
			right.BaseScenario, right.Case, wrong.BaseScenario, wrong.Case)
	}
}

// The hostname in the briefing has to be a real part of the simulated network,
// answered by real DNS over real sockets from inside the node, not a label
// printed beside a topology that knows it by another name. A player who is
// handed a name they cannot resolve is debugging the game.
//
// This runs the challenge's own scenario through the ordinary run path, so the
// diagnosis it checks is netdoc resolving the renamed name through the node's own
// /etc/resolv.conf against the simulator's own DNS service.
func TestChallengeHostnameResolvesInsideTheNamespaces(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	// A healthy challenge on each base that briefs a hostname, one with plain HTTP
	// and one with TLS: the TLS case additionally proves the renamed name is the
	// name the certificate was issued for, since the handshake verifies it.
	for _, id := range []string{"V3-022CCE", "V3-01EEF0", "V3-013556"} {
		challenge, err := BuildChallenge(id)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(id+"/"+challenge.Base, func(t *testing.T) {
			host := challengeTargetHost(challenge.Target)
			if host == "" || !strings.HasSuffix(host, challengeHostSuffix) {
				t.Fatalf("challenge %s does not brief a hostname (target %q)", id, challenge.Target)
			}
			rep := runScenarioDefinition(t, sim, netdoc, challenge.Scenario)
			var primary *TestOutcome
			for i := range rep.Tests {
				if rep.Tests[i].Node == challenge.Node {
					primary = &rep.Tests[i]
					break
				}
			}
			if primary == nil || primary.Diagnosis == nil {
				t.Fatalf("no diagnosis for the challenge node: %+v", rep.Tests)
			}
			// The target netdoc was actually pointed at is the briefed name, so both
			// contestants are answering about the same host.
			if !strings.Contains(primary.Target, host) {
				t.Fatalf("netdoc was pointed at %q, not the briefed host %q", primary.Target, host)
			}
			// And it resolved. A DNS row that passed is the simulated resolver
			// answering a name that only exists inside this simulation; a failing one
			// would mean the rename reached the briefing and not the zone.
			for _, want := range []string{"dns", "target_tcp"} {
				check, ok := findCheck(primary.Diagnosis.Checks, want)
				if !ok {
					t.Fatalf("the diagnosis has no %s row: %+v", want, primary.Diagnosis.Checks)
				}
				if check.Status != "PASS" {
					t.Fatalf("%s on the briefed host %q is %s (%s); the name is not answerable in the simulation",
						want, host, check.Status, check.Detail)
				}
			}
			if primary.Diagnosis.Verdict != diagnostic.VerdictOK {
				t.Fatalf("a healthy challenge on %q reached verdict %q: %s",
					host, primary.Diagnosis.Verdict, primary.Diagnosis.Summary)
			}
			// Nothing left the namespace to make that work: the name is under the
			// reserved TLD no public resolver may answer, and the resolver the node
			// was given is an address this scenario owns.
			client := challenge.Scenario.Topology.node(challenge.Node)
			if client == nil || client.Resolver == "" {
				t.Fatalf("the challenge node has no scenario resolver to have asked")
			}
			owned := false
			for _, node := range challenge.Scenario.Topology.Nodes {
				owned = owned || nodeOwnsAddress(node, client.Resolver)
			}
			if !owned {
				t.Fatalf("the node's resolver %q is not an address this simulation owns", client.Resolver)
			}
		})
	}
}

// findCheck is one row of a diagnosis by its stable probe id.
func findCheck(checks []DiagnosisCheck, id string) (DiagnosisCheck, bool) {
	for _, check := range checks {
		if check.ID == id {
			return check, true
		}
	}
	return DiagnosisCheck{}, false
}

// A challenge is not a kept simulation: when the command returns, the
// namespaces, the workspace and any record of them are gone.
func TestChallengeLeavesNothingBehind(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	before := stateEntries(t)
	result := runChallenge(t, sim, netdoc, "-give-up")
	if result.ChallengeID == "" {
		t.Fatalf("challenge did not run: %+v", result)
	}
	if after := stateEntries(t); len(after) != len(before) {
		t.Fatalf("challenge left %d state records behind, was %d", len(after), len(before))
	}
	leftovers, err := filepath.Glob(filepath.Join(os.TempDir(), "netdoc-sim-*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range leftovers {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			continue
		}
		if info.ModTime().After(time.Now().Add(-2 * time.Minute)) {
			t.Errorf("challenge left a workspace behind: %s", path)
		}
	}
}

func stateEntries(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(StateDir())
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		out = append(out, entry.Name())
	}
	return out
}
