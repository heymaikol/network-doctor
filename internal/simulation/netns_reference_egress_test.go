//go:build netns_integration

package simulation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// The healthy scenario stands up netdoc's own reference infrastructure as real
// services on a node that claims 1.1.1.1 and 8.8.8.8: the resolver, the
// captive-portal HTTP endpoint, the fixed QUIC endpoint, and the encrypted-DNS
// provider all answer there. That makes it the one place where the absence of
// that traffic is evidence rather than a tautology.
//
// What this file asserts on is the simulator's own evidence, collected by those
// services inside the node namespace, rather than the rows netdoc chose to
// report. That difference is the point. A row is missing when the probe was
// deselected, which is what every other test in this change already proves at a
// cheaper seam. A service that recorded nothing is proof that no packet arrived,
// whatever code path might have sent one: the netops seam the unit tests stub is
// netdoc's own abstraction, and a raw net.Dial or http.DefaultClient added to an
// automatically executed probe would sail straight past it and still be caught
// here.
//
// No scenario field is added for this. The simulator runs whatever -netdoc
// names, so a two-line wrapper is enough to put the flag in front of the run
// it performs.
func wrappedNetdoc(t *testing.T, netdoc string, flags ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netdoc-wrapper")
	script := "#!/bin/sh\nexec " + netdoc
	for _, flag := range flags {
		script += " " + flag
	}
	script += " \"$@\"\n"
	// #nosec G306 -- an executable wrapper in this test's temporary directory.
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// referenceNode is the scenario node that claims netdoc's fixed endpoints. The
// client's configured resolver lives at the same address, so DNS is judged by
// the name asked rather than by the node asked, and every other service there
// answers only netdoc's own reference traffic.
const referenceNode = "internet"

func healthyRun(t *testing.T, netdoc, sim string) (Report, Diagnosis) {
	t.Helper()
	cmd := exec.Command(sim, "run", "healthy", "-json", "-netdoc", netdoc)
	out, err := cmd.Output()
	var exit *exec.ExitError
	if err != nil && !asExitError(err, &exit) {
		t.Fatalf("run healthy: %v", err)
	}
	var rep Report
	if jsonErr := json.Unmarshal(out, &rep); jsonErr != nil {
		t.Fatalf("run healthy: report is not JSON (%v): %s", jsonErr, out)
	}
	if len(rep.Tests) != 1 || rep.Tests[0].Diagnosis == nil {
		t.Fatalf("no diagnosis came back: %+v", rep.Tests)
	}
	return rep, *rep.Tests[0].Diagnosis
}

// compiledInNameQueries are the queries any resolver in the run answered for
// the hostname netdoc compiles in. Nothing in the scenario asks for that name
// on a user's behalf, so one query is one piece of reference traffic.
func compiledInNameQueries(rep Report) []DNSQueryEvidence {
	var out []DNSQueryEvidence
	for _, q := range rep.Evidence.DNSQueries {
		if q.Name == diagnostic.ConnectivityProbeHost {
			out = append(out, q)
		}
	}
	return out
}

// referenceServiceReplies are the answers served by the non-DNS services on the
// node holding netdoc's fixed endpoints: the captive-portal endpoint and the
// encrypted-DNS provider.
func referenceServiceReplies(rep Report) []ServiceReplyEvidence {
	var out []ServiceReplyEvidence
	for _, reply := range rep.Evidence.ServiceReplies {
		if reply.Node == referenceNode {
			out = append(out, reply)
		}
	}
	return out
}

func targetServiceReplies(rep Report) []ServiceReplyEvidence {
	var out []ServiceReplyEvidence
	for _, reply := range rep.Evidence.ServiceReplies {
		if reply.Node != referenceNode {
			out = append(out, reply)
		}
	}
	return out
}

// No t.Parallel() here. The evidence read back is this run's own, so nothing
// a concurrent run does can reach it, but a test whose whole assertion is an
// absence is the last place worth saving a second.
func TestNoReferenceEgressLeavesTheSimulatedReferenceServicesUntouched(t *testing.T) {
	requireBackend(t)
	netdoc, sim := buildBinaries(t)

	// The control first. Every reference row runs, and the services behind them
	// record having been reached, which is what makes their silence below mean
	// something.
	controlReport, control := healthyRun(t, netdoc, sim)
	reference := diagnostic.ReferenceEgressProbes(true, false)
	for _, id := range reference {
		i := slices.IndexFunc(control.Checks, func(c DiagnosisCheck) bool { return c.ID == string(id) })
		if i < 0 {
			t.Fatalf("an ordinary run is missing row %q, so this scenario cannot prove anything about its absence", id)
		}
		if id != diagnostic.ProbeProxy && control.Checks[i].Status != "PASS" {
			t.Fatalf("row %q is %s in the control, so the service behind it is not reachable here", id, control.Checks[i].Status)
		}
	}
	if len(compiledInNameQueries(controlReport)) == 0 {
		t.Fatalf("the control resolved %s zero times, so its absence below would prove nothing", diagnostic.ConnectivityProbeHost)
	}
	if len(referenceServiceReplies(controlReport)) == 0 {
		t.Fatalf("no service on node %q answered the control, so their silence below would prove nothing", referenceNode)
	}

	// Now the same network, the same node, the same services still listening.
	quietReport, quiet := healthyRun(t, wrappedNetdoc(t, netdoc, "--no-reference-egress"), sim)

	// The services themselves are the witness. This is the assertion that does
	// not depend on netdoc having routed the traffic through any particular
	// abstraction of its own.
	for _, q := range compiledInNameQueries(quietReport) {
		t.Errorf("a resolver answered %s %s under -no-reference-egress, from %s", q.QueryType, q.Name, q.Source)
	}
	for _, reply := range referenceServiceReplies(quietReport) {
		t.Errorf("service %q (%s port %d) on node %q served %d request(s) under -no-reference-egress",
			reply.Service, reply.Type, reply.Port, reply.Node, reply.Count)
	}
	// Negative control at the same seam: the target's own service must still
	// have been reached, or the run proved nothing but that netdoc stayed home.
	if len(targetServiceReplies(quietReport)) == 0 {
		t.Error("no service off the reference node answered, so this run did not reach its target either")
	}

	// And the rows agree with the packets: the reference rows are gone, the
	// target's rows ran, and the verdict still stands.
	for _, id := range reference {
		if slices.ContainsFunc(quiet.Checks, func(c DiagnosisCheck) bool { return c.ID == string(id) }) {
			t.Errorf("row %q reached its service under -no-reference-egress", id)
		}
	}
	for _, id := range []diagnostic.ProbeID{diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeHTTP} {
		i := slices.IndexFunc(quiet.Checks, func(c DiagnosisCheck) bool { return c.ID == string(id) })
		if i < 0 || quiet.Checks[i].Status != "PASS" {
			t.Errorf("the target's own row %q did not pass; checks were %+v", id, quiet.Checks)
		}
	}
	if quiet.Verdict != "ok" {
		t.Errorf("verdict = %q, want ok", quiet.Verdict)
	}
}
