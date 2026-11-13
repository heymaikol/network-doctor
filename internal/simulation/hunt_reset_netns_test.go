//go:build netns_integration

package simulation

import (
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// resetMisses keeps the tcp_reset_not_distinguished findings of one analysis.
func resetMisses(manifest GeneratedCaseManifest, rep *Report) []HuntCaseFinding {
	var misses []HuntCaseFinding
	for _, f := range analyzeHuntCase(manifest, rep, collectObservedTruth(manifest, rep)) {
		if f.Code == "tcp_reset_not_distinguished" {
			misses = append(misses, f)
		}
	}
	return misses
}

// checkFor returns the row id of the test whose target is target. It fails the
// test when the run recorded no such row.
func checkFor(t *testing.T, rep *Report, target, id string) DiagnosisCheck {
	t.Helper()
	for _, test := range rep.Tests {
		if check := diagnosisCheck(test, id); test.Target == target && check.ID != "" {
			return check
		}
	}
	t.Fatalf("no %s row for %s in the run", id, target)
	return DiagnosisCheck{}
}

// requireTLSResetMiss checks the closed-cause TLS reader of a tls-failure-causes
// run. Its peer really resets the TLS handshake on 9443, the TLS row reports
// connection_closed, and no row on that endpoint classifies it as a reset. The
// miss must be raised once, named tls, and not for a port or node the reset
// does not sit on.
func requireTLSResetMiss(t *testing.T, rep *Report, target, dialed string) {
	t.Helper()
	if row := checkFor(t, rep, target, "tls"); row.Status != "FAIL" || row.Cause != diagnostic.ConnectionCauseClosed || row.SelectedIP != dialed {
		t.Fatalf("TLS row of %s = %+v; the control needs a FAIL connection_closed read of %s", target, row, dialed)
	}
	reset := false
	for _, event := range rep.Evidence.TCPResets {
		reset = reset || event.Event == "reset" && event.Result == "connection_reset" && event.Count > 0
	}
	if !reset {
		t.Fatalf("reset service recorded no reset: %+v", rep.Evidence.TCPResets)
	}
	if misses := resetMisses(huntManifest(GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 9443}), rep); len(misses) != 1 || misses[0].Probe != "tls" {
		t.Fatalf("reset on target:9443 misses = %+v, want one miss named tls", misses)
	}
	if got := resetMisses(huntManifest(GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 9442}), rep); len(got) != 0 {
		t.Fatalf("reset on the wrong port raised a miss: %+v", got)
	}
	if got := resetMisses(huntManifest(GeneratedMutation{ID: "service.tcp_reset", Node: "internet", TargetPort: 9443}), rep); len(got) != 0 {
		t.Fatalf("reset on the wrong node raised a miss: %+v", got)
	}
}

// TestHuntTLSResetMisclassifiedIsStillAFinding is the end-to-end positive
// control, read through a name next to tests of other endpoints on the same
// node.
func TestHuntTLSResetMisclassifiedIsStillAFinding(t *testing.T) {
	t.Parallel()
	requireBackend(t)
	rep := runScenario(t, "tls-failure-causes")
	requireTLSResetMiss(t, &rep, "https://closed.test:9443", "10.77.0.20")
}

// TestHuntTLSResetOnADeclaredAliasIsAMiss runs the same reader on an address the
// reset node declares as an alias. The reset service binds the wildcard
// address, so the node answers on the alias.
func TestHuntTLSResetOnADeclaredAliasIsAMiss(t *testing.T) {
	t.Parallel()
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	base, err := LibraryScenario("tls-failure-causes")
	if err != nil {
		t.Fatal(err)
	}
	s := cloneScenario(base)
	for i := range s.Topology.Nodes {
		if s.Topology.Nodes[i].Name == "target" {
			s.Topology.Nodes[i].Aliases = []string{"10.77.0.50"}
		}
	}
	for i := range s.Tests {
		if s.Tests[i].Target == "https://closed.test:9443" {
			s.Tests[i].Target = "https://10.77.0.50:9443"
		}
	}
	rep := runScenarioDefinition(t, sim, netdoc, s)
	requireTLSResetMiss(t, &rep, "https://10.77.0.50:9443", "10.77.0.50")
}

// TestHuntBannerReadersClassifyTheReset is the classified control. A banner
// probe reports a reset as connection_reset, never as connection_closed, so the
// SSH and SMTP readers of the tcp-reset scenario classify the reset on its own
// endpoint and raise no miss.
func TestHuntBannerReadersClassifyTheReset(t *testing.T) {
	t.Parallel()
	requireBackend(t)
	netdoc, sim := buildBinaries(t)
	for _, tc := range []struct{ scheme, row string }{{"ssh", "ssh_banner"}, {"smtp", "smtp_banner"}} {
		t.Run(tc.scheme, func(t *testing.T) {
			s, err := LibraryScenario("tcp-reset")
			if err != nil {
				t.Fatal(err)
			}
			s.Tests[0].Target = tc.scheme + "://reset-target.test:2222"
			rep := runScenarioDefinition(t, sim, netdoc, s)
			if check := checkFor(t, &rep, s.Tests[0].Target, tc.row); check.Status != "FAIL" ||
				check.Cause != diagnostic.ConnectionCauseReset || check.SelectedIP != "10.77.0.20" {
				t.Fatalf("%s row = %+v, want FAIL connection_reset on 10.77.0.20", tc.row, check)
			}
			manifest := huntManifest(GeneratedMutation{ID: "service.tcp_reset", Node: "target", TargetPort: 2222})
			if misses := resetMisses(manifest, &rep); len(misses) != 0 {
				t.Fatalf("classified reset raised a miss: %+v", misses)
			}
		})
	}
}
