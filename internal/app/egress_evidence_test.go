// The headless contract for a run whose direct egress failed. downgradeEgress
// relaxes that failure to a Warn when another path carried traffic off this
// network, and a Warn is not a failed check: it leaves ok true, failed_stage
// empty and the exit status 0. That makes the evidence for the downgrade an
// exit-code question, not only a wording one, which is what this pins.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
)

func TestRunJSONEgressFailureNeedsOffNetworkEvidence(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	tests := []struct {
		name    string
		target  string
		exit    int
		status  string
		finding string
	}{
		// A public address answered a direct connection, so traffic did leave
		// this machine and the reference endpoints are what did not answer.
		{"public target reached directly", "93.184.216.34:9999", 0, "WARN", "reference_egress_unreachable"},
		// Both of these answered without any public path being involved, so
		// neither one says the reference endpoints failing is a fact about
		// those addresses alone.
		{"lan target", "192.168.1.1:9999", 1, "FAIL", "direct_egress_blocked"},
		{"shared address space target", "100.100.100.100:9999", 1, "FAIL", "direct_egress_blocked"},
		// No target at all: the resolver answering is the only other thing
		// that worked, and a lookup can be served on-link.
		{"generic run with working DNS", "", 1, "FAIL", "direct_egress_blocked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, _, _ := net.SplitHostPort(tt.target)
			selected := net.ParseIP(host)
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
				for _, p := range probes {
					r := diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
					switch p.ID {
					case diagnostic.ProbeInternet:
						r.Status = diagnostic.StatusFail
					case diagnostic.ProbeProxy, diagnostic.ProbeQUIC, diagnostic.ProbeDNSEncrypted:
						r.Status = diagnostic.StatusNA
					case diagnostic.ProbeTargetTCP:
						r.SelectedIP = selected
					}
					results[p.ID] = r
				}
				// The runner Finalize belongs to, stubbed out with the probes.
				diagnostic.Finalize(results)
				return results
			}
			args := []string{"-json"}
			if tt.target != "" {
				args = append(args, tt.target)
			}
			var stdout, stderr bytes.Buffer
			if got := run(args, &stdout, &stderr); got != tt.exit {
				t.Errorf("exit = %d, want %d; stderr: %s", got, tt.exit, stderr.String())
			}
			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
			}
			if rep.OK != (tt.exit == 0) {
				t.Errorf("ok = %v, want %v", rep.OK, tt.exit == 0)
			}
			if (rep.FailedStage == "") != (tt.exit == 0) {
				t.Errorf("failed_stage = %q with exit %d", rep.FailedStage, tt.exit)
			}
			var egress report.Check
			for _, c := range rep.Checks {
				if c.ID == string(diagnostic.ProbeInternet) {
					egress = c
				}
			}
			if egress.Status != tt.status {
				t.Errorf("internet_tcp = %q, want %q", egress.Status, tt.status)
			}
			if len(rep.Findings) == 0 || rep.Findings[0].ID != tt.finding {
				t.Errorf("findings = %+v, want %s first", rep.Findings, tt.finding)
			}
		})
	}
}
