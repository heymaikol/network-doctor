package app

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// This is also the coverage-counter fixture for a local profile component
// that requests both projections. No actual probes run.
func TestDiagnosisReuseProjections(t *testing.T) {
	originalRun, originalNow := runAll, timeNow
	t.Cleanup(func() { runAll, timeNow = originalRun, originalNow })
	timeNow = func() time.Time { return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) }
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusFail, Detail: "offline"}
		}
		return results
	}
	out := diagnoseHeadless(context.Background(), headless{timeout: diagnostic.DefaultProbeTimeout}, true)
	if out.err != nil {
		t.Fatal(out.err)
	}
	if out.report.Summary != out.snapshot.Diagnosis.Summary || out.report.Verdict != out.snapshot.Diagnosis.Verdict {
		t.Fatal("report and snapshot diagnoses disagree")
	}
	if len(out.report.Findings) == 0 || len(out.report.Findings) != len(out.snapshot.Diagnosis.Findings) {
		t.Fatal("report and snapshot findings disagree")
	}
	for i, finding := range out.report.Findings {
		if finding.ID != out.snapshot.Diagnosis.Findings[i].ID {
			t.Fatal("report and snapshot finding IDs disagree")
		}
	}
}

func TestDiagnosisReuseProjectionEquivalence(t *testing.T) {
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []*diagnostic.Target{nil, target} {
		probes := diagnostic.BuildProbesFromSources(target, nil, "", false)
		for _, status := range []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusWarn, diagnostic.StatusFail, diagnostic.StatusSkip, diagnostic.StatusNA} {
			results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
			for _, p := range probes {
				results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: status, Detail: "observation", Fix: "suggestion"}
			}
			for _, partial := range []bool{false, true} {
				if partial {
					delete(results, probes[len(probes)-1].ID)
				}
				d := diagnostic.Interpret(target, diagnostic.ProbeOrder(probes), results)
				sharedReport := buildReportWithDiagnosis(target, probes, results, d)
				freshReport := buildReport(target, probes, results)
				if !reflect.DeepEqual(sharedReport, freshReport) {
					t.Fatalf("report fields differ: status=%s, partial=%t", status, partial)
				}
				h := headless{target: target, timeout: diagnostic.DefaultProbeTimeout}
				sharedSnapshot := buildSnapshotArtifactWithDiagnosis(h, probes, results, d)
				freshSnapshot := buildSnapshotArtifact(h, probes, results)
				// The invocation timestamp is independent of the diagnosis.
				freshSnapshot.CreatedAt = sharedSnapshot.CreatedAt
				for name, pair := range map[string][2]any{
					"report": {sharedReport, freshReport}, "snapshot": {sharedSnapshot, freshSnapshot},
				} {
					shared, err := json.Marshal(pair[0])
					if err != nil {
						t.Fatal(err)
					}
					fresh, err := json.Marshal(pair[1])
					if err != nil {
						t.Fatal(err)
					}
					if string(shared) != string(fresh) {
						t.Fatalf("%s serialization differs: status=%s, partial=%t", name, status, partial)
					}
				}
			}
		}
	}
}
