package fieldcase

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

func TestReplayCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "field")
	if err := ValidateCorpus(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cases++
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(root, entry.Name())
			fieldCase, err := loadCase(dir)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, SnapshotFilename)) // #nosec G304 -- repository-owned test corpus.
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := diagnostic.ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if err := compareExpected(fieldCase, actual); err != nil {
				t.Fatal(err)
			}
		})
	}
	if cases == 0 {
		t.Fatal("field replay corpus has no cases")
	}
}

func compareExpected(fieldCase Case, actual diagnostic.Diagnosis) error {
	var problems []string
	if actual.Verdict != fieldCase.Expected.Verdict {
		problems = append(problems,
			"expected verdict: "+fieldCase.Expected.Verdict,
			"actual verdict: "+actual.Verdict)
	}
	actualIDs := make([]string, len(actual.Findings))
	for i, finding := range actual.Findings {
		actualIDs[i] = string(finding.ID)
	}
	for _, id := range fieldCase.Expected.Findings {
		if !slices.Contains(actualIDs, id) {
			problems = append(problems, "missing expected finding: "+id)
		}
	}
	for _, id := range actualIDs {
		switch {
		case slices.Contains(fieldCase.Expected.NotFindings, id):
			problems = append(problems, "forbidden finding present: "+id)
		case !slices.Contains(fieldCase.Expected.Findings, id):
			problems = append(problems, "unexpected finding: "+id)
		}
	}
	// Confidence is asserted only where the case chose to, so a missing
	// expectation is silence rather than a pass. Validation has already tied
	// each entry to a required finding, so a level with nothing to compare
	// against means that finding is missing, which is reported above.
	for _, expected := range fieldCase.Expected.Confidence {
		for _, finding := range actual.Findings {
			if string(finding.ID) != expected.Finding {
				continue
			}
			if string(finding.Confidence) != expected.Level {
				problems = append(problems, "finding "+expected.Finding+" confidence: expected "+
					expected.Level+", actual "+string(finding.Confidence))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sortedActual := append([]string(nil), actualIDs...)
	sort.Strings(sortedActual)
	problems = append(problems, "actual findings: "+strings.Join(sortedActual, ", "))
	return fmt.Errorf("field case %q:\n  %s", fieldCase.ID, strings.Join(problems, "\n  "))
}

func TestCompareExpectedFailuresAreDiagnostic(t *testing.T) {
	base := Case{ID: "bootstrap-test", Expected: Expected{
		Verdict: "dns", Findings: []string{"dns_failure"}, NotFindings: []string{"offline"},
	}}
	tests := []struct {
		name   string
		actual diagnostic.Diagnosis
		want   []string
	}{
		{
			name:   "missing expected diagnosis",
			actual: diagnostic.Diagnosis{Verdict: "dns"},
			want:   []string{"field case \"bootstrap-test\"", "missing expected finding: dns_failure", "actual findings:"},
		},
		{
			name: "unexpected false positive",
			actual: diagnostic.Diagnosis{Verdict: "dns", Findings: []diagnostic.DiagnosisFinding{
				{ID: diagnostic.DiagnosisDNSFailure}, {ID: diagnostic.DiagnosisOffline},
			}},
			want: []string{"forbidden finding present: offline", "actual findings: dns_failure, offline"},
		},
		{
			name:   "incorrect verdict",
			actual: diagnostic.Diagnosis{Verdict: "network", Findings: []diagnostic.DiagnosisFinding{{ID: diagnostic.DiagnosisDNSFailure}}},
			want:   []string{"expected verdict: dns", "actual verdict: network"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := compareExpected(base, test.actual)
			if err == nil {
				t.Fatal("comparison unexpectedly passed")
			}
			for _, want := range test.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}
