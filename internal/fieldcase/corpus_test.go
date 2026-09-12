package fieldcase

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func TestRepositoryCorpus(t *testing.T) {
	if err := ValidateCorpus(filepath.Join("..", "..", "testdata", "field")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCorpus(t *testing.T) {
	tests := []struct {
		name string
		edit func(*testing.T, string, string)
		want string
	}{
		{"malformed metadata", func(t *testing.T, _, dir string) {
			write(t, filepath.Join(dir, MetadataFilename), []byte("{"))
		}, "invalid metadata"},
		{"unknown metadata field", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, MetadataFilename)
			data := read(t, path)
			write(t, path, bytes.Replace(data, []byte(`"schema"`), []byte(`"unknown": true, "schema"`), 1))
		}, "unknown field"},
		{"extra metadata value", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, MetadataFilename)
			write(t, path, append(read(t, path), []byte("{}\n")...))
		}, "exactly one JSON value"},
		{"unsupported field schema", editCase(func(c *Case) { c.Schema = "netdoc.field-case.v2" }), "unsupported field-case schema"},
		{"invalid case id", editCase(func(c *Case) { c.ID = "Bad_ID" }), "invalid case id"},
		{"duplicate case id", func(t *testing.T, root, _ string) {
			writeCase(t, root, "zz-duplicate", validCase())
		}, "duplicate case id"},
		{"case id path mismatch", editCase(func(c *Case) { c.ID = "different-id" }), "does not match directory"},
		{"wrong snapshot reference", editCase(func(c *Case) { c.Snapshot = "other.ndoc" }), "snapshot reference"},
		{"missing metadata", func(t *testing.T, _, dir string) {
			remove(t, filepath.Join(dir, MetadataFilename))
		}, "missing case.json"},
		{"missing snapshot", func(t *testing.T, _, dir string) {
			remove(t, filepath.Join(dir, SnapshotFilename))
		}, "missing snapshot.ndoc"},
		{"malformed snapshot", func(t *testing.T, _, dir string) {
			write(t, filepath.Join(dir, SnapshotFilename), []byte("not json"))
		}, "not a Network Doctor snapshot"},
		{"unsupported snapshot schema", func(t *testing.T, _, dir string) {
			write(t, filepath.Join(dir, SnapshotFilename), []byte(`{"schema":"netdoc.snapshot.v2"}`))
		}, "unsupported snapshot schema"},
		{"structurally invalid snapshot", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, SnapshotFilename)
			data := read(t, path)
			write(t, path, bytes.Replace(data, []byte(`"checks": []`), []byte(`"checks": [{"id":"dns","status":"","ran":false,"duration_ms":0}]`), 1))
		}, "has no status"},
		{"unsanitized snapshot", func(t *testing.T, _, dir string) {
			writeSnapshot(t, dir, baseSnapshot())
		}, "not explicitly sanitized"},
		{"wrong redaction policy", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, SnapshotFilename)
			write(t, path, bytes.Replace(read(t, path), []byte(snapshot.SupportRedactionPolicy), []byte("support-v2"), 1))
		}, "invalid redaction metadata"},
		{"noncanonical snapshot", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, SnapshotFilename)
			write(t, path, append(read(t, path), '\n'))
		}, "not the canonical"},
		{"compatible additive snapshot field is noncanonical", func(t *testing.T, _, dir string) {
			path := filepath.Join(dir, SnapshotFilename)
			data := read(t, path)
			data = bytes.Replace(data, []byte("{\n"), []byte("{\n  \"future_optional_field\": \"value\",\n"), 1)
			if _, err := snapshot.Decode(data); err != nil {
				t.Fatalf("snapshot.Decode rejected a compatible additive field: %v", err)
			}
			write(t, path, data)
		}, "not the canonical"},
		{"invalid assessment", editCase(func(c *Case) { c.NetworkDoctor.Assessment = "yes" }), "invalid diagnosis assessment"},
		{"invalid category", editCase(func(c *Case) { c.Environment.Categories = []string{"hotel"} }), "invalid environment category"},
		{"invalid platform", editCase(func(c *Case) { c.Environment.Platform = "macos" }), "invalid platform"},
		{"duplicate category", editCase(func(c *Case) { c.Environment.Categories = []string{CategoryVPN, CategoryVPN} }), "duplicate environment category"},
		{"other without details", editCase(func(c *Case) {
			c.Environment.Categories = []string{CategoryOther}
			c.Environment.Details = ""
		}), "other requires details"},
		{"missing ground truth", editCase(func(c *Case) { c.GroundTruth.Statement = "" }), "ground_truth.statement is required"},
		{"missing verification", editCase(func(c *Case) { c.GroundTruth.Verification = nil }), "ground_truth.verification is required"},
		{"invalid verification method", editCase(func(c *Case) { c.GroundTruth.Verification[0].Method = "network_doctor" }), "invalid method"},
		{"missing verification details", editCase(func(c *Case) { c.GroundTruth.Verification[0].Details = " " }), "verification[0].details is required"},
		{"invalid provenance", editCase(func(c *Case) { c.Provenance.Origin = "simulator" }), "invalid provenance origin"},
		{"synthetic non-bootstrap provenance", editCase(func(c *Case) { c.Provenance.Origin = OriginSynthetic }), "reserved for bootstrap"},
		{"real bootstrap provenance", func(t *testing.T, root, dir string) {
			renamed := filepath.Join(root, "bootstrap-test")
			if err := os.Rename(dir, renamed); err != nil {
				t.Fatal(err)
			}
			fieldCase := validCase()
			fieldCase.ID = "bootstrap-test"
			fieldCase.Provenance.Origin = OriginRealNetwork
			writeCaseMetadata(t, renamed, fieldCase)
		}, "must declare synthetic"},
		{"invalid expected verdict", editCase(func(c *Case) { c.Expected.Verdict = "broken" }), "invalid expected verdict"},
		{"invalid expected confidence", editCase(func(c *Case) {
			c.Expected.Findings = []string{"dns_failure"}
			c.Expected.Confidence = []ExpectedConfidence{{Finding: "dns_failure", Level: "very_high"}}
		}), "invalid level"},
		{"confidence for an unexpected finding", editCase(func(c *Case) {
			c.Expected.Confidence = []ExpectedConfidence{{Finding: "dns_failure", Level: ConfidenceHigh}}
		}), "not an expected finding"},
		{"confidence for a forbidden finding", editCase(func(c *Case) {
			c.Expected.Confidence = []ExpectedConfidence{{Finding: "offline", Level: ConfidenceHigh}}
		}), "not an expected finding"},
		{"repeated confidence", editCase(func(c *Case) {
			c.Expected.Findings = []string{"dns_failure"}
			c.Expected.Confidence = []ExpectedConfidence{
				{Finding: "dns_failure", Level: ConfidenceHigh},
				{Finding: "dns_failure", Level: ConfidenceLow},
			}
		}), "twice"},
		{"empty expected finding", editCase(func(c *Case) { c.Expected.Findings = []string{""} }), "empty finding ID"},
		{"overlapping expected finding", editCase(func(c *Case) {
			c.Expected.Findings = []string{"dns_failure"}
			c.Expected.NotFindings = []string{"dns_failure"}
		}), "appears in both"},
		{"version mismatch", editCase(func(c *Case) { c.NetworkDoctor.Version = "9.9.9" }), "does not match case version"},
		{"platform mismatch", editCase(func(c *Case) { c.Environment.Platform = "windows" }), "does not match case platform"},
		{"missing tool provenance", func(t *testing.T, _, dir string) {
			s := snapshot.SanitizeForSupport(baseSnapshot())
			s.Tool.Arch = ""
			writeInvalidSnapshot(t, dir, s)
		}, "incomplete tool provenance"},
		{"invalid creation time", func(t *testing.T, _, dir string) {
			s := snapshot.SanitizeForSupport(baseSnapshot())
			s.CreatedAt = "yesterday"
			writeInvalidSnapshot(t, dir, s)
		}, "not RFC 3339 UTC"},
		{"unexpected case file", func(t *testing.T, _, dir string) {
			write(t, filepath.Join(dir, "notes.txt"), []byte("raw report"))
		}, "unexpected entry"},
		{"unexpected corpus file", func(t *testing.T, root, _ string) {
			write(t, filepath.Join(root, "raw.ndoc"), []byte("private"))
		}, "unexpected entry"},
		{"missing corpus readme", func(t *testing.T, root, _ string) {
			remove(t, filepath.Join(root, "README.md"))
		}, "missing README.md"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, dir := validCorpus(t)
			test.edit(t, root, dir)
			err := ValidateCorpus(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateCorpus error = %v, want it to contain %q", err, test.want)
			}
			if !strings.Contains(err.Error(), root) {
				t.Errorf("error does not name corpus or case path: %v", err)
			}
		})
	}
}

func TestValidateCorpusTrustsDeclaredSupportRedaction(t *testing.T) {
	root, dir := validCorpus(t)
	s := baseSnapshot()
	s.Target = &snapshot.Target{
		Raw: "private.internal", Host: "private.internal", Port: 443, Protocol: "tls+http",
	}
	s.Redaction = &snapshot.Redaction{Sanitized: true, Policy: snapshot.SupportRedactionPolicy}
	writeSnapshot(t, dir, s)

	if err := ValidateCorpus(root); err != nil {
		t.Fatalf("ValidateCorpus rejected declared support redaction: %v", err)
	}
}

func TestValidationErrorIsDeterministic(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "README.md"), []byte("test corpus"))
	if err := os.Mkdir(filepath.Join(root, "empty-case"), 0o750); err != nil {
		t.Fatal(err)
	}
	first := ValidateCorpus(root)
	second := ValidateCorpus(root)
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("validation errors differ: %v / %v", first, second)
	}
}

func validCorpus(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	write(t, filepath.Join(root, "README.md"), []byte("synthetic test corpus"))
	dir := writeCase(t, root, validCase().ID, validCase())
	if err := ValidateCorpus(root); err != nil {
		t.Fatalf("valid synthetic corpus: %v", err)
	}
	return root, dir
}

func validCase() Case {
	return Case{
		Schema: Schema,
		ID:     "2026-08-31-synthetic-test",
		Environment: Environment{
			Categories: []string{CategorySplitDNS}, Platform: "linux",
			PlatformDetails: "synthetic test platform",
		},
		NetworkDoctor: NetworkDoctor{Version: "1.2.3", Assessment: AssessmentCorrect},
		GroundTruth: GroundTruth{
			Statement: "Synthetic ground truth used only by this validator test.",
			Verification: []Verification{{
				Method: VerificationControlledChange, Details: "The test fixture controls both outcomes.",
			}},
		},
		Expected: Expected{Verdict: "ok", Findings: []string{}, NotFindings: []string{"offline"}},
		Provenance: Provenance{
			Origin:  OriginRealNetwork,
			Summary: "Fictitious real-network metadata under internal package testdata only.",
		},
		Snapshot: SnapshotFilename,
	}
}

func baseSnapshot() snapshot.Snapshot {
	return snapshot.Snapshot{
		CreatedAt: "2026-08-31T12:00:00Z",
		Tool:      snapshot.Tool{Version: "1.2.3", OS: "linux", Arch: "amd64"},
		Checks:    []snapshot.Check{},
		Diagnosis: snapshot.Diagnosis{Verdict: "ok", Summary: "Synthetic test run passed."},
		OK:        true,
	}
}

func writeCase(t *testing.T, root, dirName string, fieldCase Case) string {
	t.Helper()
	dir := filepath.Join(root, dirName)
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeCaseMetadata(t, dir, fieldCase)
	writeSnapshot(t, dir, snapshot.SanitizeForSupport(baseSnapshot()))
	return dir
}

func editCase(edit func(*Case)) func(*testing.T, string, string) {
	return func(t *testing.T, _, dir string) {
		fieldCase := validCase()
		edit(&fieldCase)
		writeCaseMetadata(t, dir, fieldCase)
	}
}

func writeCaseMetadata(t *testing.T, dir string, fieldCase Case) {
	t.Helper()
	data, err := json.MarshalIndent(fieldCase, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, MetadataFilename), append(data, '\n'))
}

func writeSnapshot(t *testing.T, dir string, s snapshot.Snapshot) {
	t.Helper()
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, SnapshotFilename), data)
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	// #nosec G304 -- path is a test-owned file under t.TempDir.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func remove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// Invalid artifacts must bypass Encode so this tests the corpus read boundary.
func writeInvalidSnapshot(t *testing.T, dir string, s snapshot.Snapshot) {
	t.Helper()
	s.Schema = snapshot.Schema
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, SnapshotFilename), data)
}
