// Package fieldcase validates the repository's field replay corpus. It adds
// reviewed ground truth around a support snapshot and never reconstructs live
// diagnostic state.
package fieldcase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

const (
	Schema           = "netdoc.field-case.v1"
	MetadataFilename = "case.json"
	SnapshotFilename = "snapshot.ndoc"

	AssessmentCorrect       = "correct"
	AssessmentMostlyCorrect = "mostly_correct"
	AssessmentIncorrect     = "incorrect"
	AssessmentUncertain     = "uncertain"

	OriginRealNetwork = "real_network"
	OriginSynthetic   = "synthetic"

	CategoryVPN        = "vpn"
	CategoryCorporate  = "corporate"
	CategoryCampus     = "campus"
	CategoryCaptive    = "captive_portal"
	CategoryPublicWiFi = "public_wifi"
	CategoryIPv6First  = "ipv6_first"
	CategoryIPv6Only   = "ipv6_only"
	CategoryDNS64NAT64 = "dns64_nat64"
	CategorySplitDNS   = "split_dns"
	CategoryProxy      = "proxy"
	CategoryCustomDNS  = "custom_dns"
	CategoryOther      = "other"

	VerificationControlledChange    = "controlled_change"
	VerificationIndependentTool     = "independent_tool"
	VerificationConfigurationReview = "configuration_review"
	VerificationPacketCapture       = "packet_capture"
	VerificationSuccessfulFix       = "successful_remediation"
	VerificationProviderConfirmed   = "provider_confirmation"
	VerificationOther               = "other"

	ConfidenceHigh                 = "high"
	ConfidenceMedium               = "medium"
	ConfidenceLow                  = "low"
	ConfidenceInsufficientEvidence = "insufficient_evidence"
)

type Case struct {
	Schema        string        `json:"schema"`
	ID            string        `json:"id"`
	Environment   Environment   `json:"environment"`
	NetworkDoctor NetworkDoctor `json:"network_doctor"`
	GroundTruth   GroundTruth   `json:"ground_truth"`
	Expected      Expected      `json:"expected"`
	Provenance    Provenance    `json:"provenance"`
	Snapshot      string        `json:"snapshot"`
	Notes         string        `json:"notes,omitempty"`
}

type Environment struct {
	Categories      []string `json:"categories"`
	Platform        string   `json:"platform"`
	PlatformDetails string   `json:"platform_details,omitempty"`
	Details         string   `json:"details,omitempty"`
}

type NetworkDoctor struct {
	Version    string `json:"version"`
	Assessment string `json:"assessment"`
}

type GroundTruth struct {
	Statement    string         `json:"statement"`
	Verification []Verification `json:"verification"`
}

// Expected is the current machine-readable behavior independently verified
// ground truth requires. Findings is exact; NotFindings names especially
// important false positives for clearer failures.
//
// Confidence is optional and deliberately partial. A case asserts a level only
// where the reviewer can defend why that evidence warrants it; annotating every
// fixture with whatever the engine happens to say today would record the
// implementation rather than a judgment, and later calibration would then be
// measuring the corpus against itself.
type Expected struct {
	Verdict     string               `json:"verdict"`
	Findings    []string             `json:"findings"`
	NotFindings []string             `json:"not_findings,omitempty"`
	Confidence  []ExpectedConfidence `json:"confidence,omitempty"`
}

// ExpectedConfidence is the confidence one named finding must be given. Finding
// has to appear in Expected.Findings, so a case cannot assert a strength for a
// conclusion it does not also require.
type ExpectedConfidence struct {
	Finding string `json:"finding"`
	Level   string `json:"level"`
}

type Verification struct {
	Method  string `json:"method"`
	Details string `json:"details"`
}

type Provenance struct {
	Origin  string `json:"origin"`
	Summary string `json:"summary"`
}

var (
	caseIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	categories    = set(
		CategoryVPN, CategoryCorporate, CategoryCampus, CategoryCaptive,
		CategoryPublicWiFi, CategoryIPv6First, CategoryIPv6Only,
		CategoryDNS64NAT64, CategorySplitDNS, CategoryProxy,
		CategoryCustomDNS, CategoryOther,
	)
	assessments = set(
		AssessmentCorrect, AssessmentMostlyCorrect,
		AssessmentIncorrect, AssessmentUncertain,
	)
	verificationMethods = set(
		VerificationControlledChange, VerificationIndependentTool,
		VerificationConfigurationReview, VerificationPacketCapture,
		VerificationSuccessfulFix, VerificationProviderConfirmed,
		VerificationOther,
	)
	platforms   = set("linux", "darwin", "windows")
	verdicts    = set("ok", "degraded", "dns", "network", "service", "incomplete")
	confidences = set(
		ConfidenceHigh, ConfidenceMedium,
		ConfidenceLow, ConfidenceInsufficientEvidence,
	)
)

// ValidateCorpus discovers and validates every case directory under root.
// os.ReadDir returns entries in filename order, keeping the first reported
// failure deterministic as the corpus grows.
func ValidateCorpus(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("field corpus %s: %w", root, err)
	}
	readme := false
	seen := map[string]string{}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if entry.Name() == "README.md" {
			if entry.Type().IsRegular() {
				readme = true
				continue
			}
			return fmt.Errorf("field corpus %s: README.md is not a regular file", root)
		}
		if !entry.IsDir() {
			return fmt.Errorf("field corpus %s: unexpected entry %s", root, path)
		}
		fieldCase, err := loadCase(path)
		if err != nil {
			return err
		}
		metadataPath := filepath.Join(path, MetadataFilename)
		if first, duplicate := seen[fieldCase.ID]; duplicate {
			return fmt.Errorf("%s: duplicate case id %q, first used by %s", metadataPath, fieldCase.ID, first)
		}
		seen[fieldCase.ID] = metadataPath
		if fieldCase.ID != entry.Name() {
			return fmt.Errorf("%s: case id %q does not match directory %q", metadataPath, fieldCase.ID, entry.Name())
		}
	}
	if !readme {
		return fmt.Errorf("field corpus %s: missing README.md", root)
	}
	return nil
}

func loadCase(dir string) (Case, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Case{}, fmt.Errorf("field case %s: %w", dir, err)
	}
	want := map[string]bool{MetadataFilename: false, SnapshotFilename: false}
	for _, entry := range entries {
		present, expected := want[entry.Name()]
		if !expected || present || !entry.Type().IsRegular() {
			return Case{}, fmt.Errorf("field case %s: unexpected entry %s", dir, filepath.Join(dir, entry.Name()))
		}
		want[entry.Name()] = true
	}
	for _, name := range []string{MetadataFilename, SnapshotFilename} {
		if !want[name] {
			return Case{}, fmt.Errorf("field case %s: missing %s", dir, name)
		}
	}

	metadataPath := filepath.Join(dir, MetadataFilename)
	data, err := os.ReadFile(metadataPath) // #nosec G304 -- the repository-owned corpus path is intentional input.
	if err != nil {
		return Case{}, fmt.Errorf("%s: %w", metadataPath, err)
	}
	var fieldCase Case
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fieldCase); err != nil {
		return Case{}, fmt.Errorf("%s: invalid metadata: %w", metadataPath, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Case{}, fmt.Errorf("%s: metadata must contain exactly one JSON value", metadataPath)
	}
	if err := fieldCase.validate(); err != nil {
		return Case{}, fmt.Errorf("%s: %w", metadataPath, err)
	}
	if err := validateSnapshot(filepath.Join(dir, SnapshotFilename), fieldCase); err != nil {
		return Case{}, err
	}
	return fieldCase, nil
}

func (c Case) validate() error {
	if c.Schema != Schema {
		return fmt.Errorf("unsupported field-case schema %q, want %q", c.Schema, Schema)
	}
	if len(c.ID) > 80 || !caseIDPattern.MatchString(c.ID) {
		return fmt.Errorf("invalid case id %q", c.ID)
	}
	if c.Snapshot != SnapshotFilename {
		return fmt.Errorf("snapshot reference is %q, want %q", c.Snapshot, SnapshotFilename)
	}
	if len(c.Environment.Categories) == 0 {
		return errors.New("environment has no categories")
	}
	seen := map[string]bool{}
	for _, category := range c.Environment.Categories {
		if !categories[category] {
			return fmt.Errorf("invalid environment category %q", category)
		}
		if seen[category] {
			return fmt.Errorf("duplicate environment category %q", category)
		}
		seen[category] = true
	}
	if seen[CategoryOther] && blank(c.Environment.Details) {
		return errors.New("environment category other requires details")
	}
	if !platforms[c.Environment.Platform] {
		return fmt.Errorf("invalid platform %q", c.Environment.Platform)
	}
	if blank(c.NetworkDoctor.Version) {
		return errors.New("network_doctor.version is required")
	}
	if !assessments[c.NetworkDoctor.Assessment] {
		return fmt.Errorf("invalid diagnosis assessment %q", c.NetworkDoctor.Assessment)
	}
	if blank(c.GroundTruth.Statement) {
		return errors.New("ground_truth.statement is required")
	}
	if len(c.GroundTruth.Verification) == 0 {
		return errors.New("ground_truth.verification is required")
	}
	for i, verification := range c.GroundTruth.Verification {
		if !verificationMethods[verification.Method] {
			return fmt.Errorf("ground_truth.verification[%d] has invalid method %q", i, verification.Method)
		}
		if blank(verification.Details) {
			return fmt.Errorf("ground_truth.verification[%d].details is required", i)
		}
	}
	if !verdicts[c.Expected.Verdict] {
		return fmt.Errorf("invalid expected verdict %q", c.Expected.Verdict)
	}
	findings := map[string]string{}
	for _, list := range []struct {
		name   string
		values []string
	}{{"findings", c.Expected.Findings}, {"not_findings", c.Expected.NotFindings}} {
		for _, id := range list.values {
			if blank(id) {
				return fmt.Errorf("expected %s contains an empty finding ID", list.name)
			}
			if first := findings[id]; first != "" {
				return fmt.Errorf("expected finding %q appears in both %s and %s", id, first, list.name)
			}
			findings[id] = list.name
		}
	}
	asserted := map[string]bool{}
	for i, expected := range c.Expected.Confidence {
		if !confidences[expected.Level] {
			return fmt.Errorf("expected confidence[%d] has invalid level %q", i, expected.Level)
		}
		if findings[expected.Finding] != "findings" {
			return fmt.Errorf("expected confidence[%d] names %q, which is not an expected finding", i, expected.Finding)
		}
		if asserted[expected.Finding] {
			return fmt.Errorf("expected confidence names %q twice", expected.Finding)
		}
		asserted[expected.Finding] = true
	}
	if c.Provenance.Origin != OriginRealNetwork && c.Provenance.Origin != OriginSynthetic {
		return fmt.Errorf("invalid provenance origin %q", c.Provenance.Origin)
	}
	if c.Provenance.Origin == OriginSynthetic && !strings.HasPrefix(c.ID, "bootstrap-") {
		return fmt.Errorf("synthetic provenance is reserved for bootstrap-* fixtures")
	}
	if c.Provenance.Origin == OriginRealNetwork && strings.HasPrefix(c.ID, "bootstrap-") {
		return fmt.Errorf("bootstrap-* fixtures must declare synthetic provenance")
	}
	if blank(c.Provenance.Summary) {
		return errors.New("provenance.summary is required")
	}
	return nil
}

func validateSnapshot(path string, fieldCase Case) error {
	data, err := os.ReadFile(path) // #nosec G304 -- the repository-owned corpus path is intentional input.
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if s.Redaction == nil || !s.Redaction.Sanitized {
		return fmt.Errorf("%s: snapshot is not explicitly sanitized", path)
	}
	if s.Redaction.Policy != snapshot.SupportRedactionPolicy {
		return fmt.Errorf("%s: redaction policy is %q, want %q", path, s.Redaction.Policy, snapshot.SupportRedactionPolicy)
	}
	if s.Tool.Version != fieldCase.NetworkDoctor.Version {
		return fmt.Errorf("%s: snapshot tool version %q does not match case version %q", path, s.Tool.Version, fieldCase.NetworkDoctor.Version)
	}
	if s.Tool.OS != fieldCase.Environment.Platform {
		return fmt.Errorf("%s: snapshot platform %q does not match case platform %q", path, s.Tool.OS, fieldCase.Environment.Platform)
	}
	canonical, err := snapshot.Encode(s)
	if err != nil {
		return fmt.Errorf("%s: encode canonical snapshot: %w", path, err)
	}
	if !bytes.Equal(data, canonical) {
		return fmt.Errorf("%s: snapshot is not the canonical current .ndoc encoding", path)
	}
	return nil
}

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func blank(value string) bool { return strings.TrimSpace(value) == "" }
