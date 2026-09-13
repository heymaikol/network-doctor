package compare

import (
	"reflect"
	"testing"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// diagnosedRun is one valid artifact carrying every machine-readable field a
// diagnosis can hold, so a case below states only the one fact it moves. It is
// encoded once to prove the fixture is a real snapshot and not a shape only
// this test believes in; the mutations after that are the comparison's
// business, not the format's.
func diagnosedRun(t *testing.T) snapshot.Snapshot {
	t.Helper()
	// The counterfactual alternatives cite rows the finding already carries,
	// which the format requires, so the evidence below is written once and
	// referenced from both places.
	failed := snapshot.CausalEvidence{Kind: snapshot.EvidenceSupport, Check: "dns", Observation: snapshot.ObservationStatusFail}
	answered := snapshot.CausalEvidence{Kind: snapshot.EvidenceRuledOut, Check: "dns_public",
		Observation: snapshot.ObservationDNSAnswers, Value: "2001:db8::1", Candidate: "dns_name_not_found"}
	skipped := snapshot.CausalEvidence{Kind: snapshot.EvidenceNotEvaluated, Check: "target_tcp",
		Observation: snapshot.ObservationStatusSkip, Reason: snapshot.NotEvaluatedPrerequisite}
	s := snapshot.Snapshot{
		Schema: snapshot.Schema, CreatedAt: "2026-01-02T03:04:05Z",
		Tool:   snapshot.Tool{Version: "1.2.3", OS: "linux", Arch: "amd64"},
		Target: &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []snapshot.Check{
			{ID: "dns", Name: "DNS", Status: snapshot.StatusFail, Ran: true, DurationMs: 7,
				Cause: "dns_name_not_found", Detail: "The name did not resolve."},
			{ID: "dns_public", Name: "Public DNS", Status: snapshot.StatusPass, Ran: true, DurationMs: 3,
				Observed: &snapshot.Observed{Addresses: []string{"2001:db8::1", "2001:db8::2"}}},
			{ID: "target_tcp", Name: "TCP", Status: snapshot.StatusSkip},
		},
		Diagnosis: snapshot.Diagnosis{
			Verdict: "dns", Summary: "The system resolver is failing.",
			Blamed: "dns", FailedStage: "dns",
			Findings: []snapshot.Finding{{
				ID: "system_dns_failure", Verdict: "dns", Summary: "The system resolver is failing.",
				Focus: "dns", Confidence: snapshot.ConfidenceHigh,
				Evidence:       []string{"dns", "dns_public"},
				CausalEvidence: []snapshot.CausalEvidence{failed, answered, skipped},
				Counterfactual: &snapshot.Counterfactual{
					Variable: "resolver",
					Alternatives: []snapshot.CounterfactualAlternative{
						{Value: "system", Outcome: "fails", Evidence: []snapshot.CausalEvidence{failed}},
						{Value: "public", Outcome: "works", Evidence: []snapshot.CausalEvidence{answered}},
					},
				},
			}},
		},
	}
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("the parity fixture is not a valid snapshot: %v", err)
	}
	decoded, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func firstFinding(s *snapshot.Snapshot) *snapshot.Finding { return &s.Diagnosis.Findings[0] }

// compared is one mutation per stable machine-readable field of a diagnosis,
// keyed by the struct field it moves. Every one of them has to make the
// comparison say the two runs differ.
var compared = map[string]func(*snapshot.Snapshot){
	"Diagnosis.Verdict":     func(s *snapshot.Snapshot) { s.Diagnosis.Verdict = "network" },
	"Diagnosis.Blamed":      func(s *snapshot.Snapshot) { s.Diagnosis.Blamed = "dns_public" },
	"Diagnosis.FailedStage": func(s *snapshot.Snapshot) { s.Diagnosis.FailedStage = "target_tcp" },
	"Diagnosis.Findings":    func(s *snapshot.Snapshot) { s.Diagnosis.Findings = nil },

	"Finding.ID":         func(s *snapshot.Snapshot) { firstFinding(s).ID = "dns_failure" },
	"Finding.Verdict":    func(s *snapshot.Snapshot) { firstFinding(s).Verdict = "degraded" },
	"Finding.Focus":      func(s *snapshot.Snapshot) { firstFinding(s).Focus = "dns_public" },
	"Finding.Confidence": func(s *snapshot.Snapshot) { firstFinding(s).Confidence = snapshot.ConfidenceLow },
	"Finding.Evidence":   func(s *snapshot.Snapshot) { firstFinding(s).Evidence = []string{"dns"} },
	"Finding.CausalEvidence": func(s *snapshot.Snapshot) {
		firstFinding(s).CausalEvidence = firstFinding(s).CausalEvidence[:1]
	},
	"Finding.Counterfactual": func(s *snapshot.Snapshot) { firstFinding(s).Counterfactual = nil },

	"CausalEvidence.Kind":        func(s *snapshot.Snapshot) { firstFinding(s).CausalEvidence[0].Kind = snapshot.EvidenceContradiction },
	"CausalEvidence.Check":       func(s *snapshot.Snapshot) { firstFinding(s).CausalEvidence[0].Check = "target_tcp" },
	"CausalEvidence.Observation": func(s *snapshot.Snapshot) { firstFinding(s).CausalEvidence[0].Observation = snapshot.ObservationCause },
	"CausalEvidence.Value":       func(s *snapshot.Snapshot) { firstFinding(s).CausalEvidence[1].Value = "2001:db8::2" },
	"CausalEvidence.Candidate":   func(s *snapshot.Snapshot) { firstFinding(s).CausalEvidence[1].Candidate = "dns_failure" },
	"CausalEvidence.Reason": func(s *snapshot.Snapshot) {
		firstFinding(s).CausalEvidence[2].Reason = snapshot.NotEvaluatedNotApplicable
	},

	"Counterfactual.Variable": func(s *snapshot.Snapshot) { firstFinding(s).Counterfactual.Variable = "interface" },
	"Counterfactual.Alternatives": func(s *snapshot.Snapshot) {
		firstFinding(s).Counterfactual.Alternatives = firstFinding(s).Counterfactual.Alternatives[:1]
	},

	"CounterfactualAlternative.Value": func(s *snapshot.Snapshot) {
		firstFinding(s).Counterfactual.Alternatives[0].Value = "encrypted"
	},
	"CounterfactualAlternative.Outcome": func(s *snapshot.Snapshot) {
		firstFinding(s).Counterfactual.Alternatives[0].Outcome = "works"
	},
	"CounterfactualAlternative.Evidence": func(s *snapshot.Snapshot) {
		alternatives := firstFinding(s).Counterfactual.Alternatives
		alternatives[0].Evidence = alternatives[1].Evidence
	},
}

// ignored is the other half of the same classification: fields a comparison
// deliberately does not read, with the reason. All of them are derived
// sentences the snapshot documents as never parsed back, and the machine
// readable form of what they say is compared instead.
var ignored = map[string]func(*snapshot.Snapshot){
	"Diagnosis.Summary": func(s *snapshot.Snapshot) { s.Diagnosis.Summary = "Reworded, same conclusion." },
	"Finding.Summary":   func(s *snapshot.Snapshot) { firstFinding(s).Summary = "Reworded, same conclusion." },
}

// Every stable field of a diagnosis is either compared or deliberately not,
// and a developer has to say which. Adding a field to one of these structs
// fails this test until it is classified, which is what stops a future
// semantic field from falling out of the comparison in silence.
func TestEveryDiagnosisFieldIsClassified(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(snapshot.Diagnosis{}),
		reflect.TypeOf(snapshot.Finding{}),
		reflect.TypeOf(snapshot.CausalEvidence{}),
		reflect.TypeOf(snapshot.Counterfactual{}),
		reflect.TypeOf(snapshot.CounterfactualAlternative{}),
	} {
		for i := range typ.NumField() {
			key := typ.Name() + "." + typ.Field(i).Name
			_, isCompared := compared[key]
			_, isIgnored := ignored[key]
			switch {
			case isCompared && isIgnored:
				t.Errorf("%s is listed as both compared and ignored", key)
			case !isCompared && !isIgnored:
				t.Errorf("%s is neither compared nor documented as ignored: classify it in compare's parity table", key)
			}
		}
	}
	known := map[string]bool{}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(snapshot.Diagnosis{}),
		reflect.TypeOf(snapshot.Finding{}),
		reflect.TypeOf(snapshot.CausalEvidence{}),
		reflect.TypeOf(snapshot.Counterfactual{}),
		reflect.TypeOf(snapshot.CounterfactualAlternative{}),
	} {
		for i := range typ.NumField() {
			known[typ.Name()+"."+typ.Field(i).Name] = true
		}
	}
	for _, table := range []map[string]func(*snapshot.Snapshot){compared, ignored} {
		for key := range table {
			if !known[key] {
				t.Errorf("the parity table classifies %s, which is no longer a field", key)
			}
		}
	}
}

// The behavioral half: a classification is a claim, and each one is checked
// against the comparison rather than taken on trust.
func TestEverySemanticDiagnosisFieldIsCompared(t *testing.T) {
	for name, mutate := range compared {
		t.Run(name, func(t *testing.T) {
			before, after := diagnosedRun(t), diagnosedRun(t)
			mutate(&after)
			result := Snapshots(before, after)
			if result.Same() {
				t.Fatalf("moving %s compares as the same diagnosis", name)
			}
			for _, change := range result.Changes {
				if change.Section == SectionDiagnosis {
					return
				}
			}
			t.Errorf("moving %s produced no diagnosis change: %+v", name, result.Changes)
		})
	}
}

func TestIgnoredDiagnosisProseIsNotASemanticDifference(t *testing.T) {
	for name, mutate := range ignored {
		t.Run(name, func(t *testing.T) {
			before, after := diagnosedRun(t), diagnosedRun(t)
			mutate(&after)
			if result := Snapshots(before, after); !result.Same() {
				t.Errorf("rewording %s became a semantic difference: %+v", name, result.Changes)
			}
		})
	}
}

// The noise the comparison exists to see past: when the run happened, how long
// each probe took, and the sentences derived from both.
func TestTimingNoiseIsNotASemanticDifference(t *testing.T) {
	before, after := diagnosedRun(t), diagnosedRun(t)
	after.CreatedAt = "2026-07-08T09:10:11Z"
	for i := range after.Checks {
		after.Checks[i].DurationMs += 1000
		after.Checks[i].Detail = "reworded after " + after.Checks[i].ID
		after.Checks[i].Fix = "reworded fix"
	}
	if result := Snapshots(before, after); !result.Same() {
		t.Errorf("timing and prose became semantic differences: %+v", result.Changes)
	}
}

// A separator that can occur inside a value is what makes two different
// structures compare equal, and the causal-evidence value routinely holds an
// IPv6 address. These two findings carry the same characters split at
// different points, so any comparison that joins the fields with a delimiter
// reads them as one string and calls the runs identical.
func TestStructuredEvidenceIsComparedUnambiguously(t *testing.T) {
	before, after := diagnosedRun(t), diagnosedRun(t)
	firstFinding(&before).CausalEvidence[1].Value = "2001:db8::1"
	firstFinding(&before).CausalEvidence[1].Candidate = "dns_name_not_found"
	firstFinding(&after).CausalEvidence[1].Value = "2001:db8:"
	firstFinding(&after).CausalEvidence[1].Candidate = "1:dns_name_not_found"
	if result := Snapshots(before, after); result.Same() {
		t.Error("two different causal-evidence rows compare as the same evidence")
	}
}
