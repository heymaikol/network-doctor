package remote

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// diagnosedResponse is one finished remote run in the shape the worker sends
// it: a report and a snapshot built from the same pass, carrying a finding
// with typed evidence and a counterfactual so every compared dimension is
// present to be moved.
//
// No SSH server and no worker process. The contract under test is what the
// local side accepts off the wire, and the wire is one JSON object.
func diagnosedResponse(t *testing.T) Response {
	t.Helper()
	tool := snapshot.Tool{Version: "1.2.3", OS: "linux", Arch: "amd64"}
	failed := snapshot.CausalEvidence{Kind: snapshot.EvidenceSupport, Check: "dns", Observation: snapshot.ObservationStatusFail}
	answered := snapshot.CausalEvidence{Kind: snapshot.EvidenceRuledOut, Check: "dns_public",
		Observation: snapshot.ObservationDNSAnswers, Value: "2001:db8::1", Candidate: "dns_name_not_found"}
	counterfactual := &snapshot.Counterfactual{
		Variable: "resolver",
		Alternatives: []snapshot.CounterfactualAlternative{
			{Value: "system", Outcome: "fails", Evidence: []snapshot.CausalEvidence{failed}},
			{Value: "public", Outcome: "works", Evidence: []snapshot.CausalEvidence{answered}},
		},
	}
	snap := snapshot.Snapshot{
		Schema: snapshot.Schema, CreatedAt: "2026-01-02T03:04:05Z", Tool: tool,
		Target: &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []snapshot.Check{
			{ID: "dns", Name: "DNS", Status: snapshot.StatusFail, Ran: true, DurationMs: 7,
				Cause: "dns_name_not_found", Detail: "The name did not resolve."},
			{ID: "dns_public", Name: "Public DNS", Status: snapshot.StatusPass, Ran: true, DurationMs: 3,
				Observed: &snapshot.Observed{Addresses: []string{"2001:db8::1"}}},
		},
		Diagnosis: snapshot.Diagnosis{
			Verdict: "dns", Summary: "The system resolver is failing.", Blamed: "dns", FailedStage: "dns",
			Findings: []snapshot.Finding{{
				ID: "system_dns_failure", Verdict: "dns", Summary: "The system resolver is failing.",
				Focus: "dns", Confidence: snapshot.ConfidenceHigh,
				Evidence:       []string{"dns", "dns_public"},
				CausalEvidence: []snapshot.CausalEvidence{failed, answered},
				Counterfactual: counterfactual,
			}},
		},
	}
	if err := snapshot.Validate(snap); err != nil {
		t.Fatalf("the coherence fixture is not a valid snapshot: %v", err)
	}
	rep := report.Report{
		Version: tool.Version, OK: false, Verdict: "dns", FailedStage: "dns",
		Summary: "The system resolver is failing.",
		Target:  &report.Target{Host: "example.com", Port: 443, Protocol: "tls+http"},
		Checks: []report.Check{
			{ID: "dns", Name: "DNS", Status: "FAIL", Cause: "dns_name_not_found", Ms: 7, Detail: "The name did not resolve."},
			{ID: "dns_public", Name: "Public DNS", Status: "PASS", Ms: 3},
		},
		Findings: []report.Finding{{
			ID: "system_dns_failure", Focus: "dns", Confidence: "high",
			Evidence: []string{"dns", "dns_public"},
			CausalEvidence: []report.CausalEvidence{
				{Kind: "support", Check: "dns", Observation: "status_fail"},
				{Kind: "ruled_out", Check: "dns_public", Observation: "dns_answers",
					Value: "2001:db8::1", Candidate: "dns_name_not_found"},
			},
			Counterfactual: &report.Counterfactual{
				Variable: "resolver",
				Alternatives: []report.CounterfactualAlternative{
					{Value: "system", Outcome: "fails", Evidence: []report.CausalEvidence{
						{Kind: "support", Check: "dns", Observation: "status_fail"}}},
					{Value: "public", Outcome: "works", Evidence: []report.CausalEvidence{
						{Kind: "ruled_out", Check: "dns_public", Observation: "dns_answers",
							Value: "2001:db8::1", Candidate: "dns_name_not_found"}}},
				},
			},
		}},
	}
	return Response{Protocol: Protocol, Tool: tool, Report: &rep, Snapshot: &snap}
}

// decoded sends a response the way the worker does and reads it the way the
// local side does. json.Marshal, never snapshot.Encode: a writer that stamps
// the schema and normalizes the artifact would repair the discrepancy under
// test and then pronounce the repaired copy coherent.
func decoded(t *testing.T, resp Response) (Response, error) {
	t.Helper()
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return decodeResponse(bytes.NewReader(data))
}

func TestAMatchingReportAndSnapshotAreAccepted(t *testing.T) {
	if _, err := decoded(t, diagnosedResponse(t)); err != nil {
		t.Fatalf("a coherent remote diagnosis was refused: %v", err)
	}
}

// Protocol 1 is forward compatible with fields it has never heard of. The
// agreement check reads this build's own decoded structs, so a newer remote's
// additions are already gone by the time it runs and cannot be mistaken for a
// contradiction.
func TestUnknownAdditiveFieldsStayTolerated(t *testing.T) {
	data, err := json.Marshal(diagnosedResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	wire["future_envelope_field"] = "ignored"
	wire["report"].(map[string]any)["future_report_field"] = []any{"ignored"}
	wire["snapshot"].(map[string]any)["future_snapshot_field"] = map[string]any{"ignored": true}
	wire["snapshot"].(map[string]any)["checks"].([]any)[0].(map[string]any)["future_check_field"] = 1
	data, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResponse(bytes.NewReader(data)); err != nil {
		t.Fatalf("an additive field made a coherent response unreadable: %v", err)
	}
}

// A response that failed before producing a diagnosis has no pair to compare,
// and the message it carries is the whole point of it.
func TestAnErrorResponseIsNotHeldToTheAgreement(t *testing.T) {
	resp := Response{Protocol: Protocol, Tool: snapshot.Tool{Version: "1.2.3"}, Error: "-timeout must be positive"}
	got, err := decoded(t, resp)
	if err != nil {
		t.Fatalf("an error response was refused: %v", err)
	}
	if got.Error != resp.Error {
		t.Errorf("Error = %q, want %q", got.Error, resp.Error)
	}
}

// The snapshot arrives inside the envelope, so nothing has asked whether it is
// a snapshot until now. An artifact that contradicts itself is refused before
// it can be written to a file as a record of the run.
func TestAnUnusableRemoteSnapshotIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*Response){
		"wrong schema": func(r *Response) { r.Snapshot.Schema = "netdoc.snapshot.v2" },
		"unnamed check": func(r *Response) {
			r.Snapshot.Checks[0].ID = ""
			r.Report.Checks[0].ID = ""
		},
		"unknown status": func(r *Response) {
			r.Snapshot.Checks[1].Status = "PROBABLY"
			r.Report.Checks[1].Status = "PROBABLY"
		},
		"finding cites a check that is not there": func(r *Response) {
			r.Snapshot.Diagnosis.Findings[0].Focus = "target_tcp"
			r.Report.Findings[0].Focus = "target_tcp"
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := diagnosedResponse(t)
			mutate(&resp)
			_, err := decoded(t, resp)
			if err == nil {
				t.Fatal("an unusable remote snapshot was accepted")
			}
			if !strings.Contains(err.Error(), "unusable snapshot") {
				t.Errorf("err = %v, want it to name the snapshot", err)
			}
		})
	}
}

// One dimension moved at a time, in one artifact only. Each of these is a pair
// that would leave the local side printing one run and storing another.
func TestContradictoryReportAndSnapshotAreRefused(t *testing.T) {
	for name, mutate := range map[string]func(*Response){
		"envelope version":   func(r *Response) { r.Tool.Version = "9.9.9" },
		"envelope os":        func(r *Response) { r.Tool.OS = "windows" },
		"envelope arch":      func(r *Response) { r.Tool.Arch = "arm64" },
		"report version":     func(r *Response) { r.Report.Version = "9.9.9" },
		"overall result":     func(r *Response) { r.Report.OK = true },
		"verdict":            func(r *Response) { r.Report.Verdict = "ok" },
		"failed stage":       func(r *Response) { r.Report.FailedStage = "dns_public" },
		"target presence":    func(r *Response) { r.Report.Target = nil },
		"target host":        func(r *Response) { r.Report.Target.Host = "elsewhere.example" },
		"target port":        func(r *Response) { r.Report.Target.Port = 80 },
		"target protocol":    func(r *Response) { r.Report.Target.Protocol = "tcp" },
		"check count":        func(r *Response) { r.Report.Checks = r.Report.Checks[:1] },
		"check order":        func(r *Response) { r.Report.Checks[0], r.Report.Checks[1] = r.Report.Checks[1], r.Report.Checks[0] },
		"check status":       func(r *Response) { r.Report.Checks[1].Status = "WARN" },
		"check cause":        func(r *Response) { r.Report.Checks[0].Cause = "timeout" },
		"finding count":      func(r *Response) { r.Report.Findings = nil },
		"finding id":         func(r *Response) { r.Report.Findings[0].ID = "dns_failure" },
		"finding focus":      func(r *Response) { r.Report.Findings[0].Focus = "dns_public" },
		"finding confidence": func(r *Response) { r.Report.Findings[0].Confidence = "low" },
		"finding evidence":   func(r *Response) { r.Report.Findings[0].Evidence = []string{"dns"} },
		"causal evidence kind": func(r *Response) {
			r.Report.Findings[0].CausalEvidence[0].Kind = "contradiction"
		},
		"causal evidence value": func(r *Response) {
			r.Report.Findings[0].CausalEvidence[1].Value = "2001:db8::2"
		},
		"counterfactual presence": func(r *Response) { r.Report.Findings[0].Counterfactual = nil },
		"counterfactual variable": func(r *Response) {
			r.Report.Findings[0].Counterfactual.Variable = "interface"
		},
		"counterfactual alternative outcome": func(r *Response) {
			r.Report.Findings[0].Counterfactual.Alternatives[0].Outcome = "works"
		},
		"counterfactual alternative evidence": func(r *Response) {
			r.Report.Findings[0].Counterfactual.Alternatives[0].Evidence[0].Check = "dns_public"
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := diagnosedResponse(t)
			mutate(&resp)
			_, err := decoded(t, resp)
			if err == nil {
				t.Fatal("a report and a snapshot describing different runs were accepted")
			}
			if !strings.Contains(err.Error(), "different runs") {
				t.Errorf("err = %v, want it to name the disagreement", err)
			}
		})
	}
}

// sharedDiagnosisFields is every JSON field name both formats publish about the
// same object, classified. A field only one format carries cannot contradict
// the other and is not listed: the report's remediation and the snapshot's
// observations are each format's own business.
//
// Fields the two formats spell differently on either side of the wire, meaning
// the report's version against the snapshot's tool.version, and the report's
// verdict and failed_stage against the same names under the snapshot's
// diagnosis, are compared by agree and cannot be reached by matching names.
var sharedDiagnosisFields = map[string]map[string]string{
	"Run":     {"target": compared, "checks": compared, "ok": compared},
	"Target":  {"host": compared, "port": compared, "protocol": compared},
	"Finding": {"id": compared, "focus": compared, "confidence": compared, "evidence": compared, "causal_evidence": compared, "counterfactual": compared},
	"Check": {
		"id": compared, "status": compared, "cause": compared,
		"name":   "display text built from the probe and the target",
		"detail": "a derived sentence both formats document as never parsed back",
		"fix":    "a derived sentence both formats document as never parsed back",
	},
}

const compared = "compared"

func jsonFields(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			names[name] = true
		}
	}
	return names
}

// A field added to both published formats has to be classified as compared or
// as prose, which is what stops a future one from falling out of the agreement
// in silence the way confidence and the typed evidence could have.
func TestEverySharedDiagnosisFieldIsClassified(t *testing.T) {
	for name, pair := range map[string][2]reflect.Type{
		"Run":     {reflect.TypeOf(report.Report{}), reflect.TypeOf(snapshot.Snapshot{})},
		"Target":  {reflect.TypeOf(report.Target{}), reflect.TypeOf(snapshot.Target{})},
		"Check":   {reflect.TypeOf(report.Check{}), reflect.TypeOf(snapshot.Check{})},
		"Finding": {reflect.TypeOf(report.Finding{}), reflect.TypeOf(snapshot.Finding{})},
	} {
		classified := sharedDiagnosisFields[name]
		inReport, inSnapshot := jsonFields(pair[0]), jsonFields(pair[1])
		shared := map[string]bool{}
		for field := range inReport {
			if inSnapshot[field] {
				shared[field] = true
			}
			if !inSnapshot[field] && classified[field] != "" {
				t.Errorf("%s.%s is classified but the snapshot no longer carries it", name, field)
			}
		}
		for field := range shared {
			if classified[field] == "" {
				t.Errorf("%s.%s is published by both formats and neither compared nor documented as prose: classify it in remote's agreement table", name, field)
			}
		}
	}
}

// agree compares the typed evidence by encoding it, which is an equality test
// only while both packages declare it the same way. This is the check that
// keeps that true: a field added to one side and not the other would make
// every real response look like a contradiction, and it fails here first.
func TestSharedDiagnosisFieldsStayIdentical(t *testing.T) {
	for name, pair := range map[string][2]reflect.Type{
		"CausalEvidence":            {reflect.TypeOf(report.CausalEvidence{}), reflect.TypeOf(snapshot.CausalEvidence{})},
		"Counterfactual":            {reflect.TypeOf(report.Counterfactual{}), reflect.TypeOf(snapshot.Counterfactual{})},
		"CounterfactualAlternative": {reflect.TypeOf(report.CounterfactualAlternative{}), reflect.TypeOf(snapshot.CounterfactualAlternative{})},
	} {
		inReport, inSnapshot := pair[0], pair[1]
		if inReport.NumField() != inSnapshot.NumField() {
			t.Errorf("%s has %d fields in report and %d in snapshot", name, inReport.NumField(), inSnapshot.NumField())
			continue
		}
		for i := range inReport.NumField() {
			a, b := inReport.Field(i), inSnapshot.Field(i)
			if a.Name != b.Name || a.Tag.Get("json") != b.Tag.Get("json") {
				t.Errorf("%s field %d is %s %q in report and %s %q in snapshot",
					name, i, a.Name, a.Tag.Get("json"), b.Name, b.Tag.Get("json"))
			}
		}
	}
}
