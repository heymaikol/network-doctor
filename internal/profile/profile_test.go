package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func TestBuiltinRegistry(t *testing.T) {
	registry := Builtins()
	if want := []string{"github", "ssh", "smtp", "web"}; !slices.Equal(registry.Names(), want) {
		t.Fatalf("names = %v, want %v", registry.Names(), want)
	}
	for _, name := range registry.Names() {
		if definition, ok := registry.Lookup(name); !ok || definition.Name != name {
			t.Errorf("lookup(%q) = %+v, %v", name, definition, ok)
		}
	}
	if _, ok := registry.Lookup("GitHub"); ok {
		t.Fatal("mixed-case profile name was accepted")
	}
}

func TestRegistryRejectsDuplicates(t *testing.T) {
	definition := githubProfile()
	if _, err := NewRegistry(definition, definition); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestPlanRejectsInvalidDefinitionOutput(t *testing.T) {
	definition := githubProfile()
	definition.build = func(string) ([]Run, error) { return nil, nil }
	if _, err := definition.Plan(""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty plan error = %v", err)
	}
	definition.build = func(string) ([]Run, error) {
		return []Run{{ID: "run", Label: "Run", Target: &diagnostic.Target{}, Focus: diagnostic.ProbeSSH, Check: []diagnostic.ProbeID{diagnostic.ProbeSSH}, FallbackFor: "missing"}}, nil
	}
	if _, err := definition.Plan(""); err == nil || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("fallback error = %v", err)
	}
}

func TestProfileTargetRules(t *testing.T) {
	registry := Builtins()
	github, _ := registry.Lookup("github")
	if _, err := github.Plan("example.com"); err == nil || !strings.Contains(err.Error(), "does not accept") {
		t.Fatalf("github target error = %v", err)
	}
	ssh, _ := registry.Lookup("ssh")
	if _, err := ssh.Plan(""); err == nil || !strings.Contains(err.Error(), "requires") {
		t.Fatalf("ssh missing target error = %v", err)
	}
	if _, err := ssh.Plan("https://example.com"); err == nil || !strings.Contains(err.Error(), "want ssh") {
		t.Fatalf("ssh scheme error = %v", err)
	}
}

func TestBuiltinPlansAreDeterministic(t *testing.T) {
	cases := map[string]struct {
		target string
		want   []string
	}{
		"github": {want: []string{"web=https://github.com:443", "api=https://api.github.com:443", "ssh=ssh://github.com:22", "ssh-alt=ssh://ssh.github.com:443"}},
		"ssh":    {target: "server.example.com", want: []string{"ssh=ssh://server.example.com:22"}},
		"smtp":   {target: "mail.example.com", want: []string{"smtp=smtp://mail.example.com:25", "submission=smtp://mail.example.com:587"}},
		"web":    {target: "service.example.com:8443", want: []string{"https=https://service.example.com:8443", "http=http://service.example.com:80"}},
	}
	registry := Builtins()
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			definition, _ := registry.Lookup(name)
			for range 2 {
				plan, err := definition.Plan(test.target)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]string, len(plan.Runs))
				for i, run := range plan.Runs {
					got[i] = run.ID + "=" + run.Target.Raw
				}
				if !slices.Equal(got, test.want) {
					t.Fatalf("runs = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestComposeSelectionKeepsProfileMinimumAndDependencyClosure(t *testing.T) {
	definition, _ := Builtins().Lookup("github")
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	selection, check := ComposeSelection(plan.Runs[0], []diagnostic.ProbeID{diagnostic.ProbeQUIC, diagnostic.ProbeHTTPS}, []diagnostic.ProbeID{diagnostic.ProbePMTU})
	if !slices.Contains(check, diagnostic.ProbeHTTPS) || !slices.Contains(check, diagnostic.ProbeQUIC) || len(check) != len(plan.Runs[0].Check)+1 {
		t.Fatalf("composed check = %v", check)
	}
	probes := selection.BuildProbesFromSources(plan.Runs[0].Target, nil, diagnostic.DefaultPublicDNS, true)
	var ids []diagnostic.ProbeID
	for _, probe := range probes {
		ids = append(ids, probe.ID)
	}
	for _, want := range []diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeDNS, diagnostic.ProbeTargetTCP, diagnostic.ProbeTLS, diagnostic.ProbeHTTP, diagnostic.ProbeHTTPS, diagnostic.ProbeQUIC} {
		if !slices.Contains(ids, want) {
			t.Errorf("dependency closure %v lacks %s", ids, want)
		}
	}
	if slices.Contains(ids, diagnostic.ProbePMTU) {
		t.Errorf("skip did not override profile selection: %v", ids)
	}
}

func TestComponentStatusKeepsWorkingServiceAsDegraded(t *testing.T) {
	r := report.Report{
		Checks: []report.Check{
			{ID: string(diagnostic.ProbeInternet), Status: StatusFail},
			{ID: string(diagnostic.ProbeSSH), Status: StatusPass},
		},
		Verdict: diagnostic.VerdictDegraded,
	}
	if got := componentStatus(r, diagnostic.ProbeSSH); got != StatusWarn {
		t.Fatalf("component status = %s, want %s", got, StatusWarn)
	}
}

func TestAggregateFallbackAndFailure(t *testing.T) {
	definition, _ := Builtins().Lookup("github")
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	reports := make([]report.Report, len(plan.Runs))
	for i, run := range plan.Runs {
		reports[i] = serviceReport(run, StatusPass)
	}
	reports[2] = serviceReport(plan.Runs[2], StatusFail)
	result, err := BuildResult(plan, reports)
	if err != nil {
		t.Fatal(err)
	}
	if result.Aggregate.Status != StatusWarn || result.Aggregate.Finding == nil || result.Aggregate.Finding.ID != "github_fallback_available" || !result.OK {
		t.Fatalf("fallback aggregate = %+v", result)
	}
	if !strings.Contains(result.Aggregate.Summary, "works") {
		t.Errorf("summary = %q", result.Aggregate.Summary)
	}

	for i, run := range plan.Runs {
		reports[i] = serviceReport(run, StatusFail)
	}
	result, err = BuildResult(plan, reports)
	if err != nil {
		t.Fatal(err)
	}
	if result.Aggregate.Status != StatusFail || result.Aggregate.Finding.ID != "github_unreachable" || result.OK {
		t.Fatalf("failure aggregate = %+v", result)
	}
}

func serviceReport(run Run, status string) report.Report {
	failedStage := ""
	if status == StatusFail {
		failedStage = string(run.Focus)
	}
	return report.Report{
		Target:  &report.Target{Host: run.Target.Host, Port: run.Target.Port, Protocol: run.Target.Proto.String()},
		Checks:  []report.Check{{ID: string(run.Focus), Status: status}},
		Verdict: diagnostic.VerdictOK, FailedStage: failedStage, OK: status != StatusFail,
	}
}

func TestInheritedPMTUIsNotExplicitForUnknownProtocol(t *testing.T) {
	target, err := diagnostic.ParseTarget("host:9999")
	if err != nil {
		t.Fatal(err)
	}
	run := Run{Target: target, Check: serviceChecks(diagnostic.ProbeTargetTCP)}
	for _, explicit := range []bool{false, true} {
		var extra []diagnostic.ProbeID
		if explicit {
			extra = []diagnostic.ProbeID{diagnostic.ProbePMTU}
		}
		selection, checks := ComposeSelection(run, extra, nil)
		if got := slices.Contains(checks, diagnostic.ProbePMTU); got != explicit {
			t.Fatalf("recorded PMTU = %t, want %t", got, explicit)
		}
		probes := selection.BuildProbesFromSources(target, nil, diagnostic.DefaultPublicDNS, true)
		if got := slices.ContainsFunc(probes, func(p diagnostic.Probe) bool { return p.ID == diagnostic.ProbePMTU }); got != explicit {
			t.Fatalf("selected PMTU = %t, want %t", got, explicit)
		}
	}
}

// The profile's reading of a component turns on this one verdict, and the
// artifact format has to spell it without being able to import the package
// that defines it.
func TestProfileRulesMatchTheDiagnosisVocabulary(t *testing.T) {
	if snapshot.VerdictDegraded != diagnostic.VerdictDegraded {
		t.Fatalf("snapshot.VerdictDegraded = %q, diagnostic.VerdictDegraded = %q",
			snapshot.VerdictDegraded, diagnostic.VerdictDegraded)
	}
}

// mirrored is the component run spelled as the .ndoc artifact records it,
// built from the same facts the report carries. The app assembles the real
// artifact this way, and what matters here is that both halves come from one
// run rather than being written to match.
func mirrored(r report.Report) snapshot.Snapshot {
	s := snapshot.Snapshot{
		Schema: snapshot.Schema, CreatedAt: "2026-01-02T03:04:05Z",
		Tool:      snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"},
		OK:        r.OK,
		Diagnosis: snapshot.Diagnosis{Verdict: r.Verdict, Summary: r.Summary, FailedStage: r.FailedStage},
	}
	if r.Target != nil {
		s.Target = &snapshot.Target{Raw: r.Target.Host, Host: r.Target.Host, Port: r.Target.Port, Protocol: r.Target.Protocol}
	}
	for _, check := range r.Checks {
		s.Checks = append(s.Checks, snapshot.Check{
			ID: check.ID, Name: check.ID, Status: check.Status,
			Ran: check.Status != snapshot.StatusIncomplete, DurationMs: 1,
		})
	}
	return s
}

// Every conclusion the producer can reach has to be one the artifact format
// accepts. The two now share the rule rather than each spelling it, and this
// is what keeps that true through the whole reachable space instead of at the
// handful of points a hand-written fixture covers.
func TestEveryProfileResultEncodesAsACoherentArtifact(t *testing.T) {
	definition, _ := Builtins().Lookup("github")
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	statuses := []string{StatusPass, StatusWarn, StatusFail, StatusSkip, StatusNA}
	reports := make([]report.Report, len(plan.Runs))
	var walk func(int)
	walk = func(i int) {
		if i == len(plan.Runs) {
			for _, verdict := range []string{diagnostic.VerdictOK, diagnostic.VerdictDegraded} {
				for j := range reports {
					reports[j].Verdict = verdict
				}
				result, err := BuildResult(plan, reports)
				if err != nil {
					t.Fatal(err)
				}
				artifact := snapshot.ProfileSnapshot{
					Schema: snapshot.ProfileSchema, CreatedAt: "2026-01-02T03:04:06Z",
					Tool:    snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"},
					Profile: snapshot.ProfileIdentity{Name: result.Profile, Version: result.ProfileVersion, Title: result.Title},
					Aggregate: snapshot.ProfileAggregate{
						Status: result.Aggregate.Status, Summary: result.Aggregate.Summary,
					},
					OK: result.OK,
				}
				if finding := result.Aggregate.Finding; finding != nil {
					artifact.Aggregate.Finding = &snapshot.ProfileFinding{
						ID:                 finding.ID,
						AffectedComponents: finding.AffectedComponents,
						WorkingComponents:  finding.WorkingComponents,
					}
				}
				for k, component := range result.Components {
					artifact.Components = append(artifact.Components, snapshot.ProfileComponent{
						ID: component.ID, Label: component.Label, Focus: component.Focus,
						Status: component.Status, Fallback: component.Fallback,
						Snapshot: mirrored(reports[k]),
					})
				}
				if _, err := snapshot.EncodeProfile(artifact); err != nil {
					var got []string
					for _, component := range result.Components {
						got = append(got, component.ID+"="+component.Status)
					}
					t.Fatalf("a result the producer reached is not a valid artifact: %v (verdict %s, %v)", err, verdict, got)
				}
			}
			return
		}
		for _, status := range statuses {
			reports[i] = serviceReport(plan.Runs[i], status)
			walk(i + 1)
		}
	}
	walk(0)
}

// A component whose service check never ran at all was not tested, and both
// halves have to read it that way rather than as a pass.
func TestAComponentWithNoFocusRowIsNotTested(t *testing.T) {
	definition, _ := Builtins().Lookup("ssh")
	plan, err := definition.Plan("server.internal")
	if err != nil {
		t.Fatal(err)
	}
	r := serviceReport(plan.Runs[0], StatusPass)
	r.Checks = nil
	result, err := BuildResult(plan, []report.Report{r})
	if err != nil {
		t.Fatal(err)
	}
	if result.Components[0].Status != StatusSkip {
		t.Fatalf("component status = %s, want %s", result.Components[0].Status, StatusSkip)
	}
	if snapshot.ProfileComponentStatus("", r.Verdict, r.OK) != StatusSkip {
		t.Error("the artifact format reads a missing focus row differently")
	}
}
