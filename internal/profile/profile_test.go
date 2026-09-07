package profile

import (
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
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
	return report.Report{
		Target:  &report.Target{Host: run.Target.Host, Port: run.Target.Port, Protocol: run.Target.Proto.String()},
		Checks:  []report.Check{{ID: string(run.Focus), Status: status}},
		Verdict: diagnostic.VerdictOK, OK: status != StatusFail,
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
