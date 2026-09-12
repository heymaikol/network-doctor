// Package profile defines built-in service diagnostic plans and aggregates
// ordinary Network Doctor reports. It performs no network operations.
package profile

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

const ReportSchema = "netdoc.profile-report.v1"

type TargetRule string

const (
	TargetRequired  TargetRule = "required"
	TargetForbidden TargetRule = "forbidden"
)

type Definition struct {
	Name        string
	Title       string
	Description string
	Version     int
	Target      TargetRule
	build       func(string) ([]Run, error)
}

type Registry struct{ definitions []Definition }

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func NewRegistry(definitions ...Definition) (Registry, error) {
	seen := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		switch {
		case !namePattern.MatchString(definition.Name):
			return Registry{}, fmt.Errorf("invalid profile name %q", definition.Name)
		case seen[definition.Name]:
			return Registry{}, fmt.Errorf("duplicate profile name %q", definition.Name)
		case definition.Title == "" || definition.Description == "" || definition.Version < 1 || definition.build == nil:
			return Registry{}, fmt.Errorf("profile %q is incomplete", definition.Name)
		case definition.Target != TargetRequired && definition.Target != TargetForbidden:
			return Registry{}, fmt.Errorf("profile %q has invalid target rule %q", definition.Name, definition.Target)
		}
		seen[definition.Name] = true
	}
	return Registry{definitions: slices.Clone(definitions)}, nil
}

func Builtins() Registry {
	registry, err := NewRegistry(githubProfile(), sshProfile(), smtpProfile(), webProfile())
	if err != nil {
		panic(err)
	}
	return registry
}

func (r Registry) List() []Definition { return slices.Clone(r.definitions) }

func (r Registry) Names() []string {
	names := make([]string, len(r.definitions))
	for i, definition := range r.definitions {
		names[i] = definition.Name
	}
	return names
}

func (r Registry) Lookup(name string) (Definition, bool) {
	for _, definition := range r.definitions {
		if definition.Name == name {
			return definition, true
		}
	}
	return Definition{}, false
}

type Plan struct {
	Name        string
	Title       string
	Description string
	Version     int
	Runs        []Run
}

type Run struct {
	ID          string
	Label       string
	Target      *diagnostic.Target
	Focus       diagnostic.ProbeID
	Check       []diagnostic.ProbeID
	FallbackFor string
}

func (definition Definition) Plan(target string) (Plan, error) {
	target = strings.TrimSpace(target)
	switch definition.Target {
	case TargetRequired:
		if target == "" {
			return Plan{}, fmt.Errorf("profile %q requires a target", definition.Name)
		}
	case TargetForbidden:
		if target != "" {
			return Plan{}, fmt.Errorf("profile %q uses fixed service endpoints and does not accept a target", definition.Name)
		}
	}
	runs, err := definition.build(target)
	if err != nil {
		return Plan{}, err
	}
	if len(runs) == 0 {
		return Plan{}, fmt.Errorf("profile %q produced an empty diagnostic plan", definition.Name)
	}
	seen := make(map[string]bool, len(runs))
	for _, run := range runs {
		if !namePattern.MatchString(run.ID) || run.Label == "" || run.Target == nil || run.Focus == "" ||
			!slices.Contains(run.Check, run.Focus) || seen[run.ID] {
			return Plan{}, fmt.Errorf("profile %q produced an invalid diagnostic plan", definition.Name)
		}
		seen[run.ID] = true
	}
	for _, run := range runs {
		if run.FallbackFor != "" && (!seen[run.FallbackFor] || run.FallbackFor == run.ID) {
			return Plan{}, fmt.Errorf("profile %q produced an invalid fallback reference", definition.Name)
		}
	}
	return Plan{
		Name: definition.Name, Title: definition.Title, Description: definition.Description,
		Version: definition.Version, Runs: runs,
	}, nil
}

func ComposeSelection(run Run, extra, skip []diagnostic.ProbeID) (diagnostic.ProbeSelection, []diagnostic.ProbeID) {
	check := make([]diagnostic.ProbeID, 0, len(run.Check)+len(extra))
	checkSet := make(map[diagnostic.ProbeID]struct{}, len(run.Check)+len(extra))
	for i, id := range append(slices.Clone(run.Check), extra...) {
		// A profile's default list is not consent to write to an unknown service.
		if i < len(run.Check) && id == diagnostic.ProbePMTU && run.Target != nil && run.Target.Proto == diagnostic.ProtoNone {
			continue
		}
		if _, exists := checkSet[id]; exists {
			continue
		}
		checkSet[id] = struct{}{}
		check = append(check, id)
	}
	skipSet := make(map[diagnostic.ProbeID]struct{}, len(skip))
	for _, id := range skip {
		skipSet[id] = struct{}{}
	}
	return diagnostic.ProbeSelection{Check: checkSet, Skip: skipSet}, check
}

type Result struct {
	Schema         string      `json:"schema"`
	Profile        string      `json:"profile"`
	ProfileVersion int         `json:"profile_version"`
	Title          string      `json:"title"`
	Description    string      `json:"description"`
	Ts             string      `json:"ts,omitempty"`
	Components     []Component `json:"components"`
	Aggregate      Aggregate   `json:"aggregate"`
	OK             bool        `json:"ok"`
}

type Component struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Target   *report.Target `json:"target"`
	Focus    string         `json:"focus"`
	Status   string         `json:"status"`
	Fallback string         `json:"fallback_for,omitempty"`
	Report   report.Report  `json:"report"`
}

type Aggregate struct {
	Status  string   `json:"status"`
	Summary string   `json:"summary"`
	Finding *Finding `json:"finding,omitempty"`
}

type Finding struct {
	ID                 string   `json:"id"`
	AffectedComponents []string `json:"affected_components,omitempty"`
	WorkingComponents  []string `json:"working_components,omitempty"`
}

func BuildResult(plan Plan, reports []report.Report) (Result, error) {
	if len(reports) != len(plan.Runs) {
		return Result{}, fmt.Errorf("profile %q produced %d reports for %d components", plan.Name, len(reports), len(plan.Runs))
	}
	result := Result{
		Schema: ReportSchema, Profile: plan.Name, ProfileVersion: plan.Version,
		Title: plan.Title, Description: plan.Description,
		Components: make([]Component, len(plan.Runs)),
	}
	for i, r := range reports {
		run := plan.Runs[i]
		result.Components[i] = Component{
			ID: run.ID, Label: run.Label, Target: r.Target, Focus: string(run.Focus),
			Status: componentStatus(r, run.Focus), Fallback: run.FallbackFor, Report: r,
		}
	}
	result.Aggregate = aggregate(plan, result.Components)
	result.OK = result.Aggregate.Status != StatusFail
	return result, nil
}

const (
	StatusPass = "PASS"
	StatusWarn = "WARN"
	StatusFail = "FAIL"
	StatusSkip = "SKIP"
	StatusNA   = "N/A"
)

// componentStatus reads one finished run the way a profile reads it. The rule
// itself lives in internal/snapshot, which is where the .ndoc validator can
// also reach it: a component status that the artifact's own nested run does
// not support is the envelope contradicting its evidence, and one
// implementation is what makes that impossible rather than merely tested for.
func componentStatus(r report.Report, focus diagnostic.ProbeID) string {
	focusStatus := ""
	for _, check := range r.Checks {
		if check.ID == string(focus) {
			focusStatus = check.Status
			break
		}
	}
	return snapshot.ProfileComponentStatus(focusStatus, r.Verdict, r.OK)
}

func aggregate(plan Plan, components []Component) Aggregate {
	outcomes := make([]snapshot.ProfileComponentOutcome, len(components))
	for i, component := range components {
		outcomes[i] = snapshot.ProfileComponentOutcome{ID: component.ID, Status: component.Status, Fallback: component.Fallback}
	}
	// The conclusion, the status and the two component lists come from the
	// shared rule. What stays here is the sentence, which needs the labels this
	// package has and the artifact format has no business regenerating.
	conclusion := snapshot.AggregateProfile(outcomes)
	result := Aggregate{Status: conclusion.Status}
	if id := conclusion.FindingID(plan.Name); id != "" {
		result.Finding = &Finding{
			ID:                 id,
			AffectedComponents: conclusion.Affected,
			WorkingComponents:  conclusion.Working,
		}
	}
	label := func(id string) string { return runByID(plan.Runs, id).Label }
	switch conclusion.Conclusion {
	case snapshot.ProfileAllReachable:
		result.Summary = "All " + plan.Title + " components are reachable."
	case snapshot.ProfileNoneReachable:
		result.Summary = "No " + plan.Title + " component completed its service check."
	case snapshot.ProfileFallbackAvailable:
		result.Summary = label(conclusion.Unavailable) + " is unavailable, but " + label(conclusion.Available) + " works."
	case snapshot.ProfileFallbackUnavailable:
		result.Summary = label(conclusion.Available) + " works, but " + label(conclusion.Unavailable) + " is unavailable."
	default:
		result.Summary = "Some " + plan.Title + " components are unavailable or degraded while others work."
	}
	return result
}

func runByID(runs []Run, id string) Run {
	for _, run := range runs {
		if run.ID == id {
			return run
		}
	}
	return Run{}
}

func serviceChecks(focus diagnostic.ProbeID) []diagnostic.ProbeID {
	checks := []diagnostic.ProbeID{
		diagnostic.ProbeInternet, diagnostic.ProbeProxy, diagnostic.ProbeDNSPublic,
		diagnostic.ProbePMTU,
	}
	// An ordinary HTTPS target also checks its plain-HTTP redirect path. Keep
	// that established service interpretation instead of producing an
	// incomplete ordinary report for a profile component.
	if focus == diagnostic.ProbeHTTPS {
		checks = append(checks, diagnostic.ProbeHTTP)
	}
	return append(checks, focus)
}

func endpoint(scheme, host string, port int) (*diagnostic.Target, error) {
	return diagnostic.ParseTarget(scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)))
}

func serviceTarget(raw, scheme string, defaultPort int) (*diagnostic.Target, error) {
	if prefix, _, ok := strings.Cut(raw, "://"); ok && !strings.EqualFold(prefix, scheme) {
		return nil, fmt.Errorf("profile target %q uses %s, want %s or a host name", raw, prefix, scheme)
	}
	parsed, err := diagnostic.ParseTarget(raw)
	if err != nil {
		return nil, err
	}
	port := defaultPort
	if parsed.PortExplicit || strings.Contains(raw, "://") {
		port = parsed.Port
	}
	return endpoint(scheme, parsed.Host, port)
}

func githubProfile() Definition {
	return Definition{
		Name: "github", Title: "GitHub", Version: 1, Target: TargetForbidden,
		Description: "Tests GitHub web, API, direct SSH, and SSH-over-443 paths independently.",
		build: func(string) ([]Run, error) {
			specs := []struct {
				id, label, scheme, host string
				port                    int
				focus                   diagnostic.ProbeID
				fallback                string
			}{
				{"web", "Web", "https", "github.com", 443, diagnostic.ProbeHTTPS, ""},
				{"api", "API", "https", "api.github.com", 443, diagnostic.ProbeHTTPS, ""},
				{"ssh", "Direct SSH", "ssh", "github.com", 22, diagnostic.ProbeSSH, ""},
				{"ssh-alt", "Alternate SSH over port 443", "ssh", "ssh.github.com", 443, diagnostic.ProbeSSH, "ssh"},
			}
			runs := make([]Run, 0, len(specs))
			for _, spec := range specs {
				target, err := endpoint(spec.scheme, spec.host, spec.port)
				if err != nil {
					return nil, err
				}
				runs = append(runs, Run{ID: spec.id, Label: spec.label, Target: target, Focus: spec.focus, Check: serviceChecks(spec.focus), FallbackFor: spec.fallback})
			}
			return runs, nil
		},
	}
}

func sshProfile() Definition {
	return Definition{
		Name: "ssh", Title: "SSH", Version: 1, Target: TargetRequired,
		Description: "Tests the requested SSH service through DNS, routing, TCP, path-MTU, and banner evidence.",
		build: func(raw string) ([]Run, error) {
			primary, err := serviceTarget(raw, "ssh", 22)
			if err != nil {
				return nil, err
			}
			return []Run{{ID: "ssh", Label: "SSH service on port " + strconv.Itoa(primary.Port), Target: primary, Focus: diagnostic.ProbeSSH, Check: serviceChecks(diagnostic.ProbeSSH)}}, nil
		},
	}
}

func smtpProfile() Definition {
	return Definition{
		Name: "smtp", Title: "SMTP", Version: 1, Target: TargetRequired,
		Description: "Tests SMTP relay and message-submission banner paths independently.",
		build: func(raw string) ([]Run, error) {
			primary, err := serviceTarget(raw, "smtp", 25)
			if err != nil {
				return nil, err
			}
			alternatePort, alternateID, alternateLabel := 587, "submission", "Message submission on port 587"
			if primary.Port == 587 {
				alternatePort, alternateID, alternateLabel = 25, "relay", "SMTP relay on port 25"
			}
			alternate, err := endpoint("smtp", primary.Host, alternatePort)
			if err != nil {
				return nil, err
			}
			return []Run{
				{ID: "smtp", Label: "SMTP service on port " + strconv.Itoa(primary.Port), Target: primary, Focus: diagnostic.ProbeSMTP, Check: serviceChecks(diagnostic.ProbeSMTP)},
				{ID: alternateID, Label: alternateLabel, Target: alternate, Focus: diagnostic.ProbeSMTP, Check: serviceChecks(diagnostic.ProbeSMTP)},
			}, nil
		},
	}
}

func webProfile() Definition {
	return Definition{
		Name: "web", Title: "Web", Version: 1, Target: TargetRequired,
		Description: "Tests certificate-validated HTTPS and plain HTTP independently.",
		build: func(raw string) ([]Run, error) {
			secure, err := serviceTarget(raw, "https", 443)
			if err != nil {
				return nil, err
			}
			plain, err := endpoint("http", secure.Host, 80)
			if err != nil {
				return nil, err
			}
			return []Run{
				{ID: "https", Label: "HTTPS service on port " + strconv.Itoa(secure.Port), Target: secure, Focus: diagnostic.ProbeHTTPS, Check: serviceChecks(diagnostic.ProbeHTTPS)},
				{ID: "http", Label: "Plain HTTP service on port 80", Target: plain, Focus: diagnostic.ProbeHTTP, Check: serviceChecks(diagnostic.ProbeHTTP)},
			}, nil
		},
	}
}
