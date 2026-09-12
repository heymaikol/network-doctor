package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// LabScenario is an internal, structured authoring API, not another published
// YAML schema. Network uses the existing topology and service vocabulary.
// Mutations are applied to a private copy in order, before any observation.
// Expectations and truth never enter the observation producer.
type LabScenario struct {
	Name, Description string
	Network           Scenario
	Faults            []LabFault
	Views             []LabView
	Tunnels           []string // logical segments whose interfaces encapsulate traffic
	TwoSided          string   // expected placement, empty for a single view
	BlindSpots        []string
	// KnownIssues pin independently judged failures in corpus tests. RunLab
	// still reports FAIL and the CLI still exits 1; these never waive a check.
	KnownIssues []string
}

// LabFault records intent independently of the engine. Exactly one mutation
// is required: a network fault, service replacement, resolver selection, or
// route replacement. Scope names the affected object, not a diagnosed cause.
type LabFault struct {
	ID, Layer, Scope       string
	Localizable            bool
	Network                *Fault
	Service                *Service // replace an existing named service, preserving its node
	ResolverNode, Resolver string
	Route                  *Route // replace same node/destination/metric, or add a specific route
	HTTPNoResponse         string // named HTTP/TLS service accepts connections but sends no HTTP response
}

type LabView struct {
	Node, Target, SourceSegment string
	Proxy                       *TestProxy
	Expected                    LabExpected
}

// LabExpected allows ambiguity via an allowed finding set and confidence
// ranges. A missing Required is not permission to emit arbitrary findings.
type LabExpected struct {
	Verdict                      string
	Required, Allowed, Forbidden []diagnostic.DiagnosisID
	Checks                       []ExpectedCheck
	Confidence                   []LabConfidence
	Evidence                     []LabEvidenceRequirement
}

type LabConfidence struct {
	Finding  diagnostic.DiagnosisID
	Min, Max diagnostic.Confidence
}

type LabEvidenceRequirement struct {
	Finding     diagnostic.DiagnosisID
	Check       diagnostic.ProbeID
	Observation diagnostic.ObservationID
}

type LabReport struct {
	Scenario   string
	Truth      []LabFault
	Topology   Topology
	Views      []LabObservation
	TwoSided   *compare.TwoSided
	Comparison *compare.Comparison
	Problems   []string
	BlindSpots []string
}

type LabObservation struct {
	Node     string
	Expected LabExpected
	Measured []snapshot.Check // before production reconciliation
	Snapshot snapshot.Snapshot
	Trace    []LabExchange // simulator-only full paths and matched faults
}

func (r LabReport) Passed() bool { return len(r.Problems) == 0 }

func (s LabScenario) compile() (*labNetwork, error) {
	if !isSafeName(s.Name) || len(s.Views) < 1 || len(s.Views) > 2 {
		return nil, errors.New("lab requires a safe name and one or two views")
	}
	n := cloneScenario(&s.Network)
	n.Name = s.Name
	// Lab expectations are semantic and independent of the namespace oracle.
	n.Expect = Expect{Verdict: diagnostic.VerdictOK}
	n.Tests = nil
	n.Campaign = nil
	if len(n.Faults) != 0 {
		return nil, errors.New("lab base must be fault-free; use Faults")
	}
	for _, v := range s.Views {
		if err := v.Expected.validate(); err != nil {
			return nil, err
		}
		var proxy *TestProxy
		if v.Proxy != nil {
			copy := *v.Proxy
			proxy = &copy
		}
		n.Tests = append(n.Tests, Test{Node: v.Node, Target: v.Target, SourceSegment: v.SourceSegment, Proxy: proxy})
	}
	if err := cloneScenario(n).Validate(); err != nil {
		return nil, err
	}
	if (len(s.Views) == 2) != (s.TwoSided != "") {
		return nil, errors.New("two views require a two-sided expectation")
	}
	if s.TwoSided != "" && !slices.Contains([]string{compare.SideNone, compare.SideA, compare.SideB, compare.SideBoth, compare.SideShared, compare.SideUnknown}, s.TwoSided) {
		return nil, errors.New("invalid two-sided expectation")
	}
	seen := map[string]bool{}
	var silentHTTP []string
	for _, f := range s.Faults {
		if !isSafeName(f.ID) || seen[f.ID] || f.Scope == "" || !slices.Contains([]string{"link", "routing", "dns", "transport", "tls", "http"}, f.Layer) {
			return nil, fmt.Errorf("invalid or duplicate fault %q", f.ID)
		}
		seen[f.ID] = true
		count := 0
		if f.HTTPNoResponse != "" {
			count++
			found := false
			for _, node := range n.Topology.Nodes {
				for _, service := range node.Services {
					if service.Name == f.HTTPNoResponse && (service.Type == ServiceHTTP || service.Type == ServiceTLS) {
						found = true
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("fault %s: unknown HTTP service", f.ID)
			}
			silentHTTP = append(silentHTTP, f.HTTPNoResponse)
		}
		if f.Network != nil {
			count++
			n.Faults = append(n.Faults, *f.Network)
		}
		if f.Service != nil {
			count++
			found := false
			for i := range n.Topology.Nodes {
				for j := range n.Topology.Nodes[i].Services {
					if n.Topology.Nodes[i].Services[j].Name == f.Service.Name {
						n.Topology.Nodes[i].Services[j] = *f.Service
						found = true
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("fault %s: unknown service %s", f.ID, f.Service.Name)
			}
		}
		if f.ResolverNode != "" || f.Resolver != "" {
			count++
			node := n.Topology.node(f.ResolverNode)
			if node == nil || f.Resolver == "" {
				return nil, fmt.Errorf("fault %s: invalid resolver selection", f.ID)
			}
			node.Resolver = f.Resolver
		}
		if f.Route != nil {
			count++
			found := false
			for i, r := range n.Topology.Routes {
				if r.Node == f.Route.Node && r.Destination == f.Route.Destination && r.Metric == f.Route.Metric {
					n.Topology.Routes[i] = *f.Route
					found = true
					break
				}
			}
			if !found {
				n.Topology.Routes = append(n.Topology.Routes, *f.Route)
			}
		}
		if count != 1 {
			return nil, fmt.Errorf("fault %s: exactly one mutation required", f.ID)
		}
	}
	// Copy replacement service maps/slices before normalization mutates them.
	n = cloneScenario(n)
	if err := n.Validate(); err != nil {
		return nil, err
	}
	m := &labNetwork{scenario: n, tunnels: append([]string(nil), s.Tunnels...), silentHTTP: silentHTTP}
	for _, segment := range s.Tunnels {
		if !slices.ContainsFunc(n.Topology.Segments, func(v Segment) bool { return v.Name == segment }) {
			return nil, fmt.Errorf("unknown tunnel segment %s", segment)
		}
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// RunLab substitutes modeled observations, not diagnoses, into the production
// graph. RunAll owns dependency skips and Finalize; BuildSnapshot calls Interpret.
// Every callback is pure apart from its private trace. The fixed duration is a
// logical observation tick, not elapsed host time.
func RunLab(ctx context.Context, s LabScenario) (LabReport, error) {
	// Own metadata as well as topology: editing an authored fault after a run
	// must not rewrite that report's truth or invalidate its trace indices.
	// ponytail: JSON copies these small internal values; use typed cloning if
	// larger authored corpora make copying a measured bottleneck.
	data, err := json.Marshal(s)
	if err != nil {
		return LabReport{}, err
	}
	var owned LabScenario
	if err := json.Unmarshal(data, &owned); err != nil {
		return LabReport{}, err
	}
	s = owned
	m, err := s.compile()
	if err != nil {
		return LabReport{}, err
	}
	rep := LabReport{Scenario: s.Name, Truth: s.Faults, Topology: m.scenario.Topology, BlindSpots: s.BlindSpots}
	for i, v := range s.Views {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		var target *diagnostic.Target
		if v.Target != "" {
			target, err = diagnostic.ParseTarget(v.Target)
			if err != nil {
				return rep, err
			}
		}
		probes := diagnostic.ProbePlan(target, diagnostic.DefaultPublicDNS, false)
		traces := map[diagnostic.ProbeID][]LabExchange{}
		raw := map[diagnostic.ProbeID]diagnostic.ProbeResult{}
		var mu sync.Mutex
		for j := range probes {
			id := probes[j].ID
			if !labProbeSupported(id) {
				return rep, fmt.Errorf("lab has no observation adapter for %s", id)
			}
			probes[j].Run = func(_ context.Context, deps map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
				p := labProbe{network: m, view: m.scenario.Tests[i], target: target, id: id}
				result := p.observe(deps)
				result.ID = id
				result.Dur = time.Millisecond
				mu.Lock()
				traces[id] = p.trace
				raw[id] = result
				mu.Unlock()
				return result
			}
		}
		results := diagnostic.RunAll(ctx, probes, diagnostic.DefaultProbeTimeout)
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		artifact := diagnostic.BuildSnapshot(target, probes, results)
		artifact.Tool = snapshot.Tool{Version: "scenario-lab", OS: "model", Arch: "model"}
		artifact.CreatedAt = "2000-01-01T00:00:00Z"
		artifact.Options = snapshot.Options{ProbeTimeoutMs: diagnostic.ProbeTimeoutMs(diagnostic.DefaultProbeTimeout), PublicDNS: diagnostic.DefaultPublicDNS}
		if v.SourceSegment != "" {
			binding := &snapshot.Source{Interface: v.SourceSegment}
			for _, iface := range m.scenario.Topology.node(v.Node).Interfaces {
				if iface.Segment != v.SourceSegment {
					continue
				}
				if a := labInterfaceAddr(iface, true); a.IsValid() {
					binding.IPv4 = a.String()
				}
				if a := labInterfaceAddr(iface, false); a.IsValid() {
					binding.IPv6 = a.String()
				}
			}
			artifact.Options.Source = binding
		}
		// Re-encoding exercises the same artifact boundary real runs use.
		data, err := snapshot.Encode(artifact)
		if err != nil {
			return rep, err
		}
		artifact, err = snapshot.Decode(data)
		if err != nil {
			return rep, err
		}
		replay, err := diagnostic.ReplaySnapshot(artifact)
		if err != nil {
			return rep, err
		}
		order := make([]diagnostic.ProbeID, len(probes))
		for j, p := range probes {
			order[j] = p.ID
		}
		if !reflect.DeepEqual(replay, diagnostic.Interpret(target, order, results)) {
			return rep, errors.New("diagnosis changed across snapshot replay")
		}
		for _, p := range probes {
			if _, ok := raw[p.ID]; !ok {
				raw[p.ID] = results[p.ID] // prerequisite skip, never a measurement
			}
		}
		observed := LabObservation{Node: v.Node, Expected: v.Expected, Snapshot: artifact, Measured: diagnostic.BuildSnapshot(target, probes, raw).Checks}
		for _, p := range probes {
			observed.Trace = append(observed.Trace, traces[p.ID]...)
		}
		rep.Views = append(rep.Views, observed)
		for _, problem := range ValidateLabDiagnosis(v.Expected, artifact, replay) {
			rep.Problems = append(rep.Problems, v.Node+": "+problem)
		}
	}
	if len(rep.Views) == 2 {
		sides, err := compare.TwoSidedSnapshots(rep.Views[0].Snapshot, rep.Views[1].Snapshot)
		if err != nil {
			return rep, err
		}
		rep.TwoSided = &sides
		comparison := compare.Snapshots(rep.Views[0].Snapshot, rep.Views[1].Snapshot)
		rep.Comparison = &comparison
		if sides.Diagnosis.Side != s.TwoSided {
			rep.Problems = append(rep.Problems, fmt.Sprintf("two-sided: want %s, got %s", s.TwoSided, sides.Diagnosis.Side))
		}
	}
	return rep, nil
}

func (e LabExpected) validate() error {
	if !slices.Contains([]string{"ok", "degraded", "dns", "network", "service", "incomplete"}, e.Verdict) {
		return errors.New("lab expectation requires a valid verdict")
	}
	if err := (&Expect{Verdict: e.Verdict, Checks: e.Checks}).validate(); err != nil {
		return err
	}
	for _, c := range e.Checks {
		if c.Fix != "" {
			return errors.New("lab expectations use semantics, not fix wording")
		}
	}
	for _, id := range append(append([]diagnostic.DiagnosisID{}, e.Required...), e.Allowed...) {
		if id == "" || slices.Contains(e.Forbidden, id) {
			return fmt.Errorf("contradictory finding expectation %s", id)
		}
	}
	for _, c := range e.Confidence {
		if !slices.Contains(e.Required, c.Finding) || confidenceRank(c.Min) < 0 || confidenceRank(c.Max) < 0 || confidenceRank(c.Min) > confidenceRank(c.Max) {
			return errors.New("invalid confidence bounds")
		}
	}
	for _, r := range e.Evidence {
		if !slices.Contains(e.Required, r.Finding) || r.Check == "" || r.Observation == "" {
			return errors.New("invalid required evidence")
		}
	}
	return nil
}

func confidenceRank(c diagnostic.Confidence) int {
	return slices.Index([]diagnostic.Confidence{diagnostic.ConfidenceInsufficientEvidence, diagnostic.ConfidenceLow, diagnostic.ConfidenceMedium, diagnostic.ConfidenceHigh}, c)
}

// ValidateLabDiagnosis judges meaning and provenance, never summary wording.
// It accepts a diagnosis separately so negative tests can inject unsupported
// claims without changing the simulated evidence or the production engine.
func ValidateLabDiagnosis(e LabExpected, s snapshot.Snapshot, d diagnostic.Diagnosis) []string {
	return validateLabDiagnosis(e, s, d, true)
}

// ValidateLabEvidence checks provenance without authored verdict or finding expectations.
func ValidateLabEvidence(s snapshot.Snapshot, d diagnostic.Diagnosis) []string {
	return validateLabDiagnosis(LabExpected{}, s, d, false)
}

func validateLabDiagnosis(e LabExpected, s snapshot.Snapshot, d diagnostic.Diagnosis, authored bool) []string {
	var problems []string
	if authored && d.Verdict != e.Verdict {
		problems = append(problems, fmt.Sprintf("verdict: want %s, got %s", e.Verdict, d.Verdict))
	}
	if len(d.Findings) > 0 && (d.Findings[0].Verdict != d.Verdict || d.Findings[0].Focus != d.Blamed) {
		problems = append(problems, "primary finding disagrees with diagnosis")
	}
	checks := map[string]snapshot.Check{}
	for _, c := range s.Checks {
		checks[c.ID] = c
	}
	found := map[diagnostic.DiagnosisID]diagnostic.DiagnosisFinding{}
	for _, f := range d.Findings {
		if _, exists := found[f.ID]; exists {
			problems = append(problems, "duplicate finding: "+string(f.ID))
		}
		found[f.ID] = f
		if !slices.Contains([]string{diagnostic.VerdictDegraded, diagnostic.VerdictDNS, diagnostic.VerdictNetwork, diagnostic.VerdictService, diagnostic.VerdictIncomplete}, f.Verdict) {
			problems = append(problems, "invalid finding verdict: "+string(f.ID))
		}
		if confidenceRank(f.Confidence) < 0 {
			problems = append(problems, "invalid finding confidence: "+string(f.ID))
		}
		if authored && (slices.Contains(e.Forbidden, f.ID) || !slices.Contains(e.Required, f.ID) && !slices.Contains(e.Allowed, f.ID)) {
			problems = append(problems, "unsupported finding: "+string(f.ID))
		}
		support := false
		evidence := append([]diagnostic.CausalEvidence(nil), f.Evidence...)
		if f.Counterfactual != nil {
			if !labCounterfactualHolds(*f.Counterfactual, f.Evidence, checks) {
				problems = append(problems, "unsupported counterfactual: "+string(f.ID))
			}
			for _, alternative := range f.Counterfactual.Alternatives {
				evidence = append(evidence, alternative.Evidence...)
			}
		}
		for _, item := range evidence {
			c, ok := checks[string(item.Check)]
			if item.Kind == diagnostic.EvidenceNotEvaluated {
				valid := false
				switch item.Reason {
				case diagnostic.NotEvaluatedPrerequisite:
					valid = item.Observation == diagnostic.ObservationStatusSkip && ok && c.Status == snapshot.StatusSkip && !c.Ran
				case diagnostic.NotEvaluatedNotSelected:
					valid = item.Observation == "" && !ok
				case diagnostic.NotEvaluatedNotApplicable:
					valid = item.Observation == diagnostic.ObservationStatusNA && ok && c.Status == snapshot.StatusNA
				case diagnostic.NotEvaluatedIncomplete:
					valid = item.Observation == "" && ok && c.Status == snapshot.StatusIncomplete
				}
				if !valid {
					problems = append(problems, "invalid missing-evidence claim: "+string(item.Check))
				}
				continue
			}
			if !slices.Contains([]diagnostic.EvidenceKind{diagnostic.EvidenceSupport, diagnostic.EvidenceContradiction, diagnostic.EvidenceRuledOut}, item.Kind) || !ok || !c.Ran || !labEvidenceHolds(c, item) {
				problems = append(problems, fmt.Sprintf("%s cites unsupported %s on %s", f.ID, item.Observation, item.Check))
			}
			if item.Kind == diagnostic.EvidenceSupport && ok && c.Ran && item.Check == f.Focus && labEvidenceHolds(c, item) {
				support = true
			}
		}
		if !support {
			problems = append(problems, "finding has no measured support: "+string(f.ID))
		}
	}
	for _, id := range e.Required {
		if _, ok := found[id]; !ok {
			problems = append(problems, "missing finding: "+string(id))
		}
	}
	for _, c := range e.Confidence {
		if f, ok := found[c.Finding]; ok && (confidenceRank(f.Confidence) < confidenceRank(c.Min) || confidenceRank(f.Confidence) > confidenceRank(c.Max)) {
			problems = append(problems, "confidence outside bounds: "+string(c.Finding))
		}
	}
	for _, r := range e.Evidence {
		if f, ok := found[r.Finding]; ok && !slices.ContainsFunc(f.Evidence, func(x diagnostic.CausalEvidence) bool {
			return x.Kind == diagnostic.EvidenceSupport && x.Check == r.Check && x.Observation == r.Observation
		}) {
			problems = append(problems, "missing required evidence: "+string(r.Observation))
		}
	}
	for _, want := range e.Checks {
		got, ok := checks[want.ID]
		// One rule, owned by the format. The lab used to spell it a second
		// time here, and a second spelling is a second rule to drift.
		if ok && snapshot.ExecutionContradicts(got) {
			problems = append(problems, "check execution contradicts status: "+want.ID)
		}
		if !ok || got.Status != want.Status || want.Cause != "" && got.Cause != want.Cause {
			problems = append(problems, fmt.Sprintf("check %s: want %s/%s, got %s/%s", want.ID, want.Status, want.Cause, got.Status, got.Cause))
		}
		for _, family := range []struct {
			want string
			v4   bool
		}{{want.IPv4, true}, {want.IPv6, false}} {
			if family.want != "" {
				actual := ""
				if got.Observed != nil && got.Observed.Families != nil {
					actual = got.Observed.Families.IPv6
					if family.v4 {
						actual = got.Observed.Families.IPv4
					}
				}
				if actual != family.want {
					problems = append(problems, "family evidence mismatch: "+want.ID)
				}
			}
		}
	}
	return problems
}

// Check controlled-alternative labels against their cited measurements. This
// validates a claimed outcome; it never selects a diagnosis from those outcomes.
func labCounterfactualHolds(cf diagnostic.Counterfactual, evidence []diagnostic.CausalEvidence, checks map[string]snapshot.Check) bool {
	if len(cf.Alternatives) < 2 {
		return false
	}
	seen := map[string]bool{}
	for _, a := range cf.Alternatives {
		if a.Value == "" || seen[a.Value] {
			return false
		}
		seen[a.Value] = true
		matched := false
		for _, e := range a.Evidence {
			if e.Kind != diagnostic.EvidenceSupport || !slices.Contains(evidence, e) {
				return false
			}
			c, ok := checks[string(e.Check)]
			if !ok || !c.Ran || !labEvidenceHolds(c, e) {
				return false
			}
			var outcome diagnostic.CounterfactualOutcome
			switch cf.Variable {
			case diagnostic.CounterfactualDNSResolver:
				if a.Value == "system" && e.Check != diagnostic.ProbeDNS || a.Value == "independent" && e.Check != diagnostic.ProbeDNSPublic || a.Value != "system" && a.Value != "independent" {
					return false
				}
				switch e.Observation {
				case diagnostic.ObservationDNSAnswers:
					outcome = diagnostic.CounterfactualSucceeded
				case diagnostic.ObservationDNSNotFound:
					outcome = diagnostic.CounterfactualNotFound
				case diagnostic.ObservationCause, diagnostic.ObservationStatusFail:
					if c.Status == snapshot.StatusFail {
						outcome = diagnostic.CounterfactualFailed
					}
				}
			case diagnostic.CounterfactualAddressFamily:
				if a.Value != "ipv4" && a.Value != "ipv6" || e.Value != a.Value {
					return false
				}
				if e.Check == diagnostic.ProbeTargetTCP {
					if e.Observation == diagnostic.ObservationFamilyReachable {
						outcome = diagnostic.CounterfactualSucceeded
					}
					if e.Observation == diagnostic.ObservationFamilyFailed {
						outcome = diagnostic.CounterfactualFailed
					}
				}
			case diagnostic.CounterfactualResolvedAddress:
				if !labAddr(a.Value).IsValid() || e.Value != a.Value {
					return false
				}
				if e.Observation == diagnostic.ObservationAddressSucceeded {
					outcome = diagnostic.CounterfactualSucceeded
				}
				if e.Observation == diagnostic.ObservationAddressFailed {
					outcome = diagnostic.CounterfactualFailed
				}
			default:
				return false
			}
			if outcome != "" {
				if outcome != a.Outcome {
					return false
				}
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func labEvidenceHolds(c snapshot.Check, e diagnostic.CausalEvidence) bool {
	switch e.Observation {
	case diagnostic.ObservationStatusPass:
		return c.Status == "PASS"
	case diagnostic.ObservationStatusWarn:
		return c.Status == "WARN"
	case diagnostic.ObservationStatusFail:
		return c.Status == "FAIL"
	case diagnostic.ObservationCause:
		return c.Cause != "" && (e.Value == "" || e.Value == c.CauseFamily)
	case diagnostic.ObservationStatusDowngraded:
		return c.Derived != nil && c.Derived.StatusDowngraded
	}
	o := c.Observed
	if o == nil {
		return false
	}
	switch e.Observation {
	case diagnostic.ObservationDNSAnswers:
		return len(o.Addresses) > 0 && (e.Value == "" || slices.Contains(o.Addresses, e.Value))
	case diagnostic.ObservationDNSNotFound:
		return o.DNSNotFound
	case diagnostic.ObservationCaptivePortal:
		return o.Portal != nil
	case diagnostic.ObservationTimeout:
		return o.Timeout || c.Cause == diagnostic.TLSCauseTimeout
	case diagnostic.ObservationFamilyReachable, diagnostic.ObservationFamilyFailed:
		if o.Families == nil || (e.Value != "ipv4" && e.Value != "ipv6") {
			return false
		}
		value := o.Families.IPv4
		if e.Value == "ipv6" {
			value = o.Families.IPv6
		}
		want := diagnostic.FamilyReachable
		if e.Observation == diagnostic.ObservationFamilyFailed {
			want = diagnostic.FamilyUnreachable
		}
		return value == want
	case diagnostic.ObservationAddressSucceeded, diagnostic.ObservationAddressFailed:
		return slices.ContainsFunc(o.Attempts, func(a snapshot.Attempt) bool {
			return a.IP == e.Value && !a.Aborted && ((a.Cause == "") == (e.Observation == diagnostic.ObservationAddressSucceeded))
		})
	case diagnostic.ObservationRouteTunneled:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool {
			return r.Interface == e.Value && (r.Tunnel == "tunnel" || r.Tunnel == "likely")
		})
	case diagnostic.ObservationRouteDirect:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.Interface == e.Value && r.Tunnel == "direct" })
	case diagnostic.ObservationRouteUnreachable:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.Unreachable && r.Destination == e.Value })
	case diagnostic.ObservationRoutePathDiffers:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.Interface != "" && r.Interface != e.Value })
	case diagnostic.ObservationRouteNextHopDiffers:
		return e.Value != "" && slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.Gateway != "" && r.Gateway != e.Value })
	case diagnostic.ObservationRouteTableDiffers:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.TableKnown && r.Table != e.Value })
	case diagnostic.ObservationRouteInterfaceMTU:
		return slices.ContainsFunc(o.Routes, func(r snapshot.Route) bool { return r.Interface == e.Value && r.InterfaceMTU > 0 })
	case diagnostic.ObservationRouteFamilySplit:
		for _, a := range o.Routes {
			for _, b := range o.Routes {
				if a.Family != b.Family && a.Interface != b.Interface {
					return true
				}
			}
		}
	}
	return false // a newly added observable needs an explicit provenance check
}

// LabTopologyText keeps rendering dependency-free and makes every next hop
// inspectable. A segment is an interface identity in the in-memory model.
func LabTopologyText(t Topology, tunnels []string) string {
	var b strings.Builder
	for _, n := range t.Nodes {
		fmt.Fprintf(&b, "%s (%s) resolver=%s\n", n.Name, n.Role, n.Resolver)
		for _, i := range n.Interfaces {
			label := ""
			if slices.Contains(tunnels, i.Segment) {
				label = " [tunnel]"
			}
			fmt.Fprintf(&b, "  +-- %s%s %s %s\n", i.Segment, label, i.IPv4, i.IPv6)
		}
		for _, r := range t.Routes {
			if r.Node == n.Name {
				fmt.Fprintf(&b, "      %s via %s metric %d\n", r.Destination, r.Via, r.Metric)
			}
		}
	}
	return b.String()
}
