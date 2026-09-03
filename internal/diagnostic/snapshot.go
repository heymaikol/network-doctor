package diagnostic

import (
	"reflect"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// BuildSnapshot converts one finished run into the portable .ndoc artifact.
//
// This is deliberate conversion code, not a serialization of ProbeResult: the
// snapshot package knows nothing about probes, and the fields below are copied
// one at a time so that renaming a runtime field is a compile error here rather
// than a silent change to a published file format. The direction matters too.
// Only this package can read its own cross-probe evidence, which is
// unexported and would otherwise be lost when the process exits: the clock
// offset that separates a wrong local clock from a real certificate problem,
// the resolver a second opinion came from, and the mark that says a failure was
// relaxed by later reasoning rather than measured that way.
//
// It fills what the run knows: target, checks, diagnosis, and the overall
// verdict. The caller owns the fields that describe the invocation rather than
// the network, and sets Tool, CreatedAt, and Options on the result, the same
// split main.go already uses for the JSON report's version and timestamp.
//
// probes is the graph as executed, after selection, and its order is the
// snapshot's order. results may be missing an entry for a probe that never
// reported, which is what an interrupted or cancelled run leaves behind. That
// row is still recorded, because a comparison has to see that the check
// existed, but it is recorded as incomplete and it takes the whole run's ok
// down with it. Absence is never written as a pass: reading a status off the
// zero ProbeResult would say PASS, so this never reads one.
func BuildSnapshot(t *Target, probes []Probe, results map[ProbeID]ProbeResult) snapshot.Snapshot {
	s := snapshot.Snapshot{Schema: snapshot.Schema, Checks: []snapshot.Check{}, OK: true}
	if t != nil {
		s.Target = &snapshot.Target{
			Raw: t.Raw, Host: t.Host, Port: t.Port,
			Protocol: t.Proto.String(), PortExplicit: t.PortExplicit,
		}
		if t.IP != nil {
			s.Target.IP = t.IP.String()
		}
	}
	order := make([]ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
		// reported, not the result itself, is the fact this loop turns on: a
		// missing entry yields the zero ProbeResult, and its Status is
		// StatusPass. Every field below that could otherwise carry a zero value
		// into the artifact as evidence is gated on it.
		r, reported := results[p.ID]
		status := snapshot.StatusIncomplete
		if reported {
			status = r.Status.String()
		}
		// An unreported check is not a clean one. The run answered the question
		// for one fewer probe than it was asked, and ok is the field a script
		// reads first.
		s.OK = s.OK && reported && r.Status != StatusFail
		if reported && r.Status == StatusFail && s.Diagnosis.FailedStage == "" {
			s.Diagnosis.FailedStage = string(p.ID)
		}
		c := snapshot.Check{
			ID:          string(p.ID),
			Name:        p.Name,
			Status:      status,
			Cause:       r.Cause,
			CauseFamily: r.causeFamily,
			// Every probe the DAG builds is wrapped in a timer that floors at
			// one nanosecond, so a nonzero duration is exactly "the probe body
			// executed". A row skipped for a failed prerequisite, and one an
			// interrupted run never reached, both report false; their statuses
			// are what tells those two apart.
			Ran:        r.Dur > 0,
			DurationMs: Ms(r.Dur),
			Detail:     r.Detail,
			Fix:        r.Fix,
		}
		for _, dep := range p.Deps {
			c.Deps = append(c.Deps, string(dep))
		}
		c.Observed = observedFrom(r)
		if derived := derivedFrom(r); derived != nil {
			c.Derived = derived
		}
		s.Checks = append(s.Checks, c)
	}
	// One interpretation, read for every diagnostic field, so the summary, the
	// verdict, and the findings in a snapshot cannot describe different runs.
	d := Interpret(t, order, results)
	s.Diagnosis.Verdict, s.Diagnosis.Summary, s.Diagnosis.Blamed = d.Verdict, d.Summary, string(d.Blamed)
	for _, f := range d.Findings {
		finding := snapshot.Finding{
			ID: string(f.ID), Verdict: f.Verdict, Summary: f.Summary, Focus: string(f.Focus),
			Confidence: string(f.Confidence),
		}
		for _, id := range f.EvidenceRows() {
			finding.Evidence = append(finding.Evidence, string(id))
		}
		for _, e := range f.Evidence {
			finding.CausalEvidence = append(finding.CausalEvidence, snapshot.CausalEvidence{
				Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
				Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
			})
		}
		if f.Counterfactual != nil {
			cf := &snapshot.Counterfactual{Variable: string(f.Counterfactual.Variable)}
			for _, alternative := range f.Counterfactual.Alternatives {
				item := snapshot.CounterfactualAlternative{Value: alternative.Value, Outcome: string(alternative.Outcome)}
				for _, e := range alternative.Evidence {
					item.Evidence = append(item.Evidence, snapshot.CausalEvidence{
						Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
						Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
					})
				}
				cf.Alternatives = append(cf.Alternatives, item)
			}
			finding.Counterfactual = cf
		}
		s.Diagnosis.Findings = append(s.Diagnosis.Findings, finding)
	}
	return s
}

// derivedFrom copies the cross-probe conclusions off one result, and returns
// nil when the reasoning pass reached none about this row. A recorded
// agreement is a conclusion like any other and is written even though it left
// the row's status alone: it was reached from the addresses the resolvers
// returned, and a sanitized artifact keeps no way to reach it again.
func derivedFrom(r ProbeResult) *snapshot.Derived {
	var comparison snapshot.AnswerComparison
	switch r.answerComparison {
	case comparisonAgree:
		comparison = snapshot.AnswerComparisonAgree
	case comparisonDisagree:
		comparison = snapshot.AnswerComparisonDisagree
	}
	if !r.downgraded && comparison == "" {
		return nil
	}
	return &snapshot.Derived{StatusDowngraded: r.downgraded, AnswerComparison: comparison}
}

// observedFrom copies the readings off one result, and returns nil when the
// probe measured nothing beyond its status. Nil rather than an empty object so
// an absent "observed" key reads as "this row saw nothing", which is exactly
// what a row that never ran did.
func observedFrom(r ProbeResult) *snapshot.Observed {
	o := snapshot.Observed{
		DNSNotFound:        r.DNSNotFound,
		Resolver:           r.resolver,
		ResolverTargets:    append([]string(nil), r.ResolverTargets...),
		Interface:          r.Iface,
		SSID:               r.Network,
		Timeout:            r.timedOut,
		InterfaceAmbiguous: r.ifaceAmbiguous,
	}
	for _, ip := range r.Addrs {
		o.Addresses = append(o.Addresses, ip.String())
	}
	if r.SelectedIP != nil {
		o.SelectedIP = r.SelectedIP.String()
	}
	if r.Source != nil {
		o.SourceIP = r.Source.String()
	}
	if r.Families != nil {
		o.Families = &snapshot.Families{IPv4: r.Families.IPv4, IPv6: r.Families.IPv6}
	}
	if r.Portal != nil {
		o.Portal = &snapshot.Portal{RedirectURL: r.Portal.RedirectURL}
	}
	for _, a := range r.Attempts {
		attempt := snapshot.Attempt{IP: a.IP.String(), DurationMs: Ms(a.Dur), Cause: a.Cause, Aborted: a.Aborted}
		if a.Err != nil {
			attempt.Error = a.Err.Error()
		}
		o.Attempts = append(o.Attempts, attempt)
	}
	o.Routes = snapshotRoutes(r.Routes)
	if r.clockOffset != 0 {
		ms := r.clockOffset.Milliseconds()
		o.ClockOffsetMs = &ms
	}
	// DeepEqual against the zero value rather than a hand-written field list:
	// a field added to Observed and forgotten here would otherwise be dropped
	// from every row whose only reading it was.
	if reflect.DeepEqual(o, snapshot.Observed{}) {
		return nil
	}
	return &o
}

// snapshotRoutes copies the run's route decisions into the artifact, one field
// at a time for the same reason every other conversion here is written out:
// renaming a runtime field must be a compile error, not a silent change to a
// published file.
//
// A field the platform never supplied stays absent. Metric is the field where
// that matters most, since 0 is a real metric, so it is written only when the
// run actually read one.
func snapshotRoutes(routes []RouteDecision) []snapshot.Route {
	var out []snapshot.Route
	for _, r := range routes {
		item := snapshot.Route{
			Destination:  r.Destination.String(),
			Family:       r.Family,
			Interface:    r.Iface,
			Table:        r.Table,
			TableKnown:   r.TableKnown,
			InterfaceMTU: r.MTU,
			Tunnel:       string(r.Tunnel),
			TunnelKind:   r.TunnelKind,
			Unreachable:  r.Unreachable,
			Reason:       string(r.Reason),
		}
		if r.Gateway != nil {
			item.Gateway = r.Gateway.String()
		}
		if r.Source != nil {
			item.Source = r.Source.String()
		}
		if r.Prefix.IsValid() {
			item.Prefix = r.Prefix.String()
		}
		if r.MetricKnown {
			metric := r.Metric
			item.Metric = &metric
		}
		for _, competing := range r.Competing {
			item.Competing = append(item.Competing, snapshot.CompetingRoute{Interface: competing.Iface, Metric: competing.Metric})
		}
		out = append(out, item)
	}
	return out
}
