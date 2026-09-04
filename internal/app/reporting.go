package app

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// buildReport flattens probe results into the stable JSON shape, preserving
// probe order. OK means "no check failed and every check reported"; Warn, Skip,
// and N/A don't count against it, same as everywhere else in the app.
// reportRoutes copies the run's route decisions into the JSON contract, field
// by field for the same reason the snapshot conversion is written out: the
// published shape must not follow a runtime struct by accident. Every field the
// platform did not supply stays absent rather than becoming zero.
func reportRoutes(routes []diagnostic.RouteDecision) []report.Route {
	var out []report.Route
	for _, r := range routes {
		item := report.Route{
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
			item.Competing = append(item.Competing, report.CompetingRoute{Interface: competing.Iface, Metric: competing.Metric})
		}
		out = append(out, item)
	}
	return out
}

func buildReport(t *diagnostic.Target, probes []diagnostic.Probe, results map[diagnostic.ProbeID]diagnostic.ProbeResult) report.Report {
	rep := report.Report{Version: version, Checks: []report.Check{}, OK: true}
	if t != nil {
		rep.Target = &report.Target{Host: t.Host, Port: t.Port, Protocol: t.Proto.String()}
	}
	order := make([]diagnostic.ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
		// reported, not the result itself, is the fact this loop turns on: a
		// missing entry yields the zero ProbeResult, and its Status is
		// StatusPass. The report is a published format, so the absence of an
		// observation is written as its own value instead of inheriting a Go
		// zero, exactly as BuildSnapshot does for the .ndoc artifact.
		r, reported := results[p.ID]
		status := report.StatusIncomplete
		if reported {
			status = r.Status.String()
		}
		// An unreported check is not a clean one. The run answered for one
		// fewer probe than it was asked, and ok is the field a script reads
		// first.
		rep.OK = rep.OK && reported && r.Status != diagnostic.StatusFail
		if reported && r.Status == diagnostic.StatusFail && rep.FailedStage == "" {
			rep.FailedStage = string(p.ID)
		}
		c := report.Check{
			ID:              string(p.ID),
			Name:            p.Name,
			Status:          status,
			Cause:           r.Cause,
			Ms:              diagnostic.Ms(r.Dur),
			Detail:          r.Detail,
			Fix:             r.Fix,
			ResolverTargets: append([]string(nil), r.ResolverTargets...),
			Iface:           r.Iface,
			Network:         r.Network,
		}
		if r.Families != nil {
			c.Families = &report.Families{IPv4: r.Families.IPv4, IPv6: r.Families.IPv6}
		}
		if r.Portal != nil {
			c.Portal = &report.Portal{RedirectURL: r.Portal.RedirectURL}
		}
		for _, ip := range r.Addrs {
			c.Addrs = append(c.Addrs, ip.String())
		}
		if r.SelectedIP != nil {
			c.SelectedIP = r.SelectedIP.String()
		}
		if r.Source != nil {
			c.Source = r.Source.String()
		}
		for _, a := range r.Attempts {
			ra := report.Attempt{IP: a.IP.String(), Ms: diagnostic.Ms(a.Dur), Cause: a.Cause, Aborted: a.Aborted}
			if a.Err != nil {
				ra.Err = a.Err.Error()
			}
			c.Attempts = append(c.Attempts, ra)
		}
		c.Routes = reportRoutes(r.Routes)
		rep.Checks = append(rep.Checks, c)
	}
	// One interpretation, read for every diagnostic field the report carries,
	// so the summary, the verdict and the findings cannot describe different
	// runs.
	d := diagnostic.Interpret(t, order, results)
	rep.Summary, rep.Verdict = d.Summary, d.Verdict
	for i, f := range d.Findings {
		finding := report.Finding{ID: string(f.ID), Focus: string(f.Focus), Confidence: string(f.Confidence)}
		for _, id := range f.EvidenceRows() {
			finding.Evidence = append(finding.Evidence, string(id))
		}
		for _, e := range f.Evidence {
			finding.CausalEvidence = append(finding.CausalEvidence, report.CausalEvidence{
				Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
				Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
			})
		}
		if f.Counterfactual != nil {
			cf := &report.Counterfactual{Variable: string(f.Counterfactual.Variable)}
			for _, alternative := range f.Counterfactual.Alternatives {
				item := report.CounterfactualAlternative{Value: alternative.Value, Outcome: string(alternative.Outcome)}
				for _, e := range alternative.Evidence {
					item.Evidence = append(item.Evidence, report.CausalEvidence{
						Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
						Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
					})
				}
				cf.Alternatives = append(cf.Alternatives, item)
			}
			finding.Counterfactual = cf
		}
		// The advice comes from the same interpretation as the finding it hangs
		// off, so automation reads what the app shows rather than a second
		// opinion assembled here. Remediate answers for the primary finding,
		// the one the summary is about, exactly as Focus does.
		if i == 0 {
			if rem, ok := diagnostic.Remediate(d, results, runtime.GOOS); ok {
				finding.Remediation = &report.Remediation{
					ID: string(rem.ID), Action: rem.Action, Why: rem.Why,
					Steps: rem.Steps, Command: rem.Command, Expect: rem.Expect,
				}
			}
		}
		rep.Findings = append(rep.Findings, finding)
	}
	return rep
}

// reportText renders a finished report for a person: the verdict, what to do
// about it, then every check row with its detail and its fix. It is the shape
// the terminal UI's shareable report already uses, so a --via run and a copied
// TUI report read the same way.
//
// It lives here rather than in internal/report because that package is the
// schema and nothing else, and because this is the layer that knows the output
// is going to a terminal: every string below arrived from a probe and can quote
// a hostname, a TLS subject, or a captive portal's redirect, so every string is
// cleaned before it is printed.
//
// Nothing is interpreted on the way through. Each line is a field of the
// report, decided by whichever netdoc ran the probes.
func reportText(r report.Report) string {
	clean := textsafe.Clean
	var b strings.Builder
	if v := clean(r.Version); v != "" {
		fmt.Fprintf(&b, "version: %s\n", v)
	}
	if r.Target != nil {
		fmt.Fprintf(&b, "target: %s:%d (%s)\n", clean(r.Target.Host), r.Target.Port, clean(r.Target.Protocol))
	} else {
		b.WriteString("target: none (general connection check)\n")
	}
	fmt.Fprintf(&b, "verdict: %s: %s\n", verdictWord(r.Verdict), clean(r.Summary))
	// The advice the report already carries, never a second opinion assembled
	// here: it was chosen on the machine that ran the probes, by that machine's
	// operating system, and it is a suggestion to read rather than to run.
	if rem := primaryRemediation(r); rem != nil {
		fmt.Fprintf(&b, "next action: %s\n", clean(rem.Action))
		if rem.Why != "" {
			b.WriteString("  why: " + clean(rem.Why) + "\n")
		}
		for _, step := range rem.Steps {
			b.WriteString("  step: " + clean(step) + "\n")
		}
		if len(rem.Command) > 0 {
			b.WriteString("  run (suggested, not executed): " + clean(strings.Join(rem.Command, " ")) + "\n")
		}
		if rem.Expect != "" {
			b.WriteString("  expect: " + clean(rem.Expect) + "\n")
		}
	}
	b.WriteString("\nchecks:\n")
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", clean(c.Status), clean(c.Name), clean(c.Detail))
		if c.Fix != "" && (c.Status == diagnostic.StatusFail.String() || c.Status == diagnostic.StatusWarn.String()) {
			b.WriteString("        fix: " + clean(c.Fix) + "\n")
		}
		if c.Portal != nil && c.Portal.RedirectURL != "" {
			b.WriteString("        portal: " + clean(c.Portal.RedirectURL) + "\n")
		}
	}
	return b.String()
}

// verdictWord turns the machine-readable verdict into the word the status
// column already uses, so a reader is not asked to learn a second vocabulary
// for the same outcomes. A verdict this build cannot name reads as FAIL rather
// than as nothing: an unrecognized verdict is not one to present as healthy.
func verdictWord(verdict string) string {
	switch verdict {
	case diagnostic.VerdictOK:
		return diagnostic.StatusPass.String()
	case diagnostic.VerdictDegraded:
		return diagnostic.StatusWarn.String()
	}
	return diagnostic.StatusFail.String()
}

// primaryRemediation is the advice for the finding the summary is about, which
// is the only finding that carries any: the report fills it in for the primary
// finding alone.
func primaryRemediation(r report.Report) *report.Remediation {
	for _, f := range r.Findings {
		if f.Remediation != nil {
			return f.Remediation
		}
	}
	return nil
}
