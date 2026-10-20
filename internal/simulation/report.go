package simulation

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// Overall results.
const (
	ResultPass    = "PASS"    // every expectation held
	ResultPartial = "PARTIAL" // some expectations held
	ResultFail    = "FAIL"    // none did
	ResultError   = "ERROR"   // the simulation itself did not run
)

// Report is one simulation, start to finish. It is the machine-readable
// artifact: `netdoc-sim run --json` prints exactly this.
type Report struct {
	Scenario    string        `json:"scenario"`
	Description string        `json:"description,omitempty"`
	ID          string        `json:"id"`
	Backend     string        `json:"backend"`
	StartedAt   time.Time     `json:"started_at"`
	Duration    time.Duration `json:"duration_ms"`
	Result      string        `json:"result"`
	// Error is set when setup, not diagnosis, is what failed.
	Error string `json:"error,omitempty"`

	Topology []NodeInfo  `json:"topology"`
	Faults   []FaultInfo `json:"faults"`
	// Timeline is what the fault scheduler did, relative to T0, the instant
	// just before the first netdoc process started. TimelineID identifies the
	// requested timeline and ignores how long the OS took to apply it.
	Timeline    []FaultEventEvidence `json:"fault_timeline"`
	TimelineID  string               `json:"fault_timeline_id,omitempty"`
	Tests       []TestOutcome        `json:"tests"`
	Evidence    Evidence             `json:"evidence"`
	Cleanup     CleanupInfo          `json:"cleanup"`
	Suggestions []Suggestion         `json:"suggestions"`
}

// NodeInfo is a namespace the simulation created.
type NodeInfo struct {
	Name       string          `json:"name"`
	Role       string          `json:"role"`
	Address    string          `json:"address"`
	Aliases    []string        `json:"aliases,omitempty"`
	Interface  string          `json:"interface"`
	Gateway    string          `json:"gateway,omitempty"`
	Resolver   string          `json:"resolver,omitempty"`
	Services   []string        `json:"services,omitempty"`
	PID        int             `json:"pid"`
	Interfaces []InterfaceInfo `json:"interfaces,omitempty"`
	Routes     []RouteInfo     `json:"routes,omitempty"`
}

// InterfaceInfo and RouteInfo expose logical topology names rather than the
// generated Linux names used to implement them.
type InterfaceInfo struct {
	Segment string `json:"segment"`
	Address string `json:"address"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}

type RouteInfo struct {
	Destination string `json:"destination"`
	Via         string `json:"via"`
	Segment     string `json:"segment"`
	Metric      int    `json:"metric"`
	Family      string `json:"family,omitempty"`
}

// FaultInfo is one injected impairment and the exact command that injected it.
type FaultInfo struct {
	Type        string        `json:"type"`
	Node        string        `json:"node"`
	Family      string        `json:"family,omitempty"`
	Protocol    string        `json:"protocol,omitempty"`
	Port        int           `json:"port,omitempty"`
	Direction   string        `json:"direction,omitempty"`
	Summary     string        `json:"summary"`
	Command     []string      `json:"command"`
	Latency     time.Duration `json:"latency_ms,omitempty"`
	Jitter      time.Duration `json:"jitter_ms,omitempty"`
	LossPercent float64       `json:"loss_percent,omitempty"`
	Seed        uint32        `json:"seed,omitempty"`
}

// CleanupInfo records that the resources went away, and never hides a failure
// to make them go away.
type CleanupInfo struct {
	Done bool `json:"done"`
	Kept bool `json:"kept"`
	// Workspace is the scratch directory the run used, set while it still
	// exists so a kept simulation can be found and swept later.
	Workspace string   `json:"workspace,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	Errors    []string `json:"errors,omitempty"`
}

// finish computes the overall result and collects suggestions. Call once, after
// every test has run.
func (r *Report) finish() {
	for i := range r.Tests {
		r.Suggestions = append(r.Suggestions, r.Tests[i].suggest()...)
	}
	r.Suggestions = append(r.Suggestions, r.routeSuggestions()...)
	r.Suggestions = append(r.Suggestions, r.faultSuggestions()...)
	r.Suggestions = append(r.Suggestions, r.timelineSuggestions()...)
	// Empty lists, not null: a consumer iterating report.faults on a healthy
	// scenario should get nothing to do, not a type error.
	if r.Suggestions == nil {
		r.Suggestions = []Suggestion{}
	}
	if r.Timeline == nil {
		r.Timeline = []FaultEventEvidence{}
	}
	if r.Faults == nil {
		r.Faults = []FaultInfo{}
	}
	if r.Topology == nil {
		r.Topology = []NodeInfo{}
	}
	if r.Tests == nil {
		r.Tests = []TestOutcome{}
	}
	if r.Evidence.DNS == nil {
		r.Evidence.DNS = []DNSEvidence{}
	}
	if r.Evidence.DNSQueries == nil {
		r.Evidence.DNSQueries = []DNSQueryEvidence{}
	}
	if r.Evidence.SOCKSRequests == nil {
		r.Evidence.SOCKSRequests = []SOCKSEvidence{}
	}
	if r.Evidence.TLS == nil {
		r.Evidence.TLS = []TLSEvidence{}
	}
	if r.Evidence.ServiceStates == nil {
		r.Evidence.ServiceStates = []ServiceStateEvidence{}
	}
	if r.Evidence.ServiceReplies == nil {
		r.Evidence.ServiceReplies = []ServiceReplyEvidence{}
	}
	if r.Evidence.TCPResets == nil {
		r.Evidence.TCPResets = []TCPResetEvidence{}
	}
	if r.Evidence.PacketConditions == nil {
		r.Evidence.PacketConditions = []PacketConditionEvidence{}
	}
	if r.Evidence.PacketDrops == nil {
		r.Evidence.PacketDrops = []PacketDropEvidence{}
	}
	if r.Evidence.Links == nil {
		r.Evidence.Links = []LinkEvidence{}
	}
	if r.Evidence.Routes == nil {
		r.Evidence.Routes = []RouteEvidence{}
	}
	if r.Evidence.RouteTables == nil {
		r.Evidence.RouteTables = []RouteTableEvidence{}
	}
	if r.Evidence.Routers == nil {
		r.Evidence.Routers = []RouterEvidence{}
	}
	if r.Evidence.ControlledTargets == nil {
		r.Evidence.ControlledTargets = []ControlledTargetEvidence{}
	}
	if r.Evidence.FamilyReachability == nil {
		r.Evidence.FamilyReachability = []FamilyReachabilityEvidence{}
	}
	if r.Error != "" || len(r.Cleanup.Errors) > 0 {
		r.Result = ResultError
		return
	}
	pass, total := 0, len(r.Tests)
	for i := range r.Tests {
		if r.Tests[i].ok() {
			pass++
		}
	}
	switch {
	case total == 0:
		r.Result = ResultError
	case pass == total:
		r.Result = ResultPass
	case pass == 0:
		r.Result = ResultFail
	default:
		r.Result = ResultPartial
	}
}

func (r *Report) faultSuggestions() []Suggestion {
	for _, fault := range r.Faults {
		if fault.Type == FaultNetem && fault.Jitter > 0 {
			for _, condition := range r.Evidence.PacketConditions {
				if condition.Node == fault.Node && condition.RTTSamples > 0 {
					return []Suggestion{{Code: "jitter_sampling_gap",
						Message: "The simulator injected jitter, but each netdoc probe reports one connection sample and cannot evaluate variance across time.",
						Evidence: fmt.Sprintf("injected jitter %s; observed successful connection range %s..%s across %d sample(s)",
							fault.Jitter, condition.ObservedMinRTT, condition.ObservedMaxRTT, condition.RTTSamples)}}
				}
			}
		}
	}
	return nil
}

func (r *Report) routeSuggestions() []Suggestion {
	for _, route := range r.Evidence.Routes {
		if route.Selected && route.GatewayReachable != nil && !*route.GatewayReachable {
			return []Suggestion{{Code: "gateway_unreachable", Message: "A default path was selected but its next-hop neighbor was unreachable; expose this distinction from an absent route in the diagnostic result.",
				Evidence: fmt.Sprintf("%s selected %s via %s on %s; neighbor state failed", route.Node, route.Destination, route.Via, route.Segment)}}
		}
	}
	if len(r.Tests) < 2 || r.Tests[0].Diagnosis == nil || r.Tests[1].Diagnosis == nil {
		return nil
	}
	// The second test says something about routing only when it takes a path the
	// first one did not: another interface, or a target that a specific route
	// covers. A scenario author writes that control deliberately; the hunt
	// generator repeats the first test verbatim to watch a timeline, and the same
	// probe over the same path reaching the target is not an alternate route; it
	// only repeats what the first diagnosis already reported.
	control := r.Tests[1]
	if control.SourceSegment == "" && control.Target == r.Tests[0].Target {
		return nil
	}
	firstInternet := diagnosisStatus(r.Tests[0].Diagnosis, "internet_tcp")
	if firstInternet != "FAIL" && firstInternet != "WARN" {
		return nil
	}
	if diagnosisStatus(control.Diagnosis, "target_tcp") != "PASS" {
		return nil
	}
	// A warning on the egress row is not a routing fact. High latency, a first
	// SYN paid for behind cold neighbour discovery, or one address of several
	// failing all raise it while the path is perfectly fine, and on a two-test
	// scenario the control keeps passing either way. Without this the
	// suggestion fires for whatever the run actually broke, routing or not. The
	// client's own dial of the controlled endpoints is the independent evidence
	// that the selected path really is down.
	if !familyUnreachableAt(r, r.Tests[0].Node) {
		return nil
	}
	// A diagnosis that named a route cause has already told the user which
	// route failed and what to do about it. What is left is a wish about how
	// much route detail to print alongside it, which is not a gap in what the
	// diagnosis communicated, and reporting it as one buries the cases where
	// netdoc really did stay silent.
	if routeCauseNamed(r.Tests[0].Diagnosis) {
		return nil
	}
	selectedSegment := ""
	for _, route := range r.Evidence.Routes {
		if route.Node == r.Tests[0].Node && route.Selected && isInternetEndpoint("ipv4", route.Destination) {
			selectedSegment = route.Segment
			break
		}
	}
	code := "wrong_default_route_evidence"
	message := "The selected default path failed while a controlled specific path reached the target; consider exposing selected-route evidence in the diagnostic result."
	// Named rather than interpolated raw: a control that binds no interface of its
	// own leaves an empty segment, and an empty segment in a sentence about
	// segments reads as text that went missing.
	reached := "a specific route"
	if control.SourceSegment != "" && control.SourceSegment != selectedSegment {
		code = "alternate_route_available"
		message = "The preferred path failed while a controlled test through another live interface reached the target; consider reporting the alternate working path and route metrics."
		reached = "segment " + control.SourceSegment
	}
	selected := "the selected default path"
	if selectedSegment != "" {
		selected = "selected segment " + selectedSegment
	}
	return []Suggestion{{Code: code, Message: message,
		Evidence: fmt.Sprintf("%s failed; %s reached %s", selected, reached, control.Target)}}
}

// familyUnreachableAt reports whether the simulator's own dial from this node
// found an address family with nothing answering. Holder-side, so no part of it
// can be satisfied by something netdoc said.
func familyUnreachableAt(r *Report, node string) bool {
	return slices.ContainsFunc(r.Evidence.FamilyReachability, func(item FamilyReachabilityEvidence) bool {
		return item.Node == node && item.State == FamilyStateUnreachable
	})
}

// routeCauseNamed reports whether the diagnosis pointed at a route on any row.
// Which route cause it chose is a separate question, graded elsewhere; this
// only asks whether the user was sent to look at their routing table at all.
func routeCauseNamed(d *Diagnosis) bool {
	for _, check := range d.Checks {
		switch check.Cause {
		case diagnostic.RouteCauseNoDefaultRoute, diagnostic.RouteCauseGatewayUnreachable,
			diagnostic.RouteCauseSelectedPathFailed, diagnostic.RouteCausePreferredPathFailed:
			return true
		}
	}
	return false
}

func offsetLabel(d time.Duration) string {
	return "+" + strconv.FormatInt(d.Milliseconds(), 10) + "ms"
}

func diagnosisStatus(d *Diagnosis, id string) string {
	for _, check := range d.Checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

// writeJSON prints one indented machine-readable artifact. Every WriteJSON in
// this package is this call.
func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// WriteJSON prints the machine-readable report.
func (r *Report) WriteJSON(w io.Writer) error { return writeJSON(w, r) }

// WriteText prints the human-readable report. Every string that came from a
// subprocess goes through textsafe first: netdoc's detail lines carry remote
// text, and this one lands on a terminal.
func (r *Report) WriteText(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("Scenario: %s", textsafe.Clean(r.Scenario))
	if r.Description != "" {
		p("          %s", textsafe.Clean(r.Description))
	}
	p("Result:   %s   (%s backend, %s, id %s)", r.Result, r.Backend, r.Duration.Round(time.Millisecond), r.ID)
	if r.Error != "" {
		p("Error:    %s", textsafe.Clean(r.Error))
	}
	p("")

	p("Topology")
	for _, n := range r.Topology {
		extra := []string{n.Role}
		if n.Gateway != "" {
			extra = append(extra, "gw "+n.Gateway)
		}
		if n.Resolver != "" {
			extra = append(extra, "dns "+n.Resolver)
		}
		if len(n.Aliases) > 0 {
			extra = append(extra, "also "+strings.Join(n.Aliases, ","))
		}
		if len(n.Services) > 0 {
			extra = append(extra, "serves "+strings.Join(n.Services, ","))
		}
		p("  %-10s %-14s %s", n.Name, n.Address, strings.Join(extra, ", "))
		for _, iface := range n.Interfaces {
			addresses := iface.Address
			if iface.IPv4 != "" || iface.IPv6 != "" {
				addresses = strings.TrimSpace(strings.Join([]string{iface.IPv4, iface.IPv6}, " "))
			}
			p("      link %-16s %s", iface.Segment, addresses)
		}
		for _, route := range n.Routes {
			p("      route %-15s via %-15s on %s metric %d", route.Destination, route.Via, route.Segment, route.Metric)
		}
	}
	p("")

	p("Faults injected")
	if len(r.Faults) == 0 {
		p("  (none: healthy network)")
	}
	for _, f := range r.Faults {
		p("  %-18s %-4s %s", f.Type, f.Family, f.Summary)
	}
	p("")

	if len(r.Timeline) > 0 {
		p("Fault timeline   (offsets from T0, just before the first netdoc run)")
		for _, e := range r.Timeline {
			switch e.Result {
			case EventApplied:
				p("  %-9s %-52s applied at +%-8s %s", offsetLabel(e.ScheduledOffset), textsafe.Clean(e.State),
					e.AppliedOffset.Round(time.Millisecond), textsafe.Clean(e.Observed))
			case EventSkipped:
				p("  %-9s %-52s skipped, the run ended first", offsetLabel(e.ScheduledOffset), textsafe.Clean(e.State))
			default:
				p("  %-9s %-52s FAILED: %s", offsetLabel(e.ScheduledOffset), textsafe.Clean(e.State), textsafe.Clean(e.Error))
			}
		}
		for _, t := range r.Tests {
			p("  netdoc %q ran +%s..+%s", textsafe.Clean(t.Name),
				t.StartOffset.Round(time.Millisecond), t.EndOffset.Round(time.Millisecond))
		}
		p("")
	}

	for i := range r.Tests {
		r.Tests[i].writeText(w)
	}

	if len(r.Evidence.DNS) > 0 || len(r.Evidence.DNSQueries) > 0 || len(r.Evidence.SOCKSRequests) > 0 || len(r.Evidence.TLS) > 0 || len(r.Evidence.TCPResets) > 0 || len(r.Evidence.PacketConditions) > 0 ||
		len(r.Evidence.Links) > 0 || len(r.Evidence.Routes) > 0 || len(r.Evidence.Routers) > 0 || len(r.Evidence.ControlledTargets) > 0 ||
		len(r.Evidence.FamilyReachability) > 0 || len(r.Evidence.ServiceReplies) > 0 || len(r.Evidence.PacketDrops) > 0 ||
		len(r.Evidence.RouteTables) > 0 {
		p("Structured evidence")
		for _, e := range r.Evidence.Links {
			p("  LINK  %-10s %-16s %-18s up=%t", e.Node, e.Segment, e.Address, e.Up)
		}
		for _, e := range r.Evidence.Routers {
			p("  ROUTER %-10s IPv4 forwarding=%t IPv6 forwarding=%t", e.Node, e.IPv4Forwarding, e.IPv6Forwarding)
		}
		for _, e := range r.Evidence.PacketConditions {
			p("  NETEM %-10s %-16s delay=%s jitter=%s loss=%.2f%% seed=%d active=%t dropped=%d RTT=%s..%s (%d samples)", e.Node, e.Segment,
				e.Latency, e.Jitter, e.LossPercent, e.Seed, e.Active, e.DroppedPackets, e.ObservedMinRTT, e.ObservedMaxRTT, e.RTTSamples)
		}
		for _, e := range r.Evidence.Routes {
			selected := "configured"
			if e.Selected {
				selected = "selected"
			}
			gateway := "unknown"
			if e.GatewayReachable != nil {
				gateway = fmt.Sprint(*e.GatewayReachable)
			}
			p("  ROUTE %-10s %-15s via %-15s %-16s metric=%d %s %s gateway=%s", e.Node, e.Destination,
				e.Via, e.Segment, e.Metric, e.Family, selected, gateway)
		}
		for _, e := range r.Evidence.RouteTables {
			if len(e.Routes) == 0 {
				p("  TABLE %-10s %-4s (empty)", e.Node, e.Family)
				continue
			}
			for _, route := range e.Routes {
				p("  TABLE %-10s %-4s %-15s via %-15s %-16s metric=%d", e.Node, e.Family,
					route.Destination, route.Via, route.Segment, route.Metric)
			}
		}
		for _, e := range r.Evidence.ControlledTargets {
			p("  PATH  %-10s -> %-24s via %-32s %s", e.From, e.To, strings.Join(e.Via, " -> "), e.Outcome)
		}
		for _, e := range r.Evidence.FamilyReachability {
			p("  FAMILY %-10s %-4s %-12s via %s", e.Node, e.Family, e.State, strings.Join(e.Via, " -> "))
		}
		for _, e := range r.Evidence.DNS {
			p("  DNS   %-10s from %-13s %-6s %-28s %-8s %s ×%d", e.Node, e.Source, e.QueryType, e.Name, e.Result, e.Service, e.Count)
		}
		for _, e := range r.Evidence.SOCKSRequests {
			destination := e.Destination
			if e.Port != 0 {
				destination = net.JoinHostPort(destination, fmt.Sprint(e.Port))
			}
			p("  SOCKS %-10s %-8s %-7s %-28s %-22s ×%d", e.Node, e.Event, e.AddressType,
				textsafe.Clean(destination), e.Result, e.Count)
		}
		for _, e := range r.Evidence.TLS {
			presented := "not-presented"
			if e.CertificatePresented {
				presented = "presented"
			}
			p("  TLS   %-10s %-20s SNI %-24s %-13s %-27s %s ×%d", e.Node, e.CertificateMode,
				textsafe.Clean(e.RequestedServer), presented, strings.Join(e.CertificateDNS, ","), e.Result, e.Count)
		}
		for _, e := range r.Evidence.DNSQueries {
			p("  DNSQ  %-10s %-6s #%03d %-28s scheduled=%-8s actual=%s", e.Node, e.QueryType,
				e.Sequence, e.Name, e.ScheduledOutcome, e.ActualOutcome)
		}
		for _, e := range r.Evidence.TCPResets {
			p("  RESET %-10s %-10s %-24s ×%d", e.Node, e.Event, e.Result, e.Count)
		}
		for _, e := range r.Evidence.ServiceReplies {
			p("  REPLY %-10s %-14s %-16s port=%-5d status=%-3d %-10s ×%d", e.Node, e.Type,
				textsafe.Clean(e.Service), e.Port, e.Status, e.Result, e.Count)
		}
		for _, e := range r.Evidence.PacketDrops {
			p("  DROP  %-10s %-8s %-4s %-5s port=%-5d to=%-16s packets=%d", e.Node, e.Direction,
				e.Family, e.Protocol, e.Port, e.To, e.Packets)
		}
		p("")
	}

	if len(r.Suggestions) > 0 {
		p("Suggested improvements")
		for _, s := range r.Suggestions {
			p("  [%s] %s", s.Code, textsafe.Clean(s.Message))
			if s.Cause != "" {
				p("      cause: %s", textsafe.Clean(s.Cause))
			}
			if s.Evidence != "" {
				p("      evidence: %s", textsafe.Clean(s.Evidence))
			}
		}
		p("")
	}

	switch {
	case r.Cleanup.Kept:
		p("Cleanup:  kept (%s)", textsafe.Clean(r.Cleanup.Detail))
	case len(r.Cleanup.Errors) > 0:
		p("Cleanup:  INCOMPLETE")
		for _, e := range r.Cleanup.Errors {
			p("  %s", textsafe.Clean(e))
		}
	case r.Cleanup.Done:
		p("Cleanup:  ok, every namespace and process released")
	default:
		p("Cleanup:  not reached")
	}
}

func (o *TestOutcome) writeText(w io.Writer) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	target := o.Target
	if target == "" {
		target = "(generic checks)"
	}
	p("Test: %s, netdoc %s in %s (%s)", textsafe.Clean(o.Name), textsafe.Clean(target), o.Node, o.Duration.Round(time.Millisecond))
	if o.Error != "" {
		p("  ERROR: %s", textsafe.Clean(o.Error))
		if o.Stderr != "" {
			p("  stderr: %s", textsafe.Clean(o.Stderr))
		}
		p("")
		return
	}
	if o.summaryMatches() {
		p("  Summary: %s", textsafe.Clean(o.Diagnosis.Summary))
	} else {
		p("  Summary: MISMATCH")
		p("    expected: %q", textsafe.Clean(o.ExpectedSummary))
		p("    actual:   %q", textsafe.Clean(o.Diagnosis.Summary))
	}
	verdict := o.ActualVerdict
	if !o.verdictMatches() {
		verdict += fmt.Sprintf("   ✗ expected %s", o.ExpectedVerdict)
	} else if o.ExpectedVerdict != "" {
		verdict += "   ✓"
	}
	p("  Verdict: %s", verdict)
	p("  Expected findings: %d   matched: %d   false negatives: %d   false positives: %d",
		len(o.Checks)-o.countUnexpected(), o.Matched, o.FalseNegatives, o.FalsePositives)
	for _, c := range o.Checks {
		mark, note := "✓", ""
		switch c.Outcome {
		case OutcomeMatched:
		case OutcomeMissing:
			mark, note = "✗", "no such row in the report"
		case OutcomeWrongStatus:
			mark, note = "✗", "expected "+c.Expected
		case OutcomeWrongCause:
			mark, note = "✗", "expected cause "+c.ExpectedCause
		case OutcomeWrongFix:
			mark, note = "✗", fmt.Sprintf("expected fix %q, actual %q",
				textsafe.Clean(c.ExpectedFix), textsafe.Clean(c.Fix))
		case OutcomeUnexpected:
			mark, note = "!", "not expected by the scenario"
		}
		line := fmt.Sprintf("  %s %-14s %-5s %s", mark, c.ID, c.Actual, textsafe.Clean(c.Detail))
		if note != "" {
			line += "   (" + note + ")"
		}
		if c.Cause != "" {
			line += "   [cause: " + textsafe.Clean(c.Cause) + "]"
		}
		p("%s", line)
	}
	if len(o.TimedOut) > 0 {
		p("  Timed out: %s", strings.Join(o.TimedOut, ", "))
	}
	if len(o.RepeatVerdicts) > 1 {
		verdicts := uniqueSorted(o.RepeatVerdicts)
		stability := "stable across " + fmt.Sprint(len(o.RepeatVerdicts)) + " runs"
		if len(verdicts) > 1 {
			stability = "UNSTABLE across " + fmt.Sprint(len(o.RepeatVerdicts)) + " runs: " + strings.Join(verdicts, ", ")
		}
		p("  Repeats: %s", stability)
	}
	p("")
}

func (o *TestOutcome) countUnexpected() int {
	n := 0
	for _, c := range o.Checks {
		if c.Outcome == OutcomeUnexpected {
			n++
		}
	}
	return n
}
