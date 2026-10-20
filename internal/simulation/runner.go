package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/report"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// Options tune one simulation run.
type Options struct {
	// Netdoc is the netdoc binary the tests execute. Required.
	Netdoc string
	// ProbeTimeout is passed to netdoc as -timeout, and is what the report uses
	// to tell a probe that answered from one that ran out of time.
	ProbeTimeout time.Duration
	// Repeat runs each test this many times to catch a diagnosis that is not
	// reproducible. Values below 1 mean once.
	Repeat int
	// Keep leaves the environment running after the report is written.
	Keep bool
	// Hold, when set, is called once the topology is built, every fault is
	// applied and the timeline's opening state has landed, and before the first
	// netdoc process starts. Challenge Mode uses it to hand the finished network
	// to a person, so both they and netdoc face the same state. A non-nil error
	// abandons the run before any test, and cleanup still happens.
	Hold func(context.Context, Env) error
	// SetupTimeout, TestTimeout and CleanupTimeout bound the three phases. Each
	// falls back to a sane default when zero.
	SetupTimeout   time.Duration
	TestTimeout    time.Duration
	CleanupTimeout time.Duration
	// Log receives a line per privileged command as it runs. Nil is quiet.
	Log io.Writer
}

func (o Options) withDefaults() Options {
	if o.ProbeTimeout <= 0 {
		o.ProbeTimeout = diagnostic.DefaultProbeTimeout
	}
	if o.Repeat < 1 {
		o.Repeat = 1
	}
	if o.SetupTimeout <= 0 {
		o.SetupTimeout = 30 * time.Second
	}
	if o.TestTimeout <= 0 {
		// Every probe in the DAG could serially spend its budget; give the run
		// enough room that a slow scenario fails on its merits, not the clock.
		o.TestTimeout = 15*time.Second + 8*o.ProbeTimeout
	}
	if o.CleanupTimeout <= 0 {
		o.CleanupTimeout = 15 * time.Second
	}
	return o
}

// Run executes one scenario end to end and always returns a report: setup
// failures, cancellation and panics are reported, not returned as bare errors,
// because a simulation that fell over is itself a result worth printing.
//
// Cleanup runs on every exit path. It gets a context detached from the caller's
// so a cancelled or timed-out run still releases its namespaces.
func Run(ctx context.Context, s *Scenario, b Backend, opts Options) (rep *Report) {
	opts = opts.withDefaults()
	rep = &Report{
		Scenario: s.Name, Description: s.Description, ID: NewID(),
		StartedAt: time.Now(),
	}
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			rep.Error = fmt.Sprintf("simulator panic: %v", r)
		}
		rep.Duration = time.Since(start)
		rep.finish()
	}()

	caps := b.Capabilities(ctx)
	rep.Backend = caps.Backend
	if !caps.Supported {
		rep.Error = caps.Reason
		return rep
	}

	setupCtx, cancel := context.WithTimeout(ctx, opts.SetupTimeout)
	env, err := b.Prepare(setupCtx, s, rep.ID)
	cancel()
	// Prepare may return both: a partially built environment still owns
	// namespaces and processes that have to go.
	if env != nil {
		// Registered after the recover defer, so it runs before it: a panic in
		// the test loop tears the environment down first and is reported second.
		// The context is detached from the caller's so a cancelled or timed-out
		// run still releases its namespaces, under a deadline of its own.
		defer func() {
			// A backend that panics while cleaning up must not take the report
			// with it, or the user loses both the diagnosis and any idea what
			// was left behind.
			defer func() {
				if r := recover(); r != nil {
					rep.Cleanup.Errors = append(rep.Cleanup.Errors,
						fmt.Sprintf("cleanup panicked: %v", r))
					rep.Cleanup.Done = false
				}
			}()
			cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), opts.CleanupTimeout)
			defer ccancel()
			rep.Cleanup = env.Cleanup(cctx, opts.Keep)
		}()
		rep.Topology = env.Nodes()
	}
	if err != nil {
		rep.Error = "setup failed: " + textsafe.Clean(err.Error())
		return rep
	}

	faultCtx, cancel := context.WithTimeout(ctx, opts.SetupTimeout)
	rep.Faults, err = env.ApplyFaults(faultCtx, s.Faults)
	cancel()
	if err != nil {
		rep.Error = "fault injection failed: " + textsafe.Clean(err.Error())
		return rep
	}

	// T0. Every scheduled offset is measured from this instant, the moment
	// just before the first netdoc process starts. The timeline was resolved
	// during validation and does not change from here on.
	timeline := timelineFrom(s.Faults)
	t0 := time.Now()
	scheduleCtx, endSchedule := context.WithCancel(ctx)
	sched := startScheduler(scheduleCtx, env, timeline, t0)
	// This defer is registered after environment cleanup, so it always runs
	// first. In particular, a panic in a probe must not take the normal-path
	// cancellation and join with it and leave a scheduler touching teardown.
	stopSchedule := func() {
		if sched == nil {
			return
		}
		endSchedule()
		rep.Timeline = sched.wait()
		rep.TimelineID = timelineFingerprint(timeline)
		sched = nil
	}
	defer stopSchedule()

	// The hold sits here rather than before the scheduler so its holder sees the
	// network the tests will see, including any offset-zero scheduled state.
	if opts.Hold != nil {
		if err := opts.Hold(ctx, env); err != nil {
			rep.Error = "run was abandoned before its tests: " + textsafe.Clean(err.Error())
			return rep
		}
	}
	for _, t := range s.Tests {
		rep.Tests = append(rep.Tests, runTest(ctx, env, t, s.Expect, opts, t0))
	}
	// Stop the scheduler and join it before anything else touches the
	// environment: no scheduled event may reach a namespace that evidence
	// collection or cleanup is already working on.
	stopSchedule()

	evidenceCtx, evidenceCancel := context.WithTimeout(ctx, opts.SetupTimeout)
	rep.Evidence, err = env.Evidence(evidenceCtx)
	evidenceCancel()
	if err != nil {
		rep.Error = "collecting evidence failed: " + textsafe.Clean(err.Error())
	} else {
		rep.addPacketObservations()
		rep.placeEvidenceOnTimeline(t0)
	}
	return rep
}

// placeEvidenceOnTimeline converts the wall clock the node holders recorded
// into offsets from this run's epoch. Holders and director share one machine's
// clock; nothing is ordered by it, it only locates an observation.
func (r *Report) placeEvidenceOnTimeline(t0 time.Time) {
	for i := range r.Evidence.DNSQueries {
		// An observation that reached the director without a wall clock stays
		// unplaced. Marking it is what keeps it out of the interval readers
		// instead of letting the zero offset speak for it.
		if at := r.Evidence.DNSQueries[i].at; !at.IsZero() {
			r.Evidence.DNSQueries[i].Offset = at.Sub(t0)
			r.Evidence.DNSQueries[i].OffsetKnown = true
		}
	}
}

func (r *Report) addPacketObservations() {
	if len(r.Evidence.PacketConditions) == 0 {
		return
	}
	var samples []time.Duration
	for _, test := range r.Tests {
		if test.Diagnosis == nil {
			continue
		}
		for _, check := range test.Diagnosis.Checks {
			if check.ID != string(diagnostic.ProbeInternet) {
				continue
			}
			for _, attempt := range check.Attempts {
				if attempt.Error == "" && attempt.Ms > 0 {
					samples = append(samples, time.Duration(attempt.Ms)*time.Millisecond)
				}
			}
		}
	}
	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	for i := range r.Evidence.PacketConditions {
		r.Evidence.PacketConditions[i].ObservedMinRTT = samples[0]
		r.Evidence.PacketConditions[i].ObservedMaxRTT = samples[len(samples)-1]
		r.Evidence.PacketConditions[i].RTTSamples = len(samples)
	}
}

func selectedPath(routes []RouteEvidence, node, family string) []string {
	for _, route := range routes {
		if route.Node == node && route.Selected && route.Family == family {
			via := []string{route.Segment}
			if route.Via != "" {
				via = append(via, route.Via)
			}
			return via
		}
	}
	return nil
}

// internetEndpointsForFamily derives the addresses the simulator probes from
// diagnostic's production contract. Scenarios alias them onto a
// simulator-owned node so no probe can leave the namespace.
func internetEndpointsForFamily(family string) []string {
	ipv4, ipv6 := diagnostic.InternetProbeEndpoints()
	var endpoints []net.IP
	if family == string(familyIPv4) {
		endpoints = ipv4
	} else if family == string(familyIPv6) {
		endpoints = ipv6
	} else {
		return nil
	}
	out := make([]string, len(endpoints))
	for i, endpoint := range endpoints {
		out[i] = endpoint.String()
	}
	return out
}

func allInternetEndpoints() []string {
	return append(internetEndpointsForFamily(string(familyIPv4)), internetEndpointsForFamily(string(familyIPv6))...)
}

func isInternetEndpoint(family, endpoint string) bool {
	for _, candidate := range internetEndpointsForFamily(family) {
		if candidate == endpoint {
			return true
		}
	}
	return false
}

// internetProbePort is the port both netdoc and the simulator connect to on
// those endpoints.
const internetProbePort = 443

// familyProbe is one address family the simulator tries to reach the controlled
// Internet endpoints in, on its own, from inside a node.
type familyProbe struct {
	family    string
	target    string
	endpoints []string
	// available reports whether the node carries an address in this family at
	// all. That is the one thing the topology settles on its own, because it is
	// a provisioning fact rather than a network fact.
	available bool
}

// internetFamilyProbes lists both address families with the provisioning fact
// attached. A family the node carries no address for is reported unavailable
// rather than dialed: there is nothing to test, and a topology that never had
// IPv6 is not a topology whose IPv6 went down. Whether an available family
// works is never read from here; it is settled by dialing it.
func internetFamilyProbes(n *Node) []familyProbe {
	out := []familyProbe{
		{family: "ipv4", target: "IPv4 internet endpoints", endpoints: internetEndpointsForFamily("ipv4")},
		{family: "ipv6", target: "IPv6 internet endpoints", endpoints: internetEndpointsForFamily("ipv6")},
	}
	for i := range out {
		out[i].available = n.hasFamily(out[i].family)
	}
	return out
}

// runTest runs netdoc inside a node and compares the diagnosis. Repeats reuse
// the first run for the comparison and contribute only their verdict, so a
// flaky diagnosis shows up as instability rather than as a coin flip.
func runTest(ctx context.Context, env Env, t Test, expect Expect, opts Options, t0 time.Time) (out TestOutcome) {
	if t.Expect != nil {
		expect = *t.Expect
	}
	out = TestOutcome{Name: t.Name, Node: t.Node, Target: t.Target, SourceSegment: t.SourceSegment,
		StartOffset: time.Since(t0)}
	// The window this netdoc process occupied on the fault timeline is what
	// makes "the network changed while this probe ran" answerable at all.
	defer func() { out.EndOffset = time.Since(t0) }()
	argv := []string{opts.Netdoc, "-json", "-timeout", opts.ProbeTimeout.String()}
	if t.SourceSegment != "" {
		// Use the validated canonical address rather than exposing or accepting a
		// generated kernel interface name.
		for _, node := range env.Nodes() {
			if node.Name != t.Node {
				continue
			}
			for _, iface := range node.Interfaces {
				if iface.Segment == t.SourceSegment {
					address, _, _ := strings.Cut(iface.Address, "/")
					argv = append(argv, "-iface", address)
				}
			}
		}
	}
	if t.Trust != nil {
		// Recorded before the lookup that can fail, so a test that could not be
		// given its trust anchor still says which one it wanted.
		out.Trust = t.Trust.Service
	}
	commandEnv, err := probeTrustEnv(env, t)
	if err != nil {
		out.Error = textsafe.Clean(err.Error())
		out.compare(expect, opts.ProbeTimeout)
		return out
	}
	if t.Proxy != nil {
		out.Proxy = t.Proxy.Scheme + "://" + net.JoinHostPort(t.Proxy.address, fmt.Sprint(t.Proxy.Port))
		commandEnv = append(commandEnv, t.Proxy.envName()+"="+out.Proxy)
	}
	if t.Target != "" {
		argv = append(argv, t.Target)
	}
	out.Command = argv

	for i := 0; i < opts.Repeat; i++ {
		tctx, cancel := context.WithTimeout(ctx, opts.TestTimeout)
		res := env.Exec(tctx, t.Node, argv, commandEnv)
		cancel()
		diag, err := decodeDiagnosis(res)
		if i == 0 {
			out.Duration, out.ExitCode = res.Duration, res.ExitCode
			out.Signal = res.Signal
			switch {
			case res.TimedOut:
				out.ProcessOutcome = ProcessTimedOut
			case res.Cancelled:
				out.ProcessOutcome = ProcessCancelled
			case res.Signal != "":
				out.ProcessOutcome = ProcessSignaled
			case res.Err != nil:
				out.ProcessOutcome = ProcessExecError
			default:
				out.ProcessOutcome = ProcessExited
			}
			out.Stderr = strings.TrimSpace(textsafe.Clean(string(res.Stderr)))
			out.Diagnosis = diag
			if err != nil {
				out.Error = textsafe.Clean(err.Error())
			}
		}
		if opts.Repeat > 1 {
			verdict := "<no report>"
			if diag != nil {
				verdict = diag.Verdict
			}
			out.RepeatVerdicts = append(out.RepeatVerdicts, verdict)
		}
		if err != nil {
			break
		}
	}
	out.compare(expect, opts.ProbeTimeout)
	return out
}

// probeTrustEnv is the trust configuration a process in this environment needs
// to see the simulator's own certificates. It is shared so that anything else
// the simulator puts inside a node, a challenge shell for instance, verifies
// the same fixtures the netdoc run does rather than a different set.
//
// The fixed-endpoint fixtures (QUIC, encrypted DNS) share one CA directory so
// netdoc can trust them without implicitly trusting target TLS services a
// scenario did not opt into. Either fixture names the same directory; whichever
// the scenario has is enough.
func probeTrustEnv(env Env, t Test) ([]string, error) {
	var out []string
	for _, fixture := range []string{quicProbeService, encryptedDNSProbeService} {
		if root, err := env.TrustAnchor(fixture); err == nil {
			out = append(out, "SSL_CERT_DIR="+filepath.Dir(root))
			break
		}
	}
	if t.Trust != nil {
		bundle, err := env.TrustAnchor(t.Trust.Service)
		if err != nil {
			return nil, err
		}
		out = append(out, "SSL_CERT_FILE="+bundle)
	}
	return out, nil
}

// decodeDiagnosis reads netdoc's JSON report. netdoc exits 1 when a check
// failed, which is the normal case in a scenario that broke something on
// purpose, so the exit code is recorded, never treated as an error on its own.
func decodeDiagnosis(res ExecResult) (*Diagnosis, error) {
	if res.Err != nil {
		return nil, fmt.Errorf("running netdoc: %w", res.Err)
	}
	var wire report.Report
	if err := json.Unmarshal(res.Stdout, &wire); err != nil {
		stderr := strings.TrimSpace(string(res.Stderr))
		if stderr != "" {
			return nil, fmt.Errorf("netdoc exited %d without a report: %s", res.ExitCode, stderr)
		}
		return nil, fmt.Errorf("netdoc exited %d and its output is not a report: %w", res.ExitCode, err)
	}
	if len(wire.Checks) == 0 {
		return nil, fmt.Errorf("netdoc exited %d with an empty report", res.ExitCode)
	}
	d := Diagnosis{Checks: make([]DiagnosisCheck, len(wire.Checks)), Summary: wire.Summary,
		Verdict: wire.Verdict, FailedStage: wire.FailedStage, OK: wire.OK}
	for _, finding := range wire.Findings {
		converted := DiagnosisFinding{ID: finding.ID, Focus: finding.Focus, Evidence: finding.Evidence}
		for _, evidence := range finding.CausalEvidence {
			converted.CausalEvidence = append(converted.CausalEvidence, DiagnosisCausalEvidence{
				Kind: evidence.Kind, Check: evidence.Check, Observation: evidence.Observation, Value: evidence.Value,
				Candidate: evidence.Candidate, Reason: evidence.Reason,
			})
		}
		if finding.Counterfactual != nil {
			cf := &DiagnosisCounterfactual{Variable: finding.Counterfactual.Variable}
			for _, alternative := range finding.Counterfactual.Alternatives {
				item := DiagnosisCounterfactualAlternative{Value: alternative.Value, Outcome: alternative.Outcome}
				for _, evidence := range alternative.Evidence {
					item.Evidence = append(item.Evidence, DiagnosisCausalEvidence{
						Kind: evidence.Kind, Check: evidence.Check, Observation: evidence.Observation, Value: evidence.Value,
						Candidate: evidence.Candidate, Reason: evidence.Reason,
					})
				}
				cf.Alternatives = append(cf.Alternatives, item)
			}
			converted.Counterfactual = cf
		}
		d.Findings = append(d.Findings, converted)
	}
	for i, check := range wire.Checks {
		d.Checks[i] = DiagnosisCheck{ID: check.ID, Name: check.Name, Status: check.Status, Cause: check.Cause,
			Ms: check.Ms, Detail: check.Detail, Fix: check.Fix}
		if check.Families != nil {
			d.Checks[i].Families = &DiagnosisFamilies{IPv4: check.Families.IPv4, IPv6: check.Families.IPv6}
		}
		for _, r := range check.Routes {
			d.Checks[i].Routes = append(d.Checks[i].Routes, DiagnosisRoute{
				Destination: r.Destination, Family: r.Family, Interface: r.Interface, Gateway: r.Gateway,
				Source: r.Source, Prefix: r.Prefix, Tunnel: r.Tunnel, TunnelKind: r.TunnelKind,
				Unreachable: r.Unreachable, Reason: r.Reason,
			})
		}
		if check.Attempts != nil {
			d.Checks[i].Attempts = make([]DiagnosisAttempt, len(check.Attempts))
			for j, attempt := range check.Attempts {
				d.Checks[i].Attempts[j] = DiagnosisAttempt{IP: attempt.IP, Ms: attempt.Ms, Error: attempt.Err,
					Cause: attempt.Cause, Aborted: attempt.Aborted}
			}
		}
	}
	return &d, nil
}
