package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/report"
)

// fakeBackend and fakeEnv stand in for a real backend so the lifecycle
// guarantees (cleanup after a partial setup, a cancellation, a timeout, a
// panic, and cleanup called twice) can be tested without a namespace.
type fakeBackend struct {
	caps       Capabilities
	env        *fakeEnv
	prepareErr error
	// prepareEnvOnErr models a Prepare that got far enough to create resources
	// before failing: it must hand back the half-built environment anyway.
	prepareEnvOnErr bool
}

func (b *fakeBackend) Capabilities(context.Context) Capabilities { return b.caps }

func (b *fakeBackend) Prepare(context.Context, *Scenario, string) (Env, error) {
	if b.prepareErr != nil {
		if b.prepareEnvOnErr {
			return b.env, b.prepareErr
		}
		return nil, b.prepareErr
	}
	return b.env, nil
}

type fakeEnv struct {
	cleanups      int
	execs         int
	panicOnExec   bool
	panicOnClean  bool
	stdout        string
	lastEnv       []string
	lastArgv      []string
	execCtxErr    error
	timedOut      bool
	cancelled     bool
	signal        string
	sawCancelled  bool
	cleanupErrors []string
	evidence      Evidence
	// faultErr fails fault injection, the way a host missing a tc feature does.
	faultErr error
	trustErr error

	mu      sync.Mutex
	applied []TimedEvent
	// applyErr, when set, fails every scheduled event.
	applyErr error
	// applyHold blocks inside a scheduled apply, so a test can cancel while one
	// is in flight.
	applyHold chan struct{}
	// cleanedAt records when Cleanup ran, so a late event can be caught.
	cleanedAt  time.Time
	lateEvents int
	// execBeforeInitial catches a run that starts netdoc before an offset-zero
	// scheduled state has reached the environment.
	execBeforeInitial bool
}

func (e *fakeEnv) Nodes() []NodeInfo { return []NodeInfo{{Name: "client", Address: "10.77.0.10"}} }

func (e *fakeEnv) ApplyFaults(context.Context, []Fault) ([]FaultInfo, error) {
	return nil, e.faultErr
}

func (e *fakeEnv) ApplyTimedEvent(ctx context.Context, event TimedEvent) (string, error) {
	if e.applyHold != nil {
		<-e.applyHold
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cleanedAt.IsZero() {
		e.lateEvents++
	}
	e.applied = append(e.applied, event)
	return "fake", e.applyErr
}

func (e *fakeEnv) appliedEvents() []TimedEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]TimedEvent(nil), e.applied...)
}

func (e *fakeEnv) Exec(ctx context.Context, _ string, argv, env []string) ExecResult {
	e.execs++
	e.lastEnv = append([]string(nil), env...)
	e.lastArgv = append([]string(nil), argv...)
	e.mu.Lock()
	if len(e.applied) == 0 {
		e.execBeforeInitial = true
	}
	e.mu.Unlock()
	if e.panicOnExec {
		panic("probe exploded")
	}
	if ctx.Err() != nil {
		e.sawCancelled = true
		return ExecResult{Err: ctx.Err(), TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded),
			Cancelled: !errors.Is(ctx.Err(), context.DeadlineExceeded)}
	}
	return ExecResult{Stdout: []byte(e.stdout), Err: e.execCtxErr, TimedOut: e.timedOut,
		Cancelled: e.cancelled, Signal: e.signal}
}

func (e *fakeEnv) TrustAnchor(service string) (string, error) {
	if e.trustErr != nil {
		return "", e.trustErr
	}
	if service == "tls-target" {
		return "/simulator/tls-target-ca.pem", nil
	}
	return "", errors.New("unknown trust anchor")
}

func TestRunPassesOnlyValidatedProxyEnvironment(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, resolver: 10.77.0.1, services: [{name: proxy, type: socks5, port: 1080}]}", 1)
	raw = strings.Replace(raw, "target: example.test:80", "target: example.test:80, proxy: {scheme: socks5h, node: server, port: 1080}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport}
	Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if len(env.lastEnv) != 1 || env.lastEnv[0] != "ALL_PROXY=socks5h://10.77.0.1:1080" {
		t.Errorf("env = %q", env.lastEnv)
	}
}

// The CONNECT proxy has to arrive as HTTPS_PROXY. ALL_PROXY would also reach
// netdoc's proxy row, so handing it over that way would leave the variable a
// real proxy-only network actually sets completely untested.
func TestRunPassesTheCONNECTProxyAsHTTPSProxy(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, resolver: 10.77.0.1, services: [{name: connect-proxy, type: http_connect, port: 3128}]}", 1)
	raw = strings.Replace(raw, "target: example.test:80", "target: example.test:80, proxy: {scheme: http, node: server, port: 3128}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport}
	Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if len(env.lastEnv) != 1 || env.lastEnv[0] != "HTTPS_PROXY=http://10.77.0.1:3128" {
		t.Errorf("env = %q", env.lastEnv)
	}
}

func TestRunPassesOnlyGeneratedTLSRootEnvironment(t *testing.T) {
	raw := strings.Replace(minimalScenario, "address: 10.77.0.1}",
		"address: 10.77.0.1, services: [{name: tls-target, type: tls, port: 9443, certificate: {mode: valid, dns_names: [example.test]}}]}", 1)
	raw = strings.Replace(raw, "target: example.test:80", "target: example.test:80, trust: {service: tls-target}", 1)
	s, err := ParseScenario(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	env := &fakeEnv{stdout: okReport}
	Run(context.Background(), s, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if len(env.lastEnv) != 1 || env.lastEnv[0] != "SSL_CERT_FILE=/simulator/tls-target-ca.pem" {
		t.Errorf("env = %q", env.lastEnv)
	}
}

func (e *fakeEnv) Evidence(context.Context) (Evidence, error) {
	if e.evidence.FamilyReachability != nil || e.evidence.ControlledTargets != nil {
		return e.evidence, nil
	}
	return aggregateEvidence(nil), nil
}

func (e *fakeEnv) Cleanup(ctx context.Context, keep bool) CleanupInfo {
	e.mu.Lock()
	e.cleanedAt = time.Now()
	e.mu.Unlock()
	e.cleanups++
	if e.panicOnClean {
		panic("teardown exploded")
	}
	// The contract the real backend has to honour: cleanup runs under a context
	// that the caller's cancellation does not reach.
	if ctx.Err() != nil {
		e.cleanupErrors = append(e.cleanupErrors, "cleanup ran with an already-cancelled context")
	}
	return CleanupInfo{Done: len(e.cleanupErrors) == 0, Kept: keep, Errors: e.cleanupErrors}
}

const okReport = `{"checks":[{"id":"dns","status":"PASS","detail":"d"}],"verdict":"ok","summary":"s","ok":true}`

func testScenario(t *testing.T) *Scenario {
	t.Helper()
	s, err := ParseScenario(strings.NewReader(minimalScenario))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func supported() Capabilities { return Capabilities{Backend: "fake", Supported: true} }

func TestRunCleansUpAfterPartialSetupFailure(t *testing.T) {
	env := &fakeEnv{}
	b := &fakeBackend{caps: supported(), env: env, prepareErr: errors.New("veth wedged"), prepareEnvOnErr: true}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})

	if env.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1: a half-built environment still owns resources", env.cleanups)
	}
	if env.execs != 0 {
		t.Error("no test should run after setup failed")
	}
	if rep.Result != ResultError || !strings.Contains(rep.Error, "veth wedged") {
		t.Errorf("result = %s, error = %q", rep.Result, rep.Error)
	}
	if rep.Backend != "fake" {
		t.Errorf("backend = %q, want capability backend fake", rep.Backend)
	}
	// The topology that did get built is still worth reporting.
	if len(rep.Topology) != 1 {
		t.Errorf("topology = %v", rep.Topology)
	}
}

// A fault is several commands, so it can fail with some of them already
// applied: a narrowed interface and no firewall rule, say. The environment
// still has to come down: nothing that half-applied is worth keeping.
func TestRunCleansUpAfterFaultInjectionFailure(t *testing.T) {
	env := &fakeEnv{faultErr: errors.New("nft not built into this kernel")}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})

	if env.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1: a half-injected fault still owns resources", env.cleanups)
	}
	if env.execs != 0 {
		t.Error("no test should run against a topology whose faults did not all apply")
	}
	if rep.Result != ResultError || !strings.Contains(rep.Error, "nft not built") {
		t.Errorf("result = %s, error = %q", rep.Result, rep.Error)
	}
}

func TestRunCleansUpWhenPrepareBuiltNothing(t *testing.T) {
	env := &fakeEnv{}
	b := &fakeBackend{caps: supported(), env: env, prepareErr: errors.New("nope")}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})
	if env.cleanups != 0 {
		t.Errorf("cleanups = %d, want 0: there was no environment", env.cleanups)
	}
	if rep.Result != ResultError {
		t.Errorf("result = %s", rep.Result)
	}
}

func TestRunCleansUpAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env := &fakeEnv{stdout: okReport}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(ctx, testScenario(t), b, Options{Netdoc: "netdoc"})

	if env.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1", env.cleanups)
	}
	// The whole point of detaching cleanup's context: it must not arrive
	// already cancelled, or the backend could not run a single command.
	if len(env.cleanupErrors) > 0 {
		t.Errorf("cleanup context: %v", env.cleanupErrors)
	}
	if !rep.Cleanup.Done {
		t.Errorf("cleanup not done: %+v", rep.Cleanup)
	}
}

func TestRunCleansUpAfterTimeout(t *testing.T) {
	env := &fakeEnv{stdout: okReport}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{
		Netdoc: "netdoc", TestTimeout: time.Nanosecond, CleanupTimeout: 5 * time.Second,
	})
	if env.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1", env.cleanups)
	}
	if len(env.cleanupErrors) > 0 {
		t.Errorf("cleanup context: %v", env.cleanupErrors)
	}
	if !rep.Cleanup.Done {
		t.Errorf("cleanup not done: %+v", rep.Cleanup)
	}
}

func TestRunCleansUpAfterPanic(t *testing.T) {
	env := &fakeEnv{panicOnExec: true}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})

	if env.cleanups != 1 {
		t.Errorf("cleanups = %d, want 1: a panicking probe must not leak namespaces", env.cleanups)
	}
	if rep.Result != ResultError || !strings.Contains(rep.Error, "probe exploded") {
		t.Errorf("result = %s, error = %q", rep.Result, rep.Error)
	}
	if !rep.Cleanup.Done {
		t.Errorf("cleanup should still have completed: %+v", rep.Cleanup)
	}
}

func TestRunSurvivesPanickingCleanup(t *testing.T) {
	env := &fakeEnv{stdout: okReport, panicOnClean: true}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})

	if rep.Cleanup.Done {
		t.Error("a panicking cleanup must not report success")
	}
	if len(rep.Cleanup.Errors) == 0 || !strings.Contains(rep.Cleanup.Errors[0], "teardown exploded") {
		t.Errorf("cleanup errors = %v", rep.Cleanup.Errors)
	}
	// The diagnosis still has to survive: losing the report as well would leave
	// the user with nothing.
	if len(rep.Tests) != 1 || rep.Tests[0].ActualVerdict != "ok" {
		t.Errorf("tests = %+v", rep.Tests)
	}
	if rep.Result != ResultError {
		t.Errorf("result = %s, want %s", rep.Result, ResultError)
	}
}

func TestRunRefusesUnsupportedHostWithoutFallback(t *testing.T) {
	env := &fakeEnv{}
	b := &fakeBackend{caps: Capabilities{Backend: "fake", Reason: "user namespaces are off"}, env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc"})

	if rep.Result != ResultError || rep.Error != "user namespaces are off" {
		t.Errorf("result = %s, error = %q", rep.Result, rep.Error)
	}
	if env.execs != 0 {
		t.Error("nothing may run on a host that cannot simulate: no fallback to the host network")
	}
}

func TestRunRecordsRepeatVerdicts(t *testing.T) {
	env := &fakeEnv{stdout: okReport}
	b := &fakeBackend{caps: supported(), env: env}
	rep := Run(context.Background(), testScenario(t), b, Options{Netdoc: "netdoc", Repeat: 3})
	if env.execs != 3 {
		t.Errorf("execs = %d, want 3", env.execs)
	}
	if len(rep.Tests[0].RepeatVerdicts) != 3 {
		t.Errorf("repeat verdicts = %v", rep.Tests[0].RepeatVerdicts)
	}
}

func TestDecodeDiagnosisRejectsNonReports(t *testing.T) {
	tests := []struct {
		name string
		res  ExecResult
		want string
	}{
		{"exec failed", ExecResult{Err: errors.New("no such process")}, "running netdoc"},
		{"stderr only", ExecResult{Stderr: []byte("netdoc: bad target"), ExitCode: 2}, "without a report"},
		{"garbage", ExecResult{Stdout: []byte("not json"), ExitCode: 1}, "not a report"},
		{"empty report", ExecResult{Stdout: []byte(`{"checks":[]}`)}, "empty report"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeDiagnosis(tc.res)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	// netdoc exits 1 whenever a check failed, which is the normal case in a
	// scenario that broke something. That must not read as a broken run.
	d, err := decodeDiagnosis(ExecResult{Stdout: []byte(okReport), ExitCode: 1})
	if err != nil || d.Verdict != "ok" {
		t.Errorf("d = %+v, err = %v", d, err)
	}
}

func TestDecodeDiagnosisProjectsCanonicalReportWithoutExpandingSimulatorJSON(t *testing.T) {
	wire := report.Report{
		Version: "1.2.3",
		Ts:      "2030-01-02T03:04:05Z",
		Target:  &report.Target{Host: "example.test", Port: 443, Protocol: "tls+http"},
		Checks: []report.Check{{
			ID: "internet_tcp", Name: "Internet connectivity", Status: "WARN", Cause: "ipv6_unreachable",
			Families: &report.Families{IPv4: "reachable", IPv6: "unreachable"}, Ms: 17,
			Detail: "IPv4 works", Fix: "check IPv6 route", Addrs: []string{"192.0.2.1", "2001:db8::1"},
			SelectedIP: "192.0.2.1", Source: "192.0.2.2", Iface: "eth0", Network: "office",
			Portal:   &report.Portal{RedirectURL: "https://portal.example/signin"},
			Attempts: []report.Attempt{{IP: "192.0.2.1", Ms: 11}, {IP: "2001:db8::1", Ms: 17, Err: "timeout"}},
		}},
		Findings: []report.Finding{{
			ID: "direct_egress_degraded", Focus: "internet_tcp", Evidence: []string{"internet_tcp"},
			CausalEvidence: []report.CausalEvidence{{Kind: "support", Check: "internet_tcp", Observation: "status_warn"}},
		}},
		Summary: "IPv6 unavailable", Verdict: "degraded", FailedStage: "internet_tcp", OK: false,
	}
	stdout, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeDiagnosis(ExecResult{Stdout: stdout, ExitCode: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := &Diagnosis{
		Checks: []DiagnosisCheck{{
			ID: "internet_tcp", Name: "Internet connectivity", Status: "WARN", Cause: "ipv6_unreachable",
			Ms: 17, Detail: "IPv4 works", Fix: "check IPv6 route",
			Families: &DiagnosisFamilies{IPv4: "reachable", IPv6: "unreachable"},
			Attempts: []DiagnosisAttempt{{IP: "192.0.2.1", Ms: 11}, {IP: "2001:db8::1", Ms: 17, Error: "timeout"}},
		}},
		Findings: []DiagnosisFinding{{
			ID: "direct_egress_degraded", Focus: "internet_tcp", Evidence: []string{"internet_tcp"},
			CausalEvidence: []DiagnosisCausalEvidence{{Kind: "support", Check: "internet_tcp", Observation: "status_warn"}},
		}},
		Summary: "IPv6 unavailable", Verdict: "degraded", FailedStage: "internet_tcp", OK: false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnosis = %+v\nwant      %+v", got, want)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = `{"checks":[{"id":"internet_tcp","name":"Internet connectivity","status":"WARN","cause":"ipv6_unreachable","ms":17,"detail":"IPv4 works","fix":"check IPv6 route","address_families":{"ipv4":"reachable","ipv6":"unreachable"},"attempts":[{"ip":"192.0.2.1","ms":11},{"ip":"2001:db8::1","ms":17,"error":"timeout"}]}],"findings":[{"id":"direct_egress_degraded","focus":"internet_tcp","evidence":["internet_tcp"],"causal_evidence":[{"kind":"support","check":"internet_tcp","observation":"status_warn"}]}],"summary":"IPv6 unavailable","verdict":"degraded","failed_stage":"internet_tcp","ok":false}`
	if string(encoded) != wantJSON {
		t.Errorf("simulator diagnosis JSON = %s\nwant                     %s", encoded, wantJSON)
	}
}

// Ids name directories and records in shared temporary storage, so the
// exclusive creates that guard them are only as good as the odds two runs
// never draw the same id. A hundred thousand draws of runIDBytes*8 bits
// collide with a probability far below anything a flaky test would notice,
// which is what lets this assert uniqueness outright. The shape is checked in
// the same pass: an id has to survive the name rules every path derived from
// it is gated by.
func TestNewIDIsWideAndSafeEnoughToNeverCollide(t *testing.T) {
	const draws = 100_000
	seen := make(map[string]bool, draws)
	for i := 0; i < draws; i++ {
		id := NewID()
		if len(id) != 2*runIDBytes {
			t.Fatalf("id %q is %d bytes, want %d", id, len(id), 2*runIDBytes)
		}
		for _, c := range id {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("id %q is not lower-case hex", id)
			}
		}
		if !isSafeName(id) {
			t.Fatalf("id %q does not survive the rules that gate every path built from it", id)
		}
		if seen[id] {
			t.Fatalf("NewID repeated %q within %d draws", id, draws)
		}
		seen[id] = true
	}
}

// observedEvidence is what the environment recorded on its own, before any
// diagnosis was consulted. The two families deliberately disagree with each
// other, and the controlled-target dial deliberately disagrees with the failing
// diagnoses below, so a collector that copied netdoc's verdict could not
// accidentally match.
func observedEvidence() Evidence {
	out := aggregateEvidence(nil)
	out.FamilyReachability = []FamilyReachabilityEvidence{
		{Node: "client", Family: "ipv4", Target: "IPv4 internet endpoints",
			Via: []string{"client-lan", "10.78.1.1"}, State: FamilyStateReachable},
		{Node: "client", Family: "ipv6", Target: "IPv6 internet endpoints",
			Via: []string{"client-lan", "2001:db8:77:1::1"}, State: FamilyStateUnreachable},
	}
	out.ControlledTargets = []ControlledTargetEvidence{
		{From: "client", To: "10.77.0.1:80", Via: []string{"client-lan", "10.78.1.1"}, Reachable: true},
	}
	return out
}

// TestRunKeepsEvidenceExactlyAsObserved is the simulator's truth boundary in a
// single assertion: netdoc's report is the subject being evaluated, never a
// source of evidence, so the finished report's evidence must be the
// environment's own observations and nothing else. Every family verdict netdoc
// can produce is tried, including the exact opposite of the observations, a
// check with no families, a target verdict of every status, and no parsable
// report at all. None of them may add, drop, or edit a record. Comparing the
// whole Evidence rather than one field is deliberate: a future field fed from a
// diagnosis fails here without anyone remembering to extend the test.
func TestRunKeepsEvidenceExactlyAsObserved(t *testing.T) {
	targetReport := `{"checks":[{"id":"target_tcp","status":"STATUS"}],"verdict":"ok","summary":"s","ok":true}`
	cases := []struct{ name, diagnosis string }{
		{"no families", `{"checks":[{"id":"internet_tcp","status":"FAIL"}],"verdict":"broken"}`},
		{"both reachable", `{"checks":[{"id":"internet_tcp","status":"PASS","address_families":{"ipv4":"reachable","ipv6":"reachable"}}],"verdict":"ok"}`},
		{"both unreachable", `{"checks":[{"id":"internet_tcp","status":"FAIL","address_families":{"ipv4":"unreachable","ipv6":"unreachable"}}],"verdict":"broken"}`},
		{"inverted families", `{"checks":[{"id":"internet_tcp","status":"WARN","address_families":{"ipv4":"unreachable","ipv6":"reachable"}}],"verdict":"degraded"}`},
		{"unparsable report", "not a report"},
	}
	for _, status := range []string{"PASS", "WARN", "FAIL", "N/A"} {
		cases = append(cases, struct{ name, diagnosis string }{"target " + status, strings.Replace(targetReport, "STATUS", status, 1)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &fakeEnv{stdout: tc.diagnosis, evidence: observedEvidence()}
			rep := Run(context.Background(), testScenario(t), &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
			if got, want := rep.Evidence, observedEvidence(); !reflect.DeepEqual(got, want) {
				t.Errorf("diagnosis changed the observations:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}

// TestRunKeepsEvidenceWithoutATarget guards the other half of the boundary:
// with no target to reach there is nothing for a diagnosis to contribute, and
// the observations still stand on their own.
func TestRunKeepsEvidenceWithoutATarget(t *testing.T) {
	scenario := testScenario(t)
	scenario.Tests[0].Target = ""
	env := &fakeEnv{stdout: okReport, evidence: observedEvidence()}
	rep := Run(context.Background(), scenario, &fakeBackend{caps: supported(), env: env}, Options{Netdoc: "netdoc"})
	if got, want := rep.Evidence, observedEvidence(); !reflect.DeepEqual(got, want) {
		t.Errorf("evidence = %+v, want %+v", got, want)
	}
}

// TestInternetFamilyProbesFollowNodeAddresses covers eligibility: which
// families the simulator will dial at all. A family the node has no address
// for is reported unavailable rather than dialed, which is what keeps a
// single-stack topology from reading as an outage in the family it never had.
// Both families are always listed, so an absent one is stated, not inferred
// from a missing record.
func TestInternetFamilyProbesFollowNodeAddresses(t *testing.T) {
	v4 := Interface{Segment: "lan", IPv4: "10.78.1.10/24"}
	v6 := Interface{Segment: "lan", IPv6: "2001:db8:77:1::10/64"}
	dual := Interface{Segment: "lan", IPv4: "10.78.1.10/24", IPv6: "2001:db8:77:1::10/64"}
	// The legacy "address" spelling is folded into IPv4 by topology validation,
	// so a node that reaches the collector never carries it unresolved.
	for _, tc := range []struct {
		name string
		node Node
		want map[string]bool
	}{
		{"dual stack", Node{Interfaces: []Interface{dual}}, map[string]bool{"ipv4": true, "ipv6": true}},
		{"split interfaces", Node{Interfaces: []Interface{v4, v6}}, map[string]bool{"ipv4": true, "ipv6": true}},
		{"IPv4 only", Node{Interfaces: []Interface{v4}}, map[string]bool{"ipv4": true, "ipv6": false}},
		{"IPv6 only", Node{Interfaces: []Interface{v6}}, map[string]bool{"ipv4": false, "ipv6": true}},
		{"no addresses", Node{}, map[string]bool{"ipv4": false, "ipv6": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]bool{}
			for _, probe := range internetFamilyProbes(&tc.node) {
				got[probe.family] = probe.available
				if len(probe.endpoints) == 0 {
					t.Errorf("family %s has no endpoint to dial", probe.family)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("family availability = %v, want %v", got, tc.want)
			}
		})
	}
	if internetProbePort != 443 {
		t.Errorf("probe port = %d, want 443", internetProbePort)
	}
}

// TestHolderProbeReplyRejectsUnusableRequests keeps the holder from dialing
// anything the director did not spell out exactly: no names, no zones, no
// unbounded wait. Reachability is only ever observed against a literal address.
func TestHolderProbeReplyRejectsUnusableRequests(t *testing.T) {
	for _, line := range []string{
		"probe",
		"probe 1.1.1.1 443",
		"probe 1.1.1.1 443 2000 extra",
		"probe one.one.one.one 443 2000",
		"probe fe80::1%eth0 443 2000",
		"probe 1.1.1.1 0 2000",
		"probe 1.1.1.1 70000 2000",
		"probe 1.1.1.1 443 0",
		"probe 1.1.1.1 443 -1",
		"probe 1.1.1.1 443 soon",
	} {
		if got := holderCommandReply(line, nil); got != "probe-result error" {
			t.Errorf("%q answered %q, want a rejection", line, got)
		}
	}
}

// Placing evidence on the timeline is where "no wall clock" would otherwise
// turn into "observed at T0": Offset is zero before the director touches it, so
// the only thing separating the two is whether the director says it placed the
// query. An observation that really did land on T0 still has to come out known.
func TestPlaceEvidenceOnTimelineMarksOnlyPlacedQueries(t *testing.T) {
	t0 := time.Now()
	rep := &Report{Evidence: Evidence{DNSQueries: []DNSQueryEvidence{
		{Service: "unplaced", ActualOutcome: "DROPPED"},
		{Service: "at-epoch", ActualOutcome: "DROPPED", at: t0},
		{Service: "later", ActualOutcome: "ANSWER", at: t0.Add(250 * time.Millisecond)},
	}}}
	rep.placeEvidenceOnTimeline(t0)

	for i, want := range []struct {
		offset time.Duration
		known  bool
	}{{0, false}, {0, true}, {250 * time.Millisecond, true}} {
		got := rep.Evidence.DNSQueries[i]
		if got.Offset != want.offset || got.OffsetKnown != want.known {
			t.Errorf("%s: offset = %v known = %v, want %v/%v", got.Service, got.Offset, got.OffsetKnown, want.offset, want.known)
		}
	}
	// The first two share an offset on purpose; the flag is the whole difference.
	if rep.Evidence.DNSQueries[0].OffsetKnown == rep.Evidence.DNSQueries[1].OffsetKnown {
		t.Error("an unplaced query and one observed at T0 came out indistinguishable")
	}
}
