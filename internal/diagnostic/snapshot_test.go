package diagnostic

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// goldenSnapshot is the fixture this package writes and internal/snapshot
// reads back. It lives next to the decoder because the format belongs there;
// the builder here is what has to keep producing it.
//
// Regenerate deliberately, then read the diff:
//
//	NETDOC_UPDATE_GOLDEN=1 go test ./internal/diagnostic -run TestBuildSnapshotGolden
//
// A diff in this file is a change to a published artifact format, so it is
// meant to be looked at rather than accepted.
var goldenSnapshot = filepath.Join("..", "snapshot", "testdata", "example.ndoc")

// timedResults stamps the duration a real run always records. Every probe the
// DAG builds executes inside wrapRun, whose timer floors at one nanosecond, so
// a result the run reported is a result with a duration, and the snapshot's
// ran field is read straight off that. A result map written by hand in a test
// has none, and an artifact built from one would claim an outcome no probe
// body measured. A prerequisite skip is the exception, because the scheduler
// records it without calling the probe at all.
func timedResults(res map[ProbeID]ProbeResult) map[ProbeID]ProbeResult {
	out := make(map[ProbeID]ProbeResult, len(res))
	for id, r := range res {
		if r.Dur == 0 && r.Status != StatusSkip {
			r.Dur = time.Millisecond
		}
		out[id] = r
	}
	return out
}

// fixtureRun is one deliberately small, deliberately unhealthy run: a target
// whose name resolves and whose port is refused, over a link that lost IPv6
// and had its egress failure relaxed by later reasoning. It is written out by
// hand rather than taken from the live DAG, so the golden file pins the
// snapshot format and not the current probe list.
func fixtureRun() (*Target, []Probe, map[ProbeID]ProbeResult) {
	target := &Target{Raw: "example.com", Host: "example.com", Port: 443, Proto: ProtoTLSHTTP}
	probes := []Probe{
		{ID: ProbeIface, Name: "Interface"},
		{ID: ProbeSSID, Name: "Wi-Fi network", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeDNS, Name: "DNS example.com", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeDNSPublic, Name: "DNS (public 8.8.8.8)", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeTargetTCP, Name: "TCP example.com:443", Deps: []ProbeID{ProbeDNS}},
		{ID: ProbeTLS, Name: "TLS example.com", Deps: []ProbeID{ProbeTargetTCP}},
	}
	results := map[ProbeID]ProbeResult{
		ProbeIface: {
			ID: ProbeIface, Status: StatusPass, Dur: 2 * time.Millisecond,
			Source: net.ParseIP("192.0.2.10"), Iface: "eth0",
			Detail: "using eth0 source 192.0.2.10",
		},
		ProbeSSID: {
			ID: ProbeSSID, Status: StatusPass, Dur: 5 * time.Millisecond,
			Network: "Example Cafe Wi-Fi", Detail: "connected to Example Cafe Wi-Fi",
		},
		ProbeInternet: {
			ID: ProbeInternet, Status: StatusWarn, Dur: 41 * time.Millisecond,
			downgraded: true, clockOffset: 3 * time.Second,
			Families:   &FamilyConnectivity{IPv4: FamilyReachable, IPv6: FamilyUnreachable},
			SelectedIP: net.ParseIP("1.1.1.1"), Source: net.ParseIP("192.0.2.10"), Iface: "eth0",
			Detail: "IPv4 egress via 1.1.1.1 in 41ms (src 192.0.2.10 eth0)",
		},
		ProbeDNS: {
			ID: ProbeDNS, Status: StatusPass, Dur: 12 * time.Millisecond,
			Addrs:           []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
			ResolverTargets: []string{"192.0.2.53:53", "[2001:db8::53]:53"},
			Detail:          "example.com resolved to 2 addresses",
		},
		ProbeDNSPublic: {
			ID: ProbeDNSPublic, Status: StatusPass, Dur: 19 * time.Millisecond,
			resolver: "8.8.8.8", ResolverTargets: []string{"8.8.8.8:53"},
			Addrs: []net.IP{net.ParseIP("93.184.216.34")}, Detail: "8.8.8.8 agrees on 93.184.216.34",
		},
		ProbeTargetTCP: {
			ID: ProbeTargetTCP, Status: StatusFail, Dur: 33 * time.Millisecond,
			Cause: ConnectionCauseRefused, Source: net.ParseIP("192.0.2.10"), Iface: "eth0",
			Attempts: []Attempt{
				{IP: net.ParseIP("93.184.216.34"), Dur: 21 * time.Millisecond, Err: errors.New("connect: connection refused"), Cause: ConnectionCauseRefused},
				{IP: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), Dur: 12 * time.Millisecond, Err: errors.New("connect: network is unreachable"), Cause: ConnectionCauseUnreachable},
			},
			Detail: "connection to port 443 was refused on all 2 attempted address(es): 93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946",
			Fix:    "check that the service is listening on port 443",
		},
		ProbeTLS: SkipPrereq(ProbeTLS),
	}
	return target, probes, results
}

func TestBuildSnapshotGolden(t *testing.T) {
	target, probes, results := fixtureRun()
	s := BuildSnapshot(target, probes, results)
	// The invocation half, which BuildSnapshot leaves to its caller. Fixed
	// values, so the file is the same on every machine and every run.
	s.Tool = snapshot.Tool{Version: "1.2.3", OS: "linux", Arch: "amd64"}
	s.CreatedAt = "2026-01-02T03:04:05Z"
	s.Options = snapshot.Options{ProbeTimeoutMs: 4000, PublicDNS: "8.8.8.8"}

	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if os.Getenv("NETDOC_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenSnapshot, data, 0o600); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		t.Log("golden updated; read the diff before committing it")
		return
	}
	// #nosec G304 -- goldenSnapshot is a fixed repository-owned fixture path.
	want, err := os.ReadFile(goldenSnapshot)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(data) != string(want) {
		t.Errorf("snapshot bytes changed; .ndoc is a published format, so confirm this is intended and regenerate with NETDOC_UPDATE_GOLDEN=1\ngot:\n%s\nwant:\n%s", data, want)
	}
}

// Provenance: the evidence that only lives inside this package has to reach the
// artifact, or a later comparison reads an inferred state as a measured one.
func TestBuildSnapshotCarriesUnexportedEvidence(t *testing.T) {
	target, probes, results := fixtureRun()
	internetResult := results[ProbeInternet]
	internetResult.Cause, internetResult.causeFamily = RouteCauseNoDefaultRoute, counterfactualIPv4
	results[ProbeInternet] = internetResult
	checks := checksByID(BuildSnapshot(target, probes, results))

	internet := checks[string(ProbeInternet)]
	if internet.Derived == nil || !internet.Derived.StatusDowngraded {
		t.Errorf("the relaxed egress failure lost its provenance: %+v", internet.Derived)
	}
	if internet.Observed == nil || internet.Observed.ClockOffsetMs == nil || *internet.Observed.ClockOffsetMs != 3000 {
		t.Errorf("clock offset = %+v, want 3000ms", internet.Observed)
	}
	if got := checks[string(ProbeDNSPublic)]; got.Observed == nil || got.Observed.Resolver != "8.8.8.8" {
		t.Errorf("second-opinion resolver lost: %+v", got.Observed)
	}
	if got := checks[string(ProbeInternet)]; got.CauseFamily != counterfactualIPv4 {
		t.Errorf("cause family = %q, want %q", got.CauseFamily, counterfactualIPv4)
	}
	// A row nothing rewrote must not claim it was rewritten.
	if got := checks[string(ProbeDNS)]; got.Derived != nil {
		t.Errorf("dns derived = %+v, want absent on a row the reasoning pass left alone", got.Derived)
	}
}

func TestBuildSnapshotShape(t *testing.T) {
	target, probes, results := fixtureRun()
	s := BuildSnapshot(target, probes, results)

	if s.Schema != snapshot.Schema {
		t.Errorf("schema = %q", s.Schema)
	}
	if s.OK {
		t.Error("ok = true, want false: target_tcp failed")
	}
	if s.Diagnosis.FailedStage != string(ProbeTargetTCP) {
		t.Errorf("failed_stage = %q", s.Diagnosis.FailedStage)
	}
	if s.Diagnosis.Verdict == "" || s.Diagnosis.Summary == "" {
		t.Errorf("diagnosis = %+v, want a verdict and a sentence", s.Diagnosis)
	}
	if len(s.Diagnosis.Findings) != 1 || len(s.Diagnosis.Findings[0].CausalEvidence) == 0 {
		t.Fatalf("diagnosis lost causal evidence: %+v", s.Diagnosis.Findings)
	}
	for _, evidence := range s.Diagnosis.Findings[0].CausalEvidence {
		if evidence.Check == "" || checksByID(s)[evidence.Check].ID == "" {
			t.Errorf("causal evidence has no snapshot check provenance: %+v", evidence)
		}
	}
	// The producing version's own assessment travels with the finding, so a
	// later reader can compare what this build concluded against what the build
	// replaying it concludes.
	live := Interpret(target, probeIDs(probes), results)
	if got, want := s.Diagnosis.Findings[0].Confidence, string(live.Findings[0].Confidence); got != want || got == "" {
		t.Errorf("finding confidence = %q, want %q", got, want)
	}
	// Probe order is the snapshot's order, so two runs of the same graph line up
	// row for row without sorting.
	if len(s.Checks) != len(probes) {
		t.Fatalf("%d checks, want %d", len(s.Checks), len(probes))
	}
	for i, p := range probes {
		if s.Checks[i].ID != string(p.ID) {
			t.Fatalf("check %d = %q, want %q", i, s.Checks[i].ID, p.ID)
		}
	}
	checks := checksByID(s)
	if got := checks[string(ProbeTLS)]; got.Ran || got.DurationMs != 0 || got.Observed != nil {
		t.Errorf("a skipped prerequisite row claims to have run: %+v", got)
	}
	if got := checks[string(ProbeIface)]; !got.Ran || got.DurationMs != 2 {
		t.Errorf("iface = %+v, want a row that ran in 2ms", got)
	}
	if got := checks[string(ProbeTargetTCP)]; len(got.Deps) != 1 || got.Deps[0] != string(ProbeDNS) {
		t.Errorf("deps = %v, want the graph edge the run executed", got.Deps)
	}
	if got := checks[string(ProbeTargetTCP)]; len(got.Observed.Attempts) != 2 ||
		got.Observed.Attempts[0].IP != "93.184.216.34" || got.Observed.Attempts[0].Error == "" {
		t.Errorf("attempts = %+v", got.Observed.Attempts)
	}
	if got := checks[string(ProbeSSID)]; got.Observed == nil || got.Observed.SSID != "Example Cafe Wi-Fi" {
		t.Errorf("ssid = %+v", got.Observed)
	}
}

func TestBuildSnapshotCausalEvidenceRoundTrip(t *testing.T) {
	target, probes, results := fixtureRun()
	want := BuildSnapshot(target, probes, results)
	data, err := snapshot.Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, wanted := got.Diagnosis.Findings[0].Confidence, want.Diagnosis.Findings[0].Confidence; got != wanted {
		t.Errorf("confidence round-tripped as %q, want %q", got, wanted)
	}
	wantEvidence := want.Diagnosis.Findings[0].CausalEvidence
	gotEvidence := got.Diagnosis.Findings[0].CausalEvidence
	if len(gotEvidence) != len(wantEvidence) {
		t.Fatalf("causal evidence = %+v, want %+v", gotEvidence, wantEvidence)
	}
	for i := range wantEvidence {
		if gotEvidence[i] != wantEvidence[i] {
			t.Errorf("causal evidence[%d] = %+v, want %+v", i, gotEvidence[i], wantEvidence[i])
		}
	}
}

// A generic run has no target, and says so: null, never an empty Target that a
// comparison would read as "a run against the empty host".
func TestBuildSnapshotGenericRun(t *testing.T) {
	s := BuildSnapshot(nil, nil, nil)
	if s.Target != nil {
		t.Errorf("target = %+v, want nil", s.Target)
	}
	if !s.OK || s.Checks == nil || len(s.Checks) != 0 {
		t.Errorf("empty run = %+v, want ok with an empty (not null) check list", s)
	}
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(string(data), `"checks": []`) {
		t.Errorf("checks encoded as null rather than an empty list:\n%s", data)
	}
}

// An IP-literal target has no name to resolve, and the snapshot records the
// literal so a reader is not left to re-parse Raw to find that out.
func TestBuildSnapshotIPLiteralTarget(t *testing.T) {
	target := &Target{Raw: "[2001:db8::1]:8443", Host: "2001:db8::1", IP: net.ParseIP("2001:db8::1"), Port: 8443, PortExplicit: true}
	s := BuildSnapshot(target, nil, nil)
	if s.Target.IP != "2001:db8::1" || !s.Target.PortExplicit || s.Target.Port != 8443 {
		t.Errorf("target = %+v", s.Target)
	}
	if s.Target.Raw != "[2001:db8::1]:8443" {
		t.Errorf("raw = %q, want the spelling the user typed", s.Target.Raw)
	}
}

// Every row the real DAG builds must convert, including the ones this
// package's fixture leaves out. Nothing here touches the network: the probes
// are built and then given fabricated results.
func TestBuildSnapshotCoversTheRealProbeGraph(t *testing.T) {
	target, err := ParseTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	probes := BuildProbesFromSources(target, nil, DefaultPublicDNS, true)
	if len(probes) < 8 {
		t.Fatalf("the real DAG built only %d probes; this guard is not reaching it", len(probes))
	}
	results := make(map[ProbeID]ProbeResult, len(probes))
	for _, p := range probes {
		results[p.ID] = ProbeResult{ID: p.ID, Status: StatusPass, Dur: time.Millisecond}
	}
	s := BuildSnapshot(target, probes, results)
	if len(s.Checks) != len(probes) {
		t.Fatalf("%d checks for %d probes", len(s.Checks), len(probes))
	}
	for i, c := range s.Checks {
		if c.ID == "" || c.Name == "" || c.Status != "PASS" || !c.Ran {
			t.Errorf("check %d = %+v, want a named row that ran", i, c)
		}
	}
	if _, err := snapshot.Encode(s); err != nil {
		t.Errorf("the real graph does not encode: %v", err)
	}
}

// Nothing a probe cannot sanitize should reach the file: probe text goes
// through textsafe on the way out of the runner, and the snapshot copies it
// verbatim, so a hostile detail string has to survive as inert bytes rather
// than as an escape sequence.
func TestBuildSnapshotKeepsHostileTextInert(t *testing.T) {
	probes := []Probe{{ID: ProbeIface, Name: "Interface", Run: func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		return ProbeResult{Status: StatusFail, Detail: "\x1b]0;pwned\x07 and \x1b[31mred", Iface: "eth0\x1b[0m"}
	}}}
	probes[0].Run = wrapRun(probes[0].Run)
	results := RunAll(context.Background(), probes, time.Second)
	data, err := snapshot.Encode(BuildSnapshot(nil, probes, results))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.ContainsRune(string(data), 0x1b) {
		t.Errorf("an escape byte reached the snapshot:\n%q", data)
	}
}

// The one secret netdoc handles is the proxy password, and it must not reach a
// snapshot. url.URL.Host carries no userinfo, which is what keeps the proxy
// rows credential-free; this pins that rather than trusting it.
func TestBuildSnapshotOmitsProxyCredentials(t *testing.T) {
	const secret = "hunter2"
	// Injected rather than set in the environment: net/http caches the proxy
	// variables once per process, so an env-based test would silently depend on
	// whether something else in the package looked first. What is under test is
	// the artifact, not the parsing.
	proxyURL, err := url.Parse("http://alice:" + secret + "@proxy.example.com:3128")
	if err != nil {
		t.Fatal(err)
	}
	ops := &netops{
		proxyFromEnv: func(*http.Request) (*url.URL, error) { return proxyURL, nil },
		dialContext:  failingDial,
	}
	probes := []Probe{{ID: ProbeProxy, Name: "Internet (env proxy)", Run: wrapRun(ops.proxyProbe)}}
	results := RunAll(context.Background(), probes, 2*time.Second)

	data, err := snapshot.Encode(BuildSnapshot(nil, probes, results))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Errorf("the proxy password reached the snapshot:\n%s", data)
	}
	if strings.Contains(string(data), "alice") {
		t.Errorf("the proxy username reached the snapshot:\n%s", data)
	}
	// The proxy host itself is diagnostic information and is meant to be there,
	// so this test is about the credential and not about the row going quiet.
	if !strings.Contains(string(data), "proxy.example.com") {
		t.Errorf("the proxy row says nothing at all:\n%s", data)
	}
}

func failingDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial refused by the test")
}

// The snapshot must not turn into a place where the environment gets copied.
// Reading the encoded file back as free-form JSON keeps this honest even if
// somebody adds a field to the Go struct.
func TestSnapshotCarriesNoEnvironmentDump(t *testing.T) {
	t.Setenv("NETDOC_SECRET_CANARY", "s3cr3t-canary-value")
	target, probes, results := fixtureRun()
	s := BuildSnapshot(target, probes, results)
	s.Tool = snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"}
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, forbidden := range []string{"s3cr3t-canary-value", "NETDOC_SECRET_CANARY", os.Getenv("HOME"), "Authorization", "Cookie"} {
		if forbidden == "" {
			continue
		}
		if strings.Contains(string(data), forbidden) {
			t.Errorf("%q reached the snapshot:\n%s", forbidden, data)
		}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]bool{"schema": true, "created_at": true, "tool": true, "target": true, "options": true, "checks": true, "diagnosis": true, "ok": true}
	for key := range raw {
		if !want[key] {
			t.Errorf("unexpected top-level key %q; a snapshot is a reviewed set of fields, not a dump", key)
		}
	}
}

func checksByID(s snapshot.Snapshot) map[string]snapshot.Check {
	byID := make(map[string]snapshot.Check, len(s.Checks))
	for _, c := range s.Checks {
		byID[c.ID] = c
	}
	return byID
}

// The invariant this format is built on: a probe with no result must never be
// written as a pass. StatusPass is the zero value of the runtime status type,
// so "read the status off whatever the map returns" would publish a clean row
// for a check that never reported.
func TestBuildSnapshotMarksUnreportedChecksIncomplete(t *testing.T) {
	probes := []Probe{
		{ID: ProbeIface, Name: "Interface"},
		{ID: ProbeInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeQUIC, Name: "QUIC (UDP/443)", Deps: []ProbeID{ProbeIface}},
		{ID: ProbeTLS, Name: "TLS example.com", Deps: []ProbeID{ProbeInternet}},
	}
	// One of each state a row can be in, including the one the map cannot
	// express: quic_udp_443 is in the graph and absent from the results, which
	// is what a cancelled or interrupted run leaves behind.
	results := map[ProbeID]ProbeResult{
		ProbeIface:    {ID: ProbeIface, Status: StatusPass, Dur: 2 * time.Millisecond},
		ProbeInternet: {ID: ProbeInternet, Status: StatusFail, Dur: 9 * time.Millisecond},
		ProbeTLS:      SkipPrereq(ProbeTLS),
	}
	s := BuildSnapshot(nil, probes, results)
	checks := checksByID(s)

	want := map[string]struct {
		status string
		ran    bool
	}{
		string(ProbeIface):    {snapshot.StatusPass, true},
		string(ProbeInternet): {snapshot.StatusFail, true},
		string(ProbeTLS):      {snapshot.StatusSkip, false},
		string(ProbeQUIC):     {snapshot.StatusIncomplete, false},
	}
	for id, w := range want {
		got, ok := checks[id]
		if !ok {
			t.Fatalf("%s is missing from the snapshot; every row the run built is recorded", id)
		}
		if got.Status != w.status || got.Ran != w.ran {
			t.Errorf("%s = status %q ran %v, want %q ran %v", id, got.Status, got.Ran, w.status, w.ran)
		}
	}
	unreported := checks[string(ProbeQUIC)]
	if unreported.Status == snapshot.StatusPass {
		t.Fatal("a probe that never reported was recorded as a pass")
	}
	if unreported.DurationMs != 0 || unreported.Observed != nil || unreported.Derived != nil {
		t.Errorf("an unreported row carries evidence: %+v", unreported)
	}
	// The row keeps its identity so a comparison can see the check existed.
	if unreported.Name == "" || len(unreported.Deps) != 1 {
		t.Errorf("unreported row lost its place in the graph: %+v", unreported)
	}
	// A run holding a row that never reported is not a clean run, and the
	// diagnosis does not claim a verdict for one either.
	if s.OK {
		t.Error("ok = true on a run with an unreported check")
	}
	if s.Diagnosis.Verdict != VerdictIncomplete {
		t.Errorf("verdict = %q, want %q", s.Diagnosis.Verdict, VerdictIncomplete)
	}
	// And what the builder produces is what the format accepts: the guard in
	// Encode and the rule here cannot drift apart without this failing.
	if _, err := snapshot.Encode(s); err != nil {
		t.Errorf("the builder produced a snapshot the format refuses: %v", err)
	}
}

// An unreported row makes the whole run not ok even when every check that did
// report passed, because the answer to one of the questions asked is missing.
func TestBuildSnapshotUnreportedCheckClearsOK(t *testing.T) {
	probes := []Probe{{ID: ProbeIface, Name: "Interface"}, {ID: ProbeQUIC, Name: "QUIC (UDP/443)"}}
	results := map[ProbeID]ProbeResult{ProbeIface: {ID: ProbeIface, Status: StatusPass, Dur: time.Millisecond}}
	if s := BuildSnapshot(nil, probes, results); s.OK {
		t.Error("ok = true, want false: quic_udp_443 never reported")
	}
	// The control: the same graph, fully reported, is ok.
	results[ProbeQUIC] = ProbeResult{ID: ProbeQUIC, Status: StatusPass, Dur: time.Millisecond}
	if s := BuildSnapshot(nil, probes, results); !s.OK {
		t.Error("ok = false on a run where every check passed")
	}
}

// The file's status vocabulary is declared in internal/snapshot, and the
// runtime's in this package. They are written down twice on purpose, so this is
// what keeps them the same words: renaming a probe status is a change to a
// published format, and it has to fail here first.
func TestSnapshotStatusVocabularyMatchesProbeStatuses(t *testing.T) {
	want := map[Status]string{
		StatusPass: snapshot.StatusPass,
		StatusWarn: snapshot.StatusWarn,
		StatusFail: snapshot.StatusFail,
		StatusSkip: snapshot.StatusSkip,
		StatusNA:   snapshot.StatusNA,
	}
	if len(want) != len(statusNames) {
		t.Fatalf("%d probe statuses, %d mapped: a new one needs a place in the file format", len(statusNames), len(want))
	}
	for status, wire := range want {
		if got := status.String(); got != wire {
			t.Errorf("status %d serializes as %q, want %q", status, got, wire)
		}
		// No probe outcome may collide with the one value that means "this row
		// has no outcome".
		if wire == snapshot.StatusIncomplete {
			t.Errorf("probe status %d claims the incomplete marker", status)
		}
	}
}

func TestSnapshotPreservesCounterfactualDiagnosisAndAttemptEvidence(t *testing.T) {
	target := &Target{Raw: "example.com:443", Host: "example.com", Port: 443, Proto: ProtoNone}
	v4a, v4b := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	probes := []Probe{
		{ID: ProbeIface, Name: "Interface"},
		{ID: ProbeInternet, Name: "Internet"},
		{ID: ProbeDNS, Name: "DNS"},
		{ID: ProbeTargetTCP, Name: "Target TCP", Deps: []ProbeID{ProbeDNS}},
	}
	results := map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass, Dur: time.Millisecond},
		ProbeInternet: {Status: StatusPass, Dur: time.Millisecond,
			Families: &FamilyConnectivity{IPv4: FamilyReachable}},
		ProbeDNS: {Status: StatusPass, Dur: time.Millisecond, Addrs: []net.IP{v4a, v4b}},
		ProbeTargetTCP: {Status: StatusWarn, Dur: time.Millisecond, SelectedIP: v4b,
			Families: &FamilyConnectivity{IPv4: FamilyReachable}, Attempts: []Attempt{
				{IP: v4a, Dur: time.Millisecond, Err: errors.New("network unreachable"), Cause: ConnectionCauseUnreachable},
				{IP: v4b, Dur: time.Millisecond},
			}},
	}
	s := BuildSnapshot(target, probes, results)
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Diagnosis.Findings) != 1 || decoded.Diagnosis.Findings[0].ID != string(DiagnosisPartialReachability) {
		t.Fatalf("diagnosis = %+v", decoded.Diagnosis)
	}
	finding := decoded.Diagnosis.Findings[0]
	if finding.Counterfactual == nil || finding.Counterfactual.Variable != string(CounterfactualResolvedAddress) ||
		len(finding.Counterfactual.Alternatives) != 2 {
		t.Errorf("counterfactual = %+v", finding.Counterfactual)
	}
	attempts := decoded.Checks[3].Observed.Attempts
	if len(attempts) != 2 || attempts[0].Cause != ConnectionCauseUnreachable || attempts[0].Aborted {
		t.Errorf("attempt evidence = %+v", attempts)
	}
}

// Route decisions reach the artifact field for field, and a field the platform
// never supplied stays out of it rather than landing as a zero.
func TestBuildSnapshotCarriesRouteDecisions(t *testing.T) {
	tunnel := tunneled(decisionTo("198.51.100.7", "wg0", "10.20.0.0/16"), "wireguard")
	tunnel.Source, tunnel.MTU, tunnel.Table = net.ParseIP("10.20.0.2"), 1420, "table 51820"
	tunnel.Metric, tunnel.MetricKnown = 0, true
	tunnel.Reason = RouteReasonMoreSpecific
	tunnel.Competing = []CompetingRoute{{Iface: "wlan0", Metric: 600}}
	unreachable := RouteDecision{Destination: net.ParseIP("203.0.113.9"), Family: counterfactualIPv4, Unreachable: true}
	probes := []Probe{{ID: ProbeTargetTCP, Name: "Target"}}
	res := map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusFail, Dur: time.Millisecond, Routes: []RouteDecision{tunnel, unreachable}}}
	s := BuildSnapshot(nil, probes, res)
	got := s.Checks[0].Observed.Routes
	if len(got) != 2 {
		t.Fatalf("routes = %+v, want two", got)
	}
	want := snapshot.Route{
		Destination: "198.51.100.7", Family: "ipv4", Interface: "wg0", Source: "10.20.0.2",
		Prefix: "10.20.0.0/16", Metric: got[0].Metric, Table: "table 51820", InterfaceMTU: 1420,
		Tunnel: snapshot.TunnelStateTunnel, TunnelKind: "wireguard", Reason: "more_specific_than_default",
		Competing: []snapshot.CompetingRoute{{Interface: "wlan0", Metric: 600}},
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("converted route =\n%+v\nwant\n%+v", got[0], want)
	}
	if got[0].Metric == nil || *got[0].Metric != 0 {
		t.Errorf("a known metric of 0 converted to %v, want a recorded zero", got[0].Metric)
	}
	if got[1].Metric != nil || got[1].Interface != "" || !got[1].Unreachable {
		t.Errorf("an unreachable destination converted to %+v, want no invented fields", got[1])
	}
}

// A run on a platform netdoc cannot ask writes no routes key at all, which a
// reader must not confuse with a destination that had no route.
func TestBuildSnapshotOmitsRoutesWhenThePlatformAnsweredNothing(t *testing.T) {
	probes := []Probe{{ID: ProbeTargetTCP, Name: "Target"}}
	res := map[ProbeID]ProbeResult{ProbeTargetTCP: {Status: StatusPass, Dur: time.Millisecond}}
	s := BuildSnapshot(nil, probes, res)
	if s.Checks[0].Observed != nil && s.Checks[0].Observed.Routes != nil {
		t.Errorf("routes = %+v, want none", s.Checks[0].Observed.Routes)
	}
	data, err := snapshot.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "routes") {
		t.Errorf("a run with no route decisions wrote a routes key:\n%s", data)
	}
}

// probeIDs is the executed graph's order, which is what the interpretation pass
// takes and what the snapshot records.
func probeIDs(probes []Probe) []ProbeID {
	order := make([]ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
	}
	return order
}

// The compatibility Evidence field and the typed CausalEvidence beside it are
// two spellings of one fact, and a snapshot carrying both has to agree with
// itself: internal/snapshot refuses a file whose Evidence is not the
// projection of its causal evidence. The projection rule is written in two
// places, because the file format cannot import this package and this package
// owns the live finding, so the two are pinned here.
//
// The evidence below is deliberately awkward for the rule: a repeated check, a
// not-evaluated item that supplies no observation, and a later observation of
// a row that was already cited. If EvidenceRows and the validator ever stop
// agreeing about any of those, Encode refuses this snapshot.
func TestBuiltSnapshotEvidenceProjectionsAgree(t *testing.T) {
	finding := DiagnosisFinding{
		ID: DiagnosisSystemDNSFailure, Verdict: VerdictDNS, Summary: "The system resolver is failing.",
		Focus: ProbeDNS, Confidence: ConfidenceHigh,
		Evidence: []CausalEvidence{
			{Kind: EvidenceSupport, Check: ProbeDNS, Observation: ObservationStatusFail},
			{Kind: EvidenceNotEvaluated, Check: ProbeTargetTCP, Observation: ObservationStatusSkip, Reason: NotEvaluatedPrerequisite},
			{Kind: EvidenceRuledOut, Check: ProbeDNSPublic, Observation: ObservationDNSAnswers, Candidate: DiagnosisDNSNameNotFound},
			{Kind: EvidenceSupport, Check: ProbeDNS, Observation: ObservationCause},
		},
	}
	s := snapshot.Snapshot{
		Checks: []snapshot.Check{
			{ID: string(ProbeDNS), Name: "DNS", Status: snapshot.StatusFail, Cause: "timeout", Ran: true, DurationMs: 1},
			{ID: string(ProbeDNSPublic), Name: "Public DNS", Status: snapshot.StatusPass, Ran: true, DurationMs: 1,
				Observed: &snapshot.Observed{Addresses: []string{"192.0.2.1"}}},
			{ID: string(ProbeTargetTCP), Name: "TCP", Status: snapshot.StatusSkip},
		},
		Diagnosis: snapshot.Diagnosis{
			Verdict: finding.Verdict, Summary: finding.Summary, Blamed: string(ProbeDNS), FailedStage: string(ProbeDNS),
			Findings: []snapshot.Finding{{
				ID: string(finding.ID), Verdict: finding.Verdict, Summary: finding.Summary,
				Focus: string(finding.Focus), Confidence: string(finding.Confidence),
			}},
		},
	}
	for _, id := range finding.EvidenceRows() {
		s.Diagnosis.Findings[0].Evidence = append(s.Diagnosis.Findings[0].Evidence, string(id))
	}
	for _, e := range finding.Evidence {
		s.Diagnosis.Findings[0].CausalEvidence = append(s.Diagnosis.Findings[0].CausalEvidence, snapshot.CausalEvidence{
			Kind: string(e.Kind), Check: string(e.Check), Observation: string(e.Observation),
			Value: e.Value, Candidate: string(e.Candidate), Reason: string(e.Reason),
		})
	}
	if _, err := snapshot.Encode(s); err != nil {
		t.Fatalf("EvidenceRows no longer produces the projection the snapshot format validates: %v", err)
	}
}

// The graph netdoc builds has to be a graph the artifact can state. Encode
// refuses a dependency naming no row, a dependency counted twice, and a cycle,
// so a probe that gains a dependency on a row the graph does not always carry
// beside it, or a selection that keeps a dependent without what it waits on,
// fails here rather than publishing a run that could not have executed.
func TestBuiltSnapshotDependencyGraphIsPublishable(t *testing.T) {
	ops := &netops{}
	targets := []*Target{nil}
	for proto := range protoNames {
		targets = append(targets, &Target{Raw: "example.com", Host: "example.com", Port: 443, Proto: Proto(proto)})
	}
	selections := []ProbeSelection{{}, {NoReferenceEgress: true}}
	for _, id := range selectableProbeIDs() {
		selections = append(selections, ProbeSelection{Check: probeSet(id)}, ProbeSelection{Skip: probeSet(id)})
	}
	for _, target := range targets {
		name := "generic"
		if target != nil {
			name = target.Proto.String()
		}
		// Naming the opt-in row explicitly keeps the widest graph in the set.
		full := ops.buildProbes(target, DefaultPublicDNS, true, ProbePMTU)
		for _, selection := range selections {
			probes := selection.Apply(full)
			if _, err := snapshot.Encode(BuildSnapshot(target, probes, nil)); err != nil {
				t.Errorf("%s graph with selection check=%v skip=%v reference=%v: %v",
					name, selection.Check, selection.Skip, !selection.NoReferenceEgress, err)
			}
		}
	}
}

// The producer's own derivation of ran and the format's rule about it are two
// halves of one contract, and the executor is what joins them: every probe the
// DAG builds is timed, and the one result the scheduler records without
// calling a probe is a prerequisite skip. This runs the real executor over a
// graph that produces each of those and holds the artifact to the format's
// rule, so a change to either half that parts them fails here.
func TestExecutedRunsAgreeWithTheFormatAboutWhatRan(t *testing.T) {
	probes := []Probe{
		{ID: ProbeIface, Name: "Interface", Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			return ProbeResult{Status: StatusPass}
		})},
		{ID: ProbeDNS, Name: "DNS", Deps: []ProbeID{ProbeIface}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			return ProbeResult{Status: StatusFail, Detail: "no answer"}
		})},
		// Skipped by the scheduler, never called.
		{ID: ProbeTargetTCP, Name: "TCP", Deps: []ProbeID{ProbeDNS}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			t.Error("a probe behind a failed prerequisite was executed")
			return ProbeResult{Status: StatusPass}
		})},
		// Executed and inapplicable, which is the shape N/A really has.
		{ID: ProbeQUIC, Name: "QUIC", Deps: []ProbeID{ProbeIface}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			return ProbeResult{Status: StatusNA, Detail: "no address family available"}
		})},
	}
	results := RunAll(context.Background(), probes, DefaultProbeTimeout)
	artifact := BuildSnapshot(nil, probes, results)
	// One probe never reports, which is how an interrupted run leaves a row.
	artifact.Checks = append(artifact.Checks, snapshot.Check{ID: string(ProbeTLS), Name: "TLS", Status: snapshot.StatusIncomplete})

	want := map[ProbeID]struct {
		status string
		ran    bool
	}{
		ProbeIface:     {snapshot.StatusPass, true},
		ProbeDNS:       {snapshot.StatusFail, true},
		ProbeTargetTCP: {snapshot.StatusSkip, false},
		ProbeQUIC:      {snapshot.StatusNA, true},
		ProbeTLS:       {snapshot.StatusIncomplete, false},
	}
	for _, c := range artifact.Checks {
		expected, known := want[ProbeID(c.ID)]
		if !known {
			t.Fatalf("unexpected row %q", c.ID)
		}
		if c.Status != expected.status || c.Ran != expected.ran {
			t.Errorf("row %q = %s/ran=%t, want %s/ran=%t", c.ID, c.Status, c.Ran, expected.status, expected.ran)
		}
		if snapshot.ExecutionContradicts(c) {
			t.Errorf("the producer wrote row %q, which the format calls impossible: %s/ran=%t", c.ID, c.Status, c.Ran)
		}
	}
	if _, err := snapshot.Encode(artifact); err != nil {
		t.Fatalf("the format refused an artifact the executor produced: %v", err)
	}
}
