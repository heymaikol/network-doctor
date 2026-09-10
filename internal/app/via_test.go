// --via: what the local side forwards, what it does with the answer, and the
// line it keeps between a broken remote network and a broken connection.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// remoteTool is a plausible far end: a different build, on a different
// operating system, on a different architecture from the one running the test.
// Everything asserted about provenance reads one of these three fields.
var remoteTool = snapshot.Tool{Version: "9.9.9", OS: "windows", Arch: "amd64"}

// stubRemote replaces the SSH transport and records what it was asked to do.
func stubRemote(t *testing.T, resp remote.Response, err error) *remote.Request {
	t.Helper()
	orig := remoteRun
	t.Cleanup(func() { remoteRun = orig })
	var seen remote.Request
	remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
		seen = req
		return resp, err
	}
	return &seen
}

func remoteAnswer(ok bool) remote.Response {
	rep := &report.Report{
		Version: remoteTool.Version, OK: ok, Verdict: diagnostic.VerdictOK,
		Summary: "Everything checked works.",
		Target:  &report.Target{Host: "example.com", Port: 443, Protocol: "tcp"},
		Checks:  []report.Check{{ID: "dns", Name: "DNS", Status: "PASS", Detail: "resolved"}},
	}
	if !ok {
		rep.Verdict, rep.FailedStage, rep.Summary = diagnostic.VerdictNetwork, "internet", "No route to the internet."
		rep.Checks = append(rep.Checks, report.Check{ID: "internet", Name: "Internet", Status: "FAIL", Detail: "unreachable", Fix: "check the uplink"})
	}
	return remote.Response{
		Protocol: remote.Protocol, Tool: remoteTool, Report: rep,
		Snapshot: &snapshot.Snapshot{
			Schema: snapshot.Schema, CreatedAt: "2026-03-04T05:06:07Z", Tool: remoteTool, OK: ok,
			Target: &snapshot.Target{Raw: "example.com", Host: "example.com", Port: 443, Protocol: "tcp"},
			Checks: []snapshot.Check{{ID: "dns", Name: "DNS", Status: snapshot.StatusPass}},
		},
	}
}

func TestRunViaSpendsTheRemoteDiagnosisExitCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
		want int
	}{
		{"healthy", true, 0},
		{"a failed check", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRemote(t, remoteAnswer(tc.ok), nil)
			var stdout, stderr bytes.Buffer
			if got := run([]string{"--via", "server", "example.com"}, &stdout, &stderr); got != tc.want {
				t.Fatalf("exit = %d, want %d; stderr: %s", got, tc.want, stderr.String())
			}
			if !strings.Contains(stdout.String(), "checks:") {
				t.Errorf("stdout = %q, want the report", stdout.String())
			}
		})
	}
}

func TestRunViaKeepsATransportFailureOutOfTheDiagnosisCodes(t *testing.T) {
	// The whole point of the separation: this must not be mistakable for the
	// exit 1 a remote network that fails a check produces.
	stubRemote(t, remote.Response{}, errors.New("server: ssh could not open the connection"))
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing said about a diagnosis that never happened", stdout.String())
	}
	if !strings.Contains(stderr.String(), "ssh could not open the connection") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunViaSpendsTheInterruptedCodeWhenItIsTheOneThatStopped(t *testing.T) {
	// Quitting before the chain finished is exit 1 everywhere else in netdoc,
	// and a --via run that the user cancelled is that, not a broken connection.
	orig := remoteRun
	t.Cleanup(func() { remoteRun = orig })
	remoteRun = func(ctx context.Context, _, _ string, _ remote.Request) (remote.Response, error) {
		cancelSelf(t)
		<-ctx.Done()
		return remote.Response{}, errors.New("server: the run was interrupted")
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "example.com"}, &stdout, &stderr); got != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "interrupted") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// cancelSelf raises the interrupt the signal handler in runVia is watching for,
// which is the only way to reach that path without a second signal mechanism.
func cancelSelf(t *testing.T) {
	t.Helper()
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Signal(os.Interrupt); err != nil {
		t.Skipf("this platform cannot raise an interrupt at itself: %v", err)
	}
}

func TestRunViaJSONLeavesStdoutTheReportAndNothingElse(t *testing.T) {
	stubRemote(t, remoteAnswer(true), nil)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "--json", "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not the report alone: %v\n%s", err, stdout.String())
	}
	if rep.Version != remoteTool.Version {
		t.Errorf("version = %q, want the remote build's", rep.Version)
	}
	// Provenance belongs on stderr, so a pipe reading --via output sees exactly
	// what it sees for a local run.
	if !strings.Contains(stderr.String(), "Diagnosed on server by netdoc 9.9.9 (windows/amd64)") {
		t.Errorf("stderr = %q, want the remote build named", stderr.String())
	}
}

func TestRunViaForwardsTheUserSpellingAndResolvesNothingLocally(t *testing.T) {
	// An interface name that exists on no machine running this test. A local
	// run would reject it here; --via must not, because it names a NIC on the
	// far end and only the far end can resolve it.
	seen := stubRemote(t, remoteAnswer(true), nil)
	var stdout, stderr bytes.Buffer
	args := []string{
		"--via", "ideapad", "--iface", "Ethernet 4", "--timeout", "7s",
		"--public-dns", "9.9.9.9", "--check", "dns", "--skip", "quic_udp_443", "example.com:8443",
	}
	if got := run(args, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if seen.Target != "example.com:8443" {
		t.Errorf("target = %q, want the spelling the user typed", seen.Target)
	}
	if seen.Iface != "Ethernet 4" {
		t.Errorf("iface = %q, want it forwarded unresolved", seen.Iface)
	}
	if seen.TimeoutMs != 7000 || seen.PublicDNS != "9.9.9.9" {
		t.Errorf("request = %+v", *seen)
	}
	if strings.Join(seen.Check, ",") != "dns" || strings.Join(seen.Skip, ",") != "quic_udp_443" {
		t.Errorf("selection = check %q skip %q", seen.Check, seen.Skip)
	}
}

func TestRunViaStillRejectsATargetNoNetdocWouldProbe(t *testing.T) {
	stubRemote(t, remoteAnswer(true), nil)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "http://user:pw@example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "userinfo") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunViaWritesTheSnapshotTheRemoteBuilt(t *testing.T) {
	stubRemote(t, remoteAnswer(true), nil)
	path := filepath.Join(t.TempDir(), "remote.ndoc")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "--save", path, "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	// Same contract as a local --save: the artifact is the output.
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	// #nosec G304 -- path is this test's temporary snapshot file.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("the saved artifact is not a snapshot: %v", err)
	}
	// The machine that probed stamped this, and nothing here restamped it: a
	// snapshot that claimed the local build and OS would describe the wrong
	// machine, and the diagnosis in it was reached for the other one.
	if s.Tool != remoteTool {
		t.Errorf("tool = %+v, want the remote build's %+v", s.Tool, remoteTool)
	}
	if s.Tool.OS == runtime.GOOS && s.Tool.Arch == runtime.GOARCH && runtime.GOOS != "windows" {
		t.Error("the snapshot was restamped with this machine's platform")
	}
	if s.Redaction != nil {
		t.Errorf("an ordinary --save snapshot carries redaction metadata: %+v", s.Redaction)
	}
}

func TestRunViaSupportSanitizesOnTheMachineThatAskedForIt(t *testing.T) {
	stubRemote(t, remoteAnswer(true), nil)
	path := filepath.Join(t.TempDir(), "support.ndoc")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "--support", path, "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Sanitized support snapshot written") {
		t.Errorf("stderr = %q", stderr.String())
	}
	// #nosec G304 -- path is this test's temporary support snapshot.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if s.Redaction == nil || !s.Redaction.Sanitized || s.Redaction.Policy != snapshot.SupportRedactionPolicy {
		t.Errorf("redaction = %+v, want the support policy applied locally", s.Redaction)
	}
}

func TestRunViaRejectsTheModesItHasNoSessionFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"toolbox", []string{"--via", "server", "--toolbox"}},
		{"watch", []string{"--via", "server", "--watch", "example.com"}},
		{"compare", []string{"--via", "server", "--compare", "a.ndoc", "b.ndoc"}},
		{"peer-connect", []string{"--via", "server", "--peer-connect"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRemote(t, remoteAnswer(true), nil)
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "cannot be combined") {
				t.Errorf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestRunViaNeedsNoTerminal(t *testing.T) {
	// A --via run is headless, so the TUI's terminal requirement must not
	// reach it: stdout here is a buffer, which is not a terminal.
	stubRemote(t, remoteAnswer(true), nil)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--via", "server", "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if strings.Contains(stderr.String(), "not a terminal") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunRemoteWorkerTakesNothingElse(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{remote.WorkerFlag, "example.com"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit = %d, want 2", got)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want the protocol channel left clean", stdout.String())
	}
	if !strings.Contains(stderr.String(), "takes no other arguments") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestRunRemoteWorkerAnswersOnStdoutAndExitsZeroForAFailedNetwork(t *testing.T) {
	// Worker mode is checked before the flag set exists, so it is not a flag,
	// and it must not appear on the surfaces that document flags.
	var usage bytes.Buffer
	if code := run([]string{"--help"}, &usage, &bytes.Buffer{}); code != 0 {
		t.Fatalf("run(--help) = %d", code)
	}
	if strings.Contains(usage.String(), "remote-worker") {
		t.Error("--help advertises the internal worker mode")
	}

	stubFailingRun(t)
	fixedNow(t, "2026-03-04T05:06:07Z")
	// The resolver is spelled the long way on purpose: a local run records
	// the canonical form, so a remote one has to record the same text or a
	// --via snapshot differs from a local one for a setting nobody changed.
	stubWorkerStdin(t, `{"protocol":1,"target":"example.com:8443","timeout_ms":2500,"public_dns":"::ffff:9.9.9.9"}`)

	var stdout, stderr bytes.Buffer
	// Zero, with every check failing: the diagnosis rides inside the response,
	// and a nonzero status here would reach the local side as a broken
	// connection instead of a broken network.
	if got := run([]string{remote.WorkerFlag}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	var resp remote.Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("worker stdout is not one JSON object: %v\n%s", err, stdout.String())
	}
	if resp.Protocol != remote.Protocol || resp.Error != "" {
		t.Fatalf("response = %+v", resp)
	}
	if resp.Report == nil || resp.Report.OK || resp.Report.Target.Port != 8443 {
		t.Errorf("report = %+v", resp.Report)
	}
	if resp.Snapshot == nil || resp.Snapshot.Schema != snapshot.Schema || resp.Snapshot.OK {
		t.Errorf("snapshot = %+v", resp.Snapshot)
	}
	// Stamped by the machine that probed, which is what proves where a --via
	// answer came from.
	if resp.Snapshot.Tool.OS != runtime.GOOS || resp.Snapshot.Tool.Arch != runtime.GOARCH {
		t.Errorf("tool = %+v, want this machine's platform", resp.Snapshot.Tool)
	}
	if resp.Snapshot.CreatedAt != "2026-03-04T05:06:07Z" {
		t.Errorf("created_at = %q", resp.Snapshot.CreatedAt)
	}
	if resp.Snapshot.Options.ProbeTimeoutMs != 2500 || resp.Snapshot.Options.PublicDNS != "9.9.9.9" {
		t.Errorf("options = %+v, want the request's settings recorded", resp.Snapshot.Options)
	}
}

func TestRunRemoteWorkerRefusesABadRequestWithoutRunningProbes(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Error("probes ran for a request that should have been refused")
		return nil
	}
	for _, tc := range []struct{ name, request, want string }{
		{"no timeout", `{"protocol":1}`, "-timeout must be positive"},
		{"a target netdoc rejects", `{"protocol":1,"timeout_ms":1000,"target":"http://user:pw@h"}`, "userinfo"},
		{"a resolver that is not an IP", `{"protocol":1,"timeout_ms":1000,"public_dns":"not-an-ip"}`, "is not an IP address"},
		{"an unknown probe", `{"protocol":1,"timeout_ms":1000,"check":["nope"]}`, "nope"},
		{"an empty probe id", `{"protocol":1,"timeout_ms":1000,"check":[""]}`, "empty probe ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWorkerStdin(t, tc.request)
			var stdout, stderr bytes.Buffer
			if got := run([]string{remote.WorkerFlag}, &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0: a refusal is still a completed exchange", got)
			}
			var resp remote.Response
			if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(resp.Error, tc.want) {
				t.Errorf("error = %q, want it to mention %q", resp.Error, tc.want)
			}
		})
	}
}

// A working http:// proxy row is a PASS, and a PASS prints no fix line. The
// cleartext observation is the exception the renderer has to know about, or the
// advice the probe wrote is never read by anyone.
func TestReportTextShowsCleartextAdviceOnAPassingProxyRow(t *testing.T) {
	rep := report.Report{
		Version: "1.2.3", Verdict: diagnostic.VerdictOK, Summary: "The network works.",
		Checks: []report.Check{
			{ID: "dns", Name: "DNS", Status: "PASS", Detail: "resolved", Fix: "not shown for a pass"},
			{
				ID: "proxy_connect", Name: "Internet (env proxy)", Status: "PASS",
				Detail: "proxy tunnels; the CONNECT destination hostname is sent to the proxy without TLS",
				Fix:    "an http:// proxy sends the CONNECT destination hostname in cleartext",

				ConnectCleartext: true,
			},
		},
	}
	text := reportText(rep)
	if !strings.Contains(text, "fix: an http:// proxy sends the CONNECT destination hostname in cleartext") {
		t.Errorf("the cleartext advice never reached the report:\n%s", text)
	}
	if strings.Contains(text, "not shown for a pass") {
		t.Errorf("an ordinary passing row started printing its fix:\n%s", text)
	}
}

func TestReportTextSaysTheVerdictAndCleansWhatTheProbesSaw(t *testing.T) {
	rep := report.Report{
		Version: "1.2.3",
		Target:  &report.Target{Host: "example.com", Port: 443, Protocol: "tcp"},
		Verdict: diagnostic.VerdictNetwork, Summary: "No route to the internet.",
		Checks: []report.Check{
			{ID: "dns", Name: "DNS", Status: "PASS", Detail: "resolved \x1b[31mfast\x1b[0m", Fix: "not shown for a pass"},
			{ID: "internet", Name: "Internet", Status: "FAIL", Detail: "unreachable", Fix: "check the uplink"},
		},
		Findings: []report.Finding{{ID: "no_route", Remediation: &report.Remediation{
			Action: "Bring the link up", Why: "the interface is down",
			Steps: []string{"plug it in"}, Command: []string{"ip", "link"}, Expect: "state UP",
		}}},
	}
	text := reportText(rep)
	for _, want := range []string{
		"version: 1.2.3", "target: example.com:443 (tcp)", "verdict: FAIL: No route to the internet.",
		"next action: Bring the link up", "why: the interface is down", "step: plug it in",
		"run (suggested, not executed): ip link", "expect: state UP",
		"[PASS] DNS: resolved fast", "[FAIL] Internet: unreachable", "fix: check the uplink",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report text is missing %q:\n%s", want, text)
		}
	}
	if strings.ContainsRune(text, 0x1b) {
		t.Errorf("an escape sequence reached the terminal:\n%q", text)
	}
	if strings.Contains(text, "not shown for a pass") {
		t.Error("a passing row printed a fix")
	}
	// An unknown verdict from a newer netdoc must not read as healthy.
	rep.Verdict = "something-this-build-has-never-heard-of"
	if !strings.Contains(reportText(rep), "verdict: FAIL:") {
		t.Error("an unrecognized verdict was presented as something other than a failure")
	}
}

// stubWorkerStdin hands the worker one request over a stream that stays open,
// which is what the local side holds while it waits for the answer.
func stubWorkerStdin(t *testing.T, request string) {
	t.Helper()
	orig := workerStdin
	t.Cleanup(func() { workerStdin = orig })
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	workerStdin = io.MultiReader(strings.NewReader(request), blockUntilClosed{held})
}

type blockUntilClosed struct{ done <-chan struct{} }

func (b blockUntilClosed) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func stubFailingRun(t *testing.T) {
	t.Helper()
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		for _, p := range probes {
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusFail, Dur: 2 * time.Millisecond}
		}
		return results
	}
}

// The second-opinion resolver is chosen per address family, and --via runs the
// probes on another machine: a dual-stack caller resolving the default for an
// IPv6-only remote would pin it to a family it cannot use, over an instruction
// the user never gave. So the address field carries what it has always
// carried, and whether anyone named it crosses beside it for the remote to act
// on. A netdoc too old to read that field sees the request it has always seen.
func TestRunViaLetsTheRemoteChooseItsOwnSecondOpinion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantDNS  string
		wantAuto bool
	}{
		{"default", nil, diagnostic.DefaultPublicDNS, true},
		{"explicit address", []string{"--public-dns", "8.8.8.8"}, "8.8.8.8", false},
		{"explicit IPv6 address", []string{"--public-dns", "2001:4860:4860::8888"}, "2001:4860:4860::8888", false},
		{"disabled", []string{"--public-dns="}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := stubRemote(t, remoteAnswer(true), nil)
			var stdout, stderr bytes.Buffer
			args := append([]string{"--via", "ideapad"}, tc.args...)
			if got := run(append(args, "example.com"), &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			if seen.PublicDNS != tc.wantDNS || seen.PublicDNSAuto != tc.wantAuto {
				t.Errorf("request public DNS = %q auto=%v, want %q auto=%v",
					seen.PublicDNS, seen.PublicDNSAuto, tc.wantDNS, tc.wantAuto)
			}
			// The wire field stays what every protocol 1 netdoc can parse, so
			// the graceful downgrade is a downgrade and not a rejection.
			if seen.PublicDNS != "" && net.ParseIP(seen.PublicDNS) == nil {
				t.Errorf("request public DNS = %q, want an address or empty", seen.PublicDNS)
			}
		})
	}
}

// The worker end of the same contract, including the pair of mixed versions
// that share protocol 1. A request that says nobody named the resolver builds
// the automatic row here, on the machine the probes run on. A request without
// that field is an older netdoc's, and an older netdoc meant the address it
// sent: reinterpreting its default as automatic would answer a question it
// never asked.
func TestDiagnoseRemoteBuildsTheDefaultSecondOpinionLocally(t *testing.T) {
	for _, tc := range []struct {
		name, publicDNS string
		auto            bool
		wantRow         string
	}{
		{"default", diagnostic.DefaultPublicDNS, true, "DNS (public)"},
		{"explicit address", "8.8.8.8", false, "DNS (public 8.8.8.8)"},
		{"legacy client sending its own default", "8.8.8.8", false, "DNS (public 8.8.8.8)"},
		{"disabled", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := runAll
			t.Cleanup(func() { runAll = orig })
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
				for _, p := range probes {
					results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
				}
				return results
			}
			rep, snap, err := diagnoseRemote(context.Background(), remote.Request{
				Protocol: remote.Protocol, Target: "example.com",
				PublicDNS: tc.publicDNS, PublicDNSAuto: tc.auto, TimeoutMs: 1000,
			})
			if err != nil {
				t.Fatalf("diagnoseRemote: %v", err)
			}
			got := ""
			for _, c := range rep.Checks {
				if c.ID == string(diagnostic.ProbeDNSPublic) {
					got = c.Name
				}
			}
			if got != tc.wantRow {
				t.Errorf("dns_public row = %q, want %q", got, tc.wantRow)
			}
			// The snapshot records both halves of what the run was given: the
			// address, which is all options.public_dns has ever held, and
			// separately whether anyone named it, so a later comparison can
			// tell "netdoc chose" from "the user chose".
			if snap.Options.PublicDNS != tc.publicDNS || snap.Options.PublicDNSAuto != tc.auto {
				t.Errorf("snapshot options = %+v, want %q auto=%v", snap.Options, tc.publicDNS, tc.auto)
			}
		})
	}
}
