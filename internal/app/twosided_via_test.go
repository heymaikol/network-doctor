package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func resultsWithTargetStatus(probes []diagnostic.Probe, status string) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
	for _, probe := range probes {
		if probe.ID == diagnostic.ProbeTargetTCP && status == snapshot.StatusIncomplete {
			continue
		}
		probeStatus := diagnostic.StatusPass
		if probe.ID == diagnostic.ProbeTargetTCP {
			switch status {
			case snapshot.StatusFail:
				probeStatus = diagnostic.StatusFail
			case snapshot.StatusSkip:
				probeStatus = diagnostic.StatusSkip
			case snapshot.StatusNA:
				probeStatus = diagnostic.StatusNA
			}
		}
		results[probe.ID] = diagnostic.ProbeResult{ID: probe.ID, Status: probeStatus, Dur: time.Millisecond}
	}
	return results
}

func responseForLiveRequest(req remote.Request, targetStatus string) (remote.Response, error) {
	var target *diagnostic.Target
	var err error
	if req.Target != "" {
		target, err = diagnostic.ParseTarget(req.Target)
		if err != nil {
			return remote.Response{}, err
		}
	}
	checks, skips := probeList{}, probeList{}
	for _, id := range req.Check {
		checks = append(checks, diagnostic.ProbeID(id))
	}
	for _, id := range req.Skip {
		skips = append(skips, diagnostic.ProbeID(id))
	}
	h := headless{
		target: target, selection: diagnostic.ProbeSelection{Check: checks.set(), Skip: skips.set()},
		check: checks, skip: skips, publicDNS: req.PublicDNS, timeout: time.Duration(req.TimeoutMs) * time.Millisecond,
	}
	probes := h.selection.BuildProbesFromSources(target, nil, req.PublicDNS, req.PublicDNSAuto)
	results := resultsWithTargetStatus(probes, targetStatus)
	rep := buildReport(target, probes, results)
	rep.Version = remoteTool.Version
	snap := buildSnapshotArtifact(h, probes, results)
	snap.Tool = remoteTool
	return remote.Response{Protocol: remote.Protocol, Tool: remoteTool, Report: &rep, Snapshot: &snap}, nil
}

func stubLiveTwoSided(t *testing.T, localStatus, remoteStatus string) (*int, *remote.Request) {
	t.Helper()
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	localCalls := 0
	var request remote.Request
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		localCalls++
		return resultsWithTargetStatus(probes, localStatus)
	}
	remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
		request = req
		return responseForLiveRequest(req, remoteStatus)
	}
	return &localCalls, &request
}

func decodeTwoSided(t *testing.T, data []byte) compare.TwoSided {
	t.Helper()
	var result compare.TwoSided
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode two-sided result: %v\n%s", err, data)
	}
	return result
}

func TestRunLiveTwoSidedLocalizesCanonicalSnapshots(t *testing.T) {
	for _, test := range []struct {
		name, local, remote, side, id string
		exit                          int
		ambiguous                     bool
	}{
		{"local failure", snapshot.StatusFail, snapshot.StatusPass, compare.SideA, compare.TwoSidedOneSideFails, 1, true},
		{"remote failure", snapshot.StatusPass, snapshot.StatusFail, compare.SideB, compare.TwoSidedOneSideFails, 1, true},
		{"shared failure", snapshot.StatusFail, snapshot.StatusFail, compare.SideShared, compare.TwoSidedSharedFailure, 1, true},
		{"both pass", snapshot.StatusPass, snapshot.StatusPass, compare.SideNone, compare.TwoSidedNoFailure, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			localCalls, request := stubLiveTwoSided(t, test.local, test.remote)
			var stdout, stderr bytes.Buffer
			code := run([]string{"--two-sided", "--via", "ideapad", "--json", "--check", "target_tcp", "example.com"}, &stdout, &stderr)
			if code != test.exit {
				t.Fatalf("exit = %d, want %d; stderr: %s", code, test.exit, stderr.String())
			}
			if *localCalls != 1 || request.Target != "example.com" {
				t.Fatalf("local calls = %d, remote request = %+v", *localCalls, *request)
			}
			result := decodeTwoSided(t, stdout.Bytes())
			if result.Schema != compare.TwoSidedSchema || result.Diagnosis.Side != test.side || result.Diagnosis.ID != test.id {
				t.Errorf("result = schema %q, side %q, id %q", result.Schema, result.Diagnosis.Side, result.Diagnosis.ID)
			}
			if result.Diagnosis.Ambiguous != test.ambiguous {
				t.Errorf("ambiguous = %t, want %t", result.Diagnosis.Ambiguous, test.ambiguous)
			}
			if result.A.Tool.OS != runtime.GOOS || result.B.Tool != remoteTool {
				t.Errorf("tools = local %+v, remote %+v", result.A.Tool, result.B.Tool)
			}
			if result.A.Target != result.B.Target || !strings.Contains(result.A.Target, "example.com:443") {
				t.Errorf("targets = %q and %q", result.A.Target, result.B.Target)
			}
		})
	}
}

func TestRunLiveTwoSidedWithoutATargetRunsBothGenericDiagnoses(t *testing.T) {
	localCalls, request := stubLiveTwoSided(t, snapshot.StatusPass, snapshot.StatusPass)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--two-sided", "--via", "ideapad", "--json", "--check", "iface"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	result := decodeTwoSided(t, stdout.Bytes())
	if *localCalls != 1 || request.Target != "" || result.A.Target != "" || result.B.Target != "" {
		t.Errorf("local calls = %d, request target = %q, result targets = %q and %q", *localCalls, request.Target, result.A.Target, result.B.Target)
	}
}

func TestRunLiveTwoSidedIgnoresUnmeasuredDifferentials(t *testing.T) {
	for _, status := range []string{snapshot.StatusSkip, snapshot.StatusNA, snapshot.StatusIncomplete} {
		t.Run(status, func(t *testing.T) {
			stubLiveTwoSided(t, snapshot.StatusFail, status)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--two-sided", "--via", "ideapad", "--json", "--check", "target_tcp", "example.com"}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
			}
			result := decodeTwoSided(t, stdout.Bytes())
			if result.Diagnosis.Side != compare.SideNone {
				t.Errorf("side = %q, want none; an unmeasured remote row is not localization evidence", result.Diagnosis.Side)
			}
			for _, row := range result.Checks {
				if row.ID == string(diagnostic.ProbeTargetTCP) && row.Comparable {
					t.Errorf("target row with remote %s is comparable", status)
				}
			}
		})
	}
}

func TestRunLiveTwoSidedRefusesDifferentEffectiveTargets(t *testing.T) {
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		return resultsWithTargetStatus(probes, snapshot.StatusPass)
	}
	remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
		resp, err := responseForLiveRequest(req, snapshot.StatusPass)
		if err == nil {
			resp.Snapshot.Target.Host = "other.example"
		}
		return resp, err
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--two-sided", "--via", "ideapad", "--json", "--check", "target_tcp", "example.com"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "different targets") {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunLiveTwoSidedHumanOutputNamesBothVantages(t *testing.T) {
	stubLiveTwoSided(t, snapshot.StatusFail, snapshot.StatusPass)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--two-sided", "--via", "ideapad", "--check", "target_tcp", "example.com"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	for _, want := range []string{"LOCAL (SIDE A)", "ideapad (SIDE B)", "Failure placed on: side A"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout is missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunLiveTwoSidedAppliesSymmetricProbeOptions(t *testing.T) {
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	var localTimeout time.Duration
	var localIDs []string
	var request remote.Request
	var destination, command string
	runAll = func(_ context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		localTimeout = timeout
		for _, probe := range probes {
			localIDs = append(localIDs, string(probe.ID))
		}
		return resultsWithTargetStatus(probes, snapshot.StatusPass)
	}
	remoteRun = func(_ context.Context, dest, cmd string, req remote.Request) (remote.Response, error) {
		destination, command, request = dest, cmd, req
		return responseForLiveRequest(req, snapshot.StatusPass)
	}
	t.Setenv(remote.CommandEnv, "/opt/netdoc")
	var stdout, stderr bytes.Buffer
	args := []string{
		"--two-sided", "--via", "ideapad", "--json", "--timeout", "250ms", "--public-dns", "9.9.9.9",
		"--check", "target_tcp", "--skip", "path_mtu", "example.com",
	}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	if destination != "ideapad" || command != "/opt/netdoc" || request.Target != "example.com" {
		t.Errorf("destination = %q, command = %q, request = %+v", destination, command, request)
	}
	if localTimeout != 250*time.Millisecond || request.TimeoutMs != 250 || request.PublicDNS != "9.9.9.9" {
		t.Errorf("local timeout = %s, remote request = %+v", localTimeout, request)
	}
	if !slices.Equal(request.Check, []string{"target_tcp"}) || !slices.Equal(request.Skip, []string{"path_mtu"}) {
		t.Errorf("remote selection = check %v skip %v", request.Check, request.Skip)
	}
	if want := []string{"iface", "dns", "target_tcp"}; !slices.Equal(localIDs, want) {
		t.Errorf("local probes = %v, want %v", localIDs, want)
	}
	result := decodeTwoSided(t, stdout.Bytes())
	for _, caveat := range result.Caveats {
		if strings.Contains(caveat, "differ") {
			t.Errorf("matched options produced caveat %q", caveat)
		}
	}
}

func TestRunLiveTwoSidedStartsBothVantagesTogether(t *testing.T) {
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	localStarted, remoteStarted, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		close(localStarted)
		<-release
		return resultsWithTargetStatus(probes, snapshot.StatusPass)
	}
	remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
		close(remoteStarted)
		<-release
		return responseForLiveRequest(req, snapshot.StatusPass)
	}
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"--two-sided", "--via", "ideapad", "--json", "--check", "target_tcp", "example.com"}, &stdout, &stderr)
	}()
	for name, started := range map[string]<-chan struct{}{"local": localStarted, "remote": remoteStarted} {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			close(release)
			<-done
			t.Fatalf("%s diagnosis did not start while the other side was blocked", name)
		}
	}
	close(release)
	if code := <-done; code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
}

func TestRunLiveTwoSidedRemoteErrorCancelsLocalDiagnosis(t *testing.T) {
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	localStarted, localCancelled := make(chan struct{}), make(chan struct{})
	runAll = func(ctx context.Context, _ []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		close(localStarted)
		<-ctx.Done()
		close(localCancelled)
		return nil
	}
	remoteRun = func(_ context.Context, _, _ string, _ remote.Request) (remote.Response, error) {
		<-localStarted
		return remote.Response{}, errors.New("ideapad: ssh could not open the connection")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--two-sided", "--via", "ideapad", "--json", "example.com"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
	}
	select {
	case <-localCancelled:
	default:
		t.Error("remote failure did not cancel the local diagnosis")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "ssh could not open the connection") {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunLiveTwoSidedParentCancellationStopsBothDiagnoses(t *testing.T) {
	originalRunAll, originalRemoteRun := runAll, remoteRun
	t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
	localStarted, remoteStarted := make(chan struct{}), make(chan struct{})
	localCancelled, remoteCancelled := make(chan struct{}), make(chan struct{})
	runAll = func(ctx context.Context, _ []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		close(localStarted)
		<-ctx.Done()
		close(localCancelled)
		return nil
	}
	remoteRun = func(ctx context.Context, _, _ string, _ remote.Request) (remote.Response, error) {
		close(remoteStarted)
		<-ctx.Done()
		close(remoteCancelled)
		return remote.Response{}, ctx.Err()
	}
	target, err := diagnostic.ParseTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	h := headless{target: target, publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second, via: "ideapad", json: true}
	parent, cancel := context.WithCancel(context.Background())
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- runLiveTwoSided(parent, h, &stdout, &stderr) }()
	for _, started := range []<-chan struct{}{localStarted, remoteStarted} {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			cancel()
			<-done
			t.Fatal("both diagnoses did not start")
		}
	}
	cancel()
	if code := <-done; code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	for name, cancelled := range map[string]<-chan struct{}{"local": localCancelled, "remote": remoteCancelled} {
		select {
		case <-cancelled:
		default:
			t.Errorf("%s diagnosis did not observe cancellation", name)
		}
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "interrupted") {
		t.Errorf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestRunLiveTwoSidedRejectsAsymmetricAndUnrelatedFlagsBeforeStarting(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{"interface", []string{"--iface", "lo"}, "one interface selector cannot name both machines"},
		{"profile", []string{"--profile", "github"}, "cannot be combined with live -two-sided"},
		{"save", []string{"--save", dir + "/out.ndoc"}, "cannot be combined with live -two-sided"},
		{"support", []string{"--support", dir + "/out.ndoc"}, "cannot be combined with live -two-sided"},
		{"watch", []string{"--watch"}, "cannot be combined with live -two-sided"},
		{"toolbox", []string{"--toolbox"}, "cannot be combined with live -two-sided"},
		{"compare", []string{"--compare"}, "cannot be combined"},
		{"peer listener", []string{"--peer-listen", "127.0.0.1:0"}, "cannot be combined with live -two-sided"},
		{"peer connector", []string{"--peer-connect"}, "cannot be combined with live -two-sided"},
		{"history", []string{"--no-history"}, "cannot be combined with live -two-sided"},
		{"keys", []string{"--keys", "vim"}, "cannot be combined with live -two-sided"},
		{"artifact arguments", []string{"a.ndoc", "b.ndoc"}, "remove -via to read two snapshot files"},
	} {
		t.Run(test.name, func(t *testing.T) {
			originalRunAll, originalRemoteRun := runAll, remoteRun
			t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
			runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				t.Error("local diagnosis started for invalid arguments")
				return nil
			}
			remoteRun = func(context.Context, string, string, remote.Request) (remote.Response, error) {
				t.Error("remote diagnosis started for invalid arguments")
				return remote.Response{}, nil
			}
			args := append([]string{"--two-sided", "--via", "ideapad"}, test.args...)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
				t.Errorf("stdout = %q, stderr = %q, want %q", stdout.String(), stderr.String(), test.want)
			}
		})
	}
}

func TestRemoteRequestPreservesUnknownProtocolPMTUOptIn(t *testing.T) {
	for _, tc := range []struct {
		target      string
		check, skip probeList
		wantSkip    bool
	}{
		{target: "host:9999", wantSkip: true},
		{target: "host:9999", check: probeList{diagnostic.ProbeTargetTCP}, wantSkip: true},
		{target: "host:9999", check: probeList{diagnostic.ProbePMTU}},
		{target: "host:9999", check: probeList{diagnostic.ProbePMTU}, skip: probeList{diagnostic.ProbePMTU}, wantSkip: true},
		{target: "host:443"},
		{target: "ssh://host:9999"},
	} {
		target, err := diagnostic.ParseTarget(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		req := requestForRemote(headless{target: target, check: tc.check, skip: tc.skip})
		count := 0
		for _, id := range req.Skip {
			if id == string(diagnostic.ProbePMTU) {
				count++
			}
		}
		if (count == 1) != tc.wantSkip || count > 1 {
			t.Fatalf("target %s, check %v, skip %v: remote skip %v, want PMTU skip %t", tc.target, tc.check, tc.skip, req.Skip, tc.wantSkip)
		}
	}
}

func TestLiveTwoSidedPMTUSelectionDoesNotInventMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		args         []string
		wantPMTU     bool
	}{
		{name: "unknown", target: "host:9999"},
		{name: "known", target: "host:443", wantPMTU: true},
		{name: "explicit", target: "host:9999", args: []string{"--check", "path_mtu"}, wantPMTU: true},
		{name: "skipped", target: "host:9999", args: []string{"--skip", "path_mtu"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			originalRunAll, originalRemoteRun := runAll, remoteRun
			t.Cleanup(func() { runAll, remoteRun = originalRunAll, originalRemoteRun })
			var localIDs, remoteIDs []string
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				for _, p := range probes {
					localIDs = append(localIDs, string(p.ID))
				}
				return resultsWithTargetStatus(probes, snapshot.StatusPass)
			}
			remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
				resp, err := responseForLiveRequest(req, snapshot.StatusPass)
				if err == nil {
					for _, check := range resp.Report.Checks {
						remoteIDs = append(remoteIDs, check.ID)
					}
				}
				return resp, err
			}
			args := append([]string{"--two-sided", "--via", "ideapad"}, tc.args...)
			args = append(args, tc.target)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit %d: %s", code, &stderr)
			}
			if len(localIDs) == 0 || !slices.Equal(localIDs, remoteIDs) {
				t.Fatalf("measured probes differ: local %v, remote %v", localIDs, remoteIDs)
			}
			if got := slices.Contains(localIDs, string(diagnostic.ProbePMTU)); got != tc.wantPMTU {
				t.Fatalf("PMTU measured = %t, want %t", got, tc.wantPMTU)
			}
			if strings.Contains(stdout.String(), "different probes") {
				t.Fatalf("identical probe sets produced a false caveat:\n%s", &stdout)
			}
		})
	}
}
