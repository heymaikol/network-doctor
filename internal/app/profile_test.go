package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

func TestProfileCLIValidationAndDiscovery(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"list", []string{"--profile", "list"}, "github (no target)"},
		{"unknown", []string{"--profile", "GitHub"}, "unknown profile"},
		{"empty", []string{"--profile="}, "needs a name"},
		{"required target", []string{"--profile", "ssh"}, "requires a target"},
		{"forbidden target", []string{"--profile", "github", "example.com"}, "does not accept a target"},
		{"toolbox", []string{"--profile", "web", "--toolbox", "example.com"}, "profiles are headless"},
		{"keys", []string{"--profile", "web", "--keys", "vim", "example.com"}, "profiles are headless"},
		{"watch needs json", []string{"--profile", "github", "--watch"}, "requires -json"},
		{"compare", []string{"--profile", "github", "--compare", "a", "b"}, "cannot be combined"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(test.args, &stdout, &stderr)
			output := stdout.String() + stderr.String()
			if test.name == "list" {
				if code != 0 {
					t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
				}
			} else if code != 2 {
				t.Fatalf("exit = %d, want 2; output: %s", code, output)
			}
			if !strings.Contains(output, test.want) {
				t.Errorf("output = %q, want %q", output, test.want)
			}
		})
	}
}

func TestRunProfileJSONUsesStructuredComponents(t *testing.T) {
	stubPassingRun(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--profile", "github", "--json", "--no-history"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	var result profile.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("profile JSON: %v\n%s", err, stdout.String())
	}
	if result.Schema != profile.ReportSchema || result.Profile != "github" || result.ProfileVersion != 1 || len(result.Components) != 4 || !result.OK {
		t.Fatalf("result = %+v", result)
	}
	want := []string{"web", "api", "ssh", "ssh-alt"}
	for i, component := range result.Components {
		if component.ID != want[i] || component.Target == nil || component.Status != profile.StatusPass || len(component.Report.Checks) == 0 {
			t.Errorf("component %d = %+v", i, component)
		}
	}
}

func TestRunProfileSaveRoundTripRecordsComposedSelection(t *testing.T) {
	stubPassingRun(t)
	fixedNow(t, "2026-08-26T12:00:00Z")
	path := filepath.Join(t.TempDir(), "ssh-profile.ndoc")
	var stdout, stderr bytes.Buffer
	args := []string{"--profile", "ssh", "example.com", "--save", path, "--check", "quic_udp_443", "--skip", "path_mtu"}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	// #nosec G304 -- path is this test's temporary artifact.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := snapshot.DecodeProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Schema != snapshot.ProfileSchema || artifact.Profile.Name != "ssh" || len(artifact.Components) != 1 || !artifact.OK {
		t.Fatalf("artifact = %+v", artifact)
	}
	for _, component := range artifact.Components {
		check := component.Snapshot.Options.Check
		if !slices.Contains(check, "quic_udp_443") || !slices.Contains(check, component.Focus) || !slices.Equal(component.Snapshot.Options.Skip, []string{"path_mtu"}) {
			t.Errorf("component %s options = %+v", component.ID, component.Snapshot.Options)
		}
	}
	if _, err := snapshot.Decode(data); err == nil {
		t.Fatal("single-run decoder accepted profile artifact")
	}
}

func TestRunProfileSupportRedactsAllComponents(t *testing.T) {
	stubPassingRun(t)
	path := filepath.Join(t.TempDir(), "support-profile.ndoc")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--profile", "ssh", "server.internal", "--support", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	// #nosec G304 -- path is this test's temporary artifact.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := snapshot.DecodeProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Redaction == nil || !artifact.Redaction.Sanitized || !strings.Contains(stderr.String(), "Sanitized support profile snapshot written") {
		t.Fatalf("redaction = %+v; stderr: %s", artifact.Redaction, stderr.String())
	}
	for _, component := range artifact.Components {
		if component.Snapshot.Redaction == nil || component.Snapshot.Target.Host == "server.internal" {
			t.Errorf("component was not sanitized: %+v", component)
		}
	}
}

func TestRunProfileViaUsesOrdinaryRemoteRequests(t *testing.T) {
	original := remoteRun
	t.Cleanup(func() { remoteRun = original })
	var mu sync.Mutex
	var requests []remote.Request
	stubRemoteDirect(t, true)
	remoteRun = func(_ context.Context, dest, command string, req remote.Request, _ bool) (remote.Response, error) {
		if dest != "ideapad" || command != "" {
			t.Errorf("remote destination = %q, command = %q", dest, command)
		}
		target, err := diagnostic.ParseTarget(req.Target)
		if err != nil {
			t.Fatal(err)
		}
		focus := req.Check[len(req.Check)-1]
		rep := &report.Report{
			Version: remoteTool.Version, Target: &report.Target{Host: target.Host, Port: target.Port, Protocol: target.Proto.String()},
			Checks:  []report.Check{{ID: focus, Name: focus, Status: profile.StatusPass, Detail: "worked"}},
			Summary: "The selected service path works.", Verdict: diagnostic.VerdictOK, OK: true,
		}
		snap := &snapshot.Snapshot{Schema: snapshot.Schema, Tool: remoteTool, Target: &snapshot.Target{Raw: target.Raw, Host: target.Host, Port: target.Port, Protocol: target.Proto.String()}, Checks: []snapshot.Check{}}
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()
		return remote.Response{Protocol: remote.Protocol, Tool: remoteTool, Report: rep, Snapshot: snap}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--via", "ideapad", "--profile", "github", "--json", "--iface", "wlan0", "--public-dns", "9.9.9.9", "--timeout", "2s"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	var result profile.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 || len(result.Components) != 4 {
		t.Fatalf("requests = %d, components = %d", len(requests), len(result.Components))
	}
	targets := make([]string, len(requests))
	for i, req := range requests {
		targets[i] = req.Target
		if req.Iface != "wlan0" || req.PublicDNS != "9.9.9.9" || req.TimeoutMs != 2000 || len(req.Check) == 0 {
			t.Errorf("request = %+v", req)
		}
	}
	slices.Sort(targets)
	if want := []string{"https://api.github.com:443", "https://github.com:443", "ssh://github.com:22", "ssh://ssh.github.com:443"}; !slices.Equal(targets, want) {
		t.Errorf("targets = %v, want %v", targets, want)
	}
	if !strings.Contains(stderr.String(), "Diagnosed 4 profile components on ideapad") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// A profile component whose remote acquisition ran out of time stops the pass
// and names the component, rather than leaving the run waiting on a transport
// that is never going to answer. Nothing overlaps behind it, so the components
// after it are never asked for.
func TestRunProfileViaReportsARemoteTimeoutAsAComponentFailure(t *testing.T) {
	original := remoteRun
	t.Cleanup(func() { remoteRun = original })
	var mu sync.Mutex
	attempts := 0
	stubRemoteDirect(t, true)
	remoteRun = func(_ context.Context, _, _ string, _ remote.Request, _ bool) (remote.Response, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		return remote.Response{}, errors.New("ideapad: the remote run timed out after 1m20s")
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--via", "ideapad", "--profile", "github", "--json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no aggregate for a pass that never completed", stdout.String())
	}
	if !strings.Contains(stderr.String(), "timed out") {
		t.Errorf("stderr = %q, want the transport failure", stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	// Two: the refused attempt that would have opened the concurrent path, and
	// the ordinary one that replaces it and reports the failure.
	if attempts != 2 {
		t.Errorf("%d remote attempts, want the pass to stop at the first failed component", attempts)
	}
}

func TestProfilePassHonorsCancellation(t *testing.T) {
	original := runAll
	t.Cleanup(func() { runAll = original })
	runAll = func(ctx context.Context, _ []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		<-ctx.Done()
		return nil
	}
	definition, _ := profile.Builtins().Lookup("web")
	plan, err := definition.Plan("example.com")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = runProfilePass(ctx, headless{publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}, plan)
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestProfileJSONWatchWritesTimestampedNDJSON(t *testing.T) {
	stubPassingRun(t)
	definition, _ := profile.Builtins().Lookup("github")
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 1, cancel: cancel}
	base := headless{watch: true, json: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}
	if code := runProfile(ctx, base, plan, out, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	if strings.Contains(line, "\n") {
		t.Fatalf("watch output is not one JSON object per line:\n%s", buf.String())
	}
	var result profile.Result
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		t.Fatalf("watch JSON: %v\n%s", err, line)
	}
	if result.Ts == "" || len(result.Components) != 4 {
		t.Errorf("watch result = %+v", result)
	}
}

func TestProfileTextPreservesFindingEvidence(t *testing.T) {
	result := profile.Result{
		Title: "SSH", Aggregate: profile.Aggregate{Status: profile.StatusWarn, Summary: "Fallback works."},
		Components: []profile.Component{{
			ID: "ssh", Label: "Direct SSH", Focus: "ssh_banner", Status: profile.StatusFail,
			Target: &report.Target{Host: "example.com", Port: 22},
			Report: report.Report{
				Checks:   []report.Check{{ID: "target_tcp", Name: "TCP", Status: profile.StatusFail, Detail: "blocked"}},
				Findings: []report.Finding{{ID: "target_unreachable", Evidence: []string{"target_tcp"}}},
			},
		}},
	}
	text := profileText(result)
	for _, want := range []string{"SSH profile", "target_unreachable", "[FAIL] TCP: blocked", net.JoinHostPort("example.com", "22")} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
}
