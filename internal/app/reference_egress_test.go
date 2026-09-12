// --no-reference-egress at the command line: which rows a run keeps, what the
// contradiction with an explicit selector costs, what a --via worker is told,
// and what a snapshot records. The proof that no built-in destination is
// actually reached lives beside the probes, in
// internal/diagnostic/reference_policy_test.go; this file is about the
// invocation reaching that policy intact through every mode.

package app

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/heymaikol/network-doctor/internal/ui"
)

// capturePasses replaces the probe runner with one that records the rows each
// pass was given and passes them all. Nothing touches the network.
func capturePasses(t *testing.T) *[][]diagnostic.ProbeID {
	t.Helper()
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	var mu sync.Mutex
	var passes [][]diagnostic.ProbeID
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
		pass := make([]diagnostic.ProbeID, 0, len(probes))
		for _, p := range probes {
			// Timed, the way every probe the DAG builds is: a row that
			// reported an outcome ran, and the artifact says so.
			results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Dur: time.Millisecond}
			pass = append(pass, p.ID)
		}
		mu.Lock()
		passes = append(passes, pass)
		mu.Unlock()
		return results
	}
	return &passes
}

func hasProbe(pass []diagnostic.ProbeID, id diagnostic.ProbeID) bool {
	return slices.Contains(pass, id)
}

// referenceRows are the rows a target run with an automatic resolver reaches
// for on netdoc's own account. Asked of the policy rather than typed out, so
// this file cannot disagree with it.
func referenceRows(hasTarget, publicDNSNamed bool) []diagnostic.ProbeID {
	return diagnostic.ReferenceEgressProbes(hasTarget, publicDNSNamed)
}

func TestNoReferenceEgressDropsTheBuiltInRowsFromALocalRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		// keep is a row this shape must still run, or "" where the run keeps
		// nothing but local state.
		keep       diagnostic.ProbeID
		hasTarget  bool
		namedDNS   bool
		wantAbsent []diagnostic.ProbeID
	}{
		{
			name: "a target run keeps the target's own path",
			args: []string{"--json", "--no-reference-egress", "example.com"},
			keep: diagnostic.ProbeTargetTCP, hasTarget: true,
		},
		{
			name: "a generic run keeps only what it can observe locally",
			args: []string{"--json", "--no-reference-egress"},
			keep: diagnostic.ProbeIface,
		},
		{
			name: "a resolver the user named is the user's traffic",
			args: []string{"--json", "--no-reference-egress", "--public-dns", "9.9.9.9", "example.com"},
			keep: diagnostic.ProbeDNSPublic, hasTarget: true, namedDNS: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passes := capturePasses(t)
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			if len(*passes) != 1 {
				t.Fatalf("ran %d passes, want 1", len(*passes))
			}
			pass := (*passes)[0]
			for _, id := range referenceRows(tc.hasTarget, tc.namedDNS) {
				if hasProbe(pass, id) {
					t.Errorf("row %q ran under -no-reference-egress; rows were %v", id, pass)
				}
			}
			if tc.keep != "" && !hasProbe(pass, tc.keep) {
				t.Errorf("row %q did not run; rows were %v", tc.keep, pass)
			}
			// The report is the user-visible surface, and an omitted row is
			// absent from it rather than reported as skipped.
			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("stdout is not a report: %v\n%s", err, stdout.String())
			}
			for _, check := range rep.Checks {
				if slices.Contains(referenceRows(tc.hasTarget, tc.namedDNS), diagnostic.ProbeID(check.ID)) {
					t.Errorf("the report carries row %q", check.ID)
				}
			}
		})
	}
}

// Without the flag nothing moves. The same two invocations have to produce the
// graph they always did, reference rows included.
func TestWithoutTheFlagTheReferenceRowsStillRun(t *testing.T) {
	for _, args := range [][]string{{"--json", "example.com"}, {"--json"}} {
		passes := capturePasses(t)
		var stdout, stderr bytes.Buffer
		if got := run(args, &stdout, &stderr); got != 0 {
			t.Fatalf("exit = %d for %v; stderr: %s", got, args, stderr.String())
		}
		pass := (*passes)[0]
		for _, id := range referenceRows(len(args) > 1, false) {
			if !hasProbe(pass, id) {
				t.Errorf("%v: row %q is missing from an ordinary run; rows were %v", args, id, pass)
			}
		}
	}
}

// Watch Mode re-selects from a freshly built graph every pass, so the mode has
// to hold for pass three as firmly as for pass one.
func TestNoReferenceEgressHoldsAcrossWatchPasses(t *testing.T) {
	origEvery := ui.WatchEvery
	t.Cleanup(func() { ui.WatchEvery = origEvery })
	ui.WatchEvery = time.Millisecond
	passes := capturePasses(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 3, cancel: cancel}
	target, err := diagnostic.ParseTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	h := headless{
		target: target, watch: true, json: true,
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true,
		selection: diagnostic.ProbeSelection{NoReferenceEgress: true},
		timeout:   diagnostic.DefaultProbeTimeout,
	}
	if got := runHeadless(ctx, h, out, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if len(*passes) < 3 {
		t.Fatalf("ran %d passes, want at least 3", len(*passes))
	}
	for i, pass := range *passes {
		for _, id := range referenceRows(true, false) {
			if hasProbe(pass, id) {
				t.Errorf("pass %d ran row %q; rows were %v", i, id, pass)
			}
		}
	}
}

// A selector cannot compose its way past the mode, and it is not allowed to
// fail quietly either: the contradiction is named and the run refuses before a
// probe starts. Flag order does not enter into it.
func TestNoReferenceEgressRefusesAContradictorySelector(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"the direct-egress row", []string{"--no-reference-egress", "--check", "internet_tcp", "example.com"}, 2},
		{"the selector first", []string{"--check", "internet_tcp", "--no-reference-egress", "example.com"}, 2},
		{"the QUIC row", []string{"--no-reference-egress", "--check", "quic_udp_443", "example.com"}, 2},
		{"the proxy row", []string{"--no-reference-egress", "--check", "proxy_connect", "example.com"}, 2},
		{"the encrypted-DNS row", []string{"--no-reference-egress", "--check", "dns_encrypted", "example.com"}, 2},
		{"one contradiction among several rows", []string{"--no-reference-egress", "--check", "tls,internet_tcp", "example.com"}, 2},
		{"the automatic second opinion", []string{"--no-reference-egress", "--check", "dns_public", "example.com"}, 2},
		{"the generic DNS row, which resolves a compiled-in name", []string{"--no-reference-egress", "--check", "dns"}, 2},
		// The other side of the same rule: with a target, the DNS row asks
		// about the user's own host, so selecting it is no contradiction.
		{"the target's own DNS row", []string{"--json", "--no-reference-egress", "--check", "dns", "example.com"}, 0},
		// And a second opinion the user pointed somewhere is the user's.
		{"a named resolver's row", []string{"--json", "--no-reference-egress", "--public-dns", "9.9.9.9", "--check", "dns_public", "example.com"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capturePasses(t)
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Fatalf("exit = %d, want %d; stderr: %s", got, tc.want, stderr.String())
			}
			if tc.want != 2 {
				return
			}
			msg := stderr.String()
			if !strings.Contains(msg, "-no-reference-egress") || !strings.Contains(msg, "-check") {
				t.Errorf("stderr = %q, want both halves of the contradiction named", msg)
			}
		})
	}
}

// --skip is the compatible direction and stays compatible: naming a row the
// mode already removed changes nothing, and naming an unrelated one removes
// only that row.
func TestNoReferenceEgressComposesWithSkip(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		gone diagnostic.ProbeID
	}{
		{"skipping a row the mode already removed", []string{"--json", "--no-reference-egress", "--skip", "internet_tcp", "example.com"}, diagnostic.ProbeInternet},
		{"skipping an unrelated row", []string{"--json", "--no-reference-egress", "--skip", "ssid", "example.com"}, diagnostic.ProbeSSID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passes := capturePasses(t)
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			pass := (*passes)[0]
			if hasProbe(pass, tc.gone) {
				t.Errorf("row %q survived; rows were %v", tc.gone, pass)
			}
			if !hasProbe(pass, diagnostic.ProbeTargetTCP) {
				t.Errorf("the target's own row did not run; rows were %v", pass)
			}
		})
	}
}

// --via has to honor exactly the same policy, and it has to do it without a new
// protocol field: the decision is resolved here and travels as the ordinary
// skips every protocol 1 netdoc already applies, so a remote too old to know
// this flag exists still obeys it.
func TestNoReferenceEgressReachesTheRemoteAsOrdinarySkips(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		hasTarget bool
		namedDNS  bool
	}{
		{"with a target", []string{"--via", "ideapad", "--no-reference-egress", "example.com"}, true, false},
		{"generic", []string{"--via", "ideapad", "--no-reference-egress"}, false, false},
		{"with a named resolver", []string{"--via", "ideapad", "--no-reference-egress", "--public-dns", "9.9.9.9", "example.com"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := stubRemote(t, remoteAnswer(true), nil)
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
			}
			for _, id := range referenceRows(tc.hasTarget, tc.namedDNS) {
				if !slices.Contains(seen.Skip, string(id)) {
					t.Errorf("the request skips %v, which does not include %q", seen.Skip, id)
				}
			}
			if tc.namedDNS && slices.Contains(seen.Skip, string(diagnostic.ProbeDNSPublic)) {
				t.Errorf("the request skips the resolver the user named: %v", seen.Skip)
			}
			if remote.Protocol != 1 {
				t.Errorf("remote protocol is %d; this mode was built so the version would not have to move", remote.Protocol)
			}
		})
	}
}

// The worker end of the same exchange: a request carrying those skips produces
// a run without those rows, which is what makes the local resolution sufficient.
func TestTheRemoteWorkerHonorsTheResolvedSkips(t *testing.T) {
	passes := capturePasses(t)
	skip := make([]string, 0, 4)
	for _, id := range referenceRows(true, false) {
		skip = append(skip, string(id))
	}
	rep, _, err := diagnoseRemote(context.Background(), remote.Request{
		Protocol: remote.Protocol, Target: "example.com", PublicDNS: diagnostic.DefaultPublicDNS,
		PublicDNSAuto: true, TimeoutMs: 1000, Skip: skip,
	})
	if err != nil {
		t.Fatalf("diagnoseRemote: %v", err)
	}
	for _, id := range referenceRows(true, false) {
		if hasProbe((*passes)[0], id) {
			t.Errorf("the worker ran row %q; rows were %v", id, (*passes)[0])
		}
		for _, check := range rep.Checks {
			if check.ID == string(id) {
				t.Errorf("the remote report carries row %q", id)
			}
		}
	}
}

// A profile is an explicit choice of service endpoints, so those endpoints stay
// reachable. What it may not do is drag the generic reference rows in behind
// them, and its own check list names three of them.
func TestNoReferenceEgressKeepsProfileEndpointsAndDropsTheGenericRows(t *testing.T) {
	original := remoteRun
	t.Cleanup(func() { remoteRun = original })
	var mu sync.Mutex
	var requests []remote.Request
	remoteRun = func(_ context.Context, _, _ string, req remote.Request) (remote.Response, error) {
		target, err := diagnostic.ParseTarget(req.Target)
		if err != nil {
			t.Error(err)
			return remote.Response{}, err
		}
		focus := req.Check[len(req.Check)-1]
		mu.Lock()
		requests = append(requests, req)
		mu.Unlock()
		return remote.Response{
			Protocol: remote.Protocol, Tool: remoteTool,
			Report: &report.Report{
				Version: remoteTool.Version, OK: true, Verdict: diagnostic.VerdictOK,
				Summary: "The selected service path works.",
				Target:  &report.Target{Host: target.Host, Port: target.Port, Protocol: target.Proto.String()},
				Checks:  []report.Check{{ID: focus, Name: focus, Status: profile.StatusPass, Detail: "worked"}},
			},
			Snapshot: &snapshot.Snapshot{
				Schema: snapshot.Schema, Tool: remoteTool,
				Target: &snapshot.Target{Raw: target.Raw, Host: target.Host, Port: target.Port, Protocol: target.Proto.String()},
				Checks: []snapshot.Check{},
			},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--via", "ideapad", "--profile", "github", "--json", "--no-reference-egress"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 {
		t.Fatalf("ran %d components, want 4", len(requests))
	}
	for _, req := range requests {
		// The profile's own endpoint is what the run is about, and it is named
		// by the request rather than by anything compiled into a probe.
		if !strings.Contains(req.Target, "github.com") {
			t.Errorf("component target = %q, want a GitHub endpoint", req.Target)
		}
		for _, id := range referenceRows(true, false) {
			if !slices.Contains(req.Skip, string(id)) {
				t.Errorf("component %q skips %v, which does not include %q", req.Target, req.Skip, id)
			}
		}
	}
}

// The local half of the same run, so the assertion above is not only about what
// crossed a wire. A profile names internet_tcp, proxy_connect, and dns_public
// in its own check list, and none of them may run.
func TestNoReferenceEgressSuppressesAProfilesGenericChecksLocally(t *testing.T) {
	passes := capturePasses(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--profile", "web", "--json", "--no-reference-egress", "example.com"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	if len(*passes) == 0 {
		t.Fatal("the profile ran no components")
	}
	for i, pass := range *passes {
		for _, id := range referenceRows(true, false) {
			if hasProbe(pass, id) {
				t.Errorf("component %d ran row %q; rows were %v", i, id, pass)
			}
		}
		if !hasProbe(pass, diagnostic.ProbeTargetTCP) {
			t.Errorf("component %d never reached its own endpoint; rows were %v", i, pass)
		}
	}
}

// The snapshot has to describe the run it recorded, and the decision is already
// expressible in the field that exists for it. No new options key.
func TestNoReferenceEgressIsRecordedInTheSnapshotSkipList(t *testing.T) {
	capturePasses(t)
	path := filepath.Join(t.TempDir(), "run.ndoc")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--save", path, "--no-reference-egress", "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
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
	for _, id := range referenceRows(true, false) {
		if !slices.Contains(s.Options.Skip, string(id)) {
			t.Errorf("snapshot options.skip = %v, which does not include %q", s.Options.Skip, id)
		}
	}
}

// The modes that run no probes have nothing for this setting to describe, so
// they refuse it rather than accept it and ignore it.
func TestNoReferenceEgressIsRefusedWhereNoProbesRun(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.ndoc"), filepath.Join(dir, "b.ndoc")
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"compare", []string{"--compare", "--no-reference-egress", a, b}},
		{"offline two-sided", []string{"--two-sided", "--no-reference-egress", a, b}},
		{"peer listener", []string{"--peer-listen", "192.0.2.1:4242", "--no-reference-egress"}},
		{"peer connector", []string{"--peer-connect", "--no-reference-egress"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", got, stderr.String())
			}
			if !strings.Contains(stderr.String(), "no-reference-egress") {
				t.Errorf("stderr = %q, want the refused flag named", stderr.String())
			}
		})
	}
}

// Live two-sided runs one ordinary diagnosis per machine off one set of run
// settings, so both halves inherit the mode: the local pass drops the rows and
// the remote request carries them as skips.
func TestNoReferenceEgressAppliesToBothSidesOfALiveTwoSidedRun(t *testing.T) {
	passes := capturePasses(t)
	// The localizer insists both sides observed the same endpoint, and the
	// local half of this run parses example.com as tls+http.
	answer := remoteAnswer(true)
	answer.Report.Target.Protocol = "tls+http"
	answer.Snapshot.Target.Protocol = "tls+http"
	seen := stubRemote(t, answer, nil)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--two-sided", "--via", "ideapad", "--no-reference-egress", "example.com"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got, stderr.String())
	}
	if len(*passes) != 1 {
		t.Fatalf("the local side ran %d passes, want 1", len(*passes))
	}
	for _, id := range referenceRows(true, false) {
		if hasProbe((*passes)[0], id) {
			t.Errorf("side A ran row %q; rows were %v", id, (*passes)[0])
		}
		if !slices.Contains(seen.Skip, string(id)) {
			t.Errorf("side B was sent skips %v, which does not include %q", seen.Skip, id)
		}
	}
}

// A profile composes a fresh selection per component out of its own check list
// and the run's, which is a second place the decision could quietly be dropped.
// Here the resolved skip list is deliberately left empty, so nothing but the
// run-wide decision itself can keep the components honest.
func TestAProfileComponentCannotDropTheRunWideDecision(t *testing.T) {
	passes := capturePasses(t)
	definition, ok := profile.Builtins().Lookup("web")
	if !ok {
		t.Fatal("the web profile is missing")
	}
	plan, err := definition.Plan("example.com")
	if err != nil {
		t.Fatal(err)
	}
	base := headless{
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true,
		timeout:   diagnostic.DefaultProbeTimeout,
		selection: diagnostic.ProbeSelection{NoReferenceEgress: true},
	}
	if _, _, _, err := runProfilePass(context.Background(), base, plan); err != nil {
		t.Fatal(err)
	}
	if len(*passes) != len(plan.Runs) {
		t.Fatalf("ran %d components, want %d", len(*passes), len(plan.Runs))
	}
	for i, pass := range *passes {
		for _, id := range referenceRows(true, false) {
			if hasProbe(pass, id) {
				t.Errorf("component %d ran row %q; rows were %v", i, id, pass)
			}
		}
	}
}
