package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// The runAll fixture bypasses acquisition. These tests cover app graph and
// artifact contracts; diagnostic tests count underlying shared observations.
func profileSharingResults(probes []diagnostic.Probe, status diagnostic.Status, detail string) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
	for _, p := range probes {
		r := diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: detail, Dur: time.Millisecond}
		if p.ID == diagnostic.ProbeInternet || p.ID == diagnostic.ProbeProxy {
			r.Status = status
			if status == diagnostic.StatusSkip {
				r.Dur = 0
			}
		}
		results[p.ID] = r
	}
	return results
}

func profileSharingGraph(probes []diagnostic.Probe) string {
	var graph strings.Builder
	for _, p := range probes {
		fmt.Fprintf(&graph, "%s:%s:%v:%t\n", p.ID, p.Name, p.Deps, p.Reference)
	}
	return graph.String()
}

func TestProfileSharingPreservesReportsAndArtifacts(t *testing.T) {
	fixedNow(t, "2026-10-08T12:00:00Z")
	original := runAll
	t.Cleanup(func() { runAll = original })
	plan := githubPlan(t)
	base := headless{publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true, timeout: time.Second, save: "fixture.ndoc"}
	for _, status := range []diagnostic.Status{diagnostic.StatusPass, diagnostic.StatusWarn, diagnostic.StatusFail, diagnostic.StatusSkip} {
		t.Run(status.String(), func(t *testing.T) {
			var rows atomic.Int64
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				rows.Add(int64(len(probes)))
				return profileSharingResults(probes, status, "controlled observation")
			}
			reports := make([]report.Report, len(plan.Runs))
			wantSnapshots := make([]snapshot.Snapshot, len(plan.Runs))
			for i, spec := range plan.Runs {
				h := base
				h.target = spec.Target
				h.selection, h.check = profileSelection(spec, base.check, base.skip)
				out := diagnoseHeadless(context.Background(), h, true)
				if out.err != nil {
					t.Fatal(out.err)
				}
				reports[i], wantSnapshots[i] = out.report, out.snapshot
			}
			want, err := profile.BuildResult(plan, reports)
			if err != nil {
				t.Fatal(err)
			}
			rows.Store(0)
			got, gotSnapshots, _, err := runProfilePass(context.Background(), base, plan)
			if err != nil {
				t.Fatal(err)
			}
			if rows.Load() != 36 {
				t.Fatalf("component graph rows = %d, want 36", rows.Load())
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("profile report differs from independent diagnoses:\ngot: %+v\nwant: %+v", got, want)
			}
			if !reflect.DeepEqual(gotSnapshots, wantSnapshots) {
				t.Fatal("component snapshots differ from independent diagnoses")
			}
			gotArtifact, wantArtifact := buildProfileArtifact(got, gotSnapshots), buildProfileArtifact(want, wantSnapshots)
			if !reflect.DeepEqual(gotArtifact, wantArtifact) {
				t.Fatal("profile artifacts differ from independent diagnoses")
			}
			if !reflect.DeepEqual(snapshot.SanitizeProfileForSupport(gotArtifact), snapshot.SanitizeProfileForSupport(wantArtifact)) {
				t.Fatal("support artifacts differ from independent diagnoses")
			}
			for _, artifact := range []snapshot.ProfileSnapshot{gotArtifact, snapshot.SanitizeProfileForSupport(gotArtifact)} {
				data, err := snapshot.EncodeProfile(artifact)
				if err != nil {
					t.Fatalf("encode profile artifact: %v", err)
				}
				if _, err := snapshot.DecodeProfile(data); err != nil {
					t.Fatalf("decode profile artifact: %v", err)
				}
			}
		})
	}
}

func TestProfileSharingConcurrentCompletionKeepsComponentOrder(t *testing.T) {
	original := runAll
	t.Cleanup(func() { runAll = original })
	// The deadline reports deadlocked barriers, not a latency expectation.
	ctx, cancel := context.WithTimeout(context.Background(), viaBarrierStuck)
	defer cancel()
	plan := githubPlan(t)
	base := headless{publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second, save: "fixture.ndoc"}
	indices := make(map[string]int, len(plan.Runs))
	release := make([]chan struct{}, len(plan.Runs))
	for i, spec := range plan.Runs {
		selection, _ := profileSelection(spec, nil, nil)
		indices[profileSharingGraph(selection.BuildProbesFromSources(spec.Target, nil, base.publicDNS, false))] = i
		release[i] = make(chan struct{})
	}
	entered := make(chan int, len(plan.Runs))
	finished := make(chan int, len(plan.Runs))
	runAll = func(ctx context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		i, ok := indices[profileSharingGraph(probes)]
		if !ok {
			t.Error("unexpected component graph")
			return nil
		}
		entered <- i
		select {
		case <-release[i]:
		case <-ctx.Done():
			return nil
		}
		results := profileSharingResults(probes, diagnostic.StatusPass, plan.Runs[i].ID)
		finished <- i
		return results
	}
	done := make(chan struct{})
	var result profile.Result
	var snapshots []snapshot.Snapshot
	var err error
	t.Cleanup(func() {
		cancel()
		awaitVia(t, done, "local profile cleanup")
	})
	go func() {
		result, snapshots, _, err = runProfilePass(ctx, base, plan)
		close(done)
	}()
	for range plan.Runs {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("profile components did not all reach the barrier")
		}
	}
	for i := len(plan.Runs) - 1; i >= 0; i-- {
		close(release[i])
		select {
		case got := <-finished:
			if got != i {
				t.Fatalf("completion = %d, want %d", got, i)
			}
		case <-ctx.Done():
			t.Fatal("released profile component did not complete")
		}
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("profile pass did not complete")
	}
	if err != nil {
		t.Fatal(err)
	}
	for i, spec := range plan.Runs {
		component := result.Components[i]
		if component.ID != spec.ID || component.Target.Host != spec.Target.Host || component.Target.Port != spec.Target.Port {
			t.Errorf("component %d identity = %+v, want %s/%s:%d", i, component, spec.ID, spec.Target.Host, spec.Target.Port)
		}
		if snapshots[i].Target.Host != spec.Target.Host || snapshots[i].Target.Port != spec.Target.Port {
			t.Errorf("snapshot %d has another component's target", i)
		}
		for _, check := range component.Report.Checks {
			if check.Detail != spec.ID {
				t.Errorf("component %s has another component's observation: %+v", spec.ID, check)
			}
		}
	}
}

func TestProfileSharingPreservesComponentSelections(t *testing.T) {
	original := runAll
	t.Cleanup(func() { runAll = original })
	for _, noReference := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-reference=%t", noReference), func(t *testing.T) {
			plan := githubPlan(t)
			plan.Runs[0].Check = []diagnostic.ProbeID{diagnostic.ProbeHTTPS}
			base := headless{
				publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second, save: "fixture.ndoc",
				check: probeList{diagnostic.ProbeDNSPublic}, skip: probeList{diagnostic.ProbeProxy},
				selection: diagnostic.ProbeSelection{NoReferenceEgress: noReference},
			}
			observed := make(chan string, len(plan.Runs))
			runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				observed <- profileSharingGraph(probes)
				return profileSharingResults(probes, diagnostic.StatusPass, "controlled observation")
			}
			_, snapshots, _, err := runProfilePass(context.Background(), base, plan)
			if err != nil {
				t.Fatal(err)
			}
			var got, want []string
			for i, spec := range plan.Runs {
				selection, check := profileSelection(spec, base.check, base.skip)
				selection.NoReferenceEgress = noReference
				probes := selection.BuildProbesFromSources(spec.Target, nil, base.publicDNS, false)
				want = append(want, profileSharingGraph(probes))
				got = append(got, <-observed)
				wantChecks := make([]string, len(check))
				for j, id := range check {
					wantChecks[j] = string(id)
				}
				if !slices.Equal(snapshots[i].Options.Check, wantChecks) || !slices.Equal(snapshots[i].Options.Skip, []string{string(diagnostic.ProbeProxy)}) {
					t.Errorf("component %s selection options = %+v", spec.ID, snapshots[i].Options)
				}
				for _, p := range probes {
					if p.ID == diagnostic.ProbeProxy || (noReference && p.Reference) {
						t.Errorf("component %s retained excluded probe %s", spec.ID, p.ID)
					}
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("profile graphs differ from independent selected graphs:\ngot: %v\nwant: %v", got, want)
			}
		})
	}
}

func TestProfileSharingWatchPassReportsFreshObservations(t *testing.T) {
	original := runAll
	t.Cleanup(func() { runAll = original })
	plan := githubPlan(t)
	base := headless{watch: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}
	for pass := 1; pass <= 2; pass++ {
		detail := fmt.Sprintf("pass %d", pass)
		var components atomic.Int64
		runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
			components.Add(1)
			return profileSharingResults(probes, diagnostic.StatusPass, detail)
		}
		result, _, _, err := runProfilePass(context.Background(), base, plan)
		if err != nil {
			t.Fatal(err)
		}
		if components.Load() != int64(len(plan.Runs)) {
			t.Fatalf("pass %d collected %d component graphs", pass, components.Load())
		}
		for _, component := range result.Components {
			for _, check := range component.Report.Checks {
				if check.Detail != detail {
					t.Errorf("pass %d reused stale observation: %+v", pass, check)
				}
			}
		}
	}
}

func TestProfileSharingUsesFreshObservationLayerPerPass(t *testing.T) {
	originalBuild, originalRun := buildProfileProbes, runAll
	t.Cleanup(func() { buildProfileProbes, runAll = originalBuild, originalRun })
	plan := githubPlan(t)
	seen := make(chan *diagnostic.ProfilePass, len(plan.Runs))
	buildProfileProbes = func(pass *diagnostic.ProfilePass, target *diagnostic.Target, selection diagnostic.ProbeSelection, publicDNS string, auto bool) []diagnostic.Probe {
		seen <- pass
		return originalBuild(pass, target, selection, publicDNS, auto)
	}
	runAll = func(_ context.Context, probes []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		return profileSharingResults(probes, diagnostic.StatusPass, "controlled observation")
	}
	base := headless{watch: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}
	var previous *diagnostic.ProfilePass
	for range 2 {
		if _, _, _, err := runProfilePass(context.Background(), base, plan); err != nil {
			t.Fatal(err)
		}
		if len(seen) != len(plan.Runs) {
			t.Fatalf("shared builder reached by %d components, want %d", len(seen), len(plan.Runs))
		}
		pass := <-seen
		if pass == nil || pass == previous {
			t.Fatal("profile reused an observation layer across passes")
		}
		for range len(plan.Runs) - 1 {
			if other := <-seen; other != pass {
				t.Fatal("components did not use the same observation layer")
			}
		}
		previous = pass
	}
}

func TestProfileSharingCancellationEndsAllComponents(t *testing.T) {
	original := runAll
	t.Cleanup(func() { runAll = original })
	plan := githubPlan(t)
	ctx, cancel := context.WithTimeout(context.Background(), viaBarrierStuck)
	defer cancel()
	entered := make(chan struct{}, len(plan.Runs))
	var active atomic.Int64
	runAll = func(ctx context.Context, _ []diagnostic.Probe, _ time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil
	}
	done := make(chan struct{})
	var err error
	t.Cleanup(func() {
		cancel()
		awaitVia(t, done, "canceled profile cleanup")
	})
	go func() {
		_, _, _, err = runProfilePass(ctx, headless{publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second}, plan)
		close(done)
	}()
	for range plan.Runs {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("profile components did not all reach cancellation barrier")
		}
	}
	cancel()
	select {
	case <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("profile error = %v, want context cancellation", err)
		}
	case <-time.After(viaBarrierStuck):
		t.Fatal("canceled profile pass did not complete")
	}
	if got := active.Load(); got != 0 {
		t.Errorf("active component executions = %d, want 0", got)
	}
}
