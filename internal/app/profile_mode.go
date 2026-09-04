package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
	"github.com/heymaikol/network-doctor/internal/ui"
)

// runProfile executes each finite component plan through the ordinary
// headless machinery. Local components run concurrently, but remote components
// stay sequential so SSH prompts cannot collide. Output remains in registry
// order either way.
func runProfile(parent context.Context, base headless, plan profile.Plan, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	enc := json.NewEncoder(stdout)
	if !base.watch {
		enc.SetIndent("", "  ")
	}
	code := 1
	for {
		result, snapshots, tools, err := runProfilePass(ctx, base, plan)
		if err != nil {
			if ctx.Err() != nil {
				return code
			}
			fmt.Fprintln(stderr, "netdoc: -profile:", textsafe.Clean(err.Error()))
			return 2
		}
		code = 0
		if !result.OK {
			code = 1
		}
		if base.watch {
			result.Ts = time.Now().UTC().Format(time.RFC3339)
		}
		if base.via != "" && len(tools) > 0 {
			fmt.Fprintf(stderr, "Diagnosed %d profile components on %s by netdoc %s (%s/%s)\n", len(tools),
				textsafe.Clean(base.via), textsafe.Clean(tools[0].Version), textsafe.Clean(tools[0].OS), textsafe.Clean(tools[0].Arch))
		}
		switch {
		case base.json:
			if err := enc.Encode(result); err != nil {
				fmt.Fprintln(stderr, "netdoc:", err)
				return 1
			}
		case base.save == "":
			fmt.Fprint(stdout, profileText(result))
		}
		if base.save != "" {
			artifact := buildProfileArtifact(result, snapshots)
			if base.support {
				artifact = snapshot.SanitizeProfileForSupport(artifact)
			}
			if err := profileSnapshotWriteFile(base.save, artifact); err != nil {
				flagName := "-save"
				if base.support {
					flagName = "-support"
				}
				fmt.Fprintln(stderr, "netdoc:", flagName+":", textsafe.Clean(err.Error()))
				return 2
			}
			if base.support {
				fmt.Fprintf(stderr, "Sanitized support profile snapshot written to %q\n", textsafe.Clean(base.save))
			}
		}
		if !base.watch {
			return code
		}
		select {
		case <-ctx.Done():
			return code
		case <-time.After(ui.WatchEvery):
		}
	}
}

func runProfilePass(ctx context.Context, base headless, plan profile.Plan) (profile.Result, []snapshot.Snapshot, []snapshot.Tool, error) {
	outputs := make([]diagnosisOutput, len(plan.Runs))
	run := func(i int, spec profile.Run) {
		h := base
		h.target = spec.Target
		h.selection, h.check = profileSelection(spec, base.check, base.skip)
		// A profile composes its own selection per component. The run-wide
		// reference-egress decision is not a component's to drop.
		h.selection.NoReferenceEgress = base.selection.NoReferenceEgress
		outputs[i] = diagnoseHeadless(ctx, h)
	}
	if base.via != "" {
		for i, spec := range plan.Runs {
			run(i, spec)
			if outputs[i].err != nil {
				break
			}
		}
	} else {
		var wg sync.WaitGroup
		for i, spec := range plan.Runs {
			wg.Go(func() { run(i, spec) })
		}
		wg.Wait()
	}
	if ctx.Err() != nil {
		return profile.Result{}, nil, nil, ctx.Err()
	}
	reports := make([]report.Report, len(outputs))
	snapshots := make([]snapshot.Snapshot, len(outputs))
	tools := make([]snapshot.Tool, len(outputs))
	for i, output := range outputs {
		if output.err != nil {
			return profile.Result{}, nil, nil, fmt.Errorf("%s: %w", plan.Runs[i].Label, output.err)
		}
		reports[i], snapshots[i], tools[i] = output.report, output.snapshot, output.tool
	}
	result, err := profile.BuildResult(plan, reports)
	return result, snapshots, tools, err
}

func profileSelection(spec profile.Run, extra, skip probeList) (diagnostic.ProbeSelection, probeList) {
	selection, check := profile.ComposeSelection(spec, extra, skip)
	return selection, probeList(check)
}

func buildProfileArtifact(result profile.Result, snapshots []snapshot.Snapshot) snapshot.ProfileSnapshot {
	artifact := snapshot.ProfileSnapshot{
		Schema: snapshot.ProfileSchema, CreatedAt: timeNow().UTC().Format(time.RFC3339),
		Tool:       snapshot.Tool{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH},
		Profile:    snapshot.ProfileIdentity{Name: result.Profile, Version: result.ProfileVersion, Title: result.Title},
		Components: make([]snapshot.ProfileComponent, len(result.Components)),
		Aggregate:  snapshot.ProfileAggregate{Status: result.Aggregate.Status, Summary: result.Aggregate.Summary},
		OK:         result.OK,
	}
	for i, component := range result.Components {
		artifact.Components[i] = snapshot.ProfileComponent{
			ID: component.ID, Label: component.Label, Focus: component.Focus, Status: component.Status,
			Fallback: component.Fallback, Snapshot: snapshots[i],
		}
	}
	if result.Aggregate.Finding != nil {
		artifact.Aggregate.Finding = &snapshot.ProfileFinding{
			ID:                 result.Aggregate.Finding.ID,
			AffectedComponents: append([]string(nil), result.Aggregate.Finding.AffectedComponents...),
			WorkingComponents:  append([]string(nil), result.Aggregate.Finding.WorkingComponents...),
		}
	}
	return artifact
}

var profileSnapshotWriteFile = snapshot.WriteProfileFile

func profileText(result profile.Result) string {
	clean := textsafe.Clean
	var b strings.Builder
	fmt.Fprintf(&b, "%s profile\n\n", clean(result.Title))
	for _, component := range result.Components {
		endpoint := "unknown target"
		if component.Target != nil {
			endpoint = net.JoinHostPort(clean(component.Target.Host), strconv.Itoa(component.Target.Port))
		}
		fmt.Fprintf(&b, "[%s] %s  %s\n", clean(component.Status), clean(component.Label), endpoint)
	}
	fmt.Fprintf(&b, "\nverdict: %s: %s\n", clean(result.Aggregate.Status), clean(result.Aggregate.Summary))
	for _, component := range result.Components {
		if component.Status == profile.StatusPass {
			continue
		}
		fmt.Fprintf(&b, "\n%s evidence:\n", clean(component.Label))
		if component.Report.Summary != "" {
			fmt.Fprintf(&b, "  summary: %s\n", clean(component.Report.Summary))
		}
		if len(component.Report.Findings) > 0 {
			fmt.Fprintf(&b, "  finding: %s\n", clean(component.Report.Findings[0].ID))
		}
		for _, check := range profileEvidenceChecks(component) {
			fmt.Fprintf(&b, "  [%s] %s: %s\n", clean(check.Status), clean(check.Name), clean(check.Detail))
		}
	}
	return b.String()
}

func profileEvidenceChecks(component profile.Component) []report.Check {
	ids := []string{component.Focus}
	if len(component.Report.Findings) > 0 && len(component.Report.Findings[0].Evidence) > 0 {
		ids = component.Report.Findings[0].Evidence
	}
	var checks []report.Check
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		for _, check := range component.Report.Checks {
			if check.ID == id {
				checks = append(checks, check)
				break
			}
		}
	}
	return checks
}
