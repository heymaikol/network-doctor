package app

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/profile"
	"github.com/heymaikol/network-doctor/v2/internal/remote"
	"github.com/heymaikol/network-doctor/v2/internal/report"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// runProfile executes each finite component plan through the ordinary
// headless machinery. Local components run concurrently. Remote ones overlap
// only over a transport that cannot ask the user anything, to a destination
// reached without a proxy, and run one at a time otherwise, so SSH prompts
// cannot collide. A refused noninteractive acquisition fails the pass; it is
// never retried interactively. Output remains in registry order either way.
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
		if base.save != "" && !saveable(snapshots) {
			// A component that did not finish has no snapshot to write. Nothing is written
			// for this pass, and a watch goes on to the next one.
			flag := "-save"
			if base.support {
				flag = "-support"
			}
			fmt.Fprintln(stderr, "netdoc: "+flag+": nothing written for this pass, because a component did not finish")
			// A one-shot run was asked for its artifact and did not get it, which is the failure
			// exit 2 has always meant. A watch goes on to its next pass.
			if !base.watch {
				return 2
			}
		} else if base.save != "" {
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
		case <-watchAfter(base.pause()):
		}
	}
}

func runProfilePass(ctx context.Context, base headless, plan profile.Plan) (profile.Result, []snapshot.Snapshot, []snapshot.Tool, error) {
	if base.via == "" {
		base.profilePass = diagnostic.NewProfilePass(base.sources)
	}
	outputs := make([]diagnosisOutput, len(plan.Runs))
	run := func(i int, batch bool) {
		// Once the caller has cancelled, nothing new starts, and the pass reports
		// the cancellation whatever the components hold. Every acquisition goes
		// through here, so this one check covers the batch attempt, the
		// sequential path and the overlap.
		if err := ctx.Err(); err != nil {
			outputs[i] = diagnosisOutput{err: err}
			return
		}
		h := base
		h.target = plan.Runs[i].Target
		h.selection, h.check = profileSelection(plan.Runs[i], base.check, base.skip)
		// A profile composes its own selection per component. The run-wide
		// reference-egress decision is not a component's to drop.
		h.selection.NoReferenceEgress = base.selection.NoReferenceEgress
		h.viaBatch = batch
		// Only -save and -support read a component's snapshot, and both arrive
		// here as base.save.
		outputs[i] = diagnoseHeadless(ctx, h, base.save != "")
		if batch && outputs[i].err != nil {
			// The noninteractive attempt asks nothing, so say that it did not.
			outputs[i].err = fmt.Errorf("%w; no question was asked, and a run from a terminal can answer any question the destination asks", outputs[i].err)
		}
	}
	// together runs every component from first onwards at once. A component
	// that fails does not cancel its siblings: each one is an independent
	// diagnosis the aggregate still wants, attribution is by index rather than
	// by who finished first, and a pass that abandoned the others would be
	// less useful without being any more deterministic.
	together := func(first int, batch bool) {
		var wg sync.WaitGroup
		for i := first; i < len(plan.Runs); i++ {
			wg.Go(func() { run(i, batch) })
		}
		wg.Wait()
	}
	// sequential is the one-at-a-time acquisition, which is what a transport
	// still able to ask the user something has to have: at most one ssh that
	// can prompt is ever running, so two questions cannot arrive on one
	// terminal at once.
	sequential := func() {
		for i := range plan.Runs {
			run(i, false)
			if err := outputs[i].err; err != nil && !ordinaryTimeout(err) {
				return
			}
		}
	}
	switch {
	case base.via == "":
		together(0, false)
	case len(plan.Runs) < 2:
		// Nothing to overlap, so nothing to gain by asking the destination
		// whether it would let us.
		sequential()
	case !remoteDirect(ctx, base.via):
		// The destination is reached through a ProxyJump or a ProxyCommand, or
		// ssh would not say. That proxy is the user's configured path to the
		// host, so netdoc keeps it and gives up the overlap instead: a jump
		// child is a separate ssh that can ask the bastion's own questions, and
		// connecting around it would be a different connection than the one the
		// configuration asks for.
		sequential()
	default:
		// The first component is alone, and it is acquired over the transport
		// that cannot ask anything. It is a real component rather than a
		// preflight: either this destination authenticates without a question,
		// in which case the same transport carries the rest safely, or it does
		// not and the pass fails. A timeout is not a refusal: it is this
		// component's failure, and the later components still run. They are not
		// overlapped until this one has answered, and they are safe because each
		// one refuses interaction itself and holds the direct route the gate just
		// read, so no proxy child
		// can appear part-way through the pass to ask on its behalf.
		run(0, true)
		if err := outputs[0].err; err != nil && !ordinaryTimeout(err) {
			// A refused noninteractive acquisition fails the pass. Nothing is retried
			// over the transport that can prompt: a refused host key, passphrase, or
			// LocalCommand would be answered there, and a changed key accepted under
			// the user's StrictHostKeyChecking no. The other components are not
			// started either, because they share this destination, so the same
			// refusal would repeat for each of them. A timeout is not a refusal: it
			// is recorded as that component's failure, and the others still run.
			break
		}
		together(1, true)
	}
	if ctx.Err() != nil {
		return profile.Result{}, nil, nil, ctx.Err()
	}
	reports := make([]report.Report, len(outputs))
	snapshots := make([]snapshot.Snapshot, len(outputs))
	tools := make([]snapshot.Tool, len(outputs))
	for i, output := range outputs {
		if err := output.err; err != nil {
			if !ordinaryTimeout(err) {
				return profile.Result{}, nil, nil, fmt.Errorf("%s: %w", plan.Runs[i].Label, err)
			}
			reports[i] = timedOutReport(plan.Runs[i], err)
			continue
		}
		reports[i], snapshots[i], tools[i] = output.report, output.snapshot, output.tool
	}
	result, err := profile.BuildResult(plan, reports)
	return result, snapshots, tools, err
}

// ordinaryTimeout reports whether an acquisition ended by the transport's own deadline. That
// is an ordinary component failure: the pass records it and goes on. Every other error from an
// acquisition is a refusal or a failed gate, and it still ends the pass.
func ordinaryTimeout(err error) bool {
	return errors.Is(err, remote.ErrRunTimedOut)
}

// timedOutReport is the report of a component whose acquisition the deadline ended. The
// component's one check is its focus check, failed with the error that ended the attempt, so
// the profile reads the component as failed. It says nothing about what the target would have
// answered.
func timedOutReport(run profile.Run, err error) report.Report {
	id := string(run.Focus)
	r := report.Report{
		Version:     version,
		Checks:      []report.Check{{ID: id, Name: run.Label, Status: diagnostic.StatusFail.String(), Detail: textsafe.Clean(err.Error())}},
		Summary:     run.Label + " did not finish before its time ran out.",
		Verdict:     diagnostic.StatusFail.String(),
		FailedStage: id,
	}
	if t := run.Target; t != nil {
		r.Target = &report.Target{Host: t.Host, Port: t.Port, Protocol: t.Proto.String(), Zone: t.Zone}
	}
	return r
}

// saveable reports whether every component carries its own snapshot. A component whose
// acquisition timed out has none, and the artifact format cannot hold a component without one.
func saveable(snapshots []snapshot.Snapshot) bool {
	for _, s := range snapshots {
		if s.Schema == "" {
			return false
		}
	}
	return true
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
			host := clean(component.Target.Host)
			if component.Target.Zone != "" {
				host += "%" + clean(component.Target.Zone)
			}
			endpoint = net.JoinHostPort(host, strconv.Itoa(component.Target.Port))
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
