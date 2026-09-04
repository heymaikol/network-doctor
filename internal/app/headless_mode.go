package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
	"github.com/heymaikol/network-doctor/internal/ui"
)

// runAll is stubbed in tests so -json runs don't touch the network.
var runAll = diagnostic.RunAll

// headless is one non-TUI run: what to probe, and what to do with the result.
// It is a struct rather than a parameter list because -save reads most of the
// same settings the JSON report does, and a second copy of them passed
// alongside would be a second chance for the two to disagree.
type headless struct {
	target  *diagnostic.Target
	sources *diagnostic.SourceAddresses
	// iface is the -iface binding as the user spelled it, kept beside the
	// resolved sources for the same reason check and skip are kept beside the
	// selection: a remote run forwards the spelling and resolves it there.
	iface     string
	selection diagnostic.ProbeSelection
	// check and skip are the selection as the user spelled it. selection holds
	// the same IDs as sets, which have no order to record.
	check     probeList
	skip      probeList
	publicDNS string
	// publicDNSAuto says publicDNS is the default rather than a resolver this
	// run named, which is what lets the second-opinion row cross to the other
	// address family.
	publicDNSAuto bool
	timeout       time.Duration
	watch         bool
	// json asks for the report on stdout. It is independent of save: a run can
	// want the artifact, the report, or both.
	json bool
	// save is the .ndoc destination, empty when no snapshot was asked for.
	save    string
	support bool
	// via is the SSH destination the probes run on, empty for a local run.
	// viaCommand overrides the netdoc to start there.
	via        string
	viaCommand string
}

// runLiveTwoSided acquires the two ordinary runs together, then hands their
// canonical snapshots to the existing offline localization engine. A remote
// transport failure cancels the local probes; an interruption cancels both.
func runLiveTwoSided(parent context.Context, h headless, stdout, stderr io.Writer) int {
	signalCtx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	localRun := h
	localRun.via, localRun.viaCommand = "", ""
	var local, remote diagnosisOutput
	var wg sync.WaitGroup
	wg.Go(func() {
		local = diagnoseHeadless(ctx, localRun)
		if local.err != nil {
			cancel()
		}
	})
	wg.Go(func() {
		remote = diagnoseHeadless(ctx, h)
		if remote.err != nil {
			cancel()
		}
	})
	wg.Wait()

	if signalCtx.Err() != nil {
		fmt.Fprintln(stderr, "netdoc: -two-sided: the run was interrupted")
		return 1
	}
	if remote.err != nil {
		fmt.Fprintln(stderr, "netdoc: -two-sided -via:", remote.err)
		return 2
	}
	if local.err != nil {
		fmt.Fprintln(stderr, "netdoc: -two-sided:", textsafe.Clean(local.err.Error()))
		return 1
	}
	result, err := compare.TwoSidedSnapshots(local.snapshot, remote.snapshot)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc: -two-sided:", textsafe.Clean(err.Error()))
		return 2
	}
	human := result.TextWithHeadings("LOCAL (SIDE A)", h.via+" (SIDE B)")
	return emitTwoSided(result, h.json, human, stdout, stderr)
}

// runHeadless runs the probe DAG headless, prints the JSON report when one was
// asked for, and writes the snapshot when one was. Exit code mirrors the TUI
// contract: 1 if any check failed, else 0. A snapshot that cannot be written
// is exit 2, the environment-is-wrong code, since the artifact the run was for
// does not exist; the diagnosis it reached is untouched either way.
//
// With watch it never stops on its own: one compact report per line, forever,
// until the terminal interrupts it. That's NDJSON, but not a new schema: the
// line is the same report struct, plus the ts that makes a stream readable.
func runHeadless(ctx context.Context, h headless, stdout, stderr io.Writer) int {
	enc := json.NewEncoder(stdout)
	if !h.watch {
		enc.SetIndent("", "  ")
	} else {
		// Ctrl-C, or the SIGTERM a supervisor sends, has to end the stream
		// at a line boundary rather than cut one in half, and it cancels the
		// in-flight probes on the way out.
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	// code starts at 1: until a pass completes, there's no report to call a
	// success, so an interrupt before the first line lands has to fail closed.
	code := 1
	for {
		probes := h.selection.Apply(diagnostic.BuildProbesFromSources(h.target, h.sources, h.publicDNS, h.publicDNSAuto))
		results := runAll(ctx, probes, h.timeout)
		if ctx.Err() != nil {
			// Interrupted mid-pass: every probe failed because we cancelled it,
			// so reporting that pass would be a lie.
			return code
		}
		rep := buildReport(h.target, probes, results)
		code = 0
		if !rep.OK {
			code = 1
		}
		if h.watch {
			rep.Ts = time.Now().UTC().Format(time.RFC3339)
		}
		if h.json {
			if err := enc.Encode(rep); err != nil {
				fmt.Fprintln(stderr, "netdoc:", err)
				return 1
			}
		}
		// The snapshot is written after the report, so a save that fails leaves
		// the stdout contract already honored: the run's answer reaches a pipe
		// either way, and only the exit code says the artifact is missing.
		if h.save != "" {
			if err := writeSnapshot(h, probes, results); err != nil {
				flagName := "-save"
				if h.support {
					flagName = "-support"
				}
				fmt.Fprintln(stderr, "netdoc:", flagName+":", textsafe.Clean(err.Error()))
				return 2
			}
			if h.support {
				fmt.Fprintf(stderr, "Sanitized support snapshot written to %q\n", textsafe.Clean(h.save))
			}
		}
		if !h.watch {
			return code
		}
		select {
		case <-ctx.Done():
			return code
		case <-time.After(ui.WatchEvery):
		}
	}
}

type diagnosisOutput struct {
	report   report.Report
	snapshot snapshot.Snapshot
	tool     snapshot.Tool
	err      error
}

// diagnoseHeadless performs one ordinary diagnosis and returns both canonical
// artifacts. A via run uses the worker's artifacts; a local run builds them
// from the same probe results.
func diagnoseHeadless(ctx context.Context, h headless) diagnosisOutput {
	if h.via != "" {
		resp, err := remoteRun(ctx, h.via, h.viaCommand, requestForRemote(h))
		if err != nil {
			return diagnosisOutput{err: err}
		}
		return diagnosisOutput{report: *resp.Report, snapshot: *resp.Snapshot, tool: resp.Tool}
	}
	probes := h.selection.Apply(diagnostic.BuildProbesFromSources(h.target, h.sources, h.publicDNS, h.publicDNSAuto))
	results := runAll(ctx, probes, h.timeout)
	if ctx.Err() != nil {
		return diagnosisOutput{err: ctx.Err()}
	}
	s := buildSnapshotArtifact(h, probes, results)
	return diagnosisOutput{report: buildReport(h.target, probes, results), snapshot: s, tool: s.Tool}
}
