package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

func runLabFuzz(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) > 0 && args[0] == "replay" {
		if len(args) != 2 {
			fmt.Fprintln(errOut, "usage: lab fuzz replay ARTIFACT")
			return exitUsage
		}
		// #nosec G703 -- the artifact path is this command's argument: the
		// operator names the failure artifact to replay, and the process has
		// exactly the operator's own read access. There is no lesser
		// privilege to escape from here, and reading is all that happens: the
		// bytes below are size-limited and decoded as a fuzz artifact.
		f, err := os.Open(args[1])
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitUsage
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitError
		}
		a, err := simulation.DecodeLabFuzzArtifact(data)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitUsage
		}
		reproduced, err := simulation.ReplayLabFuzzArtifact(ctx, a)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitError
		}
		fmt.Fprintf(out, "property=%s code=%q reproduced=%t\n", a.Failure.Property, a.Failure.Code, reproduced)
		for i, s := range a.Minimized.Worlds {
			report, err := simulation.RunLab(ctx, s)
			if err != nil {
				fmt.Fprintln(errOut, err)
				return exitError
			}
			for _, v := range report.Views {
				fmt.Fprintf(out, "World %d view=%s snapshot (production observations and diagnosis):\n", i, v.Node)
				printLabJSON(out, v.Snapshot)
			}
		}
		if reproduced {
			return exitMismatch
		}
		return exitOK
	}
	fs := flag.NewFlagSet("lab fuzz", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var o simulation.LabFuzzOptions
	fs.Uint64Var(&o.Seed, "seed", 1, "deterministic generator seed")
	fs.IntVar(&o.Cases, "cases", 1000, "number of generated cases")
	index := fs.Int64("case", -1, "reproduce one zero-based case number")
	fs.IntVar(&o.MaxFaults, "max-faults", 4, "maximum composed faults (0..12)")
	fs.IntVar(&o.Workers, "workers", 1, "parallel cases (1..64); results remain ordered")
	fs.BoolVar(&o.TwoSided, "two-sided", true, "include two-vantage cases")
	fs.BoolVar(&o.StopOnFirst, "stop-on-first", false, "stop at the lowest failing case")
	fs.StringVar(&o.Property, "property", "", "evaluate only this named property")
	jsonOutput := fs.Bool("json", false, "print experimental campaign JSON, including replayable minimized artifacts")
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 || *index < -1 {
		return exitUsage
	}
	if *index >= 0 {
		o.Start = uint64(*index)
		o.Cases = 1
	}
	if err := o.Validate(); err != nil {
		fmt.Fprintln(errOut, err)
		return exitUsage
	}
	start := time.Now()
	summary, err := simulation.RunLabFuzz(ctx, o)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitError
	}
	if *jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			simulation.LabFuzzSummary
			Seconds, CasesPerSecond float64
		}{summary, elapsed, float64(summary.Cases) / elapsed}); err != nil {
			fmt.Fprintln(errOut, err)
			return exitError
		}
	} else {
		fmt.Fprintf(out, "generator=%s seed=%d cases=%d evaluations=%v throughput=%.1f cases/s\n", summary.Version, o.Seed, summary.Cases, summary.Evaluations, float64(summary.Cases)/elapsed)
		fmt.Fprintf(out, "failing_cases=%d violations=%d unique_originals=%d semantic_failures=%d\n", summary.FailingCases, summary.Violations, summary.UniqueOriginalFailures, len(summary.Failures))
		for _, a := range summary.Failures {
			fmt.Fprintf(out, "FAIL property=%s code=%s seed=%d case=%d\n%s\n", a.Failure.Property, a.Failure.Code, a.Original.Seed, a.Original.Index, a.Failure.Detail)
			for i, s := range a.Minimized.Worlds {
				before := a.Original.Worlds[i]
				fmt.Fprintf(out, "World %d: nodes %d -> %d, routes %d -> %d, faults %d -> %d\n%s\n", i, len(before.Network.Topology.Nodes), len(s.Network.Topology.Nodes), len(before.Network.Topology.Routes), len(s.Network.Topology.Routes), len(before.Faults), len(s.Faults), simulation.LabTopologyText(s.Network.Topology, s.Tunnels))
				printLabTruth(out, s.Faults)
			}
			fmt.Fprintf(out, "Reproduce: netdoc-sim lab fuzz --seed %d --case %d --max-faults %d --two-sided=%t --property %s\nArtifact (save JSON below, then lab fuzz replay FILE):\n", o.Seed, a.Original.Index, o.MaxFaults, o.TwoSided, a.Failure.Property)
			printLabJSON(out, a)
		}
	}
	if len(summary.Failures) > 0 {
		return exitMismatch
	}
	return exitOK
}
