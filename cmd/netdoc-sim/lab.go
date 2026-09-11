package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/heymaikol/network-doctor/internal/simulation"
)

func runLab(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: netdoc-sim lab list | describe NAME | run NAME | run --all | fuzz [flags]")
		return exitUsage
	}
	switch args[0] {
	case "fuzz":
		return runLabFuzz(ctx, args[1:], out, errOut)
	case "list":
		if len(args) != 1 {
			return exitUsage
		}
		for _, s := range simulation.LabScenarios() {
			fmt.Fprintf(out, "%-30s %s\n", s.Name, s.Description)
		}
		return exitOK
	case "describe":
		if len(args) != 2 {
			return exitUsage
		}
		s, err := simulation.FindLabScenario(args[1])
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitUsage
		}
		fmt.Fprintf(out, "Scenario: %s\n%s\n\nTopology (before faults):\n%s\n", s.Name, s.Description, simulation.LabTopologyText(s.Network.Topology, s.Tunnels))
		printLabTruth(out, s.Faults)
		for _, v := range s.Views {
			fmt.Fprintf(out, "Expected %s: ", v.Node)
			printLabJSON(out, v.Expected)
		}
		for _, b := range s.BlindSpots {
			fmt.Fprintln(out, "Blind spot:", b)
		}
		return exitOK
	case "run":
		fs := flag.NewFlagSet("lab run", flag.ContinueOnError)
		fs.SetOutput(errOut)
		all := fs.Bool("all", false, "run every built-in lab scenario")
		jsonOutput := fs.Bool("json", false, "print internal lab results as JSON (experimental format)")
		trace := fs.Bool("trace", false, "include simulator-only packet paths and matched faults")
		name, err := parseRef(fs, args[1:])
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		if err != nil {
			return exitUsage
		}
		if (*all) == (name != "") {
			fmt.Fprintln(errOut, "lab run requires NAME or --all")
			return exitUsage
		}
		scenarios := simulation.LabScenarios()
		if !*all {
			s, err := simulation.FindLabScenario(name)
			if err != nil {
				fmt.Fprintln(errOut, err)
				return exitUsage
			}
			scenarios = []simulation.LabScenario{s}
		}
		var reports []simulation.LabReport
		code := exitOK
		for _, s := range scenarios {
			report, err := simulation.RunLab(ctx, s)
			if err != nil {
				fmt.Fprintln(errOut, "lab:", err)
				return exitError
			}
			reports = append(reports, report)
			if !report.Passed() {
				code = exitMismatch
			}
			if !*jsonOutput {
				printLabReport(out, report, s.Tunnels, *trace)
			}
		}
		if *jsonOutput {
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			if err := enc.Encode(reports); err != nil {
				fmt.Fprintln(errOut, err)
				return exitError
			}
		}
		return code
	default:
		fmt.Fprintln(errOut, "unknown lab command:", args[0])
		return exitUsage
	}
}

func printLabJSON(out io.Writer, value any) {
	data, _ := json.Marshal(value)
	fmt.Fprintln(out, string(data))
}
func printLabTruth(out io.Writer, faults []simulation.LabFault) {
	fmt.Fprintln(out, "Ground truth / injected faults:")
	if len(faults) == 0 {
		fmt.Fprintln(out, "  No injected fault; service and routing state are defined by the topology.")
	}
	for _, f := range faults {
		fmt.Fprintf(out, "  %s: layer=%s scope=%s localizable=%t\n", f.ID, f.Layer, f.Scope, f.Localizable)
		fmt.Fprint(out, "    mutation: ")
		printLabJSON(out, f)
	}
}
func printLabReport(out io.Writer, r simulation.LabReport, tunnels []string, trace bool) {
	fmt.Fprintf(out, "\nScenario: %s\nTopology (normalized; network fault overlays below):\n%s\n", r.Scenario, simulation.LabTopologyText(r.Topology, tunnels))
	printLabTruth(out, r.Truth)
	for _, v := range r.Views {
		fmt.Fprintf(out, "\nObserved evidence (%s):\n", v.Node)
		for i, c := range v.Measured {
			fmt.Fprintf(out, "  %-16s %-4s cause=%s %s\n", c.ID, c.Status, c.Cause, c.Detail)
			if final := v.Snapshot.Checks[i]; final.Status != c.Status {
				fmt.Fprintf(out, "    reconciled status: %s\n", final.Status)
			}
			if c.Observed != nil {
				fmt.Fprint(out, "    ")
				printLabJSON(out, c.Observed)
			}
		}
		fmt.Fprintf(out, "Diagnosis (%s): %s\n  %s\n", v.Node, v.Snapshot.Diagnosis.Verdict, v.Snapshot.Diagnosis.Summary)
		for _, f := range v.Snapshot.Diagnosis.Findings {
			fmt.Fprintf(out, "  %s confidence=%s evidence=%v\n", f.ID, f.Confidence, f.Evidence)
		}
		fmt.Fprint(out, "Expected semantic properties: ")
		printLabJSON(out, v.Expected)
		if trace {
			fmt.Fprintln(out, "Simulator-only exchanges (not supplied to diagnosis):")
			for _, x := range v.Trace {
				fmt.Fprint(out, "  ")
				printLabJSON(out, x)
			}
		}
	}
	if r.TwoSided != nil {
		fmt.Fprint(out, r.TwoSided.Text())
		fmt.Fprint(out, "Snapshot/path comparison: ")
		printLabJSON(out, r.Comparison)
	}
	for _, b := range r.BlindSpots {
		fmt.Fprintln(out, "Blind spot:", b)
	}
	for _, p := range r.Problems {
		fmt.Fprintln(out, "Validation failure:", p)
	}
	result := "PASS"
	if !r.Passed() {
		result = "FAIL"
	}
	fmt.Fprintln(out, "Evidence support and semantic validation:", result)
}
