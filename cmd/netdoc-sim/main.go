// Command netdoc-sim builds throwaway virtual networks, runs netdoc inside
// them, and reports whether netdoc diagnosed what the scenario actually broke.
//
// It is a test harness for netdoc, not part of netdoc: nothing here ships in
// the netdoc binary, and the release builds only the root package.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/simulation"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// directorCommand is the hidden argv[1] the launcher re-executes itself with,
// once it is inside the simulation's namespaces.
const directorCommand = "__director"
const campaignDirectorCommand = "__campaign_director"
const huntDirectorCommand = "__hunt_director"
const challengeDirectorCommand = "__challenge_director"

// version is injected at build time with -X main.version, by the same
// GoReleaser build that stamps netdoc and by the container image build. Asking
// netdoc-sim rather than inferring from the package or image tag is the same
// rule the simulator applies to netdoc: the binary is the only thing that knows
// which build it is. A local build says "dev", truthfully.
var version = "dev"

func init() {
	// A `go install ...@vX.Y.Z` build has no injected version but does carry the
	// module version, and introducing itself as "dev" there would be a lie.
	if info, ok := debug.ReadBuildInfo(); ok && version == "dev" &&
		info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
}

// Exit codes. Separated so a CI job can tell "netdoc diagnosed this wrong"
// from "the simulator could not run".
const (
	exitOK       = 0 // every expectation held
	exitMismatch = 1 // the simulation ran; the diagnosis did not match
	exitUsage    = 2 // bad arguments
	exitError    = 3 // the simulation could not run
)

// Every namespace this tool creates goes through one of these two calls: the
// backend that builds a topology, and the re-execution of this binary inside
// fresh namespaces. Keeping them as variables lets the dispatch tests drive
// each command end to end on a host with no privileges at all.
var (
	newBackend     = simulation.DefaultBackend
	launchDirector = simulation.LaunchDirector
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case simulation.NodeCommand:
		// A node holder. Never invoked by hand; the director spawns it.
		if len(args) != 2 {
			fmt.Fprintln(stderr, "netdoc-sim: internal: node holder needs a config path")
			return exitUsage
		}
		if err := simulation.RunNode(ctx, args[1], os.Stdin, stdout, stderr); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim: node:", err)
			return exitError
		}
		return exitOK
	case "run":
		return launch(ctx, args, stdout, stderr)
	case "lab":
		return runLab(ctx, args[1:], stdout, stderr)
	case "campaign":
		return launchCampaign(ctx, args[1:], stdout, stderr)
	case "hunt":
		return launchHunt(ctx, args[1:], stdout, stderr)
	case "triage":
		return launchTriage(ctx, args[1:], stdout, stderr)
	case "challenge":
		return launchChallenge(ctx, args[1:], os.Stdin, stdout, stderr)
	case directorCommand:
		return direct(ctx, args[1:], stdout, stderr)
	case campaignDirectorCommand:
		return directCampaign(ctx, args[1:], stdout, stderr)
	case huntDirectorCommand:
		return directHunt(ctx, args[1:], stdout, stderr)
	case challengeDirectorCommand:
		return directChallenge(ctx, args[1:], os.Stdin, stdout, stderr)
	case "validate":
		return validate(args[1:], stdout, stderr)
	case "scenarios":
		for _, n := range simulation.LibraryNames() {
			fmt.Fprintln(stdout, n)
		}
		return exitOK
	case "starters":
		return starters(args[1:], stdout, stderr)
	case "authored":
		return authored(args[1:], stdout, stderr)
	case "capabilities":
		return capabilities(ctx, stdout)
	case "list":
		return list(stdout, stderr)
	case "inspect":
		return inspect(args[1:], stdout, stderr)
	case "cleanup":
		return cleanup(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "netdoc-sim", version)
		return exitOK
	}
	fmt.Fprintf(stderr, "netdoc-sim: unknown command %q\n", textsafe.Clean(args[0]))
	fmt.Fprintln(stderr, "run 'netdoc-sim help' for usage")
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage: netdoc-sim <command> [arguments]

Builds a virtual network from a scenario, runs netdoc inside it, and reports
whether netdoc's diagnosis matched what the scenario broke.

Commands:
  help                     print this help
  run <scenario> [flags]   build the network, run the tests, print the report
  lab <command>           offline scenario lab: list, describe, run, fuzz
  campaign <scenario>      run a seeded scenario campaign sequentially
  hunt [base] [flags]      run deterministic bug-oracle or stress mutations
  hunt merge <files...>    merge a complete set of hunt shard JSON reports
  triage [flags]           hunt the fixed baselines, reproduce findings, file issues
  challenge [id] [flags]   diagnose a hidden fault yourself, then let netdoc try
  validate <scenario>      parse and check a scenario without building anything
  scenarios                list the built-in scenarios
  starters [pack]          list the curated starter packs, or one pack's challenges
  authored                 list the hand-written challenges and their ids
  capabilities             report whether this host can simulate, and what a run does
  list                     list simulations left running by 'run -keep'
  inspect <id>             show a kept simulation's nodes and how to enter them
  cleanup [<id>|-all]      release a kept simulation's namespaces and files
  version                  print the build version, the same one netdoc reports

A <scenario> is a built-in name or a path to a YAML file.

Flags for lab run:
  -all                     run every built-in lab scenario
  -json                    print experimental lab JSON
  -trace                   include simulator-only packet paths

Flags for run:
  -json                    print the machine-readable report instead of text
  -keep                    hold the network open after the report until interrupted
  -netdoc <path>           the netdoc binary to run (default: alongside this one, then $PATH)
  -timeout <duration>      netdoc's per-probe timeout (default 4s)
  -repeat <n>              run each test n times to catch an unstable diagnosis
  -dry-run                 print every privileged command the run would make, and stop
  -v                       log each privileged command as it runs

Flags for campaign:
  -runs <n>                override the campaign's bounded default run count
  -seed <int64>            root seed (generated and printed when omitted)
  -iteration <n>           run exactly one independently derived iteration,
                           repeated -runs times when both are given
  -fail-fast               stop after the first mismatch or simulator error
  -json                    print the machine-readable aggregate report
  -netdoc <path>           the netdoc binary to run
  -timeout <duration>      netdoc's per-probe timeout (default 4s)
  -v                       log each privileged command as it runs

Flags for hunt:
  -cases <n>               logical unique cases before sharding (default 50, maximum 500)
  -seed <int64>            hunt seed (generated and printed when omitted)
  -case <n>                generate and run exactly one independently derived case
  -shard <i/N>             run zero-based shard i of the global case sequence
  -max-faults <n>          maximum mutations per case (default 2, maximum 3)
  -generator-version <v>   Hunt generator version (default: current)
  -lane <name>             bug-oracle (direct diagnosis check) or stress (no direct oracle)
  -fail-fast               stop after the first case with a reportable finding
  -dry-run                 print generated manifests without creating namespaces
  -json                    print the machine-readable hunt report
  -netdoc <path>           the netdoc binary to run
  -timeout <duration>      netdoc's per-probe timeout (default 4s)
  -v                       log each privileged command as it runs

Flags for triage:
  -scenarios <list>        comma-separated baselines (default: all)
  -cases <n>               unique generated cases per baseline (default 20)
  -hunt-results <dir>      use canonical merged hunt JSON from this directory
  -seed <int64>            override the fixed seed of every selected baseline
  -max-faults <n>          maximum mutations per case (default 2, maximum 3)
  -lane <name>             Hunt lane to triage (default bug-oracle; historical: all)
  -min-severity <level>    lowest severity worth filing (default medium)
  -create                  file reproducible findings as GitHub issues with gh
  -context <text>          debugging context recorded in the issue body
  -revision <sha>          commit to record (default: the build's VCS revision)
  -json                    print the machine-readable triage report
  -netdoc <path>           the netdoc binary to run
  -timeout <duration>      netdoc's per-probe timeout (default 4s)
  -v                       log each privileged command as it runs

Ways to play a challenge:
  netdoc-sim challenge                     draw one and play it
  netdoc-sim challenge -daily              today's challenge, the same one for
                                           everybody who plays it today
  netdoc-sim challenge -starter fundamentals
                                           a curated challenge to learn on
  netdoc-sim challenge V4-8F42C1           replay the one a friend sent you

In the session you get a shell in the broken machine, then a menu. Pick a
diagnosis by number or by name, 'b' rereads the briefing, 's' returns to the
shell, 'q' gives up. Your solve time is the shell and the menu, not the
simulator's setup or Network Doctor's own run.

Flags for challenge:
  -id <ID>                 replay a specific challenge instead of drawing one
  -daily[=YYYY-MM-DD]      play the challenge for today, or for that UTC date
  -starter <pack>          draw from a starter pack ('netdoc-sim starters')
  -authored <slug>         play a hand-written challenge ('netdoc-sim authored')
  -difficulty <level>      draw an easy, medium or hard challenge
  -answer <name>           submit this diagnosis without opening a shell
  -give-up                 skip straight to the answer
  -json                    print the machine-readable result (needs -answer or -give-up)
  -netdoc <path>           the netdoc binary to run
  -timeout <duration>      netdoc's per-probe timeout (default 4s)
  -v                       log each privileged command as it runs

Flags for cleanup:
  -all                     release every kept simulation

Exit codes: 0 the diagnosis matched, 1 it did not, 2 bad arguments,
3 the simulation could not run.

For hunt: 0 no reportable finding, 1 findings, 2 usage or generation
failure, 3 simulator runtime failure or cancellation.

For challenge: 0 your diagnosis was correct; 1 it was not, or you gave up;
2 usage; 3 the challenge could not be scored.

For triage: 0 nothing reproducible, or every reproducible finding is now
tracked by an issue; 1 reproducible findings nobody recorded; 2 usage;
3 a hunt, a reproduction, or a gh call failed.

Simulations are unprivileged: everything lives in a user namespace that owns
nothing on the host. Run 'netdoc-sim capabilities' for the details.
`)
}

// parseRef parses the flags around a single positional argument, so flags may
// come before or after it, the same grammar netdoc itself accepts. It returns
// "" when no positional argument was given; each caller decides whether that is
// a default or an error.
func parseRef(fs *flag.FlagSet, args []string) (string, error) {
	ref := ""
	for {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		if fs.NArg() == 0 {
			return ref, nil
		}
		if ref != "" {
			return "", fmt.Errorf("unexpected argument %q", textsafe.Clean(fs.Arg(0)))
		}
		ref = fs.Arg(0)
		args = fs.Args()[1:]
	}
}

type huntFlags struct {
	fs        *flag.FlagSet
	json      *bool
	cases     *int
	seed      optionalSeed
	caseNum   *int
	shard     optionalShard
	maxFaults *int
	generator *string
	lane      *string
	failFast  *bool
	dry       *bool
	netdoc    *string
	timeout   *time.Duration
	verbose   *bool
}

func newHuntFlags(out io.Writer) *huntFlags {
	f := &huntFlags{fs: flag.NewFlagSet("netdoc-sim hunt", flag.ContinueOnError)}
	f.fs.SetOutput(out)
	f.json = f.fs.Bool("json", false, "print the machine-readable hunt report")
	f.cases = f.fs.Int("cases", 50, "logical unique cases before sharding")
	f.fs.Var(&f.seed, "seed", "hunt seed")
	f.caseNum = f.fs.Int("case", -1, "run exactly one independently derived case")
	f.fs.Var(&f.shard, "shard", "zero-based shard i/N of the global case sequence")
	f.maxFaults = f.fs.Int("max-faults", 2, "maximum mutations per case")
	f.generator = f.fs.String("generator-version", simulation.HuntGeneratorVersion, "Hunt generator version")
	f.lane = f.fs.String("lane", "", "Hunt lane: bug-oracle (direct diagnosis check) or stress; historical generators use all")
	f.failFast = f.fs.Bool("fail-fast", false, "stop after the first reportable finding")
	f.dry = f.fs.Bool("dry-run", false, "print generated manifests without running them")
	f.netdoc = f.fs.String("netdoc", "", "path to the netdoc binary")
	f.timeout = f.fs.Duration("timeout", 4*time.Second, "netdoc per-probe timeout")
	f.verbose = f.fs.Bool("v", false, "log each privileged command as it runs")
	return f
}

func (f *huntFlags) parse(args []string) (string, error) {
	ref, err := parseRef(f.fs, args)
	if err != nil {
		return "", err
	}
	if ref == "" {
		ref = "healthy-routed-network"
	}
	if *f.cases < 1 || *f.cases > simulation.HuntMaxCases {
		return "", fmt.Errorf("-cases must be between 1 and %d", simulation.HuntMaxCases)
	}
	if *f.caseNum < -1 || *f.caseNum > simulation.HuntMaxCaseNumber {
		return "", fmt.Errorf("-case must be between 0 and %d", simulation.HuntMaxCaseNumber)
	}
	if *f.caseNum >= 0 && f.shard.set {
		return "", errors.New("-case and -shard are mutually exclusive")
	}
	if *f.maxFaults < 1 || *f.maxFaults > simulation.HuntMaxFaults {
		return "", fmt.Errorf("-max-faults must be between 1 and %d", simulation.HuntMaxFaults)
	}
	if !slices.Contains(simulation.HuntGeneratorVersions(), *f.generator) {
		return "", fmt.Errorf("-generator-version must be one of %s", strings.Join(simulation.HuntGeneratorVersions(), ", "))
	}
	lane, err := simulation.ResolveHuntLane(*f.generator, simulation.HuntLane(*f.lane))
	if err != nil {
		return "", err
	}
	*f.lane = string(lane)
	// Validated the way netdoc validates its own -timeout, because that is
	// where this value is going: runner.go spells it onto the child's command
	// line. A value netdoc refuses would otherwise surface as every spawned run
	// exiting 2 with the real complaint buried in a child process.
	if err := diagnostic.ValidateProbeTimeout(*f.timeout); err != nil {
		return "", err
	}
	if !slices.Contains(simulation.HuntBaseNames(), ref) {
		return "", fmt.Errorf("unsupported hunt base %q (have: %s)", textsafe.Clean(ref), strings.Join(simulation.HuntBaseNames(), ", "))
	}
	return ref, nil
}

type optionalShard struct {
	set   bool
	value simulation.HuntShard
}

func (s *optionalShard) String() string {
	if !s.set {
		return ""
	}
	return fmt.Sprintf("%d/%d", s.value.Index, s.value.Count)
}

func (s *optionalShard) Set(raw string) error {
	parts := strings.Split(raw, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid shard %q: want i/N", textsafe.Clean(raw))
	}
	index, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid shard index %q", textsafe.Clean(parts[0]))
	}
	count, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid shard count %q", textsafe.Clean(parts[1]))
	}
	value := simulation.HuntShard{Index: int(index), Count: int(count)}
	if err := value.Validate(); err != nil {
		return err
	}
	s.set, s.value = true, value
	return nil
}

type optionalSeed struct {
	set bool
	v   int64
}

func (s *optionalSeed) String() string {
	if !s.set {
		return ""
	}
	return strconv.FormatInt(s.v, 10)
}

func (s *optionalSeed) Set(raw string) error {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid seed %q: %w", textsafe.Clean(raw), err)
	}
	s.set, s.v = true, v
	return nil
}

type campaignFlags struct {
	fs        *flag.FlagSet
	json      *bool
	runs      *int
	seed      optionalSeed
	iteration *int
	failFast  *bool
	netdoc    *string
	timeout   *time.Duration
	verbose   *bool
}

func newCampaignFlags(out io.Writer) *campaignFlags {
	f := &campaignFlags{fs: flag.NewFlagSet("netdoc-sim campaign", flag.ContinueOnError)}
	f.fs.SetOutput(out)
	f.json = f.fs.Bool("json", false, "print the machine-readable aggregate report")
	f.runs = f.fs.Int("runs", 0, "override campaign run count")
	f.fs.Var(&f.seed, "seed", "campaign root seed")
	f.iteration = f.fs.Int("iteration", -1, "run exactly one iteration")
	f.failFast = f.fs.Bool("fail-fast", false, "stop after the first failure")
	f.netdoc = f.fs.String("netdoc", "", "path to the netdoc binary")
	f.timeout = f.fs.Duration("timeout", 4*time.Second, "netdoc per-probe timeout")
	f.verbose = f.fs.Bool("v", false, "log each privileged command as it runs")
	return f
}

func (f *campaignFlags) parse(args []string) (string, error) {
	ref, err := parseRef(f.fs, args)
	if err != nil {
		return "", err
	}
	if ref == "" {
		return "", errors.New("a campaign scenario is required")
	}
	if *f.runs < 0 || *f.runs > 1000 {
		return "", errors.New("-runs must be between 1 and 1000 when supplied")
	}
	if *f.iteration < -1 || *f.iteration > 999999 {
		return "", errors.New("-iteration must be between 0 and 999999")
	}
	// Netdoc's own -timeout contract, for the reason huntFlags.parse gives.
	if err := diagnostic.ValidateProbeTimeout(*f.timeout); err != nil {
		return "", err
	}
	return ref, nil
}

// runFlags is the flag set shared by the launcher and the director, so the
// launcher can forward argv verbatim and both agree on what it means.
type runFlags struct {
	fs      *flag.FlagSet
	json    *bool
	keep    *bool
	netdoc  *string
	timeout *time.Duration
	repeat  *int
	dry     *bool
	verbose *bool
}

func newRunFlags(out io.Writer) *runFlags {
	fs := flag.NewFlagSet("netdoc-sim run", flag.ContinueOnError)
	fs.SetOutput(out)
	return &runFlags{
		fs:      fs,
		json:    fs.Bool("json", false, "print the machine-readable report"),
		keep:    fs.Bool("keep", false, "hold the network open after the report"),
		netdoc:  fs.String("netdoc", "", "path to the netdoc binary"),
		timeout: fs.Duration("timeout", 4*time.Second, "netdoc per-probe timeout"),
		repeat:  fs.Int("repeat", 1, "run each test n times"),
		dry:     fs.Bool("dry-run", false, "print the privileged commands and stop"),
		verbose: fs.Bool("v", false, "log each privileged command as it runs"),
	}
}

// parse pulls the scenario reference out of argv and bounds the flags.
func (f *runFlags) parse(args []string) (string, error) {
	ref, err := parseRef(f.fs, args)
	if err != nil {
		return "", err
	}
	if ref == "" {
		return "", errors.New("a scenario is required")
	}
	if *f.repeat < 1 {
		return "", errors.New("-repeat must be at least 1")
	}
	// Netdoc's own -timeout contract, for the reason huntFlags.parse gives.
	if err := diagnostic.ValidateProbeTimeout(*f.timeout); err != nil {
		return "", err
	}
	return ref, nil
}

// launch is `netdoc-sim run` in the user's own namespaces. It validates the
// scenario where a mistake is cheap, then re-executes itself inside a fresh
// user, network and mount namespace and lets that copy do the work.
func launch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newRunFlags(stderr)
	ref, err := f.parse(args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if _, err := simulation.Load(ref); err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	if caps := newBackend(false, nil).Capabilities(ctx); !caps.Supported {
		fmt.Fprintln(stderr, "netdoc-sim:", caps.Reason)
		return exitError
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	// The netdoc binary is resolved out here, where $PATH and the working
	// directory still mean what the user meant by them.
	path, err := findNetdoc(*f.netdoc, self)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	code, err := launchDirector(ctx, self, directorArgv(f, ref, path), nil, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	return code
}

func launchCampaign(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newCampaignFlags(stderr)
	ref, err := f.parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	scenario, err := simulation.Load(ref)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	if scenario.Campaign == nil {
		fmt.Fprintln(stderr, "netdoc-sim: scenario has no campaign definition")
		return exitUsage
	}
	if caps := newBackend(false, nil).Capabilities(ctx); !caps.Supported {
		fmt.Fprintln(stderr, "netdoc-sim:", caps.Reason)
		return exitError
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	path, err := findNetdoc(*f.netdoc, self)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if !f.seed.set {
		f.seed.v, err = simulation.RandomSeed()
		if err != nil {
			fmt.Fprintln(stderr, "netdoc-sim: choose campaign seed:", err)
			return exitError
		}
		f.seed.set = true
	}
	code, err := launchDirector(ctx, self, campaignDirectorArgv(f, ref, path), nil, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	return code
}

func campaignDirectorArgv(f *campaignFlags, ref, netdoc string) []string {
	return []string{campaignDirectorCommand,
		"-netdoc", netdoc,
		"-timeout", f.timeout.String(),
		"-runs", strconv.Itoa(*f.runs),
		"-seed", strconv.FormatInt(f.seed.v, 10),
		"-iteration", strconv.Itoa(*f.iteration),
		fmt.Sprintf("-json=%t", *f.json),
		fmt.Sprintf("-fail-fast=%t", *f.failFast),
		fmt.Sprintf("-v=%t", *f.verbose),
		"--", ref,
	}
}

func directCampaign(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newCampaignFlags(stderr)
	ref, err := f.parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if !f.seed.set {
		fmt.Fprintln(stderr, "netdoc-sim: internal campaign director did not receive a seed")
		return exitError
	}
	scenario, err := simulation.Load(ref)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	var log io.Writer
	if *f.verbose {
		log = stderr
	}
	var iteration *int
	if *f.iteration >= 0 {
		value := *f.iteration
		iteration = &value
	}
	result := simulation.RunCampaign(ctx, scenario, func() simulation.Backend {
		return newBackend(false, log)
	}, simulation.CampaignOptions{
		Run:  simulation.Options{Netdoc: *f.netdoc, ProbeTimeout: *f.timeout, Log: log},
		Runs: *f.runs, Seed: f.seed.v, Iteration: iteration, FailFast: *f.failFast,
	})
	if *f.json {
		if err := result.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", err)
			return exitError
		}
	} else {
		result.WriteText(stdout)
	}
	switch result.Result {
	case simulation.ResultPass:
		return exitOK
	case simulation.ResultError:
		return exitError
	default:
		return exitMismatch
	}
}

func launchHunt(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "merge" {
		return mergeHunts(args[1:], stdout, stderr)
	}
	f := newHuntFlags(stderr)
	baseID, err := f.parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	base, err := simulation.LibraryScenario(baseID)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	if !f.seed.set {
		f.seed.v, err = simulation.RandomSeed()
		if err != nil {
			fmt.Fprintln(stderr, "netdoc-sim: choose hunt seed:", err)
			return exitError
		}
		f.seed.set = true
	}
	if *f.dry {
		result := simulation.RunHunt(ctx, baseID, base, nil, huntOptions(f, nil, true))
		return writeHuntResult(result, *f.json, stdout, stderr)
	}
	if caps := newBackend(false, nil).Capabilities(ctx); !caps.Supported {
		fmt.Fprintln(stderr, "netdoc-sim:", caps.Reason)
		return exitError
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	path, err := findNetdoc(*f.netdoc, self)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	code, err := launchDirector(ctx, self, huntDirectorArgv(f, baseID, path), nil, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	return code
}

func huntDirectorArgv(f *huntFlags, baseID, netdoc string) []string {
	argv := []string{huntDirectorCommand,
		"-netdoc", netdoc,
		"-timeout", f.timeout.String(),
		"-cases", strconv.Itoa(*f.cases),
		"-seed", strconv.FormatInt(f.seed.v, 10),
		"-case", strconv.Itoa(*f.caseNum),
		"-max-faults", strconv.Itoa(*f.maxFaults),
		"-generator-version", *f.generator,
		"-lane", *f.lane,
		fmt.Sprintf("-json=%t", *f.json),
		fmt.Sprintf("-fail-fast=%t", *f.failFast),
		fmt.Sprintf("-v=%t", *f.verbose),
	}
	if f.shard.set {
		argv = append(argv, "-shard", f.shard.String())
	}
	return append(argv, "--", baseID)
}

func directHunt(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newHuntFlags(stderr)
	baseID, err := f.parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if !f.seed.set {
		fmt.Fprintln(stderr, "netdoc-sim: internal hunt director did not receive a seed")
		return exitError
	}
	base, err := simulation.LibraryScenario(baseID)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	var log io.Writer
	if *f.verbose {
		log = stderr
	}
	result := simulation.RunHunt(ctx, baseID, base, func() simulation.Backend {
		return newBackend(false, log)
	}, huntOptions(f, log, false))
	return writeHuntResult(result, *f.json, stdout, stderr)
}

func huntOptions(f *huntFlags, log io.Writer, dry bool) simulation.HuntOptions {
	var caseNumber *int
	if *f.caseNum >= 0 {
		value := *f.caseNum
		caseNumber = &value
	}
	var shard *simulation.HuntShard
	if f.shard.set {
		value := f.shard.value
		shard = &value
	}
	return simulation.HuntOptions{Cases: *f.cases, Seed: f.seed.v, Case: caseNumber,
		Shard: shard, MaxFaults: *f.maxFaults, GeneratorVersion: *f.generator, Lane: simulation.HuntLane(*f.lane), FailFast: *f.failFast, DryRun: dry,
		Run: simulation.Options{Netdoc: *f.netdoc, ProbeTimeout: *f.timeout, Log: log}}
}

func mergeHunts(paths []string, stdout, stderr io.Writer) int {
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "netdoc-sim: hunt merge needs at least one shard JSON file")
		return exitUsage
	}
	results := make([]*simulation.HuntResult, 0, len(paths))
	for _, path := range paths {
		result, err := readHuntResult(path)
		if err != nil {
			fmt.Fprintf(stderr, "netdoc-sim: read hunt result %s: %s\n",
				textsafe.Clean(path), textsafe.Clean(err.Error()))
			return exitUsage
		}
		results = append(results, result)
	}
	result, err := simulation.MergeHuntResults(results...)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim: merge hunt results:", err)
		return exitUsage
	}
	return writeHuntResult(result, true, stdout, stderr)
}

func readHuntResult(path string) (*simulation.HuntResult, error) {
	// #nosec G304,G703 -- reading the file named by the CLI is this command's purpose.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var result simulation.HuntResult
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return &result, nil
}

func writeHuntResult(result *simulation.HuntResult, jsonOutput bool, stdout, stderr io.Writer) int {
	if jsonOutput {
		if err := result.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", err)
			return exitError
		}
	} else {
		result.WriteText(stdout)
	}
	switch {
	case result.Result == simulation.HuntResultClean:
		return exitOK
	case result.Result == simulation.HuntResultFindings:
		return exitMismatch
	case result.ErrorKind == "configuration" || result.ErrorKind == simulation.FindingGeneratorDefect:
		return exitUsage
	default:
		return exitError
	}
}

// directorArgv builds the director's command line out of what the launcher
// parsed, rather than forwarding the user's argv with an extra flag bolted on
// the front. Forwarding raw would leave two -netdoc flags on the line whenever
// the user passed one, and the flag package takes the last, quietly throwing
// away the path the launcher resolved and validated while $PATH and the working
// directory still meant what the user meant by them.
//
// Every value here is the parsed one rendered canonically, so there is nothing
// left to re-interpret: exactly one occurrence of each flag, and the scenario
// behind a "--" so a reference that starts with a dash stays a scenario.
func directorArgv(f *runFlags, ref, netdoc string) []string {
	return []string{
		directorCommand,
		"-netdoc", netdoc,
		"-timeout", f.timeout.String(),
		"-repeat", strconv.Itoa(*f.repeat),
		fmt.Sprintf("-json=%t", *f.json),
		fmt.Sprintf("-keep=%t", *f.keep),
		fmt.Sprintf("-dry-run=%t", *f.dry),
		fmt.Sprintf("-v=%t", *f.verbose),
		"--", ref,
	}
}

// direct is the run, from inside the namespaces the launcher created.
func direct(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	f := newRunFlags(stderr)
	ref, err := f.parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	scenario, err := simulation.Load(ref)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	var log io.Writer
	if *f.verbose || *f.dry {
		log = stderr
	}
	backend := newBackend(*f.dry, log)
	if *f.dry {
		fmt.Fprintf(stderr, "would run, inside a user namespace owning nothing on this host:\n")
	}
	report := simulation.Run(ctx, scenario, backend, simulation.Options{
		Netdoc:       *f.netdoc,
		ProbeTimeout: *f.timeout,
		Repeat:       *f.repeat,
		Keep:         *f.keep && !*f.dry,
		Log:          log,
	})
	if *f.dry {
		return exitOK
	}
	if *f.json {
		if err := report.WriteJSON(stdout); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", err)
			return exitError
		}
	} else {
		report.WriteText(stdout)
	}
	if *f.keep {
		hold(ctx, report, stdout)
	}
	switch report.Result {
	case simulation.ResultPass:
		return exitOK
	case simulation.ResultError:
		return exitError
	}
	return exitMismatch
}

// hold keeps a simulation alive after its report so the user can walk around
// inside it. The record it leaves is what `list`, `inspect` and `cleanup` read.
func hold(ctx context.Context, report *simulation.Report, w io.Writer) {
	state := simulation.NewState(report.ID, report.Scenario, report.Cleanup.Workspace, report.StartedAt, report.Topology)
	published := false
	if err := state.Save(); err != nil {
		fmt.Fprintln(w, "netdoc-sim: cannot record this simulation:", err)
	} else {
		published = true
	}
	fmt.Fprintf(w, "\nSimulation %s is still up. Enter a node with:\n", report.ID)
	for _, n := range report.Topology {
		fmt.Fprintf(w, "  nsenter -t %d -n -m -- sh   # %s (%s)\n", n.PID, n.Name, n.Address)
	}
	fmt.Fprintf(w, "Release it with `netdoc-sim cleanup %s`, or press Ctrl-C here.\n", report.ID)
	<-ctx.Done()
	// The namespaces go when this process does; the record must not outlive
	// them or `list` would advertise a simulation nobody can enter. A sweep
	// that failed gets said out loud, and `cleanup` can still finish the job.
	if published {
		// #nosec G703 -- state.Save validated this ID and exclusively created the exact record removed here.
		if err := os.Remove(filepath.Join(simulation.StateDir(), report.ID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(w, "netdoc-sim: cleanup:", err)
		}
	}
	// #nosec G703 -- Run returns only the workspace its backend exclusively created.
	if err := os.RemoveAll(report.Cleanup.Workspace); err != nil {
		fmt.Fprintln(w, "netdoc-sim: cleanup:", err)
	}
}

func validate(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "netdoc-sim: validate takes one scenario")
		return exitUsage
	}
	s, err := simulation.Load(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	fmt.Fprintf(stdout, "ok: %s (%d node(s), %d fault(s), %d test(s), %d expected check(s))\n",
		textsafe.Clean(s.Name), len(s.Topology.Nodes), len(s.Faults), len(s.Tests), len(s.Expect.Checks))
	return exitOK
}

func capabilities(ctx context.Context, w io.Writer) int {
	caps := newBackend(false, nil).Capabilities(ctx)
	fmt.Fprintf(w, "Backend:   %s\nSupported: %t\n", caps.Backend, caps.Supported)
	if caps.Reason != "" {
		fmt.Fprintf(w, "Reason:    %s\n", caps.Reason)
	}
	if len(caps.Missing) > 0 {
		fmt.Fprintf(w, "Missing:   %s\n", strings.Join(caps.Missing, ", "))
	}
	fmt.Fprintln(w, "\nA run will:")
	for _, p := range caps.Privileged {
		fmt.Fprintln(w, "  -", p)
	}
	fmt.Fprintln(w, "\nIt will not touch the host's interfaces, routes, resolver or firewall:")
	fmt.Fprintln(w, "  inside its user namespace the simulator has no privileges over them at all.")
	if !caps.Supported {
		return exitError
	}
	return exitOK
}

func list(stdout, stderr io.Writer) int {
	states, err := simulation.ListStates()
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	if len(states) == 0 {
		fmt.Fprintln(stdout, "no simulations are being kept alive")
		return exitOK
	}
	for _, s := range states {
		status := "alive"
		if !s.Alive() {
			status = "gone (run `netdoc-sim cleanup` to sweep)"
		}
		fmt.Fprintf(stdout, "%s  %-40s pid %-7d %s  %s\n", s.ID, textsafe.Clean(s.Scenario), s.PID,
			s.Started.Format(time.RFC3339), status)
	}
	return exitOK
}

// starters is the discovery half of the starter packs: which ones exist, and
// with a pack named, the challenge ids in it. It prints the ids on purpose:
// they are ordinary challenge ids, so a beginner can work through a pack in
// order with -id instead of drawing from it and hoping.
func starters(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "netdoc-sim: starters takes one pack name, or none to list them all")
		return exitUsage
	}
	if len(args) == 0 {
		fmt.Fprintln(stdout, "Starter packs: curated challenges to learn on. Play one with:")
		fmt.Fprintln(stdout, "  netdoc-sim challenge -starter <pack>")
		fmt.Fprintln(stdout, "\nA pack names the layer you are practising, which is a hint you asked for.")
		fmt.Fprintln(stdout, "Which fault it is remains yours to find, and one entry per pack may be")
		fmt.Fprintln(stdout, "a network with nothing wrong with it at all.")
		fmt.Fprintln(stdout)
		for _, pack := range simulation.StarterPacks() {
			fmt.Fprintf(stdout, "  %-14s %-34s %d challenges\n", pack.ID, pack.Name, len(pack.Challenges))
			fmt.Fprintf(stdout, "  %-14s %s\n\n", "", pack.Description)
		}
		fmt.Fprintln(stdout, "'netdoc-sim starters <pack>' lists a pack's challenge ids in order.")
		return exitOK
	}
	pack, ok := simulation.StarterPackByID(args[0])
	if !ok {
		fmt.Fprintf(stderr, "netdoc-sim: unknown starter pack %q (have: %s)\n",
			textsafe.Clean(args[0]), strings.Join(simulation.StarterPackNames(), ", "))
		return exitUsage
	}
	fmt.Fprintf(stdout, "%s: %s\n%s\n\n", pack.ID, pack.Name, pack.Description)
	fmt.Fprintln(stdout, "In order, easiest first:")
	for _, id := range pack.Challenges {
		fmt.Fprintf(stdout, "  netdoc-sim challenge -id %s\n", id)
	}
	return exitOK
}

var aliveWord = map[bool]string{true: "alive", false: "gone"}

func inspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "netdoc-sim: inspect takes one simulation id")
		return exitUsage
	}
	s, err := simulation.LoadState(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	fmt.Fprintf(stdout, "Simulation %s (%s)\n  started   %s\n  director  pid %d (%s)\n  workspace %s\n\n",
		s.ID, textsafe.Clean(s.Scenario), s.Started.Format(time.RFC3339), s.PID, aliveWord[s.Alive()], s.Workspace)
	for _, n := range s.Nodes {
		fmt.Fprintf(stdout, "  %-10s %-14s %s\n", n.Name, n.Address, strings.Join(n.Services, " "))
		fmt.Fprintf(stdout, "             nsenter -t %d -n -m -- sh\n", n.PID)
	}
	return exitOK
}

// newCleanupFlags is built apart from the command for the same reason every
// other command's flags are: the packaging tests read the flag set to find out
// what netdoc-sim accepts, rather than keeping a second list of their own.
func newCleanupFlags(out io.Writer) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet("netdoc-sim cleanup", flag.ContinueOnError)
	fs.SetOutput(out)
	return fs, fs.Bool("all", false, "release every kept simulation")
}

func cleanup(args []string, stdout, stderr io.Writer) int {
	fs, all := newCleanupFlags(stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	var states []*simulation.State
	switch {
	case *all && fs.NArg() > 0:
		fmt.Fprintln(stderr, "netdoc-sim: -all takes no simulation id")
		return exitUsage
	case *all:
		var err error
		if states, err = simulation.ListStates(); err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", err)
			return exitError
		}
	case fs.NArg() == 1:
		s, err := simulation.LoadState(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
			return exitUsage
		}
		states = []*simulation.State{s}
	default:
		fmt.Fprintln(stderr, "netdoc-sim: cleanup takes one simulation id, or -all")
		return exitUsage
	}
	if len(states) == 0 {
		fmt.Fprintln(stdout, "nothing to clean up")
		return exitOK
	}
	code := exitOK
	for _, s := range states {
		if err := s.Release(); err != nil {
			// Never silent: a cleanup that half worked is the one thing the
			// user has to know about.
			fmt.Fprintf(stderr, "netdoc-sim: %s: %s\n", s.ID, textsafe.Clean(err.Error()))
			code = exitError
			continue
		}
		fmt.Fprintf(stdout, "released %s (%s)\n", s.ID, textsafe.Clean(s.Scenario))
	}
	return code
}

// findNetdoc locates the binary the tests will run, in one order: the one asked
// for with -netdoc, else one sitting next to netdoc-sim, else one on $PATH. A
// build in the repo root beside a `go run ./cmd/netdoc-sim` binary will not be
// found, which is why the error says how to point at one.
//
// -netdoc never falls back. An explicit binary that cannot be executed is an
// error, because quietly running a different netdoc than the one named would
// make every result it produced a lie about which build was measured.
//
// The result is always absolute: it is forwarded across a re-execution into new
// namespaces, and it is recorded as the identity of what ran.
func findNetdoc(want, self string) (string, error) {
	if want != "" {
		path, err := exec.LookPath(want)
		if err != nil {
			return "", fmt.Errorf("-netdoc %s: %w", want, err)
		}
		return filepath.Abs(path)
	}
	// LookPath rather than Stat: the sibling has to be something this OS will
	// actually execute, meaning the executable bit on Unix or a PATHEXT suffix on
	// Windows, or a file that merely has the right name shadows a working
	// netdoc on $PATH and the run dies later, at exec time, for no visible
	// reason. LookPath also reports which name it settled on, which is the path
	// worth recording.
	sibling := filepath.Join(filepath.Dir(self), "netdoc")
	if path, err := exec.LookPath(sibling); err == nil {
		return filepath.Abs(path)
	}
	if path, err := exec.LookPath("netdoc"); err == nil {
		return filepath.Abs(path)
	}
	return "", errors.New("cannot find the netdoc binary: build one with `go build -o netdoc .` and pass it with -netdoc ./netdoc")
}

// netdocVersionTimeout bounds the one -version call. Printing a string needs no
// network, no privilege and no namespace, so a binary slower than this is not
// one a simulation is going to survive either.
const netdocVersionTimeout = 5 * time.Second

// netdocIdentity is which Network Doctor a run launched: the resolved path, and
// what that same executable answers for -version. Both travel with the run and
// land in the result, so a saved challenge names the build that produced it
// rather than whatever `netdoc` happens to mean on the next machine.
type netdocIdentity struct {
	path    string
	version string
}

// resolveNetdoc does the lookup once and then interrogates exactly what the
// lookup returned. Keeping the two together is the point: a version read from
// anywhere else (the checkout, a filename, a second lookup) can describe a
// different binary than the one the run executes.
func resolveNetdoc(ctx context.Context, want, self string) (netdocIdentity, error) {
	path, err := findNetdoc(want, self)
	if err != nil {
		return netdocIdentity{}, err
	}
	version, err := netdocVersion(ctx, path)
	if err != nil {
		return netdocIdentity{}, err
	}
	return netdocIdentity{path: path, version: version}, nil
}

// netdocVersion asks the binary what it is, through netdoc's own -version
// interface. The line is recorded as given, minus surrounding whitespace: a
// local build legitimately reports `dev`, and inventing a release version for
// it would be worse than recording the truth.
func netdocVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, netdocVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		return "", fmt.Errorf("%s -version: %w", path, err)
	}
	version := textsafe.Clean(strings.TrimSpace(string(out)))
	if version == "" {
		return "", fmt.Errorf("%s -version: printed no version", path)
	}
	return version, nil
}

// authored is the discovery half of the authored challenges: which ones exist,
// what each is for, and the ordinary challenge id that plays it. Like a starter
// pack, it prints the ids rather than hiding them: an authored challenge is a
// normal shareable id, and printing it is what lets somebody replay or post one
// without going back through this command.
func authored(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(stderr, "netdoc-sim: authored takes no arguments")
		return exitUsage
	}
	fmt.Fprintln(stdout, "Authored challenges: hand-written cases, each setting a chosen fault. Play one with:")
	fmt.Fprintln(stdout, "  netdoc-sim challenge -authored <slug>")
	fmt.Fprintln(stdout, "\nEach is an ordinary challenge id, so it can also be replayed or shared with -id.")
	fmt.Fprintln(stdout, "The line under each name says what telling it apart requires, never what it is.")
	fmt.Fprintln(stdout)
	for _, item := range simulation.AuthoredChallenges() {
		fmt.Fprintf(stdout, "  %-28s %-10s %s\n", item.Slug, item.ID, item.Name)
		fmt.Fprintf(stdout, "  %-28s %-10s %s\n\n", "", "", item.Teaches)
	}
	return exitOK
}
