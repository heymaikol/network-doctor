package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/peer"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/report"
	"github.com/heymaikol/network-doctor/internal/snapshot"
	"github.com/heymaikol/network-doctor/internal/textsafe"
	"github.com/heymaikol/network-doctor/internal/ui"
)

// version is what -version reports and what artifacts stamp. Run sets it
// from the build version the entrypoint resolved.
var version = "dev"

// Run drives the whole CLI and returns the exit code. buildVersion is what
// the entrypoint's -ldflags "-X main.version=..." stamped, "dev" for a local
// build; the module version stamped into the binary takes over there.
func Run(buildVersion string, args []string, stdout, stderr io.Writer) int {
	if info, ok := debug.ReadBuildInfo(); ok {
		version = versionString(buildVersion, info.Main.Version)
	} else {
		version = buildVersion
	}
	return run(args, stdout, stderr)
}

// versionString picks what -version reports: the build-time injected value
// when there is one, else the module version stamped into the binary, so a
// plain `go install ...@vX.Y.Z` build doesn't introduce itself as "dev".
func versionString(injected, module string) string {
	if injected == "dev" && module != "" && module != "(devel)" {
		return module
	}
	return injected
}

func run(args []string, stdout, stderr io.Writer) int {
	// The SSH login form (S) runs this binary as ssh's askpass helper so the
	// password reaches ssh through the environment instead of an argv every
	// process on the machine could read. First thing in run: ssh wants a
	// secret on stdout and nothing else.
	if secret, ok := os.LookupEnv(ui.AskpassEnv); ok {
		return askpass(args, secret, os.Getenv(ui.AskpassHostEnv), os.Getenv(ui.AskpassProxyEnv) != "", stdout, stderr)
	}
	// The far end of --via, checked before the flag set exists. It is not a
	// flag: it never appears in --help, on a man page, or in a completion,
	// because it is one netdoc talking to another and there is nothing for a
	// person to spell here. Nothing may be combined with it either, which is
	// what makes the remote command line a fixed string with no user text in
	// it. From here on its stdout is the protocol and carries one JSON object;
	// everything meant for a human goes to stderr.
	if len(args) > 0 && remote.IsWorkerFlag(args[0]) {
		if len(args) != 1 {
			fmt.Fprintf(stderr, "netdoc: %s takes no other arguments\n", remote.WorkerFlag)
			return 2
		}
		return runRemoteWorker(context.Background(), stdout, stderr)
	}
	fs := flag.NewFlagSet("netdoc", flag.ContinueOnError)
	profiles := profile.Builtins()
	// Buffered, not stderr: the flag package quotes nothing, so an undefined
	// flag name made of escape bytes would land on the terminal verbatim.
	var flagErr bytes.Buffer
	fs.SetOutput(&flagErr)
	// Suppress the automatic usage dump: an explicit -help prints the full
	// usage on stdout and exits 0, a parse error gets only a one-line hint.
	fs.Usage = func() {}
	toolbox := fs.Bool("toolbox", false, "start in toolbox mode")
	jsonOut := fs.Bool("json", false, "run the checks headless and print a JSON report")
	save := fs.String("save", "", "run the checks headless and write a diagnostic snapshot to `file` (.ndoc)")
	support := fs.String("support", "", "run the checks headless and write a sanitized support snapshot to `file` (.ndoc)")
	compareMode := fs.Bool("compare", false, "compare two saved snapshots given as arguments; runs no probes")
	twoSided := fs.Bool("two-sided", false, "localize a failure from two saved snapshots, or from local and -via live runs")
	watch := fs.Bool("watch", false, "continuously re-run checks (with -json, stream one report per line)")
	profileName := fs.String("profile", "", "run a service `profile` ("+strings.Join(profiles.Names(), ", ")+"; use list to describe them)")
	var peerListen peerListenList
	fs.Var(&peerListen, "peer-listen", "listen for one authenticated peer on exact `IP:port`; repeat for the other address family")
	peerConnect := fs.Bool("peer-connect", false, "read a temporary pairing string securely and run a two-ended diagnosis")
	viaDest := fs.String("via", "", "run the checks on this SSH `destination` instead of on this machine")
	iface := fs.String("iface", "", "bind probes to an interface name or exact local IP")
	publicDNS := fs.String("public-dns", diagnostic.DefaultPublicDNS, "second-opinion DNS resolver IP; empty skips that check")
	var checks, skips probeList
	fs.Var(&checks, "check", "run stable probe IDs in `probe[,probe...]` form; repeatable")
	fs.Var(&skips, "skip", "skip stable probe IDs in `probe[,probe...]` form; repeatable")
	noReferenceEgress := fs.Bool("no-reference-egress", false, "make no connections to netdoc's own built-in reference services; the target, profile endpoints, and this machine's configured DNS and routing still apply")
	noHistory := fs.Bool("no-history", false, "don't read or write the saved target history")
	keys := fs.String("keys", "", "keybinding `preset` for the TUI: "+strings.Join(ui.KeyPresets(), " or "))
	listChecks := fs.Bool("list-checks", false, "list stable probe IDs accepted by -check and -skip, then exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	timeout := fs.Duration("timeout", diagnostic.DefaultProbeTimeout, "per-check probe timeout")

	// The stdlib flag package stops parsing at the first non-flag argument;
	// peel positionals off and re-parse the remainder so flags are accepted
	// both before and after the target.
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				printUsage(stdout, fs)
				return 0
			}
			if msg := textsafe.Clean(strings.TrimSpace(flagErr.String())); msg != "" {
				fmt.Fprintln(stderr, msg)
			}
			fmt.Fprintln(stderr, "run 'netdoc --help' for usage")
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	// One argument everywhere except the two artifact readings. With -via,
	// -two-sided is a live target run again and accepts at most one target.
	liveTwoSided := *twoSided && *viaDest != ""
	if liveTwoSided && len(positional) > 1 {
		fmt.Fprintln(stderr, "netdoc: live -two-sided accepts at most one target; remove -via to read two snapshot files")
		return 2
	}
	allowed := 1
	if *compareMode || *twoSided && !liveTwoSided {
		allowed = 2
	}
	if len(positional) > allowed {
		// %q, not %v: argv is untrusted enough to matter, and quoting escapes
		// control bytes so an OSC 52 in an argument prints instead of running.
		fmt.Fprintf(stderr, "netdoc: unexpected arguments: %q\n", positional[allowed:])
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "netdoc", version)
		return 0
	}
	if *listChecks {
		setFlags := setFlagNames(fs)
		delete(setFlags, "list-checks")
		if len(positional) != 0 || len(setFlags) != 0 {
			fmt.Fprintln(stderr, "netdoc: -list-checks cannot be combined with a target or other flags")
			return 2
		}
		for _, probe := range diagnostic.StableProbes() {
			fmt.Fprintf(stdout, "%s\t%s\n", probe.ID, probe.Name)
		}
		return 0
	}
	if setFlagNames(fs)["profile"] && *profileName == "" {
		fmt.Fprintln(stderr, "netdoc: -profile needs a name; use -profile list to see available profiles")
		return 2
	}
	if *profileName == "list" {
		setFlags := setFlagNames(fs)
		delete(setFlags, "profile")
		if len(positional) != 0 || len(setFlags) != 0 {
			fmt.Fprintln(stderr, "netdoc: -profile list cannot be combined with a target or other flags")
			return 2
		}
		printProfiles(stdout, profiles)
		return 0
	}
	var profilePlan *profile.Plan
	// Before every other mode, and before a single probe flag is validated:
	// the artifact readings touch the network at no point, so settings that
	// decide what probes do have nothing to say about them. The live two-sided
	// form continues below because it does perform ordinary runs.
	if *compareMode && *twoSided {
		fmt.Fprintln(stderr, "netdoc: -compare and -two-sided cannot be combined")
		return 2
	}
	if *compareMode {
		return runCompare(positional, setFlagNames(fs), *jsonOut, stdout, stderr)
	}
	// The second reading of the same two files, and headless and probe-free for
	// the same reason: it asks where a failure is rather than what changed, and
	// everything it answers with comes out of the artifacts.
	if *twoSided && !liveTwoSided {
		return runTwoSided(positional, setFlagNames(fs), *jsonOut, stdout, stderr)
	}
	if liveTwoSided && rejectLiveTwoSidedFlags(setFlagNames(fs), stderr) {
		return 2
	}
	if *profileName != "" {
		definition, ok := profiles.Lookup(*profileName)
		if !ok {
			fmt.Fprintf(stderr, "netdoc: -profile: unknown profile %q; available profiles: %s\n", textsafe.Clean(*profileName), strings.Join(profiles.Names(), ","))
			return 2
		}
		rawTarget := ""
		if len(positional) == 1 {
			rawTarget = positional[0]
		}
		plan, err := definition.Plan(rawTarget)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc: -profile:", textsafe.Clean(err.Error()))
			return 2
		}
		profilePlan = &plan
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "netdoc: -timeout must be positive")
		return 2
	}
	peerMode := len(peerListen) > 0 || *peerConnect
	if len(peerListen) > 0 && *peerConnect {
		fmt.Fprintln(stderr, "netdoc: -peer-listen and -peer-connect cannot be combined")
		return 2
	}
	if peerMode {
		setFlags := setFlagNames(fs)
		for _, name := range []string{"toolbox", "watch", "profile", "check", "skip", "no-reference-egress", "public-dns", "no-history", "keys", "save", "support", "via"} {
			if setFlags[name] {
				fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with peer mode\n", name)
				return 2
			}
		}
		if len(positional) != 0 {
			fmt.Fprintln(stderr, "netdoc: a target cannot be combined with peer mode")
			return 2
		}
		if len(peerListen) > 0 && *iface != "" {
			fmt.Fprintln(stderr, "netdoc: -iface cannot be combined with -peer-listen; bind the exact interface address instead")
			return 2
		}
		if *timeout > peer.MaxOperationTimeout {
			fmt.Fprintf(stderr, "netdoc: peer mode -timeout cannot exceed %s\n", peer.MaxOperationTimeout)
			return 2
		}
	}
	if *jsonOut && *toolbox {
		fmt.Fprintln(stderr, "netdoc: -json and -toolbox cannot be combined")
		return 2
	}
	if profilePlan != nil {
		setFlags := setFlagNames(fs)
		for _, name := range []string{"toolbox", "keys"} {
			if setFlags[name] {
				fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -profile; profiles are headless\n", name)
				return 2
			}
		}
		if *watch && !*jsonOut {
			fmt.Fprintln(stderr, "netdoc: -watch with -profile requires -json")
			return 2
		}
	}
	// --via is headless, and both of these are the interactive session it does
	// not have. -watch is the sharper one: a watch is a session that keeps
	// re-running, and re-running it would be one SSH connection per pass, which
	// is a different feature and not this one.
	if *viaDest != "" {
		setFlags := setFlagNames(fs)
		for _, name := range []string{"toolbox", "watch"} {
			if setFlags[name] {
				fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -via\n", name)
				return 2
			}
		}
	}
	if *save != "" && *support != "" {
		fmt.Fprintln(stderr, "netdoc: -save and -support cannot be combined")
		return 2
	}
	artifact, artifactFlag := *save, "-save"
	if *support != "" {
		artifact, artifactFlag = *support, "-support"
	}
	if artifact != "" {
		if *toolbox {
			fmt.Fprintf(stderr, "netdoc: %s and -toolbox cannot be combined\n", artifactFlag)
			return 2
		}
		// A snapshot is one finished run, and -watch never finishes: writing
		// one per pass would leave whichever pass happened to be last, which is
		// not a decision to make silently. Recording a watch is its own
		// feature, and this is not it.
		if *watch {
			fmt.Fprintf(stderr, "netdoc: %s and -watch cannot be combined\n", artifactFlag)
			return 2
		}
		// Checked before any probe runs: a snapshot into a directory that is
		// not there is a typo, and finding out after several seconds of
		// network traffic helps nobody. This is the argument check every other
		// flag gets, not a claim that the write will succeed.
		if dir := filepath.Dir(artifact); dir != "" {
			info, err := os.Stat(dir)
			if err != nil {
				fmt.Fprintln(stderr, "netdoc:", artifactFlag+":", textsafe.Clean(err.Error()))
				return 2
			}
			if !info.IsDir() {
				fmt.Fprintf(stderr, "netdoc: %s: %s is not a directory\n", artifactFlag, textsafe.Clean(dir))
				return 2
			}
		}
	}
	// An IP, never a hostname: resolving the second opinion through the
	// resolver it exists to cross-check would defeat the check. Empty is a
	// deliberate opt-out and the one value that isn't validated, because nothing is
	// dialed, so there is nothing to parse.
	if *publicDNS != "" {
		ip := net.ParseIP(*publicDNS)
		if ip == nil {
			fmt.Fprintf(stderr, "netdoc: -public-dns: %q is not an IP address\n", textsafe.Clean(*publicDNS))
			return 2
		}
		*publicDNS = ip.String() // canonical form, so the row label matches the probe
	}
	// Nobody named a resolver, so the row is free to follow whichever address
	// family this machine can actually use. Asked of the flag set rather than
	// of the value, because the default is a real address a user may also type,
	// and typing it is a choice this must not overrule.
	publicDNSAuto := !setFlagNames(fs)["public-dns"]
	// Not resolved for --via: -iface names an interface on the machine the
	// probes run on, and for a remote run that is the far end. The spelling is
	// forwarded and the remote resolves it with this same function, so the flag
	// keeps meaning what it means rather than quietly binding a local NIC.
	var sources *diagnostic.SourceAddresses
	if *iface != "" && *viaDest == "" {
		var err error
		sources, err = diagnostic.ResolveSource(*iface)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc: -iface:", err)
			return 2
		}
	}
	if peerMode {
		options := peer.Options{Version: version, Timeout: *timeout, Sources: sources}
		if len(peerListen) > 0 {
			return runPeerListener(context.Background(), peerListen, options, *jsonOut, stdout, stderr)
		}
		return runPeerConnector(context.Background(), options, *jsonOut, stdout, stderr)
	}

	var t *diagnostic.Target
	if profilePlan == nil && len(positional) == 1 {
		parsed, err := diagnostic.ParseTarget(positional[0])
		if err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 2 // bad args / validation reject
		}
		t = parsed
	}
	selection := diagnostic.ProbeSelection{Check: checks.set(), Skip: skips.set()}
	if *noReferenceEgress {
		// Resolved once, against the shape this invocation has: which rows are
		// built-in reference egress depends on whether a target was named, and
		// on whether the second-opinion resolver was.
		reference := diagnostic.ReferenceEgressProbes(t != nil || profilePlan != nil, !publicDNSAuto)
		// The safety property is absolute, so a selector that asks for one of
		// these is a contradiction rather than a later word that wins. Refused
		// before a probe runs, and named, so it is clear which half to drop.
		for _, id := range reference {
			if _, requested := selection.Check[id]; requested {
				fmt.Fprintf(stderr, "netdoc: -check %s runs a built-in reference service, which -no-reference-egress forbids; drop one of the two\n", id)
				return 2
			}
		}
		// Lowered into the ordinary skip list, so the settings that describe
		// this run already carry it: the snapshot records it, and a --via
		// worker honors it without needing to know the flag exists.
		skips = append(skips, reference...)
		selection.Skip = skips.set()
		// That list is right for the run as invoked, and the TUI can restart
		// on a target the command line never saw, which changes which rows are
		// reference rows. From here on the graph's own marks decide.
		selection.NoReferenceEgress = true
	}
	if err := selection.Validate(); err != nil {
		fmt.Fprintln(stderr, "netdoc:", err)
		return 2
	}
	// Resolve once here, then pass the result straight to the TUI.
	keymap, err := ui.PresetKeymap(*keys)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc: -keys:", err)
		return 2
	}

	h := headless{
		target: t, sources: sources, iface: *iface, selection: selection,
		check: checks, skip: skips, publicDNS: *publicDNS, publicDNSAuto: publicDNSAuto, timeout: *timeout,
		watch: *watch, json: *jsonOut, save: artifact, support: *support != "",
	}
	h.via, h.viaCommand = *viaDest, os.Getenv(remote.CommandEnv)
	if liveTwoSided {
		return runLiveTwoSided(context.Background(), h, stdout, stderr)
	}
	if profilePlan != nil {
		return runProfile(context.Background(), h, *profilePlan, stdout, stderr)
	}
	// --via is headless for the same reason -json is: the run is over by the
	// time this process has anything to show. There is no live scheduling to
	// watch either, because the probes are running on another machine.
	if *viaDest != "" {
		return runVia(context.Background(), h, stdout, stderr)
	}

	// -save runs headless for the same reason -json does: a snapshot is a
	// finished run, and the TUI's run is not finished until the user leaves it.
	if *jsonOut || artifact != "" {
		return runHeadless(context.Background(), h, stdout, stderr)
	}

	// With no terminal on stdout the TUI has nowhere to draw: bubbletea would
	// fail on its own with a /dev/tty message that reads like a bug, and it
	// would spend exit 1, which is already "a check failed". Name the fix and
	// exit 2 instead: the environment is wrong, not the network.
	if !stdoutIsTerminal(stdout) {
		fmt.Fprintln(stderr, "netdoc: stdout is not a terminal; use --json for non-interactive output")
		return 2
	}

	// No mouse tracking: terminals translate the wheel to arrow keys in the
	// alt screen (alternate scroll), and grabbing the mouse would break
	// native text selection.
	p := tea.NewProgram(ui.NewWithSelection(t, sources, *toolbox, *watch, historyFile(*noHistory), version, *publicDNS, publicDNSAuto, selection,
		ui.WithKeymap(keymap), ui.WithProbeTimeout(*timeout), ui.WithThemeFile(themeFile()),
		ui.WithSnapshotSelection(checks.strings(), skips.strings())), tea.WithAltScreen())
	final, err := p.Run()
	// Every way out of Run lands here, including the ones that never reached
	// the model's own quit path.
	ui.Cleanup(final)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", err)
		return 1
	}
	return ui.ExitCode(final)
}

// artifactReadingFlags is every flag that describes a run netdoc would perform.
// Neither reading of two saved snapshots performs one: both read two finished
// runs off disk. The settings that produced them are already recorded in the
// files, and letting one be named again here would suggest it applied to
// something.
var artifactReadingFlags = []string{
	"toolbox", "watch", "save", "support", "peer-listen", "peer-connect", "via",
	"profile", "check", "skip", "no-reference-egress", "iface", "public-dns", "no-history", "keys", "timeout",
}

// Live two-sided mode performs one ordinary run per machine. Probe settings
// with the same meaning on both machines are allowed; presentation modes,
// multi-run modes, and settings tied to one machine are not.
var liveTwoSidedRejectedFlags = []string{
	"toolbox", "watch", "save", "support", "profile", "peer-listen", "peer-connect", "no-history", "keys",
}

func rejectLiveTwoSidedFlags(setFlags map[string]bool, stderr io.Writer) bool {
	if setFlags["iface"] {
		fmt.Fprintln(stderr, "netdoc: -iface cannot be combined with live -two-sided; one interface selector cannot name both machines")
		return true
	}
	for _, name := range liveTwoSidedRejectedFlags {
		if setFlags[name] {
			fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with live -two-sided\n", name)
			return true
		}
	}
	return false
}

// rejectRunFlags refuses the settings that cannot apply to a reading of two
// finished runs. mode is the flag that selected the reading, so the message
// names the command the user actually typed.
func rejectRunFlags(mode string, setFlags map[string]bool, stderr io.Writer) bool {
	for _, name := range artifactReadingFlags {
		if setFlags[name] {
			fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -%s\n", name, mode)
			return true
		}
	}
	return false
}

func emitTwoSided(result compare.TwoSided, jsonOut bool, human string, stdout, stderr io.Writer) int {
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	} else {
		fmt.Fprint(stdout, human)
	}
	if result.Placed() {
		return 1
	}
	return 0
}

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

// remoteRun is stubbed in tests, which have no SSH server to talk to.
var remoteRun = remote.Run

// workerStdin is the protocol's inbound channel, stubbed in tests.
var workerStdin io.Reader = os.Stdin

func requestForRemote(h headless) remote.Request {
	req := remote.Request{
		Iface: h.iface, PublicDNS: h.publicDNS, PublicDNSAuto: h.publicDNSAuto,
		TimeoutMs: h.timeout.Milliseconds(),
		Check:     h.check.strings(), Skip: h.skip.strings(),
	}
	if h.target != nil {
		// The remote parses the same validated spelling again, so a build that
		// resolves it differently records that difference in its snapshot.
		req.Target = h.target.Raw
	}
	return req
}

// runVia performs the diagnosis on another machine and presents it here.
//
// Nothing about the answer is re-derived locally. The report and the snapshot
// that come back were built and interpreted on the machine that ran the
// probes, which is the only machine that can interpret them: the remediation
// for a finding is chosen by operating system, and a Windows laptop's advice is
// not this Linux box's to rewrite. What is decided here is what a local run
// decides for itself, which is how the answer is presented and what the process
// exits with.
//
// Exit code is the ordinary contract, and deliberately: a remote network that
// fails a check is exit 1, exactly as a local one is, while a connection that
// never delivered a diagnosis is exit 2, the environment-is-wrong code. Those
// two must not be confusable, because "the network you asked about is broken"
// and "I could not reach the machine to ask" are opposite conclusions.
func runVia(parent context.Context, h headless, stdout, stderr io.Writer) int {
	// The same interruption path a headless run uses. Cancelling kills the ssh
	// process, which drops the channel, which is the EOF the remote worker
	// stops on, so a Ctrl-C here does not leave probes running over there.
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	resp, err := remoteRun(ctx, h.via, h.viaCommand, requestForRemote(h))
	if err != nil {
		fmt.Fprintln(stderr, "netdoc: -via:", err)
		// An interrupted run is exit 1, the code quitting before the chain
		// finished already spends locally. Only a transport that failed on its
		// own is the environment-is-wrong 2, and the difference is whether this
		// process was the one that stopped it.
		if ctx.Err() != nil {
			return 1
		}
		return 2
	}
	// Provenance on stderr, never stdout: with -json, stdout stays the report
	// and nothing else, byte for byte what a local run leaves in a pipe.
	fmt.Fprintf(stderr, "Diagnosed on %s by netdoc %s (%s/%s)\n", textsafe.Clean(h.via),
		textsafe.Clean(resp.Tool.Version), textsafe.Clean(resp.Tool.OS), textsafe.Clean(resp.Tool.Arch))

	rep := *resp.Report
	switch {
	case h.json:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	case h.save == "":
		// The one presentation --via adds. A local run with neither -json nor
		// an artifact has the TUI; a remote one has no live run to draw, so the
		// finished report is written out instead. A run asked for an artifact
		// stays silent on stdout, the same as a local -save does.
		fmt.Fprint(stdout, reportText(rep))
	}
	if h.save != "" {
		if err := saveSnapshot(h, *resp.Snapshot); err != nil {
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
	if rep.OK {
		return 0
	}
	return 1
}

// runRemoteWorker is the other end of --via, running on the machine being
// diagnosed. It reads one request, runs it, and writes one response.
//
// Its exit status is about the protocol and not about the network: a completed
// exchange is 0 even when every check failed, because the diagnosis travels
// inside the response and the local side spends the exit code for it. ssh
// hands the remote status back to the local process, and a worker that failed
// the exchange for a bad connection would be indistinguishable from one that
// answered "this network is broken".
func runRemoteWorker(parent context.Context, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	tool := snapshot.Tool{Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if err := remote.Serve(ctx, workerStdin, stdout, tool, diagnoseRemote); err != nil {
		// The response never landed, so there is nothing structured to say it
		// with. stderr is all that is left, and ssh delivers it to the caller.
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 1
	}
	return 0
}

// diagnoseRemote turns one remote request into the same headless run netdoc
// performs for itself, using the same parsers, the same probe graph, and the
// same report and snapshot builders. There is no remote-only diagnosis path,
// and that is the point: --via cannot drift from a local run, because there is
// nothing for it to drift from.
//
// Every field of the request is untrusted text that arrived over a pipe, so
// every field goes through the validation the CLI applies to the same flag.
// A rejection is returned rather than printed: the local side is the one with a
// terminal, and it prints what comes back.
func diagnoseRemote(ctx context.Context, req remote.Request) (*report.Report, *snapshot.Snapshot, error) {
	h := headless{
		iface:     req.Iface,
		publicDNS: req.PublicDNS,
		// Absent from a netdoc that predates the automatic default, and absent
		// means false: an old local side named this resolver as far as it knew,
		// and reinterpreting its request would answer a question it never asked.
		publicDNSAuto: req.PublicDNSAuto,
		timeout:       time.Duration(req.TimeoutMs) * time.Millisecond,
	}
	if h.timeout <= 0 {
		return nil, nil, errors.New("-timeout must be positive")
	}
	if req.Target != "" {
		t, err := diagnostic.ParseTarget(req.Target)
		if err != nil {
			return nil, nil, err
		}
		h.target = t
	}
	// Validated exactly as the local flag is: an address or empty, which is
	// what every protocol 1 netdoc has ever put in this field. Whether the
	// caller named it is the separate bit above, and it is the far end that
	// turns that into candidates, so a dual-stack caller cannot pin this
	// machine to a family it does not have.
	if req.PublicDNS != "" {
		ip := net.ParseIP(req.PublicDNS)
		if ip == nil {
			return nil, nil, fmt.Errorf("-public-dns: %q is not an IP address", textsafe.Clean(req.PublicDNS))
		}
		// Canonicalized here for the same reason a local run canonicalizes it,
		// and it has to be the same reason: the row label has to match the
		// probe, and the snapshot records this text for a later comparison to
		// read. A remote run that kept the user's spelling would differ from a
		// local one over a setting neither of them changed.
		h.publicDNS = ip.String()
	}
	for _, list := range []struct {
		dst *probeList
		ids []string
	}{{&h.check, req.Check}, {&h.skip, req.Skip}} {
		for _, id := range list.ids {
			if err := list.dst.Set(id); err != nil {
				return nil, nil, err
			}
		}
	}
	h.selection = diagnostic.ProbeSelection{Check: h.check.set(), Skip: h.skip.set()}
	if err := h.selection.Validate(); err != nil {
		return nil, nil, err
	}
	// Resolved here and nowhere else: -iface names an interface on this
	// machine, and this is the machine the probes run on.
	if req.Iface != "" {
		sources, err := diagnostic.ResolveSource(req.Iface)
		if err != nil {
			return nil, nil, fmt.Errorf("-iface: %s", textsafe.Clean(err.Error()))
		}
		h.sources = sources
	}

	probes := h.selection.Apply(diagnostic.BuildProbesFromSources(h.target, h.sources, h.publicDNS, h.publicDNSAuto))
	results := runAll(ctx, probes, h.timeout)
	if ctx.Err() != nil {
		// Cancelled mid-pass, which for a worker means the local side went
		// away. Every probe failed because we stopped it, so reporting that
		// pass would be a lie, the same judgement a local interrupted run makes.
		return nil, nil, errors.New("the run was interrupted before it finished")
	}
	rep := buildReport(h.target, probes, results)
	s := buildSnapshotArtifact(h, probes, results)
	return &rep, &s, nil
}

// timeNow is stubbed in tests so a snapshot's timestamp is reproducible.
var timeNow = time.Now
