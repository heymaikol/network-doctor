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
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/peer"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/remote"
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

// timeNow is stubbed in tests so a snapshot's timestamp is reproducible.
var timeNow = time.Now
