package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/simulation"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Challenge Mode: one foreground session, start to finish.
//
// It is not split into start/shell/diagnose/reveal commands because a simulated
// network only exists while the process holding its namespaces does. Separate
// commands would need a daemon and a state file to point at it; one session
// needs neither, and gets the two properties that matter for free: the player
// and netdoc cannot be handed different networks, and the network is gone when
// the command returns.

// challengeNoteLimit bounds the free-text note. It is recorded and printed, not
// scored, so it only has to be short enough to stay a note.
const challengeNoteLimit = 200

type challengeFlags struct {
	fs         *flag.FlagSet
	id         *string
	difficulty *string
	daily      *dailyFlag
	starter    *string
	authored   *string
	answer     *string
	giveUp     *bool
	json       *bool
	netdoc     *string
	// dailyDate is not for people to set either. -daily is resolved out in the
	// launcher, where the clock is; the director is handed the id it resolved to
	// plus the date it was the daily for, so the result can say which day it was
	// without the director having to read a clock of its own.
	dailyDate *string
	// netdocVersion is not for people to set. The launcher resolves the binary
	// and asks it for its version out here, where $PATH and the working
	// directory still mean what the user meant, and hands both to the director
	// so the identity in the result belongs to the binary that was found.
	netdocVersion *string
	timeout       *time.Duration
	verbose       *bool
}

func newChallengeFlags(out io.Writer) *challengeFlags {
	f := &challengeFlags{fs: flag.NewFlagSet("netdoc-sim challenge", flag.ContinueOnError)}
	f.fs.SetOutput(out)
	f.id = f.fs.String("id", "", "replay a specific challenge")
	f.difficulty = f.fs.String("difficulty", "", "draw an easy, medium or hard challenge")
	f.daily = &dailyFlag{}
	f.fs.Var(f.daily, "daily", "play today's challenge, or -daily=YYYY-MM-DD for another day (UTC)")
	f.starter = f.fs.String("starter", "", "draw from a curated starter pack; 'netdoc-sim starters' lists them")
	f.authored = f.fs.String("authored", "", "play a hand-written challenge by slug; 'netdoc-sim authored' lists them")
	f.answer = f.fs.String("answer", "", "submit this diagnosis without opening a shell")
	f.giveUp = f.fs.Bool("give-up", false, "skip straight to the answer")
	f.json = f.fs.Bool("json", false, "print the machine-readable result")
	f.netdoc = f.fs.String("netdoc", "", "path to the netdoc binary")
	f.dailyDate = f.fs.String("daily-date", "", "internal: the UTC date this challenge was drawn as the daily for")
	f.netdocVersion = f.fs.String("netdoc-version", "", "internal: what the resolved netdoc binary reports for -version")
	f.timeout = f.fs.Duration("timeout", 4*time.Second, "netdoc per-probe timeout")
	f.verbose = f.fs.Bool("v", false, "log each privileged command as it runs")
	return f
}

func (f *challengeFlags) parse(args []string) error {
	id, err := parseRef(f.fs, args)
	if err != nil {
		return err
	}
	// `challenge 8F42C1` is what people type, so accept it as well as -id.
	if id != "" {
		if *f.id != "" && *f.id != id {
			return errors.New("a challenge id was given twice")
		}
		*f.id = id
	}
	if *f.id != "" && *f.difficulty != "" {
		return errors.New("-id names one challenge, so -difficulty has nothing to choose")
	}
	// A daily is the same challenge for everybody who asks for that date. Every
	// other way of choosing one contradicts that outright, so each combination is
	// refused by name rather than resolved by some invented precedence, since silently
	// honouring one of the two would hand somebody a result they would post as
	// the day's challenge when it was not.
	if f.daily.set {
		// Resolved first: `-daily=false` clears the flag, so the conflict checks
		// below have to look at what it resolved to rather than at it having
		// appeared on the command line.
		if err := f.daily.resolve(); err != nil {
			return err
		}
	}
	if f.daily.set {
		switch {
		case *f.id != "":
			return errors.New("-daily and a challenge id each pick a different challenge; " +
				"play the daily, or replay the id on its own")
		case *f.difficulty != "":
			return errors.New("-daily is the same challenge for everyone that day, so it has no difficulty to choose")
		case *f.starter != "":
			return errors.New("-daily and -starter each pick a different challenge; pick one")
		}
	}
	if *f.starter != "" {
		if *f.id != "" {
			return errors.New("-id names one challenge, so -starter has nothing to draw")
		}
		if *f.difficulty != "" {
			return errors.New("a starter pack sets its own difficulties, so -difficulty has nothing to choose")
		}
		if _, ok := simulation.StarterPackByID(*f.starter); !ok {
			return fmt.Errorf("unknown starter pack %q (have: %s)", textsafe.Clean(*f.starter),
				strings.Join(simulation.StarterPackNames(), ", "))
		}
	}
	if *f.authored != "" {
		// An authored challenge is one named case, so everything that would pick a
		// different one is refused by name rather than resolved by precedence.
		switch {
		case *f.id != "":
			return errors.New("-id names one challenge, so -authored has nothing to choose")
		case *f.difficulty != "":
			return errors.New("an authored challenge carries its own difficulty, so -difficulty has nothing to choose")
		case *f.starter != "":
			return errors.New("-authored and -starter each pick a different challenge; pick one")
		case f.daily.set:
			return errors.New("-daily and -authored each pick a different challenge; pick one")
		}
		if _, ok := simulation.AuthoredChallengeBySlug(*f.authored); !ok {
			return fmt.Errorf("unknown authored challenge %q (have: %s)", textsafe.Clean(*f.authored),
				strings.Join(simulation.AuthoredChallengeSlugs(), ", "))
		}
	}
	if *f.answer != "" && *f.giveUp {
		return errors.New("-answer and -give-up are two different submissions")
	}
	if *f.answer != "" {
		if _, ok := simulation.ChallengeAnswerByName(*f.answer); !ok {
			return fmt.Errorf("unknown answer %q (have: %s)", textsafe.Clean(*f.answer),
				strings.Join(simulation.ChallengeAnswerNames(), ", "))
		}
	}
	if *f.json && *f.answer == "" && !*f.giveUp {
		return errors.New("-json runs without a terminal, so it needs -answer or -give-up")
	}
	// Validated the way netdoc validates its own -timeout: this value is spelled
	// onto the child's command line, so a value netdoc refuses would otherwise
	// surface as every spawned run exiting 2.
	if err := diagnostic.ValidateProbeTimeout(*f.timeout); err != nil {
		return err
	}
	return nil
}

// launchChallenge resolves the challenge where a mistake is cheap, then hands
// the work to a director inside fresh namespaces. Resolution happens exactly
// once, out here: the director is told an id, so the case the player is briefed
// on and the case netdoc is graded on cannot come apart.
func launchChallenge(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	f := newChallengeFlags(stderr)
	if err := f.parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return exitOK
		}
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	challenge, err := resolveChallenge(f)
	if err != nil {
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
	// Resolved once, before any namespace exists: the executable recorded in the
	// result has to be the executable the run launches, and a binary that cannot
	// even print its version is worth rejecting while the error is still cheap.
	netdoc, err := resolveNetdoc(ctx, *f.netdoc, self)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	code, err := launchDirector(ctx, self, challengeDirectorArgv(f, challenge, netdoc), stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitError
	}
	return code
}

// nowUTC is the clock the daily reads, and the only clock any of this reads.
// Kept as a variable so tests can pin a date instead of asking what day it is
// where the test happens to be running.
var nowUTC = func() time.Time { return time.Now().UTC() }

// dailyFlag is `-daily` with an optional value: bare for today, `-daily=DATE`
// for another day. IsBoolFlag is what makes the bare form legal; without it,
// `-daily` would swallow the next argument, and `netdoc-sim challenge -daily`
// with nothing after it would be a usage error rather than the shortest way to
// play. It also means `-daily V4-8F42C1` leaves the id as a positional argument,
// which the parser then refuses as two challenges at once.
type dailyFlag struct {
	set  bool
	raw  string
	date string
}

func (d *dailyFlag) String() string { return d.date }

func (d *dailyFlag) IsBoolFlag() bool { return true }

// Set only records what was typed. A bool flag's Set error is reported by the
// flag package as `invalid boolean value`, which is the wrong sentence to show
// somebody who mistyped a date, so the date is resolved in resolve() where the
// error can say what it means.
func (d *dailyFlag) Set(raw string) error {
	d.set, d.raw = true, raw
	return nil
}

// resolve turns what was typed into the UTC date this daily is for. The bare
// form arrives as flag's own "true" and means today; "false" is `-daily=false`
// and means the flag was not asked for.
func (d *dailyFlag) resolve() error {
	switch d.raw {
	case "false":
		d.set, d.date = false, ""
		return nil
	case "true":
		d.date = simulation.DailyDate(nowUTC())
		return nil
	}
	date, err := simulation.ParseDailyDate(d.raw)
	if err != nil {
		return err
	}
	d.date = date
	return nil
}

func resolveChallenge(f *challengeFlags) (*simulation.Challenge, error) {
	switch {
	case *f.id != "":
		return simulation.BuildChallenge(*f.id)
	case f.daily.set:
		return simulation.DailyChallenge(f.daily.date)
	case *f.starter != "":
		return simulation.StarterChallenge(*f.starter)
	case *f.authored != "":
		return simulation.AuthoredChallengeByID(*f.authored)
	}
	return simulation.FindChallenge(*f.difficulty)
}

// challengeDirectorArgv hands the director the resolved id rather than the way
// it was chosen. -daily and -starter exist out here, where the clock and the
// draw are; by the time the director runs there is one challenge and one id, so
// nothing inside the namespaces can pick a different one.
func challengeDirectorArgv(f *challengeFlags, challenge *simulation.Challenge, netdoc netdocIdentity) []string {
	return []string{challengeDirectorCommand,
		"-netdoc", netdoc.path,
		"-netdoc-version", netdoc.version,
		"-timeout", f.timeout.String(),
		"-id", challenge.ID,
		"-daily-date", challenge.Daily,
		"-answer", *f.answer,
		fmt.Sprintf("-give-up=%t", *f.giveUp),
		fmt.Sprintf("-json=%t", *f.json),
		fmt.Sprintf("-v=%t", *f.verbose),
	}
}

// directChallenge is the challenge, from inside the namespaces the launcher
// created. It owns the whole session: the briefing, the shell, the submission,
// the netdoc run, and the reveal.
func directChallenge(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	f := newChallengeFlags(stderr)
	if err := f.parse(args); err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
		return exitUsage
	}
	if *f.id == "" {
		fmt.Fprintln(stderr, "netdoc-sim: internal challenge director did not receive an id")
		return exitError
	}
	if *f.netdoc == "" || *f.netdocVersion == "" {
		fmt.Fprintln(stderr, "netdoc-sim: internal challenge director did not receive a resolved netdoc")
		return exitError
	}
	challenge, err := simulation.BuildChallenge(*f.id)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitUsage
	}
	// A label on how the player arrived, applied after the challenge is built:
	// the id decided the puzzle, and this decides nothing.
	if *f.dailyDate != "" {
		date, err := simulation.ParseDailyDate(*f.dailyDate)
		if err != nil {
			fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
			return exitUsage
		}
		challenge.Daily = date
	}
	var log io.Writer
	if *f.verbose {
		log = stderr
	}
	// With -json the result is the only thing on stdout, so everything the
	// session says goes to stderr and stays pipeable.
	console := stdout
	if *f.json {
		console = stderr
	}
	play := &challengePlay{challenge: challenge, stdin: stdin, in: bufio.NewReader(stdin), out: console,
		answer: *f.answer, giveUp: *f.giveUp}
	result, err := simulation.RunChallenge(ctx, challenge, newBackend(false, log), simulation.ChallengeOptions{
		Run:           simulation.Options{Netdoc: *f.netdoc, ProbeTimeout: *f.timeout, Log: log},
		NetdocVersion: *f.netdocVersion,
		Play:          play.run,
	})
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", textsafe.Clean(err.Error()))
		return exitError
	}
	code, err := reportChallenge(result, *f.json, stdout, console)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc-sim:", err)
	}
	return code
}

// reportChallenge is everything that happens once the matchup is decided: the
// result, the clipboard, and the exit status. Keeping the three in one function
// is what makes the order structural rather than remembered: there is no point
// in it where a share block could be copied before the result it summarises
// exists, and no path where the clipboard is consulted about an exit status.
//
// console is where the session has been talking: stdout normally, stderr under
// -json, where stdout is the machine's.
func reportChallenge(result *simulation.ChallengeResult, asJSON bool, stdout, console io.Writer) (int, error) {
	if asJSON {
		if err := result.WriteJSON(stdout); err != nil {
			return exitError, err
		}
	} else {
		result.WriteText(stdout)
	}
	// The daily is the one worth posting: everybody who played that day played
	// this puzzle, so a reader can compare. Copying it is best effort and
	// deliberately incapable of changing anything below it. A terminal without
	// OSC 52 is not a failed challenge, it is a challenge somebody copies by
	// hand from the block that was printed anyway. A run that could not be
	// scored is not offered at all: there is nothing to compare.
	if result.Daily != "" && result.Result != simulation.ChallengeNoResult {
		if clipboardCopy(console, result.Share()) {
			// "sent", not "copied": OSC 52 is unacknowledged, so all this
			// process ever knows is that the request went out.
			fmt.Fprintln(console, "\nShare result sent to clipboard via OSC 52.")
		}
	}
	switch {
	case result.Result == simulation.ChallengeNoResult:
		return exitError, nil
	case result.Human.Score == simulation.ChallengeCorrect:
		return exitOK, nil
	default:
		return exitMismatch, nil
	}
}

// challengePlay is the interaction: it briefs the player, lends them a shell in
// the challenge node, and takes their answer. It is handed the live network and
// deliberately reads nothing out of it: everything it prints comes from the
// challenge briefing, which is the same information netdoc's run receives.
type challengePlay struct {
	challenge *simulation.Challenge
	// stdin goes to the shell as it is, so the child inherits the terminal
	// itself: a wrapped reader would cost it job control and line editing, and
	// would leave a copier goroutine racing the prompts for the player's keys.
	// in is for the prompts, which read one line at a time from the same fd.
	stdin  io.Reader
	in     *bufio.Reader
	out    io.Writer
	answer string
	giveUp bool
	// now is the monotonic clock the solve time is measured on, injectable so a
	// test can prove where the timer starts and stops without sleeping through
	// it. time.Now carries a monotonic reading and time.Since uses it, so the
	// measurement is unaffected by the wall clock being adjusted mid-session.
	now func() time.Time
}

func (p *challengePlay) clock() time.Time {
	if p.now == nil {
		return time.Now()
	}
	return p.now()
}

func (p *challengePlay) run(ctx context.Context, session *simulation.ChallengeSession) (simulation.ChallengeSubmission, error) {
	if p.giveUp {
		return simulation.ChallengeSubmission{GaveUp: true}, nil
	}
	if p.answer != "" {
		info, _ := simulation.ChallengeAnswerByName(p.answer)
		return simulation.ChallengeSubmission{Answer: info.ID}, nil
	}
	// The timer starts here and not a line earlier. Everything before this, the
	// namespaces, the services and the faults, happened without the player, and
	// charging them for it would make the number depend on how fast the host
	// builds a network rather than on how fast they read one.
	started := p.clock()
	p.challenge.WriteBriefing(p.out)
	if !session.ShellAvailable() {
		fmt.Fprintln(p.out, "\nThis backend cannot open a shell, so answer from what you already know.")
	}
	for {
		if session.ShellAvailable() {
			fmt.Fprintln(p.out, "\nOpening a shell in the challenge node. Type `exit` when you are ready to answer.")
			if err := session.Shell(ctx, p.stdin, p.out, p.out); err != nil {
				return simulation.ChallengeSubmission{}, err
			}
		}
		submission, again := p.ask()
		if again {
			continue
		}
		// Stopped where the answer is accepted, so rereading the briefing, going
		// back into the shell and thinking at the menu are all part of the solve,
		// which they are. What is excluded is the netdoc run that follows.
		submission.Elapsed = p.clock().Sub(started)
		fmt.Fprintln(p.out, "\nAnswer locked in. Network Doctor is taking its turn on the same network…")
		return submission, nil
	}
}

// ask runs the menu once. It returns again=true when the player wants back into
// the shell, which is the only way out of here that is not a submission.
func (p *challengePlay) ask() (simulation.ChallengeSubmission, bool) {
	for {
		simulation.WriteAnswerMenu(p.out)
		fmt.Fprint(p.out, "\n> ")
		line, err := p.in.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(line))
		if err != nil && choice == "" {
			// No terminal left to ask with. Ending the challenge as a give-up is
			// the honest reading: nobody committed to a diagnosis.
			fmt.Fprintln(p.out, "\n(no answer given)")
			return simulation.ChallengeSubmission{GaveUp: true}, false
		}
		switch choice {
		case "s":
			return simulation.ChallengeSubmission{}, true
		case "b", "brief", "briefing":
			// The same renderer the session opened with, so what is recalled is what
			// was originally said, and it is still only what netdoc's run is given.
			p.challenge.WriteBriefing(p.out)
			continue
		case "q", "quit", "":
			return simulation.ChallengeSubmission{GaveUp: true}, false
		}
		picked, ok := pickAnswer(choice)
		if !ok {
			fmt.Fprintf(p.out, "\nPick a number between 1 and %d or type the diagnosis by name;"+
				" `b` for the briefing, `s` for the shell, `q` to give up.\n",
				len(simulation.ChallengeAnswerMenu))
			continue
		}
		fmt.Fprintf(p.out, "\nYou answered: %s\nWhy? (optional, one line)\n> ", picked.Label)
		note, _ := p.in.ReadString('\n')
		return simulation.ChallengeSubmission{Answer: picked.ID, Note: clipNote(note)}, false
	}
}

// pickAnswer resolves what the player typed at the menu: the number next to an
// entry, or the diagnosis by name. Both are exact, since the number has to be in
// range and the name has to match an id, an alias or a label whole, so a
// mistyped answer is asked again rather than resolved to whatever it resembled.
func pickAnswer(choice string) (simulation.ChallengeAnswerInfo, bool) {
	if number, err := strconv.Atoi(choice); err == nil {
		if number < 1 || number > len(simulation.ChallengeAnswerMenu) {
			return simulation.ChallengeAnswerInfo{}, false
		}
		return simulation.ChallengeAnswerMenu[number-1], true
	}
	return simulation.ChallengeAnswerByName(choice)
}

func clipNote(raw string) string {
	note := textsafe.Clean(strings.TrimSpace(raw))
	if len(note) > challengeNoteLimit {
		return note[:challengeNoteLimit]
	}
	return note
}
