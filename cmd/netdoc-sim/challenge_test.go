package main

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

func receivedChallenge(t *testing.T, argv []string) *challengeFlags {
	t.Helper()
	if argv[0] != challengeDirectorCommand {
		t.Fatalf("argv[0] = %q, want %q", argv[0], challengeDirectorCommand)
	}
	f := newChallengeFlags(io.Discard)
	if err := f.parse(argv[1:]); err != nil {
		t.Fatalf("the challenge director could not parse %v: %v", argv, err)
	}
	return f
}

// The challenge is resolved once, in the launcher, and the director is handed
// the id rather than the job of drawing one. That is what keeps the case the
// player is briefed on and the case netdoc is graded on the same case.
func TestChallengeLaunchResolvesTheIDTheDirectorRunsWith(t *testing.T) {
	abs := fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})
	var stdout, stderr bytes.Buffer
	args := []string{"challenge", "-netdoc", "./netdoc", "-difficulty", "hard", "-timeout", "9s"}
	for range 2 {
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	}
	if len(directors.calls) != 2 {
		t.Fatalf("directors = %+v, want two", directors.calls)
	}
	ids := make([]string, 2)
	for i, call := range directors.calls {
		f := receivedChallenge(t, call.argv)
		if *f.netdoc != abs || *f.timeout != 9*time.Second {
			t.Errorf("challenge got netdoc %q timeout %s", *f.netdoc, *f.timeout)
		}
		challenge, err := simulation.BuildChallenge(*f.id)
		if err != nil {
			t.Fatalf("the director was handed an id it cannot build: %v", err)
		}
		if challenge.Difficulty != "hard" {
			t.Errorf("asked for a hard challenge, director got a %s one", challenge.Difficulty)
		}
		ids[i] = *f.id
	}
	if ids[0] == ids[1] {
		t.Errorf("both challenges were %s; ids are not being drawn", ids[0])
	}
	for _, offered := range directors.stdin {
		if !offered {
			t.Error("a challenge director was not given a terminal to ask with")
		}
	}
}

// The reproducibility invariant, at the seam where it can break: an explicitly
// requested binary must be the one that is interrogated and the one the director
// is told to run, even when automatic discovery had a perfectly good candidate
// of its own. Both fakes report a different version, so a result carrying the
// wrong one is unmistakable.
func TestChallengeExplicitNetdocBeatsDiscoveryAndIsWhatRuns(t *testing.T) {
	discoverable := writeFakeNetdoc(t, t.TempDir(), "netdoc v1.0.0-discoverable")
	chosen := writeFakeNetdoc(t, t.TempDir(), "netdoc v2.0.0-chosen")
	t.Setenv("PATH", filepath.Dir(discoverable))
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"challenge", "-netdoc", chosen, "-give-up"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if len(directors.calls) != 1 {
		t.Fatalf("directors = %+v, want one", directors.calls)
	}
	f := receivedChallenge(t, directors.calls[0].argv)
	if *f.netdoc != chosen {
		t.Errorf("director runs %q, want the binary that was asked for, %q", *f.netdoc, chosen)
	}
	if *f.netdocVersion != "netdoc v2.0.0-chosen" {
		t.Errorf("director carries version %q, want the chosen binary's", *f.netdocVersion)
	}
	if runs := fakeNetdocInvocations(t, chosen); len(runs) != 1 || runs[0] != "-version" {
		t.Errorf("the chosen binary was invoked as %v, want exactly one -version", runs)
	}
	if runs := fakeNetdocInvocations(t, discoverable); runs != nil {
		t.Errorf("the discoverable binary ran %v, and it was never selected", runs)
	}
}

// The same invariant for the other half of the contract: with no -netdoc, the
// identity belongs to whatever discovery settled on.
func TestChallengeDiscoveredNetdocIsInterrogatedAndForwarded(t *testing.T) {
	discovered := writeFakeNetdoc(t, t.TempDir(), "netdoc v3.0.0-discovered")
	t.Setenv("PATH", filepath.Dir(discovered))
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"challenge", "-give-up"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	f := receivedChallenge(t, directors.calls[0].argv)
	if *f.netdoc != discovered || *f.netdocVersion != "netdoc v3.0.0-discovered" {
		t.Fatalf("director got %q at version %q, want %q", *f.netdoc, *f.netdocVersion, discovered)
	}
	if runs := fakeNetdocInvocations(t, discovered); len(runs) != 1 || runs[0] != "-version" {
		t.Errorf("the discovered binary was invoked as %v, want exactly one -version", runs)
	}
}

// A binary that cannot say what it is cannot be recorded, so the challenge does
// not start, and it does not go looking for a second opinion either.
func TestChallengeRefusesANetdocWithNoVersion(t *testing.T) {
	working := writeFakeNetdoc(t, t.TempDir(), "netdoc v1.0.0-working")
	silent := writeFakeNetdoc(t, t.TempDir(), "")
	t.Setenv("PATH", filepath.Dir(working))
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"challenge", "-netdoc", silent, "-give-up"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitUsage, stderr.String())
	}
	if len(directors.calls) != 0 {
		t.Fatalf("a challenge started anyway: %+v", directors.calls)
	}
	if !strings.Contains(stderr.String(), "printed no version") {
		t.Errorf("stderr = %q, want it to say the binary printed no version", stderr.String())
	}
	if runs := fakeNetdocInvocations(t, working); runs != nil {
		t.Errorf("fell back to another netdoc and ran it %v", runs)
	}
}

// Every other command is automation and reads nothing from the terminal.
func TestOnlyTheChallengeDirectorGetsATerminal(t *testing.T) {
	for _, args := range [][]string{
		{"run", "healthy", "-netdoc", "./netdoc"},
		{"campaign", "unstable-connectivity", "-netdoc", "./netdoc"},
		{"hunt", "-netdoc", "./netdoc", "-seed", "1"},
	} {
		t.Run(args[0], func(t *testing.T) {
			fakeNetdoc(t)
			stubBackends(t, true)
			directors := stubDirectors(t, &fakeDirectors{code: exitOK})
			var stdout, stderr bytes.Buffer
			run(args, &stdout, &stderr)
			for _, offered := range directors.stdin {
				if offered {
					t.Errorf("%s was given a terminal", args[0])
				}
			}
		})
	}
}

func TestChallengeReplayHandsTheDirectorTheSameID(t *testing.T) {
	fakeNetdoc(t)
	stubBackends(t, true)
	directors := stubDirectors(t, &fakeDirectors{code: exitOK})
	var stdout, stderr bytes.Buffer
	// Positional and flag forms, bare and version-prefixed, are one request.
	for _, args := range [][]string{
		{"challenge", "-id", "8f42c1", "-netdoc", "./netdoc"},
		{"challenge", "8F42C1", "-netdoc", "./netdoc"},
		{"challenge", "v1-8f42c1", "-netdoc", "./netdoc"},
	} {
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("%v: code = %d, stderr = %q", args, code, stderr.String())
		}
	}
	if len(directors.calls) != 3 {
		t.Fatalf("directors = %+v, want three", directors.calls)
	}
	for _, call := range directors.calls {
		if got := *receivedChallenge(t, call.argv).id; got != "V1-8F42C1" {
			t.Errorf("director got id %q, want the canonical V1-8F42C1", got)
		}
	}
}

func TestChallengeStopsBeforeTheDirector(t *testing.T) {
	runRejections(t, []dispatchCase{
		{name: "unknown id", supported: true, args: []string{"challenge", "-id", "nope", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "challenge id is 6 hex characters"},
		{name: "unresolvable id version", supported: true,
			args: []string{"challenge", "-id", "V9-8F42C1", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "not one this build can resolve"},
		{name: "unknown answer", supported: true, args: []string{"challenge", "-answer", "vibes", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "unknown answer"},
		{name: "two submissions", supported: true,
			args: []string{"challenge", "-answer", "dns_failure", "-give-up", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "two different submissions"},
		{name: "json without an answer", supported: true, args: []string{"challenge", "-json", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "needs -answer or -give-up"},
		{name: "id and difficulty", supported: true,
			args: []string{"challenge", "-id", "8F42C1", "-difficulty", "hard", "-netdoc", "./netdoc"},
			code: exitUsage, stderrHas: "has nothing to choose"},
		{name: "host cannot simulate", supported: false, args: []string{"challenge", "-netdoc", "./netdoc"},
			code: exitError, stderrHas: "stub backend: this host cannot simulate"},
		{name: "no netdoc anywhere", supported: true, args: []string{"challenge"}, code: exitUsage,
			stderrHas: "cannot find the netdoc binary"},
	})
}

// The director never resolves a binary of its own: it is handed one, already
// interrogated, and refuses to run a challenge whose result could not name what
// produced it.
func TestChallengeDirectorNeedsAResolvedNetdoc(t *testing.T) {
	runDirectorRejections(t, []dispatchCase{
		{name: "no netdoc", supported: true,
			args:      []string{challengeDirectorCommand, "-id", "V1-8F42C1", "-give-up"},
			code:      exitError,
			stderrHas: "did not receive a resolved netdoc"},
		{name: "no version", supported: true,
			args:      []string{challengeDirectorCommand, "-id", "V1-8F42C1", "-netdoc", "/opt/builds/netdoc", "-give-up"},
			code:      exitError,
			stderrHas: "did not receive a resolved netdoc"},
	})
}

// The usage text lists the answer vocabulary when a submission is rejected, so
// a scripted challenge does not have to guess at the names.
func TestChallengeRejectionListsTheAnswers(t *testing.T) {
	fakeNetdoc(t)
	stubBackends(t, true)
	stubDirectors(t, &fakeDirectors{})
	var stdout, stderr bytes.Buffer
	run([]string{"challenge", "-answer", "vibes", "-netdoc", "./netdoc"}, &stdout, &stderr)
	for _, name := range simulation.ChallengeAnswerNames() {
		if !strings.Contains(stderr.String(), name) {
			t.Fatalf("stderr does not offer %q: %s", name, stderr.String())
		}
	}
}

func TestUsageMentionsChallenge(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, want := range []string{"challenge [id] [flags]", "-difficulty", "-give-up"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("usage does not mention %q", want)
		}
	}
}
