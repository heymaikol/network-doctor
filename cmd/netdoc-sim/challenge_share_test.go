package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

type clipboardCall struct {
	text string
	// printed is everything the session had already written when the copy was
	// attempted, which is how a test sees that the block was on screen before it
	// was on the clipboard.
	printed string
}

type fakeClipboard struct {
	ok     bool
	copies []clipboardCall
}

// stubClipboard replaces the terminal with a recorder, so a test run never
// reaches the clipboard of whoever is running it.
func stubClipboard(t *testing.T, ok bool) *fakeClipboard {
	t.Helper()
	f := &fakeClipboard{ok: ok}
	old := clipboardCopy
	clipboardCopy = func(w io.Writer, text string) bool {
		call := clipboardCall{text: text}
		if buffer, isBuffer := w.(*bytes.Buffer); isBuffer {
			call.printed = buffer.String()
		}
		f.copies = append(f.copies, call)
		return f.ok
	}
	t.Cleanup(func() { clipboardCopy = old })
	return f
}

// dailyResult is a finished daily the player won, which is the case the
// clipboard exists for.
func dailyResult(mutate func(*simulation.ChallengeResult)) *simulation.ChallengeResult {
	r := &simulation.ChallengeResult{
		ChallengeID: "V4-8F42C1", Difficulty: "easy", Daily: "2026-03-04",
		Truth: simulation.ChallengeTruth{Scoreable: true, Label: "TCP port blocked",
			Explanation: "the port is filtered", Injected: "service.tcp_port_blocked"},
		Human:         simulation.ChallengeContestant{Score: simulation.ChallengeCorrect, Label: "TCP port blocked"},
		NetworkDoctor: simulation.ChallengeContestant{Score: simulation.ChallengeIncorrect, Label: "healthy"},
		Result:        simulation.ChallengeHumanWins,
		Timing:        simulation.ChallengeTiming{HumanMS: 200_000, NetdocMS: 4_000},
		Replay:        "netdoc-sim challenge -id V4-8F42C1",
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

// The daily is the result people post, so playing one hands them the block
// rather than asking them to select it out of a terminal. What is copied is the
// block that was printed, byte for byte: two share texts that could differ are
// two share texts that eventually will.
func TestDailyCopiesTheShareBlockItPrinted(t *testing.T) {
	clipboard := stubClipboard(t, true)
	result := dailyResult(nil)
	var stdout bytes.Buffer

	code, err := reportChallenge(result, false, &stdout, &stdout)
	if err != nil {
		t.Fatalf("reportChallenge: %v", err)
	}
	if code != exitOK {
		t.Errorf("code = %d, want %d for a correct answer", code, exitOK)
	}
	if len(clipboard.copies) != 1 {
		t.Fatalf("the daily made %d copy attempts, want exactly one", len(clipboard.copies))
	}
	copied := clipboard.copies[0]
	if copied.text != result.Share() {
		t.Errorf("copied text is not the share block:\n got:\n%s\nwant:\n%s", copied.text, result.Share())
	}
	// The reveal, and the block inside it, were already on screen: nothing is
	// copied before the result it summarises exists.
	if !strings.Contains(copied.printed, "RESULT: CHALLENGE V4-8F42C1") ||
		!strings.Contains(copied.printed, "🏆 I beat Network Doctor") {
		t.Errorf("the copy happened before the result was printed:\n%s", copied.printed)
	}
	if !strings.Contains(stdout.String(), "Share result sent to clipboard") {
		t.Errorf("a successful copy said nothing about it:\n%s", stdout.String())
	}
}

// Everything the reveal knows and the share block must not: the copy is the
// same string, so this is a second lock on the same door, at the point where
// the text leaves the process.
func TestDailyCopiesNoSpoiler(t *testing.T) {
	clipboard := stubClipboard(t, true)
	result := dailyResult(func(r *simulation.ChallengeResult) {
		r.BaseScenario, r.Seed, r.Case = "blocked-port", 4242, 7
		r.Human.Note = "the port is filtered"
	})
	var stdout bytes.Buffer
	if _, err := reportChallenge(result, false, &stdout, &stdout); err != nil {
		t.Fatal(err)
	}
	copied := clipboard.copies[0].text
	for _, secret := range []string{result.Truth.Label, result.Truth.Explanation, result.Truth.Injected,
		result.BaseScenario, result.Human.Label, result.Human.Note, "4242"} {
		if secret != "" && strings.Contains(strings.ToLower(copied), strings.ToLower(secret)) {
			t.Errorf("the clipboard payload leaks %q:\n%s", secret, copied)
		}
	}
	// Presentation-only bytes are for the terminal that printed them, never for
	// whatever the player pastes into next.
	if strings.ContainsRune(copied, '\x1b') {
		t.Errorf("the clipboard payload carries an escape sequence:\n%q", copied)
	}
}

// An ordinary challenge is not the day's puzzle, so a result nobody is
// comparing does not quietly take over the clipboard the player was using.
func TestOrdinaryChallengeCopiesNothing(t *testing.T) {
	clipboard := stubClipboard(t, true)
	var stdout bytes.Buffer
	code, err := reportChallenge(dailyResult(func(r *simulation.ChallengeResult) { r.Daily = "" }),
		false, &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if code != exitOK {
		t.Errorf("code = %d, want %d", code, exitOK)
	}
	if len(clipboard.copies) != 0 {
		t.Errorf("a challenge that was not the daily copied %+v", clipboard.copies)
	}
	if strings.Contains(stdout.String(), "clipboard") {
		t.Errorf("a challenge that was not the daily mentioned the clipboard:\n%s", stdout.String())
	}
}

// A daily nobody could score has nothing to compare, so there is nothing to
// hand anybody.
func TestUnscoreableDailyCopiesNothing(t *testing.T) {
	clipboard := stubClipboard(t, true)
	var stdout bytes.Buffer
	code, err := reportChallenge(dailyResult(func(r *simulation.ChallengeResult) {
		r.Truth = simulation.ChallengeTruth{Reason: "the simulator could not establish a truth"}
		r.Human.Score, r.NetworkDoctor.Score = "", ""
		r.Result = simulation.ChallengeNoResult
	}), false, &stdout, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if code != exitError {
		t.Errorf("code = %d, want %d for a challenge that could not be scored", code, exitError)
	}
	if len(clipboard.copies) != 0 {
		t.Errorf("an unscoreable daily copied %+v", clipboard.copies)
	}
}

// A terminal with no OSC 52, a container, a pipe: the clipboard is the one part
// of a challenge that is allowed to be unavailable. It may not turn a played
// challenge into an error, change its exit status, or print anything alarming.
// The block is on screen either way, which is all manual copying needs.
func TestClipboardFailureChangesNothingAboutTheChallenge(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*simulation.ChallengeResult)
		code   int
	}{
		{"the player was right", nil, exitOK},
		{"the player was wrong", func(r *simulation.ChallengeResult) {
			r.Human.Score, r.NetworkDoctor.Score = simulation.ChallengeIncorrect, simulation.ChallengeCorrect
			r.Result = simulation.ChallengeNetdocWins
		}, exitMismatch},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var withClipboard, withNone bytes.Buffer

			working := stubClipboard(t, true)
			wantCode, err := reportChallenge(dailyResult(tt.mutate), false, &withClipboard, &withClipboard)
			if err != nil {
				t.Fatal(err)
			}

			broken := stubClipboard(t, false)
			code, err := reportChallenge(dailyResult(tt.mutate), false, &withNone, &withNone)
			if err != nil {
				t.Fatalf("an unavailable clipboard became an error: %v", err)
			}
			if code != tt.code || code != wantCode {
				t.Errorf("code = %d with no clipboard and %d with one, want %d", code, wantCode, tt.code)
			}
			if len(working.copies) != 1 || len(broken.copies) != 1 {
				t.Errorf("copy attempts: %d with a clipboard, %d without", len(working.copies), len(broken.copies))
			}
			if strings.Contains(withNone.String(), "clipboard") {
				t.Errorf("an unavailable clipboard was reported to the player:\n%s", withNone.String())
			}
			// The printed result is the same either way: the notice is the only
			// thing a working clipboard adds, and the block is there regardless,
			// which is what keeps copying it by hand possible.
			if want := withNone.String() + "\nShare result sent to clipboard via OSC 52.\n"; withClipboard.String() != want {
				t.Errorf("the clipboard changed the printed result:\nwith:\n%s\nwithout:\n%s",
					withClipboard.String(), withNone.String())
			}
		})
	}
}

// Under -json stdout belongs to the machine, so the escape and the notice go
// where the rest of the session already went.
func TestDailyJSONKeepsTheClipboardOffStdout(t *testing.T) {
	clipboard := stubClipboard(t, true)
	var stdout, console bytes.Buffer
	if _, err := reportChallenge(dailyResult(nil), true, &stdout, &console); err != nil {
		t.Fatal(err)
	}
	if len(clipboard.copies) != 1 || clipboard.copies[0].printed != "" {
		t.Errorf("the copy did not go to the console writer: %+v", clipboard.copies)
	}
	if strings.Contains(stdout.String(), "clipboard") {
		t.Errorf("-json put a clipboard notice on stdout:\n%s", stdout.String())
	}
	if !strings.Contains(console.String(), "Share result sent to clipboard") {
		t.Errorf("-json said nothing about the clipboard on the console:\n%s", console.String())
	}
}

// Nothing that is not a terminal gets an escape sequence written to it: a
// redirected result, a piped one and a CI log are all somebody's artifact.
func TestClipboardWritesNothingToWhatIsNotATerminal(t *testing.T) {
	var buffer bytes.Buffer
	if copyToTerminalClipboard(&buffer, "share") || buffer.Len() != 0 {
		t.Errorf("a plain writer was treated as a terminal: %q", buffer.String())
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if copyToTerminalClipboard(write, "share") {
		t.Error("a pipe was treated as a terminal")
	}
	file, err := os.CreateTemp(t.TempDir(), "share")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if copyToTerminalClipboard(file, "share") {
		t.Error("a regular file was treated as a terminal")
	}
	if info, err := file.Stat(); err != nil || info.Size() != 0 {
		t.Errorf("a regular file was written to: %v, %v", info, err)
	}
}

func TestOSC52ClipboardRequest(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("share"))
	t.Setenv("TMUX", "")
	if got, want := osc52Clipboard("share"), "\x1b]52;c;"+payload+"\a"; got != want {
		t.Errorf("osc52Clipboard() = %q, want %q", got, want)
	}
	// Inside tmux the request has to ride the passthrough envelope or tmux eats
	// it instead of forwarding it to the terminal that can honour it.
	t.Setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
	if got, want := osc52Clipboard("share"), "\x1bPtmux;\x1b\x1b]52;c;"+payload+"\a\x1b\\"; got != want {
		t.Errorf("osc52Clipboard() inside tmux = %q, want %q", got, want)
	}
}
