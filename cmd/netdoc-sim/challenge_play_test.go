package main

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

// fakeClock hands out a fixed sequence of instants, one per reading, so a test
// can say how long the player took without waiting that long. A sleep-based
// timing test would be slow when it passed and flaky when it did not.
type fakeClock struct {
	at    time.Time
	steps []time.Duration
	reads int
}

func (c *fakeClock) now() time.Time {
	at := c.at
	if c.reads < len(c.steps) {
		c.at = c.at.Add(c.steps[c.reads])
	}
	c.reads++
	return at
}

// playChallenge runs the interaction against a scripted terminal and no live
// network. The session reports no shell, which is the branch that lets the menu
// be driven from a test at all, and everything else about the prompts, the timer and
// the briefing is the same code a real session runs.
func playChallenge(t *testing.T, id string, clock *fakeClock, typed ...string) (simulation.ChallengeSubmission, string) {
	t.Helper()
	challenge, err := simulation.BuildChallenge(id)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.NewReader(strings.Join(typed, "\n") + "\n")
	var out bytes.Buffer
	play := &challengePlay{challenge: challenge, stdin: script, in: bufio.NewReader(script), out: &out}
	if clock != nil {
		play.now = clock.now
	}
	submission, err := play.run(context.Background(), &simulation.ChallengeSession{Challenge: challenge})
	if err != nil {
		t.Fatalf("play %s: %v", id, err)
	}
	return submission, out.String()
}

// The briefing has to be recallable without restarting: a player who scrolled
// past it, or whose shell filled the screen, otherwise has to abandon the
// challenge to reread the target they were given.
func TestBriefingCanBeRecalledMidSession(t *testing.T) {
	challenge, err := simulation.BuildChallenge("V3-8F42C1")
	if err != nil {
		t.Fatal(err)
	}
	var opening bytes.Buffer
	challenge.WriteBriefing(&opening)

	submission, transcript := playChallenge(t, "V3-8F42C1", nil, "b", "2", "because dig said so")
	if submission.Answer != simulation.AnswerDNSFailure {
		t.Fatalf("the answer after a recall was %q", submission.Answer)
	}
	// Twice, byte for byte: the opening briefing and the recalled one come out of
	// one renderer, so there is no second format to drift.
	if got := strings.Count(transcript, opening.String()); got != 2 {
		t.Fatalf("the briefing appears %d times in the session, want 2 (opening and recall):\n%s",
			got, transcript)
	}
}

// Recall must not become a second, more generous briefing. It is the same
// renderer, so this is really a test that nobody has added a hidden-truth
// shortcut to the recall path, which is the tempting place to add one.
func TestBriefingRecallRevealsNoHiddenTruth(t *testing.T) {
	for _, id := range []string{"V3-8F42C1", "V3-011667", "V3-058EF2", "V3-022CCE", "V3-000000"} {
		_, transcript := playChallenge(t, id, nil, "b", "q")
		challenge, err := simulation.BuildChallenge(id)
		if err != nil {
			t.Fatal(err)
		}
		// Everything a result would print after the reveal, none of which may be in
		// a briefing, before it or after it.
		result := simulation.ScoreChallenge(challenge, nil, simulation.ChallengeSubmission{GaveUp: true})
		forbidden := []string{challenge.Base, result.CaseFingerprint, result.Truth.Explanation}
		for _, mutation := range challenge.Manifest.Mutations {
			forbidden = append(forbidden, mutation.ID, mutation.Description)
		}
		for _, answer := range simulation.ChallengeAnswerNames() {
			// The menu legitimately prints every label; what it may not print is the
			// one answer that is correct, and the truth's own id is how that would
			// arrive.
			if simulation.ChallengeAnswer(answer) == result.Truth.Answer && result.Truth.Answer != "" {
				forbidden = append(forbidden, answer)
			}
		}
		for _, secret := range forbidden {
			if secret == "" {
				continue
			}
			if strings.Contains(transcript, secret) {
				t.Errorf("challenge %s: the session leaks %q before the reveal:\n%s", id, secret, transcript)
			}
		}
	}
}

// The solve time is the player's, and only the player's. It starts when the
// briefing lands, since everything before that happened without them, and stops when
// the answer is accepted, before netdoc's own run.
func TestElapsedTimeCoversTheWholeInteractionAndNothingElse(t *testing.T) {
	// Readings: the start, then the stop. Ten minutes pass between them.
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0), steps: []time.Duration{10 * time.Minute}}
	submission, _ := playChallenge(t, "V3-8F42C1", clock, "2", "")
	if clock.reads != 2 {
		t.Fatalf("the session read the clock %d times; it should start and stop once each", clock.reads)
	}
	if submission.Elapsed != 10*time.Minute {
		t.Fatalf("elapsed = %s, want 10m", submission.Elapsed)
	}
}

// Rereading the briefing, retyping a mistaken answer and thinking at the prompt
// are all part of solving it, so none of them may stop the clock or restart it.
func TestElapsedTimeIncludesRecallsAndRetries(t *testing.T) {
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0), steps: []time.Duration{7 * time.Minute}}
	submission, transcript := playChallenge(t, "V3-8F42C1", clock,
		"b", "nonsense", "999", "b", "dns", "took a while")
	if submission.Answer != simulation.AnswerDNSFailure {
		t.Fatalf("answer = %q, want the DNS answer typed by name", submission.Answer)
	}
	if submission.Elapsed != 7*time.Minute {
		t.Fatalf("elapsed = %s, want the single 7m span across every prompt", submission.Elapsed)
	}
	if !strings.Contains(transcript, "Pick a number between 1 and") {
		t.Fatalf("a mistyped answer was not asked again:\n%s", transcript)
	}
}

// A player who gives up took as long as they took. The number is not a score, so
// there is nothing to withhold, and a zero there would read as an instant
// surrender.
func TestElapsedTimeIsRecordedForAGiveUp(t *testing.T) {
	clock := &fakeClock{at: time.Unix(1_700_000_000, 0), steps: []time.Duration{90 * time.Second}}
	submission, _ := playChallenge(t, "V3-8F42C1", clock, "q")
	if !submission.GaveUp {
		t.Fatal("q did not give up")
	}
	if submission.Elapsed != 90*time.Second {
		t.Fatalf("elapsed = %s, want 90s", submission.Elapsed)
	}
}

// A submission handed in on the command line had no human session at all, so it
// records no human time rather than the microseconds the process took to start.
func TestNoninteractiveSubmissionRecordsNoHumanTime(t *testing.T) {
	challenge, err := simulation.BuildChallenge("V3-8F42C1")
	if err != nil {
		t.Fatal(err)
	}
	for _, play := range []*challengePlay{
		{challenge: challenge, out: &bytes.Buffer{}, answer: "dns_failure"},
		{challenge: challenge, out: &bytes.Buffer{}, giveUp: true},
	} {
		submission, err := play.run(context.Background(), &simulation.ChallengeSession{Challenge: challenge})
		if err != nil {
			t.Fatal(err)
		}
		if submission.Elapsed != 0 {
			t.Fatalf("a non-interactive submission recorded %s of human time", submission.Elapsed)
		}
	}
}

// The menu takes a number or the diagnosis by name. Both are exact: an
// out-of-range number and a name that merely resembles one are both asked again.
func TestPickAnswerTakesNumbersAndNames(t *testing.T) {
	for _, tt := range []struct {
		typed string
		want  simulation.ChallengeAnswer
	}{
		{"1", simulation.AnswerHealthy},
		{"2", simulation.AnswerDNSFailure},
		{"dns", simulation.AnswerDNSFailure},
		{"tcp_port_blocked", simulation.AnswerPortBlocked},
		{"tcp port blocked", simulation.AnswerPortBlocked},
		{"connection refused", simulation.AnswerRefused},
	} {
		got, ok := pickAnswer(tt.typed)
		if !ok || got.ID != tt.want {
			t.Errorf("pickAnswer(%q) = %q, %t; want %s", tt.typed, got.ID, ok, tt.want)
		}
	}
	for _, typed := range []string{"0", "-1", "999", "1.5", "tcp", "connection", "nonsense"} {
		if got, ok := pickAnswer(typed); ok {
			t.Errorf("pickAnswer(%q) resolved to %s; it must ask again", typed, got.ID)
		}
	}
}
