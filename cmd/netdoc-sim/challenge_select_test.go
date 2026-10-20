package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

// pinClock fixes what "today" is, so the daily tests do not depend on the date
// the suite happens to run on or on the zone the machine happens to be in.
func pinClock(t *testing.T, at time.Time) {
	t.Helper()
	previous := nowUTC
	nowUTC = func() time.Time { return at }
	t.Cleanup(func() { nowUTC = previous })
}

func parseChallengeArgs(t *testing.T, args ...string) (*challengeFlags, error) {
	t.Helper()
	f := newChallengeFlags(io.Discard)
	return f, f.parse(args)
}

// Bare -daily is today in UTC, and -daily=DATE is that day. The bare form has to
// work without a value, which is the whole reason -daily is a flag that claims to
// be boolean.
func TestDailyFlagResolvesTodayOrAnExplicitDate(t *testing.T) {
	// Late enough in the UTC day that a machine set to a western zone would call
	// it yesterday, which is the mistake this is here to catch.
	pinClock(t, time.Date(2026, 8, 12, 23, 45, 0, 0, time.UTC))
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"-daily"}, "2026-08-12"},
		{[]string{"-daily=2026-01-01"}, "2026-01-01"},
		{[]string{"-daily=true"}, "2026-08-12"},
	} {
		f, err := parseChallengeArgs(t, tt.args...)
		if err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		if !f.daily.set || f.daily.date != tt.want {
			t.Fatalf("%v resolved to set=%t date=%q, want %q", tt.args, f.daily.set, f.daily.date, tt.want)
		}
		challenge, err := resolveChallenge(f)
		if err != nil {
			t.Fatalf("%v: %v", tt.args, err)
		}
		if challenge.Daily != tt.want {
			t.Fatalf("%v produced the daily for %q", tt.args, challenge.Daily)
		}
		if want, err := simulation.DailyChallenge(tt.want); err != nil || want.ID != challenge.ID {
			t.Fatalf("%v produced %s, not the date's own daily %s", tt.args, challenge.ID, want.ID)
		}
	}
	// -daily=false is how a boolean flag is switched off, and means the flag was
	// not asked for at all.
	f, err := parseChallengeArgs(t, "-daily=false")
	if err != nil {
		t.Fatal(err)
	}
	if f.daily.set {
		t.Fatal("-daily=false still selected a daily")
	}
}

// Everything else that picks a challenge contradicts a daily outright, so each
// combination is refused by name. Silently honouring one of the two would hand
// somebody a result they would post as the day's challenge when it was not.
func TestDailyRejectsEveryConflictingSelection(t *testing.T) {
	pinClock(t, time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC))
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"an explicit id flag", []string{"-daily", "-id", "V3-8F42C1"}, "each pick a different challenge"},
		{"an id as a positional", []string{"-daily", "V3-8F42C1"}, "each pick a different challenge"},
		{"a difficulty", []string{"-daily", "-difficulty", "hard"}, "no difficulty to choose"},
		{"a starter pack", []string{"-daily", "-starter", "routing"}, "each pick a different challenge"},
		{"a mistyped date", []string{"-daily=12-08-2026"}, "UTC calendar date"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseChallengeArgs(t, tt.args...)
			if err == nil {
				t.Fatalf("%v was accepted", tt.args)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("%v was refused with %q, want it to mention %q", tt.args, err, tt.want)
			}
		})
	}
}

// A starter pack is a way of drawing one, so it conflicts with the other ways of
// drawing one and is checked for existence before a network is built.
func TestStarterFlagIsValidatedAndDrawsFromThePack(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"an id", "has nothing to draw"},
		{"a difficulty", "has nothing to choose"},
	} {
		args := []string{"-starter", "routing", "-id", "V3-8F42C1"}
		if tt.name == "a difficulty" {
			args = []string{"-starter", "routing", "-difficulty", "hard"}
		}
		if _, err := parseChallengeArgs(t, args...); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%v with %s was refused with %v", args, tt.name, err)
		}
	}
	if _, err := parseChallengeArgs(t, "-starter", "no-such-pack"); err == nil ||
		!strings.Contains(err.Error(), "unknown starter pack") {
		t.Fatalf("an unknown pack was accepted or misreported: %v", err)
	}
	f, err := parseChallengeArgs(t, "-starter", "TLS")
	if err != nil {
		t.Fatalf("a pack named in capitals was refused: %v", err)
	}
	pack, ok := simulation.StarterPackByID("tls")
	if !ok {
		t.Fatal("no tls pack")
	}
	for range 20 {
		challenge, err := resolveChallenge(f)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, id := range pack.Challenges {
			found = found || id == challenge.ID
		}
		if !found {
			t.Fatalf("-starter tls drew %s, which is not in %v", challenge.ID, pack.Challenges)
		}
		if challenge.Daily != "" {
			t.Fatalf("a starter challenge claims to be the daily for %q", challenge.Daily)
		}
	}
}

// -answer takes the diagnosis by name now, not only by internal identifier. The
// point of the change is that nobody has to read the source to submit an answer
// from a script, so the accepted forms are pinned.
func TestAnswerFlagAcceptsNamesAndRejectsResemblance(t *testing.T) {
	for _, answer := range []string{"dns_failure", "dns", "DNS resolution", "tcp-port-blocked",
		"TCP port blocked", "refused", "ok"} {
		if _, err := parseChallengeArgs(t, "-answer", answer, "-json"); err != nil {
			t.Errorf("-answer %q was refused: %v", answer, err)
		}
	}
	for _, answer := range []string{"tcp", "dns failure!", "connection", "", "1"} {
		f := newChallengeFlags(io.Discard)
		err := f.parse([]string{"-answer", answer, "-json"})
		if answer == "" {
			// An empty -answer is not a submission, and -json says there is nobody to
			// ask, so the flags contradict each other rather than naming a bad answer.
			if err == nil || !strings.Contains(err.Error(), "needs -answer or -give-up") {
				t.Errorf("-answer \"\" -json was refused with %v", err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "unknown answer") {
			t.Errorf("-answer %q was accepted or misreported: %v", answer, err)
		}
	}
}

// The director is handed a resolved id plus the date it was the daily for, and
// resolves nothing itself. That is what keeps the challenge the player is briefed
// on and the one netdoc is graded on the same challenge, however it was chosen.
func TestDailyAndStarterReachTheDirectorAsAResolvedID(t *testing.T) {
	pinClock(t, time.Date(2026, 8, 12, 6, 0, 0, 0, time.UTC))
	fakeNetdoc(t)
	stubBackends(t, true)
	for _, tt := range []struct {
		name      string
		args      []string
		wantDaily string
		inPack    string
	}{
		{"daily", []string{"challenge", "-daily", "-netdoc", "./netdoc"}, "2026-08-12", ""},
		{"a past daily", []string{"challenge", "-daily=2026-03-04", "-netdoc", "./netdoc"}, "2026-03-04", ""},
		{"a starter", []string{"challenge", "-starter", "paths", "-netdoc", "./netdoc"}, "", "paths"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			directors := stubDirectors(t, &fakeDirectors{code: exitOK})
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != exitOK {
				t.Fatalf("code = %d, stderr = %q", code, stderr.String())
			}
			if len(directors.calls) != 1 {
				t.Fatalf("directors = %+v, want one", directors.calls)
			}
			f := receivedChallenge(t, directors.calls[0].argv)
			if *f.id == "" {
				t.Fatal("the director was not handed a resolved id")
			}
			if *f.dailyDate != tt.wantDaily {
				t.Fatalf("the director was told the daily date %q, want %q", *f.dailyDate, tt.wantDaily)
			}
			// The director must not be handed the way the challenge was chosen: it
			// resolves the id, and nothing inside the namespaces can pick another.
			for _, arg := range directors.calls[0].argv {
				if arg == "-daily" || arg == "-starter" {
					t.Fatalf("the director was handed %q as well as an id: %v", arg, directors.calls[0].argv)
				}
			}
			if tt.wantDaily != "" {
				want, err := simulation.DailyChallenge(tt.wantDaily)
				if err != nil {
					t.Fatal(err)
				}
				if *f.id != want.ID {
					t.Fatalf("the director got %s, not the %s daily %s", *f.id, tt.wantDaily, want.ID)
				}
			}
			if tt.inPack != "" {
				pack, _ := simulation.StarterPackByID(tt.inPack)
				found := false
				for _, id := range pack.Challenges {
					found = found || id == *f.id
				}
				if !found {
					t.Fatalf("the director got %s, which is not in pack %s", *f.id, tt.inPack)
				}
			}
		})
	}
}

// Discovery has to work without reading the source or the README, and it prints
// the ids so a pack can be worked through in order rather than only drawn from.
func TestStartersCommandListsPacksAndTheirChallenges(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"starters"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	listing := stdout.String()
	for _, pack := range simulation.StarterPacks() {
		if !strings.Contains(listing, pack.ID) || !strings.Contains(listing, pack.Name) ||
			!strings.Contains(listing, pack.Description) {
			t.Errorf("the listing does not offer pack %s:\n%s", pack.ID, listing)
		}
	}
	if !strings.Contains(listing, "-starter <pack>") {
		t.Errorf("the listing does not say how to play one:\n%s", listing)
	}

	stdout.Reset()
	if code := run([]string{"starters", "routing"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	pack, _ := simulation.StarterPackByID("routing")
	for _, id := range pack.Challenges {
		if !strings.Contains(stdout.String(), id) {
			t.Errorf("the routing pack listing omits %s:\n%s", id, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"starters", "no-such-pack"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("an unknown pack exited %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "unknown starter pack") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// The four ways to play have to be findable in the help, or the features exist
// only for whoever read the commit.
func TestUsageShowsTheWaysToPlay(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	text := out.String()
	for _, want := range []string{"-daily", "-starter", "starters", "challenge " + simulation.ChallengeIDVersion + "-8F42C1",
		"Ways to play", "rereads the briefing"} {
		if !strings.Contains(text, want) {
			t.Errorf("usage does not mention %q", want)
		}
	}
}

// -authored is a third way of choosing one, so it is refused alongside every
// other way and checked before a network is built. Resolving it has to reach
// the case the slug names, by the same id anybody else would replay.
func TestAuthoredFlagIsValidatedAndResolvesTheNamedCase(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"an id", []string{"-authored", "reset-after-accept", "-id", "V4-8F42C1"}, "has nothing to choose"},
		{"a difficulty", []string{"-authored", "reset-after-accept", "-difficulty", "hard"}, "has nothing to choose"},
		{"a starter pack", []string{"-authored", "reset-after-accept", "-starter", "routing"}, "each pick a different challenge"},
		{"the daily", []string{"-authored", "reset-after-accept", "-daily"}, "each pick a different challenge"},
	} {
		if _, err := parseChallengeArgs(t, tt.args...); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%v with %s was refused with %v", tt.args, tt.name, err)
		}
	}
	if _, err := parseChallengeArgs(t, "-authored", "no-such-case"); err == nil ||
		!strings.Contains(err.Error(), "unknown authored challenge") {
		t.Fatalf("an unknown authored slug was accepted or misreported: %v", err)
	}
	f, err := parseChallengeArgs(t, "-authored", "Certificate-Expired")
	if err != nil {
		t.Fatalf("a slug named in capitals was refused: %v", err)
	}
	want, ok := simulation.AuthoredChallengeBySlug("certificate-expired")
	if !ok {
		t.Fatal("no certificate-expired authored challenge")
	}
	// Deterministic, unlike a starter draw: the same slug is the same case every
	// time, which is the whole reason for authoring one.
	for range 5 {
		challenge, err := resolveChallenge(f)
		if err != nil {
			t.Fatal(err)
		}
		if challenge.ID != want.ID {
			t.Fatalf("-authored certificate-expired resolved to %s, not %s", challenge.ID, want.ID)
		}
		if challenge.Daily != "" {
			t.Fatalf("an authored challenge claims to be the daily for %q", challenge.Daily)
		}
	}
}

// The authored listing has to print the ids, because an authored challenge is
// an ordinary shareable id and hiding it would make this command the only way
// to reach one.
func TestAuthoredListingPrintsSlugsAndIDs(t *testing.T) {
	var out bytes.Buffer
	if code := authored(nil, &out, io.Discard); code != exitOK {
		t.Fatalf("authored exited %d", code)
	}
	listing := out.String()
	for _, item := range simulation.AuthoredChallenges() {
		if !strings.Contains(listing, item.Slug) {
			t.Errorf("the listing does not name %q", item.Slug)
		}
		if !strings.Contains(listing, item.ID) {
			t.Errorf("the listing does not print %s, so it could not be replayed or shared", item.ID)
		}
	}
	if code := authored([]string{"extra"}, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("authored accepted an argument, exited %d", code)
	}
}
