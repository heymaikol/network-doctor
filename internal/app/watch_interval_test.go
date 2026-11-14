package app

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/profile"
	"github.com/heymaikol/network-doctor/v2/internal/ui"
)

// stubWatchInterval replaces the pause a Watch arms after each pass, and
// restores the real one afterwards. The fake fires at once, or never when
// it is told to, so no test sleeps through a gap.
func stubWatchInterval(t *testing.T, arm func(time.Duration) <-chan time.Time) {
	t.Helper()
	orig := watchAfter
	t.Cleanup(func() { watchAfter = orig })
	watchAfter = arm
}

func firedPause() <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- time.Now()
	return fired
}

// countLines is how many passes the stream has written so far, which is what
// each pause is compared against.
func countLines(buf *bytes.Buffer) int {
	return bytes.Count(buf.Bytes(), []byte("\n"))
}

// A Watch interval the invocation cannot use is refused before any probe runs,
// in every mode the flag could reach, and the refusal names the flag.
func TestRunRefusesAWatchIntervalItCannotUse(t *testing.T) {
	orig := runAll
	t.Cleanup(func() { runAll = orig })
	runAll = func(context.Context, []diagnostic.Probe, time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		t.Error("a probe ran for a Watch interval the invocation cannot use")
		return nil
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"without watch", []string{"--json", "--watch-interval", "30s", "example.com:443"}, "netdoc: -watch-interval requires -watch"},
		{"with version", []string{"--version", "--watch-interval", "30s"}, "netdoc: -watch-interval requires -watch"},
		{"with compare", []string{"--compare", "--watch-interval", "30s", "a.ndoc", "b.ndoc"}, "netdoc: -watch-interval requires -watch"},
		{"zero", []string{"--json", "--watch", "--watch-interval", "0s", "example.com:443"}, "must be at least 1s, not 0s"},
		{"negative attached", []string{"--json", "--watch", "--watch-interval=-5s", "example.com:443"}, "must be at least 1s, not -5s"},
		{"negative separate", []string{"--json", "--watch", "--watch-interval", "-5s", "example.com:443"}, "must be at least 1s, not -5s"},
		{"below the floor", []string{"--json", "--watch", "--watch-interval", "999ms", "example.com:443"}, "must be at least 1s, not 999ms"},
		{"unitless", []string{"--json", "--watch", "--watch-interval", "30", "example.com:443"}, `invalid value "30" for flag -watch-interval`},
		{"not a duration", []string{"--json", "--watch", "--watch-interval", "soon", "example.com:443"}, `invalid value "soon" for flag -watch-interval`},
		{"overflow", []string{"--json", "--watch", "--watch-interval", "10000000000h", "example.com:443"}, `invalid value "10000000000h" for flag -watch-interval`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
		})
	}
}

// captureWatchHeadless runs the CLI up to the first pass and returns the
// settings that pass was built from. The stub panics out of the run before any
// probe exists, so nothing touches the network.
func captureWatchHeadless(t *testing.T, args []string) headless {
	t.Helper()
	orig := buildHeadlessProbes
	t.Cleanup(func() { buildHeadlessProbes = orig })
	type captured struct{}
	var got headless
	buildHeadlessProbes = func(h headless) []diagnostic.Probe {
		got = h
		panic(captured{})
	}
	var stdout, stderr bytes.Buffer
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(captured); !ok {
					panic(r)
				}
			}
		}()
		code := run(args, &stdout, &stderr)
		t.Fatalf("run returned %d before any pass was built; stderr: %s", code, stderr.String())
	}()
	return got
}

// The interval reaches the Watch that paces the passes. A run that did not name
// the flag keeps the package default, read when each pause is armed.
func TestRunCarriesTheWatchIntervalOnlyWhenNamed(t *testing.T) {
	cases := []struct {
		name string
		args []string
		// want is the interval the run carries: zero when the flag was not
		// named, so the package default is read later, not pushed now.
		want time.Duration
	}{
		{"unnamed carries nothing", []string{"--json", "--watch", "example.com:443"}, 0},
		{"named default value", []string{"--json", "--watch", "--watch-interval", "5s", "example.com:443"}, 5 * time.Second},
		{"sub-minute", []string{"--json", "--watch", "--watch-interval", "1.5s", "example.com:443"}, 1500 * time.Millisecond},
		{"floor", []string{"--json", "--watch", "--watch-interval", "1s", "example.com:443"}, time.Second},
		{"minute", []string{"--json", "--watch", "--watch-interval", "1m", "example.com:443"}, time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureWatchHeadless(t, tc.args)
			if got.watchInterval != tc.want {
				t.Errorf("carried interval = %v, want %v", got.watchInterval, tc.want)
			}
			wantPause := tc.want
			if wantPause == 0 {
				wantPause = ui.WatchEvery
			}
			if pause := got.pause(); pause != wantPause {
				t.Errorf("pause = %v, want %v", pause, wantPause)
			}
		})
	}
}

// The headless Watch waits the configured gap after each pass it has printed,
// and the gap is measured after the line is written, so the next pass never
// starts while a pause is pending.
func TestHeadlessWatchPausesTheConfiguredGapAfterEachPass(t *testing.T) {
	stubPassingRun(t)
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	var events []string
	origRun := runAll
	t.Cleanup(func() { runAll = origRun })
	runAll = func(ctx context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		events = append(events, "run")
		return origRun(ctx, probes, timeout)
	}
	pauses := 0
	stubWatchInterval(t, func(d time.Duration) <-chan time.Time {
		pauses++
		events = append(events, fmt.Sprintf("wait %s after %d lines", d, countLines(&stdout)))
		if pauses == 3 {
			cancel() // the third pause is the last thing this run does
			return make(chan time.Time)
		}
		return firedPause()
	})

	h := headless{
		target: target, selection: diagnostic.ProbeSelection{}, timeout: time.Second,
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true, watch: true, json: true,
		watchInterval: 2 * time.Second,
	}
	if code := runHeadless(ctx, h, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	want := []string{
		"run", "wait 2s after 1 lines",
		"run", "wait 2s after 2 lines",
		"run", "wait 2s after 3 lines",
	}
	if !slices.Equal(events, want) {
		t.Errorf("events = %q\nwant %q", events, want)
	}
}

// Ctrl+C during the pause ends the stream at once. The pause is not waited out,
// and no further pass starts.
func TestHeadlessWatchCancelDuringThePauseStopsAtOnce(t *testing.T) {
	stubPassingRun(t)
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	origRun := runAll
	t.Cleanup(func() { runAll = origRun })
	runs := 0
	runAll = func(ctx context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		runs++
		return origRun(ctx, probes, timeout)
	}
	pauses := 0
	stubWatchInterval(t, func(time.Duration) <-chan time.Time {
		pauses++
		cancel()
		return make(chan time.Time)
	})

	done := make(chan int, 1)
	var stdout, stderr bytes.Buffer
	h := headless{
		target: target, selection: diagnostic.ProbeSelection{}, timeout: time.Second,
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true, watch: true, json: true,
		watchInterval: time.Hour,
	}
	go func() { done <- runHeadless(ctx, h, &stdout, &stderr) }()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit = %d, want 0 for the one pass that passed", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream kept waiting out its pause after cancellation")
	}
	if runs != 1 || pauses != 1 {
		t.Errorf("passes = %d, pauses = %d; want one of each", runs, pauses)
	}
}

// The profile Watch paces its passes with the same gap, and stops during it.
func TestProfileWatchPausesTheConfiguredGap(t *testing.T) {
	stubPassingRun(t)
	definition, _ := profile.Builtins().Lookup("github")
	plan, err := definition.Plan("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	var pauses []time.Duration
	var printed []int
	stubWatchInterval(t, func(d time.Duration) <-chan time.Time {
		pauses = append(pauses, d)
		printed = append(printed, countLines(&buf))
		if len(pauses) == 2 {
			cancel()
			return make(chan time.Time)
		}
		return firedPause()
	})

	base := headless{
		watch: true, json: true, publicDNS: diagnostic.DefaultPublicDNS, timeout: time.Second,
		watchInterval: 3 * time.Second,
	}
	if code := runProfile(ctx, base, plan, &buf, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr.String())
	}
	if want := []time.Duration{3 * time.Second, 3 * time.Second}; !slices.Equal(pauses, want) {
		t.Errorf("pauses = %v, want %v", pauses, want)
	}
	if want := []int{1, 2}; !slices.Equal(printed, want) {
		t.Errorf("lines written before each pause = %v, want %v", printed, want)
	}
}
