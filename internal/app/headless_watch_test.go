package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/ui"
)

// fakeLink is the network under a headless Watch test. While down, the target's
// TCP connect fails and every row behind it is skipped.
type fakeLink struct {
	down atomic.Bool
	// tlsRuns counts TLS executions, the row a stable pass reuses.
	tlsRuns atomic.Int32
}

// fakeWatchProbes is the production row shape with each row replaced by a fake
// that passes, except the target connect while the link is down.
func fakeWatchProbes(target *diagnostic.Target, link *fakeLink) []diagnostic.Probe {
	probes := diagnostic.ProbePlan(target, diagnostic.DefaultPublicDNS, true)
	for i := range probes {
		id := probes[i].ID
		probes[i].Run = func(context.Context, map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
			if id == diagnostic.ProbeTLS {
				link.tlsRuns.Add(1)
			}
			if id == diagnostic.ProbeTargetTCP && link.down.Load() {
				return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Cause: "timeout"}
			}
			return diagnostic.ProbeResult{Status: diagnostic.StatusPass}
		}
	}
	return probes
}

// stubWatchSeams points the Watch loop at the fakes and a short interval for
// the rest of the test, and restores the production values after it.
func stubWatchSeams(t *testing.T) {
	t.Helper()
	prevRun, prevBuild, prevEvery := runAll, buildHeadlessProbes, ui.WatchEvery
	t.Cleanup(func() {
		runAll, buildHeadlessProbes, ui.WatchEvery = prevRun, prevBuild, prevEvery
	})
	runAll = diagnostic.RunAll
	ui.WatchEvery = time.Millisecond
}

// The headless loop prints only the passes that are published. Pass 3 changes the
// target's status after reusing rows, so it is confirmed by pass 4 and never
// printed. The output is one line per published pass, and the exit code is that
// of the last one printed.
func TestHeadlessWatchPrintsOnlyPublishedPasses(t *testing.T) {
	stubWatchSeams(t)
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeLink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	buildHeadlessProbes = func(h headless) []diagnostic.Probe {
		attempts++
		switch attempts {
		case 3:
			link.down.Store(true)
		case 5:
			cancel() // ends the loop before a fifth pass is printed
		}
		return fakeWatchProbes(h.target, link)
	}

	var stdout, stderr bytes.Buffer
	h := headless{
		target: target, selection: diagnostic.ProbeSelection{}, timeout: time.Second,
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true, watch: true, json: true,
	}
	code := runHeadless(ctx, h, &stdout, &stderr)

	var oks []bool
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var rep struct {
			OK bool `json:"ok"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rep); err != nil {
			t.Fatalf("line %q is not a report: %v", sc.Text(), err)
		}
		oks = append(oks, rep.OK)
	}
	if want := []bool{true, true, false}; !equalBools(oks, want) {
		t.Errorf("printed passes ok = %v, want %v: the discarded pass must not print", oks, want)
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1: the last printed pass failed", code)
	}
	// Pass 1 runs TLS. Passes 2 and 3 reuse it. Pass 4 skips it behind the failed
	// target, so TLS executes once across four passes.
	if got := link.tlsRuns.Load(); got != 1 {
		t.Errorf("TLS executed %d times over %d passes, want 1: stable passes reuse it", got, attempts)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// A one-shot run is one pass with no session.
func TestHeadlessOneShotRunsOnce(t *testing.T) {
	stubWatchSeams(t)
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	link := &fakeLink{}
	attempts := 0
	buildHeadlessProbes = func(h headless) []diagnostic.Probe {
		attempts++
		return fakeWatchProbes(h.target, link)
	}

	var stdout, stderr bytes.Buffer
	h := headless{
		target: target, selection: diagnostic.ProbeSelection{}, timeout: time.Second,
		publicDNS: diagnostic.DefaultPublicDNS, publicDNSAuto: true, json: true,
	}
	code := runHeadless(context.Background(), h, &stdout, &stderr)
	if attempts != 1 {
		t.Errorf("one-shot run made %d passes, want 1", attempts)
	}
	var rep struct {
		OK bool `json:"ok"`
	}
	dec := json.NewDecoder(&stdout)
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("one-shot output is not a report: %v", err)
	}
	if dec.More() {
		t.Error("one-shot run printed more than one report")
	}
	if code != 0 || !rep.OK {
		t.Errorf("exit code = %d, ok = %v; want 0 and ok for a healthy link", code, rep.OK)
	}
}

func equalBools(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
