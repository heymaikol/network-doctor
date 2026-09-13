// One timeout, one meaning: what the CLI accepts has to be what the probes
// spend, what --via sends, and what the artifact records, on every path that
// carries it. Integer milliseconds is the only spelling the published snapshot
// option and remote protocol 1 have, so this file pins the invocation to that
// precision and then proves nothing downstream moves it.

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/remote"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// timeoutContractCases are the values the whole contract is argued over, used
// by the CLI, remote and artifact tests below so none of them can accept a
// value another one refuses.
var timeoutContractCases = []struct {
	name     string
	flag     string
	accepted bool
	want     time.Duration
}{
	{"smallest accepted", "1ms", true, time.Millisecond},
	{"ordinary whole milliseconds", "250ms", true, 250 * time.Millisecond},
	{"seconds", "4s", true, 4 * time.Second},
	{"largest wire value", "2562047h47m16.854s", true, time.Duration(diagnostic.MaxProbeTimeoutMs) * time.Millisecond},
	{"sub-millisecond", "500us", false, 0},
	{"just under a millisecond", "999us", false, 0},
	{"fractional millisecond", "1.1ms", false, 0},
	{"half millisecond", "1.5ms", false, 0},
	{"nearly two milliseconds", "1.9ms", false, 0},
	{"one nanosecond", "1ns", false, 0},
	{"zero", "0s", false, 0},
	{"negative", "-1s", false, 0},
}

// A timeout finer than the setting can represent is refused at the invocation,
// which is the only place a person can still be told about it, and refused
// before a probe runs. Exit 2 is the ordinary bad-argument code this already
// spends for a non-positive value.
func TestRunRejectsATimeoutFinerThanMillisecondsBeforeProbing(t *testing.T) {
	for _, tc := range timeoutContractCases {
		t.Run(tc.name, func(t *testing.T) {
			orig := runAll
			t.Cleanup(func() { runAll = orig })
			var applied time.Duration
			ran := false
			runAll = func(_ context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				ran, applied = true, timeout
				results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
				for _, p := range probes {
					results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Dur: time.Millisecond}
				}
				return results
			}
			var stdout, stderr bytes.Buffer
			code := run([]string{"-json", "-no-history", "-timeout", tc.flag, "example.com:443"}, &stdout, &stderr)
			if !tc.accepted {
				if code != 2 {
					t.Fatalf("exit = %d, want 2; stderr: %s", code, stderr.String())
				}
				if ran {
					t.Error("probes ran for a timeout the invocation cannot represent")
				}
				if !strings.Contains(stderr.String(), "netdoc: -timeout") {
					t.Errorf("stderr = %q, want it to name -timeout", stderr.String())
				}
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want no report", stdout.String())
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
			}
			if applied != tc.want {
				t.Errorf("timeout handed to the runner = %v, want %v", applied, tc.want)
			}
		})
	}
}

// --via is a boundary the setting crosses, not a place it changes. Every
// accepted timeout reaches the wire as the same duration, and every value the
// wire cannot hold was already refused above, so nothing valid locally turns
// into an invalid request.
func TestViaSendsTheAcceptedTimeoutUnchanged(t *testing.T) {
	for _, tc := range timeoutContractCases {
		if !tc.accepted {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			seen := stubRemote(t, remoteAnswer(true), nil)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--via", "ideapad", "--json", "--timeout", tc.flag, "example.com"}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
			}
			if got := seen.TimeoutMs; got != tc.want.Milliseconds() {
				t.Fatalf("timeout_ms = %d, want %d", got, tc.want.Milliseconds())
			}
			// The far end rebuilds a Duration from that number. Local and
			// remote agree only if it is the same duration again.
			back, err := diagnostic.ProbeTimeoutFromMs(seen.TimeoutMs)
			if err != nil {
				t.Fatalf("the worker would refuse timeout_ms=%d: %v", seen.TimeoutMs, err)
			}
			if back != tc.want {
				t.Errorf("remote would run %v for a local %v", back, tc.want)
			}
		})
	}
}

// The worker is the other half of that equivalence, driven through the real
// worker entry point: a request the local side can build must run with the
// duration the local side meant, and a number no Duration can hold must be
// refused before it is multiplied into one.
func TestRemoteWorkerRebuildsTheTimeoutOrRefusesIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout string
		want    time.Duration
		wantErr string
	}{
		{name: "smallest accepted", timeout: "1", want: time.Millisecond},
		{name: "ordinary", timeout: "4000", want: 4 * time.Second},
		{name: "largest representable", timeout: "9223372036854", want: time.Duration(diagnostic.MaxProbeTimeoutMs) * time.Millisecond},
		{name: "absent", timeout: "0", wantErr: "-timeout must be positive"},
		{name: "negative", timeout: "-1", wantErr: "-timeout must be positive"},
		{name: "limit plus one", timeout: "9223372036855", wantErr: "-timeout must not exceed"},
		// Multiplied before it is checked, this one wraps the whole int64 range
		// and lands on a plausible 448.384us that a sign check waves through.
		{name: "overflows to a plausible positive", timeout: "18446744073710", wantErr: "-timeout must not exceed"},
		{name: "maximum int64", timeout: "9223372036854775807", wantErr: "-timeout must not exceed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig := runAll
			t.Cleanup(func() { runAll = orig })
			var applied time.Duration
			ran := false
			runAll = func(_ context.Context, probes []diagnostic.Probe, timeout time.Duration) map[diagnostic.ProbeID]diagnostic.ProbeResult {
				ran, applied = true, timeout
				results := make(map[diagnostic.ProbeID]diagnostic.ProbeResult, len(probes))
				for _, p := range probes {
					results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Dur: time.Millisecond}
				}
				return results
			}
			stubWorkerStdin(t, `{"protocol":1,"public_dns":"9.9.9.9","timeout_ms":`+tc.timeout+`}`)
			var stdout, stderr bytes.Buffer
			if code := run([]string{remote.WorkerFlag}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0: a refusal is still a completed exchange; stderr: %s", code, stderr.String())
			}
			var resp remote.Response
			if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" {
				if !strings.Contains(resp.Error, tc.wantErr) {
					t.Fatalf("error = %q, want it to mention %q", resp.Error, tc.wantErr)
				}
				if ran {
					t.Error("probes ran for a request that should have been refused")
				}
				if resp.Report != nil || resp.Snapshot != nil {
					t.Error("a refused request returned a diagnosis")
				}
				return
			}
			if resp.Error != "" {
				t.Fatalf("error = %q, want a diagnosis", resp.Error)
			}
			if applied != tc.want {
				t.Errorf("timeout handed to the runner = %v, want %v", applied, tc.want)
			}
			// The snapshot the worker hands back records the same setting it ran.
			if got := resp.Snapshot.Options.ProbeTimeoutMs; got != tc.want.Milliseconds() {
				t.Errorf("snapshot probe_timeout_ms = %d, want %d", got, tc.want.Milliseconds())
			}
		})
	}
}

// Protocol 1 has carried whole milliseconds in timeout_ms since it existed, so
// the three version pairings all resolve to the same duration with no additive
// field and no approximation. Nothing here needs an old binary: an old netdoc's
// request is a JSON object, and its behavior on a new one's request is decided
// entirely by the number in that field.
func TestMixedVersionRemotePairingsAgreeOnTheTimeout(t *testing.T) {
	// New local to any remote: the request only ever carries whole
	// milliseconds, which is exactly what a worker old enough to predate this
	// contract already reads. Reconstructing it the way every protocol 1 worker
	// always has returns the duration the local side accepted.
	for _, flag := range []string{"1ms", "250ms", "4s"} {
		d, err := time.ParseDuration(flag)
		if err != nil {
			t.Fatal(err)
		}
		seen := stubRemote(t, remoteAnswer(true), nil)
		var stdout, stderr bytes.Buffer
		if code := run([]string{"--via", "ideapad", "--json", "--timeout", flag, "example.com"}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
		}
		// How an older worker reads the field, spelled out rather than called:
		// that build has no range check and no canonical converter.
		if legacy := time.Duration(seen.TimeoutMs) * time.Millisecond; legacy != d {
			t.Errorf("an older worker would run %v for a local %v", legacy, d)
		}
	}

	// Older local to new remote: an old build sent whatever Milliseconds() made
	// of its own flag. A whole-millisecond value is honored unchanged, and the
	// zero an old build wrote for a sub-millisecond flag is refused with the
	// same message it has always been refused with.
	for _, tc := range []struct {
		ms   int64
		want time.Duration
		err  string
	}{
		{ms: 1, want: time.Millisecond},
		{ms: 4000, want: 4 * time.Second},
		{ms: 0, err: "-timeout must be positive"},
	} {
		got, err := diagnostic.ProbeTimeoutFromMs(tc.ms)
		switch {
		case tc.err != "":
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("ProbeTimeoutFromMs(%d) = (%v, %v), want %q", tc.ms, got, err, tc.err)
			}
		case err != nil:
			t.Errorf("ProbeTimeoutFromMs(%d) = %v, want %v", tc.ms, err, tc.want)
		case got != tc.want:
			t.Errorf("ProbeTimeoutFromMs(%d) = %v, want %v", tc.ms, got, tc.want)
		}
	}
}

// The artifact is the durable boundary, and the value in it has to be the
// invocation's own, not a rounding of it. Every accepted timeout writes a
// distinct probe_timeout_ms, so a later comparison recovers the difference
// between two runs that really were configured differently.
func TestSavedSnapshotRecordsTheAcceptedTimeoutExactly(t *testing.T) {
	seen := map[int64]string{}
	for _, tc := range timeoutContractCases {
		if !tc.accepted {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			stubPassingRun(t)
			path := filepath.Join(t.TempDir(), "run.ndoc")
			var stdout, stderr bytes.Buffer
			if code := run([]string{"--save", path, "--no-history", "--timeout", tc.flag, "example.com"}, &stdout, &stderr); code != 0 {
				t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
			}
			// #nosec G304 -- path is this test's temporary snapshot file.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s, err := snapshot.Decode(data)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if s.Schema != snapshot.Schema {
				t.Errorf("schema = %q, want %q: the timeout contract is not a new format", s.Schema, snapshot.Schema)
			}
			if got := s.Options.ProbeTimeoutMs; got != tc.want.Milliseconds() {
				t.Fatalf("probe_timeout_ms = %d, want %d", got, tc.want.Milliseconds())
			}
			// Zero is reserved for an artifact that does not say. A run that had
			// a timeout must never write it.
			if s.Options.ProbeTimeoutMs == 0 {
				t.Fatal("a run with a timeout recorded probe_timeout_ms = 0, which means absent")
			}
			if prev, dup := seen[s.Options.ProbeTimeoutMs]; dup {
				t.Fatalf("-timeout %s and -timeout %s both recorded probe_timeout_ms = %d", prev, tc.flag, s.Options.ProbeTimeoutMs)
			}
			seen[s.Options.ProbeTimeoutMs] = tc.flag
		})
	}
}

// Two runs whose accepted timeout policies differ must stay distinguishable all
// the way to the comparison, which is what the artifact field exists for. The
// two smallest accepted values are the tightest case: before the invocation was
// pinned to milliseconds, neighbouring policies like 1.1ms and 1.9ms both landed
// on the same stored 1 and the difference was gone for good.
func TestCompareRecoversDifferentAcceptedTimeoutPolicies(t *testing.T) {
	dir := t.TempDir()
	save := func(name, flag string) string {
		stubPassingRun(t)
		path := filepath.Join(dir, name+".ndoc")
		var stdout, stderr bytes.Buffer
		if code := run([]string{"--save", path, "--no-history", "--timeout", flag, "example.com"}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit = %d for -timeout %s, want 0; stderr: %s", code, flag, stderr.String())
		}
		return path
	}
	before, after := save("before", "1ms"), save("after", "2ms")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--compare", before, after}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit = %d, want 1 (the runs differ); stderr: %s", code, stderr.String())
	}
	if want := "probe timeout changed from 1ms to 2ms"; !strings.Contains(stdout.String(), want) {
		t.Errorf("comparison did not report the timeout difference; want %q in:\n%s", want, stdout.String())
	}
}
