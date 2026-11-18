package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/profile"
	"github.com/heymaikol/network-doctor/v2/internal/remote"
	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

// timedOut is the error the transport returns when its own deadline ends a batch run.
func timedOut(host string) error {
	return fmt.Errorf("%s: %w", host, remote.ErrRunTimedOut)
}

// A batch acquisition that the deadline ends is that component's failure. The pass goes on to
// the other components, none of them is acquired interactively, and the result is not OK.
func TestProfileViaTimedOutBatchIsAComponentFailure(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch && req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, timedOut("ideapad")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("a timed-out component ended the pass: %v", err)
	}
	// The aggregate is the profile's own rule: a failed component with a working fallback reads
	// as a warning, not as a failed pass. What must hold is that the component is recorded as
	// failed, and that the pass does not read as passing.
	if result.Aggregate.Status == profile.StatusPass {
		t.Error("a timed-out component left the pass reading PASS")
	}
	if got := result.Components[0].Status; got != profile.StatusFail {
		t.Errorf("timed-out component status = %q, want %q", got, profile.StatusFail)
	}
	got := tr.snapshot()
	if len(got.calls) != len(plan.Runs) {
		t.Fatalf("acquisitions = %d, want every component attempted once: %+v", len(got.calls), got.calls)
	}
	for _, call := range got.calls {
		if !call.batch {
			t.Errorf("a component was acquired interactively after a timeout: %+v", call)
		}
	}
}

// Negative control: a timeout cannot make the pass OK. When every component times out, the
// pass fails and every component reads as failed.
func TestProfileViaTimeoutsCannotMakeThePassOK(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 0, func(remote.Request, bool) (remote.Response, error) {
		return remote.Response{}, timedOut("ideapad")
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("timeouts ended the pass: %v", err)
	}
	if result.OK || result.Aggregate.Status != profile.StatusFail {
		t.Errorf("all components timed out, but the pass reads OK=%v aggregate=%q", result.OK, result.Aggregate.Status)
	}
	for _, c := range result.Components {
		if c.Status != profile.StatusFail {
			t.Errorf("component %q reads %q after a timeout, want FAIL", c.Label, c.Status)
		}
	}
	for _, call := range tr.snapshot().calls {
		if !call.batch {
			t.Errorf("a component was acquired interactively: %+v", call)
		}
	}
}

// Negative control: a refusal still ends the pass when another component timed out. The
// refusal is a security decision, and a timeout beside it cannot make the pass record it as a
// component failure.
func TestProfileViaRefusalEndsThePassBesideATimeout(t *testing.T) {
	plan := githubPlan(t)
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		switch req.Target {
		case plan.Runs[0].Target.Raw:
			return remote.Response{}, timedOut("ideapad")
		case plan.Runs[1].Target.Raw:
			return remote.Response{}, errTransport
		}
		return profileComponentAnswer(t, req, true), nil
	})
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil || !strings.HasPrefix(err.Error(), plan.Runs[1].Label+":") {
		t.Fatalf("error = %v, want the refusal of %q to end the pass", err, plan.Runs[1].Label)
	}
}

// A watch goes on after a pass whose component timed out, and the next pass reads its own
// acquisitions afresh. The first pass is not OK, the second is, and the session exits with the
// code of the last pass.
func TestProfileWatchKeepsGoingAfterATimedOutPass(t *testing.T) {
	plan := githubPlan(t)
	timeouts := 1
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch && req.Target == plan.Runs[0].Target.Raw && timeouts > 0 {
			timeouts--
			return remote.Response{}, timedOut("ideapad")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	stubWatchInterval(t, func(time.Duration) <-chan time.Time { return firedPause() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 2, cancel: cancel}
	base := viaBase()
	base.watch, base.json = true, true
	code := runProfile(ctx, base, plan, out, &stderr)
	if code == 2 {
		t.Fatalf("the watch ended on a timed-out component; stderr: %s", stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("watch wrote %d passes, want 2:\n%s", len(lines), buf.String())
	}
	var first, second profile.Result
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if first.Components[0].Status != profile.StatusFail || first.Aggregate.Status == profile.StatusPass {
		t.Errorf("the timed-out pass reads component %q, aggregate %q", first.Components[0].Status, first.Aggregate.Status)
	}
	if !second.OK {
		t.Errorf("the pass after the timeout reads not OK: %+v", second.Aggregate)
	}
	if code != 0 {
		t.Errorf("exit = %d, want the last pass's 0", code)
	}
}

// A watch that saves writes only the passes that finished. A pass whose component timed out has
// no snapshot to write, so it writes nothing and says so, and the next pass is saved in full.
func TestProfileWatchSavesOnlyPassesThatFinished(t *testing.T) {
	plan := githubPlan(t)
	timeouts := 1
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch && req.Target == plan.Runs[0].Target.Raw && timeouts > 0 {
			timeouts--
			return remote.Response{}, timedOut("ideapad")
		}
		resp := profileComponentAnswer(t, req, true)
		// A saved snapshot carries its creation time and its focus check: the artifact validator
		// requires the component's status to match the run beneath it.
		resp.Snapshot.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		resp.Snapshot.Checks = []snapshot.Check{{ID: req.Check[len(req.Check)-1], Name: "focus", Status: profile.StatusPass, Ran: true, DurationMs: 1, Detail: "observed"}}
		return resp, nil
	})
	stubWatchInterval(t, func(time.Duration) <-chan time.Time { return firedPause() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buf, stderr bytes.Buffer
	out := &cancelAfter{buf: &buf, n: 2, cancel: cancel}
	save := filepath.Join(t.TempDir(), "profile.json")
	base := viaBase()
	base.watch, base.json, base.save = true, true, save
	if code := runProfile(ctx, base, plan, out, &stderr); code == 2 {
		t.Fatalf("the watch ended on a timed-out component; stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "nothing written for this pass") {
		t.Errorf("stderr does not say the timed-out pass was not saved: %q", stderr.String())
	}
	if _, err := os.Stat(save); err != nil {
		t.Errorf("the pass that finished was not saved: %v", err)
	}
}
