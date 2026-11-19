package app

import (
	"bytes"
	"context"
	"errors"
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

// H: an operation timeout is not a cancellation. With the caller still active, a noninteractive
// attempt that times out is recorded as that component's failure, and the others still run over
// the noninteractive transport. No interactive attempt follows (T24).
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
	// The report's verdict is part of the published report contract, so a timed-out component
	// carries a verdict from the schema's enum, not a check status.
	if v := result.Components[0].Report.Verdict; v != "incomplete" {
		t.Errorf("timed-out component verdict = %q, want %q", v, "incomplete")
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

// Negative control: an interactive run's deadline is not an ordinary component timeout. It ends the
// pass, and no further interactive attempt follows, because a person may simply be slow to answer.
func TestProfileInteractiveTimeoutStillEndsThePass(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 0, func(remote.Request, bool) (remote.Response, error) {
		// An interactive run's deadline is not marked: the transport leaves that mark off.
		return remote.Response{}, fmt.Errorf("ideapad: the remote run timed out after 1s")
	})
	stubRemoteDirect(t, false)
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil {
		t.Fatal("an interactive timeout was recorded as a component failure and the pass went on")
	}
	calls := tr.snapshot().calls
	if len(calls) != 1 || calls[0].batch {
		t.Fatalf("acquisitions = %+v, want the one interactive attempt and nothing after it", calls)
	}
}

// A one-shot run that was asked to save and cannot, because a component did not finish, exits with
// 2 as any failed save does. Only a watch goes on to its next pass.
func TestProfileOneShotSaveWithATimeoutExitsWithTwo(t *testing.T) {
	plan := githubPlan(t)
	timeouts := 1
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if batch && req.Target == plan.Runs[0].Target.Raw && timeouts > 0 {
			timeouts--
			return remote.Response{}, timedOut("ideapad")
		}
		resp := profileComponentAnswer(t, req, true)
		resp.Snapshot.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		resp.Snapshot.Checks = []snapshot.Check{{ID: req.Check[len(req.Check)-1], Name: "focus", Status: profile.StatusPass, Ran: true, DurationMs: 1, Detail: "observed"}}
		return resp, nil
	})
	save := filepath.Join(t.TempDir(), "profile.json")
	base := viaBase()
	base.save = save
	var stdout, stderr bytes.Buffer
	if code := runProfile(context.Background(), base, plan, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2 for a save that was not written; stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(save); err == nil {
		t.Error("a pass with an unfinished component was written")
	}
	if !strings.Contains(stderr.String(), "netdoc: -save: nothing written for this pass") {
		t.Errorf("stderr does not say the save was not written: %q", stderr.String())
	}
}

// A marked timeout on the sequential path is a component failure, and the next component still runs.
// A headless run is acquired over the batch transport even on this path, so its deadline arrives
// marked while the app asked for an interactive run.
func TestProfileSequentialBatchTimeoutIsAComponentFailure(t *testing.T) {
	plan := githubPlan(t)
	tr := traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, timedOut("ideapad")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	stubRemoteDirect(t, false)
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("a marked timeout ended the sequential pass: %v", err)
	}
	if got := result.Components[0].Status; got != profile.StatusFail {
		t.Errorf("timed-out component status = %q, want %q", got, profile.StatusFail)
	}
	if len(tr.snapshot().calls) != len(plan.Runs) {
		t.Errorf("acquisitions = %d, want every component attempted once", len(tr.snapshot().calls))
	}
}

// A timed-out component's detail says what happened and that no question was asked. It does not
// suggest a run from a terminal: a terminal run would time out too.
func TestProfileTimedOutDetailDoesNotOfferATerminal(t *testing.T) {
	plan := githubPlan(t)
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, timedOut("ideapad")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("a timed-out component ended the pass: %v", err)
	}
	detail := result.Components[0].Report.Checks[0].Detail
	if strings.Contains(detail, "terminal") {
		t.Errorf("a timed-out component's detail offers a terminal: %q", detail)
	}
	if !strings.Contains(detail, "no question was asked") {
		t.Errorf("a timed-out component's detail does not say no question was asked: %q", detail)
	}
}

// An ssh failure at exit 255, such as its own connect timeout, is not offered a terminal either.
// The text is the transport's own: ssh could not open the connection, with ssh's detail lines.
func TestProfileSSHFailureDoesNotOfferATerminal(t *testing.T) {
	plan := githubPlan(t)
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, errors.New("ideapad: ssh could not open the connection\n  Connection timed out during banner exchange")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	_, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err == nil {
		t.Fatal("an ssh failure was recorded as a component failure and the pass went on")
	}
	if strings.Contains(err.Error(), "terminal") {
		t.Errorf("an ssh failure offers a terminal: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "no question was asked") {
		t.Errorf("an ssh failure does not say no question was asked: %q", err.Error())
	}
}

// oneLine keeps the lines of a multi-line error apart: each line is trimmed, and the lines are joined
// with "; ", so the sanitizer that strips line breaks does not glue them into one word.
func TestOneLineKeepsTheLinesOfAnErrorApart(t *testing.T) {
	err := errors.New("probe: ssh could not open the connection\n  kex_exchange_identification: read: Connection reset by peer\n\n  Connection reset by 127.0.0.1 port 2294")
	want := "probe: ssh could not open the connection; kex_exchange_identification: read: Connection reset by peer; Connection reset by 127.0.0.1 port 2294"
	if got := oneLine(err); got != want {
		t.Errorf("oneLine = %q, want %q", got, want)
	}
	// A bare carriage return separates lines as well, as OpenSSH reads a configuration line.
	if got := oneLine(errors.New("connection\rConnection timed out")); got != "connection; Connection timed out" {
		t.Errorf("oneLine on a bare carriage return = %q, want %q", got, "connection; Connection timed out")
	}
}

// The -profile line for an ssh exit-255 failure is one exact line, with the detail lines separated and
// the batch suffix at the end: no question was asked, and nothing about a terminal.
func TestProfileStderrIsOneExactLineForASSHFailure(t *testing.T) {
	plan := githubPlan(t)
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, errors.New("ideapad: ssh could not open the connection\n  Connection timed out during banner exchange")
		}
		return profileComponentAnswer(t, req, true), nil
	})
	base := viaBase()
	var stdout, stderr bytes.Buffer
	if code := runProfile(context.Background(), base, plan, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d, want 2 for an ssh failure that ends the pass", code)
	}
	want := "netdoc: -profile: " + plan.Runs[0].Label + ": ideapad: ssh could not open the connection; Connection timed out during banner exchange; no question was asked\n"
	if got := stderr.String(); got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

// A timed-out component's detail is one exact line: the transport's own text, then the suffix.
func TestTimedOutDetailIsOneExactLine(t *testing.T) {
	plan := githubPlan(t)
	traceProfileVia(t, 0, func(req remote.Request, batch bool) (remote.Response, error) {
		if req.Target == plan.Runs[0].Target.Raw {
			return remote.Response{}, fmt.Errorf("ideapad: %w\n  Connection detail line", remote.ErrRunTimedOut)
		}
		return profileComponentAnswer(t, req, true), nil
	})
	result, _, _, err := runProfilePass(context.Background(), viaBase(), plan)
	if err != nil {
		t.Fatalf("a timed-out component ended the pass: %v", err)
	}
	want := "ideapad: the remote run timed out; Connection detail line; no question was asked"
	if got := result.Components[0].Report.Checks[0].Detail; got != want {
		t.Errorf("detail = %q, want %q", got, want)
	}
}
