//go:build unix

package sshverify

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shellQuery runs script under sh, so the query's output and exit status are real.
func shellQuery(script string) func() ([]byte, error) {
	return func() ([]byte, error) {
		return exec.Command("sh", "-c", script).CombinedOutput() // #nosec G204 -- fixed test scripts
	}
}

// A client without GSSAPI prints one diagnostic for the probe's GSSAPIAuthentication=no override, as
// the transcript's first line. The line is removed only when the query for GSSAPI key exchange gives
// exactly the unsupported answer, with a nonzero exit. Every other answer refuses the check.
func TestGSSAPIUnsupportedDiagnosticIsAcceptedOnlyWithTheExactQueryAnswer(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	exact := `printf 'Unsupported query "kex-gss"\n'; exit 255`
	noTop := strings.Replace(alpine, gssapiUnsupportedLine+"\n", "", 1)

	cases := []struct {
		name     string
		in       string
		kex      func() ([]byte, error)
		accepted bool // whether the diagnostic is removed, or the transcript is returned unchanged
		trusted  bool // whether the judged transcript is trusted
	}{
		{"exact answer, nonzero exit", alpine, shellQuery(exact), true, true},
		{"exact answer, CRLF line endings", strings.ReplaceAll(alpine, "\n", "\r\n"), shellQuery(exact), true, true},
		{"client lists GSSAPI key exchange", alpine, shellQuery(`printf 'gss-group14-sha1-\n'; exit 255`), false, false},
		{"unrelated failure output", alpine, shellQuery(`printf 'ssh: permission denied\n'; exit 255`), false, false},
		{"empty failure", alpine, shellQuery(`exit 255`), false, false},
		{"exact answer and a second line", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\nextra\n'; exit 255`), false, false},
		{"exact answer with exit 0", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\n'; exit 0`), false, false},
		{"exact answer, then killed by a signal", alpine, shellQuery(`printf 'Unsupported query "kex-gss"\n'; kill -9 $$`), false, false},
		{"query cannot start", alpine, func() ([]byte, error) { return nil, errors.New("exec: not found") }, false, false},
		{"single misplaced diagnostic, after the banner", strings.Replace(noTop, "\n", "\n"+gssapiUnsupportedLine+"\n", 1), shellQuery(exact), true, false},
		{"diagnostic twice at the top", gssapiUnsupportedLine + "\n" + alpine, shellQuery(exact), true, false},
		{"other option named", strings.Replace(alpine, "gssapiauthentication", "gssapikeyexchange", 1), shellQuery(exact), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := withoutGSSAPIUnsupported([]byte(tc.in), tc.kex)
			if ok != tc.accepted {
				t.Fatalf("accepted = %v, want %v", ok, tc.accepted)
			}
			if !ok {
				return
			}
			trust, trusted, _ := parseHostTrust(got, 255)
			if trusted != tc.trusted {
				t.Fatalf("trusted = %v, want %v", trusted, tc.trusted)
			}
			if trusted && trust.fingerprint != presentedFingerprint(t, alpine) {
				t.Fatalf("trusted fingerprint %q, want the one OpenSSH presented", trust.fingerprint)
			}
		})
	}
}

// A query that outlives its deadline is killed, and the check is refused, not accepted.
func TestGSSAPIUnsupportedQueryTimeoutRefusesTheCheck(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	slow := func() ([]byte, error) {
		return exec.CommandContext(ctx, "sh", "-c", `printf 'Unsupported query "kex-gss"\n'; exec sleep 5`).CombinedOutput() // #nosec G204 -- fixed test script
	}
	if _, ok := withoutGSSAPIUnsupported([]byte(alpine), slow); ok {
		t.Fatal("a query that timed out was accepted")
	}
}

// The exception belongs to the check, so the check's context governs it. Each case is deterministic:
// no sleeps, and the context is ended by the test itself, after a real shell query has printed the
// exact answer and exited nonzero.
func TestGSSAPIExceptionIsRefusedOnceTheCheckContextEnds(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	exact := `printf 'Unsupported query "kex-gss"\n'; exit 255`

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endAfterAnswer := func() ([]byte, error) {
		out, err := exec.Command("sh", "-c", exact).CombinedOutput() // #nosec G204 -- fixed test script, not bound to the context
		cancel()
		return out, err
	}
	if _, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), endAfterAnswer); ok {
		t.Fatal("the exception held after the check's context ended")
	}

	past, pastCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer pastCancel()
	if _, ok := transcriptWithoutGSSAPI(past, []byte(alpine), shellQuery(exact)); ok {
		t.Fatal("the exception held under a deadline that had already passed")
	}

	live, liveCancel := context.WithCancel(context.Background())
	defer liveCancel()
	got, ok := transcriptWithoutGSSAPI(live, []byte(alpine), shellQuery(exact))
	if !ok {
		t.Fatal("control: the exact answer with a live context was refused")
	}
	if want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n"); string(got) != want {
		t.Fatalf("control: removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}

// fakeQueryClient writes an executable that stands in for the installed client. The query's arguments are
// ignored, so the query runs through the same code path as the real one.
func fakeQueryClient(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-ssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { // #nosec G306 -- a test executable in a temporary directory
		t.Fatal(err)
	}
	return path
}

// A query that prints the exact answer and then hangs must end at its deadline, and a descendant it
// started must end with it. The descendant writes its marker a second in, so the marker exists only if
// the descendant outlived the query. The check is refused.
func TestGSSAPIQueryThatHangsEndsAtItsDeadline(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	marker := filepath.Join(t.TempDir(), "descendant-ran")
	client := fakeQueryClient(t, `(sleep 1; touch "`+marker+`") & printf 'Unsupported query "kex-gss"\n'; sleep 30`)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), func() ([]byte, error) { return kexGSSQuery(ctx, client) })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a query past its deadline held the check for %v", elapsed)
	}
	if ok {
		t.Fatal("a query that hung past its deadline was accepted")
	}
	time.Sleep(1500 * time.Millisecond) // past the descendant's one-second write
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a descendant of the query outlived the query's deadline")
	}
}

// A query that exits while a descendant in its process group holds its output open. The query ends the
// group on exit, its output closes, and the answer is judged as given. The query returns at once, not
// when the descendant would have ended.
func TestGSSAPIQueryLeavingADescendantEndsWithItsOutput(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	client := fakeQueryClient(t, `(sleep 30) & printf 'Unsupported query "kex-gss"\n'; exit 255`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	got, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), func() ([]byte, error) { return kexGSSQuery(ctx, client) })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the query waited %v for a descendant that held its output", elapsed)
	}
	if !ok {
		t.Fatal("the exact answer from a query that ended its descendant was refused")
	}
	if want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n"); string(got) != want {
		t.Fatalf("removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}

// A descendant that leaves the query's process group keeps the output open, and the query cannot end
// it. The output is still open after probeWaitDelay, so the output is refused as incomplete. The
// descendant sleeps well past that bound, so the outcome does not depend on timing.
func TestGSSAPIQueryWhoseOutputStaysOpenIsRefused(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid is not installed")
	}
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	ready := filepath.Join(t.TempDir(), "ready")
	// The descendant creates ready only after setsid has moved it out of the query's group, and the query
	// waits for ready before it answers. The escape is therefore complete before the query exits, and the
	// outcome does not depend on how the two processes are scheduled. The descendant outlives the test by
	// a few seconds and holds no resources.
	client := fakeQueryClient(t, `setsid sh -c 'touch "`+ready+`"; exec sleep 5' & i=0; while [ ! -e "`+ready+`" ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done; printf 'Unsupported query "kex-gss"\n'; exit 255`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), func() ([]byte, error) { return kexGSSQuery(ctx, client) })
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the query waited %v for output that a descendant kept open", elapsed)
	}
	if ok {
		t.Fatal("output that stayed open past the bound was accepted")
	}
}

// A client that lists GSSAPI key exchange answers normally, with exit 0. The query returns the list,
// and the rule still refuses the exception: a client with GSSAPI keeps its warning refused.
func TestGSSAPIQuerySupportedClientListsItsAlgorithms(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	client := fakeQueryClient(t, `printf 'gss-curve25519-sha256-\ngss-group14-sha256-\n'; exit 0`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data, err := kexGSSQuery(ctx, client)
	if err != nil {
		t.Fatalf("a supported client's query failed: %v", err)
	}
	if !strings.Contains(string(data), "gss-curve25519-sha256-") {
		t.Fatalf("the query did not list the client's GSSAPI algorithms: %q", data)
	}
	if _, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), func() ([]byte, error) { return data, err }); ok {
		t.Fatal("a client that lists GSSAPI key exchange was granted the exception")
	}
}

// The exact unsupported answer, from a query that exits nonzero, is accepted through the real query.
func TestGSSAPIQueryExactUnsupportedAnswerIsAccepted(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	client := fakeQueryClient(t, `printf 'Unsupported query "kex-gss"\n'; exit 255`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, ok := transcriptWithoutGSSAPI(ctx, []byte(alpine), func() ([]byte, error) { return kexGSSQuery(ctx, client) })
	if !ok {
		t.Fatal("the exact unsupported answer was refused")
	}
	if want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n"); string(got) != want {
		t.Fatalf("removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}

// Only the diagnostic line is removed: no other line of the transcript changes.
func TestGSSAPIUnsupportedRemovalChangesNothingElse(t *testing.T) {
	alpine := fixture(t, "alpine-openssh-10.6p2-trust")
	got, ok := withoutGSSAPIUnsupported([]byte(alpine), shellQuery(`printf 'Unsupported query "kex-gss"\n'; exit 255`))
	if !ok {
		t.Fatal("the diagnostic was not removed")
	}
	want := strings.TrimPrefix(alpine, gssapiUnsupportedLine+"\n")
	if string(got) != want {
		t.Fatalf("removal changed other lines:\n%q\nwant\n%q", got, want)
	}
}
