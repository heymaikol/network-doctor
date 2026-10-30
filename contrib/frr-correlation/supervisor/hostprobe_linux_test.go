//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refusedByHost reports whether the output of a failed namespace or mount
// command names one of the errors that mean this host does not allow it. The
// command must have run with LC_ALL=C: util-linux and the C library translate
// these messages. Matching text is the only evidence a shell command gives, so
// anything it does not recognise is not a refusal.
func refusedByHost(output string) bool {
	low := strings.ToLower(output)
	for _, e := range capabilityErrnos {
		if strings.Contains(low, strings.ToLower(e.Error())) {
			return true
		}
	}
	return false
}

// hostRefusal runs a command a test needs to know the host can run, and tells a
// host that refuses it from a probe that failed some other way. refusal is the
// command's output when it ended with a recognised refusal. err covers every
// other failure (a command that would not start, a deadline, an exit with
// unrecognised or no output), and a caller must fail on it: it says nothing
// about the host, so it must never turn into a skip.
func hostRefusal(ctx context.Context, argv ...string) (refusal string, err error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: the callers pass binaries from LookPath and constant arguments.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, runErr := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	var exit *exec.ExitError
	switch {
	case runErr == nil:
		return "", nil
	case ctx.Err() != nil:
		return "", fmt.Errorf("%s did not finish: %w: %s", filepath.Base(argv[0]), ctx.Err(), text)
	case errors.As(runErr, &exit) && refusedByHost(text):
		return text, nil
	default:
		return "", fmt.Errorf("%s failed in a way that is not a host refusal: %w: %s", filepath.Base(argv[0]), runErr, text)
	}
}

func TestRefusedByHostRecognisesOnlyCapabilityErrors(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{"unshare: unshare failed: Operation not permitted", true},
		{"unshare: write failed /proc/self/uid_map: Operation not permitted", true},
		{"mount: /run: permission denied.", true},
		{"unshare: unshare failed: Invalid argument", true},
		{"unshare: unshare failed: No space left on device", true},
		{"unshare: unshare failed: Function not implemented", true},
		{"unshare: unshare failed: Resource temporarily unavailable", false},
		{"unshare: unshare failed: Cannot allocate memory", false},
		{"unshare: unshare failed: Too many open files", false},
		{"mount: /var/lib: mount point does not exist.", false},
		{"unshare: unrecognized option '-Urnm'", false},
		{"", false},
	} {
		if got := refusedByHost(tc.out); got != tc.want {
			t.Errorf("refusedByHost(%q) = %v, want %v", tc.out, got, tc.want)
		}
	}
}

// A refusal may skip a test. Every other way a probe can fail must stay a
// failure, or a broken probe would hide a host that could have run the test.
func TestHostRefusalSeparatesARefusalFromAFailedProbe(t *testing.T) {
	dir := t.TempDir()
	script := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // G306: the stand-in must be executable.
			t.Fatal(err)
		}
		return p
	}
	sleep := lookPath(t, "sleep")
	for _, tc := range []struct {
		name        string
		body        string
		timeout     time.Duration
		wantRefusal bool
		wantErr     bool
	}{
		{"succeeds", "exit 0", time.Second, false, false},
		{"namespace refused", `echo "unshare: unshare failed: Operation not permitted" >&2; exit 1`, time.Second, true, false},
		{"mount refused", `echo "mount: /run: permission denied." >&2; exit 32`, time.Second, true, false},
		{"unrecognised failure", `echo "unshare: unrecognized option '-Urnm'" >&2; exit 1`, time.Second, false, true},
		{"fails without saying why", "exit 1", time.Second, false, true},
		{"resource limit", `echo "unshare: unshare failed: Resource temporarily unavailable" >&2; exit 1`, time.Second, false, true},
		{"never finishes", "exec " + sleep + " 30", 200 * time.Millisecond, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			refusal, err := hostRefusal(ctx, script(strings.ReplaceAll(tc.name, " ", "-"), tc.body))
			if (refusal != "") != tc.wantRefusal || (err != nil) != tc.wantErr {
				t.Fatalf("refusal %q, error %v; want refusal %v, error %v", refusal, err, tc.wantRefusal, tc.wantErr)
			}
		})
	}
	t.Run("command that does not exist", func(t *testing.T) {
		refusal, err := hostRefusal(context.Background(), filepath.Join(dir, "absent"))
		if refusal != "" || err == nil {
			t.Fatalf("refusal %q, error %v; want an error", refusal, err)
		}
	})
}
