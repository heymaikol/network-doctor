//go:build linux && netns_integration

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The staged FRR test cannot run in CI, so its host probe is checked here against a
// stand-in unshare. The stand-in records its arguments, which pins the shape of the
// probe: a new user and network namespace, then the launch wrapper around true.
func TestStagedLaunchProbeRunsTheLaunchWrapperAndSeparatesRefusals(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        string
		wantRefusal bool
		wantErr     bool
	}{
		{"host allows it", "exit 0", false, false},
		{"namespace refused", `echo "unshare: unshare failed: Operation not permitted" >&2; exit 1`, true, false},
		{"tmpfs mount refused", `echo "mount: /var/tmp: permission denied." >&2; exit 32`, true, false},
		{"unrecognised failure", `echo "unshare: unrecognized option '--mount'" >&2; exit 1`, false, true},
		{"fails without saying why", "exit 1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The directory name holds an apostrophe and spaces, so a path pasted between quotes in the
			// stand-in script cannot parse. The assertions below are unchanged.
			dir := filepath.Join(t.TempDir(), "it's a dir")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			argvFile := filepath.Join(dir, "argv")
			shim := probeScript(t, dir, "unshare", `printf '%s\n' "$@" > `+shellQuote(argvFile)+"\n"+tc.body)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			refusal, err := stagedLaunchProbe(ctx, shim, "/bin/sh", "/bin/mount", "/bin/true")
			if (refusal != "") != tc.wantRefusal || (err != nil) != tc.wantErr {
				t.Fatalf("refusal %q, error %v; want refusal %v, error %v", refusal, err, tc.wantRefusal, tc.wantErr)
			}
			b, readErr := os.ReadFile(argvFile) //nolint:gosec // G304: a file in this test's own TempDir.
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := strings.Join([]string{"-Urn", "--", shim, "--mount", "--", "/bin/sh", "-c", `"$0" -t tmpfs tmpfs /var/tmp && exec "$@"`, "/bin/mount", "/bin/true"}, "\n") + "\n"
			if string(b) != want {
				t.Errorf("the probe ran with\n%s\nwant\n%s", b, want)
			}
		})
	}
}
