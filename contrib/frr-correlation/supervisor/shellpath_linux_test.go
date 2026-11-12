//go:build linux && netns_integration

package supervisor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A test that puts an executable into a shell command has to keep its path one
// word. The path of sleep or mount comes from LookPath, so a directory name with
// a space, a quote or a dollar sign must not change what runs. Each case runs the
// real helper against a recorder installed at such a path and checks which
// program the shell executed and with what.
func TestShellHelpersKeepAnAwkwardExecutablePathWhole(t *testing.T) {
	sh := lookPath(t, "sh")
	dir := filepath.Join(t.TempDir(), "a b'c$d;e`f\"g")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(t.TempDir(), "record")
	odd := filepath.Join(dir, "tool")
	if err := os.WriteFile(odd, []byte("#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" > \"$RECORD\"\n"), 0o700); err != nil { //nolint:gosec // G306: the recorder must be executable.
		t.Fatal(err)
	}
	vtysh := filepath.Join(t.TempDir(), "vtysh")
	if err := os.WriteFile(vtysh, []byte("#!/bin/sh\n"+execLine(odd, "30")+"\n"), 0o700); err != nil { //nolint:gosec // G306: the stand-in must be executable.
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		argv []string
		want string // what the recorder saw: its own path, then its arguments
	}{
		{"descriptor probe keeps sleep whole", holdOpenArgv(sh, "echo end", odd), odd + "\n3600\n"},
		{"vtysh stand-in keeps sleep whole", []string{vtysh}, odd + "\n30\n"},
		{"FRR wrapper keeps mount whole", withTmpfsVarTmp(sh, odd, []string{"/bin/true"}), odd + "\n-t\ntmpfs\ntmpfs\n/var/tmp\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(record)
			cmd := exec.Command(tc.argv[0], tc.argv[1:]...) //nolint:gosec // G204: the program is a test helper's own output.
			cmd.Env = append(os.Environ(), "RECORD="+record)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, strings.TrimSpace(string(out)))
			}
			got, err := os.ReadFile(record) //nolint:gosec // G304: a file in this test's own TempDir.
			if err != nil {
				t.Fatalf("the awkward path was not executed: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("the recorder saw %q, want %q", got, tc.want)
			}
		})
	}
}
