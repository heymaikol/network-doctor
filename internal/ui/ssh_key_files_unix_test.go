//go:build unix

package ui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The child process keeps a blocked file open from hanging the test runner.
// A FIFO in ~/.ssh must never hold the route read while waiting for a writer.
func TestSSHPrivateKeyPickerDoesNotOpenNamedPipes(t *testing.T) {
	const childEnv = "NETDOC_TEST_SSH_KEY_FIFO_DIR"
	const directEnv = "NETDOC_TEST_SSH_KEY_FIFO_DIRECT"
	if dir := os.Getenv(childEnv); dir != "" {
		if os.Getenv(directEnv) == "1" {
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			f, err := openSSHKeyCandidate(root, "agent-pipe")
			if err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			return
		}
		keys, err := scanSSHPrivateKeys(context.Background(), dir)
		if err != nil || len(keys) != 0 {
			t.Fatalf("FIFO scan: keys=%q, err=%v", keys, err)
		}
		return
	}
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "agent-pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, direct := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		// #nosec G702 G204 -- the subprocess is this test binary with one fixed test selector, not external input.
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHPrivateKeyPickerDoesNotOpenNamedPipes$")
		cmd.Env = append(os.Environ(), childEnv+"="+dir)
		if direct {
			cmd.Env = append(cmd.Env, directEnv+"=1")
		}
		out, err := cmd.CombinedOutput()
		expired := ctx.Err()
		cancel()
		if expired != nil {
			t.Fatalf("the SSH key scan blocked on a named pipe (direct=%v): %v", direct, expired)
		}
		if err != nil {
			t.Fatalf("the SSH key scan failed (direct=%v): %v\n%s", direct, err, out)
		}
	}
}
