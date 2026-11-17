//go:build unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A configuration read must end when its deadline passes, even when the ssh
// client hangs and a command it started holds the output pipe open. A Match
// exec command does exactly that. The fake client below starts a background
// child that keeps the pipe, then blocks, so only the process group kill and the
// wait delay can end the read.
func TestResolveIsBoundedWhenTheClientHangs(t *testing.T) {
	dir := t.TempDir()
	client := filepath.Join(dir, "ssh")
	script := "#!/bin/sh\nsleep 60 &\nsleep 60\n"
	if err := os.WriteFile(client, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	savedBinary, savedTimeout := sshBinary, resolveTimeout
	sshBinary = client
	resolveTimeout = 300 * time.Millisecond
	t.Cleanup(func() { sshBinary, resolveTimeout = savedBinary, savedTimeout })

	for attempt := 0; attempt < 3; attempt++ {
		start := time.Now()
		_, err := Resolve(context.Background(), "host", 0, "")
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("attempt %d: a hung configuration read returned no error", attempt)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("attempt %d: a hung configuration read took %v; want it bounded by its deadline", attempt, elapsed)
		}
	}
}
