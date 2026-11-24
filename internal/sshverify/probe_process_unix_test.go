//go:build unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A descendant of the probe must not outlive it. The probe is cancelled at its deadline, and its
// whole process group goes with it, so a child that would write a file a few seconds later never
// does. The probe also returns at once, although the child held its output open.
func TestProbeProcessGroupEndsWithItsDescendants(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "descendant-ran")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	script := "(sleep 2; touch " + marker + ") & sleep 30"
	_, _, _, err := runHostKeyProbe(ctx, "/bin/sh", []string{"-c", script})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the probe waited %v for a descendant that holds its output (err %v)", elapsed, err)
	}
	time.Sleep(3 * time.Second)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("a descendant of the probe kept running after the probe was cancelled")
	}
}
