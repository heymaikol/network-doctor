//go:build darwin

package diagnostic

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeDNSSD creates an executable DNS-SD fixture for a test.
func fakeDNSSD(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dns-sd")
	// #nosec G306 -- this test-owned shell fixture must be executable.
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubDNSSDCommand redirects DNS-SD execution and records its arguments.
func stubDNSSDCommand(t *testing.T, path string) *[]string {
	t.Helper()
	previous := dnssdCommand
	var calledWith []string
	dnssdCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		calledWith = append([]string(nil), args...)
		return exec.CommandContext(ctx, path, args...)
	}
	t.Cleanup(func() { dnssdCommand = previous })
	return &calledWith
}

// TestBrowseZone verifies stdout capture and command arguments.
func TestBrowseZone(t *testing.T) {
	path := fakeDNSSD(t, `printf '%s\n' 'fixture zone'
`)
	calledWith := stubDNSSDCommand(t, path)

	if got := string(browseZone(context.Background(), "_ssh._tcp")); got != "fixture zone\n" {
		t.Fatalf("browseZone output = %q, want fixture zone", got)
	}
	want := []string{"-t", "3", "-Z", "_ssh._tcp", "local."}
	if !slices.Equal(*calledWith, want) {
		t.Fatalf("dns-sd arguments = %q, want %q", *calledWith, want)
	}
}

// TestBrowseZoneRejectsStartupFailure verifies missing commands return no output.
func TestBrowseZoneRejectsStartupFailure(t *testing.T) {
	stubDNSSDCommand(t, filepath.Join(t.TempDir(), "missing"))
	if got := browseZone(context.Background(), "_ssh._tcp"); got != nil {
		t.Fatalf("browseZone output = %q after startup failure, want nil", got)
	}
}

// TestBrowseZoneBoundsOutput verifies captured stdout stays within its limit.
func TestBrowseZoneBoundsOutput(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "output")
	want := bytes.Repeat([]byte("x"), maxDNSSDOutput+1)
	if err := os.WriteFile(outputFile, want, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSSD_OUTPUT_FILE", outputFile)
	path := fakeDNSSD(t, `/bin/cat "$DNSSD_OUTPUT_FILE"
`)
	stubDNSSDCommand(t, path)

	if got := browseZone(context.Background(), "_ssh._tcp"); !bytes.Equal(got, want[:maxDNSSDOutput]) {
		t.Fatalf("browseZone returned %d bytes, want first %d", len(got), maxDNSSDOutput)
	}
}

// TestBrowseZoneBoundsInheritedStdout verifies WaitDelay bounds inherited pipes.
func TestBrowseZoneBoundsInheritedStdout(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("DNSSD_PID_FILE", pidFile)
	path := fakeDNSSD(t, `/bin/sleep 30 &
printf '%s\n' "$!" > "$DNSSD_PID_FILE"
printf '%s\n' 'fixture zone'
`)
	stubDNSSDCommand(t, path)
	t.Cleanup(func() {
		pidText, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
		if err != nil || pid <= 0 {
			return
		}
		if process, err := os.FindProcess(pid); err == nil {
			_ = process.Kill()
		}
	})

	start := time.Now()
	if got := browseZone(context.Background(), "_ssh._tcp"); got != nil {
		t.Fatalf("browseZone output = %q with stdout held open, want nil", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("browseZone remained blocked for %v after WaitDelay", elapsed)
	}
}
