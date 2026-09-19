//go:build darwin

package diagnostic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func fakeSSIDTool(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "networksetup")
	// #nosec G306 -- this test-owned shell fixture must be executable.
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func stubSSIDCommand(t *testing.T, path string) *[]string {
	t.Helper()
	previous := ssidCommand
	var calledWith []string
	ssidCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calledWith = append([]string{name}, args...)
		return exec.CommandContext(ctx, path, args...)
	}
	t.Cleanup(func() { ssidCommand = previous })
	return &calledWith
}

func TestSSIDUsesNetworksetupArgs(t *testing.T) {
	path := fakeSSIDTool(t, `printf '%s\n' 'Current Wi-Fi Network: HomeNet 5G'
`)
	calledWith := stubSSIDCommand(t, path)

	if got := ssid(context.Background(), "en0"); got != "HomeNet 5G" {
		t.Fatalf("ssid = %q, want HomeNet 5G", got)
	}
	want := []string{"networksetup", "-getairportnetwork", "en0"}
	if !slices.Equal(*calledWith, want) {
		t.Fatalf("networksetup arguments = %q, want %q", *calledWith, want)
	}
}

func TestSSIDReturnsEmptyOnStartupFailure(t *testing.T) {
	stubSSIDCommand(t, filepath.Join(t.TempDir(), "missing"))
	if got := ssid(context.Background(), "en0"); got != "" {
		t.Fatalf("ssid = %q after startup failure, want empty", got)
	}
}

func TestSSIDTimeoutStaysBounded(t *testing.T) {
	path := fakeSSIDTool(t, `exec /bin/sleep 30
`)
	stubSSIDCommand(t, path)

	start := time.Now()
	if got := ssid(context.Background(), "en0"); got != "" {
		t.Fatalf("ssid = %q after timeout, want empty", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("ssid remained blocked for %v, want the 2s command timeout", elapsed)
	}
}
