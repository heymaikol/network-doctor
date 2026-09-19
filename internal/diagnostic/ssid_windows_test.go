//go:build windows

package diagnostic

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

func TestSSIDHelperProcess(t *testing.T) {
	if os.Getenv("GO_HELPER") != "1" {
		return
	}
	switch os.Getenv("GO_HELPER_MODE") {
	case "netsh":
		data, err := os.ReadFile(os.Getenv("GO_HELPER_STDOUT_FILE"))
		if err != nil {
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(data)
	case "sleep":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func stubSSIDHelper(t *testing.T, mode string, extraEnv ...string) *[]string {
	t.Helper()
	previous := ssidCommand
	var calledWith []string
	ssidCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calledWith = append([]string{name}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestSSIDHelperProcess")
		cmd.Env = append(append(os.Environ(), extraEnv...), "GO_HELPER=1", "GO_HELPER_MODE="+mode)
		return cmd
	}
	t.Cleanup(func() { ssidCommand = previous })
	return &calledWith
}

func writeHelperStdout(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssid-stdout.txt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSSIDUsesNetshArgs(t *testing.T) {
	path := writeHelperStdout(t, []byte(netshTwoAdapters))
	calledWith := stubSSIDHelper(t, "netsh", "GO_HELPER_STDOUT_FILE="+path)

	if got := ssid(context.Background(), "Wi-Fi"); got != "HomeNet" {
		t.Fatalf("ssid = %q, want HomeNet", got)
	}
	want := []string{"netsh", "wlan", "show", "interfaces"}
	if !slices.Equal(*calledWith, want) {
		t.Fatalf("netsh arguments = %q, want %q", *calledWith, want)
	}
}

func TestSSIDReturnsEmptyOnStartupFailure(t *testing.T) {
	previous := ssidCommand
	ssidCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, `C:\missing-netsh.exe`, args...)
	}
	t.Cleanup(func() { ssidCommand = previous })

	if got := ssid(context.Background(), "Wi-Fi"); got != "" {
		t.Fatalf("ssid = %q after startup failure, want empty", got)
	}
}

func TestSSIDTimeoutStaysBounded(t *testing.T) {
	stubSSIDHelper(t, "sleep")

	start := time.Now()
	if got := ssid(context.Background(), "Wi-Fi"); got != "" {
		t.Fatalf("ssid = %q after timeout, want empty", got)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("ssid remained blocked for %v, want the 2s command timeout", elapsed)
	}
}

func TestSSIDDecodesOEMBeforeParse(t *testing.T) {
	decoded := false
	previous := decodeSSIDOutput
	decodeSSIDOutput = func(s string) string {
		decoded = true
		return textsafe.DecodeOEM(s)
	}
	t.Cleanup(func() { decodeSSIDOutput = previous })

	path := writeHelperStdout(t, []byte(netshTwoAdapters))
	stubSSIDHelper(t, "netsh", "GO_HELPER_STDOUT_FILE="+path)

	if got := ssid(context.Background(), "Wi-Fi"); got != "HomeNet" {
		t.Fatalf("ssid = %q, want HomeNet", got)
	}
	if !decoded {
		t.Fatal("ssid parsed netsh output without OEM decoding")
	}
}
