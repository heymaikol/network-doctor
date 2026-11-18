package sshverify

import (
	"context"
	"strings"
	"testing"
)

// The platform gate runs before any client is started. The program named here does
// not exist, so a read that reached the start would fail with "could not start",
// and the refusal is what shows the gate ran first.
func TestUnsupportedPlatformRefusesEveryReadBeforeAnyClientStarts(t *testing.T) {
	saved := configPlatformSupported
	t.Cleanup(func() { configPlatformSupported = saved })

	configPlatformSupported = false
	_, err := ReadConfig(context.Background(), "/nonexistent/netdoc-ssh-for-gate-test", []string{"-G", "--", "host"})
	if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("an unsupported platform returned %v; want the refusal, with nothing sent", err)
	}
	if strings.Contains(err.Error(), "could not start") {
		t.Fatalf("the read reached the client start before the platform gate: %v", err)
	}

	configPlatformSupported = true
	_, err = ReadConfig(context.Background(), "/nonexistent/netdoc-ssh-for-gate-test", []string{"-G", "--", "host"})
	if err == nil || strings.Contains(err.Error(), "not supported") {
		t.Fatalf("a supported platform was refused by the gate: %v", err)
	}
}
