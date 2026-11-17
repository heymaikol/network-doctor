package sshverify

import (
	"context"
	"strings"
	"testing"
)

// Where the configuration read is not validated, verification is refused before
// any client runs, so nothing is read or contacted.
func TestUnsupportedPlatformRefusesTheRead(t *testing.T) {
	savedSupported, savedRead := configPlatformSupported, resolveOutput
	configPlatformSupported = false
	ran := false
	resolveOutput = func(context.Context, []string) ([]byte, error) {
		ran = true
		return nil, nil
	}
	t.Cleanup(func() { configPlatformSupported, resolveOutput = savedSupported, savedRead })

	_, err := Resolve(context.Background(), "host", 0, "")

	if err == nil || !strings.Contains(err.Error(), "not supported") || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("an unsupported platform returned %v; want the refusal, with nothing sent", err)
	}
	if ran {
		t.Fatal("the ssh client ran on an unsupported platform")
	}
}
