//go:build unix

package sshverify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GSSAPIKeyExchange restricts verification only. A --via run starts the user's own ssh, which
// the user has already trusted with that setting, so the route read for --via must accept it.
// Verification sends a credential, and must refuse the route.
func TestGSSAPIKeyExchangeRestrictsVerificationOnly(t *testing.T) {
	requireOpenSSH(t)
	program, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("needs ssh on this host")
	}
	cfg := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host 127.0.0.1\n  GSSAPIKeyExchange yes\n  Port 2622\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-G", "-F", cfg, "--", "127.0.0.1"}

	route, err := ReadRoute(context.Background(), program, args)
	if err != nil {
		t.Fatalf("the --via route read failed: %v", err)
	}
	if route.Kind != RouteDirect {
		t.Fatalf("the --via route refused GSSAPIKeyExchange: %s", route.Reason)
	}

	saved := sshTestArgs
	sshTestArgs = []string{"-F", cfg}
	t.Cleanup(func() { sshTestArgs = saved })
	_, err = Resolve(context.Background(), "127.0.0.1", 0, "")
	if err == nil || !strings.Contains(err.Error(), "GSSAPIKeyExchange") {
		t.Fatalf("verification did not refuse GSSAPIKeyExchange: %v", err)
	}
}
