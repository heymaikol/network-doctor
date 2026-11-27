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

// gssKexListed reports whether this client lists a GSSAPI key exchange algorithm. A client built
// without GSSAPI answers "Unsupported query", which has no algorithm line.
func gssKexListed(program string) bool {
	out, _ := exec.Command(program, "-Q", "kex-gss").CombinedOutput() // #nosec G204 -- fixed arguments
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "gss-") {
			return true
		}
	}
	return false
}

// GSSAPIKeyExchange restricts verification only. A --via run starts the user's own ssh, which
// the user has already trusted with that setting, so the route read for --via must accept it.
// Verification sends a credential, and must refuse the route.
func TestGSSAPIKeyExchangeRestrictsVerificationOnly(t *testing.T) {
	requireOpenSSH(t)
	program, err := exec.LookPath("ssh")
	if err != nil {
		missingOpenSSH(t, "needs ssh on this host")
	}
	cfg := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(cfg, []byte("Host 127.0.0.1\n  GSSAPIKeyExchange yes\n  Port 2622\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-G", "-F", cfg, "--", "127.0.0.1"}

	route, err := ReadRoute(context.Background(), program, args)
	if !gssKexListed(program) {
		// This client has no GSSAPI. OpenSSH rejects GSSAPIKeyExchange in a configuration file as a
		// bad option, so netdoc must refuse at the route read, naming the keyword, and send nothing.
		reason := ""
		if err != nil {
			reason = err.Error()
		} else if route.Kind != RouteDirect {
			reason = route.Reason
		}
		if !strings.Contains(strings.ToLower(reason), "gssapikeyexchange") {
			t.Fatalf("without GSSAPI the route must be refused for GSSAPIKeyExchange: err %v, route %+v", err, route)
		}
		t.Log("this client has no GSSAPI key exchange: the route read refuses the keyword before anything is sent")
		return
	}
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
