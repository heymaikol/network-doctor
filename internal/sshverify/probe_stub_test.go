package sshverify

import (
	"context"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// trustOpenSSH makes the host-key decision report key as the one OpenSSH trusted, for the rest of
// the test. The credential connection then has to present exactly that key, or it is refused.
func trustOpenSSH(t *testing.T, key ssh.PublicKey) {
	t.Helper()
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{algorithm: key.Type(), fingerprint: ssh.FingerprintSHA256(key)}, true, Result{}
	})
}

// refuseOpenSSH makes the host-key decision report the refusal r. A test uses it to check that
// no credential connection follows a refusal.
func refuseOpenSSH(t *testing.T, r Result) {
	t.Helper()
	installProbe(t, func(context.Context, Target, Options) (hostTrust, bool, Result) {
		return hostTrust{}, false, r
	})
}

func installProbe(t *testing.T, probe func(context.Context, Target, Options) (hostTrust, bool, Result)) {
	t.Helper()
	saved := openSSHProbe
	t.Cleanup(func() { openSSHProbe = saved })
	openSSHProbe = probe
}

// testHomeDir is the home directory Resolve gives the parser, so a test parses like production.
func testHomeDir() string {
	home, _ := os.UserHomeDir()
	return home
}
