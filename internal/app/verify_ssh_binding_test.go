package app

import (
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// The command line discovers the host key, then checks with a credential in the same run. The
// check carries the key the discovery showed, so a key that changed in between is refused.
func TestVerifySSHCheckCarriesTheDiscoveredHostKey(t *testing.T) {
	const secret = "binding-test-secret" // #nosec G101 -- a marker string the test looks for, not a credential
	s := &stubVerify{result: sshverify.Result{Outcome: sshverify.Verified, Method: sshverify.MethodPassword}}
	installVerifyStubs(t, s)

	code, _, errOut := runVerify(t, secret+"\n", "-verify-ssh", "-verify-auth", "password", "-password-stdin", "host.example")

	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr %q", code, errOut)
	}
	if !s.attempted {
		t.Fatal("no credential check ran after the discovery")
	}
	if s.attempt.HostKey != stubHostKey {
		t.Fatalf("the check's host key = %q, want the one discovery showed %q", s.attempt.HostKey, stubHostKey)
	}
}
