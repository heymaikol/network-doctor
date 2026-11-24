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
	if s.attempt.Identity != stubIdentity {
		t.Fatalf("the check's identity = %+v, want the one discovery showed %+v", s.attempt.Identity, stubIdentity)
	}
}

// The agent check discovers the host in its own run first, and binds the check to the identity that
// discovery trusted. Nothing from an earlier run can stand in for that discovery.
func TestVerifySSHAgentCheckDiscoversBeforeItBinds(t *testing.T) {
	s := &stubVerify{
		result: sshverify.Result{Outcome: sshverify.Verified, Method: sshverify.MethodAgent},
		listed: []sshverify.AgentKey{{Fingerprint: "SHA256:abc", Type: "ssh-ed25519"}},
	}
	installVerifyStubs(t, s)

	code, _, errOut := runVerify(t, "", "-verify-ssh", "-verify-auth", "agent", "-verify-agent-key", "SHA256:abc", "host.example")

	if code != 0 {
		t.Fatalf("code = %d, want 0; stderr %q", code, errOut)
	}
	if !s.discover || !s.attempted || !s.boundAfterDiscover {
		t.Fatalf("discover %v, attempted %v, discovery before the check %v; want all three", s.discover, s.attempted, s.boundAfterDiscover)
	}
	if s.attempt.Identity != stubIdentity {
		t.Fatalf("the agent check's identity = %+v, want the one discovery trusted %+v", s.attempt.Identity, stubIdentity)
	}
}

// A discovery that does not trust the host sends no agent credential.
func TestVerifySSHAgentCheckSendsNothingWithoutATrustedDiscovery(t *testing.T) {
	s := &stubVerify{
		preflight: &sshverify.Result{Outcome: sshverify.HostKeyUnknown, HostKey: stubHostKey},
		listed:    []sshverify.AgentKey{{Fingerprint: "SHA256:abc", Type: "ssh-ed25519"}},
	}
	installVerifyStubs(t, s)

	code, _, _ := runVerify(t, "", "-verify-ssh", "-verify-auth", "agent", "-verify-agent-key", "SHA256:abc", "host.example")

	if code != 2 || s.attempted {
		t.Fatalf("code = %d, attempted = %v; want exit 2 with no agent credential", code, s.attempted)
	}
}
