//go:build integration && unix

package sshverify

import "testing"

// VisualHostKey prints a picture of the host key, and HostbasedAuthentication adds host-based lines,
// to the client's diagnostic output. Neither is in the probe's shape, and neither changes the trust
// decision. The probe turns both off, so a host that trusts a key with these settings is still
// discovered.
func TestOpenSSHVisualHostKeyAndHostbasedDoNotBreakTheCheck(t *testing.T) {
	l := newOSHLab(t, oshOpts{hostKinds: []string{"ed25519"}})
	l.writeKnown(t, l.record(l.hostKeys[0], "", l.names()))
	l.useConfig(t, l.baseConfig(l.known, "  VisualHostKey yes\n  HostbasedAuthentication yes\n"))
	tg := l.resolve(t, "127.0.0.1")

	if d := l.discover(t, tg); d.Outcome != Discovered {
		t.Fatalf("discovery with VisualHostKey and HostbasedAuthentication = %q (%s), want discovered", d.Outcome, d.Detail)
	}
}
