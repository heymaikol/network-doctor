package sshverify

import (
	"slices"
	"strings"
	"testing"
)

// The transcripts below are excerpts of OpenSSH 10.5p1 output from a loopback server. The
// probe runs with its exit status 255, which is what the client returns when the probe ends
// after the authentication method list.

const transcriptPrefix = `debug1: OpenSSH_10.5p1, OpenSSL 4.0.3 29 Sep 2026
debug1: Reading configuration data probe.conf
debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2633.
debug1: Connection established.
debug1: Remote protocol version 2.0, remote software version OpenSSH_10.5
debug1: Authenticating to 127.0.0.1:2633 as 'tester'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: mlkem768x25519-sha256
`

const transcriptAuthPhase = `debug1: Authentications that can continue: password
debug1: No more authentication methods to try.
`

// fpAttacker is a well-formed fingerprint that no server key has; the injected lines name it.
var fpAttacker = "SHA256:" + strings.Repeat("A", 43)

const (
	fpEd25519 = "SHA256:zBxr/QilxoWGhRK7/rFEBd+BlNPUQzhCv5YckuKCB2M"
	fpRSA     = "SHA256:M1Gg8NiXw4bSNGBQo8E3Ywh9mpgLHo8IJHi5xOTbpcI"
)

// trustedEd25519 is a check that OpenSSH passed: the key matched, and the authentication
// methods were listed.
var trustedEd25519 = transcriptPrefix + `debug1: kex: host key algorithm: ssh-ed25519
debug1: SSH2_MSG_KEX_ECDH_REPLY received
debug1: Server host key: ssh-ed25519 ` + fpEd25519 + `
debug1: load_hostkeys: fopen /nonexistent: No such file or directory
debug1: Host '[127.0.0.1]:2633' is known and matches the ED25519 host key.
debug1: Found key in /home/u/.ssh/known_hosts:1
debug1: SSH2_MSG_NEWKEYS received
` + transcriptAuthPhase

const kexEd25519 = `debug1: kex: host key algorithm: ssh-ed25519
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: SSH2_MSG_KEX_ECDH_REPLY received
`

// unknownKey is a check that stopped because known_hosts has no record of the key.
var unknownKey = transcriptPrefix + kexEd25519 + `debug1: Server host key: ssh-ed25519 ` + fpEd25519 + `
No ED25519 host key is known for [127.0.0.1]:2633 and you have requested strict checking.
Host key verification failed.
`

// changedKey is a check that stopped because the key differs from the recorded one.
var changedKey = transcriptPrefix + kexEd25519 + `debug1: Server host key: ssh-ed25519 ` + fpEd25519 + `
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
Host key for [127.0.0.1]:2633 has changed and you have requested strict checking.
Host key verification failed.
`

// revokedKey is a check that stopped because the key is marked revoked.
var revokedKey = transcriptPrefix + kexEd25519 + `debug1: Server host key: ssh-ed25519 ` + fpEd25519 + `
@       WARNING: REVOKED HOST KEY DETECTED!               @
The ED25519 host key for [127.0.0.1]:2633 is marked as revoked.
ED25519 host key for [127.0.0.1]:2633 was revoked and you have requested strict checking.
Host key verification failed.
`

// The injected transcripts below are what a server sends before its key exchange reply, with
// the trust lines of a passing check written into its text. A probe that accepted any of them
// would send a password to the server.
var injectedTrust = "debug1: kex: host key algorithm: ssh-ed25519\n" +
	"debug1: Server host key: ssh-ed25519 " + fpAttacker + "\n" +
	"debug1: Host '[127.0.0.1]:2640' is known and matches the ED25519 host key.\n" +
	"debug1: Authentications that can continue: password\n"

func TestProbeRefusesEveryStateWithoutTrustAndNamesTheFingerprint(t *testing.T) {
	tests := []struct {
		name       string
		transcript string
		outcome    Outcome
		fp         string
	}{
		{"unknown key", unknownKey, HostKeyUnknown, fpEd25519},
		{"changed key", changedKey, HostKeyChanged, fpEd25519},
		{"revoked key", revokedKey, HostKeyRevoked, fpEd25519},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, r := parseHostTrust([]byte(tc.transcript), 255)
			if ok {
				t.Fatal("a refused host key was trusted")
			}
			if r.Outcome != tc.outcome || r.HostKey != tc.fp {
				t.Fatalf("result = %+v, want outcome %q and fingerprint %q", r, tc.outcome, tc.fp)
			}
		})
	}
}

// A server that refuses the connection at the identification stage leaves the client's reset
// line as the only output. That is named as a closed connection, not as a malformed record.
func TestProbeNamesAConnectionTheServerClosedBeforeItsKey(t *testing.T) {
	closed := "debug1: Connecting to 127.0.0.1 [127.0.0.1] port 2703.\ndebug1: Connection established.\ndebug1: kex_exchange_identification: banner line 0: Not allowed at this time\nkex_exchange_identification: read: Connection reset by peer\nConnection reset by 127.0.0.1 port 2703\n"
	_, ok, r := parseHostTrust([]byte(closed), 255)
	if ok || r.Outcome != TransportFailure || !strings.Contains(r.Detail, "closed the connection before it named its host key") {
		t.Fatalf("a closed connection = %+v (trusted %v), want a transport failure that names the close", r, ok)
	}
}

// A server that cannot be reached, or a name that does not resolve, leaves the client's own
// line as the only output. Each is named as such, not as a malformed record.
func TestProbeNamesAnUnreachableServerOrName(t *testing.T) {
	cases := map[string]string{
		"refused":      "debug1: connect to address 127.0.0.1 port 1: Connection refused\nssh: connect to host 127.0.0.1 port 1: Connection refused\n",
		"no name":      "ssh: Could not resolve hostname probe.invalid: Name or service not known\n",
		"no agreement": "Unable to negotiate with 127.0.0.1 port 2705: no matching host key type found. Their offer: ssh-mldsa44-ed25519@openssh.com\n",
	}
	want := map[string]string{"refused": "could not be reached", "no name": "could not be resolved", "no agreement": "could not agree"}
	for name, out := range cases {
		_, ok, r := parseHostTrust([]byte(out), 255)
		if ok || r.Outcome != TransportFailure || !strings.Contains(r.Detail, want[name]) {
			t.Errorf("%s = %+v (trusted %v), want a transport failure that says it %s", name, r, ok, want[name])
		}
	}
}

// Each malformed transcript lacks one piece of OpenSSH's evidence, or has it out of order, or
// ends with an unexpected status. The host-key line alone is never enough.
func TestProbeRefusesIncompleteOrOutOfOrderEvidence(t *testing.T) {
	withoutAuth := strings.Replace(trustedEd25519, transcriptAuthPhase, "", 1)
	withoutPresented := strings.Replace(trustedEd25519, "debug1: Server host key: ssh-ed25519 "+fpEd25519+"\n", "", 1)
	withoutAlgorithm := strings.Replace(trustedEd25519, "debug1: kex: host key algorithm: ssh-ed25519\n", "", 1)
	authBeforeMatch := strings.Replace(trustedEd25519, "debug1: Host '[127.0.0.1]:2633' is known and matches the ED25519 host key.\n", "debug1: Authentications that can continue: password\n", 1)
	tests := []struct {
		name       string
		transcript string
		status     int
	}{
		{"host key matched with no authentication phase", withoutAuth, 255},
		{"authentication phase with no presented key", withoutPresented, 255},
		{"no algorithm line", withoutAlgorithm, 255},
		{"authentication line before the match", authBeforeMatch, 255},
		{"clean transcript with a zero exit status", trustedEd25519, 0},
		{"no output at all", "", 255},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok, _ := parseHostTrust([]byte(tc.transcript), tc.status); ok {
				t.Fatal("incomplete evidence was trusted")
			}
		})
	}
}

// Text a server writes before its key exchange reply reaches the output through three
// channels. Each one must refuse, because it carries lines that would otherwise pass.
func TestProbeRefusesTrustInjectedThroughEachServerChannel(t *testing.T) {
	tests := []struct {
		name       string
		transcript string
	}{
		{
			"disconnect message, printed on a line that is not a debug line",
			transcriptPrefix + "Received disconnect from 127.0.0.1 port 2640:2: \n" + injectedTrust,
		},
		{
			"debug message, printed as a Remote line",
			transcriptPrefix + "debug1: Remote: \n" + injectedTrust,
		},
		{
			"negotiation failure, whose offer carries the server's names",
			transcriptPrefix + "Unable to negotiate with 127.0.0.1 port 2641: no matching key exchange method found. Their offer: curve25519-sha256\n" + injectedTrust,
		},
		{
			"certificate key ID, printed on the presented-key line, followed by the genuine failure",
			transcriptPrefix + "debug1: kex: host key algorithm: ssh-ed25519-cert-v01@openssh.com\n" +
				"debug1: Server host certificate: ssh-ed25519-cert-v01@openssh.com " + fpAttacker + ", serial 0 ID \"x\n" +
				"debug1: Host '[127.0.0.1]:2634' is known and matches the ED25519-CERT host certificate.\n" +
				"debug1: Authentications that can continue: password\" CA ssh-ed25519 SHA256:ua50z1HNJpTq7vDDnreY7Ga/viw valid forever\n" +
				"No ED25519-CERT host key is known for [127.0.0.1]:2634 and you have requested strict checking.\n" +
				"Host key verification failed.\n",
		},
		{
			"a second presented-key line, written after the genuine one",
			trustedEd25519 + "debug1: Server host key: ssh-ed25519 " + fpAttacker + "\n",
		},
		{
			"a second match line",
			trustedEd25519 + "debug1: Host '[127.0.0.1]:2633' is known and matches the ED25519 host key.\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, _ := parseHostTrust([]byte(tc.transcript), 255)
			if ok {
				t.Fatalf("injected trust was accepted: %+v", got)
			}
		})
	}
}

// A debug line from the server, and a non-debug line before the evidence, each refuse even when
// the evidence that follows is well formed.
func TestProbeRefusesAnyNonDebugLineBeforeTheMatch(t *testing.T) {
	for _, line := range []string{
		"Warning: something the client printed, not as a debug line\n",
		"debug1: Remote: a server debug message\n",
	} {
		transcript := transcriptPrefix + line + trustedEd25519[len(transcriptPrefix):]
		if _, ok, _ := parseHostTrust([]byte(transcript), 255); ok {
			t.Fatalf("a transcript with %q before the match was trusted", line)
		}
	}
}

func TestProbeArgsForceTheChecksAndOverrideNoKnownHostsSetting(t *testing.T) {
	args := probeArgs([]string{"-p", "2622", "-l", "tester", "--", "example.test"})
	for _, want := range []string{
		"-N", "LogLevel=DEBUG1", "BatchMode=yes", "StrictHostKeyChecking=yes",
		"PreferredAuthentications=none", "IdentityAgent=none", "ControlPath=none",
		"ClearAllForwardings=yes", "PermitLocalCommand=no", "ProxyCommand=none",
		"ProxyJump=none", "UpdateHostKeys=no",
		"KnownHostsCommand=none", "PKCS11Provider=none", "SecurityKeyProvider=none",
		"GSSAPIAuthentication=no", "ForkAfterAuthentication=no",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("probe arguments lack %q: %v", want, args)
		}
	}
	for _, banned := range []string{
		"UserKnownHostsFile", "GlobalKnownHostsFile", "RevokedHostKeys", "CheckHostIP",
	} {
		for _, a := range args {
			if strings.HasPrefix(a, banned) {
				t.Errorf("probe arguments override %s: %v", banned, args)
			}
		}
	}
	if args[len(args)-1] != "example.test" {
		t.Errorf("the destination is not last: %v", args)
	}
}

// A revoked key is refused under its own name. A changed key is a different fact, and a finding
// that says the key changed would send the user to the wrong fix.
func TestRevokedKeyHasItsOwnOutcome(t *testing.T) {
	revoked := "debug1: kex: host key algorithm: ssh-ed25519\n" +
		"debug1: Server host key: ssh-ed25519 " + fpEd25519 + "\n" +
		"Host key ED25519 " + fpEd25519 + " revoked by file /etc/ssh/revoked\n" +
		"Host key verification failed.\n"
	_, ok, r := parseHostTrust([]byte(revoked), 255)
	if ok || r.Outcome != HostKeyRevoked {
		t.Fatalf("a revoked key = %q (trusted %v), want %q", r.Outcome, ok, HostKeyRevoked)
	}
}
