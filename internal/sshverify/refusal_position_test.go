package sshverify

import (
	"strings"
	"testing"
)

// The refusal named for a transcript comes only from the decision line OpenSSH prints right before
// its final line. Server text elsewhere in the output can repeat any of the words, and must not
// create or suppress a label.

// A server banner that reads like a changed-key warning, on a trusted host, is not a changed key. The
// check is refused as a transport failure, and the banner's words name nothing.
func TestBannerNamingAChangedOrRevokedKeyNamesNothing(t *testing.T) {
	base := fixture(t, "trust-plain")
	for _, banner := range []string{
		"REMOTE HOST IDENTIFICATION HAS CHANGED: contact the administrator",
		"Violators will have access revoked.",
		"Host key verification failed.",
	} {
		edited := strings.Replace(base, "Permission denied", banner+"\nPermission denied", 1)
		_, ok, r := parseHostTrust([]byte(edited), 255)
		if ok {
			t.Fatalf("a banner made the check trust a host: %+v", r)
		}
		if r.Outcome == HostKeyChanged || r.Outcome == HostKeyRevoked {
			t.Fatalf("banner %q was named %q (%s)", banner, r.Outcome, r.Detail)
		}
	}
}

// Text the server sends before any key exchange, such as a disconnect message, names no key.
func TestPreKeyExchangeDisconnectNamesNoKey(t *testing.T) {
	transcript := "debug1: Reading configuration data /etc/ssh/ssh_config\n" +
		"Received disconnect from 127.0.0.1 port 22:11: REMOTE HOST IDENTIFICATION HAS CHANGED\n" +
		"Connection closed by 127.0.0.1 port 22\n"
	_, ok, r := parseHostTrust([]byte(transcript), 255)
	if ok || r.Outcome == HostKeyChanged || r.Outcome == HostKeyRevoked {
		t.Fatalf("a pre-KEX disconnect was named %q (trusted %v, %s)", r.Outcome, ok, r.Detail)
	}
}

// A genuine revocation is named even when a key ID earlier in the output forges a changed-key line.
func TestGenuineRevocationIsNamedDespiteAForgedChangedLine(t *testing.T) {
	base := fixture(t, "unknown-plain")
	// The key ID text that downgraded a revoked key to a changed one: the warning's own words, written
	// into the transcript before the genuine decision.
	for _, forgedLine := range []string{
		"Host key for [127.0.0.1]:PORT has changed and you have requested strict checking.",
		"REMOTE HOST IDENTIFICATION HAS CHANGED!",
	} {
		forged := after(t, base, "debug1: Server host key:", forgedLine)
		revoked := strings.Replace(forged,
			"No ED25519 host key is known for [127.0.0.1]:PORT and you have requested strict checking.",
			"ED25519 host key for [127.0.0.1]:PORT was revoked and you have requested strict checking.", 1)
		if revoked == forged {
			t.Fatal("the test did not place the revoked decision")
		}
		_, ok, r := parseHostTrust([]byte(revoked), 255)
		if ok || r.Outcome != HostKeyRevoked {
			t.Fatalf("forged %q: outcome = %q (trusted %v, %s), want host key revoked", forgedLine, r.Outcome, ok, r.Detail)
		}
	}
}

// A forged decision line that is not the one before the final line names nothing; the genuine
// decision before the final line decides.
func TestOnlyTheDecisionBeforeTheFinalLineNamesTheKey(t *testing.T) {
	base := fixture(t, "unknown-plain")
	edited := after(t, base, "debug1: Server host key:", "Host key for [127.0.0.1]:PORT has changed and you have requested strict checking.")
	_, ok, r := parseHostTrust([]byte(edited), 255)
	if ok || r.Outcome != HostKeyUnknown {
		t.Fatalf("outcome = %q (trusted %v, %s), want host key unknown from the genuine decision", r.Outcome, ok, r.Detail)
	}
}

// A decision line with no final line after it names no key: the client did not finish its refusal.
func TestDecisionWithoutTheFinalLineNamesNoKey(t *testing.T) {
	base := fixture(t, "changed-plain")
	cut := strings.TrimSuffix(base, "Host key verification failed.\n")
	if cut == base {
		t.Fatal("the fixture does not end with the final line")
	}
	_, ok, r := parseHostTrust([]byte(cut), 255)
	if ok || r.Outcome == HostKeyChanged || r.Outcome == HostKeyRevoked {
		t.Fatalf("a decision with no final line was named %q (trusted %v, %s)", r.Outcome, ok, r.Detail)
	}
}

// OpenSSH names a key revoked by a revocation file on its own decision line.
func TestRevocationByFileIsNamed(t *testing.T) {
	base := fixture(t, "unknown-plain")
	revoked := strings.Replace(base,
		"No ED25519 host key is known for [127.0.0.1]:PORT and you have requested strict checking.",
		"Host key ED25519 SHA256:S0M2cw8ALfnb9uBdT89f36goG85OodHdGtf+071MOyo revoked by file /tmp/revoked.krl", 1)
	_, ok, r := parseHostTrust([]byte(revoked), 255)
	if ok || r.Outcome != HostKeyRevoked {
		t.Fatalf("outcome = %q (trusted %v, %s), want host key revoked", r.Outcome, ok, r.Detail)
	}
}
