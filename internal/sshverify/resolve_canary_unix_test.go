//go:build unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCanaryClient is a client that answers the canary's five probes the way OpenSSH
// does, except for the probe named in broken, which it answers wrongly. It keys each
// answer on the probe's configuration file, so each probe is tested on its own.
func fakeCanaryClient(t *testing.T, broken string) string {
	t.Helper()
	const head = `#!/bin/sh
cfg=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-F" ]; then cfg="$a"; fi
  prev="$a"
done
echo "debug1: Reading configuration data $cfg" >&2
if grep -q 'canonical exec' "$cfg"; then
`
	const canonicalBody = `  echo "hostname 127.0.0.1"
  exit 0
fi
if grep -q 'ProxyJump none' "$cfg"; then
`
	const proxyBody = `  echo "hostname 127.0.0.1"
  exit 0
fi
if grep -q 'KnownHostsCommand' "$cfg"; then
  echo "knownhostscommand touch x"
  echo "hostname 127.0.0.1"
  exit 0
fi
if grep -q 'exec' "$cfg"; then
  echo "debug1: Executing command: true" >&2
fi
echo "hostname 127.0.0.1"
exit 0
`
	canonicalBreak := ""
	if broken == probeCanonicalExec {
		canonicalBreak = `  echo "debug1: Executing command: true" >&2` + "\n"
	}
	proxyBreak := ""
	if broken == probeProxyJumpNone {
		proxyBreak = `  echo "proxyjump bastion"` + "\n"
	}
	khcBreak := ""
	if broken == probeKnownHostsCommand {
		// This client runs the KnownHostsCommand during the read, which -G must not do.
		khcBreak = `  sentinel=$(sed -n 's/.*KnownHostsCommand touch //p' "$cfg"); touch "$sentinel"` + "\n"
	}
	script := head + canonicalBreak + canonicalBody + proxyBreak + proxyBody
	// KnownHostsCommand is answered after the proxy branch in proxyBody, so its break
	// is spliced into that branch.
	script = strings.Replace(script, `  echo "knownhostscommand touch x"`+"\n", `  echo "knownhostscommand touch x"`+"\n"+khcBreak, 1)
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- the test writes an executable fake ssh client on purpose
		t.Fatal(err)
	}
	return path
}

// A client that answers every probe correctly passes the canary.
func TestCanaryPassesAClientThatAnswersEveryProbe(t *testing.T) {
	if err := ensureCanary(context.Background(), fakeCanaryClient(t, "")); err != nil {
		t.Fatalf("a correct client failed the canary: %v", err)
	}
}

// Each probe is shown to refuse the client that breaks it, and the refusal names it.
func TestCanaryNamesTheProbeThatFails(t *testing.T) {
	for _, probe := range []string{probeCanonicalExec, probeProxyJumpNone, probeKnownHostsCommand} {
		t.Run(probe, func(t *testing.T) {
			err := ensureCanary(context.Background(), fakeCanaryClient(t, probe))
			if err == nil || !strings.Contains(err.Error(), `"`+probe+`"`) {
				t.Fatalf("a client that breaks %s returned %v; want a refusal naming that probe", probe, err)
			}
		})
	}
}
