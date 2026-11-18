//go:build unix

package sshverify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeCanaryClient is a client that answers the canary's probes the way OpenSSH does,
// except for the one behaviour named in broken. It keys each answer on the probe's
// configuration file, so each probe is exercised on its own.
func fakeCanaryClient(t *testing.T, broken string) string {
	t.Helper()
	return writeFakeClient(t, fakeCanaryScript(broken))
}

// writeFakeClient writes an executable fake client with the given script text.
func writeFakeClient(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- the test writes an executable fake ssh client on purpose
		t.Fatal(err)
	}
	return path
}

// fakeCanaryScript is the script text of a client that answers every probe correctly,
// except for the one behaviour named in broken.
func fakeCanaryScript(broken string) string {
	return `#!/bin/sh
BROKEN="` + broken + `"
cfg=""
prev=""
last=""
for a in "$@"; do
  if [ "$prev" = "-F" ]; then cfg="$a"; fi
  prev="$a"
  last="$a"
done
# Every file read is announced, and each Include is followed to its own includes. A
# client that stops following at the first level is the include-announcement break.
walk() {
  echo "debug1: Reading configuration data $1" >&2
  for i in $(sed -n 's/^Include //p' "$1"); do
    if [ "$BROKEN" = include-announcement ] && [ "$2" -ge 1 ]; then continue; fi
    walk "$i" $(( $2 + 1 ))
  done
}
walk "$cfg" 0
case "$(cat "$cfg")" in
  *"Match !canonical exec"*) [ "$BROKEN" = canonical-positive ] || echo "debug1: Executing command: 'true'" >&2 ;;
  *"Match canonical exec"*) [ "$BROKEN" = canonical-exec ] && echo "debug1: Executing command: 'true'" >&2 ;;
  *"Match host canary exec"*) echo "debug1: Executing command: 'true'" >&2 ;;
esac
case "$(cat "$cfg")" in
  *"ProxyJump 127.0.0.2"*) [ "$BROKEN" = proxyjump-positive ] || echo "proxyjump [127.0.0.2]" ;;
  *"ProxyJump none"*) [ "$BROKEN" = proxyjump ] && echo "proxyjump bastion" ;;
esac
case "$(cat "$cfg")" in
  *"KnownHostsCommand touch"*)
    echo "knownhostscommand touch x"
    if [ "$BROKEN" = knownhostscommand ]; then
      sentinel=$(sed -n 's/.*KnownHostsCommand touch //p' "$cfg"); touch "$sentinel"
    fi ;;
  *"KnownHostsCommand none"*) echo "knownhostscommand none" ;;
esac
case "$(cat "$cfg")" in
  *'User ${NETDOC_CANARY_VAR}u'*)
    if [ "$BROKEN" = environment ]; then echo 'user ${netdoc_canary_var}u'; else echo "user alphau"; fi ;;
esac
hn="127.0.0.1"
case "$(cat "$cfg")" in
  *'HostName ${NETDOC_CANARY_VAR}.example'*)
    hn='${netdoc_canary_var}.example'
    if [ "$BROKEN" = environment-literal ]; then echo "identityfile alpha/k"; else echo 'identityfile ${NETDOC_CANARY_VAR}/k'; fi ;;
  *'Host ${NETDOC_CANARY_VAR}'*)
    if [ "$BROKEN" = environment-host ]; then hn="127.0.0.9"; else hn="$last"; fi ;;
esac
case "$(cat "$cfg")" in
  *"CanonicalizeHostname yes"*)
    if [ "$BROKEN" = canonicalizehostname ] || [ "$BROKEN" = canonicalizehostname-positive ]; then echo "canonicalizehostname false"; else echo "canonicalizehostname true"; fi ;;
  *)
    if [ "$BROKEN" = canonicalizehostname ]; then echo "canonicalizehostname true"; else echo "canonicalizehostname false"; fi ;;
esac
echo "hostname $hn"
exit 0
`
}

// A client that answers every probe correctly passes the canary.
func TestCanaryPassesAClientThatAnswersEveryProbe(t *testing.T) {
	if err := ensureCanary(context.Background(), fakeCanaryClient(t, "")); err != nil {
		t.Fatalf("a correct client failed the canary: %v", err)
	}
}

// Each positive and negative control is shown to refuse the client that breaks it, and
// the refusal names the probe. Each break is a different way the client could be wrong.
func TestCanaryNamesTheProbeThatFails(t *testing.T) {
	cases := []struct{ broken, probe string }{
		{"canonical-exec", probeCanonicalExec},
		{"canonical-positive", probeCanonicalExec},
		{"proxyjump", probeProxyJump},
		{"proxyjump-positive", probeProxyJump},
		{"knownhostscommand", probeKnownHostsCommand},
		{"canonicalizehostname", probeCanonicalize},
		{"canonicalizehostname-positive", probeCanonicalize},
		{"include-announcement", probeIncludeAnnounce},
		{"environment", probeEnvironment},
		{"environment-literal", probeEnvironment},
		{"environment-host", probeEnvironment},
	}
	for _, c := range cases {
		t.Run(c.broken, func(t *testing.T) {
			err := ensureCanary(context.Background(), fakeCanaryClient(t, c.broken))
			if err == nil || !strings.Contains(err.Error(), `"`+c.probe+`"`) {
				t.Fatalf("a client broken as %q returned %v; want a refusal naming probe %q", c.broken, err, c.probe)
			}
		})
	}
}

// A canary that runs out of its own budget is not a verdict on the client, so it is not
// kept: the next read with the same client runs the probes again. A caller that has no
// deadline of its own must not turn a slow first run into a permanent refusal.
func TestCanaryTimeoutIsNotKept(t *testing.T) {
	flag := filepath.Join(t.TempDir(), "slow")
	if err := os.WriteFile(flag, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	slowFirst := "#!/bin/sh\nif [ -e '" + flag + "' ]; then sleep 5; fi\n" + fakeCanaryScript("")[len("#!/bin/sh\n"):]
	client := writeFakeClient(t, slowFirst)
	saved := resolveTimeout
	t.Cleanup(func() { resolveTimeout = saved })

	// The first run's budget is short enough that its first probe cannot finish; the
	// second run gets the normal budget, so a healthy client is not failed by a short one.
	resolveTimeout = 300 * time.Millisecond
	if err := ensureCanary(context.Background(), client); err == nil {
		t.Fatal("a canary that ran out of its budget reported a pass")
	}
	resolveTimeout = saved
	if err := os.Remove(flag); err != nil {
		t.Fatal(err)
	}
	if err := ensureCanary(context.Background(), client); err != nil {
		t.Fatalf("a timed-out canary was kept, so a client that now answers was refused: %v", err)
	}
}
