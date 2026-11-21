//go:build integration

package remote

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBatchOpensNoForwarding: the user's configuration can set local, dynamic, and remote port
// forwardings. A batch session must open none of them. A local forwarding is a listener other
// local users can reach. A remote forwarding is a listener on the diagnosed host, which can
// reach the user's local service through this session. The control shows the interactive
// transport opens all three, and the remote reaches the local banner through the remote one.
func TestBatchOpensNoForwarding(t *testing.T) {
	lab := newBatchLab(t)
	target, banner := localBanner(t)
	lp, dp, rp := freeLoopbackPort(t), freeLoopbackPort(t), freeLoopbackPort(t)
	listeners := filepath.Join(lab.dir, "listeners")
	reached := filepath.Join(lab.dir, "reached")
	// The worker runs under bash for /dev/tcp. It records which of the three ports listen
	// (state 0A in /proc/net/tcp), then connects to the remote one and keeps what comes back.
	worker := lab.scriptWith(t, "fwd-worker", "/bin/bash", fmt.Sprintf(`check() { grep -qi ":$(printf '%%04X' "$1") 00000000:0000 0A" /proc/net/tcp && echo "$1 listening" || echo "$1 none"; }
{ check %d; check %d; check %d; } > %s
if exec 3<>/dev/tcp/127.0.0.1/%d 2>/dev/null; then head -c 64 <&3 > %s; exec 3>&-; fi
dd bs=1 count=%d of=%s 2>/dev/null
cat %s
`, lp, dp, rp, listeners, rp, reached, len(lab.body), filepath.Join(lab.dir, "worker-request"),
		filepath.Join(lab.dir, "response.json")))
	lab.configure(t, lab.known, "", fmt.Sprintf(
		"  LocalForward 127.0.0.1:%d %s\n  DynamicForward 127.0.0.1:%d\n  RemoteForward 127.0.0.1:%d %s", lp, target, dp, rp, target))

	// Control: the interactive transport opens the forwardings, and the remote reaches the banner.
	_ = lab.run(t, false, worker)
	requireForwardings(t, listeners, reached, banner, true)
	os.Remove(listeners)
	os.Remove(reached)

	err := lab.run(t, true, worker)
	lab.requireWorkerGotRequest(t, err)
	requireForwardings(t, listeners, reached, banner, false)
}

// requireForwardings checks the worker's record. With open, every port must listen and the
// banner must reach the remote. Without it, nothing may listen and the banner must not reach it.
func requireForwardings(t *testing.T, listeners, reached, banner string, open bool) {
	t.Helper()
	b, _ := os.ReadFile(listeners)
	want := " none"
	if open {
		want = " listening"
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasSuffix(line, want) {
			t.Fatalf("forwarding state %q; want every port to be%s", line, want)
		}
	}
	got, _ := os.ReadFile(reached)
	if open != strings.Contains(string(got), banner) {
		t.Fatalf("remote reached the local service through the remote forwarding = %v, want %v (read %q)",
			!open, open, got)
	}
}

// localBanner runs a local service that answers every connection with a fixed banner.
func localBanner(t *testing.T) (addr, banner string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	banner = "local-service-banner"
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(banner))
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), banner
}
