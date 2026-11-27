//go:build integration

package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBatchOpensNoForwarding: the user's configuration can set local, dynamic, and remote port
// forwardings. A batch session must open none of them. A local forwarding is a listener other
// local users can reach. A remote forwarding is a listener on the diagnosed host, which can
// reach the user's local service through this session. The control shows the interactive
// transport opens all three, and the remote reaches the local banner through the remote one.
func TestBatchOpensNoForwarding(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the listener probe reads /proc/net/tcp, which only Linux has")
	}
	t.Run("Scenario", runNoForwardingScenario)
	t.Run("OccupiedPortFailsPromptly", occupiedPortFailsPromptly)
	t.Run("SilentListenerIsBoundedAfterPreflight", silentListenerIsBounded)
	t.Run("UnintendedForwardingIsDetected", unintendedForwardingIsDetected)
	t.Run("OccupiedPortFailsScenarioPromptly", occupiedPortFailsScenarioPromptly)
}

// forwardingReadBound bounds the worker's read from the remote forwarding. It is far below the
// operation ceiling, so a silent listener on that port ends the read, not the run.
const forwardingReadBound = 10

// forwardingOccupiedEnv is set only by the test that runs the scenario as a child process. The child
// then starts with its remote forwarding port held by a silent listener, which is the case the
// preflight must catch.
const forwardingOccupiedEnv = "NETDOC_FORWARDING_OCCUPIED"

// runNoForwardingScenario is the check itself, with the control first.
func runNoForwardingScenario(t *testing.T) {
	lab := newBatchLab(t)
	target, banner := localBanner(t)
	lp, dp, rp := freeLoopbackPort(t), freeLoopbackPort(t), freeLoopbackPort(t)
	if os.Getenv(forwardingOccupiedEnv) != "" {
		rp = silentListener(t).Addr().(*net.TCPAddr).Port
	}
	// A port another process holds would make the listener check report that process as SSH's
	// forwarding. The preflight fails the run at once, with the port named.
	if err := forwardingPortsFree(lp, dp, rp); err != nil {
		t.Fatal(err)
	}
	listeners := filepath.Join(lab.dir, "listeners")
	reached := filepath.Join(lab.dir, "reached")
	worker := lab.scriptWith(t, "fwd-worker", "/bin/bash", forwardingWorker(lp, dp, rp, listeners, reached)+
		fmt.Sprintf("dd bs=1 count=%d of=%s 2>/dev/null\ncat %s\n", len(lab.body),
			filepath.Join(lab.dir, "worker-request"), filepath.Join(lab.dir, "response.json")))
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

// forwardingWorker is the part of the worker that records the forwarding ports and reads the remote
// one. The read is bounded by forwardingReadBound seconds, so a listener that accepts and never
// writes ends it. The read is a bash builtin, so no external program is needed for the bound.
func forwardingWorker(lp, dp, rp int, listeners, reached string) string {
	return fmt.Sprintf(`check() { grep -qi ":$(printf '%%04X' "$1") 00000000:0000 0A" /proc/net/tcp && echo "$1 listening" || echo "$1 none"; }
{ check %d; check %d; check %d; } > %s
if exec 3<>/dev/tcp/127.0.0.1/%d 2>/dev/null; then IFS= read -r -t %d -N 64 reply <&3; printf '%%s' "$reply" > %s; exec 3>&-; fi
`, lp, dp, rp, listeners, rp, forwardingReadBound, reached)
}

// forwardingPortsFree reports the first of the ports that another process already holds on the
// loopback address. It is only a preflight: a process can take a port after this check, which is why
// the worker's read is bounded as well.
func forwardingPortsFree(ports ...int) error {
	for _, p := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			return fmt.Errorf("forwarding port %d is already in use, so the forwarding check cannot tell its listener from SSH's: %w", p, err)
		}
		_ = ln.Close()
	}
	return nil
}

// silentListener holds a loopback port. It accepts every connection and never writes, and it is
// closed when the test ends.
func silentListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var held []net.Conn // kept open: a closed connection would end the silence
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
		}
	}()
	return ln
}

// occupiedPortFailsPromptly: a silent listener holds a forwarding port. The preflight must report that
// port at once, and must not wait for the operation ceiling.
func occupiedPortFailsPromptly(t *testing.T) {
	port := silentListener(t).Addr().(*net.TCPAddr).Port
	start := time.Now()
	err := forwardingPortsFree(freeLoopbackPort(t), port)
	if err == nil {
		t.Fatal("a port held by another process passed the preflight")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("the preflight did not name the occupied port %d: %v", port, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("the preflight took %v to report an occupied port", elapsed)
	}
}

// silentListenerIsBounded: the preflight can pass, and another process can take the forwarding port
// afterwards. The worker's read must still end after forwardingReadBound seconds, with nothing read.
func silentListenerIsBounded(t *testing.T) {
	port := silentListener(t).Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	listeners := filepath.Join(dir, "listeners")
	reached := filepath.Join(dir, "reached")
	script := forwardingWorker(freeLoopbackPort(t), freeLoopbackPort(t), port, listeners, reached)
	ctx, cancel := context.WithTimeout(context.Background(), (forwardingReadBound+20)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash")
	cmd.Stdin = strings.NewReader(script)
	start := time.Now()
	_ = cmd.Run()
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		t.Fatalf("the worker was still blocked at the deadline (%v): the read is unbounded", elapsed)
	}
	if elapsed > (forwardingReadBound+5)*time.Second {
		t.Fatalf("the worker ended after %v, want about %d seconds", elapsed, forwardingReadBound)
	}
	if got, _ := os.ReadFile(reached); len(got) > 0 {
		t.Fatalf("the worker read %q from a silent listener", got)
	}
}

// requireForwardings checks the worker's record. With open, every port must listen and the banner
// must reach the remote. Without it, nothing may listen and the banner must not reach it.
func requireForwardings(t *testing.T, listeners, reached, banner string, open bool) {
	t.Helper()
	if msg := forwardingViolation(listeners, reached, banner, open); msg != "" {
		t.Fatal(msg)
	}
}

// forwardingViolation returns the first way the worker's record differs from the expected state, or
// the empty string when it matches.
func forwardingViolation(listeners, reached, banner string, open bool) string {
	b, _ := os.ReadFile(listeners)
	want := " none"
	if open {
		want = " listening"
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if !strings.HasSuffix(line, want) {
			return fmt.Sprintf("forwarding state %q; want every port to be%s", line, want)
		}
	}
	got, _ := os.ReadFile(reached)
	if open != strings.Contains(string(got), banner) {
		return fmt.Sprintf("remote reached the local service through the remote forwarding = %v, want %v (read %q)", !open, open, got)
	}
	return ""
}

// unintendedForwardingIsDetected: the check must report a forwarding that a batch session opened, and
// must accept the expected state. The assertion is pure, so these cases need no SSH.
func unintendedForwardingIsDetected(t *testing.T) {
	dir := t.TempDir()
	listeners := filepath.Join(dir, "listeners")
	reached := filepath.Join(dir, "reached")
	write := func(state, got string) {
		if err := os.WriteFile(listeners, []byte(state), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(reached, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const banner = "local-service-banner"
	write("1 listening\n2 none\n3 none\n", "")
	if forwardingViolation(listeners, reached, banner, false) == "" {
		t.Fatal("a listening port in a batch session was not reported")
	}
	write("1 none\n2 none\n3 none\n", banner)
	if forwardingViolation(listeners, reached, banner, false) == "" {
		t.Fatal("the banner reaching the remote in a batch session was not reported")
	}
	write("1 listening\n2 listening\n3 listening\n", banner)
	if msg := forwardingViolation(listeners, reached, banner, true); msg != "" {
		t.Fatalf("the expected interactive state was reported: %s", msg)
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

// occupiedPortFailsScenarioPromptly runs the scenario as a child with its remote forwarding port held
// by another process. The child must fail at the preflight, naming the port, within seconds. Without
// the preflight it would run the control and wait for the worker's read bound.
func occupiedPortFailsScenarioPromptly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBatchOpensNoForwarding$/^Scenario$", "-test.count=1") // #nosec G204 -- the test's own binary, with fixed arguments
	cmd.Env = append(os.Environ(), forwardingOccupiedEnv+"=1")
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if ctx.Err() != nil {
		t.Fatalf("the scenario was still running at the deadline (%v): it did not fail at the preflight", elapsed)
	}
	if err == nil {
		t.Fatalf("the scenario passed with its forwarding port held by another process:\n%s", out)
	}
	if !strings.Contains(string(out), "already in use") {
		t.Fatalf("the scenario failed, but not at the preflight:\n%s", out)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the scenario took %v to fail at the preflight", elapsed)
	}
}
