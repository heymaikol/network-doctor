//go:build linux && netns_integration

package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/contrib/frr-correlation/supervisor"
	"golang.org/x/sys/unix"
)

// These tests run real children inside the supervisor's user and network
// namespaces. They import the supervisor in the test build only: the package
// itself must not depend on it.

func newNS(t *testing.T) *supervisor.Namespace {
	t.Helper()
	n, err := supervisor.NewNamespace(context.Background())
	if n != nil {
		t.Cleanup(func() {
			if err := n.Close(); err != nil {
				t.Errorf("namespace Close: %v", err)
			}
		})
	}
	if errors.Is(err, supervisor.ErrUnsupported) {
		unavailable(t, "rootless namespaces or pidfd namespace ioctls unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// run starts the test binary as a producer in the namespaces, waits for its
// leader to be proven exited and stopped, and returns the exit status.
func run(t *testing.T, n *supervisor.Namespace, env ...string) supervisor.ExitStatus {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.Start(context.Background(), supervisor.Options{Argv: []string{self}, Env: env})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-c.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("producer did not exit")
	}
	st, err := c.Stop(context.Background())
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return st
}

// The supervisor's Stop proves its leader reaped. A descendant that left the
// process group is outside that proof, and it can still hold the stream open.
// The lease is what sees it.
func TestStopSucceedsWhileADetachedWriterHoldsTheStream(t *testing.T) {
	for _, killFirst := range []bool{false, true} {
		name := map[bool]string{false: "writer alive", true: "writer killed"}[killFirst]
		t.Run(name, func(t *testing.T) {
			n := newNS(t)
			in := inboxFor(t, BGPD)
			path := filepath.Join(in.Path(), stream(BGPD))
			pidfile := filepath.Join(t.TempDir(), "pid")
			if st := run(t, n, "CAPTURE_HELPER=detach", "CAPTURE_FILE="+path, "CAPTURE_PIDFILE="+pidfile); st.Code != 0 || st.Escalated {
				t.Fatalf("producer exit %+v", st)
			}
			raw, err := os.ReadFile(pidfile) //nolint:gosec // G304: the path is this test's own TempDir.
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := strconv.Atoi(string(raw))
			t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
			state, _ := os.ReadFile("/proc/" + string(raw) + "/stat") //nolint:gosec // G304, G703: a /proc path built from a PID this test launched.
			if !strings.Contains(string(state), ") S ") && !strings.Contains(string(state), ") R ") {
				t.Fatalf("the detached writer is not running: %q", state)
			}
			if killFirst {
				if err := unix.Kill(pid, unix.SIGKILL); err != nil {
					t.Fatal(err)
				}
				waitForNoWriter(t, path)
				mustSeal(t, in)
				return
			}
			_, err = in.Seal(context.Background())
			refused(t, err, WriterPresent)
		})
	}
}

// KNOWN GAP, asserted so that it cannot be forgotten. Two producers share one
// mount namespace, one user and one process space, and each can name the
// other's inbox: through /proc/<pid>/environ, or in this test through its
// environment. The capture package cannot stop a producer that is trusted to run
// FRR from rewriting a sibling's stream before it is sealed. Per-producer mount
// and PID namespace confinement closes this, and when it lands this test must
// flip to assert the write is refused. Until then no caller may treat a
// Snapshot as evidence that the producer it names wrote it.
func TestKnownGapPeerProducerCanRewriteAnotherInbox(t *testing.T) {
	n := newNS(t)
	bgpd, zebra := inboxFor(t, BGPD), inboxFor(t, Zebra)
	target := put(t, bgpd, stream(BGPD), streamBody)
	_ = zebra // the peer would own this one; it needs only bgpd's path
	if st := run(t, n, "CAPTURE_HELPER=peerwrite", "CAPTURE_FILE="+target); st.Code != 0 {
		t.Fatalf("peer could not write another inbox, which would be a closed gap: %+v", st)
	}
	s := mustSeal(t, bgpd)
	if read(t, s) != forgedBody {
		t.Fatalf("gap test no longer demonstrates the gap: %q", read(t, s))
	}
}

// A producer in the namespaces cannot reach the memory of the collector process
// or the sealed bytes it holds. This is a property of the kernel's cross-user-
// namespace ptrace check, observed here on this kernel. It does not make the
// supervisor safe from a producer that escapes the user namespace.
func TestProducerCannotReachCollectorMemoryOrSnapshot(t *testing.T) {
	n := newNS(t)
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	s := mustSeal(t, in)
	out := filepath.Join(t.TempDir(), "out")
	if st := run(t, n, "CAPTURE_HELPER=probe", "CAPTURE_OUT="+out,
		"SUP_PID="+strconv.Itoa(os.Getpid()), "SUP_FD="+strconv.Itoa(int(s.f.Fd()))); st.Code != 0 {
		t.Fatalf("probe exit %+v", st)
	}
	raw, err := os.ReadFile(out) //nolint:gosec // G304: the path is this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, _ := strings.Cut(l, " ")
		got[k], _ = strconv.Atoi(v)
	}
	if got["visible"] != 0 || got["control-own-mem"] != 0 {
		t.Fatalf("controls failed, so the denials below prove nothing: %v", got)
	}
	for _, k := range []string{"mem-write", "mem-read", "snapshot-write", "snapshot-read", "ptrace"} {
		if e := unix.Errno(got[k]); e != unix.EACCES && e != unix.EPERM {
			t.Errorf("%s: errno %d (%v), want EACCES or EPERM", k, got[k], e)
		}
	}
	if read(t, s) != streamBody {
		t.Fatal("snapshot changed")
	}
}

// Capture descriptors are close-on-exec, so a producer starts with none of them
// and the supervisor's own inheritance check still passes while they are open.
func TestCaptureDescriptorsAreNotInherited(t *testing.T) {
	n := newNS(t)
	in := inboxFor(t, BGPD)
	put(t, in, stream(BGPD), streamBody)
	mustSeal(t, in)
	out := filepath.Join(t.TempDir(), "out")
	// The Go runtime keeps its own descriptor on the cgroup's cpu.max unless told
	// not to, and that one is not an inheritance.
	if st := run(t, n, "CAPTURE_HELPER=report", "CAPTURE_OUT="+out, "GODEBUG=containermaxprocs=0,updatemaxprocs=0"); st.Code != 0 {
		t.Fatalf("report exit %+v", st)
	}
	raw, err := os.ReadFile(out) //nolint:gosec // G304: the path is this test's own TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "fds" {
		t.Fatalf("child inherited descriptors: %q", raw)
	}
}

// Sealing and closing neither pin nor release a namespace.
func TestSealAndCloseDoNotTouchTheNamespace(t *testing.T) {
	n := newNS(t)
	before, err := n.Identity()
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbox(BGPD)
	if err != nil {
		unavailable(t, "%v", err)
	}
	put(t, in, stream(BGPD), streamBody)
	s, err := in.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := in.Close(); err != nil {
		t.Fatal(err)
	}
	if after, err := n.Identity(); err != nil || after != before {
		t.Fatalf("identity %+v then %+v (%v)", before, after, err)
	}
}
