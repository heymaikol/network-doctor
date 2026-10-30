//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A watcher whose waitid fails has not seen the child exit. Done must stay open
// while the child runs, and Stop must still prove the exit itself.
func TestUnexpectedWaitErrorIsNotReportedAsAnExit(t *testing.T) {
	base := openFDs(t)
	f := &faults{gate: make(chan struct{})}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t)) // the watcher is parked, so verify reads the pidfd alone
	if err != nil {
		t.Fatal(err)
	}
	f.failWatch.Store(true)
	f.open()
	select {
	case <-c.Done():
		t.Fatal("Done closed although the child is still running")
	case <-time.After(300 * time.Millisecond):
	}
	if st := procState(c.PID()); st == 'Z' || st == 0 {
		t.Fatalf("child is in state %q, want it running", st)
	}
	st, err := c.Stop(context.Background())
	if err != nil || st.Signal != syscall.SIGTERM || st.Escalated {
		t.Fatalf("Stop: %+v %v", st, err)
	}
	recovered(t, f, n, base)
}

// Losing the watcher while a child starts is not a launch failure: the child
// did not exit. It is stopped and the namespace stays usable.
func TestWatcherLostDuringStartIsNotALaunchFailure(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	f.failWatch.Store(true)
	_, err := n.Start(context.Background(), quickOptions(t))
	if errors.Is(err, ErrLaunchFailed) || !errors.Is(err, ErrObservationLost) {
		t.Fatalf("got %v, want ErrObservationLost and not ErrLaunchFailed", err)
	}
	if got := registered(n); got != 0 {
		t.Fatalf("%d children registered after a clean stop", got)
	}
	f.clear()
	if _, err := n.Identity(); err != nil {
		t.Fatalf("namespace unusable after a cleanly stopped child: %v", err)
	}
	recovered(t, f, n, base)
}

// The pidfd number must stay reserved while the watcher can still read it, or a
// reused number could be waited on by mistake. The watcher is parked, so Stop
// proves the exit and reaps by itself, and then has to hold the pidfd open until
// the watcher ends.
func TestStopWaitsForTheWatcherBeforeClosingThePidfd(t *testing.T) {
	base := openFDs(t)
	f := &faults{gate: make(chan struct{})}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		st  ExitStatus
		err error
	}
	stopped := make(chan result, 1)
	go func() {
		st, err := c.Stop(context.Background())
		stopped <- result{st, err}
	}()
	select {
	case r := <-stopped:
		t.Fatalf("Stop returned while the watcher still held the pidfd: %+v %v", r.st, r.err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := unix.FcntlInt(uintptr(c.pidfd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("pidfd %d closed under the watcher: %v", c.pidfd, err)
	}
	f.open() // the watcher now waits on a reaped child, which fails and ends it
	r := <-stopped
	if r.err != nil || r.st.Signal != syscall.SIGTERM {
		t.Fatalf("Stop: %+v %v", r.st, r.err)
	}
	select {
	case <-c.Lost():
	default:
		t.Fatal("the watcher had not ended when Stop returned")
	}
	recovered(t, f, n, base)
}
