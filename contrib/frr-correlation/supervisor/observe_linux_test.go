//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
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
