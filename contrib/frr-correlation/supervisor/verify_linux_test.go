//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A process that is exiting loses its namespaces a moment before it becomes a
// zombie. The read fails while the leader still looks running, and the failure
// must not be blamed on the namespaces: the child left, so the launch failed.
func TestChildLeavingWhileItsNamespacesAreUnreadableIsALaunchFailure(t *testing.T) {
	base := openFDs(t)
	f := &faults{settle: 2 * time.Second}
	f.identity = func(pidfd int) (Identity, error) {
		time.AfterFunc(10*time.Millisecond, func() { _ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0) })
		return Identity{}, ErrIdentityMismatch
	}
	n := newFaultNamespace(t, f)
	start := time.Now()
	_, err := n.Start(context.Background(), quickOptions(t))
	if !errors.Is(err, ErrLaunchFailed) || errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("got %v, want ErrLaunchFailed", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Start took %v, the settle wait should end when the exit shows", d)
	}
	if got := registered(n); got != 0 {
		t.Fatalf("%d children registered after a clean stop", got)
	}
	recovered(t, f, n, base)
}

// A leader that stays alive and unreadable is a real mismatch, not an exit. It
// is refused after the settle time, stopped and reaped.
func TestRunningChildWithUnreadableNamespacesIsAMismatch(t *testing.T) {
	base := openFDs(t)
	f := &faults{settle: 30 * time.Millisecond}
	f.identity = func(int) (Identity, error) { return Identity{}, ErrIdentityMismatch }
	n := newFaultNamespace(t, f)
	_, err := n.Start(context.Background(), quickOptions(t))
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("got %v, want ErrIdentityMismatch", err)
	}
	if got := registered(n); got != 0 {
		t.Fatalf("%d children registered after a clean stop", got)
	}
	recovered(t, f, n, base)
}
