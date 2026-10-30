//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// holderBound is how long a test waits for a call that must be bounded by the
// harness kill deadline of 200 ms. A call that is still running then is blocked,
// not slow.
const holderBound = 5 * time.Second

// finishesWithin runs fn and fails the test if it is still running after
// holderBound. On a timeout it runs rescue first, so the blocked call can finish
// and be joined instead of leaking into later tests.
func finishesWithin(t *testing.T, rescue, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
		return
	case <-time.After(holderBound):
	}
	rescue()
	select {
	case <-done:
	case <-time.After(holderBound):
		t.Log("the rescue did not unblock the call")
	}
	t.Fatalf("call still running after %v: it is waiting for a process that has not exited", holderBound)
}

// holderRunning requires the holder to be an unreaped process that is still
// alive, which is what a retry needs.
func holderRunning(t *testing.T, n *Namespace) {
	t.Helper()
	if n.holder == nil {
		t.Fatal("the holder handle was dropped although it was not reaped")
	}
	if got := n.sys.probe(n.holderFD); got != leaderRunning {
		t.Fatalf("holder in state %d, want running and unreaped", got)
	}
}

// A holder that does not exit after the signal must not block Close. Close
// returns ErrCleanupIncomplete, keeps the holder, its pidfd and the pins, and
// can be called again; once the signal gets through it finishes the job.
func TestCloseIsBoundedWhenTheHolderDoesNotExit(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	holderFD := n.holderFD // read now: release rewrites it while Close runs
	f.dropSignals.Store(true)
	rescue := func() { f.clear(); _ = unix.PidfdSendSignal(holderFD, unix.SIGKILL, nil, 0) }
	for i := range 2 {
		var err error
		finishesWithin(t, rescue, func() { err = n.Close() })
		if !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("Close %d: %v, want ErrCleanupIncomplete", i, err)
		}
		holderRunning(t, n)
		assertPinsHeld(t, n)
		assertUnusable(t, n)
	}
	recovered(t, f, n, base)
}

// The constructor releases a half-built namespace through the same path. When
// the holder will not exit, it returns the unusable namespace with the error
// instead of blocking, so the caller can retry.
func TestConstructorCleanupIsBoundedWhenTheHolderDoesNotExit(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	f.dropSignals.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var holderFD atomic.Int32
	holderFD.Store(-1)
	testHookAfterHolderStart = func(pidfd int) {
		holderFD.Store(int32(pidfd)) //nolint:gosec // G115: a descriptor number always fits in 32 bits.
		cancel()                     // retain notices the cancelled context and fails the constructor
	}
	defer func() { testHookAfterHolderStart = nil }()
	rescue := func() {
		f.clear()
		if fd := holderFD.Load(); fd >= 0 {
			_ = unix.PidfdSendSignal(int(fd), unix.SIGKILL, nil, 0)
		}
	}
	var n *Namespace
	var err error
	finishesWithin(t, rescue, func() { n, err = newNamespaceWith(ctx, f.sys()) })
	closeAtEnd(t, n, f.clear)
	if errors.Is(err, ErrUnsupported) {
		unavailable(t, "namespaces unavailable") // not the refusal under test
	}
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("got %v, want the cancellation joined with the cleanup failure", err)
	}
	if n == nil {
		t.Fatal("constructor dropped the holder handle together with its error")
	}
	holderRunning(t, n)
	assertPinsHeld(t, n)
	assertUnusable(t, n)
	recovered(t, f, n, base)
}

// Without a pidfd the holder is still ours by PID because it is unreaped, and
// its release is bounded the same way. The kernel with the namespace ioctls
// always has a pidfd, so this branch is reached by building the namespace by
// hand. Only the success path is tested: no process refuses SIGKILL here.
func TestHolderWithoutAPidfdIsReapedWithinTheBound(t *testing.T) {
	cmd := exec.Command(lookPath(t, "sleep"), "infinity") //nolint:gosec // G204: sleep comes from LookPath and the argument is constant.
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	n := &Namespace{holder: cmd, holderFD: -1, netFD: -1, userFD: -1, sys: realSys()}
	var err error
	finishesWithin(t, func() { _ = cmd.Process.Kill() }, func() { err = n.release() })
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if n.holder != nil {
		t.Fatal("the holder handle was kept after the holder was reaped")
	}
	if !reaped() {
		t.Fatal("the holder was left unreaped")
	}
}
