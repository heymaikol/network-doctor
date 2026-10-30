//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// watchProcess opens a pidfd on a process that is not the test's child, so the
// test can tell whether it has exited without trusting its PID number, which the
// kernel may reissue once the process is gone. release kills the process if it
// is still running and closes the pidfd; it also runs at cleanup, so a failing
// test cannot leave the process behind.
func watchProcess(t *testing.T, pid int) (exited func() bool, release func()) {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	release = sync.OnceFunc(func() {
		_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		_ = unix.Close(fd)
	})
	t.Cleanup(release)
	exited = func() bool {
		n, _ := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 0) //nolint:gosec // G115: a descriptor number always fits in 32 bits.
		return n > 0
	}
	return exited, release
}

// The final SIGKILL sweep is the only thing that removes a descendant the leader
// left behind. When it fails, Stop must not report the cleanup as finished and
// must not reap the leader: the zombie leader is what keeps the group ID from
// being reissued, so a retry can still name the group safely.
func TestFailedGroupSweepKeepsTheLeaderUnreapedForARetry(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, out := startHelper(t, n, "daemonize")
	pid, err := strconv.Atoi(waitFile(t, out))
	if err != nil {
		t.Fatal(err)
	}
	waitFile(t, out+".ready")
	grandchildExited, releaseGrandchild := watchProcess(t, pid)
	<-c.Done() // the leader is gone and unreaped; the grandchild lives on

	f.groupErrno.Store(uintptr(unix.EPERM))
	before := f.groupKills.Load()
	for i := range 2 {
		_, err := c.Stop(context.Background())
		if !errors.Is(err, ErrCleanupIncomplete) || !errors.Is(err, unix.EPERM) {
			t.Fatalf("Stop %d: %v, want ErrCleanupIncomplete wrapping EPERM", i, err)
		}
		if got := n.sys.probe(c.pidfd); got != leaderZombie {
			t.Fatalf("Stop %d left the leader in state %d, want an unreaped zombie holding the group ID", i, got)
		}
		if got := registered(n); got != 1 {
			t.Fatalf("Stop %d: %d children registered, want the one still owed a sweep", i, got)
		}
		if grandchildExited() {
			t.Fatalf("Stop %d: the grandchild exited although no signal reached it", i)
		}
		assertUnusable(t, n)
		assertPinsHeld(t, n)
	}
	if got := f.groupKills.Load() - before; got < 2 {
		t.Fatalf("%d sweeps over two Stop calls, want one per call", got)
	}

	f.groupErrno.Store(0)
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatalf("Stop after the fault cleared: %v", err)
	}
	for i := 0; !grandchildExited(); i++ {
		if i > 200 {
			t.Fatal("the retried sweep did not remove the grandchild")
		}
		time.Sleep(10 * time.Millisecond)
	}
	releaseGrandchild()
	recovered(t, f, n, base)
}

// ESRCH from a group signal means the group has no member at all, which leaves
// nothing to sweep. The kernel counts an unreaped zombie leader as a member, so
// this is the answer a stale group would give, and the reap that follows is what
// notices a leader somebody else collected. This pins that reading: it passes
// before and after the sweep error handling.
func TestEmptyGroupAnswerToTheSweepIsNotAFailure(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, _ := startHelper(t, n, "report")
	<-c.Done()
	f.groupErrno.Store(uintptr(unix.ESRCH))
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v, want success for an empty group", err)
	}
	recovered(t, f, n, base)
}
