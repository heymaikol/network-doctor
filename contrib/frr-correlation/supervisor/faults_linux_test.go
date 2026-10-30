//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// faults injects failures into the supervisor's kernel calls so each cleanup
// failure path runs deterministically. Nothing here makes the kernel refuse to
// kill a real process: a fault reports failure and leaves the process exactly as
// it was, so turning the fault off lets the supervisor finish the cleanup. Every
// test ends the same way, through recovered.
type faults struct {
	dropSignals atomic.Bool  // group signals report success and reach nobody
	failWaitid  atomic.Bool  // every waitid fails, so no process state can be observed
	failWatch   atomic.Bool  // the blocking waitid of a child's watcher fails
	failReap    atomic.Bool  // reaping reports failure and leaves the process unreaped
	groupKills  atomic.Int32 // group signals attempted
	gate        chan struct{}
	once        sync.Once
	identity    func(pidfd int) (Identity, error) // replaces the namespace read of a child when set
	settle      time.Duration                     // replaces the exit settle time when set
}

func (f *faults) sys() *sys {
	s := realSys()
	s.killDeadline = 200 * time.Millisecond
	if f.identity != nil {
		s.identity = f.identity
	}
	if f.settle > 0 {
		s.exitSettle = f.settle
	}
	waitid, reap, kill := s.waitid, s.reap, s.killGroup
	s.waitid = func(pidfd int, info *unix.Siginfo, options int) error {
		watcher := options&unix.WNOHANG == 0 && options&unix.WNOWAIT != 0
		if watcher && f.gate != nil {
			<-f.gate // parked until the test lets the watcher run into its fault
		}
		if f.failWaitid.Load() || watcher && f.failWatch.Load() {
			return unix.EIO
		}
		return waitid(pidfd, info, options)
	}
	s.reap = func(p *os.Process) (*os.ProcessState, error) {
		if f.failReap.Load() {
			return nil, unix.EIO
		}
		return reap(p)
	}
	s.killGroup = func(pgid int, sig unix.Signal) error {
		f.groupKills.Add(1)
		if f.dropSignals.Load() {
			return nil
		}
		return kill(pgid, sig)
	}
	return s
}

func (f *faults) open() {
	f.once.Do(func() {
		if f.gate != nil {
			close(f.gate)
		}
	})
}

func (f *faults) clear() {
	f.dropSignals.Store(false)
	f.failWaitid.Store(false)
	f.failWatch.Store(false)
	f.failReap.Store(false)
	f.open()
}

func newFaultNamespace(t *testing.T, f *faults) *Namespace {
	t.Helper()
	n, err := newNamespaceWith(context.Background(), f.sys())
	if errors.Is(err, ErrUnsupported) {
		unavailable(t, "rootless namespaces or pidfd namespace ioctls unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.clear(); _ = n.Close() })
	return n
}

// quickOptions is a long-lived child that stops after a short grace, so a
// dropped signal fails a test in milliseconds and not seconds.
func quickOptions(t *testing.T) Options {
	t.Helper()
	o, _ := helperOptions(t, "sleep")
	o.StopGrace = 50 * time.Millisecond
	return o
}

// recovered turns every fault off and requires the namespace to finish its
// cleanup through the public API and leave nothing behind.
func recovered(t *testing.T, f *faults, n *Namespace, base int) {
	t.Helper()
	f.clear()
	for i := range 2 {
		if err := n.Close(); err != nil {
			t.Fatalf("Close %d after recovery: %v", i, err)
		}
	}
	if got := openFDs(t); got != base {
		t.Fatalf("descriptors: %d before, %d after", base, got)
	}
	if !reaped() {
		t.Fatal("a process was left unreaped")
	}
}

// assertUnusable requires that no further launch or identity read is possible.
func assertUnusable(t *testing.T, n *Namespace) {
	t.Helper()
	o, _ := helperOptions(t, "sleep")
	if c, err := n.Start(context.Background(), o); !errors.Is(err, ErrClosed) {
		if c != nil {
			_, _ = c.Stop(context.Background())
		}
		t.Fatalf("Start after incomplete cleanup: %v, want ErrClosed", err)
	}
	if _, err := n.Identity(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Identity after incomplete cleanup: %v, want ErrClosed", err)
	}
}

// assertPinsHeld requires the namespace descriptors and the holder to be open.
func assertPinsHeld(t *testing.T, n *Namespace) {
	t.Helper()
	for name, fd := range map[string]int{"holder": n.holderFD, "network": n.netFD, "user": n.userFD} {
		if fd < 0 {
			t.Fatalf("%s descriptor released while cleanup is incomplete", name)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatalf("%s descriptor %d is not open: %v", name, fd, err)
		}
	}
}

func registered(n *Namespace) int {
	n.cmu.Lock()
	defer n.cmu.Unlock()
	return len(n.children)
}

// A child that fails verification is stopped. When that stop also fails, the
// child must stay registered, the namespace must refuse launches, and a later
// Close must still be able to finish the job.
func TestVerifyFailureThenStopFailureKeepsTheChildAccounted(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	unshare, sleep := lookPath(t, "unshare"), lookPath(t, "sleep")
	testNsenterArgs = func(int) []string { return []string{unshare, "--user", "--map-root-user", "--net", "--"} }
	defer func() { testNsenterArgs = nil }()
	f.dropSignals.Store(true)
	_, err := n.Start(context.Background(), Options{Argv: []string{sleep, "3600"}, StopGrace: 50 * time.Millisecond})
	if !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("got %v, want the mismatch joined with the cleanup failure", err)
	}
	if got := registered(n); got != 1 {
		t.Fatalf("%d children registered, want the one that could not be stopped", got)
	}
	assertUnusable(t, n)
	assertPinsHeld(t, n)
	recovered(t, f, n, base)
}

// A failed Close must keep the namespace pins, stay retryable, and succeed once
// the child can be stopped.
func TestCloseKeepsPinsWhileAChildIsNotProvenReaped(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	f.dropSignals.Store(true)
	for i := range 2 {
		if err := n.Close(); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("Close %d: %v, want ErrCleanupIncomplete", i, err)
		}
		assertPinsHeld(t, n)
		assertUnusable(t, n)
	}
	select {
	case <-c.Done():
		t.Fatal("child exited although its signals were dropped")
	default:
	}
	recovered(t, f, n, base)
	select {
	case <-c.Done():
	default:
		t.Fatal("child still running after recovery")
	}
}

// A holder that cannot be reaped keeps the handle, and a later Close retries.
func TestFailedHolderReapIsRetriedByAnotherClose(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	f.failReap.Store(true)
	if err := n.Close(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Close: %v, want ErrCleanupIncomplete", err)
	}
	assertPinsHeld(t, n)
	assertUnusable(t, n)
	recovered(t, f, n, base)
}

// When the constructor fails and its own cleanup also fails, the caller gets the
// namespace back with the error, so the holder is not lost.
func TestConstructorCleanupFailureKeepsTheHolderHandle(t *testing.T) {
	base := openFDs(t)
	testHookAfterHolderStart = func(pidfd int) {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		var info unix.Siginfo
		_ = unix.Waitid(unix.P_PIDFD, pidfd, &info, unix.WEXITED|unix.WNOWAIT, nil) // dead but unreaped
	}
	defer func() { testHookAfterHolderStart = nil }()
	f := &faults{}
	f.failReap.Store(true)
	n, err := newNamespaceWith(context.Background(), f.sys())
	if errors.Is(err, ErrUnsupported) {
		unavailable(t, "namespaces unavailable") // not the refusal under test
	}
	if !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("got %v, want the mismatch joined with the cleanup failure", err)
	}
	if n == nil {
		t.Fatal("constructor dropped the holder handle together with its error")
	}
	assertUnusable(t, n)
	recovered(t, f, n, base)
}

// A reap that fails is an error and not a panic. The child stays registered
// with its pidfd, and a retry reports the real exit status.
func TestReapFailureIsReportedAndRetryable(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	f.failReap.Store(true)
	if _, err := c.Stop(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Stop: %v, want ErrCleanupIncomplete", err)
	}
	if c.pidfd < 0 || registered(n) != 1 {
		t.Fatalf("handle dropped: pidfd %d, %d registered", c.pidfd, registered(n))
	}
	assertUnusable(t, n)
	f.clear()
	st, err := c.Stop(context.Background())
	if err != nil || st.Signal != syscall.SIGTERM || st.Escalated {
		t.Fatalf("retry: %+v %v", st, err)
	}
	if again, err := c.Stop(context.Background()); err != nil || again != st {
		t.Fatalf("repeated Stop changed its answer: %+v %v, was %+v", again, err, st)
	}
	recovered(t, f, n, base)
}

// A Stop the caller makes counts the same as one Close makes.
func TestStopFailureByTheCallerBlocksFurtherLaunches(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	f.dropSignals.Store(true)
	if _, err := c.Stop(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Stop: %v, want ErrCleanupIncomplete", err)
	}
	assertUnusable(t, n)
	assertPinsHeld(t, n)
	f.clear()
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	recovered(t, f, n, base)
}

// Close calls from many goroutines serialize, each failing while the fault
// lasts, and all succeed once it is gone.
func TestConcurrentCloseRetriesAfterFailure(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	if _, err := n.Start(context.Background(), quickOptions(t)); err != nil {
		t.Fatal(err)
	}
	f.dropSignals.Store(true)
	// A Start that wins the race against the very first Close legitimately
	// succeeds, so the first failed Close runs alone. From then on every Start
	// must be refused, however many Close calls run beside it.
	if err := n.Close(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("first Close: %v, want ErrCleanupIncomplete", err)
	}
	run := func(want func(error) bool, what string) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Add(1)
			go func() { defer wg.Done(); errs[i] = n.Close() }()
		}
		for range 2 {
			o, _ := helperOptions(t, "sleep")
			wg.Add(1)
			go func() {
				defer wg.Done()
				if c, err := n.Start(context.Background(), o); err == nil {
					_, _ = c.Stop(context.Background())
					t.Error("Start succeeded after a failed Close")
				}
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if !want(err) {
				t.Fatalf("%s: Close returned %v", what, err)
			}
		}
	}
	run(func(err error) bool { return errors.Is(err, ErrCleanupIncomplete) }, "fault on")
	assertPinsHeld(t, n)
	f.clear()
	run(func(err error) bool { return err == nil }, "fault off")
	recovered(t, f, n, base)
}
