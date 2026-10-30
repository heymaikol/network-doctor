//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// requireNetnsEnv matches the other namespace tests: a CI job that must run
// them fails instead of skipping when namespaces are unavailable.
const requireNetnsEnv = "NETDOC_SIM_REQUIRE_NETNS"

func newNamespace(t *testing.T) *Namespace {
	t.Helper()
	n, err := NewNamespace(context.Background())
	if errors.Is(err, ErrUnsupported) {
		if os.Getenv(requireNetnsEnv) != "" {
			t.Fatalf("%s is set but namespaces are unavailable", requireNetnsEnv)
		}
		t.Skip("rootless namespaces or pidfd namespace ioctls unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// reaped reports whether this process has no child left to wait for.
func reaped() bool {
	var info unix.Siginfo
	return unix.Waitid(unix.P_ALL, 0, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil) == unix.ECHILD
}

func TestNamespaceIsRetainedIsolatedAndReleased(t *testing.T) {
	base := openFDs(t)
	n := newNamespace(t)
	id, err := n.Identity()
	if err != nil {
		t.Fatal(err)
	}
	self, err := selfIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if id.NetIno == 0 || id.UserIno == 0 || id == self || id.NetIno == self.NetIno || id.UserIno == self.UserIno {
		t.Fatalf("namespace not distinct from the supervisor: %+v vs %+v", id, self)
	}
	for _, fd := range []int{n.netFD, n.userFD, n.holderFD} {
		if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("descriptor %d is inheritable", fd)
		}
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := n.Identity(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed namespace answered: %v", err)
	}
	if got := openFDs(t); got != base {
		t.Fatalf("descriptors: %d before, %d after", base, got)
	}
	if !reaped() {
		t.Fatal("holder was not reaped")
	}
}

// Two live namespaces never share identity, and a namespace destroyed and
// recreated gets a fresh retained identity. Kernels differ on whether an inode
// number can repeat after release, so only live descriptors are ever compared.
func TestDestroyAndRecreateNeverComparesReleasedIdentity(t *testing.T) {
	first := newNamespace(t)
	a, _ := first.Identity()
	second := newNamespace(t)
	b, _ := second.Identity()
	if a.NetIno == b.NetIno || a.UserIno == b.UserIno {
		t.Fatalf("live namespaces share identity: %+v %+v", a, b)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third := newNamespace(t)
	c, _ := third.Identity()
	if c.NetIno == b.NetIno || c.UserIno == b.UserIno {
		t.Fatalf("recreated namespace shares identity with a live one: %+v %+v", c, b)
	}
	if _, err := first.Identity(); !errors.Is(err, ErrClosed) {
		t.Fatalf("destroyed namespace still answers: %v", err)
	}
}

func TestHolderKilledBeforeInspectionRefusesAndLeaksNothing(t *testing.T) {
	base := openFDs(t)
	testHookAfterHolderStart = func(pidfd int) {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		var info unix.Siginfo
		_ = unix.Waitid(unix.P_PIDFD, pidfd, &info, unix.WEXITED|unix.WNOWAIT, nil) // dead but unreaped
	}
	defer func() { testHookAfterHolderStart = nil }()
	n, err := NewNamespace(context.Background())
	if err == nil {
		n.Close()
		t.Fatal("dead holder was accepted")
	}
	if errors.Is(err, ErrUnsupported) {
		t.Skip("namespaces unavailable") // not the refusal under test
	}
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("got %v, want ErrIdentityMismatch", err)
	}
	if got := openFDs(t); got != base {
		t.Fatalf("descriptors: %d before, %d after", base, got)
	}
	if !reaped() {
		t.Fatal("dead holder was not reaped")
	}
}

func TestCancelledStartCreatesNothing(t *testing.T) {
	base := openFDs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewNamespace(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if got := openFDs(t); got != base || !reaped() {
		t.Fatalf("cancelled start left state: %d descriptors, reaped=%v", got, reaped())
	}
}

func TestConcurrentCloseIsSafe(t *testing.T) {
	n := newNamespace(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); n.Close() }()
		go func() { defer wg.Done(); n.Identity() }()
	}
	wg.Wait()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
}

// A hostile same-UID process can SIGKILL the holder. The retained descriptors
// still pin the namespaces, and Close still reaps and releases everything.
func TestHolderKilledWhileHeldStillCleansUp(t *testing.T) {
	base := openFDs(t)
	n := newNamespace(t)
	if err := syscall.Kill(n.holder.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Identity(); err != nil {
		t.Fatalf("retained identity lost with the holder: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	if got := openFDs(t); got != base || !reaped() {
		t.Fatalf("left state: %d descriptors, reaped=%v", got, reaped())
	}
}
