//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

// With no way to read the leader, nothing may signal its process group: the
// group ID could belong to someone else by now.
func TestUnreadableLeaderIsNeverSignalledAsAGroup(t *testing.T) {
	base := openFDs(t)
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	f.failWaitid.Store(true)
	before := f.groupKills.Load()
	if _, err := c.Stop(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Stop: %v, want ErrCleanupIncomplete", err)
	}
	if got := f.groupKills.Load() - before; got != 0 {
		t.Fatalf("%d group signals sent although the leader could not be shown unreaped", got)
	}
	recovered(t, f, n, base)
}

// A child reaped by someone else cannot be accounted for. The supervisor must
// say so, never signal the stale group, and keep the namespace pinned. The
// teardown is by hand because the API has no way to recover from this.
func TestChildReapedByAnotherProcessIsTerminalAndNeverSignalledAsAGroup(t *testing.T) {
	f := &faults{}
	n := newFaultNamespace(t, f)
	c, err := n.Start(context.Background(), quickOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	pid := c.PID()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	for i := 0; procState(pid) != 'Z'; i++ {
		if i > 300 {
			t.Fatal("child did not exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil { // an unrelated reaper takes the child
		t.Fatal(err)
	}
	before := f.groupKills.Load()
	for i := range 2 {
		if _, err := c.Stop(context.Background()); !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatalf("Stop %d: %v, want ErrCleanupIncomplete", i, err)
		}
	}
	if got := f.groupKills.Load() - before; got != 0 {
		t.Fatalf("%d group signals sent to the group of a reaped leader", got)
	}
	assertUnusable(t, n)
	assertPinsHeld(t, n)
	if err := n.Close(); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("Close: %v, want ErrCleanupIncomplete", err)
	}
	assertPinsHeld(t, n)
	_ = c.cmd.Process.Release() // Go's own handle for a child it never waited for
	_ = n.holder.Process.Kill()
	_, _ = n.holder.Process.Wait()
	for _, fd := range []*int{&c.pidfd, &n.holderFD, &n.netFD, &n.userFD} {
		closeFD(fd)
	}
	n.cmu.Lock()
	delete(n.children, c)
	n.cmu.Unlock()
}
