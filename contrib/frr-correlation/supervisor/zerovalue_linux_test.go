//go:build linux

package supervisor

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// A zero-value Namespace holds 0 in every descriptor field, so a Close that
// trusted them would close the process's standard input. The test keeps its own
// copy of descriptor 0 and puts it back, so a regression reports a failure and
// does not break the test binary.
func descriptorZeroSurvives(t *testing.T, fn func()) {
	t.Helper()
	saved, err := unix.Dup(0)
	if err != nil {
		t.Skipf("descriptor 0 is not open, so there is nothing to protect: %v", err)
	}
	defer func() { _ = unix.Close(saved) }()
	fn()
	if _, err := unix.FcntlInt(0, unix.F_GETFD, 0); err != nil {
		_ = unix.Dup3(saved, 0, 0)
		t.Fatalf("descriptor 0 was closed: %v", err)
	}
}

func TestZeroValueNamespaceRefusesEverythingAndClosesNothing(t *testing.T) {
	var n Namespace
	descriptorZeroSurvives(t, func() {
		for i := range 2 {
			if err := n.Close(); !errors.Is(err, ErrClosed) {
				t.Errorf("Close %d: %v, want ErrClosed", i, err)
			}
		}
	})
	if id, err := n.Identity(); !errors.Is(err, ErrClosed) || id != (Identity{}) {
		t.Fatalf("Identity: %+v, %v, want ErrClosed", id, err)
	}
	if c, err := n.Start(context.Background(), Options{Argv: []string{"/bin/true"}}); c != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("Start: %v, %v, want ErrClosed", c, err)
	}
}

func TestNilNamespaceRefusesEverything(t *testing.T) {
	var n *Namespace
	if err := n.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Close: %v, want ErrClosed", err)
	}
	if id, err := n.Identity(); !errors.Is(err, ErrClosed) || id != (Identity{}) {
		t.Fatalf("Identity: %+v, %v, want ErrClosed", id, err)
	}
	if c, err := n.Start(context.Background(), Options{Argv: []string{"/bin/true"}}); c != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("Start: %v, %v, want ErrClosed", c, err)
	}
}
