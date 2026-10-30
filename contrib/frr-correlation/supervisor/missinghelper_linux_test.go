//go:build linux && netns_integration

package supervisor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// A helper binary that is not installed is a broken setup, not a kernel that
// lacks a capability. ErrUnsupported is the one class a test or the CI probe
// turns into a skip, so it must not describe a missing sleep or nsenter: the job
// would pass without running the suite. Each error keeps the lookup failure.
func requireLaunchFailure(t *testing.T, err error) {
	t.Helper()
	switch {
	case errors.Is(err, ErrUnsupported):
		t.Fatalf("a missing helper reads as unsupported, which a test skips: %v", err)
	case !errors.Is(err, ErrLaunchFailed):
		t.Fatalf("got %v, want ErrLaunchFailed", err)
	case !errors.Is(err, exec.ErrNotFound):
		t.Fatalf("the lookup failure was dropped: %v", err)
	}
}

func TestMissingSleepIsALaunchFailureNotUnsupported(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	n, err := NewNamespace(context.Background())
	if n != nil {
		_ = n.Close()
		t.Fatal("a Namespace came back although no holder could start")
	}
	requireLaunchFailure(t, err)
}

func TestMissingNsenterIsALaunchFailureNotUnsupported(t *testing.T) {
	n := newNamespace(t)
	o, _ := helperOptions(t, "sleep")
	path := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	_, err := n.Start(context.Background(), o)
	requireLaunchFailure(t, err)
	// Nothing was launched, so the namespace still works once nsenter is back.
	t.Setenv("PATH", path)
	c, err := n.Start(context.Background(), o)
	if err != nil {
		t.Fatalf("Start after the failed lookup: %v", err)
	}
	if _, err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
