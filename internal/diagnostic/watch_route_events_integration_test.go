//go:build linux && integration

package diagnostic

import (
	"testing"
	"time"
)

// The subscription is made on the host network namespace. Binding it needs no
// privilege and invalidates the cache once. Close must return and leave no
// reader running, and the session must hold no subscription after it.
func TestRouteEventsFollowAndCloseOnTheHost(t *testing.T) {
	s := NewWatchSession(nil)
	if err := s.FollowRouteEvents(); err != nil {
		t.Skipf("route change notifications unavailable here: %v", err)
	}
	if !s.FollowsRouteEvents() {
		t.Fatal("FollowRouteEvents returned nil, but the session follows nothing")
	}
	// The host may change its own routes at any time, so only the bind's
	// invalidation is required here, not an exact count.
	if got := s.generation.Load(); got < 1 {
		t.Errorf("generation after binding = %d, want at least 1", got)
	}
	done := s.feed.done

	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	select {
	case <-done:
	default:
		t.Fatal("reader still running after Close")
	}
	if s.FollowsRouteEvents() {
		t.Error("session still follows route events after Close")
	}
}
