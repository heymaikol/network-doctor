//go:build linux && netns_integration

package diagnostic

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// routeHelperEnv marks the child process that runs in its own user and network
// namespace. The parent test starts that child, so the change it makes is local
// to a namespace that only the child owns.
const routeHelperEnv = "NETDOC_ROUTE_EVENTS_HELPER"

// requireNetnsEnv is the simulation tests' switch (internal/simulation
// RequireNetnsEnv): a CI job that must exercise namespaces fails when they are
// unavailable, instead of going green with a skip. Developers leave it unset.
const requireNetnsEnv = "NETDOC_SIM_REQUIRE_NETNS"

func skipOrRequireNetns(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv(requireNetnsEnv) != "" {
		t.Fatalf("%s is set, so this test must run, but %s", requireNetnsEnv, reason)
	}
	t.Skip(reason)
}

// A link, address and route change made inside a fresh network namespace reach
// a session that follows route events. The helper runs in that namespace, so
// the changes are local to it and touch no host state.
func TestRouteEventsReachTheSessionFromTheKernel(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		skipOrRequireNetns(t, "ip(8) is needed to make the change inside the namespace")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRouteEventsNamespaceHelper$", "-test.v", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), routeHelperEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if errors.Is(err, syscall.EPERM) {
		skipOrRequireNetns(t, fmt.Sprintf("unprivileged user namespaces are not available: %v", err))
	}
	if err != nil {
		t.Fatalf("namespace helper failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ROUTE EVENT SEEN") {
		t.Fatalf("namespace helper did not report an event:\n%s", out)
	}
}

// TestRouteEventsNamespaceHelper runs only inside the namespace started above.
// It subscribes, then makes each kind of change the subscription covers, one
// command at a time. Each command must move the generation before the next one
// starts, so no step can be satisfied by an earlier step's notification.
func TestRouteEventsNamespaceHelper(t *testing.T) {
	if os.Getenv(routeHelperEnv) != "1" {
		t.Skip("runs only as the namespace helper")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatalf("ip(8): %v", err)
	}
	s := NewWatchSession(nil)
	if err := s.FollowRouteEvents(); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer s.Close()
	// The namespace is new and quiet, so the bind's own invalidation is the only
	// change so far.
	if got := s.generation.Load(); got != 1 {
		t.Fatalf("generation after binding = %d, want exactly 1 (the bind's invalidation)", got)
	}

	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "10.9.9.9/32", "dev", "lo"},
		{"-6", "addr", "add", "fd00::9/128", "dev", "lo"},
		{"route", "add", "10.8.8.0/24", "dev", "lo"},
		{"addr", "change", "10.9.9.9/32", "dev", "lo", "label", "lo:t"},
		{"-6", "addr", "change", "fd00::9/128", "dev", "lo", "preferred_lft", "1000"},
		{"-6", "route", "add", "2001:db8:8::/48", "dev", "lo"},
	}
	for _, args := range steps {
		before := s.generation.Load()
		if out, err := exec.Command(ip, args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
		deadline := time.Now().Add(10 * time.Second)
		for s.generation.Load() == before {
			if time.Now().After(deadline) {
				t.Fatalf("ip %v: no route change reached the session", args)
			}
			time.Sleep(10 * time.Millisecond)
		}
		// Let the rest of this step's notifications land before the next step
		// reads its baseline.
		time.Sleep(100 * time.Millisecond)
	}

	// Once the namespace is quiet, a stop is not a change: Close must leave the
	// generation where the last notification put it.
	before := s.generation.Load()
	s.Close()
	if got := s.generation.Load(); got != before {
		t.Fatalf("Close moved the generation from %d to %d: a stop is not a change", before, got)
	}
	os.Stdout.WriteString("ROUTE EVENT SEEN\n")
}
