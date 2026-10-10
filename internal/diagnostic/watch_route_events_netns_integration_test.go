//go:build linux && netns_integration

package diagnostic

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
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

// unsupportedMarker opens the helper's line for a kernel that cannot run this test.
const unsupportedMarker = "ROUTE EVENT UNSUPPORTED:"

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

// A link, address, route, policy-rule and nexthop change made inside a fresh
// network namespace reach a session that follows route events. The helper runs in that namespace, so
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
	if _, reason, ok := strings.Cut(string(out), unsupportedMarker); ok {
		skipOrRequireNetns(t, strings.TrimSpace(reason))
	}
	if !strings.Contains(string(out), "ROUTE EVENT SEEN") {
		t.Fatalf("namespace helper did not report an event:\n%s", out)
	}
}

// TestRouteEventsNamespaceHelper runs only inside the namespace started above.
// It subscribes, then makes each kind of change the subscription covers, one
// command at a time. Each command is settled before the next starts: the session
// has read every notification the command caused, so no step can be satisfied by
// an earlier step's notification.
func TestRouteEventsNamespaceHelper(t *testing.T) {
	if os.Getenv(routeHelperEnv) != "1" {
		t.Skip("runs only as the namespace helper")
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
	tap := openRouteTap(t, s)
	// Nexthop objects need Linux 5.3. Without that group this kernel cannot show
	// nexthop delivery, so the run says so and the parent decides skip or failure.
	if kernelRouteGroups(t, s)&(1<<(unix.RTNLGRP_NEXTHOP-1)) == 0 {
		os.Stdout.WriteString(unsupportedMarker + " kernel has no nexthop group: nexthop objects need Linux 5.3\n")
		return
	}
	// Each group the subscription must hold, by its rtnetlink number. The kernel's
	// own list is checked, not the code's list, so a join that did not take fails.
	joined := kernelRouteGroups(t, s)
	for _, g := range []int{1, 5, 7, 9, 11, 8, 19, 32} {
		if joined&(1<<(g-1)) == 0 {
			t.Errorf("kernel membership lacks route group %d", g)
		}
	}
	checkRefusedJoin(t)

	steps := [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "10.9.9.9/32", "dev", "lo"},
		{"-6", "addr", "add", "fd00::9/128", "dev", "lo"},
		{"route", "add", "10.8.8.0/24", "dev", "lo"},
		{"addr", "change", "10.9.9.9/32", "dev", "lo", "label", "lo:t"},
		{"-6", "addr", "change", "fd00::9/128", "dev", "lo", "preferred_lft", "1000"},
		{"-6", "route", "add", "2001:db8:8::/48", "dev", "lo"},
		// Policy rules and nexthop objects raise no link, address or route
		// notification, so each of these steps is silent without the rule and
		// nexthop groups.
		{"rule", "add", "pref", "1000", "from", "10.7.7.0/24", "table", "100"},
		{"-6", "rule", "add", "pref", "1000", "from", "fd00:7::/64", "table", "100"},
		{"nexthop", "add", "id", "42", "blackhole"},
		{"nexthop", "del", "id", "42"},
	}
	for _, args := range steps {
		tap.run(t, args...)
	}

	// Once the namespace is quiet, a stop is not a change: Close must leave the
	// generation where the last notification put it.
	before := s.generation.Load()
	s.Close()
	if got := s.generation.Load(); got != before {
		t.Fatalf("Close moved the generation from %d to %d: a stop is not a change", before, got)
	}

	// The Watch effect. A nexthop that a route uses is deleted. That removes the
	// route, and on kernel 7.2 it is announced only as a nexthop change, not a route
	// change. The reused QUIC row must still be measured again on the next pass, one
	// cadence after the change. Only the change is real here: the QUIC fault is
	// simulated by quicFaultGraph.
	const cadence = 5 * time.Second
	clock := newWatchClock()
	w := NewWatchSession(clock.Now)
	if err := w.FollowRouteEvents(); err != nil {
		t.Fatalf("subscribe for the Watch check: %v", err)
	}
	defer w.Close()
	wt := openRouteTap(t, w)
	wt.run(t, "nexthop", "add", "id", "43", "dev", "lo")
	wt.run(t, "route", "add", "10.6.6.0/24", "nhid", "43")
	n := newWatchNet()
	fault := false
	faultPass(t, w, n, &fault)
	clock.Advance(cadence)
	if _, runs, _ := faultPass(t, w, n, &fault); runs[ProbeQUIC] != 0 {
		t.Fatalf("QUIC ran %d times before any change, want it reused", runs[ProbeQUIC])
	}

	fault = true
	changedAt := clock.now
	wt.run(t, "nexthop", "del", "id", "43")
	clock.Advance(cadence)
	results, runs, attempts := faultPass(t, w, n, &fault)
	if q := results[ProbeQUIC]; q.Status != StatusFail || q.Cause != "timeout" {
		t.Fatalf("next pass: QUIC %v cause %q, want fail timeout", q.Status, q.Cause)
	}
	if runs[ProbeQUIC] != 1 || attempts != 1 {
		t.Errorf("next pass: QUIC runs=%d attempts=%d, want 1 run, 1 attempt", runs[ProbeQUIC], attempts)
	}
	if latency := clock.now.Sub(changedAt); latency != cadence {
		t.Errorf("detection latency %v, want one cadence %v, not watchMaxAge %v", latency, cadence, watchMaxAge)
	}
	// A fresh session over the same graph is the oracle. Its rows and its diagnosis
	// must both match, so a difference in routes or families that status and cause
	// would not show still fails here.
	order := ProbeOrder(quicFaultGraph(n, &fault))
	oracle, _, _ := faultPass(t, NewWatchSession(clock.Now), n, &fault)
	assertSameRowsAndDiagnosis(t, order, results, oracle)

	// Recovery: the route returns through a new nexthop. Both changes are settled
	// before the pass, so the pass sees the recovered route. A failed row is never
	// kept, so QUIC is measured on this pass whatever the notifications did.
	fault = false
	wt.run(t, "nexthop", "add", "id", "43", "dev", "lo")
	wt.run(t, "route", "add", "10.6.6.0/24", "nhid", "43")
	clock.Advance(cadence)
	results, runs, _ = faultPass(t, w, n, &fault)
	if q := results[ProbeQUIC]; q.Status != StatusPass || runs[ProbeQUIC] != 1 {
		t.Errorf("recovery: QUIC %v, measured %d times, want pass measured once", q.Status, runs[ProbeQUIC])
	}
	oracle, _, _ = faultPass(t, NewWatchSession(clock.Now), n, &fault)
	assertSameRowsAndDiagnosis(t, order, results, oracle)

	// An IPv6-only change. Every earlier notification has been read, so the quiet
	// pass reuses QUIC because nothing changed. Then one IPv6 route change, settled
	// before the next pass, must refuse it: no event is scoped to one address family.
	clock.Advance(cadence)
	if _, runs, _ = faultPass(t, w, n, &fault); runs[ProbeQUIC] != 0 {
		t.Fatalf("QUIC ran %d times on a quiet pass, want it reused", runs[ProbeQUIC])
	}
	wt.run(t, "-6", "route", "add", "2001:db8:6::/48", "dev", "lo")
	clock.Advance(cadence)
	results, runs, _ = faultPass(t, w, n, &fault)
	if _, reused := results[ProbeQUIC].ReusedFrom(); reused || runs[ProbeQUIC] != 1 {
		t.Errorf("IPv6 route change: QUIC reused=%v measured %d times, want measured again once", reused, runs[ProbeQUIC])
	}
	oracle, _, _ = faultPass(t, NewWatchSession(clock.Now), n, &fault)
	assertSameRowsAndDiagnosis(t, order, results, oracle)

	os.Stdout.WriteString("ROUTE EVENT SEEN\n")
}

// routeTap is a second subscriber to the groups a session follows. For the
// commands these tests run, the kernel queues each notification on every
// subscriber before the command returns, so once a command has returned, the tap
// holds every notification it made. The session invalidates once per datagram it
// reads, so the tap's count is the generation the session must reach. The count is
// measured for each command, not assumed. A notification the kernel queued later
// would be counted by the next drain, but it could land between a settle and the
// pass after it.
type routeTap struct {
	s      *WatchSession
	ip     string
	fd     int
	buf    []byte
	base   uint64 // session generation when the tap opened
	queued uint64 // notifications the tap has counted so far
}

// openRouteTap subscribes to the session's groups with the session's own join
// code, so the tap and the session hear the same notifications. Open it right
// after the session binds, with no change in between: the session counts every
// change from its bind, and the tap counts from its own bind.
func openRouteTap(t *testing.T, s *WatchSession) *routeTap {
	t.Helper()
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatalf("ip(8): %v", err)
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: routeGroups}); err != nil {
		t.Fatal(err)
	}
	joinOptionalRouteGroups(fd, optionalRouteGroups)
	return &routeTap{s: s, ip: ip, fd: fd, buf: make([]byte, 32<<10), base: s.generation.Load()}
}

// run makes one change with ip, settles it, and fails if the change caused no
// notification. A step that does nothing would otherwise pass on the state the
// previous step left behind.
func (r *routeTap) run(t *testing.T, args ...string) {
	t.Helper()
	before := r.queued
	if out, err := exec.Command(r.ip, args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %v: %v\n%s", args, err, out)
	}
	r.settle(t)
	if r.queued == before {
		t.Fatalf("ip %v: no notification reached the subscription", args)
	}
}

// settle waits until the session has invalidated once for every notification the
// tap has counted. It fails on an invalidation with no notification behind it, and
// on a session that never catches up within ten seconds.
func (r *routeTap) settle(t *testing.T) {
	t.Helper()
	r.queued += r.drain(t)
	want := r.base + r.queued
	deadline := time.Now().Add(10 * time.Second)
	for got := r.s.generation.Load(); got != want; got = r.s.generation.Load() {
		if got > want {
			t.Fatalf("generation %d, want %d: the session invalidated for a notification the kernel did not queue", got, want)
		}
		if time.Now().After(deadline) {
			t.Fatalf("generation %d, want %d after 10s: the session has not read every notification", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// drain reads every datagram queued on the tap and returns how many. The socket is
// non-blocking, so EAGAIN marks the end of the queue. A tap that dropped a
// datagram returns an error here, because a short count would be wrong.
func (r *routeTap) drain(t *testing.T) uint64 {
	t.Helper()
	var n uint64
	for {
		_, _, err := unix.Recvfrom(r.fd, r.buf, 0)
		if errors.Is(err, unix.EAGAIN) {
			return n
		}
		if err != nil {
			t.Fatalf("route tap read: %v (a dropped notification makes the count unreliable)", err)
		}
		n++
	}
}

// assertSameRowsAndDiagnosis compares a Watch pass with a fresh oracle. Each row must
// carry the same fingerprint, which covers its routes, families, addresses and cause,
// not only its status. The diagnosis, which Interpret derives from those rows, must
// also be equal.
func assertSameRowsAndDiagnosis(t *testing.T, order []ProbeID, watch, oracle map[ProbeID]ProbeResult) {
	t.Helper()
	for _, id := range order {
		if got, want := fingerprint(watch[id]), fingerprint(oracle[id]); got != want {
			t.Errorf("row %s: Watch %s, fresh oracle %s", id, got, want)
		}
	}
	got, want := Interpret(watchTarget(), order, watch), Interpret(watchTarget(), order, oracle)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diagnosis differs from the fresh oracle:\n got  %+v\n want %+v", got, want)
	}
}

// kernelRouteGroups returns the group membership the kernel reports for the
// subscription's socket, with bit g-1 set for group g.
func kernelRouteGroups(t *testing.T, s *WatchSession) uint32 {
	t.Helper()
	f := s.feed.src.(*netlinkRouteEvents).f
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	var bits uint32
	var sockErr error
	if err := rc.Control(func(fd uintptr) {
		bits, sockErr = membershipBits(int(fd))
	}); err != nil {
		t.Fatalf("socket: %v", err)
	}
	if sockErr != nil {
		t.Fatalf("NETLINK_LIST_MEMBERSHIPS: %v", sockErr)
	}
	return bits
}

// membershipBits returns the groups the kernel reports for fd, with bit g-1 set
// for group g. It reads the kernel's list, so a join is checked where it took effect.
func membershipBits(fd int) (uint32, error) {
	bits, err := unix.GetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_LIST_MEMBERSHIPS)
	// #nosec G115 -- the kernel's 32-bit membership word, read into an int
	return uint32(bits), err
}

// checkRefusedJoin joins group 99, which the kernel does not have, and then the
// optional groups after it. The refusal must not cost the bound groups or the
// joins after it. The socket is the namespace's own, so no host subscription is made.
func checkRefusedJoin(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: routeGroups}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, 99); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("join of group 99 = %v, want EINVAL", err)
	}
	joinOptionalRouteGroups(fd, []int{99, unix.RTNLGRP_IPV4_RULE, unix.RTNLGRP_NEXTHOP})
	bits, err := membershipBits(fd)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []int{1, 5, 7, 9, 11, 8, 32} {
		if bits&(1<<(g-1)) == 0 {
			t.Errorf("group %d missing after the refused join of group 99", g)
		}
	}
}
