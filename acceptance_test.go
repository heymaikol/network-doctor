//go:build acceptance && (darwin || windows)

// Native acceptance runs the release-shaped netdoc binary against the real
// Windows or macOS network stack and checks its platform route evidence against
// observations the binary did not produce.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/report"
)

// These are duplicated deliberately. They are the independently known first
// IPv4 and IPv6 reference destinations the interface row is required to
// describe. Reading destinations out of that row would let a wrong or missing
// production reference select the question its oracle is asked.
var nativeReferenceDestinations = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("2606:4700:4700::1111"),
}

const nativeObservationAttempts = 3

// The prepared-route case needs a topology no hosted runner has, so it is
// opt-in. Requiring it separately exists so a job that meant to run it cannot
// go green having quietly skipped it.
const (
	preparedTargetEnv        = "NETDOC_ACCEPTANCE_TARGET"
	requirePreparedTargetEnv = "NETDOC_REQUIRE_ACCEPTANCE_TARGET"
)

// hostRoute is what the platform's own route tool answered about one
// destination. A field the tool does not report stays zero.
//
// WasCloned records that the matched entry is a host route the kernel cloned
// from a wider one, which macOS does as soon as anything connects to a
// destination covered by a PRCLONING route. It is provenance, not shape: a host
// route someone configured looks identical without it, and the two are
// different facts about the host. Windows clones nothing and never sets it.
type hostRoute struct {
	Iface     string
	Gateway   netip.Addr
	Source    netip.Addr
	Prefix    netip.Prefix
	WasCloned bool
}

type hostRouteObservation struct {
	Route hostRoute
	Found bool
}

type kernelRouteObservation struct {
	Source netip.Addr
	Owners []string
	Err    string
}

// nativeSocketConnected records that a connected-socket observation has already
// happened somewhere in this process. macOS clones a host route from whatever
// entry matched the moment that happens, and the clone outlives the test that
// caused it, so no later test can qualify the configured topology from the
// route tool any more. The prepared-route test therefore runs before every test
// that connects a socket, and reads this so that a reordering says exactly that
// instead of reporting the clone as a host nobody prepared.
//
// Windows clones nothing and would not need the ordering, but the invariant is
// the same one on both platforms and one test is easier to keep true than two.
var nativeSocketConnected bool

// TestNativePreparedTargetRouteMatchesTheHostRouteTool checks the route
// evidence netdoc publishes for a user-supplied target against the platform's
// own route tool, on a host where a route narrower than the default covers that
// target and leaves by a different interface. A hosted runner only ever routes
// to a default route, so the entry-level half of netdoc's reason vocabulary is
// never exercised there against real kernel data.
//
// The prepared state is observed, never created: this test reads routes and
// opens a connected datagram socket, and changes nothing about the host.
//
// The two observations are deliberately ordered. Asking the route tool changes
// nothing, but connecting a socket makes macOS clone a host route from the
// entry that matched, after which the route tool answers the clone. So the
// topology is qualified from route-tool readings taken before anything in this
// test or in netdoc connects to these destinations, and the connected socket
// that names the source comes last. Both oracles then describe the state
// netdoc itself looked at, since netdoc decides its route evidence before it
// dials.
//
// The same ordering is why this is the first test in the file: Go runs a
// package's tests in the order they are written, and every clone a socket in an
// earlier test left behind would still be there. nativeSocketConnected turns
// that from a silent dependency into a named one.
func TestNativePreparedTargetRouteMatchesTheHostRouteTool(t *testing.T) {
	raw, dst := preparedTarget(t)
	if nativeSocketConnected {
		t.Fatalf("a connected-socket observation already ran in this process, so on macOS %s now answers about these destinations from the route cache; this test has to run before every test that connects one", hostRouteTool)
	}
	reference := nativeReferenceFor(t, dst)
	dsts := []netip.Addr{dst, reference}
	bin := buildNetdoc(t)

	// Repeating a lookup that mutates nothing is what proves the configured
	// state is stable here. The old shape proved it by bracketing the netdoc run
	// with socket observations, which on macOS could only ever settle on the
	// cloned reading it had just caused.
	var host map[netip.Addr]hostRouteObservation
	for attempt := 1; attempt <= nativeObservationAttempts; attempt++ {
		first := hostRouteObservations(t, dsts)
		second := hostRouteObservations(t, dsts)
		if reflect.DeepEqual(first, second) {
			host = second
			break
		}
		t.Logf("%s route state changed during observation %d:\nfirst  %+v\nsecond %+v", hostRouteTool, attempt, first, second)
	}
	if host == nil {
		t.Fatalf("route state for %s and %s did not stay stable across %d bounded observations", dst, reference, nativeObservationAttempts)
	}

	// The topology is established by the operating system alone, before any
	// netdoc output is read. Opting in is a claim that this host is prepared,
	// so an unprepared one is a failure and never a skip.
	hostTarget, hostReference := host[dst].Route, host[reference].Route
	if !host[dst].Found {
		t.Fatalf("%s found no route to prepared target %s; set %s to a destination this host has a prepared route for", hostRouteTool, dst, preparedTargetEnv)
	}
	if !host[reference].Found {
		t.Fatalf("%s found no route to reference destination %s, so there is no general egress path to compare the prepared one against", hostRouteTool, reference)
	}
	if hostTarget.WasCloned || hostReference.WasCloned {
		t.Fatalf("%s answered for %s or %s with a host route the kernel cloned from a wider entry, so the configured topology is hidden behind the route cache rather than absent: something connected to one of these destinations earlier on this machine, and on macOS a clone of a gatewayed route outlives the process that caused it. Observed %+v and %+v",
			hostRouteTool, dst, reference, hostTarget, hostReference)
	}
	if !hostReference.Prefix.IsValid() || hostReference.Prefix.Bits() != 0 {
		t.Fatalf("%s matched entry %v for reference destination %s, want a true default route: this host is not in the default-plus-specific shape the test requires",
			hostRouteTool, hostReference.Prefix, reference)
	}
	if !hostTarget.Prefix.IsValid() || hostTarget.Prefix.Bits() == 0 {
		t.Fatalf("%s matched entry %v for prepared target %s, want a route narrower than the default: the prepared route is missing", hostRouteTool, hostTarget.Prefix, dst)
	}
	if hostTarget.Iface == hostReference.Iface {
		t.Fatalf("%s routes both prepared target %s and reference destination %s through %q; the prepared route must leave by a different interface",
			hostRouteTool, dst, reference, hostTarget.Iface)
	}
	// The exit code is deliberately ignored. A prepared destination with
	// nothing listening fails its TCP row and still carries the route evidence,
	// which is decided before any dial is attempted.
	got, _ := runNetdoc(t, bin, "--json", "--check", "target_tcp", raw)

	// Read the route tool again before this test opens any socket of its own, so
	// the only connection that could have changed these entries is netdoc's own
	// target dial.
	after := hostRouteObservations(t, dsts)
	for _, d := range dsts {
		assertRouteSurvivedRun(t, d, host[d].Route, after[d])
	}

	// Only now the connected socket, and only for the target. It is the
	// independent source oracle on macOS, where route -n get reports none, and
	// connecting it clones the entry it matched: moving it before the netdoc run
	// is what made this test unsatisfiable on Darwin. The reference is left
	// alone because nothing here reads a source for it, and the clone a socket
	// would leave on a gatewayed destination does not expire, which would break
	// the next run of this test on the same machine.
	kernel := kernelRouteObservations(t, []netip.Addr{dst})

	// netdoc's own reference evidence is checked against the oracle before it
	// is used as the other half of the split comparison, so that comparison
	// never rests on two readings of the same netdoc output.
	reported, ok := routesByDestination(t, reportCheck(t, got, "iface"))[reference]
	if !ok {
		t.Fatalf("the interface row carries no route to reference destination %s: %+v", reference, got.Checks)
	}
	if reported.Interface != hostReference.Iface {
		t.Fatalf("%s routes reference destination %s through %q, netdoc reported %q; the general egress path must agree before the prepared one is read against it",
			hostRouteTool, reference, hostReference.Iface, reported.Interface)
	}
	if entry := mustPrefix(t, reported.Prefix); entry != hostReference.Prefix {
		t.Fatalf("%s matched entry %v for reference destination %s, netdoc reported %q", hostRouteTool, hostReference.Prefix, reference, reported.Prefix)
	}

	// An IP literal resolves to exactly itself, so the target row describes one
	// address and there is no second decision to pick the convenient one from.
	targetRoutes := routesByDestination(t, reportCheck(t, got, "target_tcp"))
	r, ok := targetRoutes[dst]
	if !ok || len(targetRoutes) != 1 {
		t.Fatalf("the target row carries %+v, want exactly one route, to %s", targetRoutes, dst)
	}
	if r.Unreachable {
		t.Fatalf("%s routes %s through %q, but netdoc reported no route", hostRouteTool, dst, hostTarget.Iface)
	}
	if r.Interface != hostTarget.Iface {
		t.Errorf("%s routes %s through %q, netdoc reported %q", hostRouteTool, dst, hostTarget.Iface, r.Interface)
	}
	if entry := mustPrefix(t, r.Prefix); entry != hostTarget.Prefix {
		t.Errorf("%s matched entry %v for %s, netdoc reported %q", hostRouteTool, hostTarget.Prefix, dst, r.Prefix)
	}
	if gateway := optionalReportedAddr(t, r.Gateway); gateway != hostTarget.Gateway {
		t.Errorf("%s reports next hop %v for %s, netdoc reported %q", hostRouteTool, hostTarget.Gateway, dst, r.Gateway)
	}
	if hostTarget.Source.IsValid() {
		assertRouteToolSource(t, dst, r, hostTarget.Source)
	} else if observed := kernel[dst]; observed.Err == "" {
		// macOS route -n get reports no source, so the kernel's own selection
		// for a connected socket is the independent answer there.
		assertReportedSource(t, r, observed.Source, observed.Owners)
	} else {
		t.Errorf("neither %s nor a connected socket could name a source for %s: %s", hostRouteTool, dst, observed.Err)
	}
	if r.Interface == reported.Interface {
		t.Errorf("netdoc routed %s and reference destination %s through the same interface %q, while %s routes them through %q and %q",
			dst, reference, r.Interface, hostRouteTool, hostTarget.Iface, hostReference.Iface)
	}
	if want := expectedPreparedReason(hostTarget.Prefix); r.Reason != want {
		t.Errorf("netdoc explained %s as %q; the entry %s matched makes it %q", dst, r.Reason, hostTarget.Prefix, want)
	}
	assertLinkClassificationPresent(t, r)
	// Recorded rather than asserted. A correctly prepared WireGuard or utun
	// link commonly reports "likely" with no kind, and an Ethernet-shaped
	// virtual adapter reports "direct", so neither value can be ground truth
	// for whether a tunnel is present.
	t.Logf("prepared target %s via %q %s reason=%q tunnel=%q kind=%q mtu=%d; reference %s via %q %s",
		dst, r.Interface, r.Prefix, r.Reason, r.Tunnel, r.TunnelKind, r.InterfaceMTU, reference, reported.Interface, reported.Prefix)
}

// TestNativeBinaryUsesLoopbackInterface proves the release-shaped binary can
// resolve and inspect a real host interface, then run the host's SSID fallback.
func TestNativeBinaryUsesLoopbackInterface(t *testing.T) {
	bin := buildNetdoc(t)
	got, code := runNetdoc(t, bin, "--json", "--check", "iface,ssid", "--iface", "127.0.0.1", "--public-dns=")
	if code != 0 {
		t.Fatalf("netdoc exited %d, want 0 for a run whose checks all pass: %+v", code, got)
	}
	if len(got.Checks) != 2 {
		t.Fatalf("checks = %+v, want interface and SSID only", got.Checks)
	}
	checks := map[string]report.Check{}
	for _, check := range got.Checks {
		checks[check.ID] = check
	}
	iface := checks["iface"]
	if iface.Status != "PASS" || iface.Source != "127.0.0.1" || iface.Iface == "" {
		t.Errorf("interface check = %+v, want loopback source on a named host interface", iface)
	}
	if ssid := checks["ssid"]; ssid.Status != "N/A" || ssid.Network != "" {
		t.Errorf("SSID check on loopback = %+v, want N/A with no network", ssid)
	}
}

// TestNativeSelectedInterfaceIsTheOneTheKernelRoutesThrough checks netdoc's
// route evidence against the stack's source and interface selection. Connecting
// a UDP socket performs that selection locally and sends no datagram.
func TestNativeSelectedInterfaceIsTheOneTheKernelRoutesThrough(t *testing.T) {
	bin := buildNetdoc(t)
	var check report.Check
	var kernel map[netip.Addr]kernelRouteObservation
	for attempt := 1; attempt <= nativeObservationAttempts; attempt++ {
		before := kernelRouteObservations(t, nativeReferenceDestinations)
		check = nativeIfaceCheck(t, bin)
		after := kernelRouteObservations(t, nativeReferenceDestinations)
		if reflect.DeepEqual(before, after) {
			kernel = after
			break
		}
		t.Logf("kernel route/source state changed during observation %d: before=%+v after=%+v", attempt, before, after)
	}
	if kernel == nil {
		t.Fatalf("kernel route/source state did not stay stable across %d bounded observations", nativeObservationAttempts)
	}

	routes := referenceRoutes(t, check)
	var headlineDst netip.Addr
	for _, dst := range nativeReferenceDestinations {
		r := routes[dst]
		if !r.Unreachable && !headlineDst.IsValid() {
			headlineDst = dst
		}
		t.Run(dst.String(), func(t *testing.T) {
			observed := kernel[dst]
			if r.Unreachable {
				if observed.Err == "" {
					t.Fatalf("netdoc reported no route to %s, but the kernel selected source %s on %v", dst, observed.Source, observed.Owners)
				}
				return
			}
			if observed.Err != "" {
				t.Fatalf("netdoc reported a route to %s through %q, but a connected UDP socket selected no path: %s", dst, r.Interface, observed.Err)
			}
			if !slices.Contains(observed.Owners, r.Interface) {
				t.Fatalf("netdoc routed %s through %q, but the kernel sources it from %s, which is assigned to %v",
					dst, r.Interface, observed.Source, observed.Owners)
			}
			assertReportedSource(t, r, observed.Source, observed.Owners)
			assertLinkClassificationPresent(t, r)
		})
	}

	if !headlineDst.IsValid() {
		t.Fatalf("both independently selected reference destinations were unreachable: %+v", check.Routes)
	}
	routed, observed := routes[headlineDst], kernel[headlineDst]
	if observed.Err == "" && !slices.Contains(observed.Owners, check.Iface) {
		t.Errorf("the interface row names %q, but traffic to %s leaves from %s, which is assigned to %v",
			check.Iface, headlineDst, observed.Source, observed.Owners)
	}
	if check.Iface != routed.Interface {
		t.Errorf("the interface row names %q while its route evidence selected %q; the row must report the interface routing chose",
			check.Iface, routed.Interface)
	}
}

// TestNativeRouteEvidenceMatchesTheHostRouteTool checks route existence,
// interface, next hop, source where available, and matched prefix against the
// platform's route tool. The observation is made before and after netdoc so a
// legitimate route change is never mistaken for an adapter defect.
func TestNativeRouteEvidenceMatchesTheHostRouteTool(t *testing.T) {
	bin := buildNetdoc(t)
	var check report.Check
	var observed map[netip.Addr]hostRouteObservation
	for attempt := 1; attempt <= nativeObservationAttempts; attempt++ {
		before := hostRouteObservations(t, nativeReferenceDestinations)
		check = nativeIfaceCheck(t, bin)
		after := hostRouteObservations(t, nativeReferenceDestinations)
		if reflect.DeepEqual(before, after) {
			observed = after
			break
		}
		t.Logf("%s route state changed during observation %d: before=%+v after=%+v", hostRouteTool, attempt, before, after)
	}
	if observed == nil {
		t.Fatalf("%s route state did not stay stable across %d bounded observations", hostRouteTool, nativeObservationAttempts)
	}

	routes := referenceRoutes(t, check)
	reachable := 0
	for _, dst := range nativeReferenceDestinations {
		r, host := routes[dst], observed[dst]
		t.Run(dst.String(), func(t *testing.T) {
			if host.Found == r.Unreachable {
				if host.Found {
					t.Fatalf("%s found a route to %s through %q, but netdoc reported no route", hostRouteTool, dst, host.Route.Iface)
				}
				t.Fatalf("%s found no route to %s, but netdoc reported one through %q", hostRouteTool, dst, r.Interface)
			}
			if !host.Found {
				return
			}
			reachable++
			if host.Route.Iface != r.Interface {
				t.Errorf("%s routes %s through %q, netdoc reported %q", hostRouteTool, dst, host.Route.Iface, r.Interface)
			}
			if got := optionalReportedAddr(t, r.Gateway); got != host.Route.Gateway {
				t.Errorf("%s reports next hop %v for %s, netdoc reported %q", hostRouteTool, host.Route.Gateway, dst, r.Gateway)
			}
			if host.Route.Source.IsValid() {
				assertRouteToolSource(t, dst, r, host.Route.Source)
			}
			if !host.Route.Prefix.IsValid() {
				t.Fatalf("%s returned no matched prefix for reachable destination %s", hostRouteTool, dst)
			}
			if got := mustPrefix(t, r.Prefix); got != host.Route.Prefix {
				t.Errorf("%s matched route entry %v for %s, netdoc reported %q", hostRouteTool, host.Route.Prefix, dst, r.Prefix)
			}
		})
	}
	if reachable == 0 {
		t.Fatalf("no reachable reference route to check against %s: %+v", hostRouteTool, check.Routes)
	}
}

// preparedTarget reads the opt-in destination. Only an absent variable is a
// skip, and even that becomes a failure once the caller declared the prepared
// state present.
func preparedTarget(t *testing.T) (string, netip.Addr) {
	t.Helper()
	value, configured := os.LookupEnv(preparedTargetEnv)
	raw := strings.TrimSpace(value)
	if raw == "" {
		const need = "this test needs an externally prepared host where a route narrower than the default covers that IP literal and leaves by a different interface"
		// Present but blank is a configured case, not an absent one. A job
		// whose value expanded to nothing did ask for this run, and reading
		// that as a host nobody opted in on is how a configured case goes
		// green having quietly skipped, so it is read apart from unset.
		if configured {
			t.Fatalf("%s is set to %q, which names no destination: %s", preparedTargetEnv, value, need)
		}
		if os.Getenv(requirePreparedTargetEnv) == "1" {
			t.Fatalf("%s is set, so an absent %s is a failure rather than a skip: %s", requirePreparedTargetEnv, preparedTargetEnv, need)
		}
		t.Skipf("%s is not set: %s", preparedTargetEnv, need)
	}
	dst, err := preparedTargetAddr(raw)
	if err != nil {
		t.Fatalf("%s=%q: %v", preparedTargetEnv, value, err)
	}
	return raw, dst
}

// preparedTargetAddr accepts the destination in netdoc's own target grammar, so
// the spelling this test validates is the spelling the binary is given, and
// requires an IP literal: a name would let a resolver choose which route is
// under test, and the route decision being checked is made per address.
func preparedTargetAddr(raw string) (netip.Addr, error) {
	target, err := diagnostic.ParseTarget(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	if target.IP == nil {
		return netip.Addr{}, fmt.Errorf("%q is a hostname; the prepared route must be named by an IP literal such as 10.20.0.5, 10.20.0.5:443 or [2001:db8::5]:443", raw)
	}
	addr, ok := netip.AddrFromSlice(target.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%q parsed to an unusable address", raw)
	}
	return addr.Unmap().WithZone(""), nil
}

func nativeReferenceFor(t *testing.T, dst netip.Addr) netip.Addr {
	t.Helper()
	for _, reference := range nativeReferenceDestinations {
		if reference.Is4() == dst.Is4() {
			return reference
		}
	}
	t.Fatalf("no independently known reference destination for the address family of %s", dst)
	return netip.Addr{}
}

// expectedPreparedReason is the explanation the prepared topology forces, read
// off the matched entry the route tool reported rather than off netdoc.
//
// Only these two are reachable once the preconditions hold. Unreachable and
// default-route are excluded by the topology the oracle proved, and the
// lower-metric branch cannot apply because competing routes are recorded beside
// reference decisions only, never beside the per-address lookups a target row
// carries. This is why it can be two lines instead of a second copy of the
// production rule.
func expectedPreparedReason(matched netip.Prefix) string {
	if matched.Bits() == matched.Addr().BitLen() {
		return "host_route"
	}
	return "more_specific_than_default"
}

func TestNativePreparedTargetConfiguration(t *testing.T) {
	for _, raw := range []string{"10.20.0.5", "10.20.0.5:443", "[2001:db8::5]:443", "2001:db8::5"} {
		got, err := preparedTargetAddr(raw)
		if err != nil || !got.IsValid() {
			t.Errorf("preparedTargetAddr(%q) = %v, %v, want the literal it names", raw, got, err)
		}
	}
	for _, raw := range []string{"example.com", "example.com:443", "https://example.com", ""} {
		if got, err := preparedTargetAddr(raw); err == nil {
			t.Errorf("preparedTargetAddr(%q) = %v, want a rejection: a name would let a resolver choose the route under test", raw, got)
		}
	}
	for _, c := range []struct{ prefix, want string }{
		{"10.20.0.5/32", "host_route"},
		{"2001:db8::5/128", "host_route"},
		{"10.20.0.0/16", "more_specific_than_default"},
		{"2001:db8::/64", "more_specific_than_default"},
	} {
		if got := expectedPreparedReason(netip.MustParsePrefix(c.prefix)); got != c.want {
			t.Errorf("expectedPreparedReason(%s) = %q, want %q", c.prefix, got, c.want)
		}
	}
}

// assertRouteSurvivedRun checks that the entry qualified before the netdoc run
// still describes the destination after it. macOS clones a host route from
// whatever entry matched as soon as netdoc dials, so the clone is accepted, but
// only as a clone of the entry that was qualified: same interface, same next
// hop, same source, and covering exactly the destination that was queried.
// Every other change is a real one, and the comparisons that follow would be
// describing a topology that no longer exists.
//
// Provenance comes from the platform's own flag rather than from the prefix
// length, so a host route someone configured is never waved through as a clone.
func assertRouteSurvivedRun(t *testing.T, dst netip.Addr, qualified hostRoute, got hostRouteObservation) {
	t.Helper()
	if !got.Found {
		t.Fatalf("%s found no route to %s after the netdoc run, but matched %v before it", hostRouteTool, dst, qualified.Prefix)
	}
	if got.Route == qualified {
		return
	}
	cloned := qualified
	cloned.Prefix, cloned.WasCloned = netip.PrefixFrom(dst, dst.BitLen()), true
	if got.Route != cloned {
		t.Fatalf("%s matched %+v for %s after the netdoc run, want the entry qualified before it (%+v) or a host route cloned from that entry (%+v)",
			hostRouteTool, got.Route, dst, qualified, cloned)
	}
}

func assertRouteToolSource(t *testing.T, dst netip.Addr, r report.Route, hostSource netip.Addr) {
	t.Helper()
	reported := mustAddr(t, r.Source)
	if dst.Is4() {
		if reported != hostSource {
			t.Errorf("%s selects source %v for %s, netdoc reported %q", hostRouteTool, hostSource, dst, r.Source)
		}
		return
	}
	if holders := interfacesHolding(t, reported); !slices.Contains(holders, r.Interface) {
		t.Errorf("netdoc reported IPv6 source %s for %s on %q, but that address is assigned to %v; %s selected %s",
			reported, dst, r.Interface, holders, hostRouteTool, hostSource)
	}
}

// IPv4 is asserted exactly. IPv6 is deliberately weaker because privacy
// addressing can make a per-flow source differ from the stable interface
// address a route entry reports; both must still belong to the selected link.
func assertReportedSource(t *testing.T, r report.Route, kernel netip.Addr, owners []string) {
	t.Helper()
	if r.Source == "" {
		if runtime.GOOS == "windows" {
			t.Errorf("netdoc omitted the source address GetBestRoute2 supplies for %s", r.Destination)
		}
		return
	}
	source := mustAddr(t, r.Source)
	if kernel.Is4() {
		if source != kernel {
			t.Errorf("netdoc reported source %s for %s, the kernel selects %s", source, r.Destination, kernel)
		}
		return
	}
	if holders := interfacesHolding(t, source); !slices.Contains(holders, r.Interface) {
		t.Errorf("netdoc reported source %s for %s on %q, but that address is assigned to %v; kernel source %s is assigned to %v",
			source, r.Destination, r.Interface, holders, kernel, owners)
	}
}

// The runner does not prove whether an Ethernet-shaped virtual adapter carries
// a VPN, so this checks only the adapter contract: a selected real interface is
// classified, and a claimed known tunnel names its operating-system kind.
func assertLinkClassificationPresent(t *testing.T, r report.Route) {
	t.Helper()
	switch r.Tunnel {
	case "direct", "likely":
		if r.TunnelKind != "" {
			t.Errorf("netdoc reported tunnel=%q with unexpected kind %q on %q", r.Tunnel, r.TunnelKind, r.Interface)
		}
	case "tunnel":
		if r.TunnelKind == "" {
			t.Errorf("netdoc reported a known tunnel on %q without its operating-system kind", r.Interface)
		}
	default:
		t.Errorf("netdoc left the selected link %q unclassified: tunnel=%q kind=%q", r.Interface, r.Tunnel, r.TunnelKind)
	}
}

func kernelRouteObservations(t *testing.T, dsts []netip.Addr) map[netip.Addr]kernelRouteObservation {
	t.Helper()
	out := make(map[netip.Addr]kernelRouteObservation, len(dsts))
	for _, dst := range dsts {
		source, err := kernelEgressSource(t, dst)
		if err != nil {
			out[dst] = kernelRouteObservation{Err: err.Error()}
			continue
		}
		owners := interfacesHolding(t, source)
		sort.Strings(owners)
		out[dst] = kernelRouteObservation{Source: source, Owners: owners}
	}
	return out
}

func hostRouteObservations(t *testing.T, dsts []netip.Addr) map[netip.Addr]hostRouteObservation {
	t.Helper()
	out := make(map[netip.Addr]hostRouteObservation, len(dsts))
	for _, dst := range dsts {
		route, found := hostRouteLookup(t, dst)
		out[dst] = hostRouteObservation{Route: route, Found: found}
	}
	return out
}

// kernelEgressSource asks the operating system which local address it would
// use for dst. UDP connect performs route and source selection without writing
// application data.
func kernelEgressSource(t *testing.T, dst netip.Addr) (netip.Addr, error) {
	t.Helper()
	nativeSocketConnected = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", netip.AddrPortFrom(dst, 443).String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("local address %v is not a UDP address", conn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("connected socket selected invalid local address %v", local.IP)
	}
	return addr.Unmap().WithZone(""), nil
}

// interfacesHolding names every interface the address is assigned to. More
// than one is kept as an explicit ambiguity rather than resolved by order.
func interfacesHolding(t *testing.T, ip netip.Addr) []string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	var names []string
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if got, ok := netip.AddrFromSlice(ipnet.IP); ok && got.Unmap().WithZone("") == ip {
				names = append(names, ifi.Name)
				break
			}
		}
	}
	return names
}

// routesByDestination indexes one check's route evidence by destination. A
// duplicate or a family label that disagrees with the address it labels is a
// defect in the row itself, so both are caught here rather than by whichever
// caller happened to look.
func routesByDestination(t *testing.T, check report.Check) map[netip.Addr]report.Route {
	t.Helper()
	got := make(map[netip.Addr]report.Route, len(check.Routes))
	for _, r := range check.Routes {
		dst := mustAddr(t, r.Destination)
		if _, duplicate := got[dst]; duplicate {
			t.Fatalf("the %s row reported destination %s more than once", check.ID, dst)
		}
		family := "ipv6"
		if dst.Is4() {
			family = "ipv4"
		}
		if r.Family != family {
			t.Errorf("route to %s reports family %q, want %q", dst, r.Family, family)
		}
		got[dst] = r
	}
	return got
}

func referenceRoutes(t *testing.T, check report.Check) map[netip.Addr]report.Route {
	t.Helper()
	got := routesByDestination(t, check)
	// Equal counts plus every wanted destination present is what rules out an
	// extra one, so a production reference the oracle was never asked about
	// cannot slip through unexamined.
	if len(got) != len(nativeReferenceDestinations) {
		t.Fatalf("interface routes = %+v, want exactly the independently known reference destinations %v", check.Routes, nativeReferenceDestinations)
	}
	for _, dst := range nativeReferenceDestinations {
		if _, ok := got[dst]; !ok {
			t.Fatalf("interface row omitted independently selected reference destination %s", dst)
		}
	}
	return got
}

func nativeIfaceCheck(t *testing.T, bin string) report.Check {
	t.Helper()
	got, code := runNetdoc(t, bin, "--json", "--check", "iface")
	if code != 0 {
		t.Fatalf("netdoc exited %d for its interface-only run: %+v", code, got)
	}
	check := reportCheck(t, got, "iface")
	if check.Status != "PASS" {
		t.Fatalf("interface row = %+v, want PASS: this host has no usable interface to check", check)
	}
	return check
}

func reportCheck(t *testing.T, got report.Report, id string) report.Check {
	t.Helper()
	for _, check := range got.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("no %q row in %+v", id, got.Checks)
	return report.Check{}
}

func buildNetdoc(t *testing.T) string {
	t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	bin := filepath.Join(t.TempDir(), "netdoc"+suffix)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build netdoc: %v\n%s", err, out)
	}
	return bin
}

// runNetdoc returns a complete JSON report even when a diagnosis exits 1.
func runNetdoc(t *testing.T, bin string, args ...string) (report.Report, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run netdoc %v: %v\n%s", args, err, stderr.String())
		}
		if ctx.Err() != nil {
			t.Fatalf("run netdoc %v did not finish: %v\nstdout: %s\nstderr: %s", args, ctx.Err(), stdout.String(), stderr.String())
		}
		code = exit.ExitCode()
	}
	var got report.Report
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode report from netdoc %v: %v\nstdout: %s\nstderr: %s", args, err, stdout.String(), stderr.String())
	}
	return got, code
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("%q is not an IP address: %v", s, err)
	}
	return addr.Unmap().WithZone("")
}

func optionalReportedAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	if s == "" {
		return netip.Addr{}
	}
	return mustAddr(t, s)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("%q is not an IP prefix: %v", s, err)
	}
	return prefix
}
