package incident

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// The case this file is about is the one an incident report gets wrong most
// expensively: a probe stops connecting, every reading it took off that
// connection goes with it, and the report announces that the machine's path to
// the network moved. Nothing moved. The readings are gone because there was no
// socket to read them from.
//
// So the passes here are built out of typed probe results through the real
// snapshot producer, which is what decides that a failed target row carries no
// selected address. A hand-written snapshot could hold any combination of
// fields, including ones no probe can produce, and would prove nothing about
// what a watch session actually sees.

var (
	lanTarget = net.ParseIP("192.168.1.1")
	lanSource = net.ParseIP("192.168.1.10")
	// publicTarget is a fixed connectivity endpoint, which is what the direct
	// egress row dials rather than the run's own target.
	publicTarget = net.ParseIP("1.1.1.1")
)

// lanResolver is the nameserver the machine was handed. The dns row records
// every resolver it dialed whether or not one answered, so a pass and a
// failure both carry it, and a comparison of the two does not report it as
// having appeared.
const lanResolver = "192.168.1.1:53"

func producerPass(at time.Time, results map[diagnostic.ProbeID]diagnostic.ProbeResult) snapshot.Snapshot {
	// A hostname, not an IP literal. dnsProbe answers a literal from its first
	// branch, with N/A, no resolver targets and no routes, so a literal target
	// cannot produce the resolving dns row every pass here carries.
	target := &diagnostic.Target{Raw: "app.lan:9999", Host: "app.lan",
		Port: 9999, Proto: diagnostic.ProtoNone, PortExplicit: true}
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
	}
	// The Wi-Fi row is in the graph only for the passes that are about it, so
	// every other case here compares two runs that never asked the question.
	if _, ok := results[diagnostic.ProbeSSID]; ok {
		probes = append(probes, diagnostic.Probe{ID: diagnostic.ProbeSSID, Name: "Wi-Fi network",
			Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}})
	}
	// Direct egress hangs off the interface row and nothing hangs off it, which
	// is what lets a pass fail there while the target row keeps connecting.
	if _, ok := results[diagnostic.ProbeInternet]; ok {
		probes = append(probes, diagnostic.Probe{ID: diagnostic.ProbeInternet, Name: "Internet (TCP egress)",
			Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}})
	}
	probes = append(probes,
		diagnostic.Probe{ID: diagnostic.ProbeDNS, Name: "DNS app.lan", Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}},
		diagnostic.Probe{ID: diagnostic.ProbeDNSPublic, Name: "DNS (public 9.9.9.9)", Deps: []diagnostic.ProbeID{diagnostic.ProbeIface}},
		diagnostic.Probe{ID: diagnostic.ProbeTargetTCP, Name: "TCP app.lan:9999", Deps: []diagnostic.ProbeID{diagnostic.ProbeDNS}})
	s := diagnostic.BuildSnapshot(target, probes, results)
	s.Tool = snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"}
	s.CreatedAt = stamp(at)
	return s
}

// lanRoute is a decision for a destination on the attached network. Every
// route a probe records has been through routeReason, which answers on_link
// for a decision that names an interface and no gateway, so no recorded
// decision carries an empty reason.
func lanRoute(iface string, source net.IP) diagnostic.RouteDecision {
	return diagnostic.RouteDecision{Destination: lanTarget, Family: "ipv4", Iface: iface,
		Source: source, Reason: diagnostic.RouteReasonOnLink}
}

// tunnelRoute is the same for a destination inside the tunnel.
func tunnelRoute(dst net.IP, iface string, source net.IP) diagnostic.RouteDecision {
	return diagnostic.RouteDecision{Destination: dst, Family: "ipv4", Iface: iface,
		Source: source, Reason: diagnostic.RouteReasonOnLink}
}

func baseResults(iface string, source net.IP) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	return map[diagnostic.ProbeID]diagnostic.ProbeResult{
		// buildProbeGraph attaches referenceRouteDecisions to this row, on the
		// finished result. Those are the fixed direct-egress endpoints, one per
		// family, and never the destination the run was asked about.
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Dur: time.Millisecond,
			Iface: iface, Source: source, Routes: []diagnostic.RouteDecision{publicRoute(iface, source)}},
		diagnostic.ProbeDNS: {ID: diagnostic.ProbeDNS, Status: diagnostic.StatusPass, Dur: time.Millisecond,
			Addrs: []net.IP{lanTarget}, ResolverTargets: []string{lanResolver},
			Routes: []diagnostic.RouteDecision{lanRoute(iface, source)}},
		diagnostic.ProbeDNSPublic: {ID: diagnostic.ProbeDNSPublic, Status: diagnostic.StatusPass, Dur: time.Millisecond,
			Addrs: []net.IP{lanTarget}},
	}
}

// connectedPass is the reported case's before and recovered state: the socket
// established, so the row carries the address it used and the local end of the
// connection the kernel chose.
func connectedPass(at time.Time, iface string, source net.IP) snapshot.Snapshot {
	results := baseResults(iface, source)
	results[diagnostic.ProbeTargetTCP] = connectedTarget(iface, source)
	return producerPass(at, results)
}

// droppedPass is the reported failure onset: a firewall silently drops the
// handshake, the dial times out, and every observation only a live socket can
// supply is absent. The route the kernel would still take is not, because a
// route lookup needs no connection.
//
// The row carries no top-level cause. targetTCPProbe sets that field on one
// branch only, where every attempt was refused, so a timed-out row records its
// cause per attempt and nowhere else.
func droppedPass(at time.Time, iface string, source net.IP) snapshot.Snapshot {
	results := baseResults(iface, source)
	results[diagnostic.ProbeTargetTCP] = droppedTarget(iface, source)
	return producerPass(at, results)
}

// droppedTarget is that target row on its own, for a pass whose subject is
// some other row and which needs a failure to open an incident on.
func droppedTarget(iface string, source net.IP) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusFail, Dur: 4 * time.Second,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{lanRoute(iface, source)},
		Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 4 * time.Second,
			Err:   errors.New("dial tcp4 192.168.1.1:9999: i/o timeout"),
			Cause: diagnostic.ConnectionCauseTimeout}},
	}
}

// egressUp is the direct-egress row as internetProbe leaves a working run: the
// handshake completed, so it reports the address it settled on and the local
// end of that socket, and it attaches no route evidence at all. The lookup ran,
// its answer was simply never needed.
func egressUp(iface string, source net.IP) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID: diagnostic.ProbeInternet, Status: diagnostic.StatusPass, Dur: 5 * time.Millisecond,
		SelectedIP: publicTarget, Source: source, Iface: iface,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable},
		Attempts: []diagnostic.Attempt{{IP: publicTarget, Dur: 4 * time.Millisecond}},
	}
}

// egressDown is the same row with no address in either family connected. That
// is the one branch internetProbe attaches its route evidence on, so the route
// arrives here having been unchanged all along.
func egressDown(iface string, source net.IP) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID: diagnostic.ProbeInternet, Status: diagnostic.StatusFail, Dur: 4 * time.Second,
		Source: source, Iface: iface,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{publicRoute(iface, source)},
		Attempts: []diagnostic.Attempt{{IP: publicTarget, Dur: 4 * time.Second,
			Err:   errors.New("dial tcp4 1.1.1.1:443: i/o timeout"),
			Cause: diagnostic.ConnectionCauseTimeout}},
	}
}

// publicRoute is the run's reference path: where general Internet traffic
// goes. referenceRouteDecisions asks for exactly one destination per family,
// internetEndpoints4[0] and internetEndpoints6[0], so 1.1.1.1 is the only IPv4
// destination an iface row can carry, and the direct egress row dials the same
// endpoints.
func publicRoute(iface string, source net.IP) diagnostic.RouteDecision {
	return diagnostic.RouteDecision{Destination: publicTarget, Family: "ipv4",
		Iface: iface, Source: source, Prefix: netip.MustParsePrefix("0.0.0.0/0"),
		Reason: diagnostic.RouteReasonDefault}
}

// failedLookup is the dns row as dnsProbe leaves a lookup that did not come
// back. Every branch of that probe records the resolvers it dialed and the
// routes to them before it returns, so a failure carries both, and the answer
// is what is missing.
func failedLookup(cause string) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Dur: 2 * time.Second,
		Cause: cause, ResolverTargets: []string{lanResolver},
		Routes: []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
	}
}

func described(changes []compare.Change) string {
	lines := make([]string, len(changes))
	for i, c := range changes {
		lines[i] = "  " + c.Path + " [" + c.Kind + "] " + c.Summary
	}
	return strings.Join(lines, "\n")
}

func paths(changes []compare.Change) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.Path
	}
	return out
}

func has(changes []compare.Change, path string) bool {
	return slices.ContainsFunc(changes, func(c compare.Change) bool { return c.Path == path })
}

// onsetOf runs a two pass session and returns the incident the second pass
// opened, which is the only thing a watch session has to interpret.
func onsetOf(t *testing.T, before, onset snapshot.Snapshot, at time.Time) Incident {
	t.Helper()
	var timeline Timeline
	timeline.Observe(at, before)
	timeline.Observe(at.Add(5*time.Second), onset)
	i, ok := timeline.Latest()
	if !ok {
		t.Fatal("no incident opened")
	}
	if i.Before == nil {
		t.Fatal("incident opened with no earlier pass to compare against")
	}
	return i
}

func TestFailedProbeObservationLossIsNotAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource),
		droppedPass(at.Add(5*time.Second), "enp1s0", lanSource), at)

	// The raw comparison is evidence and stays whole. Every reading that went
	// away is still reported as having gone away.
	for _, path := range []string{
		"checks.target_tcp.observed.selected_ip",
		"checks.target_tcp.observed.source_ip",
		"checks.target_tcp.observed.interface",
	} {
		if !has(i.OnsetChanges, path) {
			t.Errorf("raw comparison dropped %s:\n%s", path, described(i.OnsetChanges))
		}
	}

	if env := Environment(i.OnsetChanges); len(env) != 0 {
		t.Errorf("readings lost with the socket classified as environment changes:\n%s", described(env))
	}

	// They are not discarded either. An outcome is where they belong, beside
	// the status, the attempt and the cause that explain them.
	outcome := Outcome(i.OnsetChanges)
	for _, path := range []string{
		"checks.target_tcp.status",
		// A timed-out row records its cause per attempt and nowhere else, so
		// that is where the explanation for the missing readings sits.
		"checks.target_tcp.observed.attempts.192.168.1.1.cause",
		"checks.target_tcp.observed.selected_ip",
		"checks.target_tcp.observed.source_ip",
		"checks.target_tcp.observed.interface",
		"checks.target_tcp.observed.address_families.ipv4",
	} {
		if !has(outcome, path) {
			t.Errorf("outcome evidence is missing %s:\n%s", path, described(outcome))
		}
	}
	if !slices.ContainsFunc(outcome, func(c compare.Change) bool {
		return strings.HasPrefix(c.Path, "checks.target_tcp.observed.attempts.")
	}) {
		t.Errorf("outcome evidence is missing the connection attempt:\n%s", described(outcome))
	}

	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
	if note := i.Note(); !strings.Contains(note, "No recorded change in how this machine reaches the network") {
		t.Errorf("note = %q, want the steady reading", note)
	}
}

// A degraded row that then fails loses the same readings for the same reason.
func TestWarnToFailObservationLossIsNotAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	warned := connectedPass(at, "enp1s0", lanSource)
	targetRow(t, &warned).Status = snapshot.StatusWarn
	warned.Diagnosis.Verdict = "degraded"

	i := onsetOf(t, warned, droppedPass(at.Add(5*time.Second), "enp1s0", lanSource), at)
	if env := Environment(i.OnsetChanges); len(env) != 0 {
		t.Errorf("WARN to FAIL observation loss classified as environment changes:\n%s", described(env))
	}
	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
}

// A tunnel comes up and the run's whole path moves with it: the reference
// route leaves by wg0, the resolver handed out on the tunnel answers the name
// with an address inside it, and the target row connects to that address from
// the tunnel's own source. Direct egress to the fixed connectivity endpoints is
// what the corporate gateway drops, which is the failure the incident opens on.
//
// Every one of those readings was recorded on both sides. A value that moved
// from one observation to another is an environment change however much
// outcome evidence sits beside it.
func TestObservedValueMovingStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	tunnelSource := net.ParseIP("10.8.0.6")
	tunnelTarget := net.ParseIP("10.8.0.20")
	const tunnelResolver = "10.8.0.1:53"

	// The target row stays PASS because it connected. targetTCPProbe reports
	// FAIL only where no address in either family came up, and a row that
	// reached that branch has no selected address to have moved.
	steady := baseResults("enp1s0", lanSource)
	steady[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
	steady[diagnostic.ProbeInternet] = egressUp("enp1s0", lanSource)
	before := producerPass(at, steady)

	moved := baseResults("wg0", tunnelSource)
	// dnsProbe records every resolver it dialed and the route to each, so the
	// row that answers over the tunnel names the tunnel's resolver and the path
	// to it. The answer is what the lookup returned.
	moved[diagnostic.ProbeDNS] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeDNS, Status: diagnostic.StatusPass, Dur: 2 * time.Millisecond,
		Addrs: []net.IP{tunnelTarget}, ResolverTargets: []string{tunnelResolver},
		Routes: []diagnostic.RouteDecision{tunnelRoute(net.ParseIP("10.8.0.1"), "wg0", tunnelSource)},
	}
	// targetTCPProbe looks up a route per resolved address, so the destinations
	// on this row are the addresses the dns row answered with and nothing else.
	moved[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond,
		SelectedIP: tunnelTarget, Source: tunnelSource, Iface: "wg0",
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable},
		Routes:   []diagnostic.RouteDecision{tunnelRoute(tunnelTarget, "wg0", tunnelSource)},
		Attempts: []diagnostic.Attempt{{IP: tunnelTarget, Dur: 2 * time.Millisecond}},
	}
	moved[diagnostic.ProbeInternet] = egressDown("wg0", tunnelSource)
	after := producerPass(at.Add(5*time.Second), moved)

	i := onsetOf(t, before, after, at)
	env := Environment(i.OnsetChanges)
	for _, path := range []string{
		"checks.target_tcp.observed.selected_ip",
		"checks.target_tcp.observed.source_ip",
		"checks.target_tcp.observed.interface",
		"paths.target.interface",
	} {
		if !has(env, path) {
			t.Errorf("a genuine move in %s was not classified as an environment change:\n%s", path, described(env))
		}
	}
	if i.Coincidence() != CoincidenceEnvironmentChanged {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
	}
	if note := i.Note(); !strings.Contains(note, "does not establish that one caused the other") {
		t.Errorf("note = %q, want the coincidence reading", note)
	}
}

// Nothing suppresses a reading on the strength of its being absent. Without a
// check that stopped working there is no explanation for the absence, and the
// comparison's own answer stands.
func TestObservationLostWithoutProbeFailureStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	// Direct egress stops working, which opens an incident. The target row keeps
	// connecting throughout, and simply stops being able to name the interface
	// its source address belongs to.
	//
	// The failing row is the direct egress one rather than the second-opinion
	// resolver, because publicDNSProbe answers an unreachable resolver with N/A
	// and an N/A row never takes a run into failure.
	connected := func(iface string) diagnostic.ProbeResult {
		return diagnostic.ProbeResult{
			ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond,
			SelectedIP: lanTarget, Source: lanSource, Iface: iface,
			Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable},
			Routes:   []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
			Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 2 * time.Millisecond}},
		}
	}
	steady := baseResults("enp1s0", lanSource)
	steady[diagnostic.ProbeInternet] = egressUp("enp1s0", lanSource)
	steady[diagnostic.ProbeTargetTCP] = connected("enp1s0")

	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeInternet] = egressDown("enp1s0", lanSource)
	results[diagnostic.ProbeTargetTCP] = connected("")
	after := producerPass(at.Add(5*time.Second), results)

	i := onsetOf(t, producerPass(at, steady), after, at)
	if !has(Environment(i.OnsetChanges), "checks.target_tcp.observed.interface") {
		t.Errorf("an interface reading lost by a still-passing check was suppressed:\n%s",
			described(i.OnsetChanges))
	}
}

// targetRow is the target check inside a built pass, found by ID so a change
// to the probe list cannot quietly point a test at another row.
func targetRow(t *testing.T, s *snapshot.Snapshot) *snapshot.Check {
	t.Helper()
	return rowOf(t, s, diagnostic.ProbeTargetTCP)
}

func rowOf(t *testing.T, s *snapshot.Snapshot, id diagnostic.ProbeID) *snapshot.Check {
	t.Helper()
	for i := range s.Checks {
		if s.Checks[i].ID == string(id) {
			return &s.Checks[i]
		}
	}
	t.Fatalf("pass has no %s row", id)
	return nil
}

// A row that fails but keeps reading its local end is the partial case: only
// what the socket owned is gone, and the rest is compared as usual.
//
// This has to be a dial the kernel answered. A timeout spends the probe's
// context before the fallback route lookup runs, so that row names nothing and
// has no local end left to have moved. A refused dial answers in milliseconds,
// the lookup still runs, and it can come back with a different source address
// than the run before it, which is the case this pins.
func TestPartialObservationLossSuppressesOnlyWhatWentMissing(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	movedSource := net.ParseIP("192.168.1.11")
	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusFail, Dur: 3 * time.Millisecond,
		Cause: diagnostic.ConnectionCauseRefused, Source: movedSource, Iface: "enp1s0",
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
		Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 2 * time.Millisecond,
			Err:   errors.New("dial tcp4 192.168.1.1:9999: connect: connection refused"),
			Cause: diagnostic.ConnectionCauseRefused}},
	}
	after := producerPass(at.Add(5*time.Second), results)

	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), after, at)
	env := Environment(i.OnsetChanges)
	if !has(env, "checks.target_tcp.observed.source_ip") {
		t.Errorf("a source address that moved while the check failed was suppressed:\n%s", described(i.OnsetChanges))
	}
	if has(env, "checks.target_tcp.observed.selected_ip") {
		t.Errorf("the selected address lost with the socket survived as an environment change:\n%s", described(env))
	}
	if got := paths(env); !slices.Equal(got, []string{"checks.target_tcp.observed.source_ip"}) {
		t.Errorf("environment changes = %v, want the source address alone", got)
	}
}

// Recovery is the mirror image: the socket comes back and brings its readings
// with it, which is the failure ending rather than the network moving.
func TestRecoveryReadingsReturningAreNotEnvironmentChanges(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	var timeline Timeline
	timeline.Observe(at, connectedPass(at, "enp1s0", lanSource))
	onset := at.Add(5 * time.Second)
	timeline.Observe(onset, droppedPass(onset, "enp1s0", lanSource))
	back := at.Add(37 * time.Second)
	timeline.Observe(back, connectedPass(back, "enp1s0", lanSource))

	incidents := timeline.Incidents()
	if len(incidents) != 1 {
		t.Fatalf("incidents = %d, want 1", len(incidents))
	}
	i := incidents[0]
	if i.Recovered == nil || len(i.RecoveryChanges) == 0 {
		t.Fatalf("no recovery comparison: recovered=%v changes=%d", i.Recovered, len(i.RecoveryChanges))
	}
	for _, path := range []string{
		"checks.target_tcp.observed.selected_ip",
		"checks.target_tcp.observed.source_ip",
		"checks.target_tcp.observed.interface",
	} {
		if !has(i.RecoveryChanges, path) {
			t.Errorf("raw recovery comparison dropped %s:\n%s", path, described(i.RecoveryChanges))
		}
	}
	if env := Environment(i.RecoveryChanges); len(env) != 0 {
		t.Errorf("readings returning with the socket classified as environment changes:\n%s", described(env))
	}

	// The onset reading does not depend on the recovery having happened, and
	// the before and recovered states agreeing is corroboration rather than
	// the basis for it.
	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
}

// What a failing row loses depends on how it failed, and the split has to hold
// for each shape the producer can actually emit.
//
// probe_target.go's failure path calls pathIdentity(ctx, nil, addrs[0], port),
// a connectionless route lookup that needs no socket. On a refused or
// unreachable dial the context is still live, so that lookup answers and the
// row keeps its source address and interface; only the address it would have
// settled on is gone, because that is written on the connected path alone. A
// dial that times out spends the context first, so there the lookup answers
// nothing and all three go.
func TestWhatAFailingRowLosesFollowsHowItFailed(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	for _, tc := range []struct {
		name string
		pass func(time.Time) snapshot.Snapshot
		kept []string
	}{
		{diagnostic.ConnectionCauseTimeout, func(a time.Time) snapshot.Snapshot {
			return droppedPass(a, "enp1s0", lanSource)
		}, nil},
		{diagnostic.ConnectionCauseRefused, func(a time.Time) snapshot.Snapshot {
			return answeredPass(a, "enp1s0", lanSource, diagnostic.ConnectionCauseRefused)
		}, []string{"checks.target_tcp.observed.source_ip", "checks.target_tcp.observed.interface"}},
		{diagnostic.ConnectionCauseUnreachable, func(a time.Time) snapshot.Snapshot {
			return answeredPass(a, "enp1s0", lanSource, diagnostic.ConnectionCauseUnreachable)
		}, []string{"checks.target_tcp.observed.source_ip", "checks.target_tcp.observed.interface"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), tc.pass(at.Add(5*time.Second)), at)
			if env := Environment(i.OnsetChanges); len(env) != 0 {
				t.Errorf("environment changes:\n%s", described(env))
			}
			if !has(Outcome(i.OnsetChanges), "checks.target_tcp.observed.selected_ip") {
				t.Errorf("the address lost with the socket is missing from the outcome:\n%s",
					described(i.OnsetChanges))
			}
			// A reading the row still took is not reported as having changed at
			// all, which is the difference this case exists to pin.
			for _, path := range tc.kept {
				if has(i.OnsetChanges, path) {
					t.Errorf("%s is reported as changed, but this failure shape still reads it:\n%s",
						path, described(i.OnsetChanges))
				}
			}
		})
	}
}

// answeredPass is a failure the kernel answered immediately: the dial is
// refused or the network is unreachable, the probe's context is still live,
// and the route lookup on its failure path still names the source address and
// interface it would have used.
//
// Only an all-refused row carries a top-level cause. targetTCPProbe sets that
// field inside the branch it takes when every attempt was refused and leaves it
// empty on the unreachable path below it, so the cause reaches the row through
// the attempt in both cases and through the row itself in one.
func answeredPass(at time.Time, iface string, source net.IP, cause string) snapshot.Snapshot {
	results := baseResults(iface, source)
	target := diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusFail, Dur: 3 * time.Millisecond,
		Source: source, Iface: iface,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{lanRoute(iface, source)},
		Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 2 * time.Millisecond,
			Err: errors.New("dial tcp4 192.168.1.1:9999: " + dialError(cause)), Cause: cause}},
	}
	if cause == diagnostic.ConnectionCauseRefused {
		target.Cause = cause
	}
	results[diagnostic.ProbeTargetTCP] = target
	return producerPass(at, results)
}

// dialError is the syscall text the kernel returns for each cause, so a fixture
// cannot claim one cause while carrying another's error.
func dialError(cause string) string {
	if cause == diagnostic.ConnectionCauseRefused {
		return "connect: connection refused"
	}
	return "connect: network is unreachable"
}

// A check that stops running records nothing at all, which is at least as good
// a reason for a missing reading as a check that ran and failed, and it is a
// better one: a row that never ran did not fail to read the routing table, it
// never looked. So everything it would have recorded goes, the readings it
// reads off the machine included, and so does the derived paths section that is
// read off the same row.
// Both ways a row goes dark are built the way the run produces them. A skip is
// the executor declining to start a probe whose prerequisite failed, so the
// resolver has to be failing beside it. INCOMPLETE is the status no probe can
// return: BuildSnapshot writes it for a row in the graph that reported no
// result at all, which is an absent entry rather than an edited one.
func TestUnrunCheckLosesItsReadingsWithoutMovingTheEnvironment(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	for _, status := range []string{snapshot.StatusSkip, snapshot.StatusIncomplete} {
		t.Run(status, func(t *testing.T) {
			results := baseResults("enp1s0", lanSource)
			results[diagnostic.ProbeDNS] = failedLookup(diagnostic.DNSCauseTimeout)
			if status == snapshot.StatusSkip {
				results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
					ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
					Detail: "skipped: a prerequisite failed"}
			}
			after := producerPass(at.Add(5*time.Second), results)
			if got := targetRow(t, &after).Status; got != status {
				t.Fatalf("target row status = %s, want %s", got, status)
			}

			i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), after, at)
			if env := Environment(i.OnsetChanges); len(env) != 0 {
				t.Errorf("readings lost with an unrun check were classified as environment changes:\n%s",
					described(env))
			}
			if !has(Outcome(i.OnsetChanges), "paths.target.interface") {
				t.Errorf("the derived target path is missing from the outcome:\n%s",
					described(i.OnsetChanges))
			}
		})
	}
}

// A dual-stack target gives the row two addresses to try, and which one it
// ends up on is a reading like any other. Moving between them while the socket
// still comes up is a move. Losing both families is not.
func TestDualStackSelectionMovesButIsNotLost(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	v6 := net.ParseIP("2001:db8::1")

	// egress is what fails beside the target row in the case where the target
	// row keeps connecting: something has to take the run into failure, and the
	// direct egress row is the one that can do it without skipping anything.
	dualStack := func(target diagnostic.ProbeResult, egress bool) snapshot.Snapshot {
		results := baseResults("enp1s0", lanSource)
		dns := results[diagnostic.ProbeDNS]
		dns.Addrs = []net.IP{v6, lanTarget}
		results[diagnostic.ProbeDNS] = dns
		public := results[diagnostic.ProbeDNSPublic]
		public.Addrs = []net.IP{v6, lanTarget}
		results[diagnostic.ProbeDNSPublic] = public
		if egress {
			results[diagnostic.ProbeInternet] = egressUp("enp1s0", lanSource)
		} else {
			results[diagnostic.ProbeInternet] = egressDown("enp1s0", lanSource)
		}
		results[diagnostic.ProbeTargetTCP] = target
		return producerPass(at.Add(5*time.Second), results)
	}
	connected := func(selected net.IP) diagnostic.ProbeResult {
		return diagnostic.ProbeResult{
			ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond,
			SelectedIP: selected, Source: lanSource, Iface: "enp1s0",
			Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable, IPv6: diagnostic.FamilyReachable},
			Routes:   []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
			Attempts: []diagnostic.Attempt{{IP: v6, Dur: time.Millisecond}, {IP: lanTarget, Dur: 2 * time.Millisecond}},
		}
	}
	bothFamiliesTimedOut := diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusFail, Dur: 4 * time.Second,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable, IPv6: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
		Attempts: []diagnostic.Attempt{
			{IP: v6, Dur: 2 * time.Second, Err: errors.New("dial tcp6 [2001:db8::1]:9999: i/o timeout"),
				Cause: diagnostic.ConnectionCauseTimeout},
			{IP: lanTarget, Dur: 2 * time.Second, Err: errors.New("dial tcp4 192.168.1.1:9999: i/o timeout"),
				Cause: diagnostic.ConnectionCauseTimeout},
		},
	}
	healthy := dualStack(connected(v6), true)

	// The row still connects, over the other family, while something else
	// takes the session into a failure. The address it uses genuinely moved.
	moved := onsetOf(t, healthy, dualStack(connected(lanTarget), false), at)
	if !has(Environment(moved.OnsetChanges), "checks.target_tcp.observed.selected_ip") {
		t.Errorf("a selected address that moved between families was not an environment change:\n%s",
			described(moved.OnsetChanges))
	}

	// Neither family connects, so there is no address left to report.
	lost := onsetOf(t, healthy, dualStack(bothFamiliesTimedOut, true), at)
	if env := Environment(lost.OnsetChanges); len(env) != 0 {
		t.Errorf("readings lost when both families failed were classified as environment changes:\n%s", described(env))
	}
	outcome := Outcome(lost.OnsetChanges)
	for _, path := range []string{
		"checks.target_tcp.observed.address_families.ipv4",
		"checks.target_tcp.observed.address_families.ipv6",
		"checks.target_tcp.observed.selected_ip",
	} {
		if !has(outcome, path) {
			t.Errorf("outcome evidence is missing %s:\n%s", path, described(outcome))
		}
	}
}

// Leaving a Wi-Fi network takes the ssid row from PASS to N/A and its reading
// with it, and that is the environment moving in the plainest sense the tool
// reports. N/A there is an answer, not an inability to answer: ssidProbe reads
// the radio's state, so it reports the same way whether the machine is on a
// network, on a cable, or on a link the platform will not name.
func TestLeavingAWiFiNetworkStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	for _, tc := range []struct{ name, before, after string }{
		{"left", "HomeWiFi", ""},
		{"joined", "", "HomeWiFi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := onsetOf(t, wifiPass(at, tc.before, false), wifiPass(at.Add(5*time.Second), tc.after, true), at)
			if !has(Environment(i.OnsetChanges), "checks.ssid.observed.ssid") {
				t.Errorf("the Wi-Fi network the machine is on was not an environment change:\n%s",
					described(i.OnsetChanges))
			}
			if i.Coincidence() != CoincidenceEnvironmentChanged {
				t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
			}
		})
	}
}

// wifiPass is a run with the Wi-Fi row in its graph. network is the name the
// radio reported, and empty is the N/A the probe returns when there is none.
func wifiPass(at time.Time, network string, failing bool) snapshot.Snapshot {
	results := baseResults("wlan0", lanSource)
	ssid := diagnostic.ProbeResult{ID: diagnostic.ProbeSSID, Status: diagnostic.StatusNA,
		Dur: time.Millisecond, Detail: "Wi-Fi network unavailable"}
	if network != "" {
		ssid = diagnostic.ProbeResult{ID: diagnostic.ProbeSSID, Status: diagnostic.StatusPass,
			Dur: time.Millisecond, Network: network, Detail: "connected to " + network}
	}
	results[diagnostic.ProbeSSID] = ssid
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond,
		SelectedIP: lanTarget, Source: lanSource, Iface: "wlan0",
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable},
		Routes:   []diagnostic.RouteDecision{lanRoute("wlan0", lanSource)},
		Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 2 * time.Millisecond}},
	}
	if failing {
		results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
			ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusFail, Dur: 4 * time.Second,
			Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
			Routes:   []diagnostic.RouteDecision{lanRoute("wlan0", lanSource)},
			Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 4 * time.Second,
				Err:   errors.New("dial tcp4 192.168.1.1:9999: i/o timeout"),
				Cause: diagnostic.ConnectionCauseTimeout}},
		}
	}
	return producerPass(at, results)
}

// The lease expires and the default route goes with it. The attached network
// still works, so the resolver still answers and the target row still
// connects; what the machine lost is the path to everything else, and the
// direct egress row fails for exactly that reason.
//
// The route evidence here is the run's reference paths, which is what the
// iface row carries: buildProbeGraph attaches referenceRouteDecisions to that
// row, and those name the fixed direct-egress endpoints rather than whatever
// destination the run was asked about. A machine with no route to them has a
// decision saying so, because the kernel answers ENETUNREACH and routeLookup
// records that as an unreachable decision rather than as no answer.
func TestLosingTheDefaultRouteStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	noRoute := diagnostic.RouteDecision{Destination: publicTarget, Family: "ipv4",
		Unreachable: true, Reason: diagnostic.RouteReasonNoRoute}

	steady := baseResults("enp1s0", lanSource)
	steady[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
	steady[diagnostic.ProbeInternet] = egressUp("enp1s0", lanSource)

	results := baseResults("enp1s0", lanSource)
	iface := results[diagnostic.ProbeIface]
	iface.Routes = []diagnostic.RouteDecision{noRoute}
	results[diagnostic.ProbeIface] = iface
	results[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
	// The direct egress row names no source and no interface here, and that is
	// the producer rather than the fixture: with no handshake, internetProbe
	// asks pathIdentity for the local end of an unconnected UDP socket to the
	// endpoint, and a destination with no route gives it nothing to report.
	results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeInternet, Status: diagnostic.StatusFail, Dur: 2 * time.Millisecond,
		Cause:    diagnostic.RouteCauseNoDefaultRoute,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyUnreachable},
		Routes:   []diagnostic.RouteDecision{noRoute},
		Attempts: []diagnostic.Attempt{{IP: publicTarget, Dur: time.Millisecond,
			Err:   errors.New("dial tcp4 1.1.1.1:443: connect: network is unreachable"),
			Cause: diagnostic.ConnectionCauseUnreachable}},
	}

	i := onsetOf(t, producerPass(at, steady), producerPass(at.Add(5*time.Second), results), at)
	env := Environment(i.OnsetChanges)
	for _, path := range []string{
		"checks.iface.observed.routes.1.1.1.1.interface",
		"checks.iface.observed.routes.1.1.1.1.source",
		"paths.reference.interface",
	} {
		if !has(env, path) {
			t.Errorf("%s was not classified as an environment change:\n%s", path, described(i.OnsetChanges))
		}
	}
	if i.Coincidence() != CoincidenceEnvironmentChanged {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
	}
}

// The nameservers the machine was handed are configuration the dns row copies
// off the system, and it records them on its failure path for exactly that
// reason: it names every resolver it dialed whether or not one answered. So a
// resolver list that empties is the machine's configuration changing, not the
// lookup that failed. The answer the lookup returned is the other way round.
func TestLosingTheConfiguredResolverStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	results := baseResults("enp1s0", lanSource)
	// The row records no resolver and no route to one. dnsProbe derives the
	// route decisions from the resolver targets it dialed, so a machine left
	// with no nameserver configured has neither to record.
	results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Dur: 2 * time.Second,
		Cause: diagnostic.DNSCauseTimeout,
	}
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
		Detail: "skipped: a prerequisite failed",
	}

	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), producerPass(at.Add(5*time.Second), results), at)
	env := Environment(i.OnsetChanges)
	if !has(env, "checks.dns.observed.resolver_targets."+lanResolver) {
		t.Errorf("the machine losing its configured resolver was not an environment change:\n%s",
			described(i.OnsetChanges))
	}
	if !has(env, "checks.dns.observed.routes.192.168.1.1") {
		t.Errorf("the route to the resolver going away was not an environment change:\n%s",
			described(i.OnsetChanges))
	}
	// What the lookup returned is the lookup's own outcome.
	if has(env, "checks.dns.observed.addresses.192.168.1.1") {
		t.Errorf("an address a failed lookup did not return was classified as an environment change:\n%s",
			described(env))
	}
}

// The interface row reads the interface list rather than a socket, so its
// interface and source address are what the machine has assigned. Both of its
// failures say so in as many words, and losing them is the event rather than a
// reading lost with a probe.
func TestInterfaceRowLosingItsAddressStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	// The interface row is the root of the graph, so a run that loses it skips
	// every row under it. It keeps its own routes: buildProbeGraph attaches the
	// reference paths outside ifaceProbe, on the finished result, so they are
	// recorded whatever the probe made of the interface list.
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusFail, Dur: time.Millisecond,
			Detail: "selected source address is no longer assigned",
			Fix:    "choose an active interface with --iface",
			Routes: []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)}},
		diagnostic.ProbeDNS: {ID: diagnostic.ProbeDNS, Status: diagnostic.StatusSkip,
			Detail: "skipped: Interface failed"},
		diagnostic.ProbeDNSPublic: {ID: diagnostic.ProbeDNSPublic, Status: diagnostic.StatusSkip,
			Detail: "skipped: Interface failed"},
		diagnostic.ProbeTargetTCP: {ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
			Detail: "skipped: Interface failed"},
	}

	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), producerPass(at.Add(5*time.Second), results), at)
	env := Environment(i.OnsetChanges)
	for _, path := range []string{
		"checks.iface.observed.interface",
		"checks.iface.observed.source_ip",
	} {
		if !has(env, path) {
			t.Errorf("%s was not classified as an environment change:\n%s", path, described(i.OnsetChanges))
		}
	}
	if i.Coincidence() != CoincidenceEnvironmentChanged {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
	}
}

// The shape the reported defect is most often seen in: the resolver stops
// answering, the target row never runs, and the derived paths section empties
// because it is read off the row that recorded nothing. Nothing about how this
// machine reaches the network moved, and the whole environment list has to say
// so, the derived section included.
func TestDNSOutageSkippingTheTargetRowLeavesTheEnvironmentSteady(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	results := baseResults("enp1s0", lanSource)
	// The resolvers and the routes to them both survive the failure in the
	// producer, so neither moved here.
	results[diagnostic.ProbeDNS] = failedLookup(diagnostic.DNSCauseTimeout)
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
		Detail: "skipped: a prerequisite failed",
	}

	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource), producerPass(at.Add(5*time.Second), results), at)
	if env := Environment(i.OnsetChanges); len(env) != 0 {
		t.Errorf("nothing about the path moved, yet the environment reports:\n%s", described(env))
	}
	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
	// The raw comparison still reports every one of them.
	outcome := Outcome(i.OnsetChanges)
	for _, path := range []string{
		"paths.target.interface",
		"paths.resolver.agreement",
		"checks.target_tcp.observed.routes.192.168.1.1",
		"checks.target_tcp.observed.interface",
	} {
		if !has(outcome, path) {
			t.Errorf("outcome evidence is missing %s:\n%s", path, described(i.OnsetChanges))
		}
	}
}

// The split is a partition of one comparison: every change is in exactly one
// half, in the comparison's own order, whatever the classification decided.
func TestEnvironmentAndOutcomePartitionEveryComparison(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	for name, i := range map[string]Incident{
		"timeout": onsetOf(t, connectedPass(at, "enp1s0", lanSource),
			droppedPass(at.Add(5*time.Second), "enp1s0", lanSource), at),
		"wifi": onsetOf(t, wifiPass(at, "HomeWiFi", false), wifiPass(at.Add(5*time.Second), "", true), at),
		"egress": onsetOf(t, producerPass(at, egressResults(egressUp("enp1s0", lanSource))),
			producerPass(at.Add(5*time.Second), egressResults(egressDown("enp1s0", lanSource))), at),
		"negative answer": onsetOf(t, connectedPass(at, "enp1s0", lanSource),
			producerPass(at.Add(5*time.Second), negativeAnswerResults()), at),
		"second opinion": onsetOf(t,
			publicDNSPass(t, at, answeredPublicLookup(), publicResolver, connectedTarget("enp1s0", lanSource)),
			publicDNSPass(t, at.Add(5*time.Second), diagnostic.ProbeResult{ID: diagnostic.ProbeDNSPublic,
				Status: diagnostic.StatusNA, Dur: time.Millisecond,
				ResolverTargets: []string{publicResolverTarget},
				Detail:          "no second opinion: this machine resolves 192.168.1.1 without DNS"},
				"", droppedTarget("enp1s0", lanSource)), at),
	} {
		t.Run(name, func(t *testing.T) {
			env, outcome := Environment(i.OnsetChanges), Outcome(i.OnsetChanges)
			if len(env)+len(outcome) != len(i.OnsetChanges) {
				t.Fatalf("%d environment + %d outcome changes, want %d",
					len(env), len(outcome), len(i.OnsetChanges))
			}
			var merged []compare.Change
			e, o := 0, 0
			for _, c := range i.OnsetChanges {
				if e < len(env) && env[e].Path == c.Path {
					merged, e = append(merged, env[e]), e+1
					continue
				}
				if o < len(outcome) && outcome[o].Path == c.Path {
					merged, o = append(merged, outcome[o]), o+1
				}
			}
			if !slices.Equal(paths(merged), paths(i.OnsetChanges)) {
				t.Errorf("the two halves do not interleave back into the comparison's order:\n%s",
					described(i.OnsetChanges))
			}
		})
	}
}

// pathProducers has to name every field the comparison's derived paths section
// can report, because a field missing from it is one no row owns and so one
// that can never be explained away. The comparison is the authority on what
// that section holds, so the list is checked against it rather than against a
// copy of it.
func TestEveryDerivedPathFieldNamesTheRowsItIsReadFrom(t *testing.T) {
	route := func(dst, iface, gateway, prefix, tunnel, reason string) snapshot.Route {
		return snapshot.Route{Destination: dst, Family: "ipv4", Interface: iface, Gateway: gateway,
			Prefix: prefix, Tunnel: tunnel, Reason: reason}
	}
	run := func(targetIface, referenceIface, resolverIface, tunnel, prefix, reason string) snapshot.Snapshot {
		return snapshot.Snapshot{
			Schema: snapshot.Schema, OK: true,
			Tool:      snapshot.Tool{Version: "dev", OS: "linux", Arch: "amd64"},
			CreatedAt: "2026-09-15T06:49:21Z",
			Target:    &snapshot.Target{Host: "192.168.1.1", Port: 9999, Protocol: "none"},
			Checks: []snapshot.Check{
				{ID: "iface", Status: snapshot.StatusPass, Ran: true,
					Observed: &snapshot.Observed{Routes: []snapshot.Route{route("1.1.1.1", referenceIface, "192.168.1.254", "0.0.0.0/0", "", "default route")}}},
				{ID: "dns", Status: snapshot.StatusPass, Ran: true,
					Observed: &snapshot.Observed{Routes: []snapshot.Route{route("192.168.1.1", resolverIface, "192.168.1.254", "0.0.0.0/0", "", "default route")}}},
				{ID: "target_tcp", Status: snapshot.StatusPass, Ran: true,
					Observed: &snapshot.Observed{SelectedIP: "192.168.1.1",
						Routes: []snapshot.Route{route("192.168.1.1", targetIface, "192.168.1.254", prefix, tunnel, reason)}}},
			},
		}
	}
	changes := compare.Snapshots(
		run("enp1s0", "enp1s0", "enp1s0", "", "0.0.0.0/0", "default route"),
		run("wg0", "wlan0", "wlan0", "wireguard", "10.0.0.0/8", "more specific route"),
	).Changes

	var seen int
	for _, c := range changes {
		if c.Section != compare.SectionPaths {
			continue
		}
		seen++
		if _, ok := pathProducers[c.Path]; !ok {
			t.Errorf("%s is a derived path field that pathProducers does not name a row for", c.Path)
		}
	}
	if seen != len(pathProducers) {
		t.Errorf("the comparison reported %d derived path fields, pathProducers names %d:\n%s",
			seen, len(pathProducers), described(changes))
	}
}

// The direct egress row starts its route lookup on every run and attaches the
// answer only where no address in either family connected. So the route to the
// connectivity endpoint arrives in the comparison at the moment egress breaks,
// unchanged and newly recorded, and reading that as the machine's routing
// having moved is the report announcing the producer's own branch as an event.
func TestInternetRouteEvidencePublishedOnlyOnFailureIsNotARouteChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	before := baseResults("enp1s0", lanSource)
	before[diagnostic.ProbeInternet] = egressUp("enp1s0", lanSource)
	before[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
	after := baseResults("enp1s0", lanSource)
	after[diagnostic.ProbeInternet] = egressDown("enp1s0", lanSource)
	after[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)

	i := onsetOf(t, producerPass(at, before), producerPass(at.Add(5*time.Second), after), at)

	// The raw comparison reports it, because it is a true statement about the
	// two files: one records the route and the other does not.
	if !has(i.OnsetChanges, "checks.internet_tcp.observed.routes."+publicTarget.String()) {
		t.Fatalf("raw comparison dropped the route evidence:\n%s", described(i.OnsetChanges))
	}
	if env := Environment(i.OnsetChanges); len(env) != 0 {
		t.Errorf("the environment claims a change built out of failure-only route evidence:\n%s",
			described(env))
	}
	if i.Coincidence() != CoincidenceEnvironmentSteady {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
	}
	// It is still evidence about the failure, and still reported as such.
	if !has(Outcome(i.OnsetChanges), "checks.internet_tcp.observed.routes."+publicTarget.String()) {
		t.Errorf("the route evidence is missing from the outcome:\n%s", described(i.OnsetChanges))
	}
}

// Only the reading arriving or leaving is the branch talking. Two runs that
// both took the branch that publishes it recorded the same field on both
// sides, so a route that differs between them differs because the machine's
// routing differs, and it stays an environment change like any other.
func TestInternetRouteThatMovesBetweenTwoFailingRunsStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	down := func(iface string, source net.IP) map[diagnostic.ProbeID]diagnostic.ProbeResult {
		results := baseResults(iface, source)
		results[diagnostic.ProbeInternet] = egressDown(iface, source)
		results[diagnostic.ProbeTargetTCP] = connectedTarget(iface, source)
		return results
	}
	// Both passes are failing, which is how an incident's later passes are
	// compared with the one that opened it.
	changes := compare.Snapshots(
		producerPass(at, down("enp1s0", lanSource)),
		producerPass(at.Add(5*time.Second), down("wg0", net.ParseIP("10.8.0.6"))),
	).Changes
	for _, path := range []string{
		"checks.internet_tcp.observed.routes." + publicTarget.String() + ".interface",
		"checks.internet_tcp.observed.routes." + publicTarget.String() + ".source",
	} {
		if !has(Environment(changes), path) {
			t.Errorf("a route that moved between two runs that both recorded it was suppressed at %s:\n%s",
				path, described(changes))
		}
	}
}

// connectedTarget is the target row of a run whose dial succeeded.
// egressResults is a run whose target row connects and whose direct egress row
// is whatever the caller hands it.
func egressResults(egress diagnostic.ProbeResult) map[diagnostic.ProbeID]diagnostic.ProbeResult {
	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeInternet] = egress
	results[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
	return results
}

// negativeAnswerResults is a run whose resolver answered that the name has no
// records, which skips the target row behind it.
func negativeAnswerResults() map[diagnostic.ProbeID]diagnostic.ProbeResult {
	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Dur: 8 * time.Millisecond,
		DNSNotFound: true, ResolverTargets: []string{lanResolver},
		Routes: []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
	}
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
		Detail: "skipped: a prerequisite failed"}
	return results
}

func connectedTarget(iface string, source net.IP) diagnostic.ProbeResult {
	return diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusPass, Dur: 3 * time.Millisecond,
		SelectedIP: lanTarget, Source: source, Iface: iface,
		Families: &diagnostic.FamilyConnectivity{IPv4: diagnostic.FamilyReachable},
		Routes:   []diagnostic.RouteDecision{lanRoute(iface, source)},
		Attempts: []diagnostic.Attempt{{IP: lanTarget, Dur: 2 * time.Millisecond}},
	}
}

// An empty address list means two different things and the row says which.
// A resolver that answered with no records did the work: the answer set moved
// from an address to none, which is a real change in what this machine
// resolves. A lookup that never came back reports the same empty list for the
// opposite reason, and that absence is the failure's own shadow.
func TestAnAnsweredNegativeLookupIsNotTheSameAsALookupThatNeverAnswered(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	skipped := diagnostic.ProbeResult{ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
		Detail: "skipped: a prerequisite failed"}

	for _, tc := range []struct {
		name        string
		dns         diagnostic.ProbeResult
		environment bool
	}{
		// dnsProbe reports the resolver's own answer: the name resolved to
		// nothing. It records the resolvers and the routes to them as always,
		// and sets the flag that says the lookup finished.
		{"answered with no records", diagnostic.ProbeResult{
			ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Dur: 8 * time.Millisecond,
			DNSNotFound: true, ResolverTargets: []string{lanResolver},
			Routes: []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
		}, true},
		// The same empty list, reached by never getting an answer at all.
		{"never answered", failedLookup(diagnostic.DNSCauseTimeout), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := baseResults("enp1s0", lanSource)
			results[diagnostic.ProbeDNS] = tc.dns
			results[diagnostic.ProbeTargetTCP] = skipped
			i := onsetOf(t, connectedPass(at, "enp1s0", lanSource),
				producerPass(at.Add(5*time.Second), results), at)

			const addresses = "checks.dns.observed.addresses." + "192.168.1.1"
			if !has(i.OnsetChanges, addresses) {
				t.Fatalf("raw comparison dropped the address removal:\n%s", described(i.OnsetChanges))
			}
			if got := has(Environment(i.OnsetChanges), addresses); got != tc.environment {
				t.Errorf("address removal in the environment = %v, want %v:\n%s",
					got, tc.environment, described(i.OnsetChanges))
			}
		})
	}
}

// The evidence the reading above turns on is the row's own, and it stays in
// the comparison where a reader can check the same thing.
func TestACompletedNegativeAnswerReportsThatItCompleted(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeDNS] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Dur: 8 * time.Millisecond,
		DNSNotFound: true, ResolverTargets: []string{lanResolver},
		Routes: []diagnostic.RouteDecision{lanRoute("enp1s0", lanSource)},
	}
	results[diagnostic.ProbeTargetTCP] = diagnostic.ProbeResult{
		ID: diagnostic.ProbeTargetTCP, Status: diagnostic.StatusSkip,
		Detail: "skipped: a prerequisite failed"}

	i := onsetOf(t, connectedPass(at, "enp1s0", lanSource),
		producerPass(at.Add(5*time.Second), results), at)
	if !has(i.OnsetChanges, "checks.dns.observed.dns_not_found") {
		t.Errorf("the comparison does not report that the lookup completed with no records:\n%s",
			described(i.OnsetChanges))
	}
	if i.Coincidence() != CoincidenceEnvironmentChanged {
		t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentChanged)
	}
}

// An answer set that moves from one address to another is the plainest case of
// all: both runs resolved the name, and to different things.
func TestAnAnswerSetMovingBetweenAddressesStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	moved := net.ParseIP("192.168.1.2")
	resolving := func(to net.IP, egress diagnostic.ProbeResult) snapshot.Snapshot {
		results := baseResults("enp1s0", lanSource)
		dns := results[diagnostic.ProbeDNS]
		dns.Addrs = []net.IP{to}
		results[diagnostic.ProbeDNS] = dns
		public := results[diagnostic.ProbeDNSPublic]
		public.Addrs = []net.IP{to}
		results[diagnostic.ProbeDNSPublic] = public
		results[diagnostic.ProbeInternet] = egress
		results[diagnostic.ProbeTargetTCP] = connectedTarget("enp1s0", lanSource)
		return producerPass(at.Add(5*time.Second), results)
	}
	i := onsetOf(t, resolving(lanTarget, egressUp("enp1s0", lanSource)),
		resolving(moved, egressDown("enp1s0", lanSource)), at)
	for _, path := range []string{
		"checks.dns.observed.addresses." + lanTarget.String(),
		"checks.dns.observed.addresses." + moved.String(),
	} {
		if !has(Environment(i.OnsetChanges), path) {
			t.Errorf("an answer set that moved was not an environment change at %s:\n%s",
				path, described(i.OnsetChanges))
		}
	}
}

// publicResolver is the second-opinion server this run queried, and
// publicResolverTarget is the address it was dialed at. A row that names the
// resolver names the target it reached it through as well.
const (
	publicResolver       = "9.9.9.9"
	publicResolverTarget = "9.9.9.9:53"
)

// answeredPublicLookup is the second-opinion row as publicDNSAttempt leaves a
// resolver that answered: the addresses it supplied and the target dialed to
// get them. Which resolver that was is set on the finished snapshot, because
// ProbeResult carries it in an unexported field.
func answeredPublicLookup() diagnostic.ProbeResult {
	return diagnostic.ProbeResult{ID: diagnostic.ProbeDNSPublic, Status: diagnostic.StatusPass,
		Dur: time.Millisecond, Addrs: []net.IP{lanTarget},
		ResolverTargets: []string{publicResolverTarget}}
}

// publicDNSPass is a run whose second-opinion row is whatever the caller hands
// it, named with the resolver the finished row would carry, and whose target
// row decides whether the pass is healthy.
func publicDNSPass(t *testing.T, at time.Time, public diagnostic.ProbeResult, resolver string,
	target diagnostic.ProbeResult) snapshot.Snapshot {
	t.Helper()
	results := baseResults("enp1s0", lanSource)
	results[diagnostic.ProbeDNSPublic] = public
	results[diagnostic.ProbeTargetTCP] = target
	s := producerPass(at, results)
	if resolver != "" {
		row := rowOf(t, &s, diagnostic.ProbeDNSPublic)
		if row.Observed == nil {
			row.Observed = &snapshot.Observed{}
		}
		row.Observed.Resolver = resolver
	}
	return s
}

// The second-opinion row names the resolver it queried on the branches that
// have an answer to attribute, and on two of its N/A branches it has none. The
// resolver is unchanged across all of them: the run asked the same server and
// came away with nothing it could attribute, so the field leaving the row is
// the branch it took rather than the machine's second opinion moving.
func TestPublicResolverPublishedOnlyOnSomeBranchesIsNotAResolverChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	cases := []struct {
		name string
		row  diagnostic.ProbeResult
		// keptTargets is whether that branch still records what it dialed.
		keptTargets bool
	}{{
		// The public server really was queried. The hosts file answered the
		// same name, so its answer cannot be told from the server's and the
		// row declines to attribute one, keeping the target it dialed.
		name: "hosts file answered the name",
		row: diagnostic.ProbeResult{ID: diagnostic.ProbeDNSPublic, Status: diagnostic.StatusNA,
			Dur:             time.Millisecond,
			ResolverTargets: []string{publicResolverTarget},
			Detail: "no second opinion: this machine resolves 192.168.1.1 without DNS, " +
				"so a local override cannot be told from " + publicResolver + "'s answer"},
		keptTargets: true,
	}, {
		// No query left the machine, so the row has neither an answer to
		// attribute nor a target to report.
		name: "no query left the machine",
		row: diagnostic.ProbeResult{ID: diagnostic.ProbeDNSPublic, Status: diagnostic.StatusNA,
			Dur: time.Millisecond, Detail: "lookup completed without querying public DNS"},
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := publicDNSPass(t, at, answeredPublicLookup(), publicResolver,
				connectedTarget("enp1s0", lanSource))
			// An independent target failure opens the incident, so nothing
			// about the second-opinion row is what is being explained.
			onset := publicDNSPass(t, at.Add(5*time.Second), tc.row, "",
				droppedTarget("enp1s0", lanSource))
			i := onsetOf(t, before, onset, at)

			// True of the two files: one names a resolver, the other does not.
			if !has(i.OnsetChanges, "checks.dns_public.observed.resolver") {
				t.Fatalf("raw comparison dropped the resolver evidence:\n%s", described(i.OnsetChanges))
			}
			if has(Environment(i.OnsetChanges), "checks.dns_public.observed.resolver") {
				t.Errorf("a resolver the run never stopped querying was reported as an environment change:\n%s",
					described(Environment(i.OnsetChanges)))
			}
			if !has(Outcome(i.OnsetChanges), "checks.dns_public.observed.resolver") {
				t.Errorf("the resolver evidence is missing from the outcome:\n%s", described(i.OnsetChanges))
			}
			// What this run dialed is its own evidence, and it is not what
			// this policy is about. A branch that keeps its targets reports
			// them unchanged, and a branch that stops dialing anything is the
			// machine declining to ask, which stays an environment change.
			targets := "checks.dns_public.observed.resolver_targets." + publicResolverTarget
			env := Environment(i.OnsetChanges)
			if tc.keptTargets {
				if has(i.OnsetChanges, targets) {
					t.Errorf("a resolver target recorded on both sides was reported as a change:\n%s",
						described(i.OnsetChanges))
				}
				if len(env) != 0 {
					t.Errorf("the environment claims a change built out of branch-only evidence:\n%s",
						described(env))
				}
				if i.Coincidence() != CoincidenceEnvironmentSteady {
					t.Errorf("coincidence = %s, want %s", i.Coincidence(), CoincidenceEnvironmentSteady)
				}
				return
			}
			if !has(env, targets) {
				t.Errorf("a query that stopped leaving the machine was not an environment change:\n%s",
					described(i.OnsetChanges))
			}
			if len(env) != 1 {
				t.Errorf("the environment claims more than the query that stopped leaving the machine:\n%s",
					described(env))
			}
		})
	}
}

// Both runs named a resolver, so both were on a branch that publishes one, and
// a second opinion that moved from one server to another moved for real.
func TestPublicResolverMovingBetweenTwoRunsStaysAnEnvironmentChange(t *testing.T) {
	at := time.Date(2026, 9, 15, 6, 49, 21, 0, time.UTC)
	fallback := "149.112.112.112"
	after := answeredPublicLookup()
	after.ResolverTargets = []string{fallback + ":53"}

	i := onsetOf(t,
		publicDNSPass(t, at, answeredPublicLookup(), publicResolver, connectedTarget("enp1s0", lanSource)),
		publicDNSPass(t, at.Add(5*time.Second), after, fallback, droppedTarget("enp1s0", lanSource)),
		at)

	env := Environment(i.OnsetChanges)
	if !has(env, "checks.dns_public.observed.resolver") {
		t.Errorf("a second opinion that moved between two runs that both named one was suppressed:\n%s",
			described(i.OnsetChanges))
	}
	for _, path := range []string{
		"checks.dns_public.observed.resolver_targets." + publicResolverTarget,
		"checks.dns_public.observed.resolver_targets." + fallback + ":53",
	} {
		if !has(env, path) {
			t.Errorf("the resolver target evidence at %s was suppressed:\n%s", path, described(i.OnsetChanges))
		}
	}
}
