package diagnostic

import (
	"context"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// watchNet is the network a Watch session is run against. Its graph has the
// production rows and dependencies, and each row is a fake that passes unless a
// fault says otherwise. Every run is counted, so a test can say which rows a
// pass executed and which it answered from the session.
type watchNet struct {
	iface      string
	addr       net.IP // the system resolver's answer, and the target's address
	publicAddr net.IP // the public resolver's answer
	gateway    net.IP // the default route's next hop
	// targetTunnel is the state of the route to the target alone, so a split
	// tunnel can change the target's path while the interface stays the same.
	targetTunnel TunnelState
	ifaceDown    bool
	targetDown   bool
	tlsBroken    bool
	// quicBroken fails the QUIC row alone. Its route footprint is one no fresh row
	// reads, so turning it on changes no path key and no interface fingerprint.
	quicBroken bool
	// broken names one row that fails on every run. A path test breaks a single
	// row, so the other rows stay as they were and the verdict gate cannot mask
	// the result under test.
	broken ProbeID
	// tlsRoutes gives the reusable TLS row a route, as a row may carry one.
	tlsRoutes bool
	counts    *watchCounts
}

type watchCounts struct {
	mu   sync.Mutex
	runs map[ProbeID]int // executions since the last resetRuns
	all  map[ProbeID]int // every execution, including attempts a pass rejected
}

func newWatchCounts() *watchCounts {
	return &watchCounts{runs: map[ProbeID]int{}, all: map[ProbeID]int{}}
}

func newWatchNet() *watchNet {
	return &watchNet{
		iface:        "eth0",
		addr:         net.ParseIP("198.51.100.7"),
		publicAddr:   net.ParseIP("198.51.100.53"),
		gateway:      net.ParseIP("192.0.2.1"),
		targetTunnel: TunnelDirect,
		counts:       newWatchCounts(),
	}
}

func watchTarget() *Target {
	return &Target{Host: "example.test", Port: 443, Proto: ProtoTLSHTTP}
}

// watchIDs is the production row set for watchTarget, in graph order.
func watchIDs() []ProbeID {
	var ids []ProbeID
	for _, p := range ProbePlan(watchTarget(), DefaultPublicDNS, true) {
		ids = append(ids, p.ID)
	}
	return ids
}

// graph is the production row shape with each row replaced by a fake. Each
// fake reports a duration, so a reused row that wrongly kept one would show it.
func (n *watchNet) graph() []Probe {
	probes := ProbePlan(watchTarget(), DefaultPublicDNS, true)
	for i := range probes {
		id := probes[i].ID
		probes[i].Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			n.counts.mu.Lock()
			n.counts.runs[id]++
			n.counts.all[id]++
			n.counts.mu.Unlock()
			return n.result(id)
		}
	}
	return probes
}

func (n *watchNet) result(id ProbeID) ProbeResult {
	switch {
	case id == ProbeIface && n.ifaceDown:
		return ProbeResult{Status: StatusFail, Cause: "no-link", Dur: 5 * time.Millisecond}
	case id == ProbeTargetTCP && n.targetDown:
		return ProbeResult{Status: StatusFail, Cause: "timeout", Dur: 5 * time.Millisecond}
	case id == ProbeTLS && n.tlsBroken:
		return ProbeResult{Status: StatusFail, Cause: "tls-handshake", Dur: 5 * time.Millisecond}
	case id == ProbeQUIC && n.quicBroken:
		return ProbeResult{Status: StatusFail, Cause: "timeout", Dur: 5 * time.Millisecond}
	case n.broken != "" && id == n.broken:
		return ProbeResult{Status: StatusFail, Cause: "broken-on-new-path", Dur: 5 * time.Millisecond}
	}
	r := ProbeResult{Status: StatusPass, Dur: 5 * time.Millisecond}
	// The fake's routes leave out the interface name, so each path test isolates
	// the one input it changes. Production routes carry it, and both are checked.
	switch id {
	case ProbeIface:
		r.Iface = n.iface
	case ProbeDNS:
		r.Addrs = []net.IP{n.addr}
	case ProbeDNSPublic:
		r.Addrs = []net.IP{n.publicAddr}
	case ProbeInternet:
		r.Routes = []RouteDecision{{Destination: n.publicAddr, Family: "ipv4", Gateway: n.gateway, Tunnel: TunnelDirect}}
	case ProbeTargetTCP:
		r.Iface, r.SelectedIP = n.iface, n.addr
		r.Routes = []RouteDecision{{Destination: n.addr, Family: "ipv4", Gateway: n.gateway, Tunnel: n.targetTunnel}}
	case ProbeTLS:
		if n.tlsRoutes {
			r.Routes = []RouteDecision{{Destination: n.addr, Family: "ipv4", Gateway: n.gateway, Tunnel: n.targetTunnel}}
		}
	}
	return r
}

// resetRuns starts the count for the next measurement.
func (n *watchNet) resetRuns() {
	n.counts.mu.Lock()
	n.counts.runs = map[ProbeID]int{}
	n.counts.mu.Unlock()
}

// allRuns returns every execution so far, across all attempts of all passes.
func (n *watchNet) allRuns() map[ProbeID]int {
	n.counts.mu.Lock()
	defer n.counts.mu.Unlock()
	out := make(map[ProbeID]int, len(n.counts.all))
	for id, c := range n.counts.all {
		out[id] = c
	}
	return out
}

func (n *watchNet) snapshotRuns() map[ProbeID]int {
	n.counts.mu.Lock()
	defer n.counts.mu.Unlock()
	out := make(map[ProbeID]int, len(n.counts.runs))
	for id, c := range n.counts.runs {
		out[id] = c
	}
	return out
}

type watchClock struct{ now time.Time }

func newWatchClock() *watchClock {
	return &watchClock{now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *watchClock) Now() time.Time { return c.now }

func (c *watchClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// watchPass runs one Watch pass the way both front ends do: a pass that is not
// published is followed at once by the next one, which runs fresh. It returns
// the published results, the executions of the published pass, and how many
// passes ran.
func watchPass(t *testing.T, s *WatchSession, n *watchNet) (map[ProbeID]ProbeResult, map[ProbeID]int, int) {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		n.resetRuns()
		pass := s.Begin(n.graph())
		results := RunAll(context.Background(), pass.Probes(), time.Second)
		if pass.Publish(results) {
			return results, n.snapshotRuns(), attempt
		}
	}
	t.Fatal("a fresh pass was not published")
	return nil, nil, 0
}

// assertFreshDiagnosis checks that a published pass explains the network the
// way a pass that reads everything fresh does. The fresh pass runs on a twin of
// the network, so its executions do not count against the pass under test.
func assertFreshDiagnosis(t *testing.T, n *watchNet, published map[ProbeID]ProbeResult) {
	t.Helper()
	twin := *n
	twin.counts = newWatchCounts()
	probes := twin.graph()
	fresh := RunAll(context.Background(), probes, time.Second)
	want := Interpret(watchTarget(), ProbeOrder(probes), fresh)
	got := Interpret(watchTarget(), ProbeOrder(probes), published)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("published diagnosis differs from a fresh pass:\n got  %+v\n want %+v", got, want)
	}
}

func TestWatchFirstPassRunsEveryRow(t *testing.T) {
	n := newWatchNet()
	s := NewWatchSession(newWatchClock().Now)
	res, runs, passes := watchPass(t, s, n)
	if passes != 1 {
		t.Fatalf("first pass took %d attempts, want 1", passes)
	}
	for _, id := range watchIDs() {
		if runs[id] != 1 {
			t.Errorf("first pass ran %s %d times, want 1", id, runs[id])
		}
	}
	assertFreshDiagnosis(t, n, res)
}

// A failure is measured in full, and so is the recovery that closes it. After a
// pass that is not OK, the session reuses nothing until a pass is OK again.
func TestWatchUnsettledSessionRunsEveryRowUntilRecovery(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)
	clock.Advance(5 * time.Second)
	watchPass(t, s, n)

	n.targetDown = true
	for pass := 1; pass <= 3; pass++ {
		clock.Advance(5 * time.Second)
		res, runs, attempts := watchPass(t, s, n)
		if pass == 1 && attempts != 2 {
			t.Errorf("failure took %d attempts, want 2: the reused pass that saw it is discarded", attempts)
		}
		if got := res[ProbeTargetTCP].Status; got != StatusFail {
			t.Fatalf("failing pass %d published target TCP as %v", pass, got)
		}
		for _, id := range watchIDs() {
			if _, reused := res[id].ReusedFrom(); reused {
				t.Errorf("failing pass %d reused %s", pass, id)
			}
			// A row behind the failed target connect is skipped, not run, so only
			// the rows that were scheduled must have run.
			if res[id].Status != StatusSkip && runs[id] != 1 {
				t.Errorf("failing pass %d ran %s %d times, want 1", pass, id, runs[id])
			}
		}
	}

	n.targetDown = false
	clock.Advance(5 * time.Second)
	res, runs, _ := watchPass(t, s, n)
	for _, id := range watchIDs() {
		if runs[id] != 1 {
			t.Errorf("recovery pass ran %s %d times, want 1", id, runs[id])
		}
	}
	if got := res[ProbeTargetTCP].Status; got != StatusPass {
		t.Errorf("recovery pass published target TCP as %v", got)
	}
	assertFreshDiagnosis(t, n, res)
}

func TestWatchStablePassRunsOnlyFreshRows(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(5 * time.Second)
	res, runs, passes := watchPass(t, s, n)
	if passes != 1 {
		t.Fatalf("stable pass took %d attempts, want 1", passes)
	}
	for _, id := range watchIDs() {
		want := 1
		if watchReusable[id] {
			want = 0
		}
		if runs[id] != want {
			t.Errorf("stable pass ran %s %d times, want %d", id, runs[id], want)
		}
	}
	if got := res[ProbeTLS]; got.Status != StatusPass || got.Dur != 0 {
		t.Errorf("reused TLS row = status %v dur %v, want pass with no duration for a row that did not run", got.Status, got.Dur)
	}
	if got := res[ProbeIface]; got.Dur == 0 {
		t.Error("fresh interface row lost its duration")
	}
	assertFreshDiagnosis(t, n, res)
}

func TestWatchReusedRowExpiresAtMaxAge(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(watchMaxAge - 5*time.Second)
	_, runs, _ := watchPass(t, s, n)
	if runs[ProbeTLS] != 0 {
		t.Fatalf("TLS re-ran %v after sampling, inside max age", watchMaxAge-5*time.Second)
	}

	clock.Advance(5 * time.Second)
	_, runs, _ = watchPass(t, s, n)
	if runs[ProbeTLS] != 1 {
		t.Fatalf("TLS ran %d times at exactly max age, want 1", runs[ProbeTLS])
	}
}

// Path MTU sends its payload on every pass, and that transfer is the measurement,
// so a stable pass must send it again rather than reuse the last answer.
func TestWatchPathMTUMeasuresEveryPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	for pass := 1; pass <= 3; pass++ {
		clock.Advance(5 * time.Second)
		_, runs, _ := watchPass(t, s, n)
		if runs[ProbePMTU] != 1 {
			t.Errorf("stable pass %d ran path MTU %d times, want 1", pass, runs[ProbePMTU])
		}
	}
}

// A route change moves the interface and the target's path. The rows that were
// sampled through a changed row run again, and rows whose inputs did not change
// keep their evidence. The published pass stays a lightweight one because no
// status or cause changed.
// An interface change reaches every row that reads the interface, directly or
// through a row whose result is identical. HTTP reads DNS and HTTPS reads TLS,
// and both can return the same result on the new path, so neither may be reused.
// This expectation changed on reviewer request: HTTP and HTTPS were reused here.
func TestWatchInterfaceChangeRunsEveryPathRow(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.iface = "wlan0"
	clock.Advance(5 * time.Second)
	res, runs, passes := watchPass(t, s, n)
	if passes != 1 {
		t.Fatalf("route change took %d attempts, want 1: no status changed", passes)
	}
	for id, want := range map[ProbeID]int{
		ProbeIface:     1, // fresh, and its interface changed
		ProbeTargetTCP: 1, // fresh, and its interface changed
		ProbeQUIC:      1, // reads the interface row
		ProbeTLS:       1, // reads the target row
		ProbeHTTPS:     1, // reads TLS, which reran; the interface changed beneath it
		ProbeHTTP:      1, // reads DNS, which is identical; the interface changed beneath it
		ProbeDNSPublic: 1, // reads the interface row
	} {
		if runs[id] != want {
			t.Errorf("route change ran %s %d times, want %d", id, runs[id], want)
		}
	}
	if got := res[ProbeIface].Iface; got != "wlan0" {
		t.Errorf("published interface = %q, want wlan0", got)
	}
	assertFreshDiagnosis(t, n, res)
}

// A path change can leave a row's direct inputs identical while the path it
// measures has changed. Each case changes one path input and breaks one row on
// the new path. A reused copy of that row would publish PASS, and the published
// pass must instead agree with a fresh pass. Only the broken row changes status,
// so the verdict gate cannot be what catches the change.
func TestWatchPathChangeNeverPublishesAReusedRowFromTheOldPath(t *testing.T) {
	cases := []struct {
		name   string
		change func(*watchNet)
		broken ProbeID
	}{
		// HTTP reads DNS and HTTPS reads TLS. Both can return identical results
		// on a new interface, which is why neither may be reused.
		{"interface, HTTP", func(n *watchNet) { n.iface = "wlan0" }, ProbeHTTP},
		{"interface, HTTPS", func(n *watchNet) { n.iface = "wlan0" }, ProbeHTTPS},
		// Only the default route changed. QUIC and HTTP do not read the target's
		// route, so the reference egress route is the change they must see.
		{"default gateway, HTTP", func(n *watchNet) { n.gateway = net.ParseIP("192.0.2.254") }, ProbeHTTP},
		// HTTP does not read the target's route, and the interface, DNS, and
		// address are unchanged. Only the target row can show this change.
		{"target route, HTTP", func(n *watchNet) { n.targetTunnel = TunnelKnown }, ProbeHTTP},
		{"target route, HTTPS", func(n *watchNet) { n.targetTunnel = TunnelKnown }, ProbeHTTPS},
		{"address, HTTP", func(n *watchNet) { n.addr = net.ParseIP("198.51.100.8") }, ProbeHTTP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			watchPass(t, s, n)

			c.change(n)
			n.broken = c.broken
			clock.Advance(5 * time.Second)
			res, runs, _ := watchPass(t, s, n)
			if res[c.broken].Status != StatusFail {
				t.Errorf("published %s = %v, want fail on the new path: a reused row hid the change", c.broken, res[c.broken].Status)
			}
			if runs[c.broken] != 1 {
				t.Errorf("published pass ran %s %d times, want 1", c.broken, runs[c.broken])
			}
			assertFreshDiagnosis(t, n, res)
		})
	}
}

// A reusable row that carries a route must not decide whether a stable pass is
// published. Its route is measured on the pass that runs it, then reused, so a
// check that read reused routes would discard every other pass.
func TestWatchReusedRouteDoesNotDiscardStablePasses(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	n.tlsRoutes = true
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	const steps = 30 // 150 seconds: TLS expires at least twice
	tlsRuns := 0
	for step := 1; step <= steps; step++ {
		clock.Advance(5 * time.Second)
		n.resetRuns()
		pass := s.Begin(n.graph())
		results := RunAll(context.Background(), pass.Probes(), time.Second)
		if !pass.Publish(results) {
			t.Fatalf("stable pass %d was discarded: a reused row's route changed the check", step)
		}
		tlsRuns += n.snapshotRuns()[ProbeTLS]
	}
	if tlsRuns == 0 || tlsRuns >= steps {
		t.Errorf("TLS ran %d times in %d stable passes, want some reuse and some expiry", tlsRuns, steps)
	}
}

// A changed status is a transition, so the lightweight pass is not published.
// The next pass runs fresh and that is what is shown and recorded.
func TestWatchTargetOutageAndRecoveryConfirmWithFreshPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.targetDown = true
	clock.Advance(5 * time.Second)
	res, runs, passes := watchPass(t, s, n)
	if passes != 2 {
		t.Fatalf("outage took %d attempts, want 2: the first pass changed status", passes)
	}
	if res[ProbeTargetTCP].Status != StatusFail || res[ProbeTLS].Status != StatusSkip {
		t.Errorf("published outage: target %v, TLS %v; want fail and skip", res[ProbeTargetTCP].Status, res[ProbeTLS].Status)
	}
	if runs[ProbeIface] != 1 || runs[ProbeQUIC] != 1 {
		t.Errorf("confirmation pass did not run every reachable row fresh: iface %d, quic %d", runs[ProbeIface], runs[ProbeQUIC])
	}
	assertFreshDiagnosis(t, n, res)

	n.targetDown = false
	clock.Advance(5 * time.Second)
	res, runs, passes = watchPass(t, s, n)
	// The failing pass left the session unsettled, so the recovery pass runs
	// every row and needs no confirming pass of its own.
	if passes != 1 {
		t.Fatalf("recovery took %d attempts, want 1: the session is unsettled and runs every row", passes)
	}
	if res[ProbeTargetTCP].Status != StatusPass || res[ProbeTLS].Status != StatusPass {
		t.Errorf("published recovery: target %v, TLS %v; want pass", res[ProbeTargetTCP].Status, res[ProbeTLS].Status)
	}
	if runs[ProbeHTTPS] != 1 {
		t.Errorf("recovery pass reused HTTPS after an outage: ran %d times", runs[ProbeHTTPS])
	}
	assertFreshDiagnosis(t, n, res)
}

// A TLS fault that the connect does not show is the known limit of reuse: the
// passing TLS row stands until max age, then the row runs, the change is
// confirmed, and the published pass is fresh. The pass count is the latency.
func TestWatchSilentTLSFailureSurfacesAtMaxAge(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.tlsBroken = true
	masked := 0
	for {
		clock.Advance(5 * time.Second)
		res, _, passes := watchPass(t, s, n)
		if res[ProbeTLS].Status == StatusPass {
			masked++
			if passes != 1 {
				t.Fatalf("a masked pass took %d attempts, want 1", passes)
			}
			if masked > int(watchMaxAge/(5*time.Second)) {
				t.Fatalf("TLS fault still masked after %d passes, past max age", masked)
			}
			continue
		}
		if res[ProbeTLS].Status != StatusFail || res[ProbeHTTPS].Status != StatusSkip {
			t.Fatalf("detecting pass: TLS %v, HTTPS %v; want fail and skip", res[ProbeTLS].Status, res[ProbeHTTPS].Status)
		}
		assertFreshDiagnosis(t, n, res)
		break
	}
	if masked == 0 {
		t.Fatal("silent TLS failure was seen at once; reuse did not happen")
	}
}

// An interface that is down is seen on the next pass. Every reusable row sits
// behind the interface, so the pass reuses nothing: it is entirely fresh, and
// it is published at once, with no confirmation pass.
func TestWatchInterfaceDownConfirms(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.ifaceDown = true
	clock.Advance(5 * time.Second)
	n.resetRuns()
	pass := s.Begin(n.graph())
	res := RunAll(context.Background(), pass.Probes(), time.Second)
	if len(pass.reused) != 0 {
		t.Errorf("interface down reused %v, want nothing: every reusable row sits behind the interface", pass.reused)
	}
	if !pass.Publish(res) {
		t.Fatal("a pass that reused nothing was not published")
	}
	if res[ProbeIface].Status != StatusFail {
		t.Errorf("interface row = %v, want fail", res[ProbeIface].Status)
	}
	assertFreshDiagnosis(t, n, res)
}

// A changed address that keeps the same status is not a transition. The rows
// measured through it run again in the same pass and the pass is published.
func TestWatchAddressChangeRerunsMeasuredRows(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.addr = net.ParseIP("198.51.100.8")
	clock.Advance(5 * time.Second)
	res, runs, passes := watchPass(t, s, n)
	if passes != 1 {
		t.Fatalf("address change took %d attempts, want 1", passes)
	}
	if runs[ProbeTLS] != 1 {
		t.Errorf("TLS ran %d times after its address changed, want 1", runs[ProbeTLS])
	}
	if got := res[ProbeTargetTCP].SelectedIP.String(); got != "198.51.100.8" {
		t.Errorf("published target address = %s, want the new one", got)
	}
	assertFreshDiagnosis(t, n, res)
}

// Retest asks for a fresh acquisition. Nothing is reused under it.
func TestWatchForcedPassRunsEveryRow(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	s.Force()
	clock.Advance(5 * time.Second)
	_, runs, passes := watchPass(t, s, n)
	if passes != 1 {
		t.Fatalf("forced pass took %d attempts, want 1", passes)
	}
	for _, id := range watchIDs() {
		if runs[id] != 1 {
			t.Errorf("forced pass ran %s %d times, want 1", id, runs[id])
		}
	}
}

// A confirmation pass that is cancelled before it is published must not clear
// the request for a fresh pass. The outage pass reuses QUIC, which reads only
// the interface, so it is discarded and a confirmation is owed. The confirmation
// is cancelled. Recovery must then run QUIC fresh, not reuse it.
func TestWatchCancelledConfirmationStaysForced(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.targetDown = true
	clock.Advance(5 * time.Second)
	outage := s.Begin(n.graph())
	if outage.Publish(RunAll(context.Background(), outage.Probes(), time.Second)) {
		t.Fatal("outage pass that reused rows was published, want discarded")
	}

	clock.Advance(5 * time.Second)
	cancelled := s.Begin(n.graph())
	RunAll(context.Background(), cancelled.Probes(), time.Second) // never published

	n.targetDown = false
	clock.Advance(5 * time.Second)
	_, runs, _ := watchPass(t, s, n)
	if runs[ProbeQUIC] != 1 {
		t.Errorf("recovery after a cancelled confirmation ran QUIC %d times, want 1: it reused a row from before the outage", runs[ProbeQUIC])
	}
}

// A retest can arrive while a pass is running. The pass was started before the
// request, so publishing it must not clear the request: the next pass runs fresh.
func TestWatchRequestDuringPassSurvivesPublish(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(5 * time.Second)
	inFlight := s.Begin(n.graph())
	s.Force() // retest requested while the pass runs
	if !inFlight.Publish(RunAll(context.Background(), inFlight.Probes(), time.Second)) {
		t.Fatal("stable in-flight pass was not published")
	}

	clock.Advance(5 * time.Second)
	_, runs, _ := watchPass(t, s, n)
	if runs[ProbeTLS] != 1 {
		t.Errorf("pass after a retest that arrived mid-pass ran TLS %d times, want 1: the request was lost", runs[ProbeTLS])
	}
}

func TestWatchFingerprintIgnoresTimingAndFollowsEvidence(t *testing.T) {
	base := ProbeResult{
		Status: StatusPass, Iface: "eth0", SelectedIP: net.ParseIP("198.51.100.7"),
		Addrs:    []net.IP{net.ParseIP("198.51.100.7")},
		Routes:   []RouteDecision{{Destination: net.ParseIP("198.51.100.7"), Iface: "eth0"}},
		Families: &FamilyConnectivity{IPv4: "ok"},
		Attempts: []Attempt{{IP: net.ParseIP("198.51.100.7"), Dur: time.Millisecond}},
		Dur:      time.Millisecond, Detail: "connected in 1ms",
	}
	same := base
	same.Dur, same.Detail = 9*time.Millisecond, "connected in 9ms"
	same.Attempts = []Attempt{{IP: net.ParseIP("198.51.100.7"), Dur: 9 * time.Millisecond}}
	if fingerprint(base) != fingerprint(same) {
		t.Fatal("fingerprint changed for timing and detail text only")
	}
	changes := map[string]func(*ProbeResult){
		"status":   func(r *ProbeResult) { r.Status = StatusWarn },
		"cause":    func(r *ProbeResult) { r.Cause = "timeout" },
		"iface":    func(r *ProbeResult) { r.Iface = "wlan0" },
		"selected": func(r *ProbeResult) { r.SelectedIP = net.ParseIP("198.51.100.9") },
		"source":   func(r *ProbeResult) { r.Source = net.ParseIP("192.0.2.1") },
		"addrs":    func(r *ProbeResult) { r.Addrs = nil },
		"route":    func(r *ProbeResult) { r.Routes[0].Iface = "wlan0" },
		"families": func(r *ProbeResult) { r.Families = &FamilyConnectivity{IPv4: "ok", IPv6: "fail"} },
		"portal":   func(r *ProbeResult) { r.Portal = &Portal{RedirectURL: "https://portal.example"} },
		"attempts": func(r *ProbeResult) { r.Attempts[0].Cause = "refused" },
	}
	for name, change := range changes {
		r := base
		r.Routes = append([]RouteDecision(nil), base.Routes...)
		r.Attempts = append([]Attempt(nil), base.Attempts...)
		change(&r)
		if fingerprint(r) == fingerprint(base) {
			t.Errorf("fingerprint did not change for %s", name)
		}
	}
}

// Over an hour of stable Watch, faults come and go. The rows that a pass runs
// are counted against running the whole graph every pass. Each published pass
// must match a fresh pass, except during the one known window where a silent
// TLS fault is still masked.
//
// The guard on reuse is per quiet pass, not per hour. A pass that follows a
// fault runs every row, by design, until the network is OK again, so an hourly
// share mostly measures how many faults the script contains. A quiet pass has no
// fault active and no event within watchMaxAge, so it runs the rows that always
// run, plus one refresh of each reusable row per watchMaxAge.
func TestWatchHourOfStablePassesRunsFarFewerRows(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	graphRows := len(watchIDs())

	const passes = 720 // one hour at the five-second cadence
	total, full, discarded, masked, quicMasked := 0, 0, 0, 0, 0
	quietRows, quietPasses := 0, 0
	lastEvent := -passes
	quicDetected := -1
	const quicChangePass = 121
	perRow := map[ProbeID]int{}
	for pass := 0; pass < passes; pass++ {
		if pass > 0 && pass%60 == 0 {
			// Route churn with no effect on any row: a notification that costs
			// one fresh pass and changes no status.
			s.Invalidate()
			lastEvent = pass
		}
		switch pass {
		case 60:
			n.iface = "wlan0" // interface and route change
			s.Invalidate()
			lastEvent = pass
		case quicChangePass:
			// A route change only QUIC reads. No fresh row moves, so only the
			// notification tells the session to measure QUIC again. It lands one
			// pass after a QUIC sample, the worst case for a row reused to max age.
			n.quicBroken = true
			s.Invalidate()
			lastEvent = pass
		case 331:
			n.quicBroken = false
			s.Invalidate()
			lastEvent = pass
		case 180:
			n.targetDown = true
			lastEvent = pass
		case 190:
			n.targetDown = false
			lastEvent = pass
		case 300:
			n.tlsBroken = true
			lastEvent = pass
		case 420:
			n.tlsBroken = false
			lastEvent = pass
		case 500:
			n.ifaceDown = true
			lastEvent = pass
		case 505:
			n.ifaceDown = false
			lastEvent = pass
		case 600:
			n.addr = net.ParseIP("198.51.100.8") // answer rotates; status does not
			lastEvent = pass
		}
		if pass > 0 {
			clock.Advance(5 * time.Second)
		}
		before := n.allRuns()
		res, runs, attempts := watchPass(t, s, n)
		if attempts == 2 {
			discarded++
		}
		// The work a pass did includes the attempt it rejected: that work ran
		// on the network whether or not anything was printed.
		executed := 0
		for id, c := range n.allRuns() {
			perRow[id] += c - before[id]
			total += c - before[id]
			executed += c - before[id]
		}
		faulted := n.targetDown || n.tlsBroken || n.ifaceDown || n.quicBroken
		if !faulted && pass-lastEvent > int(watchMaxAge/(5*time.Second)) {
			quietRows += executed
			quietPasses++
		}
		published := 0
		for _, c := range runs {
			published += c
		}
		if published == graphRows {
			full++
		}
		if n.quicBroken && quicDetected < 0 && res[ProbeQUIC].Status == StatusFail {
			quicDetected = pass - quicChangePass
		}
		if n.quicBroken && res[ProbeQUIC].Status == StatusPass {
			quicMasked++
			continue
		}
		if n.tlsBroken && res[ProbeTLS].Status == StatusPass {
			masked++
			continue
		}
		assertFreshDiagnosis(t, n, res)
	}
	baseline := passes * graphRows
	t.Logf("passes=%d rows per pass=%d executions=%d baseline=%d (%.0f%%) full-graph passes=%d discarded=%d masked=%d",
		passes, graphRows, total, baseline, 100*float64(total)/float64(baseline), full, discarded, masked)
	t.Logf("QUIC route-footprint change at pass %d: first FAIL on pass +%d (0 is the first pass after the change); masked passes=%d",
		quicChangePass, quicDetected, quicMasked)
	for _, id := range watchIDs() {
		t.Logf("  %-16s executed %4d of %d", id, perRow[id], passes)
	}
	// The bound is per quiet pass: the rows that always run, plus each reusable
	// row once per watchMaxAge, with slack for a refresh that lands on the window
	// edge. It is a count, not a time: the fakes cost nothing to run. The reusable
	// set is spelled out here rather than read from watchReusable, so changing
	// that set fails this test instead of quietly loosening its bound.
	wantReusable := map[ProbeID]bool{
		ProbeTLS: true, ProbeHTTP: true, ProbeHTTPS: true, ProbeSSH: true,
		ProbeSMTP: true, ProbeQUIC: true, ProbeDNSEncrypted: true, ProbeProxy: true,
	}
	always, reusable := 0, 0
	for _, id := range watchIDs() {
		if watchReusable[id] != wantReusable[id] {
			t.Fatalf("watchReusable[%s] = %v, the quiet-pass bound assumes %v", id, watchReusable[id], wantReusable[id])
		}
		if wantReusable[id] {
			reusable++
		} else {
			always++
		}
	}
	if quietPasses == 0 {
		t.Fatal("the script has no quiet passes to measure")
	}
	perQuiet := float64(quietRows) / float64(quietPasses)
	bound := float64(always) + float64(reusable)*float64(5*time.Second)/float64(watchMaxAge) + 0.5
	t.Logf("quiet passes=%d executions per quiet pass=%.2f bound=%.2f", quietPasses, perQuiet, bound)
	if perQuiet > bound {
		t.Errorf("quiet passes ran %.2f rows each, want at most %.2f", perQuiet, bound)
	}
	if masked > int(watchMaxAge/(5*time.Second)) {
		t.Errorf("silent TLS fault masked for %d passes, past max age", masked)
	}
	if quicMasked > int(watchMaxAge/(5*time.Second)) {
		t.Errorf("QUIC route-footprint change masked for %d passes, past max age", quicMasked)
	}
	// With the event in place the change is seen on its first pass. Waiting out
	// max age instead is the fallback, and this test must not accept it.
	if quicDetected < 0 || quicDetected > 1 {
		t.Errorf("QUIC route-footprint change first seen on pass +%d, want +0 or +1: the route event did not refuse the reused row", quicDetected)
	}
}

// The public resolver's answer is compared with the system answer of the same
// pass, so an answer that rotated must be measured again. A reused answer would
// be up to watchMaxAge old and could disagree with a fresh system answer for no
// reason the network shows.
func TestWatchPublicDNSAnswerIsFresh(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	n.publicAddr = net.ParseIP("198.51.100.54")
	clock.Advance(5 * time.Second)
	res, runs, _ := watchPass(t, s, n)
	if runs[ProbeDNSPublic] != 1 {
		t.Errorf("public DNS ran %d times after its answer rotated, want 1", runs[ProbeDNSPublic])
	}
	if got := res[ProbeDNSPublic].Addrs; len(got) != 1 || !got[0].Equal(n.publicAddr) {
		t.Errorf("published public DNS answer = %v, want the current answer %v", got, n.publicAddr)
	}
	assertFreshDiagnosis(t, n, res)
}

// BenchmarkWatchStablePass measures the orchestration cost of one stable pass,
// with the rows as fakes. It says nothing about network cost.
func BenchmarkWatchStablePass(b *testing.B) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	benchPass(b, s, n)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clock.Advance(5 * time.Second)
		benchPass(b, s, n)
	}
}

// BenchmarkWatchFullPass is the same pass with every row run, as HEAD does it.
func BenchmarkWatchFullPass(b *testing.B) {
	n := newWatchNet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RunAll(context.Background(), n.graph(), time.Second)
	}
}

func benchPass(b *testing.B, s *WatchSession, n *watchNet) {
	b.Helper()
	pass := s.Begin(n.graph())
	results := RunAll(context.Background(), pass.Probes(), time.Second)
	if !pass.Publish(results) {
		b.Fatal("stable pass was not published")
	}
}

// publishedFresh runs one pass the way watchPass does and reports whether the
// published pass measured every row itself.
func publishedFresh(t *testing.T, s *WatchSession, n *watchNet) bool {
	t.Helper()
	for attempt := 1; attempt <= 2; attempt++ {
		pass := s.Begin(n.graph())
		results := RunAll(context.Background(), pass.Probes(), time.Second)
		if pass.Publish(results) {
			return pass.Fresh()
		}
	}
	t.Fatal("a fresh pass was not published")
	return false
}

// An input that changes for some reusable rows and not others leaves them
// expiring at different times. Then no pass may ever measure every row by
// itself, and a whole measurement drifts out of the window. The session bounds
// that: a whole measurement is never older than watchMaxAge.
func TestWatchWholeMeasurementStaysWithinMaxAgeAfterRowsDesync(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)
	for i := 0; i < 2; i++ {
		clock.Advance(5 * time.Second)
		watchPass(t, s, n)
	}

	// The system resolver's answer rotates. The rows that read it run again now,
	// while QUIC, the proxy, and encrypted DNS read only the interface and keep the
	// observation they made at the start.
	n.addr = net.ParseIP("198.51.100.8")
	clock.Advance(5 * time.Second)
	watchPass(t, s, n)

	const passes = 40
	var whole []int
	mixed := 0
	for pass := 1; pass <= passes; pass++ {
		clock.Advance(5 * time.Second)
		if publishedFresh(t, s, n) {
			whole = append(whole, pass)
		} else {
			mixed++
		}
	}
	if mixed == 0 {
		t.Fatal("no pass reused a row after the change, so the desync is not exercised")
	}
	gap := int(watchMaxAge / (5 * time.Second))
	last := 0
	for _, pass := range whole {
		if pass-last > gap {
			t.Errorf("no whole measurement between passes %d and %d, want at most %d apart", last, pass, gap)
		}
		last = pass
	}
	if passes-last > gap {
		t.Errorf("no whole measurement in the last %d passes", passes-last)
	}
}

// A reused row names the pass that sampled it, and a pass with a reused row is
// not a measurement of the whole graph.
func TestWatchReusedRowNamesTheSamplingPass(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	sampledAt := clock.Now()

	pass := s.Begin(n.graph())
	results := RunAll(context.Background(), pass.Probes(), time.Second)
	if !pass.Publish(results) || !pass.Fresh() {
		t.Fatal("first pass was not published as a fresh measurement")
	}
	for _, id := range watchIDs() {
		if _, reused := results[id].ReusedFrom(); reused {
			t.Errorf("first pass reports %s as reused", id)
		}
	}

	clock.Advance(5 * time.Second)
	pass = s.Begin(n.graph())
	results = RunAll(context.Background(), pass.Probes(), time.Second)
	if !pass.Publish(results) {
		t.Fatal("stable pass was not published")
	}
	if pass.Fresh() {
		t.Error("stable pass reused rows but reports itself fresh")
	}
	for _, id := range watchIDs() {
		when, reused := results[id].ReusedFrom()
		switch {
		case watchReusable[id] && !reused:
			t.Errorf("stable pass did not reuse %s", id)
		case watchReusable[id] && !when.Equal(sampledAt):
			t.Errorf("reused %s names sampling time %v, want the first pass at %v", id, when, sampledAt)
		case !watchReusable[id] && reused:
			t.Errorf("stable pass reused %s, which always runs", id)
		}
	}
}

// A reused observation is refused once it is older than watchMaxAge, even when
// the session's last full pass is recent. Normally the full-pass clock forces a
// fresh pass first, so this per-row bound is what the reuse check itself must
// hold: lastFull is moved here by hand to take that path away.
func TestWatchReuseRefusesAnObservationOlderThanMaxAge(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)
	watchPass(t, s, n)

	clock.Advance(watchMaxAge + time.Second)
	s.lastFull = clock.Now()
	results, ran, _ := watchPass(t, s, n)
	for _, id := range watchIDs() {
		if !watchReusable[id] {
			continue
		}
		if _, reused := results[id].ReusedFrom(); reused {
			t.Errorf("%s was reused from a measurement %v old, want it run", id, watchMaxAge+time.Second)
		}
		if ran[id] != 1 {
			t.Errorf("%s ran %d times, want 1 once its measurement is past the maximum age", id, ran[id])
		}
	}
}

// A measurement must not outlive its window because of how the wall clock moves.
// Across a suspend the wall clock advances by the time the machine slept, so the
// large forward advance stands in for that. A backward step must refuse too. The
// fake clock has no monotonic reading, so both checks read the same wall clock.
// These tests guard the wall-clock check. They cannot show that a real suspend
// is caught. Each step runs twice: once where Begin's whole-measurement check
// forces the pass, and once where lastFull is moved to now, so only the row
// observations decide.
func TestWatchWallClockStepRefusesStaleEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		step     time.Duration
		rowsOnly bool
	}{
		{"forward, as after a suspend", 2 * time.Hour, false},
		{"forward, rows alone", 2 * time.Hour, true},
		{"backward, inside the window", -5 * time.Second, false},
		{"backward, rows alone", -5 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			watchPass(t, s, n)

			clock.Advance(tc.step)
			if tc.rowsOnly {
				s.lastFull = clock.Now()
			}
			results, runs, _ := watchPass(t, s, n)
			for _, id := range watchIDs() {
				if !watchReusable[id] {
					continue
				}
				if _, reused := results[id].ReusedFrom(); reused {
					t.Errorf("%s was reused across a %v wall-clock step, want it run", id, tc.step)
				}
				if runs[id] != 1 {
					t.Errorf("%s ran %d times across a %v wall-clock step, want 1", id, runs[id], tc.step)
				}
			}
		})
	}
}

// The window rule on its own. A measurement is fresh only while both clocks place
// it inside the window. Each row names what a rule that drops one clock would
// accept wrongly: the monotonic age alone reuses the suspend row, and the wall
// age alone reuses the row whose monotonic age is past the window.
func TestWatchFreshNeedsBothClocks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mono, wall time.Duration
		want       bool
	}{
		{"inside on both", 59 * time.Second, 59 * time.Second, true},
		{"suspend: wall past the window", time.Second, 2 * time.Hour, false},
		{"wall stepped back past the sample", 2 * time.Second, -time.Second, false},
		{"monotonic past the window", 61 * time.Second, 2 * time.Second, false},
		{"monotonic exactly at the window", watchMaxAge, 59 * time.Second, false},
		{"wall exactly at the window", 59 * time.Second, watchMaxAge, false},
		{"both exactly at the window", watchMaxAge, watchMaxAge, false},
	} {
		if got := fresh(tc.mono, tc.wall); got != tc.want {
			t.Errorf("%s: fresh(%v, %v) = %t, want %t", tc.name, tc.mono, tc.wall, got, tc.want)
		}
	}
}

// reusedAny reports whether a pass answered at least one reusable row from the
// session. The in-flight tests need that, or they do not exercise expiry.
func reusedAny(results map[ProbeID]ProbeResult) bool {
	for _, id := range watchIDs() {
		if _, reused := results[id].ReusedFrom(); reused && watchReusable[id] {
			return true
		}
	}
	return false
}

// A pass publishes what it measured, so Publish must refuse evidence that has
// aged out while the pass was in flight. Each case moves the clock between Begin
// and Publish, as a suspend or a clock step does. The refused pass is discarded,
// and the pass that follows must run every reusable row fresh.
func TestWatchPublishRefusesReusedEvidenceExpiredInFlight(t *testing.T) {
	for _, tc := range []struct {
		name string
		step time.Duration
	}{
		{"forward two hours, as after a suspend", 2 * time.Hour},
		{"backward ten seconds, as after a clock step", -10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			watchPass(t, s, n)

			clock.Advance(5 * time.Second)
			inFlight := s.Begin(n.graph())
			results := RunAll(context.Background(), inFlight.Probes(), time.Second)
			if !reusedAny(results) {
				t.Fatal("no reusable row was reused, so expiry in flight is not exercised")
			}

			clock.Advance(tc.step)
			if inFlight.Publish(results) {
				t.Fatalf("published reused evidence after a %v clock step, want it discarded", tc.step)
			}

			_, runs, _ := watchPass(t, s, n)
			for _, id := range watchIDs() {
				if watchReusable[id] && runs[id] != 1 {
					t.Errorf("pass after the discard ran %s %d times, want 1 fresh run", id, runs[id])
				}
			}
		})
	}
}

// A fully fresh pass that began before a long suspend holds rows measured before
// the suspend. Publishing it would present them as current, so it is discarded.
func TestWatchPublishRefusesFreshPassStartedBeforeLongGap(t *testing.T) {
	clock := newWatchClock()
	n := newWatchNet()
	s := NewWatchSession(clock.Now)

	inFlight := s.Begin(n.graph())
	results := RunAll(context.Background(), inFlight.Probes(), time.Second)
	if reusedAny(results) {
		t.Fatal("the first pass reused a row, so it is not a fully fresh pass")
	}

	clock.Advance(2 * time.Hour)
	if inFlight.Publish(results) {
		t.Fatal("published a fresh pass that began two hours ago, want it discarded")
	}
}

// Reused evidence is current for watchMaxAge after it was sampled, and no longer.
// A pass that reused a row at 55 seconds may publish 4 seconds later, and may not
// publish at 60 seconds.
func TestWatchPublishWindowBoundaryInFlight(t *testing.T) {
	for _, tc := range []struct {
		name string
		more time.Duration
		want bool
	}{
		{"one nanosecond inside the window", 5*time.Second - time.Nanosecond, true},
		{"exactly at the window", 5 * time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newWatchClock()
			n := newWatchNet()
			s := NewWatchSession(clock.Now)
			watchPass(t, s, n)

			clock.Advance(watchMaxAge - 5*time.Second)
			inFlight := s.Begin(n.graph())
			results := RunAll(context.Background(), inFlight.Probes(), time.Second)
			if !reusedAny(results) {
				t.Fatal("no reusable row was reused, so the boundary is not exercised")
			}

			clock.Advance(tc.more)
			if got := inFlight.Publish(results); got != tc.want {
				t.Errorf("Publish = %t, want %t", got, tc.want)
			}
		})
	}
}
