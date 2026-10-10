//go:build integration

package diagnostic

// Watch over real loopback sockets. Every row dials a server this package owns,
// and nothing leaves the host: the target and the plain endpoint listen on
// 127.0.0.1, the target's name resolves to that address, and the reference rows
// stay out of the graph.
//
// The servers count accepts, ClientHellos, handshakes, requests and bytes, so
// those numbers are what reached them. Dials are counted at the client's dial
// hook, where a refused attempt also counts, so during an outage the dial count
// can exceed the accepts. Settled passes compare the two only where both connect.
//
// A Watch session and a fresh oracle run against the same servers, one pass after
// the other. Each pass is measured by the counter delta around it, so the oracle's
// traffic never lands in the session's numbers. Run with:
// go test -tags integration -run TestRealWatch ./internal/diagnostic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/incident"
)

// realCadence is the number of passes in one watchMaxAge window at the 5 second
// cadence the TUI and headless loops use.
const realCadence = int(watchMaxAge / (5 * time.Second))

// realRows is the graph the real-socket tests run: the target's TCP connect, the
// path MTU row that dials it a second time, the TLS and HTTPS rows that reuse its
// socket, and the HTTP row, which is reusable but reads only DNS. That last row is
// what lets a failing pass reuse something, so the discard-and-confirm path runs.
var realRows = map[ProbeID]struct{}{
	ProbeTargetTCP: {}, ProbePMTU: {}, ProbeTLS: {}, ProbeHTTPS: {}, ProbeHTTP: {},
}

const (
	endpointTarget = "target"
	endpointPlain  = "plain"
)

// plainEndpoint is the HTTP server on port 80 that the HTTP row reaches. Its
// accepts and the bytes it reads are counted so its connections appear in the
// totals beside the target's.
type plainEndpoint struct {
	port     string
	accepts  atomic.Int64
	requests atomic.Int64
	bytesIn  atomic.Int64
}

// countedListener counts each socket Accept returns, and the bytes read from it.
type countedListener struct {
	net.Listener
	n     *atomic.Int64
	bytes *atomic.Int64
}

func (l countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
		c = &countingConn{Conn: c, bytes: l.bytes}
	}
	return c, err
}

func startPlainEndpoint(t testing.TB) *plainEndpoint {
	t.Helper()
	p := &plainEndpoint{}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			p.requests.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p.port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(countedListener{Listener: ln, n: &p.accepts, bytes: &p.bytesIn})
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})
	return p
}

// The target's port is drawn from a band below the default ephemeral ranges
// (32768 and up on Linux, 49152 and up on macOS and Windows). Client sockets take
// their local ports from the ephemeral range, and while the target is down nothing
// holds its port. A client that took it would block the restart with EADDRINUSE.
// A host that widens its ephemeral range can still collide, and then the restart
// fails loudly rather than flaking.
const (
	targetPortLow  = 20000
	targetPortHigh = 32767
)

// listenTarget binds the first free loopback port in the target band.
func listenTarget(t testing.TB) net.Listener {
	t.Helper()
	for p := targetPortLow; p <= targetPortHigh; p++ {
		if ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			return ln
		}
	}
	t.Fatalf("no free loopback port in %d-%d for the target", targetPortLow, targetPortHigh)
	return nil
}

// realNet is the network one comparison runs against: an HTTPS target that can be
// stopped, refused and restarted on its port, and the plain endpoint. It keeps the
// client's dial counts beside the servers' accept counts, so a settled pass can be
// checked for agreement between the two. iface names the interface every route
// answer uses, and setIface moves it.
type realNet struct {
	t      testing.TB
	tg     *Target
	target *liveServer
	port   string
	stop   func()
	plain  *plainEndpoint

	mu        sync.Mutex
	iface     string
	attempts  map[string]int64 // client TCP dials per endpoint, failed or not
	connected map[string]int64 // client TCP dials that connected, per endpoint
	udp       map[string]int64 // client UDP connects per endpoint, which send nothing

	// routeCalls and dnsCalls count calls to the route and system DNS stubs. They
	// are the probes' calls into this fixture, not packets or kernel lookups.
	routeCalls atomic.Int64
	dnsCalls   atomic.Int64
	// runs, when set, counts the probes that actually ran, by ID. A row a session
	// reuses never reaches it.
	runs *runCounts
	// blackHole, when set, makes the path MTU row see no acknowledgement for its
	// payload. The row then sees what a path-MTU black hole shows a process: the
	// TCP connect works, and the bulk write never drains.
	blackHole atomic.Bool
}

// queuedBytes is the send-queue reading the path MTU probe takes. Under the black
// hole the whole payload stays queued, and otherwise the kernel's own reading
// stands.
func (n *realNet) queuedBytes(c net.Conn) (int, error) {
	if n.blackHole.Load() {
		return pmtuPayloadSize, nil
	}
	return socketQueued(c)
}

func newRealNet(t testing.TB) *realNet {
	t.Helper()
	cert, roots := selfSignedCert(t, "localhost")
	n := &realNet{t: t, target: &liveServer{roots: roots, cert: cert}, iface: "netdoc0", attempts: map[string]int64{}, connected: map[string]int64{}, udp: map[string]int64{}}
	n.stop = n.target.serve(t, listenTarget(t))
	n.port = n.target.port
	tg, err := ParseTarget("https://localhost:" + n.port)
	if err != nil {
		t.Fatal(err)
	}
	n.tg = tg
	n.plain = startPlainEndpoint(t)
	return n
}

// restart brings the target back on the port it had, so the next dial reaches
// the same address the session measured before the outage.
func (n *realNet) restart() {
	n.stop = n.target.listen(n.t, "127.0.0.1:"+n.port)
}

// setIface moves every route answer to another interface, as a Wi-Fi handoff or a
// VPN coming up does. Routes are read per pass, so the next pass sees the move.
func (n *realNet) setIface(name string) {
	n.mu.Lock()
	n.iface = name
	n.mu.Unlock()
}

func (n *realNet) currentIface() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.iface
}

// dial is the client side of every row. It counts each TCP attempt and returns
// the socket the kernel gave it, unwrapped: path MTU needs the TCP type to set
// its send buffer, and a wrapper would turn its measurement into N/A.
//
// A UDP dial is counted apart. The probes make one to learn a source address
// when TCP never connects: it sends no packet and always succeeds, so counting
// it as a connection would make a stopped target look reachable.
func (n *realNet) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	endpoint, dialPort := endpointTarget, port
	switch port {
	case n.port:
	case "80":
		endpoint, dialPort = endpointPlain, n.plain.port
	default:
		return nil, fmt.Errorf("no fixture endpoint on port %s", port)
	}
	var d net.Dialer
	if strings.HasPrefix(network, "udp") {
		n.mu.Lock()
		n.udp[endpoint]++
		n.mu.Unlock()
		return d.DialContext(ctx, network, net.JoinHostPort(host, dialPort))
	}
	n.mu.Lock()
	n.attempts[endpoint]++
	n.mu.Unlock()
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(host, dialPort))
	if err == nil {
		n.mu.Lock()
		n.connected[endpoint]++
		n.mu.Unlock()
	}
	return conn, err
}

// probes builds one pass's graph with fresh ops, as the TUI and headless loops do
// on every pass. Nothing is shared with the previous pass, so a route or address
// change would be seen, and nothing reaches the public network: the name resolves
// to loopback, public resolution fails, the portal checks are off, and no proxy is
// read from the environment.
func (n *realNet) probes() []Probe {
	o := opsFromSources(nil)
	o.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Index: 1, Name: n.currentIface(), Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	o.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) { return nil, nil }
	o.lookupIP = func(context.Context, string) ([]net.IP, []string, error) {
		n.dnsCalls.Add(1)
		return []net.IP{net.ParseIP("127.0.0.1")}, []string{"loopback"}, nil
	}
	o.lookupPublicIP = func(context.Context, string, string) ([]net.IP, []string, error) {
		return nil, nil, errors.New("the Watch fixture resolves no public names")
	}
	o.dialContext = n.dial
	o.queued = n.queuedBytes
	o.dialTLS = trustingDialTLS(n.dial, n.target.roots)
	o.tlsRootCAs = n.target.roots
	o.ssid = func(context.Context, string) string { return "" }
	o.proxyFromEnv = func(*http.Request) (*url.URL, error) { return nil, nil }
	o.routeCause = func(net.IP) string { return "" }
	// A nil portalCheck is the switch that turns the captive-portal dials off.
	o.portalCheck = nil
	// passRoutes is what Linux installs over routeFor. Clearing it keeps the
	// route answer this test gives, instead of the host's own table.
	o.passRoutes = nil
	o.routeFor = func(dst, _ net.IP) (RouteDecision, bool) {
		n.routeCalls.Add(1)
		return RouteDecision{Destination: dst, Family: "ipv4", Iface: n.currentIface(), Source: net.ParseIP("127.0.0.1"), Tunnel: TunnelDirect}, true
	}
	o.defaultRoutes = nil
	o = probeOps(n.tg, o)
	selected := ProbeSelection{Check: realRows}.Apply(o.timedProbes(n.tg, "", false))
	for i, p := range selected {
		if p.Reference {
			n.t.Fatalf("probe %s is a reference row; the fixture must not reach the public network", p.ID)
		}
		if n.runs != nil && p.Run != nil {
			id, run := p.ID, p.Run
			selected[i].Run = func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
				n.runs.inc(id)
				return run(ctx, deps)
			}
		}
	}
	return selected
}

// traffic is what one pass put on the wire, counted at the servers and the client.
type traffic struct {
	accepts, clientHellos, handshakes, requests, bytesIn int64
	plainAccepts, plainRequests, plainBytesIn            int64
	dials, plainDials                                    int64
	udp                                                  int64
}

func (a traffic) add(b traffic) traffic {
	return traffic{
		accepts: a.accepts + b.accepts, clientHellos: a.clientHellos + b.clientHellos,
		handshakes: a.handshakes + b.handshakes, requests: a.requests + b.requests,
		bytesIn: a.bytesIn + b.bytesIn, plainAccepts: a.plainAccepts + b.plainAccepts,
		plainRequests: a.plainRequests + b.plainRequests, plainBytesIn: a.plainBytesIn + b.plainBytesIn,
		dials: a.dials + b.dials, plainDials: a.plainDials + b.plainDials, udp: a.udp + b.udp,
	}
}

func (a traffic) sub(b traffic) traffic {
	return traffic{
		accepts: a.accepts - b.accepts, clientHellos: a.clientHellos - b.clientHellos,
		handshakes: a.handshakes - b.handshakes, requests: a.requests - b.requests,
		bytesIn: a.bytesIn - b.bytesIn, plainAccepts: a.plainAccepts - b.plainAccepts,
		plainRequests: a.plainRequests - b.plainRequests, plainBytesIn: a.plainBytesIn - b.plainBytesIn,
		dials: a.dials - b.dials, plainDials: a.plainDials - b.plainDials, udp: a.udp - b.udp,
	}
}

// traffic reads every counter. Callers take it before and after a pass, after
// settle, so the difference is that pass's traffic alone.
func (n *realNet) traffic() traffic {
	n.mu.Lock()
	dials, plainDials, udp := n.attempts[endpointTarget], n.attempts[endpointPlain], n.udp[endpointTarget]
	n.mu.Unlock()
	return traffic{
		accepts:       n.target.accepts.Load(),
		clientHellos:  n.target.clientHellos.Load(),
		handshakes:    n.target.handshakes.Load(),
		requests:      n.target.requests.Load(),
		bytesIn:       n.target.bytesIn.Load(),
		plainAccepts:  n.plain.accepts.Load(),
		plainRequests: n.plain.requests.Load(),
		plainBytesIn:  n.plain.bytesIn.Load(),
		dials:         dials,
		plainDials:    plainDials,
		udp:           udp,
	}
}

// settle waits, bounded, until every socket the client connected has been
// accepted by each server and its handshake attempt has finished. Only then are
// the counters a complete account of the pass that ran.
func (n *realNet) settle() {
	n.t.Helper()
	n.mu.Lock()
	wantTarget, wantPlain := n.connected[endpointTarget], n.connected[endpointPlain]
	n.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for n.target.accepts.Load() != wantTarget || n.target.pending.Load() != 0 || n.plain.accepts.Load() != wantPlain {
		if time.Now().After(deadline) {
			n.t.Fatalf("server accepted %d of %d target and %d of %d plain sockets", n.target.accepts.Load(), wantTarget, n.plain.accepts.Load(), wantPlain)
		}
		time.Sleep(time.Millisecond)
	}
}

// passRun is one run of the graph: the rows it produced, and the traffic every
// attempt carried, including attempts a publish discarded.
type passRun struct {
	res      map[ProbeID]ProbeResult
	probes   []Probe
	fresh    bool // every row was measured by this run
	attempts int  // runs made before one published
	traffic  traffic
}

// watchStep runs one Watch pass the way the headless loop does: a run that a
// publish discards is run again at once, and the result is the first run that
// publishes. The traffic of every attempt is kept, since each one touched the
// network.
func (n *realNet) watchStep(s *WatchSession) passRun {
	n.t.Helper()
	var total traffic
	for attempt := 1; attempt <= 3; attempt++ {
		before := n.traffic()
		pass := s.Begin(n.probes(), DefaultProbeTimeout)
		res := RunAll(context.Background(), pass.Probes(), DefaultProbeTimeout)
		n.settle()
		total = total.add(n.traffic().sub(before))
		if pass.Publish(res) {
			return passRun{res: res, probes: pass.Probes(), fresh: pass.Fresh(), attempts: attempt, traffic: total}
		}
	}
	n.t.Fatal("a Watch pass was not published on any of three attempts")
	return passRun{}
}

// freshStep runs the graph with no session, so every row is measured. It is the
// oracle a Watch pass must agree with, and the baseline the savings are against.
func (n *realNet) freshStep() passRun {
	n.t.Helper()
	before := n.traffic()
	probes := n.probes()
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	n.settle()
	return passRun{res: res, probes: probes, fresh: true, attempts: 1, traffic: n.traffic().sub(before)}
}

// diagnosisOf is what a pass tells the user. It is the same Interpret the TUI and
// headless loops call on a published pass.
func (n *realNet) diagnosisOf(p passRun) Diagnosis {
	return Interpret(n.tg, ProbeOrder(p.probes), p.res)
}

// checkEquivalent asserts that an incremental pass agrees with the fresh oracle
// run on the same network state. A row may differ only when the incremental pass
// reused it and the observation is still inside watchMaxAge: that is the masking
// window the session documents. Any other difference fails. It returns the masked
// rows, and whether the diagnosis differs, so a caller can account for the window.
func (n *realNet) checkEquivalent(step int, now time.Time, inc, oracle passRun) (masked []ProbeID, diagnosisDiffers bool) {
	n.t.Helper()
	for _, id := range ProbeOrder(oracle.probes) {
		got, want := inc.res[id], oracle.res[id]
		if fingerprint(got) == fingerprint(want) {
			continue
		}
		when, reused := got.ReusedFrom()
		if !reused || now.Sub(when) >= watchMaxAge {
			n.t.Errorf("step %d: %s differs from the fresh pass and is not a masked reuse:\n got  %s\n want %s\n got detail:  %s\n want detail: %s", step, id, fingerprint(got), fingerprint(want), got.Detail, want.Detail)
			continue
		}
		masked = append(masked, id)
	}
	diagnosisDiffers = !reflect.DeepEqual(n.diagnosisOf(inc), n.diagnosisOf(oracle))
	if len(masked) == 0 && diagnosisDiffers {
		n.t.Errorf("step %d: diagnosis differs from the fresh pass with no masked row:\n got  %+v\n want %+v", step, n.diagnosisOf(inc), n.diagnosisOf(oracle))
	}
	return masked, diagnosisDiffers
}

// observe feeds a pass to an incident timeline the way the TUI does: only a fresh
// pass is recorded, and the snapshot is built from the pass's own diagnosis.
func (n *realNet) observe(tl *incident.Timeline, at time.Time, p passRun) incident.Transition {
	d := n.diagnosisOf(p)
	return tl.Observe(at, BuildSnapshotWithDiagnosis(n.tg, p.probes, p.res, d))
}

// TestRealWatchCalibratesAgainstAFreshPass establishes that two fresh runs over
// the same live network compare equal under the comparator the other tests use.
// Without that, a difference between an incremental pass and the oracle could be
// noise in the comparator rather than a difference in the network.
func TestRealWatchCalibratesAgainstAFreshPass(t *testing.T) {
	n := newRealNet(t)
	first := n.freshStep()
	second := n.freshStep()
	if masked, differs := n.checkEquivalent(0, time.Time{}, second, first); len(masked) != 0 || differs {
		t.Fatalf("two fresh passes over the same network disagree: masked %v, diagnosis differs %v", masked, differs)
	}
	for _, id := range ProbeOrder(first.probes) {
		t.Logf("%-16s %-4s %s", id, first.res[id].Status, first.res[id].Cause)
	}
}

// TestRealWatchStableWindowsMatchFreshPasses runs three watchMaxAge windows of
// stable passes against the live target. Each step runs the session and then the
// oracle, and the two must agree. The counts then say what the session saved on
// the wire, pass by pass.
func TestRealWatchStableWindowsMatchFreshPasses(t *testing.T) {
	n := newRealNet(t)
	clock := newWatchClock()
	s := NewWatchSession(clock.Now)
	const steps = 3 * realCadence
	var session, oracle traffic
	for i := 0; i < steps; i++ {
		if i > 0 {
			clock.Advance(5 * time.Second)
		}
		inc := n.watchStep(s)
		want := n.freshStep()
		if masked, differs := n.checkEquivalent(i, clock.Now(), inc, want); len(masked) != 0 || differs {
			t.Errorf("step %d: stable pass masked %v, diagnosis differs %v", i, masked, differs)
		}
		whole := i%realCadence == 0
		if inc.fresh != whole {
			t.Errorf("step %d: fresh = %v, want %v: a whole measurement is due every %d passes", i, inc.fresh, whole, realCadence)
		}
		if inc.attempts != 1 {
			t.Errorf("step %d: stable pass needed %d runs to publish, want 1", i, inc.attempts)
		}
		if got := want.traffic; got.accepts != 2 || got.clientHellos != 1 || got.handshakes != 1 || got.requests != 1 || got.plainAccepts != 1 || got.plainRequests != 1 || got.dials != 2 || got.plainDials != 1 {
			t.Errorf("step %d: fresh pass traffic = %+v, want 2 target accepts, 1 ClientHello, 1 handshake, 1 request, 1 plain accept and request, 2 target dials, 1 plain dial", i, got)
		}
		if whole {
			if inc.traffic.clientHellos != 1 || inc.traffic.requests != 1 || inc.traffic.plainRequests != 1 {
				t.Errorf("step %d: whole pass traffic = %+v, want one handshake and request on each endpoint", i, inc.traffic)
			}
		} else {
			if got := inc.traffic; got.accepts != 2 || got.clientHellos != 0 || got.handshakes != 0 || got.requests != 0 || got.plainAccepts != 0 || got.plainRequests != 0 || got.dials != 2 || got.plainDials != 0 {
				t.Errorf("step %d: reused pass traffic = %+v, want 2 target accepts and 2 target dials, nothing else", i, got)
			}
			// Bytes are required only where path MTU measured: elsewhere the row is
			// N/A and this test makes no claim about what it sent.
			if want.res[ProbePMTU].Status == StatusPass && inc.traffic.bytesIn == 0 {
				t.Errorf("step %d: reused pass read no bytes, but path MTU passed and must have sent its payload", i)
			}
		}
		session = session.add(inc.traffic)
		oracle = oracle.add(want.traffic)
	}
	t.Logf("steps=%d cadence=%d", steps, realCadence)
	t.Logf("incremental: target accepts=%d ClientHellos=%d requests=%d bytesIn=%d target dials=%d plain accepts=%d plain requests=%d",
		session.accepts, session.clientHellos, session.requests, session.bytesIn, session.dials, session.plainAccepts, session.plainRequests)
	t.Logf("fresh:       target accepts=%d ClientHellos=%d requests=%d bytesIn=%d target dials=%d plain accepts=%d plain requests=%d",
		oracle.accepts, oracle.clientHellos, oracle.requests, oracle.bytesIn, oracle.dials, oracle.plainAccepts, oracle.plainRequests)
}

// TestRealWatchOutageAndRecoveryMatchFreshPasses takes the target down for three
// passes, brings it back, and then runs stable passes again. Every pass must agree
// with the oracle, the target row must read down exactly while the target is down,
// and the incident timeline, fed only fresh passes as the TUI feeds it, must open
// and close where the oracle's does.
func TestRealWatchOutageAndRecoveryMatchFreshPasses(t *testing.T) {
	n := newRealNet(t)
	clock := newWatchClock()
	s := NewWatchSession(clock.Now)
	var sessionTL, oracleTL incident.Timeline
	const outageStart, outageEnd, steps = 3, 6, 10
	at := make([]time.Time, steps)
	for i := 0; i < steps; i++ {
		if i > 0 {
			clock.Advance(5 * time.Second)
		}
		at[i] = clock.Now()
		switch i {
		case outageStart:
			n.stop()
		case outageEnd:
			n.restart()
		}
		inc := n.watchStep(s)
		want := n.freshStep()
		if masked, differs := n.checkEquivalent(i, clock.Now(), inc, want); len(masked) != 0 || differs {
			t.Errorf("step %d: pass masked %v, diagnosis differs %v; an outage or recovery must never be masked", i, masked, differs)
		}
		down := i >= outageStart && i < outageEnd
		if down != (want.res[ProbeTargetTCP].Status == StatusFail) {
			t.Errorf("step %d: target down = %v but oracle target_tcp is %s", i, down, want.res[ProbeTargetTCP].Status)
		}
		if down && !inc.fresh {
			t.Errorf("step %d: a failing pass was not fresh; an incident needs whole measurement", i)
		}
		// The oracle is a fresh pass at every step, so its timeline is fed at every
		// step, whatever the session published. The session's timeline is fed only by
		// fresh passes, as the TUI feeds it.
		wantT := n.observe(&oracleTL, clock.Now(), want)
		if expected := expectedOutageTransition(i, outageStart, outageEnd); wantT != expected {
			t.Errorf("step %d: oracle transition %q, want %q", i, wantT, expected)
		}
		var got incident.Transition
		if inc.fresh {
			got = n.observe(&sessionTL, clock.Now(), inc)
			if got != wantT {
				t.Errorf("step %d: incident transition %q, fresh oracle %q", i, got, wantT)
			}
		}
		if i == outageStart && inc.attempts != 2 {
			t.Errorf("onset step published on attempt %d, want 2: the reused HTTP row should have been discarded once", inc.attempts)
		}
		if i == outageEnd && inc.attempts != 1 {
			t.Errorf("recovery step published on attempt %d, want 1", inc.attempts)
		}
		t.Logf("step %d: attempts=%d fresh=%v target=%s transition=%q oracle=%q target accepts=%d requests=%d",
			i, inc.attempts, inc.fresh, inc.res[ProbeTargetTCP].Status, got, wantT, inc.traffic.accepts, inc.traffic.requests)
	}
	sessionIncidents, oracleIncidents := sessionTL.Incidents(), oracleTL.Incidents()
	if len(sessionIncidents) != 1 || len(oracleIncidents) != 1 {
		t.Fatalf("incidents: session %d, oracle %d, want one outage each", len(sessionIncidents), len(oracleIncidents))
	}
	// The outage opens at its first down step and closes at the first step back up.
	// Both timelines must say so, and count the failing passes between them.
	for name, inc := range map[string]incident.Incident{"session": sessionIncidents[0], "oracle": oracleIncidents[0]} {
		if !inc.Started.Equal(at[outageStart]) || !inc.Ended.Equal(at[outageEnd]) {
			t.Errorf("%s incident spans %s to %s, want %s to %s", name, inc.Started, inc.Ended, at[outageStart], at[outageEnd])
		}
		if inc.Passes != outageEnd-outageStart {
			t.Errorf("%s incident counts %d failing passes, want %d", name, inc.Passes, outageEnd-outageStart)
		}
	}
	// Whole records are not compared: each pass carries its own per-check
	// durations, which differ between any two runs. What the user reads is the
	// window, the coincidence, and the changes, so those are compared.
	if got, want := incidentFacts(sessionIncidents[0]), incidentFacts(oracleIncidents[0]); !reflect.DeepEqual(got, want) {
		t.Errorf("incident differs from the fresh oracle:\n session %q\n oracle  %q", got, want)
	}
}

// expectedOutageTransition is what a fresh observation at step i must record: the
// outage begins at its first down step, stays failing while down, and recovers at
// the first step back up. Every other step records nothing.
func expectedOutageTransition(i, down, up int) incident.Transition {
	switch {
	case i == down:
		return incident.TransitionBegan
	case i > down && i < up:
		return incident.TransitionFailing
	case i == up:
		return incident.TransitionRecovered
	}
	return incident.TransitionNone
}

// incidentFacts is what an incident tells the user: when it began and ended, how
// many failing passes it spans, how it coincides with other evidence, and what
// changed at onset and on recovery.
func incidentFacts(i incident.Incident) []string {
	facts := []string{i.Started.String(), i.Ended.String(), fmt.Sprint(i.Passes), string(i.Coincidence())}
	for _, c := range i.OnsetChanges {
		facts = append(facts, "onset: "+c.Summary)
	}
	for _, c := range i.RecoveryChanges {
		facts = append(facts, "recovery: "+c.Summary)
	}
	return facts
}

// TestRealWatchTLSRefusalIsMaskedOnlyWithinMaxAge keeps TCP up and refuses every
// handshake. A reused TLS observation is allowed to stand for watchMaxAge, so the
// session reports TLS as passing while the oracle reports it failing. The test
// requires that difference to be real, confined to the reused rows, bounded by
// the window, and gone once the window closes.
func TestRealWatchTLSRefusalIsMaskedOnlyWithinMaxAge(t *testing.T) {
	n := newRealNet(t)
	clock := newWatchClock()
	s := NewWatchSession(clock.Now)
	const refuseStart, refuseEnd, steps = 3, 3 + 2*realCadence, 3*realCadence + 3
	var maskRun, longestMask, maskedSteps, diagnosisChanged int
	var lastMasked []ProbeID
	for i := 0; i < steps; i++ {
		if i > 0 {
			clock.Advance(5 * time.Second)
		}
		switch i {
		case refuseStart:
			n.target.refuse.Store(true)
		case refuseEnd:
			n.target.refuse.Store(false)
		}
		inc := n.watchStep(s)
		want := n.freshStep()
		masked, differs := n.checkEquivalent(i, clock.Now(), inc, want)
		lastMasked = masked
		for _, id := range masked {
			if id != ProbeTLS && id != ProbeHTTPS {
				t.Errorf("step %d: masked row %s, want only the TLS rows that read the handshake", i, id)
			}
		}
		if i >= refuseStart && i < refuseEnd && want.traffic.clientHellos == 0 {
			t.Errorf("step %d: inside the refusal window but the fresh pass sent no ClientHello", i)
		}
		if len(masked) > 0 {
			maskRun++
			maskedSteps++
			if differs {
				diagnosisChanged++
			}
		} else {
			maskRun = 0
		}
		longestMask = max(longestMask, maskRun)
		t.Logf("step %d: fresh=%v masked=%v diagnosis differs=%v TLS=%s/%s oracle TLS=%s/%s",
			i, inc.fresh, masked, differs, inc.res[ProbeTLS].Status, inc.res[ProbeTLS].Cause, want.res[ProbeTLS].Status, want.res[ProbeTLS].Cause)
	}
	if maskedSteps == 0 {
		t.Fatal("no pass was masked, so the refusal did not exercise the reuse window")
	}
	if diagnosisChanged == 0 {
		t.Error("no masked pass changed the diagnosis, so the masking window never reached the user")
	}
	if longestMask > realCadence {
		t.Errorf("TLS refusal masked for %d passes in a row, want at most %d (watchMaxAge)", longestMask, realCadence)
	}
	if len(lastMasked) != 0 {
		t.Errorf("the last pass still masks %v after the window closed", lastMasked)
	}
}

// TestRealWatchRouteChangeRerunsReusedRows moves every route to a second interface
// partway through a stable run. The interface row changes, and so does the path,
// so no row that read the old interface may be reused. The pass that sees the move
// measures the whole graph on its first attempt, and the pass after it reuses again.
func TestRealWatchRouteChangeRerunsReusedRows(t *testing.T) {
	n := newRealNet(t)
	clock := newWatchClock()
	s := NewWatchSession(clock.Now)
	const change, steps = 3, 6
	for i := 0; i < steps; i++ {
		if i > 0 {
			clock.Advance(5 * time.Second)
		}
		if i == change {
			n.setIface("netdoc1")
		}
		inc := n.watchStep(s)
		want := n.freshStep()
		if masked, differs := n.checkEquivalent(i, clock.Now(), inc, want); len(masked) != 0 || differs {
			t.Errorf("step %d: pass masked %v, diagnosis differs %v; a route change must never be masked", i, masked, differs)
		}
		switch i {
		case change:
			if inc.attempts != 1 {
				t.Errorf("route change published on attempt %d, want 1: a changed interface must not reach a reused row", inc.attempts)
			}
			if !inc.fresh || inc.traffic.clientHellos != 1 || inc.traffic.requests != 1 || inc.traffic.plainRequests != 1 {
				t.Errorf("route change pass = fresh %v traffic %+v, want a whole measurement with one handshake and request on each endpoint", inc.fresh, inc.traffic)
			}
		case change + 1:
			if inc.attempts != 1 || inc.traffic.clientHellos != 0 {
				t.Errorf("pass after the route change = attempts %d traffic %+v, want reuse to resume with no handshake", inc.attempts, inc.traffic)
			}
		}
	}
}

// BenchmarkRealWatchPasses runs one Watch hour per benchmark run over real loopback
// sockets: an initial pass at t=0, then 720 scheduled passes five seconds apart.
// Run it with -benchtime=720x, one process per arm, so the CPU figures belong to a
// single arm. ns/op and the -benchmem figures divide the whole run by the 720
// scheduled passes. Every metric with a /hour suffix is a total for the run, the
// initial pass included. The schedules and arms are described in
// watch_hour_realnet_integration_test.go.
func BenchmarkRealWatchPasses(b *testing.B) {
	for _, sched := range []hourSchedule{scheduleStable, scheduleEvents} {
		b.Run(string(sched), func(b *testing.B) {
			for _, arm := range []hourArm{armIncremental, armForced, armFresh} {
				b.Run(string(arm), func(b *testing.B) {
					benchmarkHour(b, sched, arm)
				})
			}
		})
	}
}

func benchmarkHour(b *testing.B, sched hourSchedule, arm hourArm) {
	h := newHourRun(b, sched)
	b.ReportAllocs()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	user0, sys0, cpuOK := processCPU()
	b.ResetTimer()
	for i := 0; i <= b.N; i++ {
		h.advance(i)
		h.pass(arm)
	}
	b.StopTimer()
	user1, sys1, _ := processCPU()
	runtime.ReadMemStats(&after)

	tot := h.result()
	b.ReportMetric(float64(tot.published), "published/hour")
	b.ReportMetric(float64(tot.full), "full/hour")
	b.ReportMetric(float64(tot.incremental), "incremental/hour")
	b.ReportMetric(float64(tot.discarded), "discarded/hour")
	b.ReportMetric(float64(tot.traffic.dials), "dials/hour")
	b.ReportMetric(float64(tot.traffic.accepts), "accepts/hour")
	b.ReportMetric(float64(tot.traffic.clientHellos), "clienthellos/hour")
	b.ReportMetric(float64(tot.traffic.handshakes), "handshakes/hour")
	b.ReportMetric(float64(tot.traffic.requests), "requests/hour")
	b.ReportMetric(float64(tot.traffic.plainDials), "plaindials/hour")
	b.ReportMetric(float64(tot.traffic.plainAccepts), "plainaccepts/hour")
	b.ReportMetric(float64(tot.traffic.plainRequests), "plainrequests/hour")
	b.ReportMetric(float64(tot.traffic.udp), "udpconnects/hour")
	b.ReportMetric(float64(tot.traffic.bytesIn), "bytesin/hour")
	b.ReportMetric(float64(tot.traffic.plainBytesIn), "plainbytesin/hour")
	b.ReportMetric(float64(tot.routeCalls), "routecalls/hour")
	b.ReportMetric(float64(tot.dnsCalls), "dnscalls/hour")
	for _, id := range orderedRunIDs(tot.runs) {
		b.ReportMetric(float64(tot.runs[id]), "runs-"+string(id)+"/hour")
	}
	b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc), "alloc-bytes/hour")
	b.ReportMetric(float64(after.Mallocs-before.Mallocs), "allocs/hour")
	if cpuOK {
		b.ReportMetric(float64(user1-user0), "cpu-user-ns/hour")
		b.ReportMetric(float64(sys1-sys0), "cpu-sys-ns/hour")
	}
}
