// Performance budgets for the probe DAG. A probe timeout answers "when do we
// give up on this check?"; a budget answers "how long may a healthy or
// otherwise controlled run take before that is a regression?". The two are
// deliberately separate numbers: DefaultProbeTimeout may not shrink to make a
// budget green, and a budget may not be widened to hide a probe that started
// spending its whole timeout.
//
// Everything here is deterministic. The concurrency invariant is a barrier
// rather than a stopwatch, because a wall-clock comparison of "concurrent" to
// "serialized" is exactly the kind of assertion a briefly starved CI runner
// turns into a flake, while a barrier a serialized executor can never open
// fails for the one reason it exists to catch. The wall-clock bounds that do
// remain are tied to intentional deadlines and sit orders of magnitude above
// what the fixtures actually cost.

package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- budgets ----

const (
	// worstCaseRunBudget bounds one whole pass when every rung of the deepest
	// dependency chain spends its entire probe timeout. It is the DAG's depth
	// times DefaultProbeTimeout, and it is what a user waits through on a
	// network that answers nothing at all. Five rungs at four seconds is where
	// the graph stands today; the gate exists so a sixth rung, or a longer
	// default timeout, is a decision somebody makes on purpose.
	worstCaseRunBudget = 20 * time.Second

	// healthyRunBudget bounds a whole diagnosis whose every endpoint answers:
	// a quarter of what netdoc is willing to wait for one silent check. The
	// in-memory fixture below measures a few milliseconds, and roughly 100ms
	// with the race detector on a deliberately oversubscribed machine, so this
	// is an order of magnitude clear of the worst runner and still fires on any
	// probe that starts waiting out a deadline a working path never trips.
	healthyRunBudget = DefaultProbeTimeout / 4

	// healthyProbeBudget is the same idea per row, at half the whole run's
	// budget, since no single healthy row should ever dominate a pass.
	healthyProbeBudget = healthyRunBudget / 2

	// stallTimeout is the probe budget the deadline-compliance run hands out.
	// Small on purpose: a probe that honors its context returns when the
	// context does, whatever the number, and a caller is free to pass one this
	// small.
	stallTimeout = 300 * time.Millisecond

	// stallOvershoot is what a probe may add on top of stallTimeout before it
	// counts as ignoring its deadline: goroutine wake-up, a TLS record, a
	// socket teardown. Generous enough to absorb a badly oversubscribed runner,
	// tight enough that the internal deadlines probes actually carry (a 2s
	// banner read, a 4s proxy or DoT fallback) cannot hide behind it.
	stallOvershoot = 1200 * time.Millisecond
)

// ---- the DAG's cost model ----

// probeDepths reports, per probe, how many probes have to finish one after
// another before that probe can report, itself included. Both executors launch
// every ready probe at once, so a pass costs the deepest chain's worth of probe
// budgets, never the sum over every probe. Depth is therefore the run's cost,
// and a new dependency edge between two rows that used to be siblings is a
// performance regression whether or not any probe got slower.
func probeDepths(t *testing.T, probes []Probe) map[ProbeID]int {
	t.Helper()
	byID := make(map[ProbeID]Probe, len(probes))
	for _, p := range probes {
		byID[p.ID] = p
	}
	depths := make(map[ProbeID]int, len(probes))
	open := make(map[ProbeID]bool, len(probes))
	var depth func(ProbeID) int
	depth = func(id ProbeID) int {
		if d, ok := depths[id]; ok {
			return d
		}
		if open[id] {
			// Not pedantry: a cycle leaves both executors with probes that are
			// never ready, so the run finishes silently missing rows.
			t.Fatalf("probe %s sits on a dependency cycle", id)
		}
		open[id] = true
		longest := 0
		for _, dep := range byID[id].Deps {
			if d := depth(dep); d > longest {
				longest = d
			}
		}
		open[id] = false
		depths[id] = longest + 1
		return longest + 1
	}
	for _, p := range probes {
		depth(p.ID)
	}
	return depths
}

// layersOf groups probe IDs by depth, so index 0 holds the roots and each later
// entry holds the probes that become ready once the one before it is done.
func layersOf(depths map[ProbeID]int) [][]ProbeID {
	deepest := 0
	for _, d := range depths {
		if d > deepest {
			deepest = d
		}
	}
	layers := make([][]ProbeID, deepest)
	for id, d := range depths {
		layers[d-1] = append(layers[d-1], id)
	}
	for _, layer := range layers {
		slices.Sort(layer)
	}
	return layers
}

// The stage layout of every probe DAG netdoc builds. Each inner slice is one
// scheduling stage: everything in it runs at the same time, and the number of
// slices is what a pass actually costs in probe budgets. Siblings collapsing
// into a chain, which is the way this engine gets slower without any probe
// getting slower, moves an ID down a stage and fails here.
func TestProbeGraphStagesAndWorstCaseBudget(t *testing.T) {
	root := []ProbeID{ProbeIface}
	// Everything that only needs a live interface. One failure here can never
	// delay, or hide, another.
	offIface := []ProbeID{ProbeDNS, ProbeDNSEncrypted, ProbeDNSPublic, ProbeInternet, ProbeProxy, ProbeQUIC, ProbeSSID}
	for _, tc := range []struct {
		name, target string
		stages       [][]ProbeID
	}{
		{name: "generic", stages: [][]ProbeID{root, offIface}},
		{name: "tls", target: "target.test:443", stages: [][]ProbeID{
			root, offIface,
			{ProbeHTTP, ProbeTargetTCP},
			{ProbePMTU, ProbeTLS},
			{ProbeHTTPS},
		}},
		{name: "http", target: "http://target.test", stages: [][]ProbeID{
			root, offIface,
			{ProbeTargetTCP},
			{ProbeHTTP, ProbePMTU},
		}},
		{name: "ssh", target: "target.test:22", stages: [][]ProbeID{
			root, offIface,
			{ProbeTargetTCP},
			{ProbePMTU, ProbeSSH},
		}},
		{name: "smtp", target: "target.test:25", stages: [][]ProbeID{
			root, offIface,
			{ProbeTargetTCP},
			{ProbePMTU, ProbeSMTP},
		}},
		{name: "no protocol row", target: "target.test:9999", stages: [][]ProbeID{
			root, offIface,
			{ProbeTargetTCP},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var target *Target
			if tc.target != "" {
				target = mustTarget(t, tc.target)
			}
			probes := BuildProbesFromSources(target, nil, DefaultPublicDNS, true)
			got := layersOf(probeDepths(t, probes))
			for _, stage := range tc.stages {
				slices.Sort(stage)
			}
			if !slices.EqualFunc(got, tc.stages, slices.Equal) {
				t.Fatalf("scheduling stages =\n%v\nwant\n%v", got, tc.stages)
			}
			if worst := time.Duration(len(got)) * DefaultProbeTimeout; worst > worstCaseRunBudget {
				t.Errorf("worst case = %d stages x %v = %v, over the %v budget", len(got), DefaultProbeTimeout, worst, worstCaseRunBudget)
			}
		})
	}
}

// --check and --skip only remove probes, never rewire them, so a selected DAG
// can only ever be shallower than the full one. Pinning that keeps the budget
// above meaningful for every run netdoc can be asked for, not just the default.
func TestProbeSelectionNeverDeepensTheGraph(t *testing.T) {
	probes := BuildProbesFromSources(mustTarget(t, "target.test:443"), nil, DefaultPublicDNS, true)
	full := len(layersOf(probeDepths(t, probes)))
	for _, id := range []ProbeID{ProbeHTTPS, ProbeTLS, ProbePMTU, ProbeDNS, ProbeInternet} {
		for _, sel := range []ProbeSelection{
			{Check: map[ProbeID]struct{}{id: {}}},
			{Skip: map[ProbeID]struct{}{id: {}}},
		} {
			selected := sel.Apply(probes)
			if len(selected) == 0 {
				continue
			}
			if got := len(layersOf(probeDepths(t, selected))); got > full {
				t.Errorf("selection %+v yields %d stages, more than the full graph's %d", sel, got, full)
			}
		}
	}
}

// ---- concurrency, proved without a clock ----

// layerGate opens only once every probe in one scheduling stage is inside it at
// the same time. An executor that ran those probes one after another can never
// open it, so serialization shows up as probes that time out rather than as a
// wall-clock number a slow runner could also produce.
type layerGate struct {
	arrived sync.WaitGroup
	open    chan struct{}
}

func newLayerGate(n int) *layerGate {
	g := &layerGate{open: make(chan struct{})}
	g.arrived.Add(n)
	go func() {
		g.arrived.Wait()
		close(g.open)
	}()
	return g
}

// gatedProbes rebuilds probes with the same IDs and dependencies but a Run that
// reports only once its whole stage is in flight.
func gatedProbes(t *testing.T, probes []Probe) []Probe {
	t.Helper()
	depths := probeDepths(t, probes)
	gates := make(map[int]*layerGate)
	for _, layer := range layersOf(depths) {
		gates[len(gates)+1] = newLayerGate(len(layer))
	}
	gated := make([]Probe, len(probes))
	for i, p := range probes {
		gate, stage := gates[depths[p.ID]], depths[p.ID]
		gated[i] = Probe{ID: p.ID, Name: p.Name, Deps: p.Deps, Run: func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
			gate.arrived.Done()
			select {
			case <-gate.open:
				return ProbeResult{Status: StatusPass, Detail: fmt.Sprintf("stage %d ran concurrently", stage)}
			case <-ctx.Done():
				return ProbeResult{Status: StatusFail, Detail: fmt.Sprintf("stage %d never had every probe in flight at once: %v", stage, ctx.Err())}
			}
		}}
	}
	return gated
}

// The headless executor must overlap every probe a stage makes ready, so a pass
// costs the longest chain rather than the sum of every branch. The real DAG's
// shape is used rather than an invented one: the seven checks hanging off the
// interface row are the width this engine is built around.
func TestRunAllOverlapsEveryReadyProbe(t *testing.T) {
	for _, target := range []string{"", "target.test:443"} {
		t.Run("target "+target, func(t *testing.T) {
			var tg *Target
			if target != "" {
				tg = mustTarget(t, target)
			}
			probes := gatedProbes(t, BuildProbesFromSources(tg, nil, DefaultPublicDNS, true))
			// Long enough that a healthy machine never trips it, short enough
			// that a genuinely serialized executor fails in seconds.
			res := RunAll(context.Background(), probes, 2*time.Second)
			for _, p := range probes {
				if got := res[p.ID]; got.Status != StatusPass {
					t.Errorf("%s: %s", p.ID, got.Detail)
				}
			}
		})
	}
}

// A probe skipped for a failed prerequisite never ran, and Dur is the only
// place a reader can see that: BuildSnapshot publishes it as Ran, and Ms floors
// anything that did run at 1ms so a fast check can never be mistaken for one
// that did not happen. Central timing instrumentation that stamped every result
// would erase the distinction, so pin it.
func TestSkippedProbesRecordNoRuntime(t *testing.T) {
	var ran atomic.Int64
	probes := []Probe{
		{ID: ProbeIface, Name: "iface", Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			ran.Add(1)
			return ProbeResult{Status: StatusPass}
		})},
		{ID: ProbeDNS, Name: "dns", Deps: []ProbeID{ProbeIface}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			ran.Add(1)
			return ProbeResult{Status: StatusFail}
		})},
		// Runs and reports SKIP itself, which is not the same fact as never
		// having run, and must not read as one.
		{ID: ProbeInternet, Name: "internet", Deps: []ProbeID{ProbeIface}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			ran.Add(1)
			return ProbeResult{Status: StatusSkip}
		})},
		{ID: ProbeTargetTCP, Name: "tcp", Deps: []ProbeID{ProbeDNS}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			ran.Add(1)
			return ProbeResult{Status: StatusPass}
		})},
		{ID: ProbeTLS, Name: "tls", Deps: []ProbeID{ProbeTargetTCP}, Run: wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
			ran.Add(1)
			return ProbeResult{Status: StatusPass}
		})},
	}
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	if got := ran.Load(); got != 3 {
		t.Errorf("%d probes ran, want 3: the two behind the failed prerequisite must never start", got)
	}
	for _, id := range []ProbeID{ProbeIface, ProbeInternet} {
		if res[id].Dur <= 0 {
			t.Errorf("%s ran but reports Dur %v", id, res[id].Dur)
		}
	}
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS} {
		if res[id].Status != StatusSkip || res[id].Dur != 0 {
			t.Errorf("%s = %v with Dur %v, want SKIP with no runtime", id, res[id].Status, res[id].Dur)
		}
	}
	snap := BuildSnapshot(nil, probes, res)
	for _, check := range snap.Checks {
		wantRan := check.ID != string(ProbeTargetTCP) && check.ID != string(ProbeTLS)
		if check.Ran != wantRan {
			t.Errorf("snapshot check %s Ran = %v, want %v", check.ID, check.Ran, wantRan)
		}
		if wantRan && check.DurationMs < 1 {
			t.Errorf("snapshot check %s reports %dms, which reads as a probe that never ran", check.ID, check.DurationMs)
		}
	}
}

// ---- controlled endpoints ----

// budgetTargetHost is the fixture's target name. It shares a certificate with
// the fixed encrypted-DNS identity so one listener can answer as both.
const budgetTargetHost = "target.test"

// budgetFixture answers every endpoint the DAG dials, over in-memory pipes:
// ordinary HTTPS and RFC 8484 DoH on 443, plain HTTP on 80, RFC 7858 DoT on
// 853. No port is bound and no packet leaves the process, so the run's cost is
// the diagnostic engine's own and nothing else's.
type budgetFixture struct {
	tlsPipe   *pipeNet
	httpPipe  *pipeNet
	dotPipe   *pipeNet
	roots     *x509.CertPool
	loopbacks []net.IP
}

func newBudgetFixture(t *testing.T) *budgetFixture {
	t.Helper()
	cert, roots := selfSignedCert(t, EncryptedDNSHost, budgetTargetHost)
	f := &budgetFixture{
		tlsPipe:   newPipeNet(t),
		httpPipe:  newPipeNet(t),
		dotPipe:   newPipeNet(t),
		roots:     roots,
		loopbacks: []net.IP{net.ParseIP("127.0.0.1")},
	}
	quiet := log.New(io.Discard, "", 0)
	tlsSrv := &http.Server{
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: time.Second,
		ErrorLog:          quiet,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == encryptedDNSPath {
				serveDoH(w, r, dohReply{})
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	f.tlsPipe.serve(t, tlsSrv, func() error { return tlsSrv.ServeTLS(f.tlsPipe, "", "") })
	httpSrv := &http.Server{
		ReadHeaderTimeout: time.Second,
		ErrorLog:          quiet,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	}
	f.httpPipe.serve(t, httpSrv, func() error { return httpSrv.Serve(f.httpPipe) })
	serveDoT(t, f.dotPipe, cert, dotReply{})
	return f
}

// dial routes by port, which is all the probes distinguish: the fixture stands
// in for whatever host each of them believes it is talking to.
func (f *budgetFixture) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	switch port {
	case "443":
		return f.tlsPipe.dial(ctx, network, addr)
	case "80":
		return f.httpPipe.dial(ctx, network, addr)
	case "853":
		return f.dotPipe.dial(ctx, network, addr)
	}
	return nil, fmt.Errorf("no fixture endpoint on port %s", port)
}

func (f *budgetFixture) ops() *netops {
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "netdoc0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return f.loopbacks, []string{"192.0.2.53:53"}, nil
		},
		lookupPublicIP: func(context.Context, string, string) ([]net.IP, []string, error) {
			return f.loopbacks, []string{"8.8.8.8:53"}, nil
		},
		dialContext: f.dial,
		tlsRootCAs:  f.roots,
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			return quicState{version: "1", alpn: "h3"}, nil
		},
		sendBuffer:   func(net.Conn) (int, error) { return 0, fmt.Errorf("pipe has no send buffer") },
		queued:       func(net.Conn) (int, error) { return 0, fmt.Errorf("pipe has no send queue") },
		ssid:         func(context.Context, string) string { return "" },
		proxyFromEnv: func(*http.Request) (*url.URL, error) { return nil, nil },
		portalCheck: func(_ context.Context, ep portalEndpoint) (portalObservation, error) {
			return portalObservation{clean: true, code: ep.want, date: time.Now()}, nil
		},
	}
	o.dialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := f.dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		trusted := cfg.Clone()
		trusted.RootCAs = f.roots
		client := tls.Client(conn, trusted)
		if err := client.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return client, nil
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	return o
}

// timedProbes is what BuildProbesFromSources does to a freshly built DAG: the
// same central Dur instrumentation and output sanitizing every real run gets.
func timedProbes(probes []Probe) []Probe {
	out := slices.Clone(probes)
	for i := range out {
		out[i].Run = wrapRun(out[i].Run)
	}
	return out
}

// The healthy-path budget. Every endpoint answers, so nothing in the run has a
// deadline to wait out, and the whole diagnosis has to cost less than netdoc
// would spend on one silent check. This is the assertion that catches a probe
// which starts sitting on a timer that a working path never fires.
func TestHealthyRunStaysInsideItsBudget(t *testing.T) {
	f := newBudgetFixture(t)
	probes := timedProbes(f.ops().buildProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))

	start := time.Now()
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	elapsed := time.Since(start)

	for _, p := range probes {
		r := res[p.ID]
		switch r.Status {
		case StatusFail, StatusSkip:
			t.Errorf("%s = %v on a healthy path: %s", p.ID, r.Status, r.Detail)
		}
		if r.Dur > healthyProbeBudget {
			t.Errorf("%s took %v on a healthy path, over the %v budget: %s", p.ID, r.Dur, healthyProbeBudget, r.Detail)
		}
	}
	if elapsed > healthyRunBudget {
		t.Errorf("healthy diagnosis took %v, over the %v budget", elapsed, healthyRunBudget)
	}
	slowest, slowestID := time.Duration(0), ProbeID("")
	for _, p := range probes {
		if d := res[p.ID].Dur; d > slowest {
			slowest, slowestID = d, p.ID
		}
	}
	t.Logf("healthy %d-probe diagnosis finished in %v; slowest row %s at %v", len(probes), elapsed, slowestID, slowest)
}

// budgetStall accepts every connection and then says nothing, which is the
// shape that makes a probe's own deadline load-bearing: the socket is open, so
// the connect cannot end the probe, and only a read, write, or handshake
// deadline can.
type budgetStall struct {
	pipe *pipeNet
	mu   sync.Mutex
	held []net.Conn
}

func newBudgetStall(t *testing.T) *budgetStall {
	t.Helper()
	s := &budgetStall{pipe: newPipeNet(t)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := s.pipe.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.held = append(s.held, conn)
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = s.pipe.Close()
		<-done
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, conn := range s.held {
			_ = conn.Close()
		}
	})
	return s
}

// block waits out the caller's context, the way an endpoint that is reachable
// but never answers does.
func block[T any](ctx context.Context, zero T) (T, error) {
	<-ctx.Done()
	return zero, ctx.Err()
}

func (s *budgetStall) ops() *netops {
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "netdoc0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return nil, nil },
		lookupIP: func(ctx context.Context, _ string) ([]net.IP, []string, error) {
			ips, err := block(ctx, []net.IP(nil))
			return ips, nil, err
		},
		lookupPublicIP: func(ctx context.Context, _, _ string) ([]net.IP, []string, error) {
			ips, err := block(ctx, []net.IP(nil))
			return ips, nil, err
		},
		dialContext: s.pipe.dial,
		quicHandshake: func(ctx context.Context, _ net.Conn, _ *tls.Config) (quicState, error) {
			return block(ctx, quicState{})
		},
		// The black-hole shape, so the path-MTU row reaches its bulk write and
		// is cut short by the write deadline it derives from the probe budget
		// rather than by the send-queue reading a pipe cannot answer.
		sendBuffer: func(net.Conn) (int, error) { return pmtuSendBuffer, nil },
		queued:     func(net.Conn) (int, error) { return pmtuPayloadSize, nil },
		ssid: func(ctx context.Context, _ string) string {
			<-ctx.Done()
			return ""
		},
		// A configured proxy, so the proxy row dials and then has to survive an
		// endpoint that never sends a CONNECT response.
		proxyFromEnv: func(*http.Request) (*url.URL, error) { return url.Parse("http://127.0.0.1:3128") },
		portalCheck: func(ctx context.Context, _ portalEndpoint) (portalObservation, error) {
			<-ctx.Done()
			return portalObservation{}, ctx.Err()
		},
	}
	o.dialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := s.pipe.dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		client := tls.Client(conn, cfg)
		if err := client.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return client, nil
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	return o
}

// Deadline compliance, as one invariant over the whole class instead of a test
// per probe: every probe netdoc can build, handed a context and an endpoint
// that answers nothing, must come back when its context does. Nested
// operations are where this breaks in practice, since a socket read, a TLS
// handshake, a proxy exchange and a bulk write each need a deadline of their
// own, and any one of them left on a constant outlives the budget its caller
// chose. The caller's timeout is deliberately far below DefaultProbeTimeout:
// a small -timeout has to mean what it says.
func TestEveryProbeReturnsWithinItsDeadline(t *testing.T) {
	s := newBudgetStall(t)
	o := s.ops()

	// Every protocol row, plus the generic DAG, so no probe netdoc can build is
	// missing from the sweep.
	var probes []Probe
	seen := map[ProbeID]bool{}
	for _, target := range []string{"", budgetTargetHost + ":443", budgetTargetHost + ":80", budgetTargetHost + ":22", budgetTargetHost + ":25"} {
		var tg *Target
		if target != "" {
			tg = mustTarget(t, target)
		}
		for _, p := range timedProbes(o.buildProbes(tg, DefaultPublicDNS, true)) {
			if !seen[p.ID] {
				seen[p.ID] = true
				probes = append(probes, p)
			}
		}
	}
	for _, id := range selectableProbeIDs() {
		if !seen[id] {
			t.Errorf("probe %s is selectable but never reached this sweep", id)
		}
	}

	// Dependencies are handed over already satisfied so that every probe runs
	// its real body rather than reporting a missing prerequisite.
	loopback := net.ParseIP("127.0.0.1")
	deps := map[ProbeID]ProbeResult{
		ProbeIface:     {ID: ProbeIface, Status: StatusPass, Iface: "netdoc0"},
		ProbeDNS:       {ID: ProbeDNS, Status: StatusPass, Addrs: []net.IP{loopback}, SelectedIP: loopback},
		ProbeTargetTCP: {ID: ProbeTargetTCP, Status: StatusPass, SelectedIP: loopback, Iface: "netdoc0"},
		ProbeTLS:       {ID: ProbeTLS, Status: StatusPass, SelectedIP: loopback},
	}
	for _, p := range probes {
		t.Run(string(p.ID), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), stallTimeout)
			defer cancel()
			r := p.Run(ctx, deps)
			if r.Dur <= 0 {
				t.Fatalf("%s reports no runtime, so it never ran its body", p.ID)
			}
			if r.Dur > stallTimeout+stallOvershoot {
				t.Errorf("%s took %v against a %v budget, over the %v allowed: %s",
					p.ID, r.Dur, stallTimeout, stallTimeout+stallOvershoot, r.Detail)
			}
		})
	}
}

// TestHealthyDialsNeverWaitForTheAttemptStagger pins the one healthy-path cost
// that the whole-run budget above is too coarse to see. The Happy Eyeballs
// stagger is a deliberate delay before every attempt after the first, so on a
// path whose first address answers it must never be waited on at all. Both
// address racers get two candidates and an endpoint that answers instantly, and
// the assertion is that the call returns in less than one stagger: measured in
// single-digit milliseconds, so a runner would have to be twenty-five times
// slower than the worst one observed to reach the bound, while arming the timer
// one attempt too early cannot come in under attemptDelay by construction.
func TestHealthyDialsNeverWaitForTheAttemptStagger(t *testing.T) {
	t.Parallel()
	f := newBudgetFixture(t)
	o := f.ops()
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}

	for _, tc := range []struct {
		name string
		dial func(context.Context) (net.IP, time.Duration, error)
	}{
		{"tcp", func(ctx context.Context) (net.IP, time.Duration, error) {
			conn, ip, _, rtt := o.dialIPs(ctx, ips, 443)
			if conn == nil {
				return nil, rtt, fmt.Errorf("no connection")
			}
			_ = conn.Close()
			return ip, rtt, nil
		}},
		{"quic", func(ctx context.Context) (net.IP, time.Duration, error) {
			_, ip, _, _, rtt, err := o.dialQUICIPs(ctx, ips, budgetTargetHost, 443)
			return ip, rtt, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
			defer cancel()
			start := time.Now()
			ip, rtt, err := tc.dial(ctx)
			elapsed := since(start)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			if !ip.Equal(ips[0]) {
				t.Errorf("first address should have won, got %v", ip)
			}
			if elapsed >= attemptDelay {
				t.Errorf("healthy dial took %v, at or past the %v attempt stagger: the first attempt is being delayed",
					elapsed, attemptDelay)
			}
			t.Logf("first-address win in %v (reported rtt %v)", elapsed, rtt)
		})
	}
}
