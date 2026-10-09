package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// healthyHTTPSRows is the check set for a healthy HTTPS target. PMTU is the one row
// that still dials for itself, because its bulk writes cannot share a TLS stream.
var healthyHTTPSRows = map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeTLS: {}, ProbeHTTPS: {}, ProbePMTU: {}}

// requireRows fails when a row the test reads never ran. A missing result is
// the zero value, which reads as a pass, so a check on it proves nothing.
func requireRows(t testing.TB, res map[ProbeID]ProbeResult, ids ...ProbeID) {
	t.Helper()
	for _, id := range ids {
		if _, ok := res[id]; !ok {
			t.Fatalf("no %s row ran, so its status would read as a pass", id)
		}
	}
}

// targetDials counts connections the fixture was asked for at the target's pinned
// address. DoH shares port 443 but dials another address.
func targetDials(f *budgetFixture) int {
	f.tlsPipe.mu.Lock()
	defer f.tlsPipe.mu.Unlock()
	n := 0
	for _, addr := range f.tlsPipe.dialed {
		if addr == "127.0.0.1:443" {
			n++
		}
	}
	return n
}

// disarm makes a built graph behave as it did before sharing existed: every
// row dials for itself. Rows keep their link pointers, which no longer hand
// anything over.
func disarm(probes []Probe) {
	for _, p := range probes {
		if p.link != nil {
			p.link.toTLS, p.link.toHTTPS = false, false
		}
	}
}

func findProbe(t testing.TB, probes []Probe, id ProbeID) Probe {
	t.Helper()
	for _, p := range probes {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("graph has no %s row", id)
	return Probe{}
}

// A healthy HTTPS path proves TCP, TLS and HTTPS on one socket with one TLS
// handshake. The target connects only for Target TCP and PMTU.
func TestHealthyHTTPSSharesOneTargetConnection(t *testing.T) {
	f := newBudgetFixture(t)
	// The egress and encrypted DNS probes also dial 443 and would be counted.
	probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(timedProbes(f.ops().buildProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true)))
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS, ProbePMTU)

	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if res[id].Status != StatusPass {
			t.Fatalf("%s = %v on a healthy path: %s", id, res[id].Status, res[id].Detail)
		}
	}
	if got, want := targetDials(f), 2; got != want {
		t.Errorf("connections to the target = %d, want %d (Target TCP and PMTU only)", got, want)
	}
	if got, want := f.targetHandshakes.Load(), int64(1); got != want {
		t.Errorf("TLS handshakes with the target = %d, want %d", got, want)
	}
	if got := f.targetProto.Load(); got != 2 {
		t.Errorf("HEAD served over HTTP/%d, want HTTP/2 as on a fresh HTTPS connection", got)
	}
	if !res[ProbeHTTPS].SelectedIP.Equal(res[ProbeTargetTCP].SelectedIP) {
		t.Errorf("HTTPS pinned %v, Target TCP selected %v", res[ProbeHTTPS].SelectedIP, res[ProbeTargetTCP].SelectedIP)
	}
	shared := res[ProbeTargetTCP].acquisition
	if shared == 0 {
		t.Fatal("Target TCP carries no acquisition id on a shared socket")
	}
	if res[ProbeTLS].acquisition != shared || res[ProbeHTTPS].acquisition != shared {
		t.Errorf("TLS %d and HTTPS %d do not name the socket Target TCP used (%d)",
			res[ProbeTLS].acquisition, res[ProbeHTTPS].acquisition, shared)
	}
	if res[ProbePMTU].acquisition != 0 {
		t.Errorf("PMTU carries acquisition %d, but it dials its own socket", res[ProbePMTU].acquisition)
	}
}

// Disarmed, the same graph must keep the old behavior: a connection per row
// and a handshake per HTTPS row, with no provenance claimed.
func TestUnlinkedRowsDialAsBefore(t *testing.T) {
	f := newBudgetFixture(t)
	probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(timedProbes(f.ops().buildProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true)))
	disarm(probes)
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)

	if got, want := targetDials(f), 4; got != want {
		t.Errorf("connections to the target = %d, want %d (Target TCP, PMTU, TLS, HTTPS)", got, want)
	}
	if got, want := f.targetHandshakes.Load(), int64(2); got != want {
		t.Errorf("TLS handshakes with the target = %d, want %d", got, want)
	}
	for id, r := range res {
		if r.acquisition != 0 {
			t.Errorf("%s carries acquisition %d with no sharing", id, r.acquisition)
		}
	}
}

// Sharing changes how many sockets the rows use, not what they conclude. Each
// case runs once shared and once disarmed on fresh fixtures, and must produce
// the same row statuses and the same diagnosis.
func TestSharedSocketLeavesDiagnosisUnchanged(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t testing.TB, f *budgetFixture, o *netops)
		// wantTLS and wantHTTPS prove the case reaches the failure it is named for.
		wantTLS, wantHTTPS Status
	}{
		{"healthy", func(testing.TB, *budgetFixture, *netops) {}, StatusPass, StatusPass},
		{"server closes after accept", func(t testing.TB, f *budgetFixture, _ *netops) {
			closing := newPipeNet(t)
			go func() {
				for {
					c, err := closing.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}()
			f.tlsPipe = closing
		}, StatusFail, StatusSkip},
		{"invalid HTTP response", func(t testing.TB, f *budgetFixture, o *netops) {
			cert, roots := selfSignedCert(t, budgetTargetHost)
			garbage := newPipeNet(t)
			go func() {
				for {
					c, err := garbage.Accept()
					if err != nil {
						return
					}
					go answerWithGarbage(c, cert)
				}
			}()
			f.tlsPipe = garbage
			o.tlsRootCAs = roots
			o.dialTLS = trustingDialTLS(f.dial, roots)
		}, StatusPass, StatusFail},
		{"certificate not trusted", func(_ testing.TB, f *budgetFixture, o *netops) {
			o.tlsRootCAs = nil
			o.dialTLS = dialTLSWith(f.dial)
		}, StatusFail, StatusSkip},
	}
	tg := mustTarget(t, budgetTargetHost+":443")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := func(shared bool) (Diagnosis, map[ProbeID]ProbeResult) {
				f := newBudgetFixture(t)
				o := f.ops()
				c.setup(t, f, o)
				probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(o.timedProbes(tg, DefaultPublicDNS, true))
				if !shared {
					disarm(probes)
				}
				res := RunAll(context.Background(), probes, DefaultProbeTimeout)
				requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)
				order := make([]ProbeID, len(probes))
				for i, p := range probes {
					order[i] = p.ID
				}
				return Interpret(tg, order, res), res
			}
			shared, sharedRes := run(true)
			plain, plainRes := run(false)

			if got := sharedRes[ProbeTLS].Status; got != c.wantTLS {
				t.Fatalf("TLS = %v shared, want %v: %s", got, c.wantTLS, sharedRes[ProbeTLS].Cause)
			}
			if got := sharedRes[ProbeHTTPS].Status; got != c.wantHTTPS {
				t.Fatalf("HTTPS = %v shared, want %v: %s", got, c.wantHTTPS, sharedRes[ProbeHTTPS].Cause)
			}
			if sharedRes[ProbeTLS].acquisition == 0 {
				t.Fatalf("shared run did not share its socket with the TLS row: %+v", sharedRes[ProbeTLS])
			}
			for id, want := range plainRes {
				if got := sharedRes[id]; got.Status != want.Status || got.Cause != want.Cause {
					t.Errorf("%s = %v/%q shared, %v/%q disarmed", id, got.Status, got.Cause, want.Status, want.Cause)
				}
			}
			if shared.Verdict != plain.Verdict || shared.Blamed != plain.Blamed {
				t.Errorf("diagnosis = %s blaming %q shared, %s blaming %q disarmed",
					shared.Verdict, shared.Blamed, plain.Verdict, plain.Blamed)
			}
			if len(shared.Findings) != len(plain.Findings) {
				t.Fatalf("findings = %d shared, %d disarmed", len(shared.Findings), len(plain.Findings))
			}
			for i := range shared.Findings {
				s, p := shared.Findings[i], plain.Findings[i]
				if s.ID != p.ID || s.Focus != p.Focus || s.Confidence != p.Confidence {
					t.Errorf("finding %d = %s/%s/%v shared, %s/%s/%v disarmed",
						i, s.ID, s.Focus, s.Confidence, p.ID, p.Focus, p.Confidence)
				}
			}
		})
	}
}

// trackedConn remembers whether its owner closed it.
type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

type connLog struct {
	mu    sync.Mutex
	conns []*trackedConn
}

func (l *connLog) add(c net.Conn) net.Conn {
	tc := &trackedConn{Conn: c}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.conns = append(l.conns, tc)
	return tc
}

func (l *connLog) all() []*trackedConn {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*trackedConn(nil), l.conns...)
}

// Every socket the target connect opens must end with its owner. Each one is
// closed by the probe that holds it when nothing takes it over.
func TestSharedSocketHasOneOwner(t *testing.T) {
	t.Run("no TLS row to take it", func(t *testing.T) {
		f := newBudgetFixture(t)
		o := f.ops()
		var log connLog
		dial := o.dialContext
		o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil || addr != "127.0.0.1:443" {
				return c, err
			}
			return log.add(c), nil
		}
		probes := ProbeSelection{Check: map[ProbeID]struct{}{ProbeTargetTCP: {}}}.Apply(o.timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))
		res := RunAll(context.Background(), probes, DefaultProbeTimeout)
		if res[ProbeTargetTCP].Status != StatusPass {
			t.Fatalf("Target TCP = %v: %s", res[ProbeTargetTCP].Status, res[ProbeTargetTCP].Detail)
		}
		conns := log.all()
		if len(conns) != 1 {
			t.Fatalf("Target TCP opened %d sockets, want 1", len(conns))
		}
		if !conns[0].closed.Load() {
			t.Error("Target TCP left its socket open with no TLS row to take it")
		}
		if res[ProbeTargetTCP].acquisition != 0 {
			t.Errorf("Target TCP claims acquisition %d for a socket it closed", res[ProbeTargetTCP].acquisition)
		}
	})

	t.Run("release closes a socket nobody took", func(t *testing.T) {
		f := newBudgetFixture(t)
		probes := f.ops().timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true)
		link := findProbe(t, probes, ProbeTargetTCP).link
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		tc := &trackedConn{Conn: client}
		if !link.offer(tc) {
			t.Fatal("an empty link refused a socket")
		}
		ReleaseProbes(probes)
		if !tc.closed.Load() {
			t.Error("ReleaseProbes left the held socket open")
		}
		if link.offer(client) {
			t.Error("a released link accepted a socket")
		}
	})
}

// The shared socket belongs to whichever family won the race. The losing
// family's failure is recorded on Target TCP and must not leak into TLS or HTTPS.
func TestSharedSocketFollowsTheWinningFamily(t *testing.T) {
	for _, tc := range []struct {
		name          string
		winner, loser string
	}{
		{"IPv4 wins", "127.0.0.1", "[::1]"},
		{"IPv6 wins", "[::1]", "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBudgetFixture(t)
			f.loopbacks = []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}
			o := f.ops()
			dial := o.dialContext
			o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, tc.loser+":") {
					return nil, syscall.ECONNREFUSED
				}
				return dial(ctx, network, addr)
			}
			probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(o.timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))
			res := RunAll(context.Background(), probes, DefaultProbeTimeout)
			requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)

			winner := net.ParseIP(strings.Trim(tc.winner, "[]"))
			// One family failed, so Target TCP is a warning. The TLS and HTTPS rows
			// still succeed on the family that answered.
			if res[ProbeTargetTCP].Status != StatusWarn {
				t.Fatalf("Target TCP = %v with one dead family, want warn: %s", res[ProbeTargetTCP].Status, res[ProbeTargetTCP].Detail)
			}
			for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
				if res[id].Status == StatusFail {
					t.Fatalf("%s = %v: %s", id, res[id].Status, res[id].Detail)
				}
				if !res[id].SelectedIP.Equal(winner) {
					t.Errorf("%s pinned %v, want the winning %v", id, res[id].SelectedIP, winner)
				}
			}
			if s := res[ProbeTargetTCP].acquisition; s == 0 || res[ProbeTLS].acquisition != s || res[ProbeHTTPS].acquisition != s {
				t.Errorf("rows do not share one socket: TCP %d TLS %d HTTPS %d",
					res[ProbeTargetTCP].acquisition, res[ProbeTLS].acquisition, res[ProbeHTTPS].acquisition)
			}
			fam := res[ProbeTargetTCP].Families
			if fam == nil {
				t.Fatal("Target TCP reports no family evidence")
			}
			loserFamily := fam.IPv4
			if strings.HasPrefix(tc.loser, "[") {
				loserFamily = fam.IPv6
			}
			if loserFamily != FamilyUnreachable {
				t.Errorf("losing family %s = %q, want %q", tc.loser, loserFamily, FamilyUnreachable)
			}
		})
	}
}

// The link is a one-slot handoff. Whoever takes the socket owns it, and release
// is final.
func TestTargetLinkHoldsOneSocketAndReleasesIt(t *testing.T) {
	var none *targetLink
	if none.take() != nil {
		t.Fatal("a nil link yielded a socket")
	}
	none.release()

	l := newTargetLink()
	a, b := net.Pipe()
	defer b.Close()
	if !l.offer(a) {
		t.Fatal("an empty slot refused a socket")
	}
	if l.offer(b) {
		t.Fatal("a full slot accepted a second socket")
	}
	if got := l.take(); got != a {
		t.Fatalf("take = %v, want the offered socket", got)
	}
	if l.take() != nil {
		t.Fatal("take returned a socket twice")
	}
	if !l.offer(a) {
		t.Fatal("the emptied slot refused a socket")
	}
	l.release()
	if _, err := a.Write([]byte{0}); err == nil {
		t.Error("release left the held socket open")
	}
	if l.offer(b) {
		t.Error("a released link accepted a socket")
	}
}

// trustingDialTLS dials through dial and trusts roots, which the TLS probes
// do not put in their config themselves.
func trustingDialTLS(dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) func(context.Context, string, string, *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		trusted := cfg.Clone()
		trusted.RootCAs = roots
		return dialTLSWith(dial)(ctx, network, addr, trusted)
	}
}

// answerWithGarbage completes the handshake, reads the request head, and replies
// with bytes that are not HTTP. The TLS row sees a valid handshake; HTTPS must
// fail on the response.
func answerWithGarbage(c net.Conn, cert tls.Certificate) {
	defer c.Close()
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
	if tc.Handshake() != nil {
		return
	}
	r := bufio.NewReader(tc)
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(tc, "not an HTTP response\r\n\r\n")
}

// delayConn models a path with a fixed round trip. A read that follows a write
// waits one round trip from that write. This is simulated time, not a measurement
// of a real network.
type delayConn struct {
	net.Conn
	rtt  time.Duration
	mu   sync.Mutex
	sent time.Time
}

func (c *delayConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.sent = time.Now()
	c.mu.Unlock()
	return n, err
}

func (c *delayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	sent := c.sent
	c.sent = time.Time{}
	c.mu.Unlock()
	if !sent.IsZero() {
		time.Sleep(time.Until(sent.Add(c.rtt)))
	}
	return c.Conn.Read(p)
}

// delayedDial charges one simulated round trip for connecting.
func delayedDial(dial func(context.Context, string, string) (net.Conn, error), rtt time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		time.Sleep(rtt)
		return &delayConn{Conn: c, rtt: rtt}, nil
	}
}

// BenchmarkHealthyHTTPSRoundTrip times the verdict of the TCP, TLS and HTTPS
// rows against simulated round trips, shared and disarmed, and reports how many
// target connections and TLS handshakes each run needed. Run it with
// go test -run '^$' -bench BenchmarkHealthyHTTPSRoundTrip -benchtime 3x.
func BenchmarkHealthyHTTPSRoundTrip(b *testing.B) {
	f := newBudgetFixture(b)
	tg, err := ParseTarget(budgetTargetHost + ":443")
	if err != nil {
		b.Fatal(err)
	}
	benchRows := map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeTLS: {}, ProbeHTTPS: {}}
	for _, rtt := range []time.Duration{0, 20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond} {
		for _, shared := range []bool{false, true} {
			b.Run(fmt.Sprintf("rtt=%s/shared=%t", rtt, shared), func(b *testing.B) {
				o := f.ops()
				o.dialContext = delayedDial(f.dial, rtt)
				o.dialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					trusted := cfg.Clone()
					trusted.RootCAs = f.roots
					return dialTLSWith(o.dialContext)(ctx, network, addr, trusted)
				}
				connects, handshakes := targetDials(f), f.targetHandshakes.Load()
				b.ResetTimer()
				for range b.N {
					probes := ProbeSelection{Check: benchRows}.Apply(o.timedProbes(tg, DefaultPublicDNS, true))
					if !shared {
						disarm(probes)
					}
					res := RunAll(context.Background(), probes, 10*time.Second)
					requireRows(b, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)
					for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
						if res[id].Status != StatusPass {
							b.Fatalf("%s = %v: %s", id, res[id].Status, res[id].Detail)
						}
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(targetDials(f)-connects)/float64(b.N), "connects/op")
				b.ReportMetric(float64(f.targetHandshakes.Load()-handshakes)/float64(b.N), "handshakes/op")
			})
		}
	}
}

// A refused target has no socket to share. Target TCP fails, and TLS and HTTPS
// must fail on their own dials without taking or claiming any handoff.
func TestRefusedTargetLeavesNothingToShare(t *testing.T) {
	f := newBudgetFixture(t)
	o := f.ops()
	refused := func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":443") {
			return refused(ctx, network, addr)
		}
		return f.dial(ctx, network, addr)
	}
	o.dialTLS = func(context.Context, string, string, *tls.Config) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(o.timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)

	// TLS and HTTPS are gated on the TCP row by the graph, so they never dial.
	if res[ProbeTargetTCP].Status != StatusFail {
		t.Errorf("Target TCP = %v with the target refusing, want fail", res[ProbeTargetTCP].Status)
	}
	for _, id := range []ProbeID{ProbeTLS, ProbeHTTPS} {
		if res[id].Status != StatusSkip {
			t.Errorf("%s = %v behind a failed Target TCP, want skip", id, res[id].Status)
		}
	}
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if res[id].acquisition != 0 {
			t.Errorf("%s claims socket %d that was never connected", id, res[id].acquisition)
		}
	}
	if got := f.targetHandshakes.Load(); got != 0 {
		t.Errorf("TLS handshakes = %d with no connection, want 0", got)
	}
}

// A handshake that fails or is cancelled must close the socket it was given.
// The caller has already handed ownership over and cannot close it again.
func TestHandshakeOnFailureClosesTheSocket(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		peer bool // the peer closes at once, so the handshake gets EOF
	}{
		{"peer closes", context.Background(), true},
		{"context cancelled", cancelled, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			if tc.peer {
				_ = server.Close()
			} else {
				t.Cleanup(func() { _ = server.Close() })
			}
			if _, err := handshakeOn(tc.ctx, client, budgetTargetHost, nil, true); err == nil {
				t.Fatal("handshake succeeded")
			}
			if _, err := client.Write([]byte{0}); err == nil {
				t.Error("failed handshake left the socket open")
			}
		})
	}
}

// Rows of one graph may run on different goroutines. Every socket offered to
// the link must end up with exactly one owner: a taker, or release.
func TestTargetLinkIsRaceSafe(t *testing.T) {
	l := newTargetLink()
	const workers, rounds = 8, 200
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		offers []net.Conn
		takes  []net.Conn
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range rounds {
				c, peer := net.Pipe()
				go func() { _ = peer.Close() }()
				if l.offer(c) {
					mu.Lock()
					offers = append(offers, c)
					mu.Unlock()
				} else {
					_ = c.Close()
				}
				if got := l.take(); got != nil {
					mu.Lock()
					takes = append(takes, got)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if rest := l.take(); rest != nil {
		takes = append(takes, rest)
	}
	if len(offers) != len(takes) {
		t.Fatalf("%d sockets accepted, %d taken: a socket was lost or taken twice", len(offers), len(takes))
	}
	seen := make(map[net.Conn]bool, len(takes))
	for _, c := range takes {
		if seen[c] {
			t.Fatal("a socket was taken twice")
		}
		seen[c] = true
	}
	l.release()
}
