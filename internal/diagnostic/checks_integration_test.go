//go:build integration

// Opt-in (-tags integration) tests that dial real loopback sockets.

package diagnostic

// Real-socket tests, kept out of the unit suite. Run with:
//
//	go test -tags integration ./internal/diagnostic
//
// Offline-safe: loopback only.

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// dialIPs against a live loopback listener returns a connection pinned to the
// address that won, with the attempt recorded.
func TestDialIPsLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, sel, attempts, rtt := defaultOps.dialIPs(ctx, []net.IP{net.ParseIP("127.0.0.1")}, port)
	if conn == nil {
		t.Fatal("expected a connection to the loopback listener")
	}
	defer conn.Close()
	if !sel.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("selected = %v, want 127.0.0.1", sel)
	}
	if len(attempts) != 1 {
		t.Errorf("attempts = %d, want 1", len(attempts))
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want > 0", rtt)
	}
}

// The configured source reaches the kernel socket rather than only probe
// metadata: the live connection reports the address we pinned.
func TestDialFromSourceLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := opsFromSources(&SourceAddresses{IPv4: net.ParseIP("127.0.0.1")}).dialContext(
		context.Background(), "tcp4", ln.Addr().String(),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := conn.LocalAddr().(*net.TCPAddr).IP; !got.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("source = %v, want 127.0.0.1", got)
	}
}

// A refused loopback port reaches targetTCPProbe through the real wrapped
// socket error chain and receives the structured refusal cause.
func TestTargetTCPProbeRefusedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listening now → connection refused

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r := defaultOps.targetTCPProbe(port)(ctx, map[ProbeID]ProbeResult{
		ProbeDNS: {Addrs: []net.IP{net.ParseIP("127.0.0.1")}},
	})
	if r.Status != StatusFail || r.Cause != ConnectionCauseRefused {
		t.Fatalf("closed loopback result = %+v, want FAIL cause %q", r, ConnectionCauseRefused)
	}
	if len(r.Attempts) != 1 || !errors.Is(r.Attempts[0].Err, connectionRefusedErrno) {
		t.Errorf("want one attempt with wrapped refusal errno, got %+v", r.Attempts)
	}
}

// pathIdentity reads a real winning conn's LocalAddr as ground truth.
func TestPathIdentityLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	src, iface, _ := defaultOps.pathIdentity(context.Background(), conn, net.ParseIP("127.0.0.1"), port)
	if src == nil || !src.IsLoopback() {
		t.Errorf("src = %v, want a loopback address", src)
	}
	if iface == "" {
		t.Error("iface should resolve for the loopback source")
	}
}

// The PMTU probe over a real socket, against the case most likely to produce a
// false alarm: a listener that accepts the connection and then never reads a
// byte. Its receive buffer has to absorb the whole payload; if it doesn't, the
// probe's own write stalls and every healthy peer that pauses gets accused of
// black-holing packets. Nothing here is a black hole, so nothing may warn.
func TestPMTUProbeLoopbackSilentPeerDoesNotWarn(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn // held open, never read from
	}()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
	defer cancel()
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("127.0.0.1")}}
	r := defaultOps.pmtuProbe(port, ProtoNone)(ctx, deps)
	want := StatusPass
	if conn := <-accepted; conn != nil {
		// Where the kernel reports no send queue, delivery cannot be proven and
		// the probe says so instead of passing. Either verdict is silence,
		// which is the property under test; a warn is what may never appear.
		if _, err := socketQueued(conn); err != nil {
			want = StatusNA
		}
		conn.Close()
	}
	if r.Status != want {
		t.Errorf("silent-but-healthy peer = %+v, want %v (%d KiB must fit in its receive buffer)", r, want, pmtuPayloadSize>>10)
	}
}

// socketQueued is the reading the whole probe now rests on, so check it against
// a real kernel rather than a stub: zero on an idle socket, non-zero while a
// peer refuses to drain, and an error on anything that is not a socket.
//
// The falling edge is not asserted here. Draining through the deliberately tiny
// receive window this test needs takes tens of seconds, and
// TestPMTUProbeLoopbackSilentPeerDoesNotWarn already covers it end to end: that
// test can only reach PASS if the queue drops back to zero.
func TestSocketQueuedTracksRealSendQueue(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// A small receive buffer is what makes the backlog appear: the peer
		// cannot quietly absorb the payload the way a default-sized one would.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetReadBuffer(1 << 10)
		}
		accepted <- conn
	}()

	client, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	if queued, err := socketQueued(client); err != nil {
		t.Skipf("no send-queue accounting on this platform: %v", err)
	} else if queued != 0 {
		t.Errorf("idle socket has %d bytes queued, want 0", queued)
	}

	// Far more than the peer's pinned receive window, so some of it has to
	// stay put. Closing the client at test exit releases the writer.
	go func() {
		_ = client.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, _ = client.Write(make([]byte, 1<<20))
	}()
	if queued := pollQueued(t, client, func(n int) bool { return n > 0 }); queued == 0 {
		t.Fatal("send queue never rose while the peer refused to read")
	}

	// net.Pipe has no descriptor, which is how the probe knows to fall back.
	pipe, other := net.Pipe()
	defer pipe.Close()
	defer other.Close()
	if _, err := socketQueued(pipe); err == nil {
		t.Error("socketQueued on a non-socket returned no error")
	}
}

// pollQueued watches the send queue until want holds or the test runs out of
// patience, and reports the last reading either way.
func pollQueued(t *testing.T, conn net.Conn, want func(int) bool) int {
	t.Helper()
	var queued int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		n, err := socketQueued(conn)
		if err != nil {
			t.Fatalf("socketQueued: %v", err)
		}
		if queued = n; want(n) {
			return n
		}
	}
	return queued
}

// ResolveSource resolves both of the forms -iface accepts, without this test
// knowing what the loopback interface is called (lo, lo0, "Loopback
// Pseudo-Interface 1", ...).
func TestResolveSourceResolvesLoopbackInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	name := ""
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback == 0 {
			continue
		}
		if addrs, err := ifaces[i].Addrs(); err == nil && sourceAddresses(addrs) != nil {
			name = ifaces[i].Name
			break
		}
	}
	if name == "" {
		t.Skip("no loopback interface with a usable address")
	}

	sources, err := ResolveSource(name)
	if err != nil {
		t.Fatalf("ResolveSource(%q): %v", name, err)
	}
	ip := sources.primary()
	if !ip.IsLoopback() {
		t.Errorf("ResolveSource(%q).primary() = %v, want a loopback address", name, ip)
	}
	// The interface name rides along for the drill-down tools whose binding
	// option takes a name; the exact-IP form has no name to report.
	if sources.Iface != name {
		t.Errorf("ResolveSource(%q).Iface = %q, want %q", name, sources.Iface, name)
	}
	for _, literal := range []net.IP{sources.IPv4, sources.IPv6} {
		if literal == nil {
			continue
		}
		byIP, err := ResolveSource(literal.String())
		if err != nil {
			t.Fatalf("ResolveSource(%q): %v", literal, err)
		}
		if byIP.Iface != "" {
			t.Errorf("ResolveSource(%q).Iface = %q, want empty", literal, byIP.Iface)
		}
		if !byIP.primary().Equal(literal) || byIP.IPv4 != nil && byIP.IPv6 != nil {
			t.Errorf("ResolveSource(%q) = %+v, want only that address", literal, byIP)
		}
	}

	// The exact-IP form has to accept what the name form just handed back.
	again, err := ResolveSource(ip.String())
	if err != nil {
		t.Fatalf("ResolveSource(%q): %v", ip, err)
	}
	if !again.primary().Equal(ip) {
		t.Errorf("ResolveSource(%q).primary() = %v, want %v", ip, again.primary(), ip)
	}

	// TEST-NET-1 is reserved for documentation, so it is never a local address.
	if _, err := ResolveSource("192.0.2.1"); err == nil {
		t.Error("an unassigned IP should be rejected")
	}
	if _, err := ResolveSource("netdoc-no-such-interface"); err == nil {
		t.Error("an unknown interface name should be rejected")
	}
}

// The configured source has to reach the DNS socket too, not only the TCP one:
// a probe that binds correctly while its resolver leaks onto the default route
// is the failure this test exists to catch.
func TestResolverDialsFromSourceLoopback(t *testing.T) {
	stub := newDNSStub(t, net.ParseIP("192.0.2.7"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The address the hook is handed comes from resolv.conf and varies per
	// machine; send every query to the stub instead. What is under test is the
	// dialer the source produced, not which server the host would have picked.
	dial := dialContextFromSources(sourceAddresses([]net.Addr{&net.IPAddr{IP: net.ParseIP("127.0.0.1")}}))
	ips, targets, err := lookupIPWithDial(ctx, "netdoc.test.", func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, stub.addr())
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !containsIP(ips, net.ParseIP("192.0.2.7")) {
		t.Errorf("ips = %v, want 192.0.2.7", ips)
	}
	if len(targets) == 0 {
		t.Error("lookup should report the resolver target that was tried")
	}
	stub.wantSources(t, net.ParseIP("127.0.0.1"))
}

// Same for the second-opinion resolver, which additionally must ignore the
// address it is given and always ask the public server.
func TestPublicResolverDialsFromSourceLoopback(t *testing.T) {
	stub := newDNSStub(t, net.ParseIP("192.0.2.8"))
	// The first resolver the untouched default reaches for. Which one it is does
	// not matter here; that it is the address the dial hook sees does.
	resolver := publicDNSServer(PublicDNSCandidates(DefaultPublicDNS, true)[0])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		mu      sync.Mutex
		targets []string
	)
	dial := dialContextFromSources(sourceAddresses([]net.Addr{&net.IPAddr{IP: net.ParseIP("127.0.0.1")}}))
	ips, targets, err := lookupIPPublicWithDial(ctx, "netdoc.test.", func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		targets = append(targets, addr)
		mu.Unlock()
		return dial(ctx, network, stub.addr())
	}, resolver)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !containsIP(ips, net.ParseIP("192.0.2.8")) {
		t.Errorf("ips = %v, want 192.0.2.8", ips)
	}
	if len(targets) != 1 || targets[0] != resolver {
		t.Errorf("resolver targets = %v, want %s", targets, resolver)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(targets) == 0 {
		t.Fatal("the dial hook was never called")
	}
	for _, addr := range targets {
		if addr != resolver {
			t.Errorf("dialed %q, want %q", addr, resolver)
		}
	}
	stub.wantSources(t, net.ParseIP("127.0.0.1"))
}

func containsIP(ips []net.IP, want net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(want) {
			return true
		}
	}
	return false
}

// dnsStub is a loopback UDP resolver that answers A queries with one fixed
// address and everything else with an empty NOERROR, enough to satisfy the Go
// resolver's parallel A/AAAA pair without a DNS library. It records the source
// address every query arrived from, which is the whole point of it.
type dnsStub struct {
	conn *net.UDPConn
	mu   sync.Mutex
	srcs []net.IP
}

func newDNSStub(t *testing.T, answer net.IP) *dnsStub {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	s := &dnsStub{conn: conn}
	go s.serve(answer)
	return s
}

func (s *dnsStub) addr() string { return s.conn.LocalAddr().String() }

func (s *dnsStub) serve(answer net.IP) {
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // closed by cleanup
		}
		s.mu.Lock()
		s.srcs = append(s.srcs, from.IP)
		s.mu.Unlock()
		if reply := dnsReply(buf[:n], answer); reply != nil {
			s.conn.WriteToUDP(reply, from)
		}
	}
}

// wantSources asserts every query reached the stub from want. Reading after the
// lookup returned is safe: the resolver has no queries left in flight.
func (s *dnsStub) wantSources(t *testing.T, want net.IP) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.srcs) == 0 {
		t.Fatal("no query reached the stub resolver")
	}
	for _, src := range s.srcs {
		if !src.Equal(want) {
			t.Errorf("query source = %v, want %v", src, want)
		}
	}
}

// dnsReply turns a query into a response: the same header and question back,
// plus a single A record when A is what was asked for. Anything else, whether
// AAAA or a packet too short to parse, gets an answerless NOERROR, which the resolver
// accepts without retrying.
func dnsReply(q []byte, answer net.IP) []byte {
	if len(q) < 12 {
		return nil
	}
	// Walk the question's length-prefixed labels to the qtype behind them.
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1:])

	r := append([]byte(nil), q[:i+5]...)
	r[2], r[3] = 0x81, 0x80 // QR + RD, RA + NOERROR
	binary.BigEndian.PutUint16(r[6:], 0)
	// Any EDNS OPT record the resolver appended is dropped along with the
	// counts that described it.
	binary.BigEndian.PutUint16(r[8:], 0)
	binary.BigEndian.PutUint16(r[10:], 0)
	if qtype != 1 {
		return r
	}
	binary.BigEndian.PutUint16(r[6:], 1)
	// 0xc00c points back at the question's name; then A, IN, TTL 60, 4 bytes.
	r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(r, answer.To4()...)
}

func TestTargetSiblingVerificationUsesSelectedSourceLoopback(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ip, winner := net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")
	o := opsFromSources(&SourceAddresses{IPv4: ip})
	dial := o.dialContext
	var source net.IP
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			source = conn.LocalAddr().(*net.TCPAddr).IP
		}
		return conn, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
	defer cancel()
	got, ran := o.verifyTargetSibling(ctx, []net.IP{ip, winner}, winner, []Attempt{
		{IP: ip, Err: context.Canceled, Cause: ConnectionCauseCanceled, Aborted: true}, {IP: winner},
	}, ln.Addr().(*net.TCPAddr).Port)
	if !ran || got.Err != nil || !source.Equal(ip) {
		t.Fatalf("ran=%t attempt=%+v source=%v", ran, got, source)
	}
}
