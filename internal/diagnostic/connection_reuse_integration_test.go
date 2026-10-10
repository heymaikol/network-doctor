//go:build integration

package diagnostic

// Real loopback sockets: the target rows against a live HTTPS server. The
// server counts the sockets it accepts and the handshakes it completes. The
// client wraps every socket it dials and requires each one to be closed by its
// owner once the probes return. The client side is the one that decides, so the
// check does not depend on when a garbage collector would release a socket.
// Run with: go test -tags integration ./internal/diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// liveServer is an HTTPS server on loopback with its own counters. Each counter
// means one thing: accepts is every TCP socket, clientHellos every ClientHello
// read, handshakes only the handshakes that completed, requests every HTTP
// request answered, and bytesIn every byte the server read off its sockets. A
// refused handshake therefore moves clientHellos alone.
type liveServer struct {
	port         string
	roots        *x509.CertPool
	cert         tls.Certificate
	accepts      atomic.Int64
	clientHellos atomic.Int64
	handshakes   atomic.Int64
	requests     atomic.Int64
	http2        atomic.Int64
	bytesIn      atomic.Int64
	// pending counts accepted sockets whose handshake has not yet returned.
	// awaitServed waits for it to reach zero before the counters are read.
	pending atomic.Int64
	// refuse makes every new handshake fail after its ClientHello, as a server
	// with a broken certificate or a TLS-terminating middlebox does. The socket
	// still accepts, so TCP passes and TLS fails.
	refuse atomic.Bool
	// dropFirst closes the first socket accepted before any byte is read, as a
	// middlebox or a restarting backend does right after accept.
	dropFirst bool
}

// errRefusedHandshake is what GetConfigForClient returns when refuse is set.
var errRefusedHandshake = errors.New("handshake refused by fixture")

// handshakingListener completes each TLS handshake before it hands a connection
// to the server. ServeTLS would hand over connections whose handshake has not
// run yet, so a refused handshake would be counted as a completed one.
type handshakingListener struct {
	net.Listener
	live  *liveServer
	cfg   *tls.Config
	ready chan net.Conn
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	raw   map[net.Conn]bool // accepted sockets whose handshake is still running
}

// handshakeTimeout bounds how long a silent client can hold a handshake open.
const handshakeTimeout = 5 * time.Second

func newHandshakingListener(ln net.Listener, live *liveServer, cfg *tls.Config) *handshakingListener {
	l := &handshakingListener{Listener: ln, live: live, cfg: cfg, ready: make(chan net.Conn), done: make(chan struct{}), raw: map[net.Conn]bool{}}
	go l.acceptLoop()
	return l
}

func (l *handshakingListener) acceptLoop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			_ = l.Close()
			return
		}
		// pending goes up before accepts, so a reader that sees the socket
		// counted also sees it pending until its handshake returns.
		l.live.pending.Add(1)
		n := l.live.accepts.Add(1)
		if l.live.dropFirst && n == 1 {
			_ = c.Close()
			l.live.pending.Add(-1)
			continue
		}
		c = &countingConn{Conn: c, bytes: &l.live.bytesIn}
		// Close sweeps raw under mu after it closes done. A socket checked and
		// tracked under the same lock is either swept or refused here, never
		// left running after Close has returned.
		l.mu.Lock()
		if l.closed() {
			l.mu.Unlock()
			_ = c.Close()
			l.live.pending.Add(-1)
			return
		}
		l.raw[c] = true
		l.mu.Unlock()
		go l.handshake(c)
	}
}

// countingConn counts the bytes read from one accepted socket.
type countingConn struct {
	net.Conn
	bytes *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytes.Add(int64(n))
	return n, err
}

func (l *handshakingListener) handshake(c net.Conn) {
	defer l.live.pending.Add(-1)
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	tc := tls.Server(c, l.cfg)
	err := tc.Handshake()
	if err == nil {
		l.live.handshakes.Add(1)
		_ = c.SetDeadline(time.Time{})
	} else {
		// Read out what the client still sends before the socket closes. A close
		// with unread bytes resets the connection, and a reset can cut the client's
		// bulk write short at a point set by timing. The path-MTU probe sends such a
		// write after a handshake that fails, so its verdict then flips between PASS
		// and N/A from one pass to the next. A peer that reads what it is sent does
		// not reset. The socket stays in raw until the drain ends, so Close still
		// sweeps it, and the handshake deadline bounds the drain.
		_, _ = io.Copy(io.Discard, c)
	}
	l.mu.Lock()
	delete(l.raw, c)
	l.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return
	}
	select {
	case l.ready <- tc:
	case <-l.done:
		_ = tc.Close()
	}
}

// closed reports whether Close has begun. Callers hold mu, so a socket checked
// here is either swept by Close or refused.
func (l *handshakingListener) closed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *handshakingListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ready:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops the listener, and closes every socket whose handshake is still
// running so no handshake goroutine outlives the server.
func (l *handshakingListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() {
		close(l.done)
		l.mu.Lock()
		defer l.mu.Unlock()
		for c := range l.raw {
			_ = c.Close()
		}
	})
	return err
}

func startLiveServer(t testing.TB, dropFirst bool) *liveServer {
	t.Helper()
	cert, roots := selfSignedCert(t, "localhost")
	live := &liveServer{roots: roots, cert: cert, dropFirst: dropFirst}
	live.listen(t, "127.0.0.1:0")
	return live
}

// listen serves live on addr, a loopback address. stop is as for serve.
func (live *liveServer) listen(t testing.TB, addr string) (stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return live.serve(t, ln)
}

// serve runs the HTTPS server on ln, a loopback listener, and sets live.port to
// its port. The returned func stops the server: it closes the listener and every
// socket it holds, and returns once the server has finished, so a test that
// restarts on the same port starts from nothing open.
func (live *liveServer) serve(t testing.TB, ln net.Listener) (stop func()) {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{live.cert},
		// Serve does not offer HTTP/2 the way ServeTLS does, so the list is set here.
		// Without h2 in it, an HTTP/2 client falls back to HTTP/1.1 and the h2 path
		// goes untested against a real server.
		NextProtos: []string{"h2", "http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			live.clientHellos.Add(1)
			if live.refuse.Load() {
				return nil, errRefusedHandshake
			}
			return nil, nil
		},
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			live.requests.Add(1)
			if r.ProtoMajor == 2 {
				live.http2.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	live.port = port
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(newHandshakingListener(ln, live, cfg))
	}()
	stop = func() {
		_ = srv.Close()
		<-served
	}
	t.Cleanup(stop)
	return stop
}

// awaitServed waits, bounded, until every accepted socket has finished its
// handshake attempt. The counters are read only after that, so a handshake that
// completes on the server just after the client returns is still counted.
func awaitServed(t testing.TB, live *liveServer) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for live.pending.Load() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d server handshakes still running after the client returned", live.pending.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// dialLog records every connection the client dials, so each one can be
// checked for a Close by whoever ends up holding it.
type dialLog struct {
	mu    sync.Mutex
	conns []*trackedConn
}

func (d *dialLog) wrap(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := &trackedConn{Conn: c}
		d.mu.Lock()
		d.conns = append(d.conns, tc)
		d.mu.Unlock()
		return tc, nil
	}
}

// runLive diagnoses the live server with the target rows, shared or disarmed.
func runLive(t *testing.T, shared, dropFirst bool) (map[ProbeID]ProbeResult, *liveServer) {
	t.Helper()
	live := startLiveServer(t, dropFirst)
	tg, err := ParseTarget("https://localhost:" + live.port)
	if err != nil {
		t.Fatal(err)
	}
	var dials dialLog
	o := opsFromSources(nil)
	o.lookupIP = func(context.Context, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, []string{"loopback"}, nil
	}
	o.tlsRootCAs = live.roots
	o.dialContext = dials.wrap(o.dialContext)
	o.dialTLS = trustingDialTLS(o.dialContext, live.roots)
	probes := ProbeSelection{Check: map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeTLS: {}, ProbeHTTPS: {}}}.Apply(o.timedProbes(tg, DefaultPublicDNS, true))
	if !shared {
		disarm(probes)
	}
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)
	awaitClosed(t, &dials)
	awaitServed(t, live)
	return res, live
}

// awaitClosed gives the transport a moment to finish with its connections, then
// fails for each dialed socket still open. A socket nobody closed is a leak.
func awaitClosed(t *testing.T, dials *dialLog) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		dials.mu.Lock()
		open := 0
		for _, c := range dials.conns {
			if !c.closed.Load() {
				open++
			}
		}
		total := len(dials.conns)
		dials.mu.Unlock()
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%d of %d dialed sockets were never closed by their owner", open, total)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The shared run answers TCP, TLS and HTTPS from one dialed socket and one
// handshake, and closes it. The disarmed run dials one socket per row, with two
// handshakes. Both must agree on every row's status.
func TestSharedSocketAgainstLiveHTTPSServer(t *testing.T) {
	shared, sharedLive := runLive(t, true, false)
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if shared[id].Status != StatusPass {
			t.Fatalf("%s = %v on a live server: %s", id, shared[id].Status, shared[id].Cause)
		}
	}
	if got := sharedLive.accepts.Load(); got != 1 {
		t.Errorf("server accepted %d sockets, want 1 shared by TCP, TLS and HTTPS", got)
	}
	if got := sharedLive.handshakes.Load(); got != 1 {
		t.Errorf("server completed %d handshakes, want 1", got)
	}
	if got := sharedLive.http2.Load(); got != 1 {
		t.Errorf("server answered %d requests over HTTP/2, want 1: the HTTPS row must reach the live server's h2 path", got)
	}

	plain, plainLive := runLive(t, false, false)
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if plain[id].Status != shared[id].Status {
			t.Errorf("%s = %v disarmed, %v shared", id, plain[id].Status, shared[id].Status)
		}
	}
	if got := plainLive.accepts.Load(); got != 3 {
		t.Errorf("disarmed server accepted %d sockets, want 3 (TCP, TLS, HTTPS)", got)
	}
	if got := plainLive.handshakes.Load(); got != 2 {
		t.Errorf("disarmed server completed %d handshakes, want 2", got)
	}
}

// A socket the server drops right after accept must not fail the rows. TCP
// connects to it and passes. TLS reads the closure, dials again, and passes.
// HTTPS then dials for itself. Both runs agree, and no socket is left open.
func TestSharedSocketSurvivesDroppedFirstSocket(t *testing.T) {
	shared, sharedLive := runLive(t, true, true)
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if shared[id].Status != StatusPass {
			t.Fatalf("%s = %v shared on a live server: %s", id, shared[id].Status, shared[id].Cause)
		}
	}
	for _, id := range []ProbeID{ProbeTLS, ProbeHTTPS} {
		if got := shared[id].acquisition; got != 0 {
			t.Errorf("%s fell back to a fresh connection but still claims socket %d", id, got)
		}
	}
	if got := sharedLive.accepts.Load(); got != 3 {
		t.Errorf("server accepted %d sockets, want 3: the dropped one, its replacement, and HTTPS", got)
	}
	if got := sharedLive.handshakes.Load(); got != 2 {
		t.Errorf("server completed %d handshakes, want 2", got)
	}

	plain, _ := runLive(t, false, true)
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if plain[id].Status != shared[id].Status {
			t.Errorf("%s = %v disarmed, %v shared", id, plain[id].Status, shared[id].Status)
		}
	}
}

// A handshake the client refuses never completes, so the server must not count
// it as one. The client here trusts no root, so it aborts after the server has
// already sent its certificate. The server saw the ClientHello and nothing more.
func TestLiveServerCountsOnlyCompletedHandshakes(t *testing.T) {
	live := startLiveServer(t, false)
	raw, err := net.Dial("tcp4", "127.0.0.1:"+live.port)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(raw, &tls.Config{ServerName: "localhost", RootCAs: x509.NewCertPool()})
	if err := client.Handshake(); err == nil {
		_ = client.Close()
		t.Fatal("handshake succeeded against a root the client does not trust")
	}
	_ = client.Close()
	awaitServed(t, live)
	if got := live.clientHellos.Load(); got != 1 {
		t.Errorf("server read %d ClientHellos, want 1", got)
	}
	if got := live.handshakes.Load(); got != 0 {
		t.Errorf("server counted %d completed handshakes for a refused one, want 0", got)
	}
}
