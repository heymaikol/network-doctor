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
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// liveServer is an HTTPS server on loopback with its own counters.
type liveServer struct {
	port       string
	roots      *x509.CertPool
	accepts    atomic.Int64 // sockets accepted
	handshakes atomic.Int64 // TLS handshakes completed
}

type countingListener struct {
	net.Listener
	live *liveServer
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.live.accepts.Add(1)
	}
	return c, err
}

func startLiveServer(t *testing.T) *liveServer {
	t.Helper()
	cert, roots := selfSignedCert(t, "localhost")
	live := &liveServer{roots: roots}
	srv := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				live.handshakes.Add(1)
				return nil, nil
			},
		},
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.ServeTLS(&countingListener{Listener: ln, live: live}, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	_, live.port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return live
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
func runLive(t *testing.T, shared bool) (map[ProbeID]ProbeResult, *liveServer) {
	t.Helper()
	live := startLiveServer(t)
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
	shared, sharedLive := runLive(t, true)
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

	plain, plainLive := runLive(t, false)
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
