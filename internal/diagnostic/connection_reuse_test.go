package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// differentialRows is the check set for the differential cases. PMTU is left
// out: it dials the target on its own and in parallel, so it would race for
// which dial reaches the fixture first.
var differentialRows = map[ProbeID]struct{}{ProbeTargetTCP: {}, ProbeTLS: {}, ProbeHTTPS: {}}

// dropFirstDial makes the first connection to the target a socket the server
// closes after reading the ClientHello. Target TCP connects to it and sees no
// failure; a TLS handshake on it reads end of file.
func dropFirstDial(_ testing.TB, f *budgetFixture, o *netops) {
	var first atomic.Bool
	dial := o.dialContext
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !strings.HasSuffix(addr, ":443") || !first.CompareAndSwap(false, true) {
			return dial(ctx, network, addr)
		}
		client, server := net.Pipe()
		go func() {
			_, _ = server.Read(make([]byte, 4096))
			_ = server.Close()
		}()
		return client, nil
	}
}

// rawConnKey carries the raw connection of an accepted TLS connection to its
// request handler.
type rawConnKey struct{}

// dropReusedSocket serves the target and closes the first connection that
// completes a handshake as soon as its first request arrives. The TLS row hands
// that connection to HTTPS when sharing is on, so only the shared HTTPS request
// meets the closure. A fresh HTTPS connection is never the first. With http1
// set the server speaks HTTP/1.1 only, so the closure lands before any response
// bytes. Otherwise HTTP/2 is negotiated, as in production.
func dropReusedSocket(t testing.TB, f *budgetFixture, o *netops, http1 bool) {
	cert, roots := selfSignedCert(t, budgetTargetHost)
	p := newPipeNet(t)
	var mu sync.Mutex
	var first net.Conn
	var dropped atomic.Bool
	srv := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				mu.Lock()
				if first == nil {
					first = hello.Conn
				}
				mu.Unlock()
				return nil, nil
			},
		},
		ReadHeaderTimeout: time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				return context.WithValue(ctx, rawConnKey{}, tc.NetConn())
			}
			return ctx
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := r.Context().Value(rawConnKey{}).(net.Conn)
			mu.Lock()
			doomed := raw != nil && raw == first
			mu.Unlock()
			if doomed && dropped.CompareAndSwap(false, true) {
				f.targetProto.Store(int64(r.ProtoMajor))
				_ = raw.Close()
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	if http1 {
		// An empty map turns HTTP/2 off, so the closure lands between the request
		// and any response bytes, with nothing in flight to fail on.
		srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	p.serve(t, srv, func() error { return srv.ServeTLS(p, "", "") })
	f.tlsPipe = p
	o.tlsRootCAs = roots
	o.dialTLS = trustingDialTLS(f.dial, roots)
}

// differentialRun is one diagnosis of the target rows on a fresh fixture.
type differentialRun struct {
	diag  Diagnosis
	res   map[ProbeID]ProbeResult
	dials int64 // connections the probes made to the target
	proto int64 // HTTP major version of the request the fixture dropped
}

// runDifferential diagnoses the target rows once on a fresh fixture, shared or
// disarmed. It counts the connections the probes make to the target, whichever
// path dials them, and records the protocol of any dropped request.
func runDifferential(t *testing.T, setup func(testing.TB, *budgetFixture, *netops), shared bool) differentialRun {
	t.Helper()
	f := newBudgetFixture(t)
	o := f.ops()
	setup(t, f, o)
	var dials atomic.Int64
	countedDial := o.dialContext
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":443") {
			dials.Add(1)
		}
		return countedDial(ctx, network, addr)
	}
	countedTLS := o.dialTLS
	o.dialTLS = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		if strings.HasSuffix(addr, ":443") {
			dials.Add(1)
		}
		return countedTLS(ctx, network, addr, cfg)
	}
	tg := mustTarget(t, budgetTargetHost+":443")
	probes := ProbeSelection{Check: differentialRows}.Apply(o.timedProbes(tg, DefaultPublicDNS, true))
	if !shared {
		disarm(probes)
	}
	res := RunAll(context.Background(), probes, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)
	order := make([]ProbeID, len(probes))
	for i, p := range probes {
		order[i] = p.ID
	}
	return differentialRun{
		diag:  Interpret(tg, order, res),
		res:   res,
		dials: dials.Load(),
		proto: f.targetProto.Load(),
	}
}

// requireAgreement compares a shared run with a disarmed one: each row's status,
// cause, pinned address, detail and attempts, and the diagnosis and its findings.
func requireAgreement(t *testing.T, shared, plain differentialRun) {
	t.Helper()
	for id, want := range plain.res {
		got := shared.res[id]
		if got.Status != want.Status || got.Cause != want.Cause {
			t.Errorf("%s = %v/%q shared, %v/%q disarmed", id, got.Status, got.Cause, want.Status, want.Cause)
		}
		if !got.SelectedIP.Equal(want.SelectedIP) {
			t.Errorf("%s pinned %v shared, %v disarmed", id, got.SelectedIP, want.SelectedIP)
		}
		if id != ProbeTargetTCP && got.Detail != want.Detail {
			t.Errorf("%s detail %q shared, %q disarmed", id, got.Detail, want.Detail)
		}
		requireSameAttempts(t, id, got.Attempts, want.Attempts)
	}
	if shared.diag.Verdict != plain.diag.Verdict || shared.diag.Blamed != plain.diag.Blamed {
		t.Errorf("diagnosis = %s blaming %q shared, %s blaming %q disarmed",
			shared.diag.Verdict, shared.diag.Blamed, plain.diag.Verdict, plain.diag.Blamed)
	}
	if len(shared.diag.Findings) != len(plain.diag.Findings) {
		t.Fatalf("findings = %d shared, %d disarmed", len(shared.diag.Findings), len(plain.diag.Findings))
	}
	for i := range shared.diag.Findings {
		s, p := shared.diag.Findings[i], plain.diag.Findings[i]
		if s.ID != p.ID || s.Focus != p.Focus || s.Confidence != p.Confidence {
			t.Errorf("finding %d = %s/%s/%v shared, %s/%s/%v disarmed",
				i, s.ID, s.Focus, s.Confidence, p.ID, p.Focus, p.Confidence)
		}
	}
}

// Sharing changes how many sockets the rows use, not what they conclude. Each
// case runs once shared and once disarmed on fresh fixtures, and the two runs
// must agree on every row, the target connections, and the diagnosis. dials is
// how many connections the shared run makes to the target. fresh names the rows
// that fell back to a fresh connection in the shared run, which must carry no
// provenance.
func TestSharedSocketLeavesDiagnosisUnchanged(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t testing.TB, f *budgetFixture, o *netops)
		// wantTLS and wantHTTPS prove the case reaches the outcome it is named for.
		wantTLS, wantHTTPS Status
		fresh              []ProbeID
		dials              int64
	}{
		{"healthy", func(testing.TB, *budgetFixture, *netops) {}, StatusPass, StatusPass, nil, 1},
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
		}, StatusFail, StatusSkip, nil, 1},
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
		}, StatusPass, StatusFail, nil, 1},
		{"certificate not trusted", func(_ testing.TB, f *budgetFixture, o *netops) {
			o.tlsRootCAs = nil
			o.dialTLS = dialTLSWith(f.dial)
		}, StatusFail, StatusSkip, nil, 1},
		{"first dial dropped", dropFirstDial, StatusPass, StatusPass, []ProbeID{ProbeTLS, ProbeHTTPS}, 3},
		{"reused socket dropped over HTTP/1.1", func(t testing.TB, f *budgetFixture, o *netops) {
			dropReusedSocket(t, f, o, true)
		}, StatusPass, StatusPass, []ProbeID{ProbeHTTPS}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shared := runDifferential(t, c.setup, true)
			plain := runDifferential(t, c.setup, false)
			if got := shared.res[ProbeTLS].Status; got != c.wantTLS {
				t.Fatalf("TLS = %v shared, want %v: %s", got, c.wantTLS, shared.res[ProbeTLS].Cause)
			}
			if got := shared.res[ProbeHTTPS].Status; got != c.wantHTTPS {
				t.Fatalf("HTTPS = %v shared, want %v: %s", got, c.wantHTTPS, shared.res[ProbeHTTPS].Cause)
			}
			if shared.dials != c.dials {
				t.Errorf("shared run made %d target connections, want %d", shared.dials, c.dials)
			}
			for _, id := range []ProbeID{ProbeTLS, ProbeHTTPS} {
				fresh := slices.Contains(c.fresh, id)
				switch {
				case fresh && shared.res[id].acquisition != 0:
					t.Errorf("%s fell back to a fresh connection but still claims socket %d", id, shared.res[id].acquisition)
				case !fresh && shared.res[id].Status != StatusSkip && shared.res[id].acquisition == 0:
					t.Errorf("%s dialed on its own in the shared run, so sharing was not exercised", id)
				}
			}
			requireAgreement(t, shared, plain)
		})
	}
}

// Production negotiates HTTP/2, and the case above turns it off. This keeps it
// on: the dropped request is an HTTP/2 stream whose response never arrives. The
// HTTPS row must fall back to one fresh connection and report no provenance.
func TestSharedHTTP2SocketDroppedFallsBack(t *testing.T) {
	setup := func(t testing.TB, f *budgetFixture, o *netops) { dropReusedSocket(t, f, o, false) }
	shared := runDifferential(t, setup, true)
	plain := runDifferential(t, setup, false)
	if shared.proto != 2 {
		t.Fatalf("the dropped request used HTTP/%d, want HTTP/2", shared.proto)
	}
	for _, id := range []ProbeID{ProbeTargetTCP, ProbeTLS, ProbeHTTPS} {
		if got := shared.res[id]; got.Status != StatusPass {
			t.Errorf("%s = %v shared: %s", id, got.Status, got.Cause)
		}
	}
	if got := shared.res[ProbeHTTPS].acquisition; got != 0 {
		t.Errorf("HTTPS fell back but still claims socket %d", got)
	}
	if shared.dials != 2 {
		t.Errorf("shared run made %d target connections, want 2: the shared socket and one fresh", shared.dials)
	}
	requireAgreement(t, shared, plain)
}

// answerThenCut completes an HTTP/2 handshake, answers the client's SETTINGS
// with its own, and reads the request. It then answers with the header of a
// HEADERS frame on stream 1 that declares five bytes of header block and sends
// none. The response has begun, and then the connection ends.
func answerThenCut(c net.Conn, cert tls.Certificate) {
	defer c.Close()
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if tc.Handshake() != nil {
		return
	}
	// The client writes its preface and SETTINGS, and more frames, before its
	// read loop starts. Each write blocks until this side reads it, so the
	// server keeps reading, and its own SETTINGS goes out from a goroutine.
	if _, err := io.ReadFull(tc, make([]byte, 24)); err != nil {
		return
	}
	settled := make(chan error, 1)
	for seen := 0; ; seen++ {
		var hdr [9]byte
		if _, err := io.ReadFull(tc, hdr[:]); err != nil {
			return
		}
		n := int64(hdr[0])<<16 | int64(hdr[1])<<8 | int64(hdr[2])
		if _, err := io.CopyN(io.Discard, tc, n); err != nil {
			return
		}
		if seen == 0 {
			go func() { _, err := tc.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); settled <- err }()
		}
		// HEADERS on stream 1 is the request.
		if hdr[3] == 1 && binary.BigEndian.Uint32(hdr[5:]) == 1 {
			break
		}
	}
	// The client writes while it reads, so the cut goes out from its own goroutine
	// once the client has seen SETTINGS. This side keeps draining the client's
	// frames until the connection ends, so none of its writes block.
	go func() {
		if <-settled == nil {
			_, _ = tc.Write([]byte{0, 0, 5, 1, 4, 0, 0, 0, 1})
		}
		_ = c.Close()
	}()
	_, _ = io.Copy(io.Discard, tc)
}

// resetInsteadOfClose reports the end of a connection as a reset, as a peer
// does when it drops a socket with unread data.
type resetInsteadOfClose struct{ net.Conn }

func (c resetInsteadOfClose) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		err = &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", connectionResetErrno)}
	}
	return n, err
}

// A response that begins and then breaks is a server failure, not a dead socket.
// The HTTPS row keeps the invalid-response cause, and it must not dial again.
func TestSharedHTTP2ResponseBreaksAfterHeadersStaysInvalid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset bool
	}{
		{"closed", false},
		{"reset", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup := func(t testing.TB, f *budgetFixture, o *netops) {
				cert, roots := selfSignedCert(t, budgetTargetHost)
				cut := newPipeNet(t)
				go func() {
					for {
						c, err := cut.Accept()
						if err != nil {
							return
						}
						go answerThenCut(c, cert)
					}
				}()
				f.tlsPipe = cut
				o.tlsRootCAs = roots
				if tc.reset {
					dial := o.dialContext
					o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						c, err := dial(ctx, network, addr)
						if err != nil || !strings.HasSuffix(addr, ":443") {
							return c, err
						}
						return resetInsteadOfClose{c}, nil
					}
				}
				o.dialTLS = trustingDialTLS(o.dialContext, roots)
			}
			shared := runDifferential(t, setup, true)
			plain := runDifferential(t, setup, false)
			if got := shared.res[ProbeTLS].Status; got != StatusPass {
				t.Fatalf("TLS = %v, want pass: the handshake completes before the response begins: %s", got, shared.res[ProbeTLS].Detail)
			}
			https := shared.res[ProbeHTTPS]
			if https.Status != StatusFail || https.Cause != HTTPCauseInvalidResponse {
				t.Fatalf("HTTPS = %v cause %q, want fail with %q: %s", https.Status, https.Cause, HTTPCauseInvalidResponse, https.Detail)
			}
			if shared.dials != 1 {
				t.Errorf("shared run made %d target connections, want 1: a response that began must not dial again", shared.dials)
			}
			if got, want := https.acquisition, shared.res[ProbeTargetTCP].acquisition; got == 0 || got != want {
				t.Errorf("HTTPS acquisition %d, want the shared socket %d", got, want)
			}
			requireAgreement(t, shared, plain)
		})
	}
}

// deadSocket separates a connection that ended from an answer the server gave.
// Only the first kind justifies a fresh connection.
func TestDeadSocketSeparatesEndedConnectionsFromAnswers(t *testing.T) {
	ended := []error{io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, tlsHandshakeError{io.EOF}}
	answered := []error{x509.UnknownAuthorityError{}, context.DeadlineExceeded, tlsHandshakeError{x509.UnknownAuthorityError{}}}
	for _, err := range ended {
		if !deadSocket(err) {
			t.Errorf("%v not classed as a dead socket", err)
		}
	}
	for _, err := range answered {
		if deadSocket(err) {
			t.Errorf("%v classed as a dead socket, but the server answered", err)
		}
	}
}

// requireSameAttempts compares the dials two runs report for one row, entry by
// entry. Duration is timing, so it is left out.
func requireSameAttempts(t *testing.T, id ProbeID, shared, plain []Attempt) {
	t.Helper()
	key := func(a Attempt) string {
		return fmt.Sprintf("%v err=%t cause=%q aborted=%t", a.IP, a.Err != nil, a.Cause, a.Aborted)
	}
	var got, want []string
	for _, a := range shared {
		got = append(got, key(a))
	}
	for _, a := range plain {
		want = append(want, key(a))
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s attempts = %q shared, %q disarmed", id, got, want)
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
// The losing family refuses with this platform's refusal errno: a refusal is
// the only failure that proves the family is down without egress evidence.
func TestSharedSocketFollowsTheWinningFamily(t *testing.T) {
	for _, tc := range []struct {
		name          string
		winner, loser string
	}{
		{"IPv4 wins", "127.0.0.1", "[::1]"},
		{"IPv6 wins", "[::1]", "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(shared bool) map[ProbeID]ProbeResult {
				f := newBudgetFixture(t)
				f.loopbacks = []net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}
				o := f.ops()
				dial := o.dialContext
				o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					if strings.HasPrefix(addr, tc.loser+":") {
						return nil, connectionRefusedErrno
					}
					return dial(ctx, network, addr)
				}
				probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(o.timedProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true))
				if !shared {
					disarm(probes)
				}
				res := RunAll(context.Background(), probes, DefaultProbeTimeout)
				requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS)
				return res
			}
			res := run(true)
			plain := run(false)

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
			// The disarmed HTTPS row dials only the pinned address, so it reports one
			// attempt. The shared row must report the same, not the dead family too.
			requireSameAttempts(t, ProbeHTTPS, res[ProbeHTTPS].Attempts, plain[ProbeHTTPS].Attempts)
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

// httpsWatchPass runs one Watch pass of the healthy HTTPS graph and returns the pass,
// its results, and the graph it ran, whose socket RunAll has released.
func httpsWatchPass(t *testing.T, f *budgetFixture, session *WatchSession) (*WatchPass, map[ProbeID]ProbeResult, []Probe) {
	t.Helper()
	probes := ProbeSelection{Check: healthyHTTPSRows}.Apply(timedProbes(f.ops().buildProbes(mustTarget(t, budgetTargetHost+":443"), DefaultPublicDNS, true)))
	pass := session.Begin(probes)
	graph := pass.Probes()
	res := RunAll(context.Background(), graph, DefaultProbeTimeout)
	requireRows(t, res, ProbeTargetTCP, ProbeTLS, ProbeHTTPS, ProbePMTU)
	return pass, res, graph
}

// A Watch pass that answers TLS and HTTPS from the pass before touches no
// socket for them. Target TCP and PMTU still dial, and no socket outlives the
// pass that opened it.
func TestWatchPassReusesRowsOverSharedSocket(t *testing.T) {
	f := newBudgetFixture(t)
	session := NewWatchSession(time.Now)

	first, res, graph := httpsWatchPass(t, f, session)
	if !first.Publish(res) {
		t.Fatal("the first pass was not published")
	}
	if TargetSocketOpen(graph) {
		t.Error("the first pass left its target socket open")
	}

	second, res, graph := httpsWatchPass(t, f, session)
	if !second.reused[ProbeTLS] || !second.reused[ProbeHTTPS] {
		t.Fatalf("second pass reused TLS=%v HTTPS=%v, want both", second.reused[ProbeTLS], second.reused[ProbeHTTPS])
	}
	if second.reused[ProbeTargetTCP] || second.reused[ProbePMTU] {
		t.Error("Target TCP and PMTU are never reused, but the second pass answered one of them from the first")
	}
	if res[ProbeHTTPS].Status != StatusPass {
		t.Fatalf("reused HTTPS = %v: %s", res[ProbeHTTPS].Status, res[ProbeHTTPS].Detail)
	}
	if TargetSocketOpen(graph) {
		t.Error("the second pass left its target socket open")
	}
	if got, want := targetDials(f), 4; got != want {
		t.Errorf("connections to the target = %d, want %d (Target TCP and PMTU in each pass)", got, want)
	}
	if got, want := f.targetHandshakes.Load(), int64(1); got != want {
		t.Errorf("TLS handshakes with the target = %d, want %d (the reused pass handshakes nothing)", got, want)
	}
}

// Reuse of TLS with HTTPS run fresh is the case where Target TCP's socket reaches
// HTTPS still plain. HTTPS must close it and dial its own connection, which
// carries no provenance.
func TestWatchFreshHTTPSAfterReusedTLSDialsItsOwnSocket(t *testing.T) {
	f := newBudgetFixture(t)
	session := NewWatchSession(time.Now)

	first, res, _ := httpsWatchPass(t, f, session)
	if !first.Publish(res) {
		t.Fatal("the first pass was not published")
	}
	delete(session.cache, ProbeHTTPS)

	second, res, graph := httpsWatchPass(t, f, session)
	if !second.reused[ProbeTLS] || second.reused[ProbeHTTPS] {
		t.Fatalf("second pass reused TLS=%v HTTPS=%v, want TLS only", second.reused[ProbeTLS], second.reused[ProbeHTTPS])
	}
	if res[ProbeHTTPS].Status != StatusPass {
		t.Fatalf("fresh HTTPS = %v: %s", res[ProbeHTTPS].Status, res[ProbeHTTPS].Detail)
	}
	if got := res[ProbeHTTPS].acquisition; got != 0 {
		t.Errorf("fresh HTTPS carries acquisition %d, want none", got)
	}
	if TargetSocketOpen(graph) {
		t.Error("the second pass left its target socket open")
	}
	if got, want := targetDials(f), 5; got != want {
		t.Errorf("connections to the target = %d, want %d (Target TCP and PMTU in both passes, then HTTPS's own dial)", got, want)
	}
	if got, want := f.targetHandshakes.Load(), int64(2); got != want {
		t.Errorf("TLS handshakes with the target = %d, want %d (the first pass, then HTTPS's own)", got, want)
	}
}

// Watch fingerprints decide reuse, so a row's fingerprint must not change with
// the socket it happened to use: a new run's socket would otherwise invalidate
// every row built on a shared one.
func TestFingerprintIgnoresSocketProvenance(t *testing.T) {
	a := ProbeResult{Status: StatusPass, acquisition: 1}
	b := ProbeResult{Status: StatusPass, acquisition: 2}
	if fingerprint(a) != fingerprint(b) {
		t.Error("the fingerprint changes with the socket a row used")
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
	refused := func(context.Context, string, string) (net.Conn, error) { return nil, connectionRefusedErrno }
	o.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":443") {
			return refused(ctx, network, addr)
		}
		return f.dial(ctx, network, addr)
	}
	o.dialTLS = func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return nil, connectionRefusedErrno
	}
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
