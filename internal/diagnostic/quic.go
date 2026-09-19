package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	quic "github.com/quic-go/quic-go"
)

// quicState is the small piece of quic-go state the diagnostic reports.
// Keeping it local avoids leaking a transport dependency into ProbeResult.
type quicState struct {
	version string
	alpn    string
}

// connectedPacketConn adapts the UDP connection produced by the existing
// family-aware dialer to the PacketConn quic-go needs. The remote address is
// fixed, so WriteTo cannot accidentally send elsewhere.
type connectedPacketConn struct{ net.Conn }

func (c connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c connectedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

// socketBufferConn is the optional socket-buffer surface quic-go looks for on
// the PacketConn it is given. *net.UDPConn has it; the plain net.Conn
// interface does not, so wrapping one hides it and quic-go logs that it cannot
// size its buffers.
type socketBufferConn interface {
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

// bufferedPacketConn carries those buffer controls through to the underlying
// socket. It stops there on purpose: adding SyscallConn, ReadMsgUDP, and
// WriteMsgUDP would satisfy quic.OOBCapablePacketConn, and quic-go would then
// send with WriteMsgUDP to the address it picks instead of through WriteTo,
// which is the one thing that keeps this adapter pinned to its connected peer.
type bufferedPacketConn struct {
	connectedPacketConn
	buffers socketBufferConn
}

func (c bufferedPacketConn) SetReadBuffer(bytes int) error  { return c.buffers.SetReadBuffer(bytes) }
func (c bufferedPacketConn) SetWriteBuffer(bytes int) error { return c.buffers.SetWriteBuffer(bytes) }

// newPacketConn keeps the adapter truthful about what it can do: buffer
// controls are advertised only when the connection underneath really has them,
// so a connection without them reports that instead of accepting the call and
// doing nothing.
func newPacketConn(conn net.Conn) net.PacketConn {
	adapter := connectedPacketConn{conn}
	if buffers, ok := conn.(socketBufferConn); ok {
		return bufferedPacketConn{adapter, buffers}
	}
	return adapter
}

// handshakeQUIC returns only after QUIC transport parameters, TLS certificate
// validation, and h3 ALPN negotiation have completed. That authenticated
// response is the positive remote evidence a bare UDP Write cannot provide.
func handshakeQUIC(ctx context.Context, conn net.Conn, tlsConfig *tls.Config) (quicState, error) {
	if conn.RemoteAddr() == nil {
		return quicState{}, errors.New("UDP connection has no remote address")
	}
	transport := &quic.Transport{Conn: newPacketConn(conn)}
	defer func() { _ = transport.Close() }()
	qconn, err := transport.Dial(ctx, conn.RemoteAddr(), tlsConfig, nil)
	if err != nil {
		return quicState{}, err
	}
	defer func() { _ = qconn.CloseWithError(0, "probe complete") }()
	state := qconn.ConnectionState()
	if state.TLS.NegotiatedProtocol != "h3" || len(state.TLS.PeerCertificates) == 0 {
		return quicState{}, fmt.Errorf("invalid QUIC handshake evidence (ALPN %q, %d peer certificates)", state.TLS.NegotiatedProtocol, len(state.TLS.PeerCertificates))
	}
	return quicState{version: state.Version.String(), alpn: state.TLS.NegotiatedProtocol}, nil
}

type quicAttempt struct {
	state   quicState
	attempt Attempt
	source  net.IP
	index   int
}

// dialQUICIPs applies the same staggered, family-aware address selection used
// by TCP probes, but success means a completed QUIC handshake rather than a
// locally connected UDP socket.
func (o *netops) dialQUICIPs(ctx context.Context, ips []net.IP, host string, port int) (quicState, net.IP, net.IP, []Attempt, time.Duration, error) {
	ips = interleaveFamilies(ips)
	if len(ips) > maxAttempts {
		ips = ips[:maxAttempts]
	}
	if len(ips) == 0 || ctx.Err() != nil {
		return quicState{}, nil, nil, nil, 0, ctx.Err()
	}

	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan quicAttempt, len(ips))
	next := make(chan struct{}, len(ips))
	handshake := o.quicHandshake
	if handshake == nil {
		handshake = handshakeQUIC
	}

	go func() {
		for i, ip := range ips {
			if i > 0 {
				timer := time.NewTimer(attemptDelay)
				select {
				case <-timer.C:
				case <-next:
				case <-dctx.Done():
					timer.Stop()
					return
				}
				timer.Stop()
			}
			if dctx.Err() != nil {
				return
			}
			go func(index int, ip net.IP) {
				start := time.Now()
				network := "udp6"
				if ip.To4() != nil {
					network = "udp4"
				}
				conn, err := o.dialContext(dctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				var source net.IP
				var state quicState
				if err == nil {
					source = connIP(conn.LocalAddr())
					state, err = handshake(dctx, conn, &tls.Config{ServerName: host, NextProtos: []string{"h3"}, RootCAs: o.tlsRootCAs})
					_ = conn.Close()
				}
				result := quicAttempt{state: state, source: source, attempt: Attempt{IP: ip, Dur: since(start), Err: err}, index: index}
				results <- result
				if err != nil {
					next <- struct{}{}
				}
			}(i, ip)
		}
	}()

	var attempts []Attempt
	failures := make([]error, len(ips))
	for pending := len(ips); pending > 0; pending-- {
		select {
		case result := <-results:
			attempts = append(attempts, result.attempt)
			if result.attempt.Err == nil {
				return result.state, result.attempt.IP, result.source, attempts, result.attempt.Dur, nil
			}
			failures[result.index] = result.attempt.Err
		case <-ctx.Done():
			return quicState{}, nil, nil, attempts, 0, ctx.Err()
		}
	}
	return quicState{}, nil, nil, attempts, 0,
		fmt.Errorf("all %d QUIC address attempts failed (%s): %w", len(ips), joinIPs(ips), failures[0])
}

func connIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	case *net.IPAddr:
		return a.IP
	}
	return nil
}

func (o *netops) quicProbe(host string, port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		ips, _, err := o.lookupIPRetrying(ctx, host)
		if err != nil || len(ips) == 0 {
			return ProbeResult{Status: StatusNA, Detail: "cannot resolve QUIC endpoint " + host + ": unable to determine UDP/443 reachability"}
		}
		if ips = o.compatibleSourceIPs(ips); len(ips) == 0 {
			return ProbeResult{Status: StatusNA, Detail: "QUIC endpoint has no address family available on the selected interface"}
		}

		state, selected, source, attempts, rtt, err := o.dialQUICIPs(ctx, ips, host, port)
		r := ProbeResult{SelectedIP: selected, Source: source, Attempts: attempts}
		if source != nil {
			r.Iface, r.ifaceAmbiguous = o.ifaceForIP(source)
		}
		if err == nil {
			r.Status = StatusPass
			r.Detail = fmt.Sprintf("QUIC %s handshake with %s over UDP/443 in %dms (%s)", state.version, host, Ms(rtt), state.alpn)
			return r
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			r.Status = StatusNA
			r.Detail = "QUIC check canceled before the endpoint answered"
			return r
		}
		r.Status = StatusFail
		r.Cause = QUICCauseHandshake
		r.Detail = "could not establish QUIC with " + host + " over UDP/443: " + err.Error()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || timeoutError(err) {
			r.Cause = QUICCauseTimeout
			r.Detail = "QUIC handshake with " + host + " over UDP/443 timed out; the endpoint did not complete the exchange"
		}
		r.Fix = "UDP/443 may be filtered or the selected QUIC endpoint may be unavailable; applications can fall back to TCP"
		return r
	}
}
