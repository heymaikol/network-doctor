package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
)

// targetLink carries the one live socket to a target through the TCP, TLS and
// HTTPS rows of a single graph. The slot holds at most one connection. Taking
// it transfers ownership: the taker must close the connection or offer it on.
// Nil is a valid link and means every row dials for itself, as before.
//
// A link belongs to one graph and one run. release ends it, so a row that
// finishes after its graph was discarded closes its socket instead of handing
// it to a consumer that will never run.
type targetLink struct {
	mu     sync.Mutex
	conn   net.Conn
	closed bool
	// id names the socket for provenance. Rows that used the same socket carry
	// it; a fresh dial carries zero, which means independent.
	id uint64
	// toTLS and toHTTPS are set by armLinks from the rows that survived
	// selection. A handoff happens only when its consumer is in the graph.
	toTLS, toHTTPS bool
	// attempt is the dial that produced the socket, as Target TCP recorded it. A
	// row that reuses the socket reports it, so the row reads as it did when it
	// dialed that address itself.
	attempt []Attempt
}

var linkIDs atomic.Uint64

func newTargetLink() *targetLink {
	return &targetLink{id: linkIDs.Add(1)}
}

// offer stores c for the next row. It reports false, and leaves c with the
// caller, when the slot is full or the link has been released.
func (l *targetLink) offer(c net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.conn != nil {
		return false
	}
	l.conn = c
	return true
}

// setAttempts records the dial behind the socket. It is copied, and it stays
// after the socket is taken.
func (l *targetLink) setAttempts(a []Attempt) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempt = slices.Clone(a)
}

// attemptsOf returns the recorded dial, or nil when there is none.
func (l *targetLink) attemptsOf() []Attempt {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.attempt)
}

// winningAttempt returns the dial that produced the socket to ip. A row that
// dialed ip itself records only that dial, so the row that reuses the socket
// must not carry the failed dials of other addresses.
func winningAttempt(attempts []Attempt, ip net.IP) []Attempt {
	for _, a := range attempts {
		if a.Err == nil && a.IP.Equal(ip) {
			return []Attempt{a}
		}
	}
	return nil
}

// deadSocket reports whether err says the peer or the path ended a connection
// that was already open, as opposed to an answer from the server: a certificate
// problem, a TLS alert, or a deadline. Only these justify a fresh connection.
func deadSocket(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || isConnectionReset(err)
}

// take removes the stored connection, or returns nil when there is none.
func (l *targetLink) take() net.Conn {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.conn
	l.conn = nil
	return c
}

// open reports whether the link still accepts a connection.
func (l *targetLink) open() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.closed
}

// release closes any stored connection and refuses later offers.
func (l *targetLink) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
}

// ReleaseProbes ends the target links of a graph that is being discarded.
// Callers must invoke it before dropping the graph, or a socket held by a
// row that is still in flight is never closed. RunAll calls it on return,
// once every row has finished.
func ReleaseProbes(probes []Probe) {
	for _, p := range probes {
		p.link.release()
	}
}

// TargetSocketOpen reports whether the graph's target link still accepts a
// connection. It is false once the graph is released, and for a graph with no
// target link at all.
func TargetSocketOpen(probes []Probe) bool {
	for _, p := range probes {
		if p.link != nil {
			return p.link.open()
		}
	}
	return false
}

// armLinks lets the rows that survived selection hand the socket along. A row
// removed by selection takes its handoff with it, so no socket waits for a
// consumer that will not run.
func armLinks(probes []Probe) {
	var link *targetLink
	var hasTLS, hasHTTPS bool
	for _, p := range probes {
		if p.link != nil {
			link = p.link
		}
		switch p.ID {
		case ProbeTLS:
			hasTLS = true
		case ProbeHTTPS:
			hasHTTPS = true
		}
	}
	if link != nil {
		link.toTLS, link.toHTTPS = hasTLS, hasHTTPS
	}
}

// handshakeOn runs a TLS client handshake over a connection that TCP already
// opened. The ALPN list matches what the HTTPS transport offers, so the
// negotiated protocol is the one HTTPS would have used on its own socket.
// On failure the connection is closed and the error is tagged as a handshake
// failure, which the TLS row classifies the same way as a failed dialTLS.
func handshakeOn(ctx context.Context, conn net.Conn, host string, roots *x509.CertPool, h2 bool) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: host, RootCAs: roots}
	if h2 {
		cfg.NextProtos = []string{"h2", "http/1.1"}
	}
	client := tls.Client(conn, cfg)
	if err := client.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, tlsHandshakeError{err}
	}
	return client, nil
}
