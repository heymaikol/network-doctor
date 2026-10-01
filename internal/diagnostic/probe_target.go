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
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ConnectionFailureCause gives peer mode and the ordinary target probe one
// cross-platform vocabulary for a failed TCP dial.
func ConnectionFailureCause(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return ConnectionCauseCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return ConnectionCauseTimeout
	case isConnectionRefused(err):
		return ConnectionCauseRefused
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ConnectionCauseTimeout
	}
	return ConnectionCauseUnreachable
}

func (o *netops) targetTCPProbe(port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		addrs := interleaveFamilies(deps[ProbeDNS].Addrs)
		if len(addrs) > maxAttempts {
			addrs = addrs[:maxAttempts]
		}
		if len(addrs) == 0 {
			r.Status, r.Detail = StatusFail, "no resolved addresses"
			return r
		}
		// Per address, never per hostname: a name whose A and AAAA records
		// leave by different interfaces is exactly the case this exists to
		// keep visible, and one decision for the hostname would erase it.
		routes := o.explainedRouteDecisions(o.referenceRouteDecisions(), addrs...)
		v4addrs, v6addrs := splitFamilies(addrs)
		type familyResult struct {
			conn     net.Conn
			sel      net.IP
			attempts []Attempt
			rtt      time.Duration
		}
		var v4, v6 familyResult
		var wg sync.WaitGroup
		if len(v4addrs) > 0 {
			wg.Go(func() { v4.conn, v4.sel, v4.attempts, v4.rtt = o.dialIPs(ctx, v4addrs, port) })
		}
		if len(v6addrs) > 0 {
			wg.Go(func() { v6.conn, v6.sel, v6.attempts, v6.rtt = o.dialIPs(ctx, v6addrs, port) })
		}
		wg.Wait()
		resolved4, resolved6 := splitFamilies(deps[ProbeDNS].Addrs)
		r.Families = &FamilyConnectivity{
			IPv4: targetFamilyState(resolved4, v4.conn, v4.attempts),
			IPv6: targetFamilyState(resolved6, v6.conn, v6.attempts),
		}

		// Prefer IPv6 when both complete together, but keep the faster working
		// family when one path is measurably slower. The other family is still
		// independently observed before this probe ends.
		primary, secondary := v6, v4
		if primary.conn == nil || secondary.conn != nil && secondary.rtt < primary.rtt {
			primary, secondary = v4, v6
		}
		conn, sel, rtt := primary.conn, primary.sel, primary.rtt
		r.Attempts = append(append([]Attempt{}, primary.attempts...), secondary.attempts...)
		if conn != nil {
			defer conn.Close()
			if secondary.conn != nil {
				defer secondary.conn.Close()
			}
			if a, ok := o.verifyTargetSibling(ctx, addrs, sel, r.Attempts, port); ok {
				r.Attempts = append(r.Attempts, a)
				primary.attempts = append(primary.attempts, a)
			}
			src, iface, ambiguous := o.pathIdentity(ctx, conn, sel, port)
			r.Status, r.SelectedIP, r.Source, r.Iface, r.ifaceAmbiguous = StatusPass, sel, src, iface, ambiguous
			r.Routes = routes
			r.Detail = fmt.Sprintf("connected to %s:%d in %dms (src %s %s)", sel, port, Ms(rtt), src, iface)
			// Failed addresses within a family that did connect are partial
			// reachability. A whole failed family is reconciled later against the
			// independent egress-family observation, so single-stack hosts stay clean.
			var warningAttempts []Attempt
			warningAttempts = append(warningAttempts, primary.attempts...)
			if secondary.conn != nil {
				warningAttempts = append(warningAttempts, secondary.attempts...)
			}
			allAttempts := r.Attempts
			r.Attempts = warningAttempts
			applyDialWarnings(&r, rtt)
			r.Attempts = allAttempts
			return r
		}
		refused := len(r.Attempts) > 0 && ctx.Err() == nil
		for _, attempt := range r.Attempts {
			if ConnectionFailureCause(attempt.Err) != ConnectionCauseRefused {
				refused = false
				break
			}
		}
		// All addresses failed: deterministic fallback path = first address.
		src, iface, ambiguous := o.pathIdentity(ctx, nil, addrs[0], port)
		r.Status, r.Source, r.Iface, r.ifaceAmbiguous = StatusFail, src, iface, ambiguous
		r.Routes = routes
		tried := make([]net.IP, len(r.Attempts))
		for i, a := range r.Attempts {
			tried[i] = a.IP
		}
		if refused {
			r.Cause = ConnectionCauseRefused
			r.Detail = fmt.Sprintf("connection to port %d was refused on all %d attempted address(es): %s", port, len(r.Attempts), joinIPs(tried))
			r.Fix = fmt.Sprintf("connection refused: check that a service is listening on port %d and that no firewall is actively rejecting it", port)
			return r
		}
		r.Detail = fmt.Sprintf("port %d unreachable on all %d address(es): %s", port, len(r.Attempts), joinIPs(tried))
		r.Fix = fmt.Sprintf("port %d blocked/refused: firewall, wrong network, or VPN routing?", port)
		return r
	}
}

// A retry has its own individual-address budget. Expiration of the enclosing
// probe is still an aborted observation, never evidence against the address.
const targetSiblingTimeout = time.Second

func (o *netops) verifyTargetSibling(ctx context.Context, resolved []net.IP, winner net.IP, attempts []Attempt, port int) (Attempt, bool) {
	deadline, bounded := ctx.Deadline()
	// Reserve one dial even if every resolved candidate started, including
	// successful race losers that dialIPs closes without recording.
	if !bounded || ctx.Err() != nil || time.Until(deadline) <= targetSiblingTimeout || len(resolved) >= maxAttempts {
		return Attempt{}, false
	}
	var candidate net.IP
	for _, a := range attempts {
		if a.IP.To16() == nil || a.IP.Equal(winner) || (a.IP.To4() != nil) != (winner.To4() != nil) ||
			!containsResolvedIP(resolved, a.IP) || len(o.compatibleSourceIPs([]net.IP{a.IP})) == 0 {
			continue
		}
		// Already proved a failed sibling: more connections add no needed evidence.
		if a.Err != nil && !isCanceledAttempt(a) {
			return Attempt{}, false
		}
		if candidate == nil && a.Cause == ConnectionCauseCanceled {
			candidate = a.IP
		}
	}
	if candidate != nil {
		vctx, cancel := context.WithTimeout(ctx, targetSiblingTimeout)
		defer cancel()
		network := "tcp6"
		if candidate.To4() != nil {
			network = "tcp4"
		}
		start := time.Now()
		conn, err := o.dialContext(vctx, network, net.JoinHostPort(candidate.String(), strconv.Itoa(port)))
		if conn != nil {
			_ = conn.Close()
		}
		verified := Attempt{IP: candidate, Dur: since(start), Err: err}
		if err != nil {
			verified.Cause = ConnectionFailureCause(err)
			verified.Aborted = ctx.Err() != nil
		}
		return verified, true
	}
	return Attempt{}, false
}

func (o *netops) tlsProbe(host string, port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		ip := deps[ProbeTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		conn, err := o.dialTLS(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), &tls.Config{ServerName: host})
		if err != nil {
			// Name the address: the cert that failed belongs to whatever the
			// resolver handed us, and that's often the actual culprit.
			r.Status, r.SelectedIP = StatusFail, ip
			r.Cause = tlsFailureCause(err, time.Now())
			// Only a handshake on a connection this probe opened observed a
			// TLS exchange stalling. A timeout during the probe's own dial
			// keeps the same Cause but is not half of the path-MTU correlation.
			var handshake tlsHandshakeError
			r.timedOut = r.Cause == TLSCauseTimeout && errors.As(err, &handshake)
			r.Detail = "TLS check to " + ip.String() + " failed: " + err.Error()
			r.Fix = tlsFix(err)
			if iface := deps[ProbeTargetTCP].Iface; timeoutError(err) {
				if mtu := o.mtuFor(iface); mtu > 0 {
					r.Detail += fmt.Sprintf(" (%s MTU is %d)", iface, mtu)
				}
			}
			return r
		}
		_ = conn.Close()
		r.Status, r.SelectedIP, r.Detail = StatusPass, ip, "TLS handshake OK (SNI "+host+")"
		return r
	}
}

// tlsHandshakeError is a dialTLS failure that came after the TCP connection
// opened, which is what separates a stalled handshake from a stalled dial.
type tlsHandshakeError struct{ error }

func (e tlsHandshakeError) Unwrap() error { return e.error }

// dialTLSWith opens a connection with dial and runs the TLS handshake on it,
// marking a handshake failure so the caller can tell it from a failed dial.
func dialTLSWith(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	return func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, tlsHandshakeError{err}
		}
		return tlsConn, nil
	}
}

// h2ResponseConn passes an HTTP/2 connection's decrypted bytes through to the
// transport untouched and sets answered at the first HEADERS or DATA frame
// header on stream 1. The transport keeps every decision about the protocol;
// this only splits the stream at frame boundaries, holding at most one frame
// header. Stream 1 is this request's: a client opens its streams from 1, and a
// transport with DisableKeepAlives makes each HTTP/2 connection single use, so
// a retried request gets a new connection and a new stream 1. Frames on stream
// 0 manage the connection, and other types on stream 1 carry no response.
type h2ResponseConn struct {
	*tls.Conn
	answered *atomic.Bool

	checked, h2 bool
	hdr         [9]byte
	have        int // bytes of hdr read so far
	skip        int // payload bytes left in the current frame, under 1<<24
}

// Read is called only by the transport's single read loop, after the
// handshake, so the negotiated protocol is known on the first call.
func (c *h2ResponseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.checked {
		c.checked = true
		c.h2 = c.ConnectionState().NegotiatedProtocol == "h2"
	}
	for b := p[:n]; c.h2 && len(b) > 0; {
		if c.skip > 0 {
			k := min(c.skip, len(b))
			b, c.skip = b[k:], c.skip-k
			continue
		}
		k := copy(c.hdr[c.have:], b)
		b, c.have = b[k:], c.have+k
		if c.have < len(c.hdr) {
			break
		}
		c.have = 0
		c.skip = int(c.hdr[0])<<16 | int(c.hdr[1])<<8 | int(c.hdr[2])
		// Type 0 is DATA and 1 is HEADERS; the top stream ID bit is reserved.
		if typ, id := c.hdr[3], binary.BigEndian.Uint32(c.hdr[5:])&(1<<31-1); id == 1 && typ <= 1 {
			c.answered.Store(true)
			c.h2 = false
		}
	}
	return n, err
}

// Close keeps the HTTP/2 transport's bound on closing an unresponsive peer,
// which it applies only to a bare *tls.Conn: the close_notify alert gets 250ms
// before the connection underneath is closed.
func (c *h2ResponseConn) Close() error {
	if c.ConnectionState().NegotiatedProtocol == "h2" {
		t := time.AfterFunc(250*time.Millisecond, func() { _ = c.NetConn().Close() })
		defer t.Stop()
	}
	return c.Conn.Close()
}

func tlsFailureCause(err error, now time.Time) string {
	var (
		hostErr x509.HostnameError
		invalid x509.CertificateInvalidError
		unknown x509.UnknownAuthorityError
	)
	switch {
	case errors.As(err, &hostErr):
		return TLSCauseHostnameMismatch
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		if invalid.Cert != nil && now.Before(invalid.Cert.NotBefore) {
			return TLSCauseCertificateNotYet
		}
		return TLSCauseCertificateExpired
	case errors.As(err, &unknown):
		return TLSCauseUntrustedIssuer
	case timeoutError(err):
		return TLSCauseTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return TLSCauseConnectionClosed
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return TLSCauseTCPUnreachable
	default:
		return TLSCauseHandshake
	}
}

func (o *netops) httpProbe(host string, port int, scheme string, addressDep ProbeID) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		protocol := strings.ToUpper(scheme)
		var addrs []net.IP
		if addressDep == ProbeDNS {
			addrs = deps[addressDep].Addrs
		} else if ip := deps[addressDep].SelectedIP; ip != nil {
			addrs = []net.IP{ip}
		}
		if len(addrs) == 0 {
			r.Status, r.Detail = StatusSkip, "no address available for "+protocol
			return r
		}
		// Fresh, non-reusing transport restricted to the resolved/pinned IPs;
		// redirects and proxy off; bounded response headers (attacker-controlled).
		// The transport dials on its own goroutine, which can outlive client.Do
		// on ctx timeout, so the closure must not write to r directly.
		var dialMu sync.Mutex
		var dialIP net.IP
		var dialAttempts []Attempt
		var answered, started atomic.Bool
		dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, selected, attempts, _ := o.dialIPs(ctx, addrs, port)
			dialMu.Lock()
			dialIP, dialAttempts = selected, attempts
			dialMu.Unlock()
			if conn == nil {
				if len(attempts) > 0 && attempts[len(attempts)-1].Err != nil {
					return nil, attempts[len(attempts)-1].Err
				}
				return nil, fmt.Errorf("all %s addresses failed", protocol)
			}
			return conn, nil
		}
		tr := &http.Transport{
			Proxy:                  nil,
			ForceAttemptHTTP2:      true,
			DialContext:            dial,
			TLSClientConfig:        &tls.Config{ServerName: host, RootCAs: o.tlsRootCAs},
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
		}
		// The connection goes back without a handshake: the transport runs it
		// with its own traces, and has already added h2 to the ALPN list of the
		// config cloned here, as it does for the connections it wraps itself.
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &h2ResponseConn{Conn: tls.Client(conn, tr.TLSClientConfig.Clone()), answered: &answered}, nil
		}
		client := &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
		// GotFirstResponseByte is the evidence that the endpoint answered. HTTP/1
		// fires it after peeking a byte from the reader above the connection,
		// which for HTTPS is the decrypted stream, so TLS handshake records
		// never count. HTTP/2 fires it only once a whole header block decodes,
		// so h2ResponseConn adds the first frame header of a response.
		//
		// started is the evidence that this request's protocol exchange began:
		// GotConn hands it a connection, and for HTTPS TLSHandshakeStart opens
		// the handshake first, which GotConn only follows once it completes. A
		// dial can finish after the deadline, and the transport still handshakes
		// it or hands it over, so an event counts only before the deadline.
		begin := func() {
			if ctx.Err() == nil {
				started.Store(true)
			}
		}
		trace := &httptrace.ClientTrace{
			GotConn:              func(httptrace.GotConnInfo) { begin() },
			TLSHandshakeStart:    begin,
			GotFirstResponseByte: func() { answered.Store(true) },
		}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, url, nil)
		if err != nil {
			r.Status, r.Detail = StatusFail, "cannot build request: "+err.Error()
			return r
		}
		resp, err := client.Do(req)
		dialMu.Lock()
		r.SelectedIP, r.Attempts = dialIP, dialAttempts
		dialMu.Unlock()
		if err != nil {
			r.Status = StatusFail
			// A timeout before the exchange began is a stalled dial that
			// exchanged nothing. SelectedIP cannot tell: a dial that finishes
			// as the deadline expires records one the request never used.
			r.timedOut = timeoutError(err) && started.Load()
			// Name the winner if one address connected and the failure came
			// later, otherwise everything tried.
			tried := joinIPs(addrs)
			if r.SelectedIP != nil {
				tried = r.SelectedIP.String()
			}
			r.Detail = "no " + protocol + " response from " + tried + ": " + err.Error()
			r.Fix = protocol + " blocked: proxy or firewall?"
			// Bytes arriving outrank how the attempt ended: an endpoint that
			// answered and then closed, reset, or stalled still answered, with
			// something unreadable. timedOut is recorded beside the cause, so
			// a stall after bytes still counts for the PMTU correlation.
			switch {
			case answered.Load():
				r.Cause = HTTPCauseInvalidResponse
				r.Detail = protocol + " response from " + tried + " could not be read: " + err.Error()
				r.Fix = "the endpoint answered, but not with a readable " + protocol + " response: another service on this port, or a broken server or intermediary?"
			case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
				// EPIPE is a write to a connection the peer already reset.
				r.Cause = ConnectionCauseReset
				r.Detail = tried + " reset the connection before any " + protocol + " response: " + err.Error()
				r.Fix = "the endpoint aborted the request: another service on this port, or a server or intermediary rejecting it?"
			case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
				// HTTP/2 reports a clean close before headers as ErrUnexpectedEOF.
				r.Cause = ConnectionCauseClosed
				r.Detail = tried + " closed the connection before any " + protocol + " response: " + err.Error()
				r.Fix = "the endpoint aborted the request: another service on this port, or a server or intermediary rejecting it?"
			}
			return r
		}
		_ = resp.Body.Close()
		r.Status = StatusPass
		r.Detail = fmt.Sprintf("%s %d (responded)", protocol, resp.StatusCode)
		return r
	}
}

// readBannerLine reads one banner line and reports whether it is complete. A
// line without its "\n" delimiter was cut short by EOF, a reset, the read
// deadline or the byte limit, so it is a fragment of what the peer meant to
// send and never a valid protocol greeting, however it starts.
func readBannerLine(br *bufio.Reader) (line string, complete bool, err error) {
	line, err = br.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err == nil, err
}

func (o *netops) bannerProbe(id ProbeID, label string, port int) Probe {
	return Probe{ID: id, Name: label, Deps: []ProbeID{ProbeTargetTCP}, Run: func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		ip := deps[ProbeTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		conn, err := o.dialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			r.Status, r.SelectedIP = StatusFail, ip
			r.Detail = "connect to " + ip.String() + " failed: " + err.Error()
			return r
		}
		defer conn.Close()
		// A banner arrives immediately or (shy server) never. Keep the short
		// read leash, capped by the remaining probe budget because net.Conn
		// reads don't honor ctx directly.
		deadline := time.Now().Add(2 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			r.Status, r.SelectedIP = StatusFail, ip
			r.Detail = "cannot set banner read deadline: " + err.Error()
			return r
		}
		// Strict byte limit: a hostile server streaming without a newline can't
		// exhaust memory.
		br := bufio.NewReader(io.LimitReader(conn, 1024))
		line, complete, readErr := readBannerLine(br)
		first := line
		// RFC 4253 section 4.2 lets an SSH server send other lines of data
		// before its identification string, and forbids those lines from
		// starting with "SSH-". Keep reading complete lines under the same byte
		// limit and read deadline until the identification string shows up.
		for id == ProbeSSH && complete && !strings.HasPrefix(line, "SSH-") {
			line, complete, readErr = readBannerLine(br)
			if first == "" {
				first = line
			}
		}
		r.SelectedIP = ip
		if first == "" && errors.Is(readErr, syscall.ECONNRESET) {
			r.Status, r.Cause = StatusFail, ConnectionCauseReset
			r.Detail = "peer accepted the connection and reset it before sending a banner"
		} else if first == "" {
			// Port answered but the service said nothing: functional, degraded.
			r.Status, r.Detail = StatusWarn, "connected, no banner within deadline"
		} else if valid := complete && (id == ProbeSSH && strings.HasPrefix(line, "SSH-") ||
			id == ProbeSMTP && (strings.HasPrefix(line, "220 ") || strings.HasPrefix(line, "220-"))); !valid {
			r.Status, r.Detail = StatusFail, "unexpected service banner: "+first
		} else {
			r.Status, r.Detail = StatusPass, "banner: "+line
		}
		return r
	}}
}
