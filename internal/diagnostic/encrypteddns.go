package diagnostic

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The encrypted-DNS endpoint is fixed, and deliberately not derived from
// anything the user configures. --public-dns names a plaintext resolver IP:
// reinterpreting it as a DoH/DoT provider would invent a TLS identity nobody
// vouched for, and there is no safe way to guess a hostname from an address.
// Cloudflare publishes these addresses for both transports. Its DoT listener
// also presents a certificate valid for the cloudflare-dns.com DoH identity,
// so the probe can dial by IP and still verify one fixed name, with no bootstrap
// lookup through the very resolver path this row exists to test.
const (
	// EncryptedDNSHost is the TLS identity and HTTP authority of the fixed
	// encrypted-DNS probe endpoint.
	EncryptedDNSHost = "cloudflare-dns.com"
	// encryptedDNSPath is the RFC 8484 query path Cloudflare publishes.
	encryptedDNSPath = "/dns-query"
	// dohPort and dotPort are the standard ports: RFC 8484 rides ordinary HTTPS,
	// RFC 7858 has its own.
	dohPort = 443
	dotPort = 853
	// dnsMessageMediaType is the only content type RFC 8484 defines for a
	// wire-format exchange.
	dnsMessageMediaType = "application/dns-message"
)

// Encrypted-DNS failure causes. Reachability and a timeout have different
// remediation, and neither claims that a filter was proven responsible.
const (
	EncryptedDNSCauseUnavailable = "encrypted_dns_unavailable"
	EncryptedDNSCauseTimeout     = "timeout"
)

// maxDNSMessage bounds every response this probe will read. The query is one A
// record for one name; a legitimate answer is a few hundred bytes, and the peer
// is untrusted.
const maxDNSMessage = 4096

// DNS wire constants: only what verifying one A response needs.
const (
	dnsHeaderLen     = 12
	dnsTypeA         = 1
	dnsClassIN       = 1
	dnsFlagResponse  = 0x8000
	dnsOpcodeMask    = 0x7800
	dnsFlagTC        = 0x0200
	dnsFlagRD        = 0x0100
	dnsRcodeMask     = 0x000f
	dnsRcodeSuccess  = 0
	dnsRcodeFormErr  = 1
	dnsRcodeServFail = 2
	dnsRcodeNXDom    = 3
	dnsRcodeNotImp   = 4
	dnsRcodeRefused  = 5
	dnsRcodeYXDomain = 6
)

// encryptedDNSEndpoint is the resolver both transports talk to. ips are
// bootstrap addresses dialed directly; host is the TLS identity and the HTTP
// authority, so certificate verification and the Host header stay correct even
// though no name was resolved to get here. A struct so tests can point the same
// code at a local fixture without a second implementation.
type encryptedDNSEndpoint struct {
	host    string
	ips     []net.IP
	dohPort int
	dotPort int
}

// defaultEncryptedDNS is the fixed diagnostic endpoint. The IPv4 address is the
// one the direct-egress row already dials, so a scenario or network that
// reaches netdoc's usual endpoints reaches this one too.
var defaultEncryptedDNS = encryptedDNSEndpoint{
	host:    EncryptedDNSHost,
	ips:     []net.IP{internetEndpoints4[0], internetEndpoints6[0]},
	dohPort: dohPort,
	dotPort: dotPort,
}

// dnsQuery is one A query plus what is needed to recognize its answer: the
// transaction id and the question section a normal response has to echo.
type dnsQuery struct {
	id       uint16
	question []byte
	wire     []byte
}

// newDNSQuery builds a single-question A lookup with a random transaction ID
// for DoT. DoH replaces it with zero because HTTP provides correlation.
func newDNSQuery(name string) (dnsQuery, error) {
	question, err := dnsQuestion(name)
	if err != nil {
		return dnsQuery{}, err
	}
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return dnsQuery{}, fmt.Errorf("generate DNS transaction id: %w", err)
	}
	id := binary.BigEndian.Uint16(seed[:])
	wire := make([]byte, 0, dnsHeaderLen+len(question))
	wire = binary.BigEndian.AppendUint16(wire, id)
	wire = binary.BigEndian.AppendUint16(wire, dnsFlagRD)
	wire = binary.BigEndian.AppendUint16(wire, 1) // one question
	wire = append(wire, 0, 0, 0, 0, 0, 0)         // no answer, authority, or additional records
	wire = append(wire, question...)
	return dnsQuery{id: id, question: question, wire: wire}, nil
}

// withID gives DoH the zero ID RFC 8484 recommends while leaving DoT's
// unpredictable correlation ID alone. The wire copy keeps the concurrent
// transports from sharing mutable bytes.
func (q dnsQuery) withID(id uint16) dnsQuery {
	q.id = id
	q.wire = bytes.Clone(q.wire)
	binary.BigEndian.PutUint16(q.wire[:2], id)
	return q
}

// dnsQuestion encodes QNAME + QTYPE + QCLASS. Length-prefixed labels only: no
// compression pointer is legal in this first name because RFC 1035 pointers
// refer to a prior occurrence, and only the DNS header precedes it. Refusing
// to write one also keeps the echo comparison a plain byte match.
func dnsQuestion(name string) ([]byte, error) {
	out := make([]byte, 0, len(name)+6)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("%q is not a usable DNS name", name)
		}
		// #nosec G115 -- DNS labels are bounded to 63 bytes immediately above.
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > 255 {
		return nil, fmt.Errorf("%q is too long for a DNS name", name)
	}
	out = binary.BigEndian.AppendUint16(out, dnsTypeA)
	out = binary.BigEndian.AppendUint16(out, dnsClassIN)
	return out, nil
}

// verify reports whether msg has a valid DNS header and question correlated to
// this exact query. It is the whole point of the row: a TLS handshake, an HTTP
// 2xx, or a pile of bytes off a socket prove that something answered, not that
// DNS worked. Transaction id, the response bit, one echoed question, and a
// real resolver rcode are what separate the two. Answer records are deliberately
// not parsed: a valid NOERROR/NODATA response still proves resolver reachability.
//
// NXDOMAIN counts alongside NOERROR: both are a resolver completing the
// question that was asked. A standard-query error RCODE still proves that the
// encrypted resolver answered, but not that it completed the query; callers
// distinguish that degraded service response from an unreachable transport.
func (q dnsQuery) verify(msg []byte) error {
	if len(msg) < dnsHeaderLen {
		return fmt.Errorf("response is %d bytes, too short for a DNS header", len(msg))
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != q.id {
		return fmt.Errorf("response transaction id 0x%04x does not match the query's 0x%04x", id, q.id)
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&dnsFlagResponse == 0 {
		return errors.New("response has the query bit set, so it answers nothing")
	}
	if opcode := flags & dnsOpcodeMask; opcode != 0 {
		return fmt.Errorf("response uses unexpected opcode %d", opcode>>11)
	}
	if flags&dnsFlagTC != 0 {
		return errors.New("response is marked truncated")
	}
	rcode := flags & dnsRcodeMask
	questions := binary.BigEndian.Uint16(msg[4:6])
	if questions == 0 && (rcode == dnsRcodeFormErr || rcode == dnsRcodeNotImp) {
		// A server that could not parse or implement the request can legally
		// omit the question. The verified transport plus matching DNS ID (and,
		// for DoT, one outstanding query) still correlates this error response.
		if len(msg) != dnsHeaderLen || binary.BigEndian.Uint16(msg[6:8]) != 0 ||
			binary.BigEndian.Uint16(msg[8:10]) != 0 || binary.BigEndian.Uint16(msg[10:12]) != 0 {
			return errors.New("questionless error response is not an empty DNS header")
		}
		return &dnsResponseError{rcode: rcode}
	}
	if questions != 1 {
		return fmt.Errorf("response carries %d questions, want the 1 that was asked", questions)
	}
	if len(msg) < dnsHeaderLen+len(q.question) {
		return fmt.Errorf("response is %d bytes, too short to echo this query", len(msg))
	}
	// Case-insensitive: DNS names are, and a resolver is free to echo a label in
	// a different case. Type and class are numeric bytes that folding leaves be.
	if !bytes.EqualFold(msg[dnsHeaderLen:dnsHeaderLen+len(q.question)], q.question) {
		return errors.New("response echoes a different question than the one sent")
	}
	switch rcode {
	case dnsRcodeSuccess, dnsRcodeNXDom:
		return nil
	case dnsRcodeFormErr, dnsRcodeServFail, dnsRcodeNotImp, dnsRcodeRefused, dnsRcodeYXDomain:
		return &dnsResponseError{rcode: rcode}
	default:
		return fmt.Errorf("resolver answered rcode %d, which is not valid for this standard query", rcode)
	}
}

// dnsResponseError is a structurally valid, correlated DNS response whose
// standard-query RCODE says the resolver could not complete the query. It proves
// encrypted reachability even though the resolver service is degraded.
type dnsResponseError struct{ rcode uint16 }

func (e *dnsResponseError) Error() string {
	names := [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN"}
	if int(e.rcode) >= len(names) {
		return fmt.Sprintf("resolver answered an unknown response code (rcode %d)", e.rcode)
	}
	return fmt.Sprintf("resolver answered %s (rcode %d)", names[e.rcode], e.rcode)
}

// transportOutcome is one encrypted transport's result. err == nil means a
// correlated DNS response completed the query; dnsResponseError means the
// resolver answered with a valid DNS error. Every other error means no
// usable correlated DNS response came back over that transport.
type transportOutcome struct {
	selected net.IP
	source   net.IP
	attempts []Attempt
	dur      time.Duration
	err      error
}

func resolverAnswered(out transportOutcome) bool {
	var responseErr *dnsResponseError
	return out.err == nil || errors.As(out.err, &responseErr)
}

func encryptedDNSFailureCause(ctx context.Context, dohErr, dotErr error) string {
	// If either alternative consumed its whole budget without an answer, the
	// final reachability result remained unresolved until the deadline. Detail
	// still preserves the sibling's more specific immediate failure.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || timeoutError(dohErr) || timeoutError(dotErr) {
		return EncryptedDNSCauseTimeout
	}
	return EncryptedDNSCauseUnavailable
}

// encryptedDNSProbe asks whether this machine can complete a DNS exchange over
// an encrypted transport at all. DoH and DoT are tried concurrently against the
// same fixed resolver, and either one succeeding answers the question, since they
// are alternative ways to reach encrypted DNS, not two
// separate capabilities a user needs both of.
//
// Concurrently rather than in sequence for a reason: a network that black-holes
// one of the two ports would otherwise spend the whole probe budget on it and
// report the other as untried, turning a working encrypted path into a failed
// row. Each half owns and closes its own connection and honors the probe
// context. The first successful exchange cancels its sibling so the probe
// returns as soon as encrypted DNS is proven to work.
//
// There is no fallback to plaintext 53 anywhere in here, by design. This row's
// only job is to say whether encrypted DNS itself works.
func (o *netops) encryptedDNSProbe(ep encryptedDNSEndpoint, name string) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		var r ProbeResult
		dotQuery, err := newDNSQuery(name)
		if err != nil {
			r.Status, r.Detail = StatusNA, "cannot build the encrypted DNS query: "+err.Error()
			return r
		}
		ep.ips = o.compatibleSourceIPs(ep.ips)
		if len(ep.ips) == 0 {
			r.Status = StatusNA
			r.Detail = "the encrypted DNS resolver has no address family available on the selected interface"
			return r
		}

		var doh, dot transportOutcome
		ctx2, cancel2 := context.WithCancel(ctx)
		defer cancel2()
		dohCh := make(chan transportOutcome, 1)
		dotCh := make(chan transportOutcome, 1)
		go func() { dohCh <- o.dohExchange(ctx2, ep, dotQuery.withID(0)) }()
		go func() { dotCh <- o.dotExchange(ctx2, ep, dotQuery) }()
		// First success cancels the sibling so it exits without spending its
		// full deadline; the buffered channels collect both outcomes. Once
		// canceled, a sibling's transport error may be the cancellation itself,
		// so it is not reported as that transport being unavailable.
		var canceled bool
		select {
		case doh = <-dohCh:
			if canceled = doh.err == nil; canceled {
				cancel2()
			}
			dot = <-dotCh
		case dot = <-dotCh:
			if canceled = dot.err == nil; canceled {
				cancel2()
			}
			doh = <-dohCh
		}

		r.Attempts = append(append([]Attempt{}, doh.attempts...), dot.attempts...)
		won := doh
		// Prefer query success over a resolver error; otherwise retain DoH's
		// precedence among correlated responses, including resolver errors.
		if doh.err != nil && (dot.err == nil || !resolverAnswered(doh)) {
			won = dot
		}
		if resolverAnswered(won) {
			r.SelectedIP, r.Source = won.selected, won.source
			if won.source != nil {
				if o.sources != nil {
					r.Iface, r.ifaceAmbiguous = deps[ProbeIface].Iface, deps[ProbeIface].ifaceAmbiguous
				} else {
					r.Iface, r.ifaceAmbiguous = o.ifaceForIP(won.source)
				}
			}
		}
		switch {
		case doh.err == nil && dot.err == nil:
			r.Status = StatusPass
			r.Detail = fmt.Sprintf("DoH and DoT both completed a DNS query for %s via %s (DoH %dms, DoT %dms)",
				name, ep.host, Ms(doh.dur), Ms(dot.dur))
		case doh.err == nil:
			r.Status = StatusPass
			if resolverAnswered(dot) {
				r.Detail = fmt.Sprintf("DoH completed a DNS query for %s via %s in %dms; DoT %v",
					name, ep.host, Ms(doh.dur), dot.err)
			} else if canceled {
				r.Detail = fmt.Sprintf("DoH completed a DNS query for %s via %s in %dms",
					name, ep.host, Ms(doh.dur))
			} else {
				r.Detail = fmt.Sprintf("DoH completed a DNS query for %s via %s in %dms; DoT unavailable: %v",
					name, ep.host, Ms(doh.dur), dot.err)
			}
		case dot.err == nil:
			r.Status = StatusPass
			if resolverAnswered(doh) {
				r.Detail = fmt.Sprintf("DoT completed a DNS query for %s via %s in %dms; DoH %v",
					name, ep.host, Ms(dot.dur), doh.err)
			} else if canceled {
				r.Detail = fmt.Sprintf("DoT completed a DNS query for %s via %s in %dms",
					name, ep.host, Ms(dot.dur))
			} else {
				r.Detail = fmt.Sprintf("DoT completed a DNS query for %s via %s in %dms; DoH unavailable: %v",
					name, ep.host, Ms(dot.dur), doh.err)
			}
		case resolverAnswered(doh) || resolverAnswered(dot):
			r.Status = StatusWarn
			r.Detail = fmt.Sprintf("encrypted DNS reached %s, but the resolver returned an error (DoH: %v; DoT: %v)", ep.host, doh.err, dot.err)
			r.Fix = "the encrypted resolver answered but did not complete the DNS query: retry later or check resolver policy; this is not evidence that DoH/DoT is blocked"
		case errors.Is(ctx.Err(), context.Canceled):
			r.Status = StatusNA
			r.Detail = "encrypted DNS check canceled before either transport answered"
		default:
			r.Status = StatusFail
			r.Cause = encryptedDNSFailureCause(ctx, doh.err, dot.err)
			r.Detail = fmt.Sprintf("no encrypted DNS via %s (DoH: %v; DoT: %v)", ep.host, doh.err, dot.err)
			r.Fix = "neither DoH (443) nor DoT (853) completed a verified DNS exchange; the resolver may be unavailable, or the network may block or intercept encrypted DNS"
		}
		return r
	}
}

// dohExchange runs one RFC 8484 exchange: POST the wire-format query to the
// resolver's HTTPS endpoint and read a correlated wire-format answer back.
//
// The transport is built here rather than borrowed so the request cannot be
// carried by anything but this machine's own path to the resolver: Proxy is nil
// (an environment proxy answering for the resolver would let the row pass
// without encrypted DNS ever leaving as encrypted DNS), redirects are not
// followed, the dial goes to the bootstrap addresses through the family-aware
// source-bound dialer, and certificate verification runs against the endpoint's
// real name.
func (o *netops) dohExchange(ctx context.Context, ep encryptedDNSEndpoint, query dnsQuery) transportOutcome {
	start := time.Now()
	// The transport dials on its own goroutine, which can outlive client.Do on a
	// context timeout, so the closure publishes under a lock instead of writing
	// the outcome directly.
	var mu sync.Mutex
	var out transportOutcome
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, selected, attempts, _ := o.dialIPs(ctx, ep.ips, ep.dohPort)
			mu.Lock()
			out.selected, out.attempts = selected, attempts
			if conn != nil {
				out.source = connIP(conn.LocalAddr())
			}
			mu.Unlock()
			if conn == nil {
				if n := len(attempts); n > 0 && attempts[n-1].Err != nil {
					return nil, attempts[n-1].Err
				}
				return nil, errors.New("no DoH address answered")
			}
			return conn, nil
		},
		TLSClientConfig:        &tls.Config{ServerName: ep.host, RootCAs: o.tlsRootCAs, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()

	// The authority carries the default port only when it isn't the default, so
	// the Host header a real resolver sees is the ordinary one.
	authority := ep.host
	if ep.dohPort != dohPort {
		authority = net.JoinHostPort(ep.host, strconv.Itoa(ep.dohPort))
	}
	finish := func(err error) transportOutcome {
		mu.Lock()
		defer mu.Unlock()
		out.dur, out.err = since(start), err
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+encryptedDNSPath, bytes.NewReader(query.wire))
	if err != nil {
		return finish(err)
	}
	req.Header.Set("Content-Type", dnsMessageMediaType)
	req.Header.Set("Accept", dnsMessageMediaType)
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return finish(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return finish(fmt.Errorf("resolver answered HTTP %s, want a 2xx response with a DNS message", resp.Status))
	}
	contentTypes := resp.Header.Values("Content-Type")
	if len(contentTypes) > 1 {
		return finish(fmt.Errorf("resolver answered multiple Content-Type fields %q, want one %s", contentTypes, dnsMessageMediaType))
	}
	if len(contentTypes) == 1 {
		contentType := contentTypes[0]
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.EqualFold(mediaType, dnsMessageMediaType) {
			return finish(fmt.Errorf("resolver answered Content-Type %q, want %s", contentType, dnsMessageMediaType))
		}
	}
	// Bounded: the body is attacker-controlled, and one extra byte is enough to
	// tell "at the limit" from "over it".
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return finish(fmt.Errorf("cannot read the DNS response body: %w", err))
	}
	if len(body) > maxDNSMessage {
		return finish(fmt.Errorf("DNS response body exceeds %d bytes", maxDNSMessage))
	}
	return finish(query.verify(body))
}

// dotExchange runs one RFC 7858 exchange: TLS to the resolver's DoT port, then
// the query behind the two-byte length prefix DNS-over-TCP framing requires,
// then a correlated answer read back out of the same framing.
func (o *netops) dotExchange(ctx context.Context, ep encryptedDNSEndpoint, query dnsQuery) transportOutcome {
	start := time.Now()
	conn, selected, attempts, _ := o.dialIPs(ctx, ep.ips, ep.dotPort)
	out := transportOutcome{selected: selected, attempts: attempts}
	finish := func(err error) transportOutcome {
		out.dur, out.err = since(start), err
		return out
	}
	if conn == nil {
		if n := len(attempts); n > 0 && attempts[n-1].Err != nil {
			return finish(fmt.Errorf("cannot reach %s on port %d: %w", ep.host, ep.dotPort, attempts[n-1].Err))
		}
		return finish(fmt.Errorf("cannot reach %s on port %d", ep.host, ep.dotPort))
	}
	defer conn.Close()
	// A net.Conn read doesn't watch ctx, so the deadline is its leash, and a
	// deadline alone would leave an explicit cancellation waiting for it, hence
	// the close on ctx.Done. stop runs before the deferred Close, so the hook is
	// gone before the connection is.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(DefaultProbeTimeout)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return finish(fmt.Errorf("cannot bound the DoT exchange: %w", err))
	}
	out.source = connIP(conn.LocalAddr())

	tlsConn := tls.Client(conn, &tls.Config{ServerName: ep.host, RootCAs: o.tlsRootCAs, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return finish(fmt.Errorf("TLS to port %d failed: %w", ep.dotPort, err))
	}
	// #nosec G115 -- dnsQuestion bounds this one-question query far below 65535 bytes.
	framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(query.wire)), uint16(len(query.wire)))
	if _, err := tlsConn.Write(append(framed, query.wire...)); err != nil {
		return finish(fmt.Errorf("cannot send the DNS query: %w", err))
	}
	var header [2]byte
	if _, err := io.ReadFull(tlsConn, header[:]); err != nil {
		return finish(fmt.Errorf("no DNS response after the TLS handshake: %w", err))
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > maxDNSMessage {
		return finish(fmt.Errorf("DoT framing declares a %d-byte message", size))
	}
	msg := make([]byte, size)
	if _, err := io.ReadFull(tlsConn, msg); err != nil {
		return finish(fmt.Errorf("truncated DNS response: %w", err))
	}
	return finish(query.verify(msg))
}
