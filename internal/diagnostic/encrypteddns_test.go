package diagnostic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fixtures ----

// dnsResponseFor builds the answer a healthy resolver would return for query:
// the same transaction id, the response bit, the question echoed back, and one
// A record. Tests mutate the result to describe every way a peer can answer
// with something that is not this query's answer.
func dnsResponseFor(query []byte) []byte {
	question := query[dnsHeaderLen:]
	resp := make([]byte, 0, len(query)+16)
	resp = append(resp, query[0], query[1]) // transaction id
	resp = binary.BigEndian.AppendUint16(resp, dnsFlagResponse|dnsFlagRD|0x0080)
	resp = binary.BigEndian.AppendUint16(resp, 1) // one question
	resp = binary.BigEndian.AppendUint16(resp, 1) // one answer
	resp = append(resp, 0, 0, 0, 0)               // no authority or additional records
	resp = append(resp, question...)
	// One A record for the queried name, by compression pointer to the question.
	resp = append(resp, 0xc0, dnsHeaderLen)
	resp = binary.BigEndian.AppendUint16(resp, dnsTypeA)
	resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
	resp = binary.BigEndian.AppendUint32(resp, 60)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	return append(resp, 192, 0, 2, 77)
}

// dohReply is what the DoH fixture answers with; a nil payload means "answer the
// query correctly".
type dohReply struct {
	status        int
	contentType   string
	extraType     string
	noContentType bool
	location      string
	payload       []byte
	mutate        func([]byte) []byte
	check         func(*http.Request, []byte)
}

// dotReply describes the DoT fixture's behaviour on the far side of a completed
// TLS handshake. silent leaves the query unanswered, which is the case a bare
// handshake must never be mistaken for.
type dotReply struct {
	silent bool
	frame  func(response []byte) []byte
	mutate func([]byte) []byte
}

// encryptedDNSFixture is a DoH endpoint, a DoT endpoint, or both, reachable
// only over in-memory pipes. Either half can be left out, which is how a
// blocked port is expressed: the dial is refused, exactly as a closed port is.
type encryptedDNSFixture struct {
	ep    encryptedDNSEndpoint
	roots *x509.CertPool

	doh *pipeNet
	dot *pipeNet

	mu     sync.Mutex
	dialed []string
}

type encryptedDNSLocalConn struct {
	net.Conn
	local net.Addr
}

func (c encryptedDNSLocalConn) LocalAddr() net.Addr { return c.local }

const encryptedFixtureHost = "resolver.test"

func newEncryptedDNSFixture(t *testing.T, ips []net.IP, doh *dohReply, dot *dotReply) *encryptedDNSFixture {
	t.Helper()
	cert, roots := selfSignedCert(t, encryptedFixtureHost)
	f := &encryptedDNSFixture{
		ep:    encryptedDNSEndpoint{host: encryptedFixtureHost, ips: ips, dohPort: dohPort, dotPort: dotPort},
		roots: roots,
	}
	if doh != nil {
		f.doh = newPipeNet(t)
		srv := &http.Server{
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
			ReadHeaderTimeout: time.Second,
			Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveDoH(w, r, *doh) }),
			// A pipe torn down at cleanup is not a finding worth printing.
			ErrorLog: log.New(io.Discard, "", 0),
		}
		f.doh.serve(t, srv, func() error { return srv.ServeTLS(f.doh, "", "") })
	}
	if dot != nil {
		f.dot = newPipeNet(t)
		serveDoT(t, f.dot, cert, *dot)
	}
	return f
}

func serveDoH(w http.ResponseWriter, r *http.Request, reply dohReply) {
	query, err := io.ReadAll(io.LimitReader(r.Body, maxDNSMessage))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if reply.check != nil {
		reply.check(r, query)
	}
	payload := reply.payload
	if payload == nil {
		payload = dnsResponseFor(query)
	}
	if reply.mutate != nil {
		payload = reply.mutate(payload)
	}
	if !reply.noContentType {
		contentType := reply.contentType
		if contentType == "" {
			contentType = dnsMessageMediaType
		}
		w.Header().Set("Content-Type", contentType)
		if reply.extraType != "" {
			w.Header().Add("Content-Type", reply.extraType)
		}
	} else {
		// A nil value suppresses net/http's automatic application/octet-stream.
		w.Header()["Content-Type"] = nil
	}
	status := reply.status
	if status == 0 {
		status = http.StatusOK
	}
	if reply.location != "" {
		w.Header().Set("Location", reply.location)
	}
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// serveDoT is the RFC 7858 side of the fixture: TLS, then length-prefixed DNS.
func serveDoT(t *testing.T, p *pipeNet, cert tls.Certificate, reply dotReply) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := p.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := conn.Handshake(); err != nil {
					return
				}
				var header [2]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(header[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				if reply.silent {
					// The query was read and no answer follows: a completed TLS
					// session on 853 must never read as a completed DNS exchange.
					<-done
					return
				}
				response := dnsResponseFor(query)
				if reply.mutate != nil {
					response = reply.mutate(response)
				}
				frame := reply.frame
				if frame == nil {
					frame = func(msg []byte) []byte {
						// #nosec G115 -- the fixture only frames the bounded query response under test.
						return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
					}
				}
				_, _ = conn.Write(frame(response))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = p.Close()
		<-done
	})
}

// dial routes by port to whichever half of the fixture exists and records every
// address asked for, so a test can prove what the probe did and did not dial.
func (f *encryptedDNSFixture) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+" "+addr)
	f.mu.Unlock()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	target := f.doh
	if port == "853" {
		target = f.dot
	}
	if target == nil || (port != "443" && port != "853") {
		return nil, errors.New("connection refused")
	}
	return target.dial(ctx, network, addr)
}

func (f *encryptedDNSFixture) addresses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

func (f *encryptedDNSFixture) ops() *netops {
	return &netops{
		dialContext: f.dial,
		tlsRootCAs:  f.roots,
		interfaces:  func() ([]net.Interface, error) { return nil, nil },
	}
}

func (f *encryptedDNSFixture) run(t *testing.T, ops *netops) ProbeResult {
	t.Helper()
	// Everything here is in-memory, so the only case that waits is the one that
	// is supposed to: a peer that answers nothing.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return ops.encryptedDNSProbe(f.ep, ConnectivityProbeHost)(ctx, nil)
}

var fixtureIPs = []net.IP{net.ParseIP("192.0.2.10")}

// ---- DNS wire format ----

func TestDNSQueryRejectsOverlongName(t *testing.T) {
	name := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 62)}, ".")
	if _, err := newDNSQuery(name); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("newDNSQuery accepted a 256-byte QNAME: %v", err)
	}
}

func TestDNSVerifierRejectsMalformedResponses(t *testing.T) {
	query, err := newDNSQuery(ConnectivityProbeHost)
	if err != nil {
		t.Fatal(err)
	}
	valid := dnsResponseFor(query.wire)
	for _, c := range []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{"truncated QNAME", func(msg []byte) []byte { return msg[:dnsHeaderLen+3] }, "too short"},
		{"wrong question count", func(msg []byte) []byte {
			binary.BigEndian.PutUint16(msg[4:6], 0)
			return msg
		}, "0 questions"},
		{"compression pointer in question", func(msg []byte) []byte {
			msg[dnsHeaderLen], msg[dnsHeaderLen+1] = 0xc0, 0xff
			return msg
		}, "different question"},
		{"oversized label", func(msg []byte) []byte {
			msg[dnsHeaderLen] = 64
			return msg
		}, "different question"},
		{"wrong question type", func(msg []byte) []byte {
			msg[dnsHeaderLen+len(query.question)-4] ^= 1
			return msg
		}, "different question"},
		{"wrong question class", func(msg []byte) []byte {
			msg[dnsHeaderLen+len(query.question)-2] ^= 1
			return msg
		}, "different question"},
		{"unexpected opcode", func(msg []byte) []byte {
			binary.BigEndian.PutUint16(msg[2:4], binary.BigEndian.Uint16(msg[2:4])|0x0800)
			return msg
		}, "unexpected opcode"},
		{"truncated response bit", func(msg []byte) []byte {
			binary.BigEndian.PutUint16(msg[2:4], binary.BigEndian.Uint16(msg[2:4])|dnsFlagTC)
			return msg
		}, "marked truncated"},
	} {
		t.Run(c.name, func(t *testing.T) {
			msg := c.mutate(append([]byte(nil), valid...))
			if err := query.verify(msg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("verify = %v, want error containing %q", err, c.want)
			}
		})
	}
}

func TestDNSVerifierClassifiesValidReachabilityResponsesWithoutAnswers(t *testing.T) {
	query, err := newDNSQuery(ConnectivityProbeHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, rcode := range []uint16{dnsRcodeSuccess, dnsRcodeNXDom} {
		response := append([]byte(nil), dnsResponseFor(query.wire)[:dnsHeaderLen+len(query.question)]...)
		binary.BigEndian.PutUint16(response[6:8], 0)
		binary.BigEndian.PutUint16(response[2:4], dnsFlagResponse|dnsFlagRD|rcode)
		if err := query.verify(response); err != nil {
			t.Errorf("rcode %d without answers: %v", rcode, err)
		}
	}
	for _, rcode := range []uint16{dnsRcodeFormErr, dnsRcodeServFail, dnsRcodeNotImp, dnsRcodeRefused, dnsRcodeYXDomain} {
		response := append([]byte(nil), dnsResponseFor(query.wire)[:dnsHeaderLen+len(query.question)]...)
		binary.BigEndian.PutUint16(response[6:8], 0)
		binary.BigEndian.PutUint16(response[2:4], dnsFlagResponse|dnsFlagRD|rcode)
		var responseErr *dnsResponseError
		if err := query.verify(response); !errors.As(err, &responseErr) || responseErr.rcode != rcode {
			t.Errorf("standard-query rcode %d = %v, want a correlated resolver error", rcode, err)
		}
	}
	// FORMERR and NOTIMP can legally omit the question when the server could
	// not parse or implement it. The header still has the matching ID.
	for _, rcode := range []uint16{dnsRcodeFormErr, dnsRcodeNotImp} {
		response := make([]byte, dnsHeaderLen)
		binary.BigEndian.PutUint16(response[0:2], query.id)
		binary.BigEndian.PutUint16(response[2:4], dnsFlagResponse|rcode)
		var responseErr *dnsResponseError
		if err := query.verify(response); !errors.As(err, &responseErr) || responseErr.rcode != rcode {
			t.Errorf("header-only rcode %d = %v, want a correlated resolver error", rcode, err)
		}
	}
	malformedEmptyError := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(malformedEmptyError[0:2], query.id)
	binary.BigEndian.PutUint16(malformedEmptyError[2:4], dnsFlagResponse|dnsRcodeFormErr)
	binary.BigEndian.PutUint16(malformedEmptyError[6:8], 1)
	if err := query.verify(malformedEmptyError); err == nil || !strings.Contains(err.Error(), "empty DNS header") {
		t.Errorf("questionless FORMERR with a missing answer = %v, want a malformed-response error", err)
	}
	// Codes 7-10 belong to UPDATE and 11 to DSO; 12-15 are unassigned. None is
	// a valid error for this OPCODE=QUERY message. YXDOMAIN (6) is valid here
	// because RFC 6672 uses it when DNAME substitution makes a name too long.
	for rcode := uint16(7); rcode <= 15; rcode++ {
		response := append([]byte(nil), dnsResponseFor(query.wire)[:dnsHeaderLen+len(query.question)]...)
		binary.BigEndian.PutUint16(response[6:8], 0)
		binary.BigEndian.PutUint16(response[2:4], dnsFlagResponse|dnsFlagRD|rcode)
		var responseErr *dnsResponseError
		if err := query.verify(response); err == nil || errors.As(err, &responseErr) {
			t.Errorf("non-query rcode %d = %v, want an invalid protocol response", rcode, err)
		}
	}
}

// Error() formats an rcode straight out of a 7-entry name table, but the field
// holds any 4-bit wire value. An unfamiliar code must read back, not panic.
func TestDNSResponseErrorFormatsEveryRcode(t *testing.T) {
	known := map[uint16]string{
		dnsRcodeSuccess:  "resolver answered NOERROR (rcode 0)",
		dnsRcodeFormErr:  "resolver answered FORMERR (rcode 1)",
		dnsRcodeServFail: "resolver answered SERVFAIL (rcode 2)",
		dnsRcodeNXDom:    "resolver answered NXDOMAIN (rcode 3)",
		dnsRcodeNotImp:   "resolver answered NOTIMP (rcode 4)",
		dnsRcodeRefused:  "resolver answered REFUSED (rcode 5)",
		dnsRcodeYXDomain: "resolver answered YXDOMAIN (rcode 6)",
	}
	for rcode, want := range known {
		if got := (&dnsResponseError{rcode: rcode}).Error(); got != want {
			t.Errorf("rcode %d = %q, want %q", rcode, got, want)
		}
	}
	// 7 (YXRRSET) and 9 (NOTAUTH) are real assigned codes; 15 is the largest
	// value the 4-bit header field can carry.
	for _, rcode := range []uint16{7, 9, 15, ^uint16(0)} {
		want := fmt.Sprintf("resolver answered an unknown response code (rcode %d)", rcode)
		if got := (&dnsResponseError{rcode: rcode}).Error(); got != want {
			t.Errorf("rcode %d = %q, want %q", rcode, got, want)
		}
	}
}

func TestDNSVerifierMatchesQuestionCaseInsensitively(t *testing.T) {
	query, err := newDNSQuery(ConnectivityProbeHost)
	if err != nil {
		t.Fatal(err)
	}
	response := dnsResponseFor(query.wire)
	response[dnsHeaderLen+1] = 'C'
	if err := query.verify(response); err != nil {
		t.Fatalf("verify rejected a case-only QNAME change: %v", err)
	}
}

// dnsRR encodes one resource record: an owner name, a type, class IN, a TTL,
// and RDATA behind its own length.
func dnsRR(name []byte, rrtype uint16, rdata []byte) []byte {
	rr := append(bytes.Clone(name), 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(rr[len(name):], rrtype)
	binary.BigEndian.PutUint16(rr[len(name)+2:], dnsClassIN)
	binary.BigEndian.PutUint32(rr[len(name)+4:], 60)
	// #nosec G115 -- DNS test RDATA is limited to fixed IPv4/IPv6-sized fixtures.
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
	return append(rr, rdata...)
}

// dnsVerifierSeeds is the corpus the response-verifier fuzz target starts from:
// the answers a healthy resolver sends, and the shapes a hostile or broken peer
// can send instead. Each case is assembled from the protocol rather than pasted
// in as a blob, so a reader can see which rule it aims at.
//
// Name compression and resource records reach verify only as opaque bytes: it
// parses no names beyond the byte-for-byte question echo and no answer section
// at all, because a correlated NODATA response already proves the resolver
// answered. Those families are seeded anyway, so mutation starts from realistic
// record shapes instead of inventing them from noise.
func dnsVerifierSeeds(tb testing.TB, q dnsQuery) [][]byte {
	tb.Helper()
	valid := dnsResponseFor(q.wire)
	// body is the first byte after the echoed question; the QTYPE and QCLASS
	// the response has to match sit in the four bytes before it.
	body := dnsHeaderLen + len(q.question)
	const ok = dnsFlagResponse | dnsFlagRD | 0x0080 // QR, RD, RA

	// respond assembles a response that echoes this query's question, with the
	// given header flags, section counts, and trailing section bytes.
	respond := func(flags uint16, counts [4]uint16, tail []byte) []byte {
		msg := binary.BigEndian.AppendUint16(make([]byte, 0, body+len(tail)), q.id)
		msg = binary.BigEndian.AppendUint16(msg, flags)
		for _, c := range counts {
			msg = binary.BigEndian.AppendUint16(msg, c)
		}
		return append(append(msg, q.question...), tail...)
	}
	// header is a response with no question section at all.
	header := func(flags uint16, counts [4]uint16) []byte {
		return bytes.Clone(respond(flags, counts, nil)[:dnsHeaderLen])
	}
	// edit is the valid response with one field overwritten.
	edit := func(mutate func([]byte)) []byte {
		msg := bytes.Clone(valid)
		mutate(msg)
		return msg
	}
	cut := func(n int) []byte { return bytes.Clone(valid[:n]) }
	setU16 := func(msg []byte, off int, v uint16) { binary.BigEndian.PutUint16(msg[off:], v) }

	question := func(name string) []byte {
		encoded, err := dnsQuestion(name)
		if err != nil {
			tb.Fatal(err)
		}
		return encoded
	}
	// A name on its own is the question minus QTYPE and QCLASS.
	owner := func(name string) []byte { return question(name)[:len(question(name))-4] }
	pointer := []byte{0xc0, dnsHeaderLen} // compression pointer to the question
	address := []byte{192, 0, 2, 77}
	answer := dnsRR(pointer, dnsTypeA, address)
	// A response to a different name, carrying this query's transaction id.
	otherName := dnsResponseFor(append(bytes.Clone(q.wire[:dnsHeaderLen]), question("example.test")...))

	return [][]byte{
		// 1. Valid answers: what the row exists to recognize.
		valid,                                   // one A record
		respond(ok, [4]uint16{1, 0, 0, 0}, nil), // NOERROR/NODATA
		respond(ok, [4]uint16{1, 2, 0, 0}, append(bytes.Clone(answer), answer...)), // duplicate answers
		respond(ok, [4]uint16{1, 1, 1, 1}, bytes.Join([][]byte{ // extra authority + additional
			answer,
			dnsRR(owner("gstatic.com"), 2, owner("ns1.gstatic.com")),
			dnsRR(pointer, 28, bytes.Repeat([]byte{0x20}, 16)),
		}, nil)),
		respond(ok|dnsRcodeNXDom, [4]uint16{1, 0, 1, 0}, dnsRR(owner("com"), 6, bytes.Repeat([]byte{0}, 22))),

		// 2. Degenerate input: nothing to parse.
		{},
		{0x00},
		{0xc0, 0x0c},
		cut(dnsHeaderLen - 1), // one byte short of a header

		// 3. Truncation at each structural boundary of a valid response.
		cut(dnsHeaderLen),     // header only, but QDCOUNT says 1
		cut(dnsHeaderLen + 3), // mid-QNAME
		cut(body - 5),         // QNAME unterminated
		cut(body - 4),         // name complete, no QTYPE
		cut(body - 1),         // mid-QCLASS
		cut(body),             // question complete, ANCOUNT says 1
		cut(body + 6),         // mid resource-record header
		cut(len(valid) - 2),   // mid-RDATA

		// 4. Malformed names and labels in the echoed question.
		edit(func(m []byte) { m[dnsHeaderLen] = 64 }),                            // label over the 63-byte limit
		edit(func(m []byte) { m[dnsHeaderLen] = 0xff }),                          // impossible label length
		edit(func(m []byte) { m[dnsHeaderLen], m[dnsHeaderLen+1] = 0xc0, 0x0c }), // pointer to itself
		edit(func(m []byte) { m[dnsHeaderLen], m[dnsHeaderLen+1] = 0xc0, 0xff }), // pointer past the message
		edit(func(m []byte) { m[body-5] = 1 }),                                   // terminator replaced by a label
		append(cut(dnsHeaderLen), 63),                                            // label longer than the message

		// 5. Header states that are not an answer to a standard query.
		respond(dnsFlagRD, [4]uint16{1, 0, 0, 0}, nil),                 // QR clear: a query, not a response
		respond(ok|0x0800, [4]uint16{1, 0, 0, 0}, nil),                 // OPCODE 1 (IQUERY)
		respond(ok|dnsOpcodeMask, [4]uint16{1, 0, 0, 0}, nil),          // OPCODE 15
		respond(ok|dnsFlagTC, [4]uint16{1, 1, 0, 0}, answer),           // TC: the answer did not fit
		respond(ok|dnsRcodeServFail, [4]uint16{1, 0, 0, 0}, nil),       // SERVFAIL
		respond(ok|dnsRcodeNXDom, [4]uint16{1, 0, 0, 0}, nil),          // NXDOMAIN
		respond(ok|dnsRcodeRefused, [4]uint16{1, 0, 0, 0}, nil),        // REFUSED
		respond(ok|7, [4]uint16{1, 0, 0, 0}, nil),                      // rcode 7: not a standard-query error
		respond(ok|0x000f, [4]uint16{1, 0, 0, 0}, nil),                 // rcode 15
		header(ok|dnsRcodeFormErr, [4]uint16{0, 0, 0, 0}),              // legal questionless FORMERR
		header(ok|dnsRcodeNotImp, [4]uint16{0, 0, 0, 0}),               // legal questionless NOTIMP
		header(ok|dnsRcodeFormErr, [4]uint16{0, 1, 0, 0}),              // questionless FORMERR that claims an answer
		header(ok|dnsRcodeServFail, [4]uint16{0, 0, 0, 0}),             // no question, and no excuse for dropping it
		header(ok, [4]uint16{0, 0, 0, 0}),                              // NOERROR with nothing in it
		respond(ok, [4]uint16{0xffff, 0xffff, 0xffff, 0xffff}, answer), // every count lies
		respond(ok, [4]uint16{1, 0xffff, 0, 0}, nil),                   // ANCOUNT lies, no records follow

		// 6. Correlation failures: valid DNS, wrong conversation.
		edit(func(m []byte) { setU16(m, 0, ^q.id) }), // mismatched transaction id
		otherName, // right id, different question name
		edit(func(m []byte) { setU16(m, body-4, 28) }), // right name, QTYPE AAAA
		edit(func(m []byte) { setU16(m, body-2, 3) }),  // right name and type, class CH
		header(ok, [4]uint16{1, 0, 0, 0}),              // claims a question, sends none
		respond(ok, [4]uint16{2, 0, 0, 0}, q.question), // two questions where one was asked

		// 7. Structurally valid, semantically surprising.
		respond(ok, [4]uint16{1, 1, 0, 0}, dnsRR(pointer, 0xffff, []byte{0})),                                   // unknown RR type
		respond(ok, [4]uint16{1, 1, 0, 0}, dnsRR(owner("elsewhere.example"), dnsTypeA, address)),                // answer for another name
		respond(ok, [4]uint16{1, 1, 0, 0}, dnsRR(owner(strings.Repeat("a", 63)+".example"), dnsTypeA, address)), // longest legal label
		// RDLENGTH claims 64KB behind four bytes of RDATA.
		respond(ok, [4]uint16{1, 1, 0, 0}, append(bytes.Clone(dnsRR(pointer, dnsTypeA, address)[:len(pointer)+8]), 0xff, 0xff, 192, 0, 2, 1)),
	}
}

// dnsVerifierOracle restates the correlation contract verify owns, written from
// the rules rather than from verify's code: which responses a peer must send for
// its bytes to count as an answer to this exact query, and the rcode such an
// answer carries. Everything else is a message some other party could have
// produced, and must not reach the caller as a resolver response.
func dnsVerifierOracle(q dnsQuery, msg []byte) (rcode uint16, correlated bool) {
	if len(msg) < dnsHeaderLen {
		return 0, false
	}
	var field [6]uint16
	for i := range field {
		field[i] = binary.BigEndian.Uint16(msg[2*i:])
	}
	id, flags, counts := field[0], field[1], field[2:]
	rcode = flags & dnsRcodeMask
	switch {
	case id != q.id, // some other conversation
		flags&dnsFlagResponse == 0, // a query, not an answer
		flags&dnsOpcodeMask != 0,   // not the standard query that was sent
		flags&dnsFlagTC != 0:       // the answer did not fit, so this is not it
		return rcode, false
	}
	switch counts[0] {
	case 0:
		// Only a server that could not parse or implement the query may omit
		// the question, and only in an otherwise empty header.
		if (rcode != dnsRcodeFormErr && rcode != dnsRcodeNotImp) || len(msg) != dnsHeaderLen ||
			counts[1] != 0 || counts[2] != 0 || counts[3] != 0 {
			return rcode, false
		}
	case 1:
		if len(msg) < dnsHeaderLen+len(q.question) {
			return rcode, false
		}
		if !dnsNameFoldEqual(msg[dnsHeaderLen:dnsHeaderLen+len(q.question)], q.question) {
			return rcode, false
		}
	default:
		return rcode, false
	}
	return rcode, true
}

// dnsNameFoldEqual is DNS's own case rule, RFC 4343, ASCII letters and nothing
// else, spelled out so the oracle does not borrow the comparison it checks.
func dnsNameFoldEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// FuzzEncryptedDNSResponseVerifier drives arbitrary hostile bytes through the
// boundary that separates "something answered on port 443" from "encrypted DNS
// works". Everything upstream of verify (TLS, HTTP status, media type, DoT
// framing) proves only that a peer spoke; verify is the sole reason the row
// cannot be passed by a captive portal, an interceptor, or a stale packet.
//
// The query side is fixed and valid, the response side is whatever the fuzzer
// produces. Not panicking is the floor: every input is classified by an
// independent oracle, and verify has to agree with it about acceptance, about
// the rcode carried back, and about the difference between a malformed message
// and a valid response reporting an error.
func FuzzEncryptedDNSResponseVerifier(f *testing.F) {
	query, err := newDNSQuery(ConnectivityProbeHost)
	if err != nil {
		f.Fatal(err)
	}
	// newDNSQuery randomizes the transaction id, and a corpus entry recorded
	// against a random id would not reproduce on the next run. Pinning one keeps
	// found crashes replayable; withID is what DoH already does in production.
	query = query.withID(0x4a3b)

	// A verifier that rejected everything would satisfy every invariant below,
	// so anchor the two ends before fuzzing.
	if err := query.verify(dnsResponseFor(query.wire)); err != nil {
		f.Fatalf("verify rejected the answer a healthy resolver sends: %v", err)
	}
	if err := query.verify(nil); err == nil {
		f.Fatal("verify accepted an empty response")
	}
	for _, seed := range dnsVerifierSeeds(f, query) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		before := bytes.Clone(msg)
		err := query.verify(msg)
		if !bytes.Equal(msg, before) {
			t.Fatalf("verify rewrote the caller's response buffer: % x -> % x", before, msg)
		}

		rcode, correlated := dnsVerifierOracle(query, msg)
		var responseErr *dnsResponseError
		switch {
		case !correlated:
			// Malformed or uncorrelated: a plain error, never a resolver verdict.
			if err == nil || errors.As(err, &responseErr) {
				t.Fatalf("verify returned %v for a response that does not answer this query: % x", err, msg)
			}
		case rcode == dnsRcodeSuccess || rcode == dnsRcodeNXDom:
			if err != nil {
				t.Fatalf("verify rejected a correlated rcode %d response: %v (% x)", rcode, err, msg)
			}
		case rcode <= dnsRcodeYXDomain: // FORMERR, SERVFAIL, NOTIMP, REFUSED, YXDOMAIN
			if !errors.As(err, &responseErr) || responseErr.rcode != rcode {
				t.Fatalf("verify returned %v for a correlated rcode %d response, want that rcode reported: % x", err, rcode, msg)
			}
		default: // 7-15 are not standard-query errors
			if err == nil || errors.As(err, &responseErr) {
				t.Fatalf("verify returned %v for non-query rcode %d: % x", err, rcode, msg)
			}
		}
		// The row's PASS/WARN/FAIL split reads verify's error through this, so a
		// parser error must never arrive as a degraded resolver.
		if answered := resolverAnswered(transportOutcome{err: err}); answered != (correlated && rcode <= dnsRcodeYXDomain) {
			t.Fatalf("resolverAnswered = %t for correlated=%t rcode=%d: % x", answered, correlated, rcode, msg)
		}

		if err != nil && !errors.As(err, &responseErr) {
			return
		}
		// Whatever was accepted, acceptance has to be bound to this query's
		// transaction id and to the question that was actually asked.
		wrongID := bytes.Clone(msg)
		binary.BigEndian.PutUint16(wrongID[0:2], ^query.id)
		if err := query.verify(wrongID); err == nil || errors.As(err, &responseErr) {
			t.Fatalf("verify accepted a response after its transaction id changed: %v (% x)", err, wrongID)
		}
		if len(msg) > dnsHeaderLen {
			wrongName := bytes.Clone(msg)
			wrongName[dnsHeaderLen] = 0xff // not a label length, not a case fold of one
			if err := query.verify(wrongName); err == nil || errors.As(err, &responseErr) {
				t.Fatalf("verify accepted a response after its question changed: %v (% x)", err, wrongName)
			}
		}
	})
}

// ---- DoH ----

func TestDoHValidExchangePasses(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, nil)
	r := f.run(t, f.ops())
	if r.Status != StatusPass || !strings.Contains(r.Detail, "DoH completed a DNS query") {
		t.Fatalf("result = %+v, want PASS naming DoH", r)
	}
	if !strings.Contains(r.Detail, "DoT unavailable") {
		t.Errorf("detail = %q, want the failing transport named too", r.Detail)
	}
}

func TestDoHSendsTheWireQueryAsPublished(t *testing.T) {
	wantQuestion, err := dnsQuestion(ConnectivityProbeHost)
	if err != nil {
		t.Fatal(err)
	}
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{check: func(r *http.Request, body []byte) {
		if r.Method != http.MethodPost || r.URL.Path != encryptedDNSPath || r.URL.RawQuery != "" || r.Host != encryptedFixtureHost {
			t.Errorf("request = %s https://%s%s?%s", r.Method, r.Host, r.URL.Path, r.URL.RawQuery)
		}
		if r.Header.Get("Content-Type") != dnsMessageMediaType || r.Header.Get("Accept") != dnsMessageMediaType {
			t.Errorf("headers = %v", r.Header)
		}
		if len(body) != dnsHeaderLen+len(wantQuestion) || binary.BigEndian.Uint16(body[0:2]) != 0 ||
			binary.BigEndian.Uint16(body[2:4]) != dnsFlagRD ||
			binary.BigEndian.Uint16(body[4:6]) != 1 || !bytes.Equal(body[dnsHeaderLen:], wantQuestion) {
			t.Errorf("DoH body is not the one-question DNS wire message: % x", body)
		}
	}}, nil)
	if r := f.run(t, f.ops()); r.Status != StatusPass {
		t.Fatalf("result = %+v, want PASS", r)
	}
}

// The whole point of the row: TLS and HTTP both succeeding proves nothing on
// their own. Each of these is a completed HTTPS request that is not an answer.
func TestDoHWithoutACorrelatedAnswerCannotPass(t *testing.T) {
	cases := []struct {
		name  string
		reply dohReply
		want  string
	}{
		{
			name:  "valid DNS body with wrong media type",
			reply: dohReply{contentType: "text/html"},
			want:  "Content-Type",
		},
		{
			name:  "malformed media type",
			reply: dohReply{contentType: "application/dns-message; version"},
			want:  "Content-Type",
		},
		{
			name:  "empty declared media type",
			reply: dohReply{contentType: " "},
			want:  "Content-Type",
		},
		{
			name:  "multiple media types",
			reply: dohReply{contentType: "application/dns-message, text/plain"},
			want:  "Content-Type",
		},
		{
			name:  "duplicate Content-Type fields",
			reply: dohReply{contentType: dnsMessageMediaType, extraType: "text/plain"},
			want:  "multiple Content-Type",
		},
		{
			name:  "empty body",
			reply: dohReply{payload: []byte{}},
			want:  "too short",
		},
		{
			name:  "oversized body",
			reply: dohReply{payload: make([]byte, maxDNSMessage+1)},
			want:  "exceeds",
		},
		{
			name: "wrong transaction id",
			reply: dohReply{mutate: func(resp []byte) []byte {
				resp[0], resp[1] = resp[0]^0xff, resp[1]^0xff
				return resp
			}},
			want: "transaction id",
		},
		{
			name: "answers a different question",
			reply: dohReply{mutate: func(resp []byte) []byte {
				resp[dnsHeaderLen+1] ^= 0x01 // corrupt the first label of the echoed QNAME
				return resp
			}},
			want: "different question",
		},
		{
			name: "query bit still set",
			reply: dohReply{mutate: func(resp []byte) []byte {
				binary.BigEndian.PutUint16(resp[2:4], dnsFlagRD)
				return resp
			}},
			want: "query bit",
		},
		{
			name: "unexpected opcode",
			reply: dohReply{mutate: func(resp []byte) []byte {
				binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|0x0800)
				return resp
			}},
			want: "unexpected opcode",
		},
		{
			name: "truncated DNS response",
			reply: dohReply{mutate: func(resp []byte) []byte {
				binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|dnsFlagTC)
				return resp
			}},
			want: "marked truncated",
		},
		{
			name:  "HTTP error status",
			reply: dohReply{status: http.StatusForbidden},
			want:  "HTTP 403",
		},
		{
			name:  "redirected elsewhere",
			reply: dohReply{status: http.StatusFound, location: "https://attacker.invalid/dns-query"},
			want:  "HTTP 302",
		},
		{
			name:  "bodyless successful response",
			reply: dohReply{status: http.StatusNoContent},
			want:  "too short",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEncryptedDNSFixture(t, fixtureIPs, &c.reply, nil)
			r := f.run(t, f.ops())
			if r.Status != StatusFail {
				t.Fatalf("result = %+v, want FAIL: an HTTPS round trip is not a DNS answer", r)
			}
			if !strings.Contains(r.Detail, c.want) {
				t.Errorf("detail = %q, want it to name %q", r.Detail, c.want)
			}
		})
	}
}

func TestDoHAcceptsSuccessful2xxAndPermittedMediaTypeForms(t *testing.T) {
	for _, reply := range []dohReply{
		{status: http.StatusCreated, contentType: "Application/Dns-Message; version=1"},
		{noContentType: true},
	} {
		f := newEncryptedDNSFixture(t, fixtureIPs, &reply, nil)
		r := f.run(t, f.ops())
		if r.Status != StatusPass {
			t.Fatalf("reply = %+v, result = %+v, want a verified DNS message in a 2xx response to pass", reply, r)
		}
	}
}

// ---- DoT ----

func TestDoTValidExchangePasses(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, nil, &dotReply{})
	r := f.run(t, f.ops())
	if r.Status != StatusPass || !strings.Contains(r.Detail, "DoT completed a DNS query") {
		t.Fatalf("result = %+v, want PASS naming DoT", r)
	}
	if !strings.Contains(r.Detail, "DoH unavailable") {
		t.Errorf("detail = %q, want the failing transport named too", r.Detail)
	}
}

func TestDoTWithoutACorrelatedAnswerCannotPass(t *testing.T) {
	cases := []struct {
		name  string
		reply dotReply
		want  string
	}{
		{
			name:  "TLS completes and nothing follows",
			reply: dotReply{silent: true},
			want:  "no DNS response after the TLS handshake",
		},
		{
			name: "unframed reply",
			reply: dotReply{frame: func(msg []byte) []byte {
				msg[0], msg[1] = 0xff, 0xff // a deterministic impossible frame size
				return msg                  // the two-byte length prefix DoT requires is missing
			}},
			want: "DoT framing declares",
		},
		{
			name: "framing longer than the message",
			reply: dotReply{frame: func(msg []byte) []byte {
				// #nosec G115 -- the bounded test response plus 64 still fits DoT's uint16 frame.
				return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg)+64)), msg...)
			}},
			want: "truncated DNS response",
		},
		{
			name: "zero-length frame",
			reply: dotReply{frame: func([]byte) []byte {
				return []byte{0, 0}
			}},
			want: "DoT framing declares a 0-byte message",
		},
		{
			name: "wrong transaction id",
			reply: dotReply{mutate: func(resp []byte) []byte {
				resp[0], resp[1] = resp[0]^0xff, resp[1]^0xff
				return resp
			}},
			want: "transaction id",
		},
		{
			name: "answers a different question",
			reply: dotReply{mutate: func(resp []byte) []byte {
				resp[dnsHeaderLen+1] ^= 0x01
				return resp
			}},
			want: "different question",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newEncryptedDNSFixture(t, fixtureIPs, nil, &c.reply)
			r := f.run(t, f.ops())
			if r.Status != StatusFail {
				t.Fatalf("result = %+v, want FAIL: a TLS session on 853 is not a DNS answer", r)
			}
			if !strings.Contains(r.Detail, c.want) {
				t.Errorf("detail = %q, want it to name %q", r.Detail, c.want)
			}
		})
	}
}

// A resolver whose certificate this machine cannot verify is not encrypted DNS
// it can use, on either transport. Production verification is what makes that
// true, so the test withholds the fixture root rather than relaxing anything.
func TestEncryptedDNSRequiresVerifiedCertificate(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, &dotReply{})
	ops := f.ops()
	ops.tlsRootCAs = x509.NewCertPool()

	r := f.run(t, ops)
	if r.Status != StatusFail {
		t.Fatalf("result = %+v, want FAIL for an unverifiable resolver certificate", r)
	}
}

func TestEncryptedDNSRequiresTheEndpointsName(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, &dotReply{})
	f.ep.host = "other.test" // certificate is for resolver.test

	r := f.run(t, f.ops())
	if r.Status != StatusFail || !strings.Contains(r.Detail, "other.test") {
		t.Fatalf("result = %+v, want FAIL naming the identity that was demanded", r)
	}
}

// ---- row semantics ----

func TestEncryptedDNSRowSemantics(t *testing.T) {
	for _, c := range []struct {
		name       string
		doh        *dohReply
		dot        *dotReply
		wantStatus Status
		wantDetail string
	}{
		{"both transports work", &dohReply{}, &dotReply{}, StatusPass, "DoH and DoT both completed"},
		{"DoH works, DoT blocked", &dohReply{}, nil, StatusPass, "DoH completed a DNS query"},
		{"DoT works, DoH blocked", nil, &dotReply{}, StatusPass, "DoT completed a DNS query"},
		{"neither works", nil, nil, StatusFail, "no encrypted DNS via"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newEncryptedDNSFixture(t, fixtureIPs, c.doh, c.dot)
			r := f.run(t, f.ops())
			if r.Status != c.wantStatus || !strings.Contains(r.Detail, c.wantDetail) {
				t.Fatalf("result = %+v, want %v mentioning %q", r, c.wantStatus, c.wantDetail)
			}
			if c.wantStatus == StatusFail && r.Cause != EncryptedDNSCauseUnavailable {
				t.Errorf("cause = %q, want %q", r.Cause, EncryptedDNSCauseUnavailable)
			}
		})
	}
}

func TestEncryptedDNSResolverErrorsWarnWithoutClaimingUnavailable(t *testing.T) {
	setRcode := func(rcode uint16) func([]byte) []byte {
		return func(resp []byte) []byte {
			binary.BigEndian.PutUint16(resp[2:4], dnsFlagResponse|dnsFlagRD|rcode)
			return resp
		}
	}
	for _, c := range []struct {
		name string
		doh  *dohReply
		dot  *dotReply
		want string
	}{
		{"DoH SERVFAIL", &dohReply{mutate: setRcode(2)}, nil, "SERVFAIL"},
		{"DoT REFUSED", nil, &dotReply{mutate: setRcode(5)}, "REFUSED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newEncryptedDNSFixture(t, fixtureIPs, c.doh, c.dot)
			r := f.run(t, f.ops())
			if r.Status != StatusWarn || r.Cause != "" || !strings.Contains(r.Detail, c.want) || strings.Contains(r.Detail, "no encrypted DNS") {
				t.Fatalf("result = %+v, want WARN naming the resolver error without an unavailable cause", r)
			}
			results := map[ProbeID]ProbeResult{
				ProbeInternet:     {Status: StatusPass},
				ProbeDNS:          {Status: StatusPass},
				ProbeDNSEncrypted: r,
			}
			if encryptedDNSBlocked(results) {
				t.Fatal("a correlated resolver error was diagnosed as blocked encrypted DNS")
			}
			order := []ProbeID{ProbeInternet, ProbeDNS, ProbeDNSEncrypted}
			d := Interpret(nil, order, results)
			if d.Verdict != VerdictDegraded || d.Summary == encryptedDNSSummary {
				t.Fatalf("diagnosis = %q, %q, want a generic degraded verdict without the blocking diagnosis", d.Summary, d.Verdict)
			}
		})
	}
}

func TestEncryptedDNSFailureCausePrecedence(t *testing.T) {
	timedOut := context.DeadlineExceeded
	for _, c := range []struct {
		name     string
		doh, dot error
		want     string
	}{
		{"DoH refused and DoT timed out", errors.New("connection refused"), timedOut, EncryptedDNSCauseTimeout},
		{"DoH malformed and DoT timed out", errors.New("different question"), timedOut, EncryptedDNSCauseTimeout},
		{"DoH TLS failure and DoT timed out", errors.New("certificate verify failed"), timedOut, EncryptedDNSCauseTimeout},
		{"DoH timed out and DoT protocol failed", timedOut, errors.New("invalid frame"), EncryptedDNSCauseTimeout},
		{"both timed out", timedOut, timedOut, EncryptedDNSCauseTimeout},
		{"both failed immediately", errors.New("HTTP 403"), errors.New("connection refused"), EncryptedDNSCauseUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := encryptedDNSFailureCause(context.Background(), c.doh, c.dot); got != c.want {
				t.Fatalf("cause = %q, want %q", got, c.want)
			}
		})
	}
}

// One blocked transport must not spend the whole budget and leave the other
// unasked: they run at the same time, so a working DoT still reports a PASS
// well inside one probe timeout.
func TestEncryptedDNSTransportsRunConcurrently(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, &dotReply{silent: true})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	start := time.Now()
	r := f.ops().encryptedDNSProbe(f.ep, ConnectivityProbeHost)(ctx, nil)
	if r.Status != StatusPass || !strings.Contains(r.Detail, "DoH completed") {
		t.Fatalf("result = %+v, want the answering transport to carry the row", r)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe took %v; a stalled transport should not serialize with the working one", elapsed)
	}
}

// ---- what the probe must never do ----

// No fallback to plaintext DNS, ever. This row exists to answer whether
// encrypted DNS itself works; a UDP or TCP 53 query would answer a different
// question and report it as this one.
func TestEncryptedDNSNeverFallsBackToPort53(t *testing.T) {
	for _, c := range []struct {
		name string
		doh  *dohReply
		dot  *dotReply
	}{
		{"working", &dohReply{}, &dotReply{}},
		{"both blocked", nil, nil},
		{"garbage over DoH", &dohReply{payload: []byte("not dns")}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newEncryptedDNSFixture(t, fixtureIPs, c.doh, c.dot)
			f.run(t, f.ops())
			for _, addr := range f.addresses() {
				if strings.HasSuffix(addr, ":53") {
					t.Fatalf("probe dialed %q; encrypted DNS must never fall back to port 53", addr)
				}
				if !strings.HasSuffix(addr, ":443") && !strings.HasSuffix(addr, ":853") {
					t.Fatalf("probe dialed %q, want only the DoH and DoT ports", addr)
				}
			}
		})
	}
}

// An environment proxy would answer for the resolver and let the row pass
// without an encrypted query ever reaching one. The transport ignores the
// environment entirely, and nothing here writes to it.
func TestEncryptedDNSIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.9:1")
	t.Setenv("http_proxy", "http://192.0.2.9:1")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.9:1")
	t.Setenv("https_proxy", "http://192.0.2.9:1")
	t.Setenv("ALL_PROXY", "socks5://192.0.2.9:1")
	t.Setenv("all_proxy", "socks5://192.0.2.9:1")
	t.Setenv("NO_PROXY", "resolver.test")
	t.Setenv("no_proxy", "resolver.test")

	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, nil)
	r := f.run(t, f.ops())
	if r.Status != StatusPass {
		t.Fatalf("result = %+v, want the proxy environment to be ignored, not honored", r)
	}
	for _, addr := range f.addresses() {
		if strings.Contains(addr, "192.0.2.9") {
			t.Fatalf("probe dialed the proxy at %q", addr)
		}
	}
}

func TestEncryptedDNSCancellationReturnsPromptly(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, nil, &dotReply{silent: true})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan ProbeResult, 1)
	go func() { result <- f.ops().encryptedDNSProbe(f.ep, ConnectivityProbeHost)(ctx, nil) }()
	// Give both transports time to be in flight before pulling the context.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case r := <-result:
		if r.Status != StatusNA {
			t.Fatalf("canceled result = %+v, want N/A", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("encrypted DNS probe did not terminate after cancellation")
	}
}

func TestEncryptedDNSTimeoutIsBoundedByTheProbeContext(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, nil, &dotReply{silent: true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	r := f.ops().encryptedDNSProbe(f.ep, ConnectivityProbeHost)(ctx, nil)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("probe ran %v past its own deadline", elapsed)
	}
	if r.Status != StatusFail || r.Cause != EncryptedDNSCauseTimeout {
		t.Fatalf("result = %+v, want FAIL with the timeout cause", r)
	}
}

// ---- source address and interface selection ----

func TestEncryptedDNSUsesOnlyFamiliesTheSelectedInterfaceHas(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")
	f := newEncryptedDNSFixture(t, []net.IP{v6, v4}, &dohReply{}, &dotReply{})
	ops := f.ops()
	ops.sources = &SourceAddresses{IPv4: net.ParseIP("192.0.2.1")}

	r := f.run(t, ops)
	if r.Status != StatusPass {
		t.Fatalf("result = %+v, want PASS over the family the interface has", r)
	}
	for _, addr := range f.addresses() {
		if strings.Contains(addr, "2001:db8::10") || strings.Contains(addr, "6 ") {
			t.Fatalf("dialed %q from an IPv4-only interface selection", addr)
		}
	}
}

func TestEncryptedDNSIsNotApplicableWithoutACompatibleFamily(t *testing.T) {
	f := newEncryptedDNSFixture(t, []net.IP{net.ParseIP("2001:db8::10")}, &dohReply{}, &dotReply{})
	ops := f.ops()
	ops.sources = &SourceAddresses{IPv4: net.ParseIP("192.0.2.1")}

	r := f.run(t, ops)
	if r.Status != StatusNA || !strings.Contains(r.Detail, "no address family") {
		t.Fatalf("result = %+v, want N/A rather than a failure the interface could not avoid", r)
	}
	if len(f.addresses()) != 0 {
		t.Fatalf("dialed %v with no compatible source family", f.addresses())
	}
}

func TestEncryptedDNSDialsIPv6WhenThatIsWhatTheEndpointHas(t *testing.T) {
	v6 := net.ParseIP("2001:db8::10")
	f := newEncryptedDNSFixture(t, []net.IP{v6}, &dohReply{}, nil)
	ops := f.ops()
	ops.sources = &SourceAddresses{IPv4: net.ParseIP("192.0.2.1"), IPv6: net.ParseIP("2001:db8::1")}

	r := f.run(t, ops)
	if r.Status != StatusPass {
		t.Fatalf("result = %+v, want PASS over IPv6", r)
	}
	for _, addr := range f.addresses() {
		if !strings.HasPrefix(addr, "tcp6 ") {
			t.Fatalf("dialed %q, want the IPv6 network for an IPv6 endpoint", addr)
		}
	}
}

// The row is bound by the same --iface plumbing as every other outbound probe:
// it dials through netops.dialContext, which opsFromSources replaces with the
// source-bound dialer. No second interface lookup, no private dialer.
func TestEncryptedDNSUsesTheSharedSourceBoundDialer(t *testing.T) {
	sources := &SourceAddresses{IPv4: net.ParseIP("127.0.0.1"), Iface: "lo"}
	ops := opsFromSources(sources)
	var bound []net.IP
	var mu sync.Mutex
	ops.dialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		source, _ := ops.sources.forDial(network, addr)
		mu.Lock()
		bound = append(bound, source)
		mu.Unlock()
		return nil, errors.New("connection refused")
	}
	ep := encryptedDNSEndpoint{host: encryptedFixtureHost, ips: []net.IP{net.ParseIP("192.0.2.10")}, dohPort: dohPort, dotPort: dotPort}

	if r := ops.encryptedDNSProbe(ep, ConnectivityProbeHost)(context.Background(), nil); r.Status != StatusFail {
		t.Fatalf("result = %+v, want FAIL when every dial is refused", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bound) == 0 {
		t.Fatal("the probe never dialed through the shared dialer")
	}
	for _, source := range bound {
		if !source.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("dial bound to %v, want the address --iface selected", source)
		}
	}
}

func TestEncryptedDNSReusesSelectedInterfaceResult(t *testing.T) {
	f := newEncryptedDNSFixture(t, fixtureIPs, &dohReply{}, nil)
	ops := f.ops()
	ops.sources = &SourceAddresses{IPv4: net.ParseIP("192.0.2.1")}
	dial := ops.dialContext
	ops.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return encryptedDNSLocalConn{Conn: conn, local: &net.TCPAddr{IP: ops.sources.IPv4}}, nil
	}
	ops.interfaces = func() ([]net.Interface, error) {
		t.Fatal("encrypted DNS enumerated interfaces after its Interface dependency completed")
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := ops.encryptedDNSProbe(f.ep, ConnectivityProbeHost)(ctx, map[ProbeID]ProbeResult{
		ProbeIface: {Status: StatusPass, Iface: "selected0"},
	})
	if r.Status != StatusPass || r.Iface != "selected0" {
		t.Fatalf("result = %+v, want PASS reusing selected0", r)
	}
}

// ---- diagnosis ----

func TestDiagnoseEncryptedDNSBlockedWhilePlainDNSWorks(t *testing.T) {
	wantSummary := "Plain DNS works, but encrypted DNS could not complete a verified exchange. The resolver may be unavailable, or the network may be blocking or interfering with DoH/DoT."
	if encryptedDNSSummary != wantSummary {
		t.Fatalf("encrypted DNS summary = %q, want %q", encryptedDNSSummary, wantSummary)
	}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS, ProbeDNSPublic, ProbeDNSEncrypted}
	res := map[ProbeID]ProbeResult{
		ProbeIface:        {Status: StatusPass},
		ProbeInternet:     {Status: StatusPass},
		ProbeQUIC:         {Status: StatusPass},
		ProbeProxy:        {Status: StatusNA},
		ProbeDNS:          {Status: StatusPass},
		ProbeDNSPublic:    {Status: StatusPass},
		ProbeDNSEncrypted: {Status: StatusFail, Cause: EncryptedDNSCauseUnavailable, Detail: "no encrypted DNS"},
	}

	d := Interpret(nil, order, res)
	if d.Verdict != VerdictDegraded || d.Summary != encryptedDNSSummary {
		t.Fatalf("diagnosis = %q, %q", d.Summary, d.Verdict)
	}
	// The claim stops at what two probes observed. Intent is not observable.
	for _, overclaim := range []string{"forc", "downgrad", "Firefox", "browser chose"} {
		if strings.Contains(strings.ToLower(d.Summary), strings.ToLower(overclaim)) {
			t.Errorf("summary %q claims %q, which the probes cannot show", d.Summary, overclaim)
		}
	}
}

func TestDiagnoseDoesNotBlameEncryptedDNSWhenAllDNSIsDown(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeDNSEncrypted}
	res := map[ProbeID]ProbeResult{
		ProbeIface:        {Status: StatusPass},
		ProbeInternet:     {Status: StatusPass},
		ProbeDNS:          {Status: StatusFail},
		ProbeDNSEncrypted: {Status: StatusFail},
	}

	d := Interpret(nil, order, res)
	if d.Summary == encryptedDNSSummary || d.Verdict != VerdictDNS {
		t.Fatalf("diagnosis = %q, %q, want the DNS-wide failure rather than an encrypted-specific claim", d.Summary, d.Verdict)
	}
}

func TestReconcileEncryptedDNSOnlyAddsEvidenceItHas(t *testing.T) {
	blocked := map[ProbeID]ProbeResult{
		ProbeInternet:     {Status: StatusPass},
		ProbeDNS:          {Status: StatusPass},
		ProbeDNSEncrypted: {Status: StatusFail, Detail: "no encrypted DNS via resolver.test"},
	}
	Finalize(blocked)
	got := blocked[ProbeDNSEncrypted]
	if !strings.Contains(got.Detail, "specific to encrypted DNS") || got.Fix == "" {
		t.Fatalf("blocked encrypted row = %+v, want the plaintext comparison recorded", got)
	}

	allDown := map[ProbeID]ProbeResult{
		ProbeInternet:     {Status: StatusPass},
		ProbeDNS:          {Status: StatusFail},
		ProbeDNSEncrypted: {Status: StatusFail, Detail: "no encrypted DNS via resolver.test"},
	}
	Finalize(allDown)
	if strings.Contains(allDown[ProbeDNSEncrypted].Detail, "specific to encrypted DNS") {
		t.Fatalf("encrypted row = %+v, want no encrypted-specific claim while DNS is down entirely", allDown[ProbeDNSEncrypted])
	}

	// A run without the public-DNS row must not read its absent result as a pass.
	noPublic := map[ProbeID]ProbeResult{
		ProbeInternet:     {Status: StatusPass},
		ProbeDNS:          {Status: StatusFail},
		ProbeDNSEncrypted: {Status: StatusFail, Detail: "no encrypted DNS"},
	}
	if encryptedDNSBlocked(noPublic) {
		t.Fatal("an absent public-DNS row counted as working plaintext DNS")
	}

	// A machine with no working egress cannot reach the encrypted resolver for
	// reasons that have nothing to do with encrypted DNS, so the row keeps its
	// own evidence and gains no encrypted-specific claim.
	noEgress := map[ProbeID]ProbeResult{
		ProbeInternet:     {Status: StatusFail},
		ProbeDNS:          {Status: StatusPass},
		ProbeDNSEncrypted: {Status: StatusFail, Detail: "no encrypted DNS via resolver.test"},
	}
	Finalize(noEgress)
	if strings.Contains(noEgress[ProbeDNSEncrypted].Detail, "specific to encrypted DNS") {
		t.Fatalf("encrypted row = %+v, want no encrypted-specific claim without working egress", noEgress[ProbeDNSEncrypted])
	}
}

func TestEncryptedDNSBlockedTruthTable(t *testing.T) {
	base := func() map[ProbeID]ProbeResult {
		return map[ProbeID]ProbeResult{
			ProbeInternet:     {Status: StatusPass},
			ProbeDNS:          {Status: StatusPass},
			ProbeDNSEncrypted: {Status: StatusFail},
		}
	}
	for _, c := range []struct {
		name string
		edit func(map[ProbeID]ProbeResult)
		want bool
	}{
		{"plain DNS works and encrypted fails", func(map[ProbeID]ProbeResult) {}, true},
		{"public plaintext resolver is the only one working", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNS] = ProbeResult{Status: StatusFail}
			r[ProbeDNSPublic] = ProbeResult{Status: StatusPass}
		}, true},
		{"all DNS fails", func(r map[ProbeID]ProbeResult) { r[ProbeDNS] = ProbeResult{Status: StatusFail} }, false},
		{"direct egress fails", func(r map[ProbeID]ProbeResult) { r[ProbeInternet] = ProbeResult{Status: StatusFail} }, false},
		{"proxy-only downgrade", func(r map[ProbeID]ProbeResult) {
			r[ProbeInternet] = ProbeResult{Status: StatusWarn, downgraded: true}
		}, false},
		{"captive portal", func(r map[ProbeID]ProbeResult) {
			r[ProbeInternet] = ProbeResult{Status: StatusFail, Portal: &Portal{}}
		}, false},
		{"encrypted succeeds", func(r map[ProbeID]ProbeResult) { r[ProbeDNSEncrypted] = ProbeResult{Status: StatusPass} }, false},
		{"encrypted resolver answered with an error", func(r map[ProbeID]ProbeResult) {
			r[ProbeDNSEncrypted] = ProbeResult{Status: StatusWarn, Detail: "resolver answered SERVFAIL"}
		}, false},
		{"encrypted is not applicable", func(r map[ProbeID]ProbeResult) { r[ProbeDNSEncrypted] = ProbeResult{Status: StatusNA} }, false},
		{"encrypted row is absent", func(r map[ProbeID]ProbeResult) { delete(r, ProbeDNSEncrypted) }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			results := base()
			c.edit(results)
			if got := encryptedDNSBlocked(results); got != c.want {
				t.Fatalf("encryptedDNSBlocked = %v, want %v for %+v", got, c.want, results)
			}
		})
	}
}

func TestEncryptedDNSDiagnosisOutcomeTruthTable(t *testing.T) {
	outcomes := []struct {
		name   string
		result ProbeResult
	}{
		{"transports unreachable", ProbeResult{Status: StatusFail, Cause: EncryptedDNSCauseUnavailable}},
		{"TLS verification failure", ProbeResult{Status: StatusFail, Cause: EncryptedDNSCauseUnavailable}},
		{"malformed protocol response", ProbeResult{Status: StatusFail, Cause: EncryptedDNSCauseUnavailable}},
		{"valid SERVFAIL", ProbeResult{Status: StatusWarn, Detail: "resolver answered SERVFAIL"}},
		{"valid REFUSED", ProbeResult{Status: StatusWarn, Detail: "resolver answered REFUSED"}},
		{"DoH valid and DoT failed", ProbeResult{Status: StatusPass}},
		{"DoT valid and DoH failed", ProbeResult{Status: StatusPass}},
		{"both valid", ProbeResult{Status: StatusPass}},
		{"both timed out", ProbeResult{Status: StatusFail, Cause: EncryptedDNSCauseTimeout}},
		{"probe canceled", ProbeResult{Status: StatusNA}},
	}
	conditions := []struct {
		name          string
		plain, egress Status
	}{
		{"plain and direct egress work", StatusPass, StatusPass},
		{"plain fails", StatusFail, StatusPass},
		{"direct egress fails", StatusPass, StatusFail},
		{"plain and direct egress fail", StatusFail, StatusFail},
	}
	for _, outcome := range outcomes {
		for _, condition := range conditions {
			t.Run(outcome.name+"/"+condition.name, func(t *testing.T) {
				results := map[ProbeID]ProbeResult{
					ProbeInternet:     {Status: condition.egress},
					ProbeDNS:          {Status: condition.plain},
					ProbeDNSEncrypted: outcome.result,
				}
				want := outcome.result.Status == StatusFail && condition.plain == StatusPass && condition.egress == StatusPass
				if got := encryptedDNSBlocked(results); got != want {
					t.Fatalf("encryptedDNSBlocked = %v, want %v for %+v", got, want, results)
				}
			})
		}
	}
}

func TestEncryptedDNSRowIsAnIndependentInterfaceBranch(t *testing.T) {
	for _, probes := range [][]Probe{
		BuildProbesFromSources(nil, nil, DefaultPublicDNS, true),
		BuildProbesFromSources(mustTarget(t, "github.com"), nil, DefaultPublicDNS, true),
	} {
		var found bool
		for _, p := range probes {
			if p.ID != ProbeDNSEncrypted {
				continue
			}
			found = true
			if len(p.Deps) != 1 || p.Deps[0] != ProbeIface {
				t.Fatalf("encrypted DNS deps = %v, want [iface]: plain and encrypted DNS are independent", p.Deps)
			}
			if p.Name != "DNS (encrypted DoH/DoT)" {
				t.Fatalf("row name = %q", p.Name)
			}
		}
		if !found {
			t.Fatal("encrypted DNS probe missing from the DAG")
		}
	}
}

// The DoH transport dials on a goroutine that can outlive the request when the
// context expires mid-dial, so the outcome is published under a lock rather
// than written where the probe is already reading it. Only -race fails on the
// difference.
func TestDoHDialOutlivesRequest(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(60 * time.Millisecond)
		return nil, errors.New("connection refused")
	}}
	ep := encryptedDNSEndpoint{host: encryptedFixtureHost, ips: fixtureIPs, dohPort: dohPort, dotPort: dotPort}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	r := ops.encryptedDNSProbe(ep, ConnectivityProbeHost)(ctx, nil)
	time.Sleep(120 * time.Millisecond) // stay alive for the dial's write, the racing access

	if r.Status != StatusFail {
		t.Fatalf("result = %+v, want FAIL when no address answers", r)
	}
}
