// Probe behavior against local listeners and stubs: Happy Eyeballs stagger and
// cancellation, DNS/TLS/banner failure paths, and the HTTP header cap.

package diagnostic

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/snapshot"
)

// splitDNSFixture is a two-resolver DNS network for the real Go resolver.
//
// LookupIP(ctx, "ip", host) asks A and AAAA as independent queries, each with
// its own Dial and its own failover, so on a machine whose resolv.conf names
// more than one server the two halves of a single hostname lookup can be
// answered by two different resolvers. The fixture is that machine's network:
// each dial lands on the next simulated resolver, and each resolver answers
// only the one query it was handed.
type splitDNSFixture struct {
	mu        sync.Mutex
	dialed    []string
	exchanges []splitDNSExchange
}

// splitDNSExchange is one query answered by one simulated resolver: who
// answered it, what was asked, and the single address that answer carried.
type splitDNSExchange struct {
	server string
	qtype  uint16
	answer string
}

const (
	dnsTypeAAAA      = 28
	splitDNSAnswerA  = "192.0.2.7"
	splitDNSAnswer6  = "2001:db8::7"
	splitDNSAnswerIn = 60 // TTL
)

var splitDNSServers = [...]string{"192.0.2.53:53", "[2001:db8::53]:53"}

// dial gives each query its own resolver and records the address the Go
// resolver actually asked for, which is the ground truth the recorder under
// test has to reproduce.
func (f *splitDNSFixture) dial(_ context.Context, _, addr string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dialed) >= len(splitDNSServers) {
		return nil, fmt.Errorf("unexpected resolver dial %d", len(f.dialed)+1)
	}
	conn := &splitDNSConn{fixture: f, server: splitDNSServers[len(f.dialed)]}
	f.dialed = append(f.dialed, addr)
	return conn, nil
}

// served is read after the lookup returns, by which point both exchanges have
// completed: LookupIP("ip") waits for both families before combining them.
func (f *splitDNSFixture) served() (dialed []string, exchanges []splitDNSExchange) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...), append([]splitDNSExchange(nil), f.exchanges...)
}

// splitDNSConn is one resolver on the other end of one connection. It is not a
// PacketConn, so the Go resolver frames queries the way it does over TCP.
type splitDNSConn struct {
	fixture *splitDNSFixture
	server  string
	reply   []byte
}

func (c *splitDNSConn) Read(p []byte) (int, error) {
	if len(c.reply) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.reply)
	c.reply = c.reply[n:]
	return n, nil
}

func (c *splitDNSConn) Write(p []byte) (int, error) {
	if len(p) < dnsHeaderLen+2 {
		return 0, io.ErrUnexpectedEOF
	}
	query := p[2:] // past the two-byte length prefix
	i := dnsHeaderLen
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	if i+5 > len(query) {
		return 0, io.ErrUnexpectedEOF
	}
	qtype := binary.BigEndian.Uint16(query[i+1:])
	response := append([]byte(nil), query[:i+5]...)
	response[2], response[3] = 0x81, 0x80 // response, recursion available
	binary.BigEndian.PutUint16(response[6:], 1)
	binary.BigEndian.PutUint16(response[8:], 0)
	binary.BigEndian.PutUint16(response[10:], 0)
	response = append(response, 0xc0, 0x0c) // pointer to the question's name
	response = binary.BigEndian.AppendUint16(response, qtype)
	response = append(response, 0, 1, 0, 0, 0, splitDNSAnswerIn)
	answer := splitDNSAnswerA
	switch qtype {
	case dnsTypeA:
		response = append(response, 0, 4)
		response = append(response, net.ParseIP(splitDNSAnswerA).To4()...)
	case dnsTypeAAAA:
		answer = splitDNSAnswer6
		response = append(response, 0, 16)
		response = append(response, net.ParseIP(splitDNSAnswer6).To16()...)
	default:
		return 0, errors.New("unexpected DNS query type")
	}
	c.fixture.mu.Lock()
	c.fixture.exchanges = append(c.fixture.exchanges, splitDNSExchange{c.server, qtype, answer})
	c.fixture.mu.Unlock()
	// #nosec G115 -- the response is this fixture's own header, question and
	// one record, tens of bytes and never near the 16-bit length prefix.
	c.reply = binary.BigEndian.AppendUint16(nil, uint16(len(response)))
	c.reply = append(c.reply, response...)
	return len(p), nil
}

func (*splitDNSConn) Close() error                     { return nil }
func (*splitDNSConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*splitDNSConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*splitDNSConn) SetDeadline(time.Time) error      { return nil }
func (*splitDNSConn) SetReadDeadline(time.Time) error  { return nil }
func (*splitDNSConn) SetWriteDeadline(time.Time) error { return nil }

// silentConn simulates a server that accepts the connection but never sends a
// banner: every read fails immediately as a deadline timeout, so the test
// doesn't wait out the real 2s read deadline.
type silentConn struct{ fakeConn }

func (silentConn) Read([]byte) (int, error)        { return 0, os.ErrDeadlineExceeded }
func (silentConn) SetReadDeadline(time.Time) error { return nil }

type resetConn struct{ fakeConn }

func (resetConn) Read([]byte) (int, error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}
}
func (resetConn) Write(p []byte) (int, error)     { return len(p), nil }
func (resetConn) SetReadDeadline(time.Time) error { return nil }

type deadlineErrorConn struct{ fakeConn }

func (deadlineErrorConn) SetReadDeadline(time.Time) error { return errors.New("unsupported") }

func TestBannerProbeClassifiesWrappedReset(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) { return resetConn{}, nil }}
	probe := ops.bannerProbe(ProbeSSH, "SSH", "", 22)
	r := probe.Run(context.Background(), map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}})
	if r.Status != StatusFail || r.Cause != ConnectionCauseReset {
		t.Fatalf("reset result = %+v", r)
	}
}

func TestHTTPProbeClassifiesWrappedReset(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) { return resetConn{}, nil }}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	r := ops.httpProbe("example.com", 80, "http", ProbeTargetTCP, nil)(context.Background(), deps)
	if r.Status != StatusFail || r.Cause != ConnectionCauseReset {
		t.Fatalf("HTTP reset result = %+v", r)
	}
}

func TestBannerProbeRejectsUnboundedRead(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) { return deadlineErrorConn{}, nil }}
	r := ops.bannerProbe(ProbeSSH, "SSH", "", 22).Run(context.Background(), map[ProbeID]ProbeResult{
		ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")},
	})
	if r.Status != StatusFail || !strings.Contains(r.Detail, "cannot set banner read deadline") {
		t.Fatalf("unbounded banner read = %+v, want failure", r)
	}
}

func TestDNSFailureCauseUsesStructuredErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"timeout", fmt.Errorf("wrapped: %w", &net.DNSError{IsTimeout: true}), DNSCauseTimeout},
		{"temporary", fmt.Errorf("wrapped: %w", &net.DNSError{IsTemporary: true}), DNSCauseTemporaryFailure},
		{"not found", &net.DNSError{IsNotFound: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := dnsFailureCause(tc.err); got != tc.want {
				t.Errorf("cause = %q, want %q", got, tc.want)
			}
		})
	}
}

// Target TCP reports only the addresses dialIPs actually attempted.
func TestTargetTCPProbeAttemptCap(t *testing.T) {
	calls := 0
	ops := &netops{dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
		if network == "tcp4" {
			calls++
		}
		return nil, errors.New("connection refused")
	}}
	ips := make([]net.IP, maxAttempts+4)
	for i := range ips {
		ips[i] = net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1))
	}

	r := ops.targetTCPProbe(80, nil)(context.Background(), map[ProbeID]ProbeResult{ProbeDNS: {Addrs: ips}})
	if calls != maxAttempts || len(r.Attempts) != maxAttempts {
		t.Errorf("calls = %d, attempts = %d, want %d each", calls, len(r.Attempts), maxAttempts)
	}
	want := fmt.Sprintf("port 80 unreachable on all %d address(es): %s", len(r.Attempts), joinIPs(ips[:maxAttempts]))
	if r.Detail != want {
		t.Errorf("detail = %q, want %q", r.Detail, want)
	}
}

func TestTargetTCPProbeClassifiesOnlyWrappedSocketRefusal(t *testing.T) {
	wrappedConnectError := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: err}}
	}
	tests := []struct {
		name      string
		err       error
		wantCause string
	}{
		{"connection refused", wrappedConnectError(connectionRefusedErrno), ConnectionCauseRefused},
		{"timeout", wrappedConnectError(os.ErrDeadlineExceeded), ""},
		{"connection reset", wrappedConnectError(syscall.ECONNRESET), ""},
		{"EOF", io.EOF, ""},
		{"closed connection", net.ErrClosed, ""},
		{"network unreachable", wrappedConnectError(syscall.ENETUNREACH), ""},
		{"TLS failure", tls.RecordHeaderError{Msg: "not a TLS record"}, ""},
		{"proxy refusal", socks5ReplyError{code: 5}, ""},
		{"matching error text without errno", errors.New("connection refused"), ""},
		{"generic failure", errors.New("dial failed"), ""},
	}
	deps := map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{net.ParseIP("192.0.2.1")}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
				return nil, tt.err
			}}
			r := ops.targetTCPProbe(443, nil)(context.Background(), deps)
			if r.Status != StatusFail || r.Cause != tt.wantCause {
				t.Fatalf("result = %+v, want FAIL cause %q", r, tt.wantCause)
			}
			if tt.wantCause == ConnectionCauseRefused {
				if !strings.Contains(r.Detail, "was refused") || !strings.Contains(r.Fix, "actively rejecting") {
					t.Errorf("refusal wording = detail %q, fix %q", r.Detail, r.Fix)
				}
			} else if !strings.Contains(r.Detail, "unreachable") {
				t.Errorf("non-refusal detail = %q, want the broader unreachable result", r.Detail)
			}
		})
	}
}

func TestTargetTCPProbeDoesNotClassifyMixedFailuresAsRefusal(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: connectionRefusedErrno}}
	ops := &netops{dialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
		if network == "udp" {
			return nil, errors.New("path identity unavailable")
		}
		host, _, _ := net.SplitHostPort(addr)
		if host == "192.0.2.1" {
			return nil, refused
		}
		return nil, os.ErrDeadlineExceeded
	}}
	addrs := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	r := ops.targetTCPProbe(443, nil)(context.Background(), map[ProbeID]ProbeResult{ProbeDNS: {Addrs: addrs}})
	if r.Status != StatusFail || r.Cause != "" || len(r.Attempts) != 2 || !strings.Contains(r.Detail, "unreachable") {
		t.Fatalf("mixed refusal and timeout = %+v, want the broader failure", r)
	}
}

// A cancelled context dials nothing instead of grinding through addresses.
func TestDialIPsCancelledStopsEarly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, context.Canceled
	}}
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("192.0.2.3")}

	conn, _, attempts, _ := ops.dialIPs(ctx, ips, 80)
	if conn != nil {
		t.Fatal("expected no connection under a cancelled context")
	}
	if calls != 0 || len(attempts) != 0 {
		t.Errorf("calls = %d, attempts = %d, want 0 each (cancelled ctx must not dial)", calls, len(attempts))
	}
}

// Happy Eyeballs: while an early address hangs, a later one is started after
// the stagger delay and its success wins without waiting out the first.
func TestDialIPsRacesStaggered(t *testing.T) {
	win := net.ParseIP("192.0.2.2")
	ops := &netops{dialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.1") {
			<-ctx.Done() // first address black-holes
			return nil, ctx.Err()
		}
		return fakeConn{}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	conn, sel, attempts, _ := ops.dialIPs(ctx, []net.IP{net.ParseIP("192.0.2.1"), win}, 80)
	if conn == nil || !sel.Equal(win) {
		t.Fatalf("sel = %v, want the second address to win the race", sel)
	}
	_ = conn.Close()
	if len(attempts) != 2 || !attempts[0].IP.Equal(net.ParseIP("192.0.2.1")) || attempts[0].Err == nil ||
		!attempts[1].IP.Equal(win) || attempts[1].Err != nil {
		t.Fatalf("attempts = %+v, want cancelled first address followed by the winner", attempts)
	}
	if attempts[0].Dur < 200*time.Millisecond {
		t.Errorf("first attempt lasted %v, want evidence that the 250ms stagger elapsed", attempts[0].Dur)
	}
	if e := time.Since(start); e > 2*time.Second {
		t.Errorf("race took %v, want well under the hung address's deadline", e)
	}
}

// Addresses are interleaved by family, IPv6 first, per RFC 8305.
func TestInterleaveFamilies(t *testing.T) {
	got := interleaveFamilies([]net.IP{
		net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"),
		net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"),
	})
	want := []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("interleave[%d] = %v, want %v (full: %v)", i, got[i], w, got)
		}
	}
}

// One hostname lookup, two resolvers. Go asks A and AAAA as independent
// queries that dial and fail over independently, so a machine with more than
// one nameserver can have the two halves of a result answered by two different
// servers. The DNS row used to keep one dial target and credit the whole
// combined answer to it, and this run is a counterexample to that claim: each
// resolver supplied exactly one of the two addresses that came back, so naming
// either as the source of both is false.
func TestLookupIPNeverCreditsOneResolverWithACombinedAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fixture := &splitDNSFixture{}
	ips, targets, err := lookupIPWithDial(ctx, "resolver-attribution.test.", fixture.dial)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	dialed, exchanges := fixture.served()

	// The real resolver split one lookup into two exchanges, one per address
	// family, each on its own connection to its own resolver.
	if len(exchanges) != 2 || exchanges[0].server == exchanges[1].server {
		t.Fatalf("exchanges = %+v, want one on each resolver", exchanges)
	}
	byType := map[uint16]string{}
	for _, e := range exchanges {
		byType[e.qtype] = e.server
	}
	if byType[dnsTypeA] == "" || byType[dnsTypeAAAA] == "" {
		t.Fatalf("exchanges = %+v, want A and AAAA answered separately", exchanges)
	}

	// Both halves came back as one address set, and neither resolver served the
	// other's half. "These addresses came via <resolver>" is therefore false of
	// this result whichever resolver it names.
	answers := make(map[string]bool, len(ips))
	for _, ip := range ips {
		answers[ip.String()] = true
	}
	for _, e := range exchanges {
		if !answers[e.answer] {
			t.Fatalf("addresses %v are missing %s, which %s served", ips, e.answer, e.server)
		}
	}
	if len(answers) != len(exchanges) {
		t.Fatalf("addresses = %v, want one from each of the %d resolvers", ips, len(exchanges))
	}

	// What the run may report is what Dial saw, all of it: one target per
	// exchange, deduplicated and ordered. A single overwritten slot could not
	// hold two exchanges, which is what made the old row's claim unprovable.
	if len(dialed) != len(exchanges) {
		t.Errorf("%d dials for %d exchanges, want one target recorded per exchange", len(dialed), len(exchanges))
	}
	want := append([]string(nil), dialed...)
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(targets, want) {
		t.Errorf("recorded targets = %v, want every address the resolver dialed, %v", targets, want)
	}
}

// A target is recorded when DNS is dialed and never otherwise. Under the usual
// "hosts: files dns" ordering a name the hosts file answers costs no query, so
// the row has no resolver to name and must not invent one; this is also why the
// second-opinion lookup needs no hosts-file probe of its own to tell a local
// override from a real answer. It is only that ordering: see
// TestDNSProbeNeverCreditsTheOnlyResolverWithTheAnswer for the other one.
func TestLookupIPRecordsATargetOnlyWhenDNSIsDialed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var dials atomic.Int32
	ips, targets, err := lookupIPWithDial(ctx, "localhost", func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("no resolver is reachable in this test")
	})
	if (dials.Load() == 0) != (len(targets) == 0) {
		t.Fatalf("%d dials recorded targets %v; a target may only come from a dial", dials.Load(), targets)
	}
	// Where the hosts file answers, as it does wherever localhost is in it, the
	// lookup succeeded having contacted nothing.
	if dials.Load() == 0 && (err != nil || len(ips) == 0) {
		t.Fatalf("hosts-file answer = %v, %v; want addresses with no resolver contacted", ips, err)
	}
}

// DNS failure modes: resolver error and an empty (no A record) answer both
// fail with an actionable detail, never panic or pass.
func TestDNSProbeErrors(t *testing.T) {
	ops := &netops{lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
		return nil, []string{"192.168.1.1:53"}, errors.New("SERVFAIL")
	}}
	r := ops.dnsProbe("example.com", nil)(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "cannot resolve example.com (resolver tried: 192.168.1.1)") || r.Fix == "" {
		t.Errorf("lookup error = %+v, want FAIL naming the one resolver dialed, plus a fix", r)
	}

	ops.lookupIP = func(context.Context, string) ([]net.IP, []string, error) { return nil, nil, nil }
	r = ops.dnsProbe("example.com", nil)(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "no A/AAAA records") {
		t.Errorf("empty answer = %+v, want FAIL with 'no A/AAAA records'", r)
	}
}

// A resolver that goes quiet and comes back inside one run is resampled: the
// probe retries a timeout once and reports what the second query saw. NXDOMAIN
// is conclusive, so it costs exactly one query.
func TestDNSProbeRetriesTransientFailure(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}
	notFound := &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
	for _, tc := range []struct {
		name     string
		first    error
		want     Status
		attempts int
		targets  []string
	}{
		{"recovered resolver passes on the retry", timeout, StatusPass, 2, []string{"192.0.2.53:53", "198.51.100.53:53"}},
		{"down resolver still fails", timeout, StatusFail, 2, []string{"192.0.2.53:53", "198.51.100.53:53"}},
		{"nxdomain is not retried", notFound, StatusFail, 1, []string{"192.0.2.53:53"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			ops := &netops{lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
				attempts++
				target := "192.0.2.53:53"
				if attempts == 2 {
					target = "198.51.100.53:53"
				}
				if attempts == 1 || tc.want == StatusFail {
					return nil, []string{target}, tc.first
				}
				return []net.IP{net.ParseIP("192.0.2.1")}, []string{target}, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), DefaultProbeTimeout)
			defer cancel()
			r := ops.dnsProbe("example.com", nil)(ctx, nil)
			if r.Status != tc.want || attempts != tc.attempts {
				t.Errorf("status = %v after %d lookups, want %v after %d", r.Status, attempts, tc.want, tc.attempts)
			}
			if !slices.Equal(r.ResolverTargets, tc.targets) {
				t.Errorf("resolver targets = %v, want completed samples %v", r.ResolverTargets, tc.targets)
			}
		})
	}
}

// The second sample runs alongside the first query rather than in place of it,
// which is what lets both of these hold at once: a resolver that answers late
// but inside the budget keeps its answer, and one that is silent until it
// recovers mid-probe is still asked again in time to hear it.
func TestDNSProbeResamplesWithoutCuttingTheFirstQuery(t *testing.T) {
	for _, tc := range []struct {
		name string
		// answers is how long after the probe starts the resolver begins
		// answering; a query sent before then is never answered at all.
		answers time.Duration
		budget  time.Duration
	}{
		{"a late answer is waited out", 0, 500 * time.Millisecond},
		{"a resolver that recovers mid-probe is re-asked", 400 * time.Millisecond, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			start := time.Now()
			ops := &netops{lookupIP: func(ctx context.Context, _ string) ([]net.IP, []string, error) {
				attempts.Add(1)
				if time.Since(start) < tc.answers {
					<-ctx.Done() // sent too early to ever be answered
					return nil, nil, &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}
				}
				select {
				case <-time.After(300 * time.Millisecond):
					return []net.IP{net.ParseIP("192.0.2.1")}, nil, nil
				case <-ctx.Done():
					return nil, nil, &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true}
				}
			}}
			ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
			defer cancel()
			if r := ops.dnsProbe("example.com", nil)(ctx, nil); r.Status != StatusPass {
				t.Errorf("status = %v (%s) after %d lookups, want PASS", r.Status, r.Detail, attempts.Load())
			}
		})
	}
}

// The resample is bounded and borrows nothing. A resolver that answers costs
// exactly one query, so the common path pays nothing for the retry; a cancelled
// parent stops the probe at two queries rather than letting the retry outlive
// the context it was handed or wait out a budget that is already gone.
func TestDNSProbeResampleStaysInsideTheParentContext(t *testing.T) {
	answer := func(context.Context, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("192.0.2.1")}, nil, nil
	}
	for _, tc := range []struct {
		name     string
		lookup   func(context.Context, string) ([]net.IP, []string, error)
		cancel   bool
		want     Status
		attempts int32
	}{
		{"an answered query is not resampled", answer, false, StatusPass, 1},
		{"a cancelled parent stops at the one resample", func(ctx context.Context, _ string) ([]net.IP, []string, error) {
			// Bounded rather than a bare <-ctx.Done(): a query handed a context
			// detached from the parent would otherwise wedge here until the
			// suite timeout instead of failing on the assertions below.
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
				return []net.IP{net.ParseIP("192.0.2.1")}, nil, nil
			}
			return nil, nil, &net.DNSError{Err: ctx.Err().Error(), Name: "example.com"}
		}, true, StatusFail, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			var mu sync.Mutex
			var seen []context.Context
			ops := &netops{lookupIP: func(ctx context.Context, host string) ([]net.IP, []string, error) {
				attempts.Add(1)
				mu.Lock()
				seen = append(seen, ctx)
				mu.Unlock()
				return tc.lookup(ctx, host)
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			start := time.Now()
			r := ops.dnsProbe("example.com", nil)(ctx, nil)
			// Without a deadline the resample timer is DefaultProbeTimeout/2.
			// Returning well inside that is what proves the probe followed the
			// parent rather than waiting out a budget of its own.
			if elapsed := time.Since(start); tc.cancel && elapsed >= DefaultProbeTimeout/2 {
				t.Errorf("probe took %s after the parent was cancelled", elapsed)
			}
			if r.Status != tc.want || attempts.Load() != tc.attempts {
				t.Errorf("status = %v after %d lookups, want %v after %d", r.Status, attempts.Load(), tc.want, tc.attempts)
			}
			cancel()
			mu.Lock()
			defer mu.Unlock()
			for i, c := range seen {
				select {
				case <-c.Done():
				default:
					t.Errorf("query %d still holds a live context after the parent was cancelled", i+1)
				}
			}
		})
	}
}

// One resolver dialed is provenance and keeps the "via" the row has always
// read: nothing else was asked. Several are attempts and are named as such,
// sorted so the row is the same on every run. None is said as nothing at all.
func TestDNSProbeNamesResolverTargets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []string
		want    string
	}{
		{"standard port is bare", []string{"192.168.1.1:53"}, "example.com → 192.0.2.1 (resolver tried: 192.168.1.1)"},
		{"odd port is kept", []string{"127.0.0.1:5353"}, "example.com → 192.0.2.1 (resolver tried: 127.0.0.1:5353)"},
		{"IPv6 resolver", []string{"[2001:db8::1]:53"}, "example.com → 192.0.2.1 (resolver tried: 2001:db8::1)"},
		{"several are attempts too", []string{"192.0.2.53:53", "[2001:db8::53]:53"}, "example.com → 192.0.2.1 (resolvers tried: 192.0.2.53, 2001:db8::53)"},
		{"no DNS target omitted", nil, "example.com → 192.0.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &netops{lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
				return []net.IP{net.ParseIP("192.0.2.1")}, tc.targets, nil
			}}
			r := ops.dnsProbe("example.com", nil)(context.Background(), nil)
			if r.Status != StatusPass || r.Detail != tc.want {
				t.Errorf("detail = %q (%v), want %q", r.Detail, r.Status, tc.want)
			}
		})
	}
}

// One dialed target is not provenance either, so the row credits it with
// nothing. Go queries DNS before the hosts file wherever the host is configured
// "hosts: dns files", and reads the hosts file only when the queries came back
// with nothing (net/dnsclient_unix.go, goLookupIPCNAMEOrder). A lookup there can
// dial exactly one server, be answered by no server at all, and still return
// addresses, which is the case "via <server>" would have described wrongly. It
// cannot be built in process, because the ordering is read from the host's own
// nsswitch.conf, so what is pinned here is the claim the row is allowed to make.
func TestDNSProbeNeverCreditsTheOnlyResolverWithTheAnswer(t *testing.T) {
	ops := &netops{lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
		return []net.IP{net.ParseIP("192.0.2.1")}, []string{"192.0.2.53:53"}, nil
	}}
	r := ops.dnsProbe("example.com", nil)(context.Background(), nil)
	if !strings.Contains(r.Detail, "192.0.2.53") {
		t.Errorf("detail = %q, want the resolver the lookup dialed", r.Detail)
	}
	// "via" is the whole difference: it reads as "this answer came from there",
	// which no single Dial record establishes.
	if strings.Contains(r.Detail, "via") {
		t.Errorf("detail = %q, want the answer credited to no resolver", r.Detail)
	}
	if !strings.Contains(r.Detail, "tried") {
		t.Errorf("detail = %q, want one target reported as an attempt, as several are", r.Detail)
	}
}

func TestPublicDNSProbe(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
	for _, tc := range []struct {
		name    string
		ips     []net.IP
		targets []string
		err     error
		litIP   net.IP
		status  Status
		missing bool
	}{
		{"answer", []net.IP{net.ParseIP("192.0.2.1")}, []string{"8.8.8.8:53"}, nil, nil, StatusPass, false},
		{"nxdomain is evidence", nil, []string{"8.8.8.8:53"}, notFound, nil, StatusPass, true},
		{"unreachable is unavailable", nil, []string{"8.8.8.8:53"}, errors.New("network unreachable"), nil, StatusNA, false},
		{"hosts-file answer is not public DNS evidence", []net.IP{net.ParseIP("192.0.2.1")}, nil, nil, nil, StatusNA, false},
		{"a tried resolver does not make a hosts-file answer one", []net.IP{net.ParseIP("192.0.2.1")}, []string{"8.8.8.8:53"}, errHostsFileAnswer, nil, StatusNA, false},
		{"literal is not applicable", nil, nil, nil, net.ParseIP("192.0.2.2"), StatusNA, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			server := ""
			ops := &netops{lookupPublicIP: func(_ context.Context, _, srv string) ([]net.IP, []string, error) {
				called, server = true, srv
				return tc.ips, tc.targets, tc.err
			}}
			r := ops.publicDNSProbe("example.com", tc.litIP, []string{"8.8.8.8"})(context.Background(), nil)
			if called && server != "8.8.8.8:53" {
				t.Errorf("queried %q, want 8.8.8.8:53", server)
			}
			if r.Status != tc.status || r.DNSNotFound != tc.missing {
				t.Errorf("result = %+v, want status %s, not-found %v", r, tc.status, tc.missing)
			}
			if len(tc.targets) == 0 && (len(r.ResolverTargets) != 0 || strings.Contains(r.Detail, "via ")) {
				t.Errorf("result = %+v, claimed public DNS without a resolver Dial", r)
			}
			if tc.litIP != nil && called {
				t.Error("literal IP must not contact public DNS")
			}
		})
	}
}

// A PASS on the public row means an independent resolver answered, and the
// diagnosis spends it as exactly that: publicResolves promotes a system-DNS
// failure to system_dns_failure, contradicts dns_failure, and rules out
// dns_name_not_found. So the row may only carry Addrs it can prove came from
// the server, and a resolver target having been dialed proves nothing on its
// own: under "hosts: dns files" the Go resolver queries DNS first and reads the
// hosts file only when that came back empty, so a real dial to the public
// server can be followed by a local answer it never sent.
func TestPublicDNSNeedsMoreThanAResolverAttempt(t *testing.T) {
	ops := &netops{lookupPublicIP: func(context.Context, string, string) ([]net.IP, []string, error) {
		// What lookupIPPublicWithDial reports for the case above: the server was
		// dialed, and the answer that came back is not the server's.
		return []net.IP{net.ParseIP("198.51.100.77")}, []string{"8.8.8.8:53"}, errHostsFileAnswer
	}}
	r := ops.publicDNSProbe("example.com", nil, []string{"8.8.8.8"})(context.Background(), nil)
	if r.Status != StatusNA {
		t.Errorf("status = %s, want %s: an attempted resolver is not an answering one", r.Status, StatusNA)
	}
	// Addrs is the load-bearing field, not the prose: len(Addrs) > 0 is what
	// publicResolves and ObservationDNSAnswers both read.
	if len(r.Addrs) != 0 {
		t.Errorf("addrs = %v, want none: the public resolver did not supply them", r.Addrs)
	}
	if r.DNSNotFound {
		t.Error("DNSNotFound set: the public resolver reported nothing either way")
	}
	// The attempt evidence still belongs on the row; only the answer was unproven.
	if !slices.Equal(r.ResolverTargets, []string{"8.8.8.8:53"}) {
		t.Errorf("resolver targets = %v, want the dialed target kept as an attempt", r.ResolverTargets)
	}
	// N/A here is not the resolver being unreachable: it answered, or did not,
	// and this run cannot tell. Saying "unavailable" would send the reader after
	// an egress problem that the probe never observed.
	if strings.Contains(r.Detail, "unavailable") || strings.Contains(r.Detail, "via ") {
		t.Errorf("detail = %q, want the reason given as an unprovable answer, not an unreachable server", r.Detail)
	}
}

// answeredWithoutDNS is what separates the two. It resolves with every dial
// refused, so an answer that still comes back came from somewhere other than
// DNS, whichever side of the query this host reads its hosts file on.
func TestAnsweredWithoutDNSSeesOnlyNonDNSAnswers(t *testing.T) {
	ctx := context.Background()
	// A literal needs no name source at all, which is the same shape as a hosts
	// hit: an answer no query produced. Deterministic on every platform, unlike
	// an entry in the developer machine's own hosts file.
	if !answeredWithoutDNS(ctx, "127.0.0.1") {
		t.Error("an answer that needed no query was not recognized as one")
	}
	// .invalid is reserved as never resolvable, and no hosts file ships one.
	if answeredWithoutDNS(ctx, "no-such-name.invalid") {
		t.Error("a name nothing can answer was reported as answered without DNS")
	}
	// An expired budget must not read as "nothing to say": that would restore
	// the false PASS by the back door.
	expired, cancel := context.WithCancel(ctx)
	cancel()
	if !answeredWithoutDNS(expired, "127.0.0.1") {
		t.Error("a cancelled context suppressed a local answer that exists")
	}
}

// The guard lives in lookupIPPublicWithDial rather than in the probe, so no
// future caller of the public lookup can forget it.
func TestLookupIPPublicRefusesAnAnswerDNSDidNotSupply(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Error("the public lookup dialed for a name that needs no query")
		return nil, errors.New("must not dial")
	}
	ips, targets, err := lookupIPPublicWithDial(context.Background(), "127.0.0.1", dial, "8.8.8.8:53")
	if !errors.Is(err, errHostsFileAnswer) {
		t.Errorf("err = %v, want the answer refused as unprovable", err)
	}
	if len(ips) != 0 {
		t.Errorf("ips = %v, want none returned to be credited to the public resolver", ips)
	}
	if len(targets) != 0 {
		t.Errorf("targets = %v, want none: nothing was dialed", targets)
	}
}

// The egress probe diagnoses each family independently: IPv4 up + IPv6 down is
// a PASS that names the missing family; both down is a FAIL naming both.
func TestInternetProbeFamilies(t *testing.T) {
	v4only := &netops{
		dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "[") { // IPv6 endpoints are bracketed
				return nil, errors.New("no route to host")
			}
			return fakeConn{}, nil
		},
		interfaces: func() ([]net.Interface, error) { return nil, nil },
	}
	r := v4only.internetProbe(context.Background(), nil)
	if r.Status != StatusPass || !strings.Contains(r.Detail, "IPv4 egress via") || !strings.Contains(r.Detail, "no IPv6 egress") {
		t.Errorf("v4-only network = %+v, want PASS naming the missing IPv6 egress", r)
	}
	if r.Families == nil || r.Families.IPv4 != FamilyReachable || r.Families.IPv6 != FamilyUnreachable {
		t.Errorf("v4-only families = %+v", r.Families)
	}

	down := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no route to host")
		},
		interfaces: func() ([]net.Interface, error) { return nil, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r = down.internetProbe(ctx, nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "1.1.1.1") || !strings.Contains(r.Detail, "2606:4700:4700::1111") {
		t.Errorf("both families down = %+v, want FAIL naming endpoints from both families", r)
	}
	if r.Families == nil || r.Families.IPv4 != FamilyUnreachable || r.Families.IPv6 != FamilyUnreachable {
		t.Errorf("down families = %+v", r.Families)
	}
}

func TestInternetProbeAddsBackwardCompatibleRouteCause(t *testing.T) {
	called := false
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no route to host")
		},
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		// Sticky, because a host with no default route in either family is
		// asked about both: the contract this pins is that the first candidate
		// is classified, not that it is the only one classified.
		routeCause: func(destination net.IP) string {
			called = called || destination.Equal(net.ParseIP("1.1.1.1"))
			return RouteCauseNoDefaultRoute
		},
	}
	r := ops.internetProbe(context.Background(), nil)
	if r.Status != StatusFail || r.Cause != RouteCauseNoDefaultRoute || !called {
		t.Errorf("route-classified egress = %+v, called=%t", r, called)
	}
}

// TestInternetProbeClassifiesTheFamilyThatHasRoutes covers the machine the
// first candidate address misdescribes. Both families fail, the endpoint list
// leads with IPv4, and IPv4 has no default route because this host does not do
// IPv4: reading the cause off that table reports "no default route" to someone
// whose IPv6 defaults are present with a metric preference. That metadata
// calls for investigation, not an instruction to restore a missing route.
// The family with defaults of its own is the one asked.
func TestInternetProbeClassifiesTheFamilyThatHasRoutes(t *testing.T) {
	asked := map[string]string{}
	ops := &netops{routeCause: func(destination net.IP) string {
		if destination.To4() != nil {
			asked["ipv4"] = destination.String()
			return RouteCauseNoDefaultRoute
		}
		asked["ipv6"] = destination.String()
		return RouteCausePreferredPathFailed
	}}
	r, dialed := dialedNetworks(t, ops, map[string]bool{"tcp4": true, "tcp6": true})
	if r.Status != StatusFail || r.Cause != RouteCausePreferredPathFailed {
		t.Errorf("IPv6-only host with preferred route metadata = %+v, want %s", r, RouteCausePreferredPathFailed)
	}
	if dialed != "[tcp4 tcp6]" || asked["ipv4"] == "" || asked["ipv6"] == "" {
		t.Errorf("dialed %s, classifier saw %v: both families are still tried and still asked", dialed, asked)
	}
	if fix := routeFix(r.Cause); !strings.Contains(fix, "test each path before changing preference") {
		t.Errorf("fix hint = %q, want advice to measure paths before changing preference", fix)
	}

	// The other family having nothing to say leaves the original verdict
	// alone, which is what keeps a genuinely routeless host reported as one.
	both := &netops{routeCause: func(net.IP) string { return RouteCauseNoDefaultRoute }}
	if r, _ := dialedNetworks(t, both, map[string]bool{"tcp4": true, "tcp6": true}); r.Cause != RouteCauseNoDefaultRoute {
		t.Errorf("no defaults in either family = %+v, want %s", r, RouteCauseNoDefaultRoute)
	}
}

// Same dial outcome, two verdicts: a v4-only network passes, but a machine
// holding a global IPv6 address with no IPv6 egress is black-holed and warns.
func TestInternetProbeBlackHoledIPv6(t *testing.T) {
	blackholed := &netops{
		dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "[") {
				return nil, errors.New("connection timed out")
			}
			return fakeConn{}, nil
		},
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("fe80::1")},     // link-local doesn't count
				&net.IPNet{IP: net.ParseIP("2001:db8::1")}, // this does
			}, nil
		},
	}
	r := blackholed.internetProbe(context.Background(), nil)
	if r.Status != StatusWarn || r.Cause != FamilyCauseIPv6Unreachable || !strings.Contains(r.Detail, "black-holed") {
		t.Errorf("black-holed IPv6 = %+v, want WARN naming it", r)
	}

	linkLocalOnly := *blackholed
	linkLocalOnly.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1")}}, nil
	}
	if r := linkLocalOnly.internetProbe(context.Background(), nil); r.Status != StatusPass {
		t.Errorf("v4-only network = %+v, want PASS: no global IPv6 means nothing is broken", r)
	}

	ulaOnly := *blackholed
	ulaOnly.interfaceAddrs = func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("fd00::1")}}, nil
	}
	if r := ulaOnly.internetProbe(context.Background(), nil); r.Status != StatusPass {
		t.Errorf("ULA-only network = %+v, want PASS: fc00::/7 was never meant to reach the internet", r)
	}
}

func TestInternetProbeBlackHoledIPv4WithWorkingIPv6(t *testing.T) {
	ops := &netops{
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network == "tcp4" {
				return nil, errors.New("connection timed out")
			}
			return fakeConn{}, nil
		},
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "eth0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("10.77.0.10"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
	r := ops.internetProbe(context.Background(), nil)
	if r.Status != StatusWarn || r.Cause != FamilyCauseIPv4Unreachable || r.Families == nil ||
		r.Families.IPv4 != FamilyUnreachable || r.Families.IPv6 != FamilyReachable {
		t.Errorf("black-holed IPv4 = %+v", r)
	}
}

// dialedNetworks runs the egress probe against a dial stub that always
// succeeds and reports which address families it was actually asked to dial.
// Success everywhere is the point: what the probe declines to attempt is then
// the only thing separating the cases.
func dialedNetworks(t *testing.T, ops *netops, fail map[string]bool) (ProbeResult, string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]bool{}
	ops.interfaces = func() ([]net.Interface, error) { return nil, nil }
	ops.dialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		mu.Lock()
		seen[network] = true
		mu.Unlock()
		if fail[network] {
			return nil, errors.New("no route to host")
		}
		return fakeConn{}, nil
	}
	r := ops.internetProbe(context.Background(), nil)
	// TCP only: the probe also dials UDP to learn the source address of a
	// failed path, which is not an egress attempt against an endpoint.
	networks := make([]string, 0, len(seen))
	for network := range seen {
		if strings.HasPrefix(network, "tcp") {
			networks = append(networks, network)
		}
	}
	sort.Strings(networks)
	return r, fmt.Sprint(networks)
}

// --iface binds probe traffic to one interface's addresses, so an interface
// holding no address of a family cannot test that family at all. Dialing it
// anyway only proves the bind is impossible, and reporting that as
// FamilyUnreachable accuses the network of an outage nobody measured. The
// incompatible family has to be dropped before the dial, the way the QUIC and
// encrypted-DNS rows already drop theirs.
func TestInternetProbeSkipsFamiliesTheSelectedSourceCannotDial(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")
	for _, tc := range []struct {
		name     string
		sources  *SourceAddresses
		want4    string
		want6    string
		wantDial string
	}{
		{name: "unrestricted source tests both families", sources: nil,
			want4: FamilyReachable, want6: FamilyReachable, wantDial: "[tcp4 tcp6]"},
		{name: "dual-stack interface tests both families", sources: &SourceAddresses{IPv4: v4, IPv6: v6, Iface: "eth0"},
			want4: FamilyReachable, want6: FamilyReachable, wantDial: "[tcp4 tcp6]"},
		{name: "IPv4-only interface never dials IPv6", sources: &SourceAddresses{IPv4: v4, Iface: "eth0"},
			want4: FamilyReachable, want6: "", wantDial: "[tcp4]"},
		{name: "IPv6-only interface never dials IPv4", sources: &SourceAddresses{IPv6: v6, Iface: "eth0"},
			want4: "", want6: FamilyReachable, wantDial: "[tcp6]"},
		// An exact local IP sets only its own family, so it reaches this path
		// through the same struct an interface name does.
		{name: "IPv4 literal source never dials IPv6", sources: &SourceAddresses{IPv4: v4},
			want4: FamilyReachable, want6: "", wantDial: "[tcp4]"},
		{name: "IPv6 literal source never dials IPv4", sources: &SourceAddresses{IPv6: v6},
			want4: "", want6: FamilyReachable, wantDial: "[tcp6]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, dialed := dialedNetworks(t, &netops{sources: tc.sources}, nil)
			if dialed != tc.wantDial {
				t.Errorf("dialed %s, want %s: an incompatible family must not be attempted", dialed, tc.wantDial)
			}
			if r.Status != StatusPass {
				t.Errorf("status = %s, want PASS: %s", r.Status, r.Detail)
			}
			if r.Families == nil || r.Families.IPv4 != tc.want4 || r.Families.IPv6 != tc.want6 {
				t.Fatalf("families = %+v, want IPv4 %q IPv6 %q", r.Families, tc.want4, tc.want6)
			}
			// "no IPv6 egress" is a claim about the network. A family that was
			// never dialed has earned no such claim.
			for family, state := range map[string]string{"IPv4": tc.want4, "IPv6": tc.want6} {
				if state == "" && strings.Contains(r.Detail, "no "+family+" egress") {
					t.Errorf("detail = %q, must not report %s egress it never tested", r.Detail, family)
				}
			}
		})
	}
}

// The other half of the invariant: a family the selected source can dial is
// judged exactly as before, and only the families actually attempted appear in
// the failure text.
func TestInternetProbeStillFailsFamiliesTheSelectedSourceCanDial(t *testing.T) {
	v4, v6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")

	var routed net.IP
	ops := &netops{sources: &SourceAddresses{IPv4: v4, Iface: "eth0"},
		routeCause: func(destination net.IP) string { routed = destination; return RouteCauseNoDefaultRoute }}
	r, dialed := dialedNetworks(t, ops, map[string]bool{"tcp4": true})
	if r.Status != StatusFail || r.Cause != RouteCauseNoDefaultRoute || !routed.Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("IPv4-only interface with dead IPv4 = %+v, routeCause saw %v, want the unchanged FAIL", r, routed)
	}
	if r.Families == nil || r.Families.IPv4 != FamilyUnreachable || r.Families.IPv6 != "" {
		t.Errorf("families = %+v, want IPv4 unreachable and IPv6 untested", r.Families)
	}
	if dialed != "[tcp4]" || strings.Contains(r.Detail, "2606:4700:4700::1111") {
		t.Errorf("dialed %s, detail = %q: the failure must name only endpoints it tried", dialed, r.Detail)
	}

	// A dual-stack selection has both families available, so one of them going
	// down is a real partial outage and must keep saying so.
	partial := &netops{sources: &SourceAddresses{IPv4: v4, IPv6: v6, Iface: "eth0"}}
	r, dialed = dialedNetworks(t, partial, map[string]bool{"tcp6": true})
	if r.Status != StatusWarn || r.Cause != FamilyCauseIPv6Unreachable || r.Families == nil ||
		r.Families.IPv4 != FamilyReachable || r.Families.IPv6 != FamilyUnreachable {
		t.Errorf("dual-stack with dead IPv6 = %+v, families %+v, want the unchanged black-hole WARN", r, r.Families)
	}
	if dialed != "[tcp4 tcp6]" || !strings.Contains(r.Detail, "no IPv6 egress") {
		t.Errorf("dialed %s, detail = %q: an available family that fails is still unreachable", dialed, r.Detail)
	}
}

func TestDialIPsConstrainsAddressFamily(t *testing.T) {
	var networks []string
	var mu sync.Mutex
	ops := &netops{dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
		mu.Lock()
		networks = append(networks, network)
		mu.Unlock()
		return nil, errors.New("refused")
	}}
	_, _, _, _ = ops.dialIPs(context.Background(), []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, 443)
	sort.Strings(networks)
	if fmt.Sprint(networks) != "[tcp4 tcp6]" {
		t.Errorf("networks = %v", networks)
	}
}

// portalAnswers stubs netops.portalCheck with one canned observation per fixed
// endpoint, in portalEndpoints order. A nil entry is an endpoint that did not
// answer at all, which is what an unreachable auxiliary service looks like.
func portalAnswers(t *testing.T, answers ...*portalObservation) func(context.Context, portalEndpoint) (portalObservation, error) {
	t.Helper()
	if len(answers) != len(portalEndpoints) {
		t.Fatalf("portalAnswers got %d answers for %d fixed endpoints", len(answers), len(portalEndpoints))
	}
	return func(_ context.Context, ep portalEndpoint) (portalObservation, error) {
		for i, candidate := range portalEndpoints {
			if candidate.url == ep.url {
				if answers[i] == nil {
					return portalObservation{}, errors.New("no route to host")
				}
				return *answers[i], nil
			}
		}
		t.Errorf("probe asked an endpoint that is not in the fixed set: %q", ep.url)
		return portalObservation{}, errors.New("unknown endpoint")
	}
}

// cleanAnswer is an endpoint answering exactly what it documents; seenAnswer is
// one answering something else. portalCheckWithDial decides which is which from
// a real response, and TestPortalCheck proves that rule; these two are how the
// inference above it is stated.
func cleanAnswer(code int) *portalObservation { return &portalObservation{clean: true, code: code} }

func seenAnswer(code int, redirect string) *portalObservation {
	return &portalObservation{code: code, redirect: redirect}
}

// The inference boundary, as the matrix of what the two independently operated
// connectivity endpoints can say. One provider answering unexpectedly is a fact
// about that provider: a block aimed at its name, its own outage, or a hijacked
// DNS answer all look exactly like a portal from here. Only corroboration, both
// endpoints intercepted on one pass, carries the captive-portal claim.
func TestInternetProbePortalCorroboration(t *testing.T) {
	dialOK := func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }
	ifaces := func() ([]net.Interface, error) { return nil, nil }
	const signin = "https://portal.example/signin"

	cases := []struct {
		name         string
		google, ncsi *portalObservation
		want         Status
		wantPortal   bool
		wantRedirect string
	}{
		{name: "both clean", google: cleanAnswer(204), ncsi: cleanAnswer(200), want: StatusPass},
		{
			name: "both intercepted", google: seenAnswer(302, signin), ncsi: seenAnswer(302, "https://portal.example/other"),
			want: StatusFail, wantPortal: true, wantRedirect: signin,
		},
		{name: "google intercepted, other clean", google: seenAnswer(302, signin), ncsi: cleanAnswer(200), want: StatusWarn},
		// A 200 with the wrong payload is exactly the filter page this endpoint
		// exists to catch, and on its own it still proves nothing.
		{name: "google clean, other intercepted", google: cleanAnswer(204), ncsi: seenAnswer(200, ""), want: StatusWarn},
		{name: "google intercepted, other unavailable", google: seenAnswer(302, signin), ncsi: nil, want: StatusWarn},
		{name: "other intercepted, google unavailable", google: nil, ncsi: seenAnswer(302, signin), want: StatusWarn},
		{name: "google clean, other unavailable", google: cleanAnswer(204), ncsi: nil, want: StatusPass},
		{name: "other clean, google unavailable", google: nil, ncsi: cleanAnswer(200), want: StatusPass},
		{name: "both unavailable", want: StatusPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &netops{dialContext: dialOK, interfaces: ifaces, portalCheck: portalAnswers(t, c.google, c.ncsi)}
			r := o.internetProbe(context.Background(), nil)
			if r.Status != c.want {
				t.Errorf("status = %v, want %v (detail %q)", r.Status, c.want, r.Detail)
			}
			if (r.Portal != nil) != c.wantPortal {
				t.Fatalf("portal evidence = %+v, want present=%v", r.Portal, c.wantPortal)
			}
			if c.wantPortal {
				if r.Portal.RedirectURL != c.wantRedirect {
					t.Errorf("redirect = %q, want %q", r.Portal.RedirectURL, c.wantRedirect)
				}
				if !strings.Contains(r.Detail, "intercepted") || r.Fix == "" {
					t.Errorf("corroborated interception = detail %q fix %q", r.Detail, r.Fix)
				}
				return
			}
			// Nothing but corroboration may name a portal, and a lone
			// discrepancy still names no cause for itself: the only cause it
			// may record is the neutral one that says a connectivity endpoint
			// answered unexpectedly, which is the observation the row already
			// reports in prose and nothing more.
			wantCause := ""
			if c.want == StatusWarn {
				wantCause = ConnectivityCauseUnexpectedResponse
			}
			if r.Cause != wantCause {
				t.Errorf("cause = %q, want %q: one endpoint is not a diagnosis", r.Cause, wantCause)
			}
			if c.want == StatusWarn && !strings.Contains(r.Detail, "answered unexpectedly") {
				t.Errorf("detail = %q, want the observation named", r.Detail)
			}
			if c.want == StatusPass && strings.Contains(r.Detail, "unexpected") {
				t.Errorf("detail = %q, want no discrepancy reported", r.Detail)
			}
			// The row stays usable evidence of egress, so a single discrepant
			// provider cannot turn a working network into a failure.
			if !directEgressOK(map[ProbeID]ProbeResult{ProbeInternet: r}) {
				t.Errorf("direct egress read as broken from %+v", r)
			}
		})
	}
}

// The same matrix carried up to the verdict: the diagnosis a single discrepant
// provider produces is never the captive-portal one, and the corroborated pair
// still is.
func TestPortalDiagnosisNeedsCorroboration(t *testing.T) {
	dialOK := func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }
	ifaces := func() ([]net.Interface, error) { return nil, nil }
	const signin = "https://portal.example/signin"
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}

	cases := []struct {
		name         string
		google, ncsi *portalObservation
		wantPortal   bool
	}{
		{name: "corroborated", google: seenAnswer(302, signin), ncsi: seenAnswer(302, signin), wantPortal: true},
		{name: "google alone", google: seenAnswer(302, signin), ncsi: cleanAnswer(200)},
		{name: "other alone", google: cleanAnswer(204), ncsi: seenAnswer(200, "")},
		{name: "google alone, other unavailable", google: seenAnswer(302, signin)},
		{name: "both clean", google: cleanAnswer(204), ncsi: cleanAnswer(200)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &netops{dialContext: dialOK, interfaces: ifaces, portalCheck: portalAnswers(t, c.google, c.ncsi)}
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {ID: ProbeIface, Status: StatusPass},
				ProbeInternet: o.internetProbe(context.Background(), nil),
				ProbeDNS:      {ID: ProbeDNS, Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
			}
			res[ProbeInternet] = ProbeResult{ID: ProbeInternet, Status: res[ProbeInternet].Status,
				Detail: res[ProbeInternet].Detail, Portal: res[ProbeInternet].Portal, Families: res[ProbeInternet].Families}
			d := Interpret(nil, order, res)
			portal := false
			for _, f := range d.Findings {
				if f.ID == DiagnosisCaptivePortal {
					portal = true
				}
			}
			if portal != c.wantPortal {
				t.Errorf("captive-portal finding = %v, want %v (summary %q)", portal, c.wantPortal, d.Summary)
			}
		})
	}
}

// A network whose TCP handshakes all succeed is still not online when both
// endpoints come back as something else: that's a portal answering for it.
func TestInternetProbeCaptivePortal(t *testing.T) {
	dialOK := func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }
	ifaces := func() ([]net.Interface, error) { return nil, nil }
	const signin = "https://portal.example/signin"
	both := func(o *portalObservation) []*portalObservation { return []*portalObservation{o, o} }

	portal := &netops{
		dialContext: dialOK, interfaces: ifaces,
		portalCheck: portalAnswers(t, both(seenAnswer(http.StatusFound, signin))...),
	}
	r := portal.internetProbe(context.Background(), nil)
	if r.Status != StatusFail || r.Portal == nil || r.Portal.RedirectURL != signin ||
		r.Fix == "" || !strings.Contains(r.Detail, "intercepted") {
		t.Errorf("portal network = %+v, want FAIL flagged as a portal with a fix", r)
	}
	// And the exemption holds: DNS answering must not launder it into a Warn.
	res := map[ProbeID]ProbeResult{ProbeInternet: r, ProbeDNS: {Status: StatusPass}}
	downgradeEgress(res)
	if res[ProbeInternet].Status != StatusFail {
		t.Errorf("downgraded portal to %v, want FAIL to survive a passing DNS", res[ProbeInternet].Status)
	}

	// An interception that advertises nothing is still an interception, and the
	// retained URL comes from the first endpoint that offered one, whichever
	// request happened to finish first.
	noRedirect := &netops{
		dialContext: dialOK, interfaces: ifaces,
		portalCheck: portalAnswers(t, seenAnswer(http.StatusOK, ""), seenAnswer(http.StatusOK, "")),
	}
	if r := noRedirect.internetProbe(context.Background(), nil); r.Status != StatusFail ||
		r.Portal == nil || r.Portal.RedirectURL != "" {
		t.Errorf("non-redirect interception = %+v, want portal evidence without a URL", r)
	}
	trailing := &netops{
		dialContext: dialOK, interfaces: ifaces,
		portalCheck: portalAnswers(t, seenAnswer(http.StatusOK, ""), seenAnswer(http.StatusFound, signin)),
	}
	if r := trailing.internetProbe(context.Background(), nil); r.Portal == nil || r.Portal.RedirectURL != signin {
		t.Errorf("second-endpoint redirect = %+v, want it retained", r.Portal)
	}

	// Portals that drop 443 entirely still answer plain HTTP; the evidence
	// must survive having no handshake to attach it to.
	dead := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	blocked443 := &netops{
		dialContext: dead, interfaces: ifaces,
		portalCheck: portalAnswers(t, both(seenAnswer(http.StatusFound, signin))...),
	}
	if r := blocked443.internetProbe(context.Background(), nil); r.Status != StatusFail ||
		r.Portal == nil || r.Portal.RedirectURL != signin || !strings.Contains(r.Fix, "sign in") {
		t.Errorf("portal blocking 443 = %+v, want portal evidence, not a bare no-egress verdict", r)
	}
	// The same dead path with one endpoint discrepant is a dead path, not a
	// portal: the observation is recorded and nothing is concluded from it.
	oneEndpoint := &netops{
		dialContext: dead, interfaces: ifaces,
		portalCheck: portalAnswers(t, seenAnswer(http.StatusFound, signin), cleanAnswer(200)),
	}
	if r := oneEndpoint.internetProbe(context.Background(), nil); r.Status != StatusFail || r.Portal != nil ||
		strings.Contains(r.Fix, "sign in") || !strings.Contains(r.Detail, "answered unexpectedly") {
		t.Errorf("one discrepant endpoint on a dead path = %+v, want no portal claim", r)
	}

	// Unreachable checks are not evidence of a portal, so the dial result stands.
	broken := &netops{dialContext: dialOK, interfaces: ifaces, portalCheck: portalAnswers(t, nil, nil)}
	if r := broken.internetProbe(context.Background(), nil); r.Status != StatusPass || r.Portal != nil {
		t.Errorf("failed checks = %+v, want the TCP verdict to stand", r)
	}
}

// Two observations, one probe budget. No check here answers until every check
// has started, so an executor that ran them one after the other would let the
// first spend the whole context and come back with nothing: only an overlapping
// run collects an answer from both.
func TestInternetProbeChecksEndpointsConcurrently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered := make(chan struct{}, len(portalEndpoints))
	all := make(chan struct{})
	go func() {
		for range portalEndpoints {
			<-entered
		}
		close(all)
	}()
	var answered atomic.Int32
	o := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil },
		interfaces:  func() ([]net.Interface, error) { return nil, nil },
		portalCheck: func(ctx context.Context, ep portalEndpoint) (portalObservation, error) {
			entered <- struct{}{}
			select {
			case <-all:
				answered.Add(1)
				return portalObservation{clean: true, code: ep.want}, nil
			case <-ctx.Done():
				return portalObservation{}, ctx.Err()
			}
		},
	}
	r := o.internetProbe(ctx, nil)
	if got, want := int(answered.Load()), len(portalEndpoints); got != want {
		t.Fatalf("%d of %d endpoint checks were in flight at once; they ran serially", got, want)
	}
	if r.Status != StatusPass || r.Portal != nil {
		t.Errorf("probe = %+v, want a plain PASS", r)
	}
}

// The parent deadline bounds the pair: neither observation gets a budget of its
// own, and an endpoint that never answers cannot outlive the probe.
func TestInternetProbeEndpointChecksHonorContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	o := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil },
		interfaces:  func() ([]net.Interface, error) { return nil, nil },
		portalCheck: func(ctx context.Context, _ portalEndpoint) (portalObservation, error) {
			<-ctx.Done()
			return portalObservation{}, ctx.Err()
		},
	}
	done := make(chan ProbeResult, 1)
	go func() { done <- o.internetProbe(ctx, nil) }()
	select {
	case r := <-done:
		if r.Portal != nil {
			t.Errorf("expired checks produced portal evidence: %+v", r.Portal)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the probe outlived its context")
	}
}

// A TLS handshake error is a FAIL with the cleaned error in the detail and a
// fix hint, not a panic and not a skip.
func TestTLSProbeHandshakeFailure(t *testing.T) {
	ops := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("x509: certificate has expired")
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}

	r := ops.tlsProbe("example.com", 443, nil)(context.Background(), deps)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "TLS check to 192.0.2.1 failed") ||
		!strings.Contains(r.Detail, "certificate has expired") || r.Fix == "" {
		t.Errorf("handshake failure = %+v, want FAIL with error detail and a fix", r)
	}
}

func TestTLSProbeClassifiesStructuredFailures(t *testing.T) {
	now := time.Date(2030, 6, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		DNSNames:  []string{"secure-target.test"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	tests := []struct {
		name  string
		err   error
		cause string
	}{
		{"expired", x509.CertificateInvalidError{Cert: &x509.Certificate{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)}, Reason: x509.Expired}, TLSCauseCertificateExpired},
		{"not yet valid", x509.CertificateInvalidError{Cert: &x509.Certificate{NotBefore: now.Add(24 * time.Hour), NotAfter: now.Add(48 * time.Hour)}, Reason: x509.Expired}, TLSCauseCertificateNotYet},
		{"hostname", x509.HostnameError{Certificate: leaf, Host: "wrong.test"}, TLSCauseHostnameMismatch},
		{"unknown issuer", x509.UnknownAuthorityError{Cert: leaf}, TLSCauseUntrustedIssuer},
		{"timeout", context.DeadlineExceeded, TLSCauseTimeout},
		{"closed", io.ErrUnexpectedEOF, TLSCauseConnectionClosed},
		{"reset", syscall.ECONNRESET, TLSCauseConnectionClosed},
		{"refused", syscall.ECONNREFUSED, TLSCauseTCPUnreachable},
		{"protocol", tls.RecordHeaderError{Msg: "not TLS"}, TLSCauseHandshake},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, err := range []error{tc.err, fmt.Errorf("wrapped TLS failure: %w", tc.err)} {
				if got := tlsFailureCause(err, now); got != tc.cause {
					t.Errorf("tlsFailureCause(%T) = %q, want %q", tc.err, got, tc.cause)
				}
			}
		})
	}
}

func TestTLSProbeIncludesBackwardCompatibleCause(t *testing.T) {
	now := time.Now()
	errExpired := x509.CertificateInvalidError{
		Cert:   &x509.Certificate{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-24 * time.Hour)},
		Reason: x509.Expired,
	}
	ops := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return nil, fmt.Errorf("verify peer: %w", errExpired)
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	r := ops.tlsProbe("secure-target.test", 443, nil)(context.Background(), deps)
	if r.Status != StatusFail || r.Cause != TLSCauseCertificateExpired ||
		!strings.HasPrefix(r.Detail, "TLS check to 192.0.2.1 failed:") || r.Fix == "" {
		t.Fatalf("TLS result = %+v", r)
	}
}

func TestTLSProbeTimeoutReportsMTU(t *testing.T) {
	ops := &netops{
		dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			return nil, context.DeadlineExceeded
		},
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0", MTU: 1420}}, nil
		},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {
		SelectedIP: net.ParseIP("192.0.2.1"),
		Iface:      "fake0",
	}}

	r := ops.tlsProbe("example.com", 443, nil)(context.Background(), deps)
	if !strings.Contains(r.Detail, "fake0 MTU is 1420") ||
		!strings.Contains(r.Fix, "Path MTU row") || r.Cause != TLSCauseTimeout {
		t.Errorf("TLS timeout = %+v, want MTU detail and a pointer at the PMTU row", r)
	}
}

// pmtuTestBudget is the probe budget the stall cases run under. The probe
// derives its write deadline as budget minus pmtuHeadroom, so this same figure
// is how long a descheduled goroutine may sit between the deadline being set
// here and the probe reading it back before the probe gives up with "not enough
// of the probe budget left" instead of measuring the stall under test. The
// stall cases wait it out, so it buys loaded-runner margin at its own cost.
const pmtuTestBudget = pmtuHeadroom + time.Second

// The PMTU probe reads one asymmetry: a payload that must travel as full-size
// segments either drains the (deliberately small) send buffer or stalls in it.
// net.Pipe has no send queue to read, so these are the cases as they look on a
// platform without queue accounting: a stall is the black-hole evidence and
// never more than a WARN; a write the far end took proves only that something
// local took it; a peer that hangs up says nothing either way. net.Pipe stands
// in for the socket, since its writes block until the far end reads, which is
// exactly the behavior being classified.
func TestPMTUProbeClassifiesWrite(t *testing.T) {
	tests := []struct {
		name   string
		serve  func(net.Conn) // runs against the far end of the pipe
		status Status
		detail string
		fix    bool
	}{
		{
			name:   "nothing acknowledged",
			serve:  func(net.Conn) {}, // a black hole: our segments never land
			status: StatusWarn,
			detail: "stalled after 0 KiB of 24 KiB without draining the measured 4 KiB TCP send buffer",
			fix:    true,
		},
		{
			// A goroutine reading the far end of a pipe is not a path. With no
			// send queue to read, nothing here separates that from a kernel
			// that swallowed the write and sent none of it, so the row reports
			// what it could not establish rather than clearing the path.
			name:   "write accepted, delivery unmeasurable",
			serve:  func(c net.Conn) { _, _ = io.Copy(io.Discard, c) },
			status: StatusNA,
			detail: "path-MTU delivery could not be verified",
		},
		{
			name: "peer hangs up",
			// Take a byte before hanging up: the read blocks until the probe's
			// Write, so the close lands during the write rather than racing the
			// setup that precedes it.
			serve:  func(c net.Conn) { _, _ = c.Read(make([]byte, 1)); _ = c.Close() },
			status: StatusNA,
			detail: "inconclusive; the peer dropped the connection after 0 KiB",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			go tc.serve(server)
			ops := &netops{
				dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
				interfaces:  func() ([]net.Interface, error) { return []net.Interface{{Name: "wg0", MTU: 1420}}, nil },
				sendBuffer:  func(net.Conn) (int, error) { return pmtuSendBuffer, nil },
				tcpMSS:      func(net.Conn) (int, error) { return 1380, nil },
			}
			deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1"), Iface: "wg0"}}
			// Short budget so the stall case doesn't wait out pmtuWriteWait.
			ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
			defer cancel()

			r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps)
			if r.Status != tc.status || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("pmtu = %+v, want %v containing %q", r, tc.status, tc.detail)
			}
			if (r.Fix != "") != tc.fix {
				t.Errorf("pmtu fix = %q, want present: %v", r.Fix, tc.fix)
			}
			if !r.SelectedIP.Equal(net.ParseIP("192.0.2.1")) {
				t.Errorf("SelectedIP = %v, want the pinned dependency IP", r.SelectedIP)
			}
		})
	}
}

// The evidence has to name the interface MTU it contradicts, since that number is
// what turns "something is dropping packets" into a value to lower.
func TestPMTUProbeWarnNamesInterfaceMTU(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
		interfaces:  func() ([]net.Interface, error) { return []net.Interface{{Name: "wg0", MTU: 1420}}, nil },
		sendBuffer:  func(net.Conn) (int, error) { return pmtuSendBuffer, nil },
		tcpMSS:      func(net.Conn) (int, error) { return 1380, nil },
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1"), Iface: "wg0"}}
	ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
	defer cancel()

	if r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps); !strings.Contains(r.Detail, "wg0 advertises a 1420-byte MTU") {
		t.Errorf("pmtu detail = %q, want the interface MTU named", r.Detail)
	}
	// An unreadable MTU costs the note, not the verdict.
	ops.interfaces = func() ([]net.Interface, error) { return nil, errors.New("nope") }
	client2, server2 := net.Pipe()
	t.Cleanup(func() { _ = server2.Close() })
	ops.dialContext = func(context.Context, string, string) (net.Conn, error) { return client2, nil }
	ctx2, cancel2 := context.WithTimeout(context.Background(), pmtuTestBudget)
	defer cancel2()
	if r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx2, deps); r.Status != StatusWarn || strings.Contains(r.Detail, "advertises") {
		t.Errorf("pmtu without a readable MTU = %+v, want WARN with no MTU note", r)
	}
}

func TestPMTUProbeSkipsWithoutPinnedIP(t *testing.T) {
	r := new(netops).pmtuProbe(443, ProtoTLSHTTP)(context.Background(), map[ProbeID]ProbeResult{})
	if r.Status != StatusSkip {
		t.Errorf("pmtu without a pinned IP = %+v, want SKIP", r)
	}
}

func TestPMTUProbeDeclinesUnmeasurableSendBuffer(t *testing.T) {
	tests := []struct {
		name   string
		buffer func(net.Conn) (int, error)
		detail string
	}{
		{
			name: "socket option unavailable",
			buffer: func(net.Conn) (int, error) {
				return 0, errors.New("unsupported")
			},
			detail: "cannot read the effective TCP send buffer",
		},
		{
			name: "kernel buffer holds payload",
			buffer: func(net.Conn) (int, error) {
				return pmtuPayloadSize, nil
			},
			detail: "large enough to hold the whole probe locally",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			ops := &netops{
				dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
				sendBuffer:  tc.buffer,
			}
			deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
			r := ops.pmtuProbe(443, ProtoTLSHTTP)(context.Background(), deps)
			if r.Status != StatusNA || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("pmtu = %+v, want N/A containing %q", r, tc.detail)
			}
		})
	}
}

// resetWriteConn takes half the payload and then reports the peer's reset, the
// way a real socket does when the far end goes away mid-write.
type resetWriteConn struct{ fakeConn }

func (resetWriteConn) Write(b []byte) (int, error) {
	return len(b) / 2, fmt.Errorf("wrapped write: %w", syscall.ECONNRESET)
}
func (resetWriteConn) SetWriteDeadline(time.Time) error { return nil }

// Where a platform can account for its send queue, the verdict comes from what
// the peer acknowledged and never from the write returning. The distinction is
// the whole probe on Linux, where a socket reporting an 8 KiB send buffer still
// swallows a 24 KiB write with nothing on the wire.
func TestPMTUProbeClassifiesByAcknowledgement(t *testing.T) {
	// A far end that drains the pipe, so every case below gets the same
	// complete, successful Write and can only be told apart by the queue.
	tests := []struct {
		name   string
		queued func(net.Conn) (int, error)
		status Status
		detail string
		fix    bool
	}{
		{
			// The regression: the old logic saw a 24 KiB write accepted past an
			// 8 KiB send buffer and called it PASS. Nothing was acknowledged.
			name:   "write accepted but nothing acknowledged",
			queued: func(net.Conn) (int, error) { return pmtuPayloadSize, nil },
			status: StatusWarn,
			detail: "24 KiB written, none of it acknowledged within",
			fix:    true,
		},
		{
			name:   "payload acknowledged",
			queued: func(net.Conn) (int, error) { return 0, nil },
			status: StatusPass,
			detail: "24 KiB of the 24 KiB payload acknowledged by the peer",
		},
		{
			// Forward progress is forward progress: a full-size segment landed,
			// so the path carries them even with a tail still in flight.
			name:   "still draining at the deadline",
			queued: func(net.Conn) (int, error) { return pmtuPayloadSize - 4096, nil },
			status: StatusPass,
			detail: "4 KiB of the 24 KiB payload acknowledged by the peer",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			go func() { _, _ = io.Copy(io.Discard, server) }()
			ops := &netops{
				dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
				// The doubled value Linux hands back for a 4 KiB request, and
				// comfortably less than the payload: the old inference had
				// everything it wanted and still got this wrong.
				sendBuffer: func(net.Conn) (int, error) { return 2 * pmtuSendBuffer, nil },
				tcpMSS:     func(net.Conn) (int, error) { return 1448, nil },
				queued:     tc.queued,
			}
			deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
			ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
			defer cancel()

			r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps)
			if r.Status != tc.status || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("pmtu = %+v, want %v containing %q", r, tc.status, tc.detail)
			}
			if (r.Fix != "") != tc.fix {
				t.Errorf("pmtu fix = %q, want present: %v", r.Fix, tc.fix)
			}
			// The row reports what it measured. Naming the black hole outright
			// is reconciliation's job, once an independent probe agrees.
			if tc.status == StatusWarn && !strings.Contains(r.Detail, "consistent with a path-MTU black hole") {
				t.Errorf("pmtu detail = %q, want hedged black-hole wording", r.Detail)
			}
		})
	}
}

// A healthy path acknowledges nothing at the instant Write returns, because the bytes
// are still in flight. The probe has to wait out that latency instead of
// reading the queue once and calling a working link a black hole.
func TestPMTUProbeWaitsForAcknowledgement(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()
	var samples int
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
		sendBuffer:  func(net.Conn) (int, error) { return 2 * pmtuSendBuffer, nil },
		queued: func(net.Conn) (int, error) {
			// Nothing acknowledged for the first few samples, then the ACKs land.
			if samples++; samples <= 3 {
				return pmtuPayloadSize, nil
			}
			return 0, nil
		},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
	defer cancel()

	if r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps); r.Status != StatusPass {
		t.Errorf("delayed acknowledgement = %+v, want PASS", r)
	}
	if samples < 4 {
		t.Errorf("queue sampled %d times, want the probe to keep watching until the ACKs arrive", samples)
	}
}

// pmtuCancelBudget gives the cancellation case a write window wide enough that
// only cancellation can plausibly be what ends the wait. The probe derives its
// write deadline as budget minus pmtuHeadroom, so the wait under test is the
// full pmtuWriteWait, and a return well inside that window is evidence the
// deadline was not what returned it.
const pmtuCancelBudget = pmtuHeadroom + pmtuWriteWait

// Cancelling the run has to stop the acknowledgement watch. The connection is
// dialled with the context, but an established socket does not care that the
// context was later cancelled, so the polling loop is the only thing that can
// notice. Without that, a cancelled probe keeps sampling until its own write
// deadline and holds the whole run open for the rest of the window.
func TestPMTUProbeStopsWaitingWhenCanceled(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()

	// Closed from inside the queue reader, so cancellation cannot land before
	// the watch is running: the first read is the one taken before the payload
	// is written, and the third proves the loop has sampled, waited, and come
	// back for more.
	polling := make(chan struct{})
	samples := 0
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
		sendBuffer:  func(net.Conn) (int, error) { return 2 * pmtuSendBuffer, nil },
		queued: func(net.Conn) (int, error) {
			if samples++; samples == 3 {
				close(polling)
			}
			// Never any progress, so nothing but cancellation or the deadline
			// can end the watch.
			return pmtuPayloadSize, nil
		},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), pmtuCancelBudget)
	defer cancel()

	done := make(chan ProbeResult, 1)
	go func() { done <- ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps) }()

	<-polling
	start := time.Now()
	cancel()

	var r ProbeResult
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("cancelled PMTU probe never returned")
	}
	// Generous enough to survive a loaded runner, and still decisively short of
	// the write window the unfixed probe sits out.
	if waited := time.Since(start); waited > pmtuWriteWait/2 {
		t.Errorf("cancelled PMTU probe returned after %v, want well inside the %v write window", waited, pmtuWriteWait)
	}
	// Cancellation is not evidence about the path, so it cannot borrow one of
	// the readings' verdicts: not the black-hole WARN, not the send-buffer
	// fallback's PASS, and not a fix hint for a problem nothing measured.
	if r.Status != StatusNA || !strings.Contains(r.Detail, "canceled") {
		t.Errorf("cancelled PMTU probe = %+v, want N/A naming the cancellation", r)
	}
	if r.Fix != "" {
		t.Errorf("cancelled PMTU probe fix = %q, want none", r.Fix)
	}
}

// A budget that merely ran out is not cancellation: it is the write deadline
// arriving from the other direction, so it has to answer the way the deadline
// does, with a reading and no error. An error here would read as a platform
// that cannot account for its send queue, and that fallback can call a stall a
// pass.
func TestAwaitAcknowledgedTreatsAnExpiredBudgetAsTheDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), pmtuQueueSample)
	defer cancel()

	// A write deadline far enough out that only the expiring budget can end the
	// watch, and a queue that never drains so nothing else can.
	delivered, err := awaitAcknowledged(ctx, func(net.Conn) (int, error) { return pmtuPayloadSize, nil },
		nil, pmtuPayloadSize, time.Now().Add(time.Hour))
	if err != nil || delivered > 0 {
		t.Errorf("awaitAcknowledged past the budget = (%d, %v), want the deadline's answer: no delivery, no error", delivered, err)
	}
}

// A reset purges the send queue, so an empty queue after one reads as a fully
// acknowledged payload. Inconclusive has to win over that.
func TestPMTUProbeReportsResetOverDrainedQueue(t *testing.T) {
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return resetWriteConn{}, nil },
		sendBuffer:  func(net.Conn) (int, error) { return 2 * pmtuSendBuffer, nil },
		queued:      func(net.Conn) (int, error) { return 0, nil },
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}

	r := ops.pmtuProbe(443, ProtoTLSHTTP)(context.Background(), deps)
	if r.Status != StatusNA || !strings.Contains(r.Detail, "the peer dropped the connection") {
		t.Errorf("reset mid-write = %+v, want N/A naming the dropped connection", r)
	}
}

// blackHoleConn is what a path-MTU black hole looks like from userspace on a
// kernel that accepts more than the send buffer it reports: the whole payload
// is taken locally and not one byte reaches a peer. There is no peer.
type blackHoleConn struct{ fakeConn }

func (blackHoleConn) Write(b []byte) (int, error)      { return len(b), nil }
func (blackHoleConn) SetWriteDeadline(time.Time) error { return nil }

// overrunConn takes more than the send buffer it reports and then stops, which
// is the shape the old inference read as delivery. Bytes past the buffer are
// still bytes a kernel holds, not bytes a peer took.
type overrunConn struct{ fakeConn }

func (overrunConn) Write([]byte) (int, error) {
	return 2 * pmtuSendBuffer, fmt.Errorf("wrapped write: %w", syscall.ECONNRESET)
}
func (overrunConn) SetWriteDeadline(time.Time) error { return nil }

// Without send-queue accounting nothing can tell the write above apart from a
// delivered one. A completed Write says the local kernel took the bytes and
// nothing more: not that they left the machine, and not that the peer
// acknowledged them, so it cannot be a PASS. With no reading to contradict it
// either, it is not a black-hole WARN: the limitation is in the observer, not
// the path.
func TestPMTUProbeWithoutQueueAccountingCannotPass(t *testing.T) {
	// Both writes the send-buffer inference used to read as delivery.
	for _, tc := range []struct {
		name string
		conn net.Conn
	}{
		{"whole payload accepted", blackHoleConn{}},
		{"write overruns the send buffer, then stops", overrunConn{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &netops{
				dialContext: func(context.Context, string, string) (net.Conn, error) { return tc.conn, nil },
				sendBuffer:  func(net.Conn) (int, error) { return pmtuSendBuffer, nil },
				queued:      func(net.Conn) (int, error) { return 0, errors.New("no TCP send-queue accounting on windows") },
			}
			deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
			ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
			defer cancel()

			r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps)
			if r.Status != StatusNA {
				t.Errorf("pmtu without queue accounting = %+v, want N/A: the write was accepted locally and nothing measured what became of it", r)
			}
			if !strings.Contains(r.Detail, "could not be verified") {
				t.Errorf("pmtu detail = %q, want it to name the delivery it could not verify", r.Detail)
			}
			// Nothing demonstrated a path-MTU defect, so nothing may be
			// recommended for one.
			if r.Fix != "" {
				t.Errorf("pmtu fix = %q, want none: no black hole was demonstrated", r.Fix)
			}
		})
	}
}

// The send buffer only has to be smaller than the payload where it is the
// measurement. With a readable send queue its size is beside the point, and
// bailing out on it would cost the platforms that can actually answer.
func TestPMTUProbeIgnoresSendBufferSizeWithQueueAccounting(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() { _, _ = io.Copy(io.Discard, server) }()
	ops := &netops{
		dialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
		sendBuffer:  func(net.Conn) (int, error) { return 4 * pmtuPayloadSize, nil },
		queued:      func(net.Conn) (int, error) { return pmtuPayloadSize, nil },
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), pmtuTestBudget)
	defer cancel()

	if r := ops.pmtuProbe(443, ProtoTLSHTTP)(ctx, deps); r.Status != StatusWarn {
		t.Errorf("oversized send buffer with queue accounting = %+v, want WARN from the queue reading", r)
	}
}

// The payload is sized exactly, and only a TLS target gets the record header
// that keeps an OpenSSL server reading long enough to acknowledge it.
func TestPMTUPayloadShape(t *testing.T) {
	tlsPayload, plain := pmtuPayload(ProtoTLSHTTP), pmtuPayload(ProtoSSH)
	if len(tlsPayload) != pmtuPayloadSize || len(plain) != pmtuPayloadSize {
		t.Fatalf("payload sizes = %d, %d, want %d", len(tlsPayload), len(plain), pmtuPayloadSize)
	}
	if !bytes.HasPrefix(tlsPayload, tlsRecordHeader) {
		t.Error("TLS payload does not start with a TLS record header")
	}
	if bytes.HasPrefix(plain, tlsRecordHeader) {
		t.Error("non-TLS payload should not claim to be a TLS record")
	}
	if !bytes.Contains(plain, []byte("netdoc path-mtu probe")) {
		t.Error("payload should identify itself in a capture")
	}
}

// A server that connects but never sends a banner is a WARN (the port
// answered, the service didn't) with the explicit no-banner detail, once the
// read deadline hits.
func TestBannerProbeReadTimeout(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return silentConn{}, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}

	r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(context.Background(), deps)
	if r.Status != StatusWarn || r.Detail != "connected, no banner within deadline" {
		t.Errorf("silent server = %+v, want WARN with no-banner detail", r)
	}
	if !r.SelectedIP.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("SelectedIP = %v, want the pinned dependency IP", r.SelectedIP)
	}
}

// A peer that stays connected but stops talking is ended by the read deadline,
// capped here by the context. One that said only an SMTP continuation line
// before going quiet sent an unterminated reply, which must not pass.
func TestBannerProbeReadTimeoutHonorsContext(t *testing.T) {
	tests := []struct {
		name, prelude string
		id            ProbeID
		want          Status
		detail        string
	}{
		{"silent server", "", ProbeSSH, StatusWarn, "connected, no banner within deadline"},
		{"SMTP continuation line then silence", "220-mail.example ESMTP ready\r\n", ProbeSMTP, StatusFail, "unexpected service banner: 220-mail.example ESMTP ready"},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			// The prelude is already in the client's buffer when the probe
			// starts, so no writer races the deadline. Once it is read, the
			// server holds the pipe open and the real read deadline ends it.
			conn := &preludeConn{Conn: client, r: io.MultiReader(strings.NewReader(tt.prelude), client)}
			ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			r := ops.bannerProbe(tt.id, "service banner", "", 22).Run(ctx, deps)
			if want, _ := ctx.Deadline(); !conn.readDeadline.Equal(want) {
				t.Errorf("read deadline = %v, want the context deadline %v", conn.readDeadline, want)
			}
			if r.Status != tt.want || r.Detail != tt.detail {
				t.Errorf("status = %v, detail = %q, want %v %q", r.Status, r.Detail, tt.want, tt.detail)
			}
		})
	}
}

// preludeConn serves bytes already received before reading from Conn, whose
// deadlines it keeps. readDeadline records the last read deadline requested.
type preludeConn struct {
	net.Conn
	r            io.Reader
	readDeadline time.Time
}

func (c *preludeConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *preludeConn) SetReadDeadline(d time.Time) error {
	c.readDeadline = d
	return c.Conn.SetReadDeadline(d)
}

// runScriptedBanner runs the banner probe id against a peer that sends server
// and then closes the connection.
func runScriptedBanner(id ProbeID, server string) ProbeResult {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return &scriptConn{r: strings.NewReader(server)}, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	return ops.bannerProbe(id, "service banner", "", 22).Run(context.Background(), deps)
}

func TestBannerProbeValidatesProtocol(t *testing.T) {
	tests := []struct {
		name   string
		id     ProbeID
		banner string
		want   Status
	}{
		{"SSH identification", ProbeSSH, "SSH-2.0-OpenSSH_9.7\r\n", StatusPass},
		{"SSH impostor", ProbeSSH, "220 mail.example ESMTP\r\n", StatusFail},
		{"SMTP greeting", ProbeSMTP, "220 mail.example ESMTP\r\n", StatusPass},
		{"SMTP multiline greeting", ProbeSMTP, "220-mail.example ESMTP\r\n220 ready\r\n", StatusPass},
		{"SMTP unterminated multiline greeting", ProbeSMTP, "220-mail.example ESMTP\r\n", StatusFail},
		{"SMTP impostor", ProbeSMTP, "SSH-2.0-OpenSSH_9.7\r\n", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runScriptedBanner(tt.id, tt.banner)
			if r.Status != tt.want {
				t.Errorf("status = %v, detail = %q, want %v", r.Status, r.Detail, tt.want)
			}
		})
	}
}

// serveImplicitTLSSMTP answers the way an RFC 8314 submissions server on port
// 465 does: it says nothing until the client opens TLS, and sends greeting only
// over the finished TLS session. sni reports the name the last client asked for.
// Each connection presents the next of certs, and the last one from then on.
func serveImplicitTLSSMTP(t *testing.T, greeting string, certs ...tls.Certificate) (p *pipeNet, sni func() string) {
	t.Helper()
	p = newPipeNet(t)
	var name atomic.Value
	name.Store("")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			raw, err := p.Accept()
			if err != nil {
				return
			}
			cert := certs[min(int(accepted.Add(1)), len(certs))-1]
			wg.Go(func() {
				defer raw.Close()
				// net.Pipe has no buffer, so a client that rejects the
				// certificate blocks sending its alert while this side blocks
				// sending the rest of its flight. A short handshake deadline
				// breaks that tie the way the HTTPS fixtures do.
				_ = raw.SetDeadline(time.Now().Add(100 * time.Millisecond))
				conn := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{cert},
					GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						name.Store(hello.ServerName)
						return nil, nil
					},
				})
				if conn.Handshake() != nil {
					return
				}
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				// Write and read at once, for the same reason: a client that
				// hangs up without reading the greeting must not be left
				// stuck sending close_notify.
				wg.Go(func() { _, _ = io.WriteString(conn, greeting) })
				_, _ = io.Copy(io.Discard, conn)
			})
		}
	})
	t.Cleanup(func() {
		_ = p.Close()
		wg.Wait()
	})
	return p, func() string { return name.Load().(string) }
}

// runSMTPRows runs the SMTP banner row of target's graph and everything it
// depends on above Target TCP, with Target TCP pinned to a fixed address.
func runSMTPRows(t *testing.T, ops *netops, target string) map[ProbeID]ProbeResult {
	t.Helper()
	var rows []Probe
	for _, p := range (ProbeSelection{Check: probeSet(ProbeSMTP)}).Apply(ops.buildProbes(mustTarget(t, target), "", false)) {
		switch p.ID {
		case ProbeIface, ProbeDNS:
			continue
		case ProbeTargetTCP:
			p.Deps = nil
			p.Run = func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
				return ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP("192.0.2.25")}
			}
		}
		rows = append(rows, p)
	}
	return RunAll(t.Context(), rows, DefaultProbeTimeout)
}

// implicitTLSOps dials p and trusts roots, for both the TLS row and the SMTP
// row's own TLS connection.
func implicitTLSOps(p *pipeNet, roots *x509.CertPool) *netops {
	dial := dialTLSWith(p.dial)
	return &netops{dialContext: p.dial, tlsRootCAs: roots, dialTLS: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		cfg = cfg.Clone()
		cfg.RootCAs = roots
		return dial(ctx, network, addr, cfg)
	}}
}

// Port 465 is implicit TLS (RFC 8314 section 3.3): a healthy server waits for
// the ClientHello and greets only inside TLS. A client that waits for a
// plaintext 220 first never gets one, so this fixture fails any probe that does.
func TestSMTPOnPort465GreetsOverImplicitTLS(t *testing.T) {
	const host = "mail.example"
	cert, roots := selfSignedCert(t, host)
	p, sni := serveImplicitTLSSMTP(t, "220 mail.example ESMTP\r\n", cert)
	res := runSMTPRows(t, implicitTLSOps(p, roots), "smtp://"+host+":465")
	if r := res[ProbeSMTP]; r.Status != StatusPass || r.Detail != "banner: 220 mail.example ESMTP" {
		t.Fatalf("SMTP row = %+v, want PASS on the greeting sent over TLS", r)
	}
	if r, ok := res[ProbeTLS]; !ok || r.Status != StatusPass {
		t.Errorf("TLS row = %+v (present %v), want PASS", r, ok)
	}
	if got := sni(); got != host {
		t.Errorf("SNI = %q, want %q", got, host)
	}
}

// Each layer of an implicit-TLS endpoint fails as itself: a rejected handshake
// is a TLS failure that leaves the greeting untested, never a missing or
// unexpected plaintext banner, and a working handshake followed by silence or
// the wrong greeting is the SMTP row's finding.
func TestSMTPOnPort465ReportsTheLayerThatFailed(t *testing.T) {
	const host = "mail.example"
	for _, tc := range []struct {
		name, certHost, greeting string
		tls, smtp                Status
		tlsCause, detail         string
	}{
		{"certificate for another name", "other.example", "220 other.example ESMTP\r\n", StatusFail, StatusSkip, TLSCauseHostnameMismatch, "skipped: a prerequisite failed"},
		{"silent after TLS", host, "", StatusPass, StatusWarn, "", "connected, no banner within deadline"},
		{"wrong greeting after TLS", host, "554 go away\r\n", StatusPass, StatusFail, "", "unexpected service banner: 554 go away"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, roots := selfSignedCert(t, tc.certHost)
			p, _ := serveImplicitTLSSMTP(t, tc.greeting, cert)
			res := runSMTPRows(t, implicitTLSOps(p, roots), "smtp://"+host+":465")
			if r, ok := res[ProbeTLS]; !ok || r.Status != tc.tls || r.Cause != tc.tlsCause {
				t.Errorf("TLS row = %+v (present %v), want %v %q", r, ok, tc.tls, tc.tlsCause)
			}
			if r := res[ProbeSMTP]; r.Status != tc.smtp || r.Detail != tc.detail {
				t.Errorf("SMTP row = %+v, want %v %q", r, tc.smtp, tc.detail)
			}
		})
	}
}

// The diagnosis follows the rows: a rejected certificate on port 465 is the
// TLS finding, not a service banner one.
func TestSMTPOnPort465DiagnosesTLSFailureAsTLS(t *testing.T) {
	target := mustTarget(t, "smtp://mail.example:465")
	order := planOrder(t, target)
	ip := net.ParseIP("192.0.2.25")
	res := settle(t, target, order, map[ProbeID]ProbeResult{
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{ip}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{ip}},
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: ip},
		ProbeTLS:       {Status: StatusFail, SelectedIP: ip, Cause: TLSCauseHostnameMismatch},
	})
	d := Interpret(target, order, res)
	if want := tlsDiagnosisID(TLSCauseHostnameMismatch); len(d.Findings) == 0 || d.Findings[0].ID != want {
		t.Fatalf("finding = %+v, want %q: %q", d.Findings, want, d.Summary)
	}
}

// The SMTP row on port 465 opens a TLS connection of its own after the TLS row
// passed. When that second handshake fails, no greeting was read, so it is the
// TLS finding about the SMTP row's connection, not a service banner failure.
func TestSMTPOnPort465SecondHandshakeFailureStaysTLS(t *testing.T) {
	const host = "mail.example"
	good, roots := selfSignedCert(t, host)
	// Trusted, so the second handshake fails on the name alone.
	other, _ := selfSignedCert(t, "other.example")
	roots.AddCert(other.Leaf)
	p, _ := serveImplicitTLSSMTP(t, "220 mail.example ESMTP\r\n", good, other)
	target := mustTarget(t, "smtp://"+host+":465")
	ran := runSMTPRows(t, implicitTLSOps(p, roots), target.Raw)
	if r := ran[ProbeTLS]; r.Status != StatusPass {
		t.Fatalf("TLS row = %+v, want PASS on the first handshake", r)
	}
	smtp := ran[ProbeSMTP]
	if smtp.Status != StatusFail || smtp.Cause != TLSCauseHostnameMismatch || strings.Contains(smtp.Detail, "banner") || smtp.Fix == "" {
		t.Errorf("SMTP row = %+v, want FAIL with cause %q, a TLS fix, and no banner", smtp, TLSCauseHostnameMismatch)
	}

	order := planOrder(t, target)
	ip := net.ParseIP("192.0.2.25")
	res := settle(t, target, order, map[ProbeID]ProbeResult{
		ProbeDNS:       {Status: StatusPass, Addrs: []net.IP{ip}},
		ProbeDNSPublic: {Status: StatusPass, Addrs: []net.IP{ip}},
		ProbeTargetTCP: {Status: StatusPass, SelectedIP: ip},
		ProbeTLS:       ran[ProbeTLS],
		ProbeSMTP:      smtp,
	})
	d := Interpret(target, order, res)
	if len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisTLSHostnameMismatch || d.Focus() != ProbeSMTP || d.Blamed != ProbeSMTP {
		t.Fatalf("diagnosis = %+v, want %q about the SMTP row", d, DiagnosisTLSHostnameMismatch)
	}
	if ev := d.Findings[0].Evidence; len(ev) == 0 || ev[0].Check != ProbeSMTP || ev[0].Kind != EvidenceSupport {
		t.Errorf("evidence = %+v, want the SMTP row first", ev)
	}
	if !strings.Contains(d.Summary, "TLS row's handshake passed") {
		t.Errorf("summary = %q, want it to say the TLS row passed and this was the SMTP check's own connection", d.Summary)
	}
}

// Relay and submission ports greet in plaintext at connection start; STARTTLS,
// if any, comes later. Only 465 moves the greeting inside TLS.
func TestSMTPOnPlaintextPortsReadsTheBannerBeforeAnyTLS(t *testing.T) {
	for _, target := range []string{"mail.example:25", "mail.example:587", "smtp://mail.example", "smtp://mail.example:587", "smtp://mail.example:2525"} {
		t.Run(target, func(t *testing.T) {
			ops := &netops{
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					return &scriptConn{r: strings.NewReader("220 mail.example ESMTP\r\n")}, nil
				},
				dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
					t.Error("a plaintext SMTP port opened TLS")
					return nil, errors.New("unexpected TLS dial")
				},
			}
			res := runSMTPRows(t, ops, target)
			if _, ok := res[ProbeTLS]; ok {
				t.Errorf("graph has a TLS row for %s", target)
			}
			if r := res[ProbeSMTP]; r.Status != StatusPass {
				t.Errorf("SMTP row = %+v, want PASS on the plaintext greeting", r)
			}
		})
	}
}

// RFC 4253 section 4.2 terminates the SSH identification string with CR LF, so
// only a complete line identifies a service. bufio.Reader.ReadString returns
// the bytes it did get together with the error that stopped it, and those
// bytes are a fragment: a peer that writes "SSH-2." and hangs up said nothing
// valid, however promising the prefix looks. The same holds for the SMTP
// greeting, which RFC 5321 section 4.2 also terminates with CR LF.
func TestBannerProbeRequiresCompleteLine(t *testing.T) {
	tests := []struct {
		name   string
		id     ProbeID
		server string
		want   Status
		detail string
	}{
		{
			name:   "truncated SSH identification then EOF",
			id:     ProbeSSH,
			server: "SSH-2.",
			want:   StatusFail,
			detail: "unexpected service banner: SSH-2.",
		},
		{
			name:   "LF-terminated SSH identification",
			id:     ProbeSSH,
			server: "SSH-2.0-test\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-test",
		},
		{
			name:   "CRLF-terminated SSH identification",
			id:     ProbeSSH,
			server: "SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "preliminary line then a complete identification",
			id:     ProbeSSH,
			server: "Authorized use only\r\nSSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "preliminary line then a truncated identification",
			id:     ProbeSSH,
			server: "Authorized use only\r\nSSH-2.",
			want:   StatusFail,
			detail: "unexpected service banner: Authorized use only",
		},
		{
			name:   "truncated preliminary line that never identifies",
			id:     ProbeSSH,
			server: "Authorized use onl",
			want:   StatusFail,
			detail: "unexpected service banner: Authorized use onl",
		},
		{
			name:   "identification cut off by the byte limit",
			id:     ProbeSSH,
			server: "SSH-2.0-" + strings.Repeat("x", 2000) + "\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: SSH-2.0-" + strings.Repeat("x", 1016),
		},
		{
			name:   "truncated SMTP greeting then EOF",
			id:     ProbeSMTP,
			server: "220 ",
			want:   StatusFail,
			detail: "unexpected service banner: 220 ",
		},
		{
			name:   "truncated SMTP continuation greeting then EOF",
			id:     ProbeSMTP,
			server: "220-mail.exam",
			want:   StatusFail,
			detail: "unexpected service banner: 220-mail.exam",
		},
		{
			name:   "complete SMTP greeting",
			id:     ProbeSMTP,
			server: "220 mail.example ESMTP\r\n",
			want:   StatusPass,
			detail: "banner: 220 mail.example ESMTP",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runScriptedBanner(tt.id, tt.server)
			if r.Status != tt.want || r.Detail != tt.detail {
				t.Errorf("status = %v, detail = %q, want %v %q", r.Status, r.Detail, tt.want, tt.detail)
			}
		})
	}
}

// An SMTP reply is complete only at a line whose code is followed by a space
// (RFC 5321 section 4.2.1). Every earlier line of a greeting reads "220-", and
// the whole reply shares the one 1024-byte read limit.
func TestBannerProbeRequiresTerminatedSMTPGreeting(t *testing.T) {
	const first = "220-mail.example ESMTP ready\r\n"
	const unterminated = "unexpected service banner: 220-mail.example ESMTP ready"
	tests := []struct{ name, server, detail string }{
		{"continuation line then EOF", first, unterminated},
		{"continuation lines then EOF", first + "220-feature one\r\n", unterminated},
		{"continuation then a truncated final line", first + "220 fin", unterminated},
		{"continuation ended by another reply code", first + "554 no service\r\n", unterminated},
		{"non-220 greeting", "554 mail.example no service\r\n", "unexpected service banner: 554 mail.example no service"},
		{"multiline greeting cut off by the byte limit", strings.Repeat("220-feature\r\n", 100) + "220 ready\r\n", "unexpected service banner: 220-feature"},
		{"complete multiline greeting", first + "220-feature one\r\n220 feature two\r\n", "banner: 220-mail.example ESMTP ready"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := StatusFail
			if strings.HasPrefix(tt.detail, "banner: ") {
				want = StatusPass
			}
			r := runScriptedBanner(ProbeSMTP, tt.server)
			if r.Status != want || r.Detail != tt.detail {
				t.Errorf("status = %v, detail = %q, want %v %q", r.Status, r.Detail, want, tt.detail)
			}
		})
	}
}

// A peer that streams forever without a newline gets no pass and no unbounded
// read: the 1024-byte limit ends the probe.
func TestBannerProbeEndlessStreamStaysBounded(t *testing.T) {
	stream := &countingReader{}
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return &scriptConn{r: stream}, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(context.Background(), deps)
	if stream.n > 1024 {
		t.Errorf("read %d bytes, want the 1024-byte limit to hold", stream.n)
	}
	if r.Status != StatusFail {
		t.Errorf("endless banner = %+v, want FAIL", r)
	}
}

// countingReader is an endless "SSH-" stream with no line ending, counting the
// bytes the probe consumes.
type countingReader struct{ n int }

func (c *countingReader) Read(p []byte) (int, error) {
	const prefix = "SSH-2.0-"
	for i := range p {
		if n := c.n + i; n < len(prefix) {
			p[i] = prefix[n]
			continue
		}
		p[i] = 'x'
	}
	c.n += len(p)
	return len(p), nil
}

// Dependent probes fed an empty/zero dependency map degrade to their explicit
// fail/skip states, with no nil-deref and no accidental pass.
func TestProbesMalformedDeps(t *testing.T) {
	ops := &netops{}
	empty := map[ProbeID]ProbeResult{}
	ctx := context.Background()

	if r := ops.targetTCPProbe(443, nil)(ctx, empty); r.Status != StatusFail || !strings.Contains(r.Detail, "no resolved addresses") {
		t.Errorf("targetTCP without DNS result = %+v, want FAIL 'no resolved addresses'", r)
	}
	if r := ops.tlsProbe("example.com", 443, nil)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("tls without pinned IP = %+v, want SKIP", r)
	}
	if r := ops.httpProbe("example.com", 80, "http", ProbeDNS, nil)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("http without DNS addrs = %+v, want SKIP", r)
	}
	if r := ops.httpProbe("example.com", 443, "https", ProbeTLS, nil)(ctx, empty); r.Status != StatusSkip {
		t.Errorf("https without TLS pinned IP = %+v, want SKIP", r)
	}
	if r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(ctx, empty); r.Status != StatusSkip {
		t.Errorf("banner without pinned IP = %+v, want SKIP", r)
	}
}

// A response whose headers blow past MaxResponseHeaderBytes fails the HTTP
// probe instead of buffering unbounded attacker-controlled bytes.
func TestHTTPProbeHeaderLimit(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			br := bufio.NewReader(server)
			for { // consume the HEAD request up to the blank line
				line, err := br.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			// 128 KiB header, double the transport's 64 KiB cap.
			_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 128<<10) + "\r\n\r\n"))
		}()
		return client, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r := ops.httpProbe("example.com", 80, "http", ProbeTargetTCP, nil)(ctx, deps)
	if r.Status != StatusFail || r.Cause != HTTPCauseInvalidResponse || !strings.Contains(r.Detail, "HTTP response from 192.0.2.1 could not be read") || !strings.Contains(r.Detail, "exceeded") {
		t.Errorf("oversized headers = %+v, want FAIL naming the address and the exceeded header limit", r)
	}
}

// A failing stage names the address it used, so the reader doesn't have to
// cross-reference the DNS row to find out what was actually dialed. When no
// address connected there is no winner to name, so all of them are listed.
func TestHTTPProbeFailureNamesAddresses(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}
	addrs := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	deps := map[ProbeID]ProbeResult{ProbeDNS: {Addrs: addrs}}

	r := ops.httpProbe("example.com", 80, "http", ProbeDNS, nil)(context.Background(), deps)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "192.0.2.1, 192.0.2.2") {
		t.Errorf("total dial failure = %+v, want FAIL listing every attempted address", r)
	}
}

// The transport dials on a goroutine that outlives client.Do when the context
// expires mid-dial, so the failure detail has to name the address from the
// guarded snapshot rather than re-read what that goroutine is still writing.
// Only -race fails on the difference.
func TestHTTPProbeDialOutlivesRequest(t *testing.T) {
	// The dial outlasts the request deadline on its own clock, and nothing hands it
	// the baton, or the handoff would order the very access under test.
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(60 * time.Millisecond)
		return nil, errors.New("connection refused")
	}}
	deps := map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{net.ParseIP("192.0.2.1")}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	r := ops.httpProbe("example.com", 80, "http", ProbeDNS, nil)(ctx, deps)
	time.Sleep(100 * time.Millisecond) // stay alive for the dial's write, the racing access

	if r.Status != StatusFail || !strings.Contains(r.Detail, "192.0.2.1") {
		t.Errorf("dial outliving the request = %+v, want FAIL naming the address", r)
	}
}

// A real HTTP/2 round trip, with ALPN, TLS, and the h2 framing all genuinely
// negotiated, over in-memory pipes, so nothing binds a port. The server hangs
// up on anything that arrives as HTTP/1.1, which is what makes the PASS
// evidence that the probe's transport actually reached agreement on h2.
func TestHTTPSProbeSupportsHTTP2OnlyServer(t *testing.T) {
	const host = "http2.example"
	cert, roots := selfSignedCert(t, host)
	var overHTTP2 atomic.Bool
	p := newPipeNet(t)
	srv := &http.Server{
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				conn, _, _ := w.(http.Hijacker).Hijack()
				_ = conn.Close()
				return
			}
			overHTTP2.Store(true)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	p.serve(t, srv, func() error { return srv.ServeTLS(p, "", "") })

	ops := &netops{dialContext: p.dial, tlsRootCAs: roots}
	deps := map[ProbeID]ProbeResult{ProbeTLS: {SelectedIP: net.ParseIP("192.0.2.10")}}
	r := ops.httpProbe(host, 443, "https", ProbeTLS, nil)(context.Background(), deps)
	if r.Status != StatusPass {
		t.Fatalf("HTTP/2-only HTTPS probe = %+v, want PASS", r)
	}
	if !overHTTP2.Load() {
		t.Error("the request never arrived over HTTP/2; the probe's h2 negotiation is untested")
	}
}

// The probe's TLS connection is built for the HTTP/2 observation, so pin that
// it still verifies the chain and the name before anything reaches the server.
func TestHTTPSProbeStillVerifiesTheCertificate(t *testing.T) {
	cert, roots := selfSignedCert(t, "http2.example")
	for _, tc := range []struct {
		name, host string
		roots      *x509.CertPool
	}{
		{"wrong name", "other.example", roots},
		{"untrusted issuer", "http2.example", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Bool
			p := newPipeNet(t)
			srv := &http.Server{
				TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
				ReadHeaderTimeout: 100 * time.Millisecond,
				ErrorLog:          log.New(io.Discard, "", 0),
				Handler:           http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }),
			}
			p.serve(t, srv, func() error { return srv.ServeTLS(p, "", "") })
			ops := &netops{dialContext: p.dial, tlsRootCAs: tc.roots}
			deps := map[ProbeID]ProbeResult{ProbeTLS: {SelectedIP: net.ParseIP("192.0.2.10")}}
			r := ops.httpProbe(tc.host, 443, "https", ProbeTLS, nil)(context.Background(), deps)
			if r.Status != StatusFail || r.Cause != "" || !strings.Contains(r.Detail, "x509") || reached.Load() {
				t.Fatalf("result = %+v, handler reached %v; want a certificate failure before any request", r, reached.Load())
			}
		})
	}
}

// bodyMatches accepts only the documented clean forms: the exact payload and
// the same payload with a trailing CRLF. Truncation, an altered byte, or any
// further trailing content is rejected, and the read stays bounded.
func TestBodyMatches(t *testing.T) {
	ep := portalEndpoint{body: ncsiCleanBody}
	longSuffix := ncsiCleanBody + strings.Repeat("x", 4096)
	cases := []struct {
		name string
		body string
		want bool
	}{
		{name: "exact expected payload", body: ncsiCleanBody, want: true},
		{name: "expected plus documented CRLF", body: ncsiCleanBody + "\r\n", want: true},
		{name: "truncated", body: ncsiCleanBody[:len(ncsiCleanBody)-1]},
		{name: "one incorrect byte", body: "Microsoft Connect Fest"},
		{name: "expected plus arbitrary HTML", body: ncsiCleanBody + "<html>intercepted</html>"},
		{name: "expected plus long arbitrary suffix", body: longSuffix},
		{name: "empty body", body: ""},
		{name: "CRLF alone", body: "\r\n"},
		{name: "LF only after payload", body: ncsiCleanBody + "\n"},
		{name: "CR only after payload", body: ncsiCleanBody + "\r"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ep.bodyMatches(strings.NewReader(c.body))
			if got != c.want {
				t.Errorf("bodyMatches(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
	// An endpoint that documents no body stays clean without consuming input.
	if !((portalEndpoint{}).bodyMatches(strings.NewReader("anything"))) {
		t.Error("empty documented body should match without reading")
	}
}

// The real portalCheckWithDial round trip over in-memory pipes: an endpoint is
// clean only when it answers a documented clean form (exact payload or payload
// plus CRLF), a redirect is reported rather than chased, and the proxy env
// never enters the path. Prefix-plus-extra bodies are discrepant, not clean.
func TestPortalCheck(t *testing.T) {
	// internetProbe only runs the round trips below when the field is wired, so
	// a nil here disables captive-portal detection with nothing else failing.
	if defaultOps.portalCheck == nil {
		t.Fatal("defaultOps.portalCheck is nil; captive-portal detection is silently off")
	}
	// Two independently operated endpoints is the whole of the fix: with one,
	// that operator alone decides whether this machine is behind a portal.
	if len(portalEndpoints) < 2 {
		t.Fatalf("portalEndpoints = %+v; a single endpoint cannot corroborate itself", portalEndpoints)
	}
	hosts := map[string]bool{}
	for _, ep := range portalEndpoints {
		u, err := url.Parse(ep.url)
		if err != nil || u.Scheme != "http" {
			t.Fatalf("endpoint %q must be a plain-HTTP URL: %v", ep.url, err)
		}
		hosts[u.Hostname()] = true
	}
	if len(hosts) != len(portalEndpoints) {
		t.Errorf("endpoints share a host (%v); they have to be independently operated", hosts)
	}

	var chased bool
	p := newPipeNet(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/connecttest.txt":
			fmt.Fprint(w, ncsiCleanBody+"\r\n")
		case "/truncated":
			fmt.Fprint(w, ncsiCleanBody[:len(ncsiCleanBody)-1])
		case "/wrongbody":
			// The shape of a filter's "everything is fine" page: a 200 that
			// says something else entirely.
			fmt.Fprint(w, "<html>You are connected to GuestWiFi</html>")
		case "/prefix-html":
			// Clean prefix followed by an interceptor's page: must not count
			// as the documented NCSI answer.
			fmt.Fprint(w, ncsiCleanBody+"<html>intercepted page...</html>")
		case "/prefix-long":
			fmt.Fprint(w, ncsiCleanBody+strings.Repeat("x", 4096))
		case "/redirect":
			http.Redirect(w, r, "/signin", http.StatusFound)
		case "/unsafe":
			w.Header().Set("Location", "file:///tmp/signin")
			w.WriteHeader(http.StatusFound)
		case "/signin":
			chased = true
			w.WriteHeader(http.StatusOK)
		}
	})}
	p.serve(t, srv, func() error { return srv.Serve(p) })

	const base = "http://portal.example"
	noBody := func(path string) portalEndpoint {
		return portalEndpoint{url: base + path, want: http.StatusNoContent}
	}
	withBody := func(path string) portalEndpoint {
		return portalEndpoint{url: base + path, want: http.StatusOK, body: ncsiCleanBody}
	}

	// A proxy that would divert the request if the transport honored it.
	t.Setenv("HTTP_PROXY", "http://192.0.2.9:1")
	t.Setenv("http_proxy", "http://192.0.2.9:1")

	for _, c := range []struct {
		name         string
		ep           portalEndpoint
		wantClean    bool
		wantCode     int
		wantRedirect string
	}{
		{name: "documented 204", ep: noBody("/generate_204"), wantClean: true, wantCode: http.StatusNoContent},
		{name: "documented payload", ep: withBody("/connecttest.txt"), wantClean: true, wantCode: http.StatusOK},
		// The point of reading the body at all: an arbitrary 200 is not a
		// clean NCSI answer, which is how a filter's own page gets counted.
		{name: "200 with the wrong payload", ep: withBody("/wrongbody"), wantCode: http.StatusOK},
		{name: "200 with a short payload", ep: withBody("/truncated"), wantCode: http.StatusOK},
		// Prefix match alone is not enough: trailing HTML or a long suffix
		// after the clean payload is discrepant, not clean.
		{name: "200 with clean prefix plus HTML", ep: withBody("/prefix-html"), wantCode: http.StatusOK},
		{name: "200 with clean prefix plus long suffix", ep: withBody("/prefix-long"), wantCode: http.StatusOK},
		{name: "204 where a payload was documented", ep: withBody("/generate_204"), wantCode: http.StatusNoContent},
		{name: "payload where a 204 was documented", ep: noBody("/connecttest.txt"), wantCode: http.StatusOK},
		{name: "intercepted", ep: noBody("/redirect"), wantCode: http.StatusFound, wantRedirect: base + "/signin"},
		{name: "intercepted to a non-HTTP scheme", ep: noBody("/unsafe"), wantCode: http.StatusFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := portalCheckWithDial(context.Background(), c.ep, p.dial)
			if err != nil || got.clean != c.wantClean || got.code != c.wantCode || got.redirect != c.wantRedirect {
				t.Errorf("observation = %+v (err %v), want clean=%v code=%d redirect=%q",
					got, err, c.wantClean, c.wantCode, c.wantRedirect)
			}
		})
	}
	if chased {
		t.Error("followed the redirect to the sign-in page; the 302 is the answer")
	}

	// Every dial went to the endpoint's own host: the proxy env was ignored,
	// which the pipe dialer can assert directly instead of inferring it from a
	// request that would have failed.
	p.mu.Lock()
	for _, addr := range p.dialed {
		if addr != "portal.example:80" {
			t.Errorf("dialed %q, want portal.example:80: the proxy env leaked into the transport", addr)
		}
	}
	p.mu.Unlock()

	// A dead endpoint is an error, not a zero-status observation callers can read.
	_ = p.Close()
	if got, err := portalCheckWithDial(context.Background(), noBody("/generate_204"), p.dial); err == nil ||
		got != (portalObservation{}) {
		t.Errorf("dead endpoint = (%+v, %v), want the zero observation and an error", got, err)
	}
}

// The Date on a clean answer is the only remote clock netdoc gets for free, so
// the round trip has to hand it back verbatim and degrade to the zero time
// rather than to a wrong time when the header is absent or unparsable.
func TestPortalCheckDate(t *testing.T) {
	const stamped = "Sun, 06 Nov 1994 08:49:37 GMT"
	want := time.Date(1994, time.November, 6, 8, 49, 37, 0, time.UTC)

	p := newPipeNet(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dated":
			w.Header().Set("Date", stamped)
		case "/nodate":
			// net/http stamps a Date of its own unless the header is removed.
			w.Header()["Date"] = nil
		case "/baddate":
			w.Header().Set("Date", "the day before yesterday")
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	p.serve(t, srv, func() error { return srv.Serve(p) })

	for _, c := range []struct {
		path string
		want time.Time
	}{
		{"/dated", want},
		{"/nodate", time.Time{}},
		{"/baddate", time.Time{}},
	} {
		ep := portalEndpoint{url: "http://portal.example" + c.path, want: http.StatusNoContent}
		got, err := portalCheckWithDial(context.Background(), ep, p.dial)
		if err != nil || !got.clean {
			t.Fatalf("%s = (%+v, %v), want a clean answer", c.path, got, err)
		}
		if !got.date.Equal(c.want) {
			t.Errorf("%s date = %v, want %v", c.path, got.date, c.want)
		}
	}
}

// Remote time is evidence only when it came from a response that matched what
// the endpoint documents. Anything else was written by whatever answered
// instead, and an interceptor's clock must never be read as the network's.
// Endpoint order breaks a tie between two clean answers, so the reading stays
// the Google-derived one whenever that endpoint answered cleanly.
func TestInternetProbeClockOffset(t *testing.T) {
	dialOK := func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }
	ifaces := func() ([]net.Interface, error) { return nil, nil }
	dated := func(o *portalObservation, at time.Time) *portalObservation {
		o.date = at
		return o
	}
	now := time.Now()
	behind, ahead := now.Add(-3*time.Hour), now.Add(2*time.Hour)

	cases := []struct {
		name         string
		google, ncsi *portalObservation
		want         time.Duration
	}{
		{name: "clean google with a date", google: dated(cleanAnswer(204), behind), want: 3 * time.Hour},
		{name: "clean google without a date", google: cleanAnswer(204)},
		{name: "intercepted google with a date", google: dated(seenAnswer(302, ""), behind), ncsi: cleanAnswer(200)},
		{name: "interception answering 200 with a date", google: dated(seenAnswer(200, ""), behind), ncsi: cleanAnswer(200)},
		// The other endpoint is a clean observation too, so its clock counts
		// when it is the only clean one on the pass.
		{name: "other endpoint clean with a date", google: dated(seenAnswer(302, ""), ahead), ncsi: dated(cleanAnswer(200), behind), want: 3 * time.Hour},
		{name: "unavailable google, clean other", ncsi: dated(cleanAnswer(200), behind), want: 3 * time.Hour},
		// Both clean and both dated: endpoint order decides, so the reading is
		// the one netdoc has always taken.
		{name: "both clean and dated", google: dated(cleanAnswer(204), behind), ncsi: dated(cleanAnswer(200), ahead), want: 3 * time.Hour},
		{name: "both unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &netops{dialContext: dialOK, interfaces: ifaces, portalCheck: portalAnswers(t, c.google, c.ncsi)}
			got := o.internetProbe(context.Background(), nil).clockOffset
			if c.want == 0 {
				if got != 0 {
					t.Errorf("clockOffset = %v, want no reading", got)
				}
				return
			}
			// The offset carries one in-process round trip, so it is exact to
			// far better than the minute of slack allowed here.
			if diff := (got - c.want).Abs(); diff > time.Minute {
				t.Errorf("clockOffset = %v, want about %v", got, c.want)
			}
		})
	}
}

// pipeNet is a net.Listener whose connections come from net.Pipe: dial hands
// the caller the client end and queues the server end for Accept. Real HTTP,
// TLS, ALPN and h2 framing included, runs over it without binding a port, so
// the round trips stay deterministic and independent of host network state.
// A closed pipeNet refuses dials, which is this fake's "connection refused".
type pipeNet struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once

	mu     sync.Mutex
	dialed []string
}

func newPipeNet(t testing.TB) *pipeNet {
	p := &pipeNet{conns: make(chan net.Conn), closed: make(chan struct{})}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func (p *pipeNet) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.closed:
		return nil, net.ErrClosed
	}
}

func (p *pipeNet) Close() error { p.once.Do(func() { close(p.closed) }); return nil }

// Addr is never read for routing; net.Pipe supplies the conns' own addresses.
func (p *pipeNet) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "pipe"} }

// dial is the netops.dialContext stand-in. It records the address it was asked
// for, the only way to tell a proxied request from a direct one when the
// transport's destination no longer decides where the bytes go.
func (p *pipeNet) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	p.mu.Lock()
	p.dialed = append(p.dialed, addr)
	p.mu.Unlock()

	client, server := net.Pipe()
	select {
	case p.conns <- server:
		return client, nil
	case <-p.closed:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
}

// serve runs srv on this listener until the test ends. Callers pass run so a
// TLS server can go through http.Server.ServeTLS, which is what installs the
// h2 next-proto handler that a hand-rolled tls.Server would miss.
func (p *pipeNet) serve(t testing.TB, srv *http.Server, run func() error) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		// A serve loop that has stopped must stop accepting too, or the next
		// dial parks on an unbuffered channel until the whole package times out
		// and buries the error that stopped it.
		defer func() { _ = p.Close() }()
		if err := run(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
}

// selfSignedCert mints a throwaway leaf for hosts plus the pool that trusts it,
// so a TLS round trip needs neither fixture files nor the host's trust store.
// More than one name is for a fixture that has to answer as several endpoints
// on one listener; the first is the subject.
func selfSignedCert(t testing.TB, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}

// The untouched default has to survive a host that has only one working address
// family. Before the second-opinion setting could mean "choose", it named one
// IPv4 resolver, so an IPv6-only machine lost the row to an address it had no
// way to dial while its own DNS and its own Internet worked perfectly. The
// stub below is the network answering per resolver, which is the only thing the
// probe can observe about a family from inside this branch.
func TestPublicDNSDefaultSurvivesAnUnusableAddressFamily(t *testing.T) {
	const v4, v6 = "8.8.8.8", "2001:4860:4860::8888"
	unreachable := errors.New("connect: network is unreachable")
	answer := []net.IP{net.ParseIP("192.0.2.9")}

	for _, tc := range []struct {
		name      string
		reachable string
		wantAsked []string // resolvers dialed, in order
		wantVia   string   // the resolver the row credits
	}{
		{"IPv4 only", v4, []string{v4}, v4},
		{"IPv6 only", v6, []string{v4, v6}, v6},
		{"dual stack takes the first candidate", "", []string{v4}, v4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			ops := &netops{lookupPublicIP: func(_ context.Context, _, server string) ([]net.IP, []string, error) {
				asked = append(asked, server)
				// "" means every resolver answers, which is the dual-stack case.
				if tc.reachable != "" && server != publicDNSServer(tc.reachable) {
					return nil, []string{server}, unreachable
				}
				return answer, []string{server}, nil
			}}
			r := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(DefaultPublicDNS, true))(context.Background(), nil)

			if r.Status != StatusPass || len(r.Addrs) != 1 || !r.Addrs[0].Equal(answer[0]) {
				t.Fatalf("result = %+v, want a passing second opinion", r)
			}
			var want []string
			for _, resolver := range tc.wantAsked {
				want = append(want, publicDNSServer(resolver))
			}
			if !slices.Equal(asked, want) {
				t.Errorf("dialed %v, want %v", asked, want)
			}
			// Every resolver dialed is attempt evidence; only the one that
			// answered may be credited with the answer.
			if !slices.Equal(r.ResolverTargets, want) {
				t.Errorf("resolver targets = %v, want %v", r.ResolverTargets, want)
			}
			if r.resolver != tc.wantVia || !strings.Contains(r.Detail, "via "+tc.wantVia) {
				t.Errorf("result = %+v, want the answer credited to %s alone", r, tc.wantVia)
			}
			for _, resolver := range []string{v4, v6} {
				if resolver != tc.wantVia && strings.Contains(r.Detail, "via "+resolver) {
					t.Errorf("detail = %q, credits %s, which supplied nothing", r.Detail, resolver)
				}
			}
		})
	}
}

// "--public-dns 8.8.8.8" is a choice, not a preference for Google over the
// other family. A user who names a resolver gets that resolver queried and no
// other, even when it is the address the default would have reached for first
// and even when it cannot be reached at all.
func TestExplicitPublicDNSQueriesOnlyWhatItNames(t *testing.T) {
	for _, resolver := range []string{"8.8.8.8", "2001:4860:4860::8888", "9.9.9.9"} {
		t.Run(resolver, func(t *testing.T) {
			var asked []string
			ops := &netops{lookupPublicIP: func(_ context.Context, _, server string) ([]net.IP, []string, error) {
				asked = append(asked, server)
				return nil, []string{server}, errors.New("connect: network is unreachable")
			}}
			r := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(resolver, false))(context.Background(), nil)
			if !slices.Equal(asked, []string{publicDNSServer(resolver)}) {
				t.Errorf("dialed %v, want only %s", asked, publicDNSServer(resolver))
			}
			if r.Status != StatusNA {
				t.Errorf("status = %s, want %s: the named resolver did not answer", r.Status, StatusNA)
			}
		})
	}
}

// An automatic run that reached nobody must still say who it tried. The row is
// N/A either way, and burying one of two failed families in a single-resolver
// sentence would understate what the run actually knows.
func TestPublicDNSReportsEveryResolverItCouldNotReach(t *testing.T) {
	ops := &netops{lookupPublicIP: func(_ context.Context, _, server string) ([]net.IP, []string, error) {
		return nil, []string{server}, errors.New("connect: network is unreachable")
	}}
	r := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(DefaultPublicDNS, true))(context.Background(), nil)
	if r.Status != StatusNA || len(r.Addrs) != 0 || r.DNSNotFound {
		t.Fatalf("result = %+v, want an unavailable row with nothing claimed", r)
	}
	for _, resolver := range PublicDNSCandidates(DefaultPublicDNS, true) {
		if !slices.Contains(r.ResolverTargets, publicDNSServer(resolver)) {
			t.Errorf("resolver targets = %v, want %s among them", r.ResolverTargets, publicDNSServer(resolver))
		}
		if !strings.Contains(r.Detail, resolver) {
			t.Errorf("detail = %q, want %s named as tried", r.Detail, resolver)
		}
	}
}

// A resolver that answered has answered the row, whatever it said. Only an
// unreachable one is worth another family: moving on from an NXDOMAIN would
// shop for a second answer until one agreed, and moving on from a hosts-file
// hit would ask a second server about a file it cannot see either.
func TestPublicDNSStopsAtTheFirstResolverThatAnswered(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
	for _, tc := range []struct {
		name    string
		ips     []net.IP
		targets []string
		err     error
		status  Status
	}{
		{"an answer", []net.IP{net.ParseIP("192.0.2.1")}, []string{"8.8.8.8:53"}, nil, StatusPass},
		{"no such name", nil, []string{"8.8.8.8:53"}, notFound, StatusPass},
		{"a local override", []net.IP{net.ParseIP("192.0.2.1")}, []string{"8.8.8.8:53"}, errHostsFileAnswer, StatusNA},
		{"a lookup that never went out", nil, nil, nil, StatusNA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked := 0
			ops := &netops{lookupPublicIP: func(context.Context, string, string) ([]net.IP, []string, error) {
				asked++
				return tc.ips, tc.targets, tc.err
			}}
			r := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(DefaultPublicDNS, true))(context.Background(), nil)
			if asked != 1 {
				t.Errorf("dialed %d resolvers, want 1: the first one answered", asked)
			}
			if r.Status != tc.status {
				t.Errorf("status = %s, want %s", r.Status, tc.status)
			}
		})
	}
}

// A resolver that is routed but silently dropped answers nothing and reports
// nothing, so a strictly sequential default would spend the row's whole budget
// on it and never reach the family that works. Each automatic candidate gets an
// even share of what is left instead. An explicit resolver keeps the entire
// budget it has always had, because it has nothing to make room for.
func TestPublicDNSDefaultLeavesTimeForTheOtherFamily(t *testing.T) {
	const budget = 200 * time.Millisecond
	for _, tc := range []struct {
		name      string
		auto      bool
		wantAsked int
	}{
		{"the default keeps a share for the second family", true, 2},
		{"an explicit resolver keeps the whole budget", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deadlines []time.Duration
			ops := &netops{lookupPublicIP: func(ctx context.Context, _, server string) ([]net.IP, []string, error) {
				deadline, ok := ctx.Deadline()
				if !ok {
					t.Fatal("attempt ran without a deadline")
				}
				deadlines = append(deadlines, time.Until(deadline))
				<-ctx.Done() // a black hole: nothing comes back until time runs out
				return nil, []string{server}, ctx.Err()
			}}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			start := time.Now()
			r := ops.publicDNSProbe("example.com", nil, PublicDNSCandidates(DefaultPublicDNS, tc.auto))(ctx, nil)

			if len(deadlines) != tc.wantAsked {
				t.Fatalf("dialed %d resolvers, want %d", len(deadlines), tc.wantAsked)
			}
			switch shared := deadlines[0] <= budget*3/4; {
			case tc.wantAsked > 1 && !shared:
				t.Errorf("first attempt held %v of a %v budget, want a share of it", deadlines[0], budget)
			case tc.wantAsked == 1 && shared:
				t.Errorf("first attempt held %v of a %v budget, want all of it", deadlines[0], budget)
			}
			if elapsed := time.Since(start); elapsed > 2*budget {
				t.Errorf("row took %v, want the probe budget of %v to bound every attempt", elapsed, budget)
			}
			if r.Status != StatusNA {
				t.Errorf("status = %s, want %s", r.Status, StatusNA)
			}
		})
	}
}

// RFC 4253 section 4.2 lets an SSH server send other lines of data before its
// identification string, so the probe must keep reading complete lines instead
// of judging the first one. The byte limit and the read deadline still bound
// the search, and a line that only mentions "SSH-" is not an identification.
func TestBannerProbeSSHPreliminaryLines(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   Status
		detail string
	}{
		{
			name:   "identification first",
			server: "SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "one preliminary line",
			server: "Authorized use only\r\nSSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "multiple preliminary lines",
			server: "Authorized use only\r\nAll activity is logged\r\n\r\nSSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "preliminary lines then EOF",
			server: "Authorized use only\r\nAll activity is logged\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: Authorized use only",
		},
		{
			name:   "byte limit reached before identification",
			server: strings.Repeat("All activity is logged\r\n", 50) + "SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: All activity is logged",
		},
		{
			// The preliminary line leaves 6 bytes of the 1024-byte budget, so
			// the identification arrives as a delimiterless "SSH-2." fragment.
			name:   "identification truncated by the byte limit",
			server: strings.Repeat("x", 1016) + "\r\n" + "SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: " + strings.Repeat("x", 1016),
		},
		{
			// The same boundary one byte the other way: the identification and
			// its CRLF land exactly on the 1024th byte, so it still counts.
			name:   "identification ends exactly on the byte limit",
			server: strings.Repeat("x", 1001) + "\r\n" + "SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "misleading preliminary text is not an identification",
			server: "this host speaks SSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: this host speaks SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "misleading preliminary text before the identification",
			server: "this host speaks SSH-2.0-OpenSSH_8.9\r\nSSH-2.0-OpenSSH_9.7\r\n",
			want:   StatusPass,
			detail: "banner: SSH-2.0-OpenSSH_9.7",
		},
		{
			name:   "wrong protocol banner stays rejected",
			server: "220 mail.example ESMTP\r\n",
			want:   StatusFail,
			detail: "unexpected service banner: 220 mail.example ESMTP",
		},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
				return &scriptConn{r: strings.NewReader(tt.server)}, nil
			}}
			r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(context.Background(), deps)
			if r.Status != tt.want || r.Detail != tt.detail {
				t.Errorf("status = %v, detail = %q, want %v %q", r.Status, r.Detail, tt.want, tt.detail)
			}
		})
	}
}

// RFC 4253 section 4.2 defines the identification string as
// "SSH-protoversion-softwareversion SP comments CR LF". Once a line starts with
// "SSH-" it claims to be that string, so malformed syntax fails instead of
// being skipped as a preliminary line.
func TestBannerProbeSSHIdentificationSyntax(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   Status
	}{
		{"SSH 2.0", "SSH-2.0-OpenSSH_9.7\r\n", StatusPass},
		{"SSH 2.0 with comments", "SSH-2.0-OpenSSH_9.7 Ubuntu-7ubuntu4\r\n", StatusPass},
		{"SSH 2.0 with empty comments", "SSH-2.0-OpenSSH_9.7 \r\n", StatusPass},
		{"compat 1.99", "SSH-1.99-OpenSSH_3.9p1\r\n", StatusPass},
		{"legacy 1.5", "SSH-1.5-Cisco-1.25\r\n", StatusPass},
		{"dash inside software version, as real devices send", "SSH-2.0-Cisco-1.25\r\n", StatusPass},
		{"bare LF", "SSH-2.0-test\n", StatusPass},
		// "SSH-2.0-" is 8 bytes; the x run fills the rest. Limit is 255 bytes on the wire.
		{"253 bytes + CRLF = 255", "SSH-2.0-" + strings.Repeat("x", 245) + "\r\n", StatusPass},
		{"254 bytes + CRLF = 256", "SSH-2.0-" + strings.Repeat("x", 246) + "\r\n", StatusFail},
		{"254 bytes + LF = 255", "SSH-2.0-" + strings.Repeat("x", 246) + "\n", StatusPass},
		{"255 bytes + LF = 256", "SSH-2.0-" + strings.Repeat("x", 247) + "\n", StatusFail},
		{"prefix only", "SSH-\r\n", StatusFail},
		{"garbage", "SSH-garbage\r\n", StatusFail},
		{"missing software version", "SSH-2.0\r\n", StatusFail},
		{"empty software version", "SSH-2.0-\r\n", StatusFail},
		{"empty software version with comments", "SSH-2.0- comment\r\n", StatusFail},
		{"empty protocol version", "SSH--OpenSSH_9.7\r\n", StatusFail},
		{"protocol version without minor", "SSH-2-OpenSSH_9.7\r\n", StatusFail},
		{"protocol version with letters", "SSH-two.zero-OpenSSH_9.7\r\n", StatusFail},
		{"protocol version with empty minor", "SSH-2.-OpenSSH_9.7\r\n", StatusFail},
		{"space in protocol version", "SSH-2.0 -OpenSSH_9.7\r\n", StatusFail},
		{"control byte in software version", "SSH-2.0-Open\x00SSH\r\n", StatusFail},
		{"non-ASCII byte in software version", "SSH-2.0-Open\x80SSH\r\n", StatusFail},
		{"non-ASCII byte in protocol version", "SSH-2.\x80-OpenSSH_9.7\r\n", StatusFail},
		{"non-ASCII byte in comments", "SSH-2.0-OpenSSH_9.7 caf\xc3\xa9\r\n", StatusPass},
		{"extra CR before LF", "SSH-2.0-OpenSSH_9.7\r\r\n", StatusFail},
		{"extra CR at the length limit", "SSH-2.0-" + strings.Repeat("x", 245) + "\r\r\n", StatusFail},
		{"preliminary text then valid", "Authorized use only\r\nSSH-2.0-OpenSSH_9.7\r\n", StatusPass},
		{"preliminary text then malformed", "Authorized use only\r\nSSH-garbage\r\n", StatusFail},
		{"valid after malformed is not reached", "SSH-garbage\r\nSSH-2.0-OpenSSH_9.7\r\n", StatusFail},
		{"SMTP greeting", "220 mail.example ESMTP\r\n", StatusFail},
	}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
				return &scriptConn{r: strings.NewReader(tt.server)}, nil
			}}
			r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(context.Background(), deps)
			if r.Status != tt.want {
				t.Errorf("status = %v (%q), want %v", r.Status, r.Detail, tt.want)
			}
		})
	}
}

// The read deadline is set once, before the first line, so a server that sends
// a preliminary line and then stalls cannot stretch the probe: the search for
// the identification string ends at the same deadline as a single read.
func TestBannerProbeSSHPreliminaryLineStallHonorsDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() { _, _ = server.Write([]byte("Authorized use only\r\n")) }()
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(ctx, deps)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("banner probe took %v, want the read deadline to cap the line search", elapsed)
	}
	if r.Status != StatusFail || r.Detail != "unexpected service banner: Authorized use only" {
		t.Errorf("stalled server = %+v, want FAIL naming the preliminary line", r)
	}
}

// A deadline that lands mid-identification truncates the line the same way the
// byte limit does, and a truncated line is not an identification string either.
func TestBannerProbeSSHTruncatedIdentificationAtDeadline(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	go func() { _, _ = server.Write([]byte("Authorized use only\r\nSSH-2.")) }()
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return client, nil
	}}
	deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	r := ops.bannerProbe(ProbeSSH, "SSH banner", "", 22).Run(ctx, deps)
	if r.Status != StatusFail || r.Detail != "unexpected service banner: Authorized use only" {
		t.Errorf("identification cut off by the deadline = %+v, want FAIL", r)
	}
}

// Issue #106: a discrepant endpoint is reported as what it answered, and the
// two ways an answer can differ are different observations. A correct status
// carrying the wrong payload is the case the documented body exists to catch,
// and reporting it as a status mismatch produced the nonsense "answered 200,
// want 200" for exactly the endpoint the check is about.
//
// The run underneath every case is a healthy one: both families dial, both
// reference endpoints answer, and one connectivity endpoint is the only thing
// that differs. So each case also pins what that row may not turn into, which
// is a portal claim, a broken path, or a failure.
func TestInternetProbeSaysWhichPartOfAnEndpointAnswerDiffered(t *testing.T) {
	dialOK := func(context.Context, string, string) (net.Conn, error) { return fakeConn{}, nil }
	ifaces := func() ([]net.Interface, error) { return nil, nil }
	ncsi := portalEndpoints[1]

	for _, c := range []struct {
		name    string
		answer  *portalObservation
		want    string
		notWant string
	}{
		{
			// The reported case: HTTP 200 is what this endpoint documents, and
			// the payload under it was not.
			name:    "documented status with an undocumented body",
			answer:  &portalObservation{code: ncsi.want},
			want:    ncsi.url + " answered 200 with an unexpected response body",
			notWant: "answered 200, want 200",
		},
		{
			name:    "undocumented status",
			answer:  seenAnswer(http.StatusFound, ""),
			want:    ncsi.url + " answered 302, want 200",
			notWant: "unexpected response body",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := &netops{dialContext: dialOK, interfaces: ifaces,
				portalCheck: portalAnswers(t, cleanAnswer(http.StatusNoContent), c.answer)}
			r := o.internetProbe(context.Background(), nil)
			if r.Status != StatusWarn {
				t.Fatalf("status = %v, want WARN (detail %q)", r.Status, r.Detail)
			}
			if !strings.Contains(r.Detail, c.want) {
				t.Errorf("detail = %q, want it to contain %q", r.Detail, c.want)
			}
			if strings.Contains(r.Detail, c.notWant) {
				t.Errorf("detail = %q, want it not to describe the discrepancy as %q", r.Detail, c.notWant)
			}
			// The dials are the egress evidence, and they all succeeded: the
			// row has to keep saying so beside the discrepancy.
			if r.Portal != nil {
				t.Errorf("portal evidence = %+v, want none from one endpoint", r.Portal)
			}
			if r.Families == nil || r.Families.IPv4 != FamilyReachable || r.Families.IPv6 != FamilyReachable {
				t.Errorf("families = %+v, want both reachable", r.Families)
			}
			if !strings.Contains(r.Detail, "IPv4 egress via") || !directEgressOK(map[ProbeID]ProbeResult{ProbeInternet: r}) {
				t.Errorf("row stopped representing working direct egress: %+v", r)
			}
			// The one piece of structured state the diagnosis reads, so it
			// never has to parse the sentence above.
			if r.Cause != ConnectivityCauseUnexpectedResponse {
				t.Errorf("cause = %q, want %q", r.Cause, ConnectivityCauseUnexpectedResponse)
			}

			order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS}
			res := map[ProbeID]ProbeResult{
				ProbeIface:    {ID: ProbeIface, Status: StatusPass},
				ProbeInternet: r,
				ProbeDNS:      {ID: ProbeDNS, Status: StatusPass, Addrs: []net.IP{net.ParseIP("192.0.2.1")}},
			}
			d := Interpret(nil, order, res)
			const want = "Online but degraded: one connectivity check returned an unexpected response (see the ! row for details)."
			if d.Summary != want {
				t.Errorf("summary:\n got %q\nwant %q", d.Summary, want)
			}
			if d.Verdict != VerdictDegraded {
				t.Errorf("verdict = %q, want %q", d.Verdict, VerdictDegraded)
			}
			for _, f := range d.Findings {
				if f.ID == DiagnosisCaptivePortal {
					t.Errorf("one discrepant endpoint produced %q", f.ID)
				}
			}
			// No row failed, which is what ok and the exit code are read from.
			for id, row := range res {
				if row.Status == StatusFail {
					t.Errorf("%s failed, so this run would no longer report ok", id)
				}
			}

			// The sentence is recomputed from the artifact, so the evidence
			// that distinguishes it has to survive the .ndoc boundary. Cause
			// already crosses it, which is why nothing new was stored.
			probes := make([]Probe, len(order))
			for i, id := range order {
				probes[i] = Probe{ID: id, Name: string(id)}
			}
			data, err := snapshot.Encode(withSnapshotProvenance(BuildSnapshot(nil, probes, timedResults(res))))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if replayed.Summary != want {
				t.Errorf("replayed summary:\n got %q\nwant %q", replayed.Summary, want)
			}
		})
	}
}

// pipeHTTPServer is a netops.dialContext whose far end reads the request's
// header block and then hands the connection to respond. Everything happens
// over net.Pipe, so nothing binds a port and nothing waits on a clock.
func pipeHTTPServer(respond func(net.Conn)) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			br := bufio.NewReader(server)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			respond(server)
		}()
		return client, nil
	}
}

// eofResetConn reads a clean close as a TCP reset, which net.Pipe cannot
// produce, wrapped the way the kernel error reaches the transport.
type eofResetConn struct{ net.Conn }

func (c eofResetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if errors.Is(err, io.EOF) {
		err = &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}
	}
	return n, err
}

// Issue #212: silence, a close or reset before any response, and response
// bytes that cannot be read as HTTP are different failures, and only silence
// may be described as no response or a held request. Bytes arriving outrank how
// the connection then ended, so a reset after them is still an invalid
// response. An HTTP error status is still a response.
func TestHTTPProbeDistinguishesFailuresBeforeAResponse(t *testing.T) {
	cases := []struct {
		name     string
		respond  func(net.Conn)
		reset    bool
		timeout  time.Duration
		status   Status
		cause    string
		timedOut bool
		id       DiagnosisID
		says     string
	}{
		{name: "invalid status line", respond: func(c net.Conn) { _, _ = c.Write([]byte("THIS IS NOT HTTP\r\n\r\n")) },
			status: StatusFail, cause: HTTPCauseInvalidResponse, id: DiagnosisInvalidHTTPResponse, says: "answered"},
		{name: "oversized headers", respond: func(c net.Conn) {
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", 128<<10) + "\r\n\r\n"))
		}, status: StatusFail, cause: HTTPCauseInvalidResponse, id: DiagnosisInvalidHTTPResponse, says: "answered"},
		{name: "reset after response bytes", respond: func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 200")) }, reset: true,
			status: StatusFail, cause: HTTPCauseInvalidResponse, id: DiagnosisInvalidHTTPResponse, says: "answered"},
		{name: "silence", respond: func(c net.Conn) { _, _ = c.Read(make([]byte, 1)) }, timeout: 100 * time.Millisecond,
			status: StatusFail, timedOut: true, id: DiagnosisHTTPNoResponse, says: "No HTTP response"},
		// The deadline ends it, but bytes already arrived: still an answer,
		// and still a timeout.
		{name: "response bytes then silence", respond: func(c net.Conn) {
			_, _ = c.Write([]byte("HTTP/1.1 200"))
			_, _ = c.Read(make([]byte, 1))
		}, timeout: 100 * time.Millisecond,
			status: StatusFail, cause: HTTPCauseInvalidResponse, timedOut: true, id: DiagnosisInvalidHTTPResponse, says: "answered"},
		{name: "clean close", respond: func(net.Conn) {},
			status: StatusFail, cause: ConnectionCauseClosed, id: DiagnosisHTTPConnectionClosed, says: "then closed it"},
		{name: "reset", respond: func(net.Conn) {}, reset: true,
			status: StatusFail, cause: ConnectionCauseReset, id: DiagnosisHTTPConnectionClosed, says: "then reset it"},
		{name: "404", respond: func(c net.Conn) { _, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")) },
			status: StatusPass},
	}
	silent := func(s string) bool {
		s = strings.ToLower(s)
		return strings.Contains(s, "no http response") || strings.Contains(s, "holding")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dial := pipeHTTPServer(tc.respond)
			ops := &netops{dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := dial(ctx, network, addr)
				if tc.reset {
					c = eofResetConn{c}
				}
				return c, err
			}}
			deps := map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}}
			timeout := cmp.Or(tc.timeout, 5*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			r := ops.httpProbe("example.com", 80, "http", ProbeTargetTCP, nil)(ctx, deps)
			if r.Status != tc.status || r.Cause != tc.cause || r.timedOut != tc.timedOut {
				t.Fatalf("result = %+v (timedOut %v), want status %v cause %q timedOut %v", r, r.timedOut, tc.status, tc.cause, tc.timedOut)
			}
			if r.Status == StatusPass {
				return
			}
			target := &Target{Raw: "example.com", Host: "example.com", Port: 80, Proto: ProtoHTTP}
			order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeHTTP}
			res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
				ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass}, ProbeHTTP: r}
			d := Interpret(target, order, res)
			rem, _ := Remediate(d, res, "linux")
			if d.Findings[0].ID != tc.id || !strings.Contains(d.Summary, tc.says) {
				t.Errorf("finding %s %q, want %s saying %q", d.Findings[0].ID, d.Summary, tc.id, tc.says)
			}
			if got, want := silent(d.Summary) || silent(rem.Why), tc.id == DiagnosisHTTPNoResponse; got != want {
				t.Errorf("summary %q / remediation %q: claims silence = %v, want %v", d.Summary, rem.Why, got, want)
			}
			// A timeout, whatever arrived before it, is half of the path-MTU
			// correlation; an immediate failure is not.
			res[ProbePMTU] = ProbeResult{Status: StatusWarn}
			order = append(order, ProbePMTU)
			if got := Interpret(target, order, res).Findings[0].ID == DiagnosisProbablePathMTU; got != tc.timedOut {
				t.Errorf("with a PMTU warning, path-MTU finding = %v, want %v", got, tc.timedOut)
			}
		})
	}
}

// HTTPS gets the same classification from decrypted application bytes, never
// from the TLS records that carried the handshake.
func TestHTTPSProbeDistinguishesFailuresBeforeAResponse(t *testing.T) {
	const host = "invalid.example"
	cert, roots := selfSignedCert(t, host)
	for _, tc := range []struct {
		name  string
		reply string
		cause string
		stall bool
	}{
		{"invalid", "THIS IS NOT HTTP\r\n\r\n", HTTPCauseInvalidResponse, false},
		{"clean close", "", ConnectionCauseClosed, false},
		{"response bytes then silence", "HTTP/1.1 200", HTTPCauseInvalidResponse, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &netops{tlsRootCAs: roots, dialContext: func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
					defer func() { _ = conn.Close() }()
					if _, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
						_, _ = conn.Write([]byte(tc.reply))
						// Wait for the client to close first: on a net.Pipe two
						// close_notify alerts with no reader block for 5s.
						if tc.reply != "" {
							_, _ = io.Copy(io.Discard, conn)
						}
					}
				}()
				return client, nil
			}}
			timeout := 5 * time.Second
			if tc.stall {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			r := ops.httpProbe(host, 443, "https", ProbeTLS, nil)(ctx, map[ProbeID]ProbeResult{ProbeTLS: {SelectedIP: net.ParseIP("192.0.2.10")}})
			if r.Status != StatusFail || r.Cause != tc.cause || r.timedOut != tc.stall {
				t.Fatalf("HTTPS %s = %+v, want FAIL with %q", tc.name, r, tc.cause)
			}
		})
	}
}

// The HTTP/2 transport reports a clean close before response headers as
// io.ErrUnexpectedEOF, not io.EOF; it is still a close, not silence.
func TestHTTP2ProbeCloseBeforeHeadersIsAClose(t *testing.T) {
	const host = "h2.example"
	cert, roots := selfSignedCert(t, host)
	negotiated := make(chan string, 1)
	ops := &netops{tlsRootCAs: roots, dialContext: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
			defer func() { _ = conn.Close() }()
			if conn.Handshake() != nil {
				return
			}
			negotiated <- conn.ConnectionState().NegotiatedProtocol
			// Read the client preface, then frames until the request's
			// HEADERS, and close without sending a frame back.
			if _, err := io.ReadFull(conn, make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))); err != nil {
				return
			}
			for {
				var hdr [9]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil {
					return
				}
				n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
				if _, err := io.ReadFull(conn, make([]byte, n)); err != nil || hdr[3] == 0x1 {
					return
				}
			}
		}()
		return client, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := ops.httpProbe(host, 443, "https", ProbeTLS, nil)(ctx, map[ProbeID]ProbeResult{ProbeTLS: {SelectedIP: net.ParseIP("192.0.2.10")}})
	if proto := <-negotiated; proto != "h2" {
		t.Fatalf("negotiated %q, want h2", proto)
	}
	// connection_closed ranks below the answered branch, so it also proves
	// no response byte was seen.
	if r.Status != StatusFail || r.Cause != ConnectionCauseClosed || r.timedOut {
		t.Fatalf("result = %+v (timedOut %v), want FAIL with %q", r, r.timedOut, ConnectionCauseClosed)
	}
	target := &Target{Raw: host, Host: host, Port: 443, Proto: ProtoTLSHTTP}
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbeTLS, ProbeHTTPS}
	res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
		ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass}, ProbeTLS: {Status: StatusPass}, ProbeHTTPS: r}
	d := Interpret(target, order, res)
	rem, _ := Remediate(d, res, "linux")
	if d.Findings[0].ID != DiagnosisHTTPConnectionClosed || !strings.Contains(d.Summary, "closed the connection") {
		t.Errorf("finding %s %q, want %s describing a close", d.Findings[0].ID, d.Summary, DiagnosisHTTPConnectionClosed)
	}
	for _, s := range []string{d.Summary, rem.Why} {
		if s = strings.ToLower(s); strings.Contains(s, "no http response") || strings.Contains(s, "holding") {
			t.Errorf("%q describes silence, want a close", s)
		}
	}
}

// h2Frame encodes one HTTP/2 frame for a test server to write raw.
func h2Frame(typ, flags byte, stream uint32, payload ...byte) []byte {
	//nolint:gosec // G115: test payloads are a few bytes, far under the 24-bit length field.
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags}
	return append(binary.BigEndian.AppendUint32(b, stream), payload...)
}

// Issue #216: the HTTP/2 transport reports the first response byte only once a
// whole header block decodes, so a frame on the request's stream that never
// completes one is still the endpoint answering. Frames that manage the
// connection, or that touch the stream without carrying a response, are not.
func TestHTTP2ProbeSeparatesResponseFramesFromSilence(t *testing.T) {
	const host = "h2.example"
	cert, roots := selfSignedCert(t, host)
	settings := h2Frame(0x4, 0, 0)
	ping := h2Frame(0x6, 0, 0, make([]byte, 8)...)
	window := h2Frame(0x8, 0, 0, 0, 0, 0x10, 0)
	// 0x88 is the HPACK static entry for ":status: 200".
	headers := h2Frame(0x1, 0x5, 1, 0x88)
	for _, tc := range []struct {
		name   string
		writes [][]byte
		// end is how the server finishes after its writes: close, reset, or
		// stall until the probe deadline.
		end      string
		status   Status
		cause    string
		timedOut bool
	}{
		{"silence", nil, "stall", StatusFail, "", true},
		{"connection frames then silence", [][]byte{settings, ping, window}, "stall", StatusFail, "", true},
		{"connection frames then close", [][]byte{settings, ping, window}, "close", StatusFail, ConnectionCauseClosed, false},
		{"stream window update then close", [][]byte{settings, h2Frame(0x8, 0, 1, 0, 0, 0x10, 0)}, "close", StatusFail, ConnectionCauseClosed, false},
		{"stream reset", [][]byte{settings, h2Frame(0x3, 0, 1, 0, 0, 0, 0x1)}, "stall", StatusFail, "", false},
		{"valid headers", [][]byte{settings, headers}, "stall", StatusPass, "", false},
		{"headers frame header then close", [][]byte{settings, headers[:9]}, "close", StatusFail, HTTPCauseInvalidResponse, false},
		{"headers split into single bytes then close", slices.Collect(func(yield func([]byte) bool) {
			for i := range headers[:9] {
				if !yield(headers[i : i+1]) {
					return
				}
			}
		}), "close", StatusFail, HTTPCauseInvalidResponse, false},
		{"connection frames and headers frame header in one write", [][]byte{slices.Concat(settings, ping, headers[:9])}, "close", StatusFail, HTTPCauseInvalidResponse, false},
		// An extension frame is skipped whole, even when its payload looks
		// like a response frame header.
		{"extension frame payload is not a frame", [][]byte{settings, h2Frame(0xb, 0, 1, headers[:9]...)}, "close", StatusFail, ConnectionCauseClosed, false},
		{"header block never ends then close", [][]byte{settings, h2Frame(0x1, 0x1, 1, 0x88)}, "close", StatusFail, HTTPCauseInvalidResponse, false},
		{"undecodable header block", [][]byte{settings, h2Frame(0x1, 0x5, 1, 0xff)}, "stall", StatusFail, HTTPCauseInvalidResponse, false},
		{"data before headers", [][]byte{settings, h2Frame(0x0, 0x1, 1, 'x')}, "stall", StatusFail, HTTPCauseInvalidResponse, false},
		{"headers frame header then reset", [][]byte{settings, headers[:9]}, "reset", StatusFail, HTTPCauseInvalidResponse, false},
		{"headers frame header then silence", [][]byte{settings, headers[:9]}, "stall", StatusFail, HTTPCauseInvalidResponse, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			negotiated := make(chan string, 1)
			ops := &netops{tlsRootCAs: roots, dialContext: func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() {
					conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
					defer func() { _ = conn.Close() }()
					if conn.Handshake() != nil {
						return
					}
					negotiated <- conn.ConnectionState().NegotiatedProtocol
					if _, err := io.ReadFull(conn, make([]byte, len("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))); err != nil {
						return
					}
					// Read frames until the request's HEADERS, which must open
					// stream 1, then answer on that stream.
					for {
						var hdr [9]byte
						if _, err := io.ReadFull(conn, hdr[:]); err != nil {
							return
						}
						n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
						if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
							return
						}
						if hdr[3] == 0x1 {
							if id := binary.BigEndian.Uint32(hdr[5:]); id != 1 {
								t.Errorf("request opened stream %d, want 1", id)
							}
							break
						}
					}
					drained := make(chan struct{})
					go func() { _, _ = io.Copy(io.Discard, conn); close(drained) }()
					for _, w := range tc.writes {
						if _, err := conn.Write(w); err != nil {
							return
						}
					}
					switch tc.end {
					case "stall":
						<-drained
					case "reset":
						// Drop the transport without a close_notify, so the
						// client reads EOF and eofResetConn turns it into a reset.
						_ = server.Close()
					}
				}()
				if tc.end == "reset" {
					return eofResetConn{client}, nil
				}
				return client, nil
			}}
			timeout := 5 * time.Second
			if tc.end == "stall" {
				timeout = 500 * time.Millisecond
			}
			var firstByte atomic.Bool
			trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.Store(true) }}
			ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(context.Background(), trace), timeout)
			defer cancel()
			r := ops.httpProbe(host, 443, "https", ProbeTLS, nil)(ctx, map[ProbeID]ProbeResult{ProbeTLS: {SelectedIP: net.ParseIP("192.0.2.10")}})
			if proto := <-negotiated; proto != "h2" {
				t.Fatalf("negotiated %q, want h2", proto)
			}
			if r.Status != tc.status || r.Cause != tc.cause || r.timedOut != tc.timedOut {
				t.Fatalf("result = %+v (timedOut %v, GotFirstResponseByte %v), want status %v cause %q timedOut %v",
					r, r.timedOut, firstByte.Load(), tc.status, tc.cause, tc.timedOut)
			}
		})
	}
}

// The TLS probe dials its own TCP connection, so a timeout can come from that
// dial before any handshake starts. The endpoint row passing does not prove
// the TLS probe's connection opened, so no text may say it did.
func TestTLSDialTimeoutSummaryIsStageNeutral(t *testing.T) {
	c := matrixCaseNamed(t, "TLS timed out with a healthy path")
	ops := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	}}
	res := maps.Clone(c.res)
	res[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP("192.0.2.1")}
	res[ProbeTLS] = ops.tlsProbe("example.com", 443, nil)(context.Background(), res)
	if res[ProbeTLS].Cause != TLSCauseTimeout {
		t.Fatalf("dial timeout cause = %q, want %q", res[ProbeTLS].Cause, TLSCauseTimeout)
	}
	if r := res[ProbeTLS]; !strings.HasPrefix(r.Detail, "TLS check to 192.0.2.1 failed:") || strings.Contains(r.Fix, "TCP connected") ||
		!strings.Contains(r.Fix, "Path MTU row") {
		t.Errorf("TLS row detail %q, fix %q: want a stage-neutral detail and a Path MTU hint", r.Detail, r.Fix)
	}
	d := Interpret(c.target, c.order, res)
	if len(d.Findings) == 0 || d.Findings[0].ID != DiagnosisTLSTimeout {
		t.Fatalf("findings = %+v, want %s", d.Findings, DiagnosisTLSTimeout)
	}
	rem, _ := Remediate(d, res, "linux")
	if !strings.Contains(rem.Why, "endpoint TCP check reached") || !strings.Contains(rem.Why, "own connection") ||
		!strings.Contains(strings.Join(rem.Steps, " "), "Path MTU row") {
		t.Errorf("remediation why %q, steps %q: want the endpoint check, the TLS check's own connection, and the Path MTU row", rem.Why, rem.Steps)
	}
	for _, overclaim := range []string{"TCP connected", "the handshake spent"} {
		if strings.Contains(rem.Why, overclaim) {
			t.Errorf("remediation why %q claims %q", rem.Why, overclaim)
		}
	}
	if !strings.Contains(d.Summary, "reaches example.com:443") || !strings.Contains(d.Summary, "TLS check times out") {
		t.Errorf("summary %q does not say the endpoint check reached the host and the TLS check timed out", d.Summary)
	}
	for _, overclaim := range []string{"after the connection opens", "handshake times out"} {
		if strings.Contains(d.Summary, overclaim) {
			t.Errorf("summary %q claims %q for a timeout that may have come from the TLS probe's own dial", d.Summary, overclaim)
		}
	}
}

// The TLS probe's own TCP dial timing out is not a TLS exchange stalling, so
// only a handshake that timed out on a connection the probe opened is half of
// the path-MTU correlation. A passing endpoint row is a separate connection
// and proves nothing about this one. The cases run the production dialTLS
// around a scripted dial, so the stage comes from where the probe failed.
func TestTLSTimeoutJoinsPathMTUCorrelationOnlyAfterConnecting(t *testing.T) {
	cases := []struct {
		name        string
		dial        func(context.Context, string, string) (net.Conn, error)
		cause       string
		stalled     bool
		withPMTU    DiagnosisID
		withoutPMTU DiagnosisID
	}{
		{name: "dial timeout", dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
		}, cause: TLSCauseTimeout, withPMTU: DiagnosisTLSTimeout, withoutPMTU: DiagnosisTLSTimeout},
		{name: "handshake timeout", dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() { _, _ = io.Copy(io.Discard, server) }()
			return client, nil
		}, cause: TLSCauseTimeout, stalled: true, withPMTU: DiagnosisProbablePathMTU, withoutPMTU: DiagnosisTLSTimeout},
		{name: "dial refused", dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
		}, cause: TLSCauseTCPUnreachable, withPMTU: DiagnosisTLSTCPUnreachable, withoutPMTU: DiagnosisTLSTCPUnreachable},
		// The far end answering by closing is an answer, never a stall.
		{name: "closed during handshake", dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				// Read the whole ClientHello record, then hang up.
				header := make([]byte, 5)
				if _, err := io.ReadFull(server, header); err == nil {
					_, _ = io.CopyN(io.Discard, server, int64(header[3])<<8|int64(header[4]))
				}
				_ = server.Close()
			}()
			return client, nil
		}, cause: TLSCauseConnectionClosed, withPMTU: DiagnosisTLSConnectionClosed, withoutPMTU: DiagnosisTLSConnectionClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := matrixCaseNamed(t, "TLS timed out with a healthy path")
			ops := &netops{dialTLS: dialTLSWith(tc.dial)}
			res := maps.Clone(c.res)
			res[ProbeTargetTCP] = ProbeResult{Status: StatusPass, SelectedIP: net.ParseIP("192.0.2.1")}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			r := ops.tlsProbe("example.com", 443, nil)(ctx, res)
			if r.Status != StatusFail || r.Cause != tc.cause || r.timedOut != tc.stalled {
				t.Fatalf("TLS result = %+v (timedOut %v), want FAIL with %q and timedOut %v", r, r.timedOut, tc.cause, tc.stalled)
			}
			res[ProbeTLS] = r
			d := Interpret(c.target, c.order, res)
			if d.Findings[0].ID != tc.withoutPMTU {
				t.Errorf("without a PMTU warning, finding = %s, want %s", d.Findings[0].ID, tc.withoutPMTU)
			}
			if tc.cause == TLSCauseTimeout && d.Summary != c.summary {
				t.Errorf("summary = %q, want the stage-neutral %q", d.Summary, c.summary)
			}
			res[ProbePMTU] = ProbeResult{Status: StatusWarn}
			d = Interpret(c.target, c.order, res)
			if d.Findings[0].ID != tc.withPMTU {
				t.Fatalf("with a PMTU warning, finding = %s %q, want %s", d.Findings[0].ID, d.Summary, tc.withPMTU)
			}
			if tc.withPMTU == DiagnosisTLSTimeout && d.Summary != c.summary {
				t.Errorf("summary = %q, want the stage-neutral %q", d.Summary, c.summary)
			}
			if tc.withPMTU == DiagnosisProbablePathMTU && (d.Verdict != VerdictNetwork || d.Findings[0].Focus != ProbePMTU) {
				t.Errorf("verdict %s focus %s, want %s focus %s", d.Verdict, d.Findings[0].Focus, VerdictNetwork, ProbePMTU)
			}
			// Replay recomputes the diagnosis from the artifact alone, so the
			// stage has to travel in it.
			probes := make([]Probe, len(c.order))
			for i, id := range c.order {
				probes[i] = Probe{ID: id, Name: string(id)}
			}
			data, err := snapshot.Encode(withSnapshotProvenance(BuildSnapshot(c.target, probes, timedResults(res))))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := snapshot.Decode(data)
			if err != nil {
				t.Fatal(err)
			}
			replayed, err := ReplaySnapshot(artifact)
			if err != nil {
				t.Fatal(err)
			}
			assertDiagnosisSemantics(t, replayed, d)
		})
	}
	// Marking the stage hides nothing the classifier reads.
	if got := tlsFailureCause(tlsHandshakeError{x509.UnknownAuthorityError{}}, time.Now()); got != TLSCauseUntrustedIssuer {
		t.Errorf("a rejected certificate from the handshake classifies as %q, want %q", got, TLSCauseUntrustedIssuer)
	}
	// A completed handshake records no stall.
	ops := &netops{dialTLS: func(context.Context, string, string, *tls.Config) (net.Conn, error) { return fakeConn{}, nil }}
	r := ops.tlsProbe("example.com", 443, nil)(context.Background(), map[ProbeID]ProbeResult{ProbeTargetTCP: {SelectedIP: net.ParseIP("192.0.2.1")}})
	if r.Status != StatusPass || r.timedOut {
		t.Errorf("successful TLS = %+v (timedOut %v), want PASS with no stall", r, r.timedOut)
	}
}

// An HTTP or HTTPS probe dials its own connection, so its timeout can come
// from that dial before any exchange starts, and a passing endpoint row is a
// separate connection that proves nothing about this one. Only a timeout after
// the exchange began, whether in the TLS handshake the transport runs on the
// connection or in the request itself, is half of the path-MTU correlation.
// The cases run the real httpProbe, so the stage comes from where it failed,
// and a trace on the request shows which stage that was.
func TestHTTPTimeoutJoinsPathMTUCorrelationOnlyAfterConnecting(t *testing.T) {
	const host = "stall.example"
	cert, roots := selfSignedCert(t, host)
	ip := net.ParseIP("192.0.2.10")
	// The transport detaches its dial from the request context and cancels it
	// once the request gives up, so a dial that never connects returns then.
	dialStall := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// The connection opens and the far end reads everything without a word.
	silent := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, server) }()
		return client, nil
	}
	// The TLS handshake completes and the request is read, but never answered.
	tlsSilent := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			conn := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
			_, _ = io.Copy(io.Discard, conn)
		}()
		return client, nil
	}
	for _, tc := range []struct {
		name   string
		scheme string
		dial   func(context.Context, string, string) (net.Conn, error)
		// gotConn and handshake are the trace events the stage implies.
		gotConn, handshake, stalled bool
	}{
		{"HTTP dial", "http", dialStall, false, false, false},
		{"HTTP request", "http", silent, true, false, true},
		{"HTTPS dial", "https", dialStall, false, false, false},
		{"HTTPS handshake", "https", silent, false, true, true},
		{"HTTPS request", "https", tlsSilent, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &netops{tlsRootCAs: roots, dialContext: tc.dial}
			target := &Target{Raw: host, Host: host, Port: 80, Proto: ProtoHTTP}
			id, dep, port, noResponse := ProbeHTTP, ProbeTargetTCP, 80, DiagnosisHTTPNoResponse
			order := []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeHTTP}
			res := map[ProbeID]ProbeResult{ProbeIface: {Status: StatusPass}, ProbeInternet: {Status: StatusPass},
				ProbeDNS: {Status: StatusPass, Addrs: []net.IP{ip}}, ProbeTargetTCP: {Status: StatusPass, SelectedIP: ip}}
			if tc.scheme == "https" {
				target = &Target{Raw: host, Host: host, Port: 443, Proto: ProtoTLSHTTP}
				id, dep, port, noResponse = ProbeHTTPS, ProbeTLS, 443, DiagnosisHTTPSNoResponse
				order = []ProbeID{ProbeIface, ProbeInternet, ProbeDNS, ProbeTargetTCP, ProbePMTU, ProbeTLS, ProbeHTTPS}
				res[ProbeTLS] = ProbeResult{Status: StatusPass, SelectedIP: ip}
			}
			var gotConn, handshake atomic.Bool
			trace := &httptrace.ClientTrace{
				GotConn:           func(httptrace.GotConnInfo) { gotConn.Store(true) },
				TLSHandshakeStart: func() { handshake.Store(true) },
			}
			ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(context.Background(), trace), 500*time.Millisecond)
			defer cancel()
			r := ops.httpProbe(host, port, tc.scheme, dep, nil)(ctx, res)
			if gotConn.Load() != tc.gotConn || handshake.Load() != tc.handshake {
				t.Fatalf("GotConn %v, TLSHandshakeStart %v, want %v, %v", gotConn.Load(), handshake.Load(), tc.gotConn, tc.handshake)
			}
			if r.Status != StatusFail || r.Cause != "" || r.timedOut != tc.stalled {
				t.Fatalf("result = %+v (timedOut %v), want FAIL with no cause and timedOut %v", r, r.timedOut, tc.stalled)
			}
			res[id] = r
			res[ProbePMTU] = ProbeResult{Status: StatusPass}
			if got := Interpret(target, order, res).Findings[0].ID; got != noResponse {
				t.Errorf("without a PMTU warning, finding = %s, want %s", got, noResponse)
			}
			res[ProbePMTU] = ProbeResult{Status: StatusWarn}
			want := noResponse
			if tc.stalled {
				want = DiagnosisProbablePathMTU
			}
			d := Interpret(target, order, res)
			if d.Findings[0].ID != want {
				t.Fatalf("with a PMTU warning, finding = %s %q, want %s", d.Findings[0].ID, d.Summary, want)
			}
			// Replay recomputes the diagnosis from the artifact alone. An
			// artifact written before the stage was told apart may record a
			// dial timeout as a stall, and its missing selected IP still says
			// the probe never connected.
			for _, recorded := range []bool{r.timedOut, true} {
				old := r
				old.timedOut = recorded
				res[id] = old
				probes := make([]Probe, len(order))
				for i, id := range order {
					probes[i] = Probe{ID: id, Name: string(id)}
				}
				data, err := snapshot.Encode(withSnapshotProvenance(BuildSnapshot(target, probes, timedResults(res))))
				if err != nil {
					t.Fatal(err)
				}
				artifact, err := snapshot.Decode(data)
				if err != nil {
					t.Fatal(err)
				}
				replayed, err := ReplaySnapshot(artifact)
				if err != nil {
					t.Fatal(err)
				}
				assertDiagnosisSemantics(t, replayed, d)
			}
		})
	}
}
