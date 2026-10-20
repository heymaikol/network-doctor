package diagnostic

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// publicDNSFixtureConn reuses the in-memory A/AAAA responder, replacing its
// answer with a controlled DNS error when requested. Go still performs the
// real lookup, including retries and DNS error conversion. No sockets open.
type publicDNSFixtureConn struct {
	*splitDNSConn
	rcode  uint16
	mutate func([]byte) []byte
}

func (c *publicDNSFixtureConn) Write(p []byte) (int, error) {
	n, err := c.splitDNSConn.Write(p)
	if err != nil {
		return n, err
	}
	response := c.reply[2:]
	if c.rcode != 0 {
		end, err := skipDNSName(response, dnsHeaderLen)
		if err != nil {
			return 0, err
		}
		response = response[:end+4]
		binary.BigEndian.PutUint16(response[2:4], 0x8180|c.rcode)
		clear(response[6:12])
	}
	if c.mutate != nil {
		response = c.mutate(response)
	}
	if response == nil {
		c.reply = nil
		return n, nil
	}
	// #nosec G115 -- this fixture's bounded header, question and A/AAAA record.
	c.reply = binary.BigEndian.AppendUint16(nil, uint16(len(response)))
	c.reply = append(c.reply, response...)
	return n, nil
}

func (c *publicDNSFixtureConn) Read(p []byte) (int, error) {
	if len(c.reply) == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	return c.splitDNSConn.Read(p)
}

// PacketConn is the Go resolver's signal to use datagrams. Translate framing
// at the fixture boundary so both transports share the same DNS responses.
type publicDNSFixturePacketConn struct{ *publicDNSFixtureConn }

func (c publicDNSFixturePacketConn) Write(p []byte) (int, error) {
	// #nosec G115 -- Go's single-question DNS query is bounded.
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(p)))
	n, err := c.publicDNSFixtureConn.Write(append(framed, p...))
	return max(0, n-2), err
}

func (c publicDNSFixturePacketConn) Read(p []byte) (int, error) {
	if len(c.reply) < 2 {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, c.reply[2:])
	c.reply = nil
	return n, nil
}

func (c publicDNSFixturePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	return n, c.RemoteAddr(), err
}

func (c publicDNSFixturePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

// Split the TCP length prefix as well as the payload across separate reads.
type publicDNSFragmentConn struct{ net.Conn }

func (c publicDNSFragmentConn) Read(p []byte) (int, error) { return c.Conn.Read(p[:min(1, len(p))]) }

func TestPublicDNSServiceErrorKeepsAnsweringResolver(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode uint16
	}{
		{"SERVFAIL", dnsRcodeServFail},
		{"REFUSED", dnsRcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &splitDNSFixture{}
			resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
			var asked []string
			ops := &netops{lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
				asked = append(asked, server)
				return lookupIPPublicWithDial(ctx, host, func(context.Context, string, string) (net.Conn, error) {
					rcode := uint16(0)
					if server == publicDNSServer(resolvers[0]) {
						rcode = tc.rcode
					}
					return &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: fixture, server: server}, rcode: rcode}, nil
				}, server)
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			// Establish that the fallback resolver really can resolve both families.
			ips, _, err := ops.lookupPublicIP(ctx, "netdoc.test.", publicDNSServer(resolvers[1]))
			if err != nil || len(ips) != 2 {
				t.Fatalf("fallback fixture: addresses=%v error=%v", ips, err)
			}
			asked = nil
			r := ops.publicDNSProbe("netdoc.test.", nil, resolvers)(ctx, nil)
			_, exchanges := fixture.served()
			if !slices.ContainsFunc(exchanges, func(e splitDNSExchange) bool { return e.server == publicDNSServer(resolvers[0]) }) {
				t.Fatal("first resolver never received a query")
			}
			if r.Status != StatusNA || r.resolver != resolvers[0] || len(r.Addrs) != 0 || r.DNSNotFound ||
				!strings.Contains(r.Detail, tc.name) || strings.Contains(r.Detail, "unavailable") || len(asked) != 1 {
				t.Fatalf("answering resolver's %s was lost: status=%s resolver=%s detail=%q addresses=%v asked=%v",
					tc.name, r.Status, r.resolver, r.Detail, r.Addrs, asked)
			}
		})
	}
}

func TestGoResolverPublicDNSErrorEvidence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rcode       uint16
		dialErr     error
		readTimeout bool
		mutate      func([]byte) []byte
	}{
		{name: "SERVFAIL", rcode: dnsRcodeServFail},
		{name: "REFUSED", rcode: dnsRcodeRefused},
		{name: "NXDOMAIN", rcode: dnsRcodeNXDom},
		{name: "transport refusal", dialErr: &net.OpError{Op: "dial", Net: "udp", Err: syscall.ECONNREFUSED}},
		{name: "timeout", readTimeout: true},
		{name: "malformed response", mutate: func(msg []byte) []byte { return msg[:dnsHeaderLen] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := lookupIPWithDial(context.Background(), "netdoc.test.", func(context.Context, string, string) (net.Conn, error) {
				if tc.dialErr != nil {
					return nil, tc.dialErr
				}
				if tc.readTimeout {
					return publicDNSTimeoutConn{&splitDNSConn{}}, nil
				}
				return &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, rcode: tc.rcode, mutate: tc.mutate}, nil
			})
			var dnsErr *net.DNSError
			if !errors.As(err, &dnsErr) {
				t.Fatalf("error=%T %v, want DNSError", err, err)
			}
			t.Logf("error=%T temporary=%v timeout=%v notFound=%v unwrap=%T: %v", err, dnsErr.IsTemporary, dnsErr.IsTimeout, dnsErr.IsNotFound, errors.Unwrap(dnsErr), err)
			if dnsErr.IsNotFound != (tc.rcode == dnsRcodeNXDom) || dnsErr.IsTimeout != tc.readTimeout {
				t.Fatalf("unexpected flags: %+v", dnsErr)
			}
		})
	}
}

type publicDNSTimeoutConn struct{ net.Conn }

func (publicDNSTimeoutConn) Read([]byte) (int, error) { return 0, os.ErrDeadlineExceeded }

func (publicDNSTimeoutConn) Write(p []byte) (int, error) { return len(p), nil }

// lostDNSConn is a query dropped on the way to the resolver: the write
// succeeds and no reply ever comes, so the read waits until the lookup gives
// up on it, the way a lost datagram does.
type lostDNSConn struct {
	*publicDNSFixtureConn
	ctx context.Context
}

func (c lostDNSConn) Read(p []byte) (int, error) {
	if len(c.reply) == 0 {
		<-c.ctx.Done()
		return 0, os.ErrDeadlineExceeded
	}
	return c.publicDNSFixtureConn.Read(p)
}

// One lost datagram must not cost the answer the other family already got.
// Go asks A and AAAA separately and returns neither until both settle, and its
// per-query timeout outlasts the probe budget, so a lookup whose AAAA query was
// dropped used to report the A answer it had received as a resolver timeout.
// The packet-loss scenario failed that way, with the resolver answering every
// A query it was sent. A lookup that received no address is still a failure,
// whichever family was lost.
func TestDNSProbeKeepsAnAnswerWhenTheOtherFamilyIsLost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lost   []uint16
		nodata []uint16
		want   Status
		addrs  []string
	}{
		{"a lost AAAA query keeps the A answer", []uint16{dnsTypeAAAA}, nil, StatusPass, []string{splitDNSAnswerA}},
		{"a lost A query keeps the AAAA answer", []uint16{dnsTypeA}, nil, StatusPass, []string{splitDNSAnswer6}},
		{"a lost A query beside an empty AAAA answer fails", []uint16{dnsTypeA}, []uint16{dnsTypeAAAA}, StatusFail, nil},
		{"both families lost fails", []uint16{dnsTypeA, dnsTypeAAAA}, nil, StatusFail, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutate := func(msg []byte) []byte {
				end, _ := skipDNSName(msg, dnsHeaderLen)
				qtype := binary.BigEndian.Uint16(msg[end:])
				if slices.Contains(tc.lost, qtype) {
					return nil
				}
				if slices.Contains(tc.nodata, qtype) {
					clear(msg[6:8])
					return msg[:end+4]
				}
				return msg
			}
			ops := &netops{lookupIP: func(ctx context.Context, host string) ([]net.IP, []string, error) {
				return lookupIPWithDial(ctx, host, func(ctx context.Context, _, _ string) (net.Conn, error) {
					fixture := &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: mutate}
					return lostDNSConn{fixture, ctx}, nil
				})
			}}
			// Well inside any resolv.conf timeout, so only the probe budget can
			// end a lost query.
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			r := ops.dnsProbe("netdoc.test.", nil)(ctx, nil)
			got := make([]string, len(r.Addrs))
			for i, ip := range r.Addrs {
				got[i] = ip.String()
			}
			if r.Status != tc.want || !slices.Equal(got, tc.addrs) {
				t.Fatalf("result = %s %v (%s), want %s %v", r.Status, got, r.Detail, tc.want, tc.addrs)
			}
			if tc.want == StatusFail && r.Cause != DNSCauseTimeout {
				t.Errorf("cause = %q, want %q: nothing answered in time", r.Cause, DNSCauseTimeout)
			}
		})
	}
}

func TestPublicDNSWireOutcomes(t *testing.T) {
	noRecords := func(msg []byte) []byte {
		end, _ := skipDNSName(msg, dnsHeaderLen)
		clear(msg[6:12])
		return msg[:end+4]
	}
	for _, transport := range []string{"UDP", "fragmented TCP"} {
		for _, tc := range []struct {
			name     string
			rcode    uint16
			mutate   func([]byte) []byte
			dialErr  error
			timeout  bool
			fallback bool
			missing  bool
			service  string
		}{
			{name: "A and AAAA"},
			{name: "NXDOMAIN", rcode: dnsRcodeNXDom, missing: true},
			{name: "no records", mutate: noRecords, missing: true},
			{name: "SERVFAIL", rcode: dnsRcodeServFail, service: "SERVFAIL"},
			{name: "REFUSED", rcode: dnsRcodeRefused, service: "REFUSED"},
			{name: "FORMERR", rcode: dnsRcodeFormErr, service: "FORMERR"},
			{name: "transport refusal", dialErr: &net.OpError{Op: "dial", Net: "udp", Err: syscall.ECONNREFUSED}, fallback: true},
			{name: "transport timeout", timeout: true, fallback: true},
			{name: "malformed service error", rcode: dnsRcodeServFail, mutate: func(msg []byte) []byte { msg[7] = 1; return msg }, fallback: true},
			{name: "wrong ID", rcode: dnsRcodeServFail, mutate: func(msg []byte) []byte { msg[0] ^= 1; return msg }, fallback: true},
			{name: "wrong question", rcode: dnsRcodeRefused, mutate: func(msg []byte) []byte { msg[13] ^= 1; return msg }, fallback: true},
			{name: "questionless FORMERR", rcode: dnsRcodeFormErr, mutate: func(msg []byte) []byte { msg[5] = 0; return msg[:dnsHeaderLen] }, fallback: true},
			{name: "UDP truncation then TCP SERVFAIL", rcode: dnsRcodeServFail, service: "SERVFAIL"},
		} {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				fixture := &splitDNSFixture{}
				resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
				var asked []string
				ops := &netops{lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
					asked = append(asked, server)
					return lookupIPPublicWithDial(ctx, host, func(_ context.Context, network, _ string) (net.Conn, error) {
						conn := &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: fixture, server: server}}
						if server == publicDNSServer(resolvers[0]) {
							if tc.dialErr != nil {
								return nil, tc.dialErr
							}
							if tc.timeout {
								return publicDNSTimeoutConn{conn}, nil
							}
							conn.rcode, conn.mutate = tc.rcode, tc.mutate
							if tc.name == "UDP truncation then TCP SERVFAIL" && network == "udp" {
								conn.mutate = func(msg []byte) []byte { msg[2] |= 2; return msg }
							}
						}
						if transport == "UDP" && network == "udp" {
							return publicDNSFixturePacketConn{conn}, nil
						}
						return publicDNSFragmentConn{conn}, nil
					}, server)
				}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				r := ops.publicDNSProbe("netdoc.test.", nil, resolvers)(ctx, nil)
				wantResolver, wantAsked := resolvers[0], []string{publicDNSServer(resolvers[0])}
				if tc.fallback {
					wantResolver = resolvers[1]
					wantAsked = append(wantAsked, publicDNSServer(resolvers[1]))
				}
				if r.resolver != wantResolver || !slices.Equal(asked, wantAsked) || !slices.Equal(r.ResolverTargets, wantAsked) {
					t.Fatalf("resolver=%s asked=%v targets=%v, want resolver=%s asked=%v", r.resolver, asked, r.ResolverTargets, wantResolver, wantAsked)
				}
				if tc.service != "" {
					if r.Status != StatusNA || !strings.Contains(r.Detail, "answered") || !strings.Contains(r.Detail, tc.service) || strings.Contains(r.Detail, "unavailable") || r.DNSNotFound || len(r.Addrs) != 0 {
						t.Fatalf("service error was not retained: %+v", r)
					}
				} else if r.Status != StatusPass || r.DNSNotFound != tc.missing {
					t.Fatalf("incorrect DNS semantics: %+v", r)
				} else if !tc.missing && (!containsResolvedIP(r.Addrs, net.ParseIP(splitDNSAnswerA)) || !containsResolvedIP(r.Addrs, net.ParseIP(splitDNSAnswer6))) {
					t.Fatalf("missing A/AAAA answers: %+v", r)
				}
			})
		}
	}
}

func TestPublicDNSResponseSurvivesLaterTimeout(t *testing.T) {
	for _, rcode := range []uint16{dnsRcodeServFail, dnsRcodeSuccess} {
		t.Run((&dnsResponseError{rcode: rcode}).Error(), func(t *testing.T) {
			var replies atomic.Int32
			fixture := &splitDNSFixture{}
			resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
			var asked []string
			ops := &netops{lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
				asked = append(asked, server)
				return lookupIPPublicWithDial(ctx, host, func(context.Context, string, string) (net.Conn, error) {
					return &publicDNSFixtureConn{
						splitDNSConn: &splitDNSConn{fixture: fixture, server: server},
						rcode:        rcode,
						mutate: func(msg []byte) []byte {
							if replies.Add(1) > 1 {
								return nil
							} // all later reads time out
							end, _ := skipDNSName(msg, dnsHeaderLen)
							clear(msg[6:12])
							// Empty NOERROR without RA/AA is a valid reply, but Go
							// rejects it as an unusable referral and retries too.
							msg[3] &^= 0x80
							return msg[:end+4]
						},
					}, nil
				}, server)
			}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := ops.publicDNSProbe("netdoc.test.", nil, resolvers)(ctx, nil)
			if replies.Load() < 2 || len(asked) != 1 || r.resolver != resolvers[0] || r.Status != StatusNA || r.DNSNotFound || len(r.Addrs) != 0 || !strings.Contains(r.Detail, "answered") || strings.Contains(r.Detail, "unavailable") {
				t.Fatalf("response lost after timeouts: replies=%d asked=%v result=%+v", replies.Load(), asked, r)
			}
			if rcode == dnsRcodeServFail && !strings.Contains(r.Detail, "SERVFAIL") {
				t.Fatalf("service error lost: %s", r.Detail)
			}
		})
	}
}

// dropQueries loses the reply to each query type in lost and answers those in
// nodata with NOERROR and no records. Every other reply passes through.
func dropQueries(lost, nodata []uint16) func([]byte) []byte {
	return func(msg []byte) []byte {
		end, _ := skipDNSName(msg, dnsHeaderLen)
		qtype := binary.BigEndian.Uint16(msg[end:])
		if slices.Contains(lost, qtype) {
			return nil
		}
		if slices.Contains(nodata, qtype) {
			clear(msg[6:8])
			return msg[:end+4]
		}
		return msg
	}
}

// The public lookup has the shape the system lookup had before PR #365: Go
// returns neither family until both settle, so a lost datagram discarded the
// answer the public resolver had already sent for the other family.
func TestPublicDNSKeepsAnAnswerWhenTheOtherFamilyIsLost(t *testing.T) {
	resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
	both := []uint16{dnsTypeA, dnsTypeAAAA}
	for _, tc := range []struct {
		name      string
		resolvers []string
		mutate    func([]byte) []byte
		rcode     uint16
		asked     int
		want      Status
		addrs     []string
		detail    string
	}{
		{"a lost AAAA query keeps the A answer", resolvers[:1], dropQueries([]uint16{dnsTypeAAAA}, nil), 0, 1, StatusPass, []string{splitDNSAnswerA}, "(via " + resolvers[0] + ")"},
		{"a lost A query keeps the AAAA answer", resolvers[:1], dropQueries([]uint16{dnsTypeA}, nil), 0, 1, StatusPass, []string{splitDNSAnswer6}, "(via " + resolvers[0] + ")"},
		{"automatic resolvers keep the first answer without fallback", resolvers, dropQueries([]uint16{dnsTypeAAAA}, nil), 0, 1, StatusPass, []string{splitDNSAnswerA}, "(via " + resolvers[0] + ")"},
		{"a lost A query beside an empty AAAA answer is not a second opinion", resolvers[:1], dropQueries([]uint16{dnsTypeA}, []uint16{dnsTypeAAAA}), 0, 1, StatusNA, nil, "answered"},
		{"a SERVFAIL on A keeps its rcode beside a lost AAAA query", resolvers[:1], dropQueries([]uint16{dnsTypeAAAA}, nil), dnsRcodeServFail, 1, StatusNA, nil, "SERVFAIL"},
		{"NXDOMAIN on A beside a lost AAAA query", resolvers[:1], dropQueries([]uint16{dnsTypeAAAA}, nil), dnsRcodeNXDom, 1, StatusNA, nil, "answered"},
		{"both families lost is unavailable", resolvers[:1], dropQueries(both, nil), 0, 1, StatusNA, nil, "unavailable"},
		{"both families lost falls back to the next resolver", resolvers, dropQueries(both, nil), 0, 2, StatusNA, nil, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Well inside any resolv.conf timeout, so only the probe budget can end a lost query.
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			var asked []string
			var late atomic.Int32
			ops := &netops{lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
				asked = append(asked, server)
				return lookupIPPublicWithDial(ctx, host, func(dctx context.Context, _, _ string) (net.Conn, error) {
					// An expired lookup's dial is refused, as net.Dialer refuses it, so
					// nothing leaves. Only a dial that ignores the deadline is a leak.
					if dctx.Err() != nil {
						return nil, dctx.Err()
					}
					if time.Now().After(deadline) {
						late.Add(1)
					}
					conn := &publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, rcode: tc.rcode, mutate: tc.mutate}
					return lostDNSConn{conn, dctx}, nil
				}, server)
			}}
			r := ops.publicDNSProbe("netdoc.test.", nil, tc.resolvers)(ctx, nil)
			var got []string
			for _, ip := range r.Addrs {
				got = append(got, ip.String())
			}
			var wantTargets []string
			for _, ip := range tc.resolvers[:tc.asked] {
				wantTargets = append(wantTargets, publicDNSServer(ip))
			}
			if r.Status != tc.want || !slices.Equal(got, tc.addrs) || r.DNSNotFound ||
				!strings.Contains(r.Detail, tc.detail) || len(asked) != tc.asked ||
				r.resolver != tc.resolvers[tc.asked-1] || !slices.Equal(r.ResolverTargets, wantTargets) {
				t.Fatalf("result = %s %v (%s) resolver=%s targets=%v asked=%v, want %s %v (%s) resolver=%s targets=%v asked=%d",
					r.Status, got, r.Detail, r.resolver, r.ResolverTargets, asked,
					tc.want, tc.addrs, tc.detail, tc.resolvers[tc.asked-1], wantTargets, tc.asked)
			}
			if n := late.Load(); n != 0 {
				t.Errorf("%d resolver dials began after the probe deadline", n)
			}
		})
	}
}

// Replay may only use responses that verified for the query asked. A reply that
// fails verification must not become an address, even beside a lost AAAA query.
func TestPublicDNSReplayIgnoresUnverifiedReplies(t *testing.T) {
	resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
	for _, tc := range []struct {
		name   string
		damage func([]byte)
	}{
		{"wrong ID", func(msg []byte) { msg[0] ^= 1 }},
		{"wrong question", func(msg []byte) { msg[13] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutate := func(msg []byte) []byte {
				end, _ := skipDNSName(msg, dnsHeaderLen)
				if binary.BigEndian.Uint16(msg[end:]) == dnsTypeAAAA {
					return nil
				}
				tc.damage(msg)
				return msg
			}
			ops := &netops{lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
				return lookupIPPublicWithDial(ctx, host, func(dctx context.Context, _, _ string) (net.Conn, error) {
					return lostDNSConn{&publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: mutate}, dctx}, nil
				}, server)
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			r := ops.publicDNSProbe("netdoc.test.", nil, resolvers[:1])(ctx, nil)
			if r.Status != StatusNA || len(r.Addrs) != 0 {
				t.Fatalf("unverified reply became an answer: %+v", r)
			}
		})
	}
}

// watchedDNSConn is a lostDNSConn that reports when it delivers a reply. Go
// closes a query's connection only after reading its reply, and the observer
// verifies that reply inside the read, so Close runs after the answer is recorded.
type watchedDNSConn struct {
	lostDNSConn
	delivered bool
	onAnswer  func()
}

func (c *watchedDNSConn) Read(p []byte) (int, error) {
	answered := len(c.reply) > 0
	n, err := c.lostDNSConn.Read(p)
	c.delivered = c.delivered || answered
	return n, err
}

func (c *watchedDNSConn) Close() error {
	if c.delivered {
		c.onAnswer()
	}
	return c.lostDNSConn.Close()
}

// Cancelling the caller's context ends a lost AAAA query the same way a deadline
// does, and must keep the A answer that already arrived. The cancel waits for
// both events: the AAAA query was dropped, and the A answer was read and
// verified. Go starts the two queries on separate goroutines, so either can
// come first. The timeout is a backstop for a run where an event never happens.
func TestPublicDNSCallerCancellationKeepsAnAnswer(t *testing.T) {
	resolvers := PublicDNSCandidates(DefaultPublicDNS, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var lost, answered atomic.Int32
	finish := func() {
		if lost.Load() > 0 && answered.Load() > 0 {
			cancel()
		}
	}
	drop := dropQueries([]uint16{dnsTypeAAAA}, nil)
	mutate := func(msg []byte) []byte {
		reply := drop(msg)
		if reply == nil {
			lost.Add(1)
			finish()
		}
		return reply
	}
	ops := &netops{lookupPublicIP: func(lctx context.Context, host, server string) ([]net.IP, []string, error) {
		return lookupIPPublicWithDial(lctx, host, func(dctx context.Context, _, _ string) (net.Conn, error) {
			if dctx.Err() != nil {
				return nil, dctx.Err()
			}
			return &watchedDNSConn{
				lostDNSConn: lostDNSConn{&publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: mutate}, dctx},
				onAnswer: func() {
					answered.Add(1)
					finish()
				},
			}, nil
		}, server)
	}}
	r := ops.publicDNSProbe("netdoc.test.", nil, resolvers[:1])(ctx, nil)
	if !errors.Is(ctx.Err(), context.Canceled) || answered.Load() != 1 || lost.Load() < 1 {
		t.Fatalf("ctx.Err()=%v answered=%d lost=%d: the cancel must follow one verified answer and a lost AAAA reply",
			ctx.Err(), answered.Load(), lost.Load())
	}
	if r.Status != StatusPass || len(r.Addrs) != 1 || r.Addrs[0].String() != splitDNSAnswerA {
		t.Fatalf("cancelled lookup result = %s %v (%s), want PASS with %s", r.Status, r.Addrs, r.Detail, splitDNSAnswerA)
	}
}

// The hosts-file guard covers an address the replay hands back, not only one
// the first lookup returns. Forcing the local answer makes the guard refuse the
// replayed A address, which must not be credited to the public server.
func TestPublicDNSReplayKeepsTheHostsFileGuard(t *testing.T) {
	previous := answeredWithoutDNSCheck
	t.Cleanup(func() { answeredWithoutDNSCheck = previous })
	answeredWithoutDNSCheck = func(context.Context, string) bool { return true }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	drop := dropQueries([]uint16{dnsTypeAAAA}, nil)
	ips, _, err := lookupIPPublicWithDial(ctx, "netdoc.test.", func(dctx context.Context, _, _ string) (net.Conn, error) {
		return lostDNSConn{&publicDNSFixtureConn{splitDNSConn: &splitDNSConn{fixture: &splitDNSFixture{}}, mutate: drop}, dctx}, nil
	}, "8.8.8.8")
	if !errors.Is(err, errHostsFileAnswer) || len(ips) != 0 {
		t.Fatalf("ips=%v err=%v, want errHostsFileAnswer and no addresses", ips, err)
	}
}
