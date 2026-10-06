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
