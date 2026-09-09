package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQUICProbeUsesFixedEndpointAndFamilyDialer(t *testing.T) {
	wantIP := net.ParseIP("192.0.2.44")
	var lookedUp, network, address string
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		lookupIP: func(_ context.Context, host string) ([]net.IP, []string, error) {
			lookedUp = host
			return []net.IP{wantIP}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, gotNetwork, gotAddress string) (net.Conn, error) {
			network, address = gotNetwork, gotAddress
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}}, nil
		},
		quicHandshake: func(_ context.Context, _ net.Conn, cfg *tls.Config) (quicState, error) {
			if cfg.ServerName != ConnectivityProbeHost || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h3" {
				t.Fatalf("TLS config = %+v", cfg)
			}
			return quicState{version: "v1", alpn: "h3"}, nil
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusPass || lookedUp != ConnectivityProbeHost || network != "udp4" || address != "192.0.2.44:443" {
		t.Fatalf("result = %+v, lookup = %q, dial = %s %s", r, lookedUp, network, address)
	}
}

func TestQUICProbeDoesNotCrossBindMissingSourceFamily(t *testing.T) {
	ops := &netops{
		sources: &SourceAddresses{IPv4: net.ParseIP("192.0.2.10")},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("2001:db8::44")}, []string{"[2001:db8::53]:53"}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("IPv6 destination was dialed with an IPv4-only source selection")
			return nil, nil
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusNA || !strings.Contains(r.Detail, "no address family") {
		t.Fatalf("result = %+v, want N/A for incompatible family", r)
	}
}

func TestQUICProbeUsesCompatibleFamilyWhenSelectedInterfaceLacksOtherFamily(t *testing.T) {
	v4 := net.ParseIP("192.0.2.44")
	var network string
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		sources:    &SourceAddresses{IPv4: net.ParseIP("192.0.2.10")},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("2001:db8::44"), v4}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, gotNetwork, _ string) (net.Conn, error) {
			network = gotNetwork
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}}, nil
		},
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			return quicState{version: "v1", alpn: "h3"}, nil
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusPass || network != "udp4" || !r.SelectedIP.Equal(v4) {
		t.Fatalf("result = %+v, network = %q, want compatible IPv4 attempt", r, network)
	}
}

func TestQUICProbeUsesIPv6Destination(t *testing.T) {
	wantIP := net.ParseIP("2001:db8::44")
	var network string
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{wantIP}, []string{"[2001:db8::53]:53"}, nil
		},
		dialContext: func(_ context.Context, gotNetwork, _ string) (net.Conn, error) {
			network = gotNetwork
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("2001:db8::10")}}, nil
		},
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			return quicState{version: "v1", alpn: "h3"}, nil
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusPass || network != "udp6" || !r.SelectedIP.Equal(wantIP) || !r.Source.Equal(net.ParseIP("2001:db8::10")) {
		t.Fatalf("result = %+v, network = %q", r, network)
	}
}

type quicTestConn struct {
	fakeConn
	family int
	closed chan struct{}
	once   sync.Once
}

func (c *quicTestConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestQUICProbeRacesBlackHoledIPv6WithWorkingIPv4(t *testing.T) {
	v4 := net.ParseIP("192.0.2.44")
	v6 := net.ParseIP("2001:db8::44")
	conns := make(chan *quicTestConn, 2)
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{v6, v4}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			family, local := 6, net.ParseIP("2001:db8::10")
			if network == "udp4" {
				family, local = 4, net.ParseIP("192.0.2.10")
			}
			conn := &quicTestConn{fakeConn: fakeConn{local: &net.UDPAddr{IP: local}}, family: family, closed: make(chan struct{})}
			conns <- conn
			return conn, nil
		},
		quicHandshake: func(ctx context.Context, conn net.Conn, _ *tls.Config) (quicState, error) {
			if conn.(*quicTestConn).family == 6 {
				<-ctx.Done()
				return quicState{}, ctx.Err()
			}
			return quicState{version: "v1", alpn: "h3"}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(ctx, nil)
	if r.Status != StatusPass || !r.SelectedIP.Equal(v4) {
		t.Fatalf("result = %+v, want IPv4 to win while IPv6 is black-holed", r)
	}
	for range 2 {
		var conn *quicTestConn
		select {
		case conn = <-conns:
		case <-time.After(time.Second):
			t.Fatal("both address families were not attempted")
		}
		select {
		case <-conn.closed:
		case <-time.After(time.Second):
			t.Fatalf("IPv%d UDP socket was not closed", conn.family)
		}
	}
}

func TestQUICProbeImmediateFamilyFailureDoesNotPoisonSuccess(t *testing.T) {
	v4 := net.ParseIP("192.0.2.44")
	v6 := net.ParseIP("2001:db8::44")
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{v6, v4}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network == "udp6" {
				return nil, errors.New("IPv6 unreachable")
			}
			return fakeConn{local: &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}}, nil
		},
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			return quicState{version: "v1", alpn: "h3"}, nil
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusPass || !r.SelectedIP.Equal(v4) {
		t.Fatalf("result = %+v, want IPv4 success after immediate IPv6 failure", r)
	}
}

func TestQUICProbeAllFamiliesFailDeterministically(t *testing.T) {
	v4 := net.ParseIP("192.0.2.44")
	v6 := net.ParseIP("2001:db8::44")
	ops := &netops{
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{v4, v6}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			return nil, errors.New(network + " unreachable")
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusFail || r.Cause != QUICCauseHandshake ||
		!strings.Contains(r.Detail, "2001:db8::44, 192.0.2.44") {
		t.Fatalf("result = %+v, want stable all-family failure", r)
	}
}

func TestQUICProbePreservesAttemptTimeoutCause(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("2001:db8::44"), net.ParseIP("192.0.2.44")}, []string{"192.0.2.53:53"}, nil
		},
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			local := net.ParseIP("2001:db8::10")
			if network == "udp4" {
				local = net.ParseIP("192.0.2.10")
			}
			return fakeConn{local: &net.UDPAddr{IP: local}}, nil
		},
		quicHandshake: func(context.Context, net.Conn, *tls.Config) (quicState, error) {
			return quicState{}, context.DeadlineExceeded
		},
	}

	r := ops.quicProbe(ConnectivityProbeHost, quicProbePort)(context.Background(), nil)
	if r.Status != StatusFail || r.Cause != QUICCauseTimeout {
		t.Fatalf("result = %+v, want attempt timeout to remain classified as timeout", r)
	}
}

func TestDiagnoseTCPHealthyQUICFailed(t *testing.T) {
	order := []ProbeID{ProbeIface, ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS}
	results := map[ProbeID]ProbeResult{
		ProbeIface:    {Status: StatusPass},
		ProbeInternet: {Status: StatusPass},
		ProbeQUIC:     {Status: StatusFail, Cause: QUICCauseTimeout},
		ProbeProxy:    {Status: StatusNA},
		ProbeDNS:      {Status: StatusPass},
	}

	d := Interpret(nil, order, results)
	if d.Verdict != VerdictDegraded || !strings.Contains(d.Summary, "TCP/443 works") || !strings.Contains(d.Summary, "fall back to TCP") {
		t.Fatalf("diagnosis = %q, %q", d.Summary, d.Verdict)
	}
}
