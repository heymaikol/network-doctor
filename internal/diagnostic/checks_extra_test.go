// Stub-network tests for probe plumbing: dialIPs, path identity, dial
// warnings, proxy CONNECT handling, and the egress downgrade.

package diagnostic

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// fakeConn is a no-network net.Conn stand-in; only LocalAddr and Close are
// used by the code under test.
type fakeConn struct {
	net.Conn
	local net.Addr
}

func (c fakeConn) LocalAddr() net.Addr { return c.local }
func (fakeConn) Close() error          { return nil }

func TestStatusString(t *testing.T) {
	cases := []struct {
		s    Status
		want string
	}{
		{StatusPass, "PASS"},
		{StatusWarn, "WARN"},
		{StatusFail, "FAIL"},
		{StatusSkip, "SKIP"},
		{StatusNA, "N/A"},
		{Status(-1), "?"},
		{Status(255), "?"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("Status(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestJoinIPs(t *testing.T) {
	if got := joinIPs(nil); got != "" {
		t.Errorf("joinIPs(nil) = %q, want empty", got)
	}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	if got := joinIPs(ips); got != "1.1.1.1, 8.8.8.8" {
		t.Errorf("joinIPs = %q, want '1.1.1.1, 8.8.8.8'", got)
	}
}

func TestSourceAddressesPrimary(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("2001:db8::2")},
		&net.IPNet{IP: net.ParseIP("192.0.2.2")},
	}
	if got := sourceAddresses(addrs).primary(); !got.Equal(net.ParseIP("192.0.2.2")) {
		t.Errorf("preferred source = %v, want IPv4 address", got)
	}
	if got := sourceAddresses(addrs[:1]).primary(); !got.Equal(net.ParseIP("2001:db8::2")) {
		t.Errorf("IPv6-only source = %v, want 2001:db8::2", got)
	}
}

func TestSourceAddressesSelectAndBindEachFamily(t *testing.T) {
	v4 := net.ParseIP("192.0.2.2")
	v6 := net.ParseIP("2001:db8::2")
	cases := []struct {
		name      string
		addrs     []net.Addr
		want4     net.IP
		want6     net.IP
		network   string
		dest      string
		wantLocal net.IP
	}{
		{"dual IPv4 QUIC probe", []net.Addr{&net.IPAddr{IP: v6}, &net.IPAddr{IP: v4}}, v4, v6, "udp4", "192.0.2.1:443", v4},
		{"dual IPv6 QUIC probe", []net.Addr{&net.IPAddr{IP: v4}, &net.IPAddr{IP: v6}}, v4, v6, "udp6", "[2001:db8::1]:443", v6},
		{"IPv4 only", []net.Addr{&net.IPAddr{IP: v4}}, v4, nil, "udp", "192.0.2.53:53", v4},
		{"IPv6 only", []net.Addr{&net.IPAddr{IP: v6}}, nil, v6, "udp", "[2001:db8::53]:53", v6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sources := sourceAddresses(tc.addrs)
			if sources == nil || !sources.IPv4.Equal(tc.want4) || !sources.IPv6.Equal(tc.want6) {
				t.Fatalf("sourceAddresses() = %+v, want IPv4 %v IPv6 %v", sources, tc.want4, tc.want6)
			}
			source, family := sources.forDial(tc.network, tc.dest)
			if source == nil || family == 0 {
				t.Fatalf("forDial(%q, %q) = (%v, %d), want %v", tc.network, tc.dest, source, family, tc.wantLocal)
			}
			d := dialerFromSource(source, tc.network, nil)
			var local net.IP
			switch addr := d.LocalAddr.(type) {
			case *net.TCPAddr:
				local = addr.IP
			case *net.UDPAddr:
				local = addr.IP
			}
			if !local.Equal(tc.wantLocal) {
				t.Errorf("local source = %v, want %v", local, tc.wantLocal)
			}
		})
	}
}

func TestSelectedSourceDoesNotFallBackAcrossFamilies(t *testing.T) {
	v4Only := &SourceAddresses{IPv4: net.ParseIP("192.0.2.2")}
	if source, family := v4Only.forDial("tcp6", "[2001:db8::1]:443"); source != nil || family != 6 {
		t.Fatalf("IPv6 selection from IPv4-only interface = (%v, %d), want (nil, 6)", source, family)
	}
	if _, err := dialContextFromSources(v4Only)(context.Background(), "udp6", "[2001:db8::1]:443"); err == nil || !strings.Contains(err.Error(), "no IPv6 source address") {
		t.Fatalf("IPv6 dial from IPv4-only interface error = %v", err)
	}

	v6Only := &SourceAddresses{IPv6: net.ParseIP("2001:db8::2")}
	if source, family := v6Only.forDial("tcp4", "192.0.2.1:443"); source != nil || family != 4 {
		t.Fatalf("IPv4 selection from IPv6-only interface = (%v, %d), want (nil, 4)", source, family)
	}
	if _, err := dialContextFromSources(v6Only)(context.Background(), "udp4", "192.0.2.1:443"); err == nil || !strings.Contains(err.Error(), "no IPv4 source address") {
		t.Fatalf("IPv4 dial from IPv6-only interface error = %v", err)
	}
}

func TestIfaceProbeAcceptsDualSourcesAndExactSecondaryAddress(t *testing.T) {
	v4 := net.ParseIP("192.0.2.2")
	v6 := net.ParseIP("2001:db8::2")
	addrs := []net.Addr{
		&net.IPAddr{IP: net.ParseIP("192.0.2.1")},
		&net.IPAddr{IP: v4},
		&net.IPAddr{IP: v6},
	}
	base := netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return addrs, nil },
	}
	for _, sources := range []*SourceAddresses{{IPv4: v4, IPv6: v6}, {IPv4: v4}} {
		ops := base
		ops.sources = sources
		r := ops.ifaceProbe(context.Background(), nil)
		if r.Status != StatusPass || r.Iface != "fake0" {
			t.Errorf("ifaceProbe(%+v) = %+v, want PASS on fake0", sources, r)
		}
	}
}

func TestDialerFromUsesNetworkAddressType(t *testing.T) {
	source := net.ParseIP("192.0.2.2")
	if _, ok := dialerFromSource(source, "tcp", nil).LocalAddr.(*net.TCPAddr); !ok {
		t.Error("TCP dialer LocalAddr is not *net.TCPAddr")
	}
	if _, ok := dialerFromSource(source, "udp", nil).LocalAddr.(*net.UDPAddr); !ok {
		t.Error("UDP dialer LocalAddr is not *net.UDPAddr")
	}
}

// dialIPs with a stubbed dialer returns a connection pinned to the address
// that won, with the attempt recorded. No real sockets.
func TestDialIPsSuccess(t *testing.T) {
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		time.Sleep(time.Millisecond) // make the recorded RTT observable
		return fakeConn{}, nil
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, sel, attempts, rtt := ops.dialIPs(ctx, []net.IP{net.ParseIP("192.0.2.1")}, 80)
	if conn == nil {
		t.Fatal("expected a connection from the stub dialer")
	}
	defer conn.Close()
	if !sel.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("selected = %v, want 192.0.2.1", sel)
	}
	if len(attempts) != 1 {
		t.Errorf("attempts = %d, want 1", len(attempts))
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want > 0", rtt)
	}
}

func TestDialIPsEmpty(t *testing.T) {
	conn, sel, attempts, rtt := (&netops{}).dialIPs(context.Background(), nil, 80)
	if conn != nil || sel != nil || attempts != nil || rtt != 0 {
		t.Errorf("dialIPs(empty) = (%v,%v,%v,%v), want all zero", conn, sel, attempts, rtt)
	}
}

// A refused dial fails deterministically: no conn, the failed attempt is
// recorded with its error.
func TestDialIPsRefused(t *testing.T) {
	errRefused := errors.New("connection refused")
	ops := &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errRefused
	}}

	conn, _, attempts, _ := ops.dialIPs(context.Background(), []net.IP{net.ParseIP("192.0.2.1")}, 80)
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expected no connection from the failing dialer")
	}
	if len(attempts) != 1 || !errors.Is(attempts[0].Err, errRefused) {
		t.Errorf("want one failed attempt with the dialer's error, got %+v", attempts)
	}
}

// Siblings that fail before the win stay in the attempt list. Every stub dial
// returns instantly, so failures pile up faster than the race loop drains them
// and the winning hand-off becomes ready with several still queued, the exact
// shape that used to lose them. Repeated because the interleaving is a race.
func TestDialIPsKeepsFailuresThatLostToTheWinner(t *testing.T) {
	ops := &netops{dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.255:") {
			return fakeConn{}, nil
		}
		return nil, errors.New("connection refused")
	}}
	var ips []net.IP
	for i := range maxAttempts - 1 {
		ips = append(ips, net.IPv4(192, 0, 2, byte(i+1)))
	}
	ips = append(ips, net.IPv4(192, 0, 2, 255)) // only address the stub connects to

	for round := range 200 {
		conn, sel, attempts, _ := ops.dialIPs(context.Background(), ips, 80)
		if conn == nil {
			t.Fatalf("round %d: expected the last address to win", round)
		}
		_ = conn.Close()
		if len(attempts) != len(ips) {
			t.Fatalf("round %d: recorded %d of %d attempts: %+v", round, len(attempts), len(ips), attempts)
		}
		if !attempts[len(attempts)-1].IP.Equal(sel) {
			t.Fatalf("round %d: winner is not the last attempt: %+v", round, attempts)
		}
	}
}

// pathIdentity reads the winning conn's LocalAddr as ground truth and maps it
// back to an interface via the stubbed interface list.
func TestPathIdentityFromConn(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0"}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
	conn := fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 40000}}

	src, iface, ambiguous := ops.pathIdentity(context.Background(), conn, net.ParseIP("192.0.2.1"), 80)
	if !src.Equal(net.ParseIP("192.0.2.7")) {
		t.Errorf("src = %v, want 192.0.2.7", src)
	}
	if iface != "fake0" || ambiguous {
		t.Errorf("iface = %q (ambiguous %t), want fake0 and not ambiguous", iface, ambiguous)
	}
}

// ifaceForIP for an address assigned to no interface is an explicit unknown,
// never a guess. The interface list is stubbed, so the verdict comes from the
// fixture rather than from whatever addresses the test machine happens to hold.
func TestIfaceForIPUnknown(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0"}, {Name: "fake1"}}, nil
		},
		interfaceAddrs: func(ifi *net.Interface) ([]net.Addr, error) {
			if ifi.Name == "fake1" {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}}, nil
			}
			return nil, nil
		},
	}
	if got, ambiguous := ops.ifaceForIP(net.ParseIP("203.0.113.213")); got != "(unknown iface)" || ambiguous {
		t.Errorf("ifaceForIP(unassigned) = %q (ambiguous %t), want '(unknown iface)' and not ambiguous", got, ambiguous)
	}
	// The same stub still resolves an address it does hold, so the unknown
	// above is a real miss and not an empty interface list.
	if got, ambiguous := ops.ifaceForIP(net.ParseIP("192.0.2.7")); got != "fake1" || ambiguous {
		t.Errorf("ifaceForIP(assigned) = %q (ambiguous %t), want fake1 and not ambiguous", got, ambiguous)
	}
}

// Probes run against stubbed netops: no real network, DNS, or OS interface
// access, which is the point of the function-field seam.
func TestNetopsInjection(t *testing.T) {
	ops := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0", Flags: net.FlagUp | net.FlagRunning}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, []string{"192.0.2.53:53"}, nil
		},
		ssid: func(context.Context, string) string { return "FakeNet" },
	}

	r := ops.ifaceProbe(context.Background(), nil)
	if r.Status != StatusPass || r.Iface != "fake0" || r.Network != "" {
		t.Errorf("ifaceProbe with stubs = %+v, want PASS on fake0 without SSID", r)
	}
	network := ops.ssidProbe(context.Background(), map[ProbeID]ProbeResult{ProbeIface: r})
	if network.Status != StatusPass || network.Network != "FakeNet" {
		t.Errorf("ssidProbe with stubs = %+v, want PASS on FakeNet", network)
	}

	r = ops.dnsProbe("example.com", nil)(context.Background(), nil)
	if r.Status != StatusPass || len(r.Addrs) != 1 || !r.Addrs[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("dnsProbe with stubs = %+v, want PASS with 192.0.2.1", r)
	}
}

// Degraded-but-functional dials downgrade to WARN: high latency, sibling
// address failures before a win, and an ambiguous source interface. A clean
// fast dial stays PASS.
func TestApplyDialWarnings(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	cases := []struct {
		name     string
		attempts []Attempt
		rtt      time.Duration
		iface    string
		amb      bool
		want     Status
		note     string
	}{
		{"clean", []Attempt{{IP: ip}}, 10 * time.Millisecond, "eth0", false, StatusPass, ""},
		{"cancelled sibling", []Attempt{{IP: ip, Err: context.Canceled}, {IP: ip}}, 10 * time.Millisecond, "eth0", false, StatusPass, ""},
		{"high latency", []Attempt{{IP: ip}}, warnRTT, "eth0", false, StatusWarn, "high latency"},
		{"partial addresses", []Attempt{{IP: net.ParseIP("192.0.2.2"), Err: errors.New("refused")}, {IP: ip}}, 10 * time.Millisecond, "eth0", false, StatusWarn, "1 of 2 address(es) failed"},
		{"ambiguous iface", []Attempt{{IP: ip}}, 10 * time.Millisecond, "eth0", true, StatusWarn, "ambiguous source interface"},
		// The display text is not the control channel: an interface whose real
		// name reads like the placeholder is a clean pass.
		{"iface named like the placeholder", []Attempt{{IP: ip}}, 10 * time.Millisecond, "(ambiguous)", false, StatusPass, ""},
	}
	for _, c := range cases {
		r := ProbeResult{Status: StatusPass, Attempts: c.attempts, Iface: c.iface, ifaceAmbiguous: c.amb, Detail: "connected"}
		applyDialWarnings(&r, c.rtt)
		if r.Status != c.want {
			t.Errorf("%s: status = %v, want %v", c.name, r.Status, c.want)
		}
		if c.note != "" && !strings.Contains(r.Detail, c.note) {
			t.Errorf("%s: detail = %q, want it to mention %q", c.name, r.Detail, c.note)
		}
	}
}

// scriptConn plays a canned proxy response and swallows writes; stands in for
// the wire in the CONNECT probe tests.
type scriptConn struct {
	fakeConn
	r               io.Reader
	w               strings.Builder
	readDeadlineErr error
	writeDeadline   time.Time
}

func (c *scriptConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *scriptConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *scriptConn) SetReadDeadline(time.Time) error    { return c.readDeadlineErr }
func (c *scriptConn) SetWriteDeadline(d time.Time) error { c.writeDeadline = d; return nil }
func (c *scriptConn) SetDeadline(d time.Time) error      { c.writeDeadline = d; return nil }

func proxyOps(proxy string, dial func(context.Context, string, string) (net.Conn, error)) *netops {
	return &netops{
		proxyFromEnv: func(*http.Request) (*url.URL, error) {
			if proxy == "" {
				return nil, nil
			}
			return url.Parse(proxy)
		},
		dialContext: dial,
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("192.0.2.10")}, []string{"192.0.2.53:53"}, nil
		},
	}
}

func TestProxyProbeNoProxyIsNA(t *testing.T) {
	r := proxyOps("", nil).proxyProbe(context.Background(), nil)
	if r.Status != StatusNA || !strings.Contains(r.Detail, "no proxy") {
		t.Errorf("no env proxy = %+v, want N/A", r)
	}
}

func TestProxyProbeUnknownSchemeIsNA(t *testing.T) {
	ops := proxyOps("socks4://proxy.corp", func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("an unsupported proxy scheme must not be dialed")
		return nil, nil
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusNA || !strings.Contains(r.Detail, "socks4") {
		t.Errorf("SOCKS4 proxy = %+v, want N/A", r)
	}
}

// socks5Reply is a granted CONNECT: greeting picks no-auth, then reply code 0
// with a bound IPv4 address.
var socks5Reply = string([]byte{5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

// Both SOCKS schemes use a real handshake. socks5 sends the address resolved
// by the client; socks5h sends the hostname for the proxy to resolve.
func TestProxyProbeSocks5(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			conn := &scriptConn{r: strings.NewReader(socks5Reply)}
			var dialed string
			ops := proxyOps(scheme+"://proxy.corp", func(_ context.Context, _, addr string) (net.Conn, error) {
				dialed = addr
				return conn, nil
			})
			r := ops.proxyProbe(context.Background(), nil)
			if r.Status != StatusPass || !strings.Contains(r.Detail, "proxy proxy.corp:1080 tunnels") {
				t.Errorf("granted SOCKS5 CONNECT = %+v, want PASS", r)
			}
			if dialed != "proxy.corp:1080" {
				t.Errorf("dialed %q, want proxy.corp:1080 (default SOCKS port)", dialed)
			}
			want := string([]byte{5, 1, 0, 5, 1, 0})
			if scheme == "socks5h" {
				want += string([]byte{3, byte(len(ConnectivityProbeHost))}) + ConnectivityProbeHost
			} else {
				want += string([]byte{1, 192, 0, 2, 10})
			}
			want += string([]byte{1, 187})
			if conn.w.String() != want {
				t.Errorf("wire bytes = %q, want %q", conn.w.String(), want)
			}
			if conn.writeDeadline.IsZero() {
				t.Error("deadline is zero, want the probe budget as a leash")
			}
		})
	}
}

func TestProxyProbeSocks5LocalDNSFailure(t *testing.T) {
	conn := &scriptConn{r: strings.NewReader(string([]byte{5, 0}))}
	ops := proxyOps("socks5://proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	ops.lookupIP = func(context.Context, string) ([]net.IP, []string, error) {
		return nil, []string{"192.0.2.53:53"}, errors.New("no such host")
	}
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "is reachable, but local DNS cannot resolve") ||
		!strings.Contains(r.Detail, "192.0.2.53") {
		t.Errorf("local DNS failure = %+v, want reachable proxy and resolver evidence", r)
	}
	if r.Cause != ProxyCauseClientDNS {
		t.Errorf("cause = %q, want %q", r.Cause, ProxyCauseClientDNS)
	}
	if got := conn.w.String(); got != string([]byte{5, 1, 0}) {
		t.Errorf("wire bytes = %q, want greeting only", got)
	}
}

func TestProxyProbeSocks5Failures(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  string
	}{
		{"auth demanded", []byte{5, 2}, "cleartext"},
		{"refused", []byte{5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0}, "connection refused"},
		{"no domain names", []byte{5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0}, "address type not supported"},
		{"unknown reply code", []byte{5, 0, 5, 99, 0, 1, 0, 0, 0, 0, 0, 0}, "reply code 99"},
		{"not a SOCKS port", []byte("HTTP/1.1 400 Bad Request\r\n"), "not a SOCKS5 proxy"},
		{"truncated", []byte{5, 0, 5, 0, 0, 1}, "truncated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := &scriptConn{r: strings.NewReader(string(c.reply))}
			ops := proxyOps("socks5h://user:pw@proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			})
			r := ops.proxyProbe(context.Background(), nil)
			if r.Status != StatusFail || !strings.Contains(r.Detail, c.want) {
				t.Errorf("SOCKS5 %s = %+v, want FAIL mentioning %q", c.name, r, c.want)
			}
			if strings.Contains(conn.w.String(), "pw") {
				t.Errorf("SOCKS5 handshake leaked credentials: %q", conn.w.String())
			}
		})
	}
}

func TestProxyProbeSocks5Unreachable(t *testing.T) {
	ops := proxyOps("socks5h://proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "cannot reach proxy") {
		t.Errorf("unreachable SOCKS5 proxy = %+v, want FAIL", r)
	}
	if r.Cause != ProxyCauseUnreachable {
		t.Errorf("cause = %q, want %q", r.Cause, ProxyCauseUnreachable)
	}
}

func TestSOCKS5ReplyCausesDistinguishFailureStages(t *testing.T) {
	for _, tc := range []struct {
		code  byte
		cause string
	}{
		{3, ProxyCauseDestinationUnreachable},
		{4, ProxyCauseProxyDNS},
		{5, ProxyCauseDestinationUnreachable},
		{8, ProxyCauseProtocol},
	} {
		conn := &scriptConn{r: strings.NewReader(string([]byte{5, 0, 5, tc.code, 0, 1, 0, 0, 0, 0, 0, 0}))}
		ops := proxyOps("socks5h://proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		})
		if got := ops.proxyProbe(context.Background(), nil).Cause; got != tc.cause {
			t.Errorf("reply %d cause = %q, want %q", tc.code, got, tc.cause)
		}
	}
}

func TestSOCKS5HostUnreachableCauseDependsOnResolutionLocation(t *testing.T) {
	for _, tc := range []struct {
		scheme string
		cause  string
	}{
		{"socks5", ProxyCauseDestinationUnreachable},
		{"socks5h", ProxyCauseProxyDNS},
	} {
		conn := &scriptConn{r: strings.NewReader(string([]byte{5, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0}))}
		ops := proxyOps(tc.scheme+"://proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		})
		if got := ops.proxyProbe(context.Background(), nil).Cause; got != tc.cause {
			t.Errorf("%s reply 4 cause = %q, want %q", tc.scheme, got, tc.cause)
		}
	}
}

func TestSOCKS5RejectsInvalidConnectReplyHeader(t *testing.T) {
	for _, reply := range [][]byte{
		{4, 0, 0, 1, 0, 0, 0, 0, 0, 0},
		{5, 0, 1, 1, 0, 0, 0, 0, 0, 0},
	} {
		conn := &scriptConn{r: strings.NewReader(string(append([]byte{5, 0}, reply...)))}
		ops := proxyOps("socks5h://proxy.corp:1080", func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		})
		r := ops.proxyProbe(context.Background(), nil)
		if r.Status != StatusFail || r.Cause != ProxyCauseProtocol || !strings.Contains(r.Detail, "invalid CONNECT reply header") {
			t.Errorf("reply %v result = %+v", reply[:4], r)
		}
	}
}

// Go's own ProxyFromEnvironment ignores ALL_PROXY; netdoc must not, or a box
// proxied only through ALL_PROXY reads as having no proxy at all.
//
// net/http reads HTTP(S)_PROXY and NO_PROXY once per process and caches them,
// so a machine, container or CI runner that already exports a proxy cannot be
// undone with t.Setenv here. The assertions therefore run in a child: this
// same test binary, re-run with every *_PROXY variable stripped, whatever the
// parent inherited. The marker variable tells the child to run them.
func TestProxyFromEnvironmentAllProxy(t *testing.T) {
	if os.Getenv("NETDOC_PROXY_ENV_HELPER") == "" {
		args := []string{"-test.run=^TestProxyFromEnvironmentAllProxy$"}
		// go test -cover exports GOCOVERDIR, but a test binary only writes its
		// counters there when told to, so the child's coverage of
		// proxyFromEnvironment lands in the parent's profile.
		if dir := os.Getenv("GOCOVERDIR"); dir != "" {
			args = append(args, "-test.gocoverdir="+dir)
		}
		// #nosec G204 G702 -- the child is this same test binary, os.Args[0],
		// re-run with a literal -test.run filter.
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
			name, _, _ := strings.Cut(kv, "=")
			return strings.HasSuffix(strings.ToUpper(name), "_PROXY")
		}), "NETDOC_PROXY_ENV_HELPER=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("test rerun without proxy variables: %v\n%s", err, out)
		}
		return
	}
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: ConnectivityProbeHost}}
	for _, name := range []string{"ALL_PROXY", "all_proxy"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("ALL_PROXY", "")
			t.Setenv("all_proxy", "")
			t.Setenv(name, "socks5h://proxy.corp:1080")
			u, err := proxyFromEnvironment(req)
			if err != nil || u == nil || u.Scheme != "socks5h" || u.Host != "proxy.corp:1080" {
				t.Errorf("proxyFromEnvironment = %v, %v; want socks5h://proxy.corp:1080", u, err)
			}
		})
	}
	// A NO_PROXY hit is why net/http returned nil; falling back to ALL_PROXY
	// there would report a proxy this host would never go through.
	for _, np := range []string{"*", "gstatic.com", ".gstatic.com", "*.gstatic.com", "connectivitycheck.gstatic.com",
		// A port-scoped entry exempts the request Go would send to that port.
		// The probe asks about https with no explicit port, so 443 is the
		// port the entry has to be read against.
		"connectivitycheck.gstatic.com:443", "gstatic.com:443"} {
		t.Run("NO_PROXY="+np, func(t *testing.T) {
			t.Setenv("ALL_PROXY", "socks5h://proxy.corp:1080")
			t.Setenv("NO_PROXY", np)
			if u, err := proxyFromEnvironment(req); u != nil || err != nil {
				t.Errorf("proxyFromEnvironment = %v, %v; want nil, nil", u, err)
			}
		})
	}
	t.Run("NO_PROXY miss still falls back", func(t *testing.T) {
		t.Setenv("ALL_PROXY", "socks5h://proxy.corp:1080")
		t.Setenv("NO_PROXY", "example.com,notgstatic.com")
		if u, err := proxyFromEnvironment(req); err != nil || u == nil || u.Host != "proxy.corp:1080" {
			t.Errorf("proxyFromEnvironment = %v, %v; want socks5h://proxy.corp:1080", u, err)
		}
	})
	// The port in an entry narrows it. A request to another port on the same
	// name is not exempt, so the ALL_PROXY fallback still applies.
	t.Run("NO_PROXY port does not carry to another port", func(t *testing.T) {
		t.Setenv("ALL_PROXY", "socks5h://proxy.corp:1080")
		t.Setenv("NO_PROXY", ConnectivityProbeHost+":443")
		other := &http.Request{URL: &url.URL{Scheme: "https", Host: ConnectivityProbeHost + ":8443"}}
		if u, err := proxyFromEnvironment(other); err != nil || u == nil || u.Host != "proxy.corp:1080" {
			t.Errorf("proxyFromEnvironment = %v, %v; want socks5h://proxy.corp:1080", u, err)
		}
	})
	// The default port comes from the scheme, so an entry pinned to 443 leaves
	// a plain http request on port 80 proxied.
	t.Run("NO_PROXY port is matched per scheme default", func(t *testing.T) {
		t.Setenv("ALL_PROXY", "socks5h://proxy.corp:1080")
		t.Setenv("NO_PROXY", ConnectivityProbeHost+":443")
		plain := &http.Request{URL: &url.URL{Scheme: "http", Host: ConnectivityProbeHost}}
		if u, err := proxyFromEnvironment(plain); err != nil || u == nil || u.Host != "proxy.corp:1080" {
			t.Errorf("proxyFromEnvironment = %v, %v; want socks5h://proxy.corp:1080", u, err)
		}
	})
	t.Run("bare host defaults to http", func(t *testing.T) {
		t.Setenv("ALL_PROXY", "proxy.corp:3128")
		u, err := proxyFromEnvironment(req)
		if err != nil || u == nil || u.Scheme != "http" || u.Host != "proxy.corp:3128" {
			t.Errorf("proxyFromEnvironment = %v, %v; want http://proxy.corp:3128", u, err)
		}
	})
}

// noProxyBypasses stands in for the NO_PROXY check net/http already applied to
// HTTP(S)_PROXY, so it has to read an entry the way Go's matcher does. The
// expectations below are httpproxy's, the package net/http builds
// ProxyFromEnvironment out of: "foo.com" matches foo.com and bar.foo.com,
// ".foo.com" and "*.foo.com" are the same subdomain-only entry, an entry may
// carry a port, and the port a request is matched on is the scheme default
// when the URL does not name one.
func TestNoProxyBypasses(t *testing.T) {
	const probeHost = ConnectivityProbeHost
	cases := []struct {
		noProxy string
		scheme  string // "" means https
		host    string
		want    bool
	}{
		// A wildcard entry is Go's spelling of a leading-dot entry.
		{noProxy: "*.gstatic.com", host: probeHost, want: true},
		{noProxy: "*.gstatic.com", host: "gstatic.com", want: false},
		{noProxy: "*.GSTATIC.COM", host: probeHost, want: true},
		{noProxy: "*.example.com", host: probeHost, want: false},
		// Domain boundaries: a suffix that is not a label boundary is a miss.
		{noProxy: "*.gstatic.com", host: "notgstatic.com", want: false},
		// A star that does not begin a label is a literal, not a wildcard.
		{noProxy: "*gstatic.com", host: probeHost, want: false},
		{noProxy: "gstatic.com", host: "notgstatic.com", want: false},
		{noProxy: ".gstatic.com", host: "notgstatic.com", want: false},
		// Bare domain: the domain itself and its subdomains.
		{noProxy: "gstatic.com", host: probeHost, want: true},
		{noProxy: "gstatic.com", host: "gstatic.com", want: true},
		// Leading dot: subdomains only.
		{noProxy: ".gstatic.com", host: probeHost, want: true},
		{noProxy: ".gstatic.com", host: "gstatic.com", want: false},
		// Exact hostname.
		{noProxy: probeHost, host: probeHost, want: true},
		{noProxy: probeHost, host: "other.gstatic.com", want: false},
		// Everything, and nothing. A wildcard ignores the port entirely.
		{noProxy: "*", host: probeHost, want: true},
		{noProxy: "*", host: probeHost + ":8443", want: true},
		{noProxy: "", host: probeHost, want: false},
		// Lists, whitespace and empty entries.
		{noProxy: "example.com, *.gstatic.com", host: probeHost, want: true},
		{noProxy: " , .gstatic.com , ", host: probeHost, want: true},
		{noProxy: "example.com,notgstatic.com", host: probeHost, want: false},
		// A port on the entry narrows it to that port. An https URL with no
		// explicit port is matched on 443, which is why the reported
		// NO_PROXY=host:443 case has to bypass.
		{noProxy: probeHost + ":443", host: probeHost, want: true},
		{noProxy: probeHost + ":443", host: probeHost + ":443", want: true},
		{noProxy: probeHost + ":443", host: probeHost + ":8443", want: false},
		{noProxy: probeHost + ":443", scheme: "http", host: probeHost, want: false},
		{noProxy: probeHost + ":80", scheme: "http", host: probeHost, want: true},
		// A port rides along with the domain and wildcard forms too.
		{noProxy: "gstatic.com:443", host: probeHost, want: true},
		{noProxy: ".gstatic.com:443", host: probeHost, want: true},
		{noProxy: "*.gstatic.com:443", host: probeHost, want: true},
		{noProxy: "gstatic.com:443", host: probeHost + ":8443", want: false},
		// IP and CIDR entries, which net/http honors and the probe host never
		// exercises. Pinned so the fallback stays the same matcher, not a
		// hostname-only subset of it.
		{noProxy: "10.0.0.0/8", host: "10.1.2.3", want: true},
		{noProxy: "10.0.0.0/8", host: "11.1.2.3", want: false},
		{noProxy: "10.1.2.3", host: "10.1.2.3", want: true},
		{noProxy: "10.1.2.3:443", host: "10.1.2.3", want: true},
		{noProxy: "10.1.2.3:443", host: "10.1.2.3:8443", want: false},
		// Go never proxies localhost or a loopback literal, whatever NO_PROXY
		// says, so neither may be resurrected through ALL_PROXY.
		{noProxy: "example.com", host: "localhost", want: true},
		{noProxy: "example.com", host: "127.0.0.1", want: true},
		{noProxy: "example.com", host: "[::1]", want: true},
	}
	for _, c := range cases {
		scheme := c.scheme
		if scheme == "" {
			scheme = "https"
		}
		t.Run(c.noProxy+"/"+scheme+"://"+c.host, func(t *testing.T) {
			// Lowercase first: Windows environment names are case-insensitive,
			// so the two calls are one variable there and the last write wins.
			t.Setenv("no_proxy", "")
			t.Setenv("NO_PROXY", c.noProxy)
			reqURL := &url.URL{Scheme: scheme, Host: c.host}
			if got := noProxyBypasses(reqURL); got != c.want {
				t.Errorf("noProxyBypasses(%q) with NO_PROXY=%q = %v, want %v", reqURL, c.noProxy, got, c.want)
			}
			// The point of the fallback check is agreeing with net/http, so
			// compare against httpproxy directly rather than trusting the
			// table alone.
			const sentinel = "http://proxy.invalid"
			cfg := &httpproxy.Config{HTTPProxy: sentinel, HTTPSProxy: sentinel, NoProxy: c.noProxy}
			proxy, err := cfg.ProxyFunc()(reqURL)
			if want := err == nil && proxy == nil; want != c.want {
				t.Errorf("httpproxy bypass for %q with NO_PROXY=%q = %v, want %v", reqURL, c.noProxy, want, c.want)
			}
		})
	}
	t.Run("lowercase no_proxy is read when NO_PROXY is unset", func(t *testing.T) {
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "*.gstatic.com")
		if !noProxyBypasses(&url.URL{Scheme: "https", Host: probeHost}) {
			t.Errorf("noProxyBypasses(%q) with no_proxy=*.gstatic.com = false, want true", probeHost)
		}
	})
}

func TestProxyProbeUnreachable(t *testing.T) {
	var dialed string
	ops := proxyOps("http://proxy.corp", func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = addr
		return nil, errors.New("connection refused")
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "cannot reach proxy") {
		t.Errorf("unreachable proxy = %+v, want FAIL", r)
	}
	if dialed != "proxy.corp:80" {
		t.Errorf("dialed %q, want proxy.corp:80 (default http port)", dialed)
	}
}

func TestProxyProbeMalformedURLFailsWithoutDial(t *testing.T) {
	// The last value is net/http's fallback parse of http://proxy:65536.
	for _, proxy := range []string{"://bad", "http://:3128", "http://proxy:0", "http://proxy:65536", "https://proxy:65536", "http://http://proxy:65536"} {
		t.Run(proxy, func(t *testing.T) {
			ops := proxyOps(proxy, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("malformed proxy must not be dialed")
				return nil, nil
			})
			r := ops.proxyProbe(context.Background(), nil)
			if r.Status != StatusFail || !strings.Contains(r.Detail, "bad proxy configuration") {
				t.Errorf("malformed proxy = %+v, want FAIL bad proxy configuration", r)
			}
		})
	}
}

// TestProxyProbeParseErrorIsRedacted guards against a regression where the
// raw net/url parser error, which can repeat the malformed HTTPS_PROXY/
// HTTP_PROXY value verbatim, including any embedded credentials, leaks into
// the report. The probe must fail with a fixed, generic detail instead.
func TestProxyProbeParseErrorIsRedacted(t *testing.T) {
	const sentinel = "SENSITIVE_PROXY_VALUE"
	ops := &netops{
		proxyFromEnv: func(*http.Request) (*url.URL, error) {
			return nil, errors.New("parse " + sentinel + ": invalid control character in URL")
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("a proxy parse error must not be dialed")
			return nil, nil
		},
	}
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail {
		t.Errorf("status = %v, want FAIL", r.Status)
	}
	if !strings.Contains(r.Detail, "bad proxy configuration") || !strings.Contains(r.Detail, "HTTPS_PROXY") || !strings.Contains(r.Detail, "HTTP_PROXY") {
		t.Errorf("detail = %q, want an actionable bad proxy configuration message", r.Detail)
	}
	if strings.Contains(r.Detail, sentinel) || strings.Contains(r.Fix, sentinel) {
		t.Errorf("parser error text leaked into report: detail=%q fix=%q", r.Detail, r.Fix)
	}
}

func TestProxyProbeConnectOK(t *testing.T) {
	conn := &scriptConn{r: strings.NewReader("HTTP/1.1 200 Connection established\r\n\r\n")}
	ops := proxyOps("http://proxy.corp:3128", func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := ops.proxyProbe(ctx, nil)
	if r.Status != StatusPass || !strings.Contains(r.Detail, "proxy proxy.corp:3128 tunnels") {
		t.Errorf("granted CONNECT = %+v, want PASS", r)
	}
	if deadline, _ := ctx.Deadline(); !conn.writeDeadline.Equal(deadline) {
		t.Errorf("CONNECT write deadline = %v, want %v", conn.writeDeadline, deadline)
	}
}

func TestProxyProbeRejectsUnboundedRead(t *testing.T) {
	conn := &scriptConn{r: strings.NewReader("HTTP/1.1 200 Connection established\r\n\r\n"), readDeadlineErr: errors.New("unsupported")}
	ops := proxyOps("http://proxy.corp:3128", func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || r.Cause != ProxyCauseProtocol || !strings.Contains(r.Detail, "cannot set proxy read deadline") {
		t.Fatalf("unbounded CONNECT read = %+v, want protocol failure", r)
	}
}

// A deadline-less ctx must not leave the conn with no deadline at all.
func TestProxyProbeDeadlinelessCtxStillBoundsConn(t *testing.T) {
	conn := &scriptConn{r: strings.NewReader("HTTP/1.1 200 Connection established\r\n\r\n")}
	ops := proxyOps("http://proxy.corp:3128", func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	if r := ops.proxyProbe(context.Background(), nil); r.Status != StatusPass {
		t.Fatalf("granted CONNECT = %+v, want PASS", r)
	}
	if conn.writeDeadline.IsZero() {
		t.Error("write deadline is zero, want the probe budget as a fallback leash")
	}
}

func TestProxyProbeRefusesCleartextCredentials(t *testing.T) {
	conn := &scriptConn{r: strings.NewReader("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")}
	ops := proxyOps("http://user:pw@proxy.corp:3128", func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "refusing") {
		t.Errorf("auth over http proxy = %+v, want FAIL refusing cleartext credentials", r)
	}
	if strings.Contains(conn.w.String(), "Proxy-Authorization") {
		t.Errorf("CONNECT sent credentials before refusing:\n%s", conn.w.String())
	}
}

func TestProxyProbeHTTPSCredentialsWaitForChallenge(t *testing.T) {
	first := &scriptConn{r: strings.NewReader("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")}
	second := &scriptConn{r: strings.NewReader("HTTP/1.1 200 Connection established\r\n\r\n")}
	conns := []*scriptConn{first, second}
	ops := proxyOps("https://user:pw@proxy.corp:3128", nil)
	ops.dialTLS = func(context.Context, string, string, *tls.Config) (net.Conn, error) {
		conn := conns[0]
		conns = conns[1:]
		return conn, nil
	}
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusPass {
		t.Fatalf("authenticated CONNECT = %+v, want PASS", r)
	}
	if strings.Contains(first.w.String(), "Proxy-Authorization") {
		t.Errorf("first CONNECT sent credentials preemptively:\n%s", first.w.String())
	}
	if !strings.Contains(second.w.String(), "Proxy-Authorization: Basic dXNlcjpwdw==") {
		t.Errorf("second CONNECT did not answer challenge:\n%s", second.w.String())
	}
}

func TestProxyProbeAuthRequired(t *testing.T) {
	ops := proxyOps("http://proxy.corp:3128", func(context.Context, string, string) (net.Conn, error) {
		return &scriptConn{r: strings.NewReader("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")}, nil
	})
	r := ops.proxyProbe(context.Background(), nil)
	if r.Status != StatusFail || !strings.Contains(r.Fix, "credentials") {
		t.Errorf("407 from proxy = %+v, want FAIL with credentials fix", r)
	}
}

// noProxyBypasses matches suffixes and "*" only, with no IP literals and no CIDR, and
// is safe solely because ConnectivityProbeHost is the one host it is ever asked about. Pin
// that: whatever target the user names, the proxy probe still asks about
// ConnectivityProbeHost. If this fails, noProxyBypasses must become httpproxy.
func TestProxyProbeOnlyAsksAboutProbeHost(t *testing.T) {
	targets := []*Target{
		nil,
		{Host: "10.0.0.7", IP: net.ParseIP("10.0.0.7"), Port: 443, Proto: ProtoTLSHTTP},
		{Host: "intranet.corp", Port: 22, Proto: ProtoSSH},
	}
	for _, target := range targets {
		var asked []string
		o := &netops{proxyFromEnv: func(req *http.Request) (*url.URL, error) {
			asked = append(asked, req.URL.Hostname())
			return nil, nil
		}}
		for _, p := range o.buildProbes(target, DefaultPublicDNS, true) {
			if p.ID == ProbeProxy {
				p.Run(context.Background(), nil)
			}
		}
		if len(asked) == 0 {
			t.Fatalf("target %+v: proxy probe never consulted the environment", target)
		}
		for _, h := range asked {
			if h != ConnectivityProbeHost {
				t.Errorf("target %+v: proxy probe asked about %q, want %q", target, h, ConnectivityProbeHost)
			}
		}
	}
}

// HTTP_PROXY-only environments (no HTTPS_PROXY) still count as configured.
func TestProxyProbeFallsBackToHTTP(t *testing.T) {
	ops := &netops{proxyFromEnv: func(req *http.Request) (*url.URL, error) {
		if req.URL.Scheme == "http" {
			return url.Parse("http://proxy:8080")
		}
		return nil, nil
	}, dialContext: func(context.Context, string, string) (net.Conn, error) {
		return &scriptConn{r: strings.NewReader("HTTP/1.1 200 Connection established\r\n\r\n")}, nil
	}}
	if r := ops.proxyProbe(context.Background(), nil); r.Status != StatusPass {
		t.Errorf("HTTP_PROXY fallback = %+v, want PASS", r)
	}
}

// downgradeEgress turns a direct-egress FAIL into WARN only when another path
// carried traffic off this network: the endpoint check reached a public
// address directly, or the environment proxy tunnels traffic. The Warn is what
// takes the failure out of ok and the exit code, so activity that never left
// the network does not buy one.
func TestDowngradeEgress(t *testing.T) {
	public, lan, shared := net.ParseIP("93.184.216.34"), net.ParseIP("192.168.1.10"), net.ParseIP("100.100.100.100")
	cases := []struct {
		name string
		res  map[ProbeID]ProbeResult
		want Status
	}{
		// A resolver answering is not egress: the lookup may have been served
		// on-link from a cache or a local zone, and the generic truth table
		// already calls this state a network outage rather than a degradation.
		{"generic dns works", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass},
		}, StatusFail},
		{"generic dns fails too", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusFail},
		}, StatusFail},
		{"target tcp works", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass, SelectedIP: public},
		}, StatusWarn},
		{"target tcp works with warnings", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusWarn, SelectedIP: public},
		}, StatusWarn},
		// The two destinations that answer without leaving the network. Both
		// are ordinary targets, and neither says anything about egress.
		{"lan target works, dns too", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass, SelectedIP: lan},
		}, StatusFail},
		{"shared address space target works", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass, SelectedIP: shared},
		}, StatusFail},
		// A row that says it connected but not to where cannot support the
		// claim either, which is what an artifact from before the address was
		// recorded looks like on replay.
		{"target tcp works, address unrecorded", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass},
		}, StatusFail},
		{"target tcp fails, dns pass not enough", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusFail},
		}, StatusFail},
		{"egress passing untouched", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusPass}, ProbeDNS: {Status: StatusPass},
		}, StatusPass},
		{"proxy path saves generic", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusFail}, ProbeProxy: {Status: StatusPass},
		}, StatusWarn},
		{"degraded proxy path saves generic", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusFail}, ProbeProxy: {Status: StatusWarn},
		}, StatusWarn},
		{"proxy path saves target", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusFail}, ProbeProxy: {Status: StatusPass},
		}, StatusWarn},
		{"proxy path saves a lan-only run", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusPass}, ProbeTargetTCP: {Status: StatusPass, SelectedIP: lan}, ProbeProxy: {Status: StatusPass},
		}, StatusWarn},
		{"proxy NA not enough", map[ProbeID]ProbeResult{
			ProbeInternet: {Status: StatusFail}, ProbeDNS: {Status: StatusFail}, ProbeProxy: {Status: StatusNA},
		}, StatusFail},
	}
	for _, c := range cases {
		downgradeEgress(c.res)
		if got := c.res[ProbeInternet].Status; got != c.want {
			t.Errorf("%s: internet status = %v, want %v", c.name, got, c.want)
		}
	}
}

// A dual-stack name on a single-stack network is the common case, not a
// degraded one: the resolver hands out AAAA records an IPv4-only link can
// never reach, and every one of them fails. The connect stays a clean PASS and
// the dead addresses stay visible in Attempts. Sibling failures in the family
// that actually carried the connection still warn.
func TestTargetTCPProbeIgnoresTheAbsentFamily(t *testing.T) {
	v4, v4b, v6 := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2"), net.ParseIP("2001:db8::1")
	cases := []struct {
		name     string
		addrs    []net.IP
		reach    net.IP // the only address the stub dialer accepts
		want     Status
		attempts int
	}{
		{"v6 unreachable, v4 won", []net.IP{v4, v6}, v4, StatusPass, 2},
		// Both families are now observed independently. The failed family stays
		// evidence, but does not warn until general egress proves it usable.
		{"v4 unreachable, v6 won", []net.IP{v4, v6}, v6, StatusPass, 2},
		{"same-family sibling failed", []net.IP{v4b, v4}, v4, StatusWarn, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := &netops{
				dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
					if host, _, _ := net.SplitHostPort(addr); net.ParseIP(host).Equal(c.reach) {
						return fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.7")}}, nil
					}
					return nil, errors.New("network is unreachable")
				},
				interfaces: func() ([]net.Interface, error) {
					return []net.Interface{{Name: "fake0"}}, nil
				},
				interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
					return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}}, nil
				},
			}
			r := ops.targetTCPProbe(443)(context.Background(), map[ProbeID]ProbeResult{ProbeDNS: {Addrs: c.addrs}})
			if r.Status != c.want {
				t.Errorf("status = %v, want %v (detail %q)", r.Status, c.want, r.Detail)
			}
			if !r.SelectedIP.Equal(c.reach) {
				t.Errorf("selected = %v, want %v", r.SelectedIP, c.reach)
			}
			// Every address tried stays in the report either way.
			if len(r.Attempts) != c.attempts {
				t.Errorf("attempts = %d, want %d", len(r.Attempts), c.attempts)
			}
		})
	}
}

// ifaceProbe failure branches: enumeration error, and interfaces that exist
// but none up (loopback doesn't count).
func TestIfaceProbeFailures(t *testing.T) {
	ops := &netops{interfaces: func() ([]net.Interface, error) {
		return nil, errors.New("EPERM")
	}}
	if r := ops.ifaceProbe(context.Background(), nil); r.Status != StatusFail || !strings.Contains(r.Detail, "cannot list interfaces") {
		t.Errorf("interfaces error = %+v, want FAIL cannot list interfaces", r)
	}

	ops = &netops{interfaces: func() ([]net.Interface, error) {
		return []net.Interface{
			{Name: "lo", Flags: net.FlagLoopback | net.FlagUp | net.FlagRunning},
			{Name: "eth0", Flags: 0}, // present but down
		}, nil
	}}
	if r := ops.ifaceProbe(context.Background(), nil); r.Status != StatusFail || r.Detail != "no interface up" {
		t.Errorf("all down = %+v, want FAIL no interface up", r)
	}
}

// ifaceProbe follows the reference route, not kernel enumeration order. This is
// the case the old path got wrong: a loopback or secondary link named first
// would win enumeration, so SSID detection probed the wrong link.
func TestIfaceProbeFollowsTheReferenceRoute(t *testing.T) {
	var ssidIface string
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{
				{Name: "NpcapLoopback", Flags: net.FlagUp | net.FlagRunning},
				{Name: "Wi-Fi", Flags: net.FlagUp | net.FlagRunning},
			}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("198.51.100.7")}, []string{"192.168.1.1:53"}, nil
		},
		ssid: func(_ context.Context, iface string) string {
			ssidIface = iface
			return "Home"
		},
		routeFor: func(net.IP, net.IP) (RouteDecision, bool) {
			return RouteDecision{Iface: "Wi-Fi", Tunnel: TunnelDirect}, true
		},
	}
	o.routes = newRouteCache(o.routeFor, o.sources)

	r := o.ifaceProbe(context.Background(), nil)
	if r.Status != StatusPass || r.Iface != "Wi-Fi" {
		t.Fatalf("ifaceProbe = %v iface %q, want PASS on Wi-Fi, the interface the reference route uses", r.Status, r.Iface)
	}
	network := o.ssidProbe(context.Background(), map[ProbeID]ProbeResult{ProbeIface: r})
	if network.Status != StatusPass || network.Network != "Home" {
		t.Errorf("ssidProbe = %+v, want PASS on Home", network)
	}
	if ssidIface != "Wi-Fi" {
		t.Errorf("ssid lookup called on %q, want Wi-Fi", ssidIface)
	}
}

// When the routing table names nothing, ifaceProbe keeps the enumeration-order
// fallback, which still names the first up-and-running non-loopback interface.
func TestIfaceProbeFallsBackToEnumerationWhenRoutingNamesNothing(t *testing.T) {
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{
				{Name: "NpcapLoopback", Flags: net.FlagUp | net.FlagRunning},
				{Name: "Wi-Fi", Flags: net.FlagUp | net.FlagRunning},
			}, nil
		},
		routeFor: func(net.IP, net.IP) (RouteDecision, bool) { return RouteDecision{}, false },
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	r := o.ifaceProbe(context.Background(), nil)
	if r.Status != StatusPass || r.Iface != "NpcapLoopback" {
		t.Fatalf("ifaceProbe = %v iface %q, want fallback to the first enumerated interface", r.Status, r.Iface)
	}
}

// A routed interface that is not usable (here, down) is skipped, so the probe
// falls back to the first usable interface rather than reporting a dead link.
func TestIfaceProbeSkipsARoutedInterfaceThatIsNotUsable(t *testing.T) {
	o := &netops{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{
				{Name: "Ethernet", Flags: 0}, // down
				{Name: "Wi-Fi", Flags: net.FlagUp | net.FlagRunning},
			}, nil
		},
		routeFor: func(net.IP, net.IP) (RouteDecision, bool) {
			return RouteDecision{Iface: "Ethernet", Tunnel: TunnelDirect}, true
		},
	}
	o.routes = newRouteCache(o.routeFor, o.sources)
	r := o.ifaceProbe(context.Background(), nil)
	if r.Status != StatusPass || r.Iface != "Wi-Fi" {
		t.Fatalf("ifaceProbe = %v iface %q, want Wi-Fi since the routed Ethernet is down", r.Status, r.Iface)
	}
}

// targetTCPProbe against the stub dialer: empty DNS input, a clean connect
// (with path identity resolved through the stubbed interface list), and the
// all-addresses-failed fallback.
func TestTargetTCPProbe(t *testing.T) {
	dst := net.ParseIP("192.0.2.1")
	deps := map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{dst}}}

	r := (&netops{}).targetTCPProbe(443)(context.Background(), map[ProbeID]ProbeResult{})
	if r.Status != StatusFail || r.Detail != "no resolved addresses" {
		t.Errorf("no addrs = %+v, want FAIL no resolved addresses", r)
	}

	ops := &netops{
		dialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp4" || addr != "192.0.2.1:443" {
				t.Errorf("dialed %s %s, want tcp4 192.0.2.1:443", network, addr)
			}
			return fakeConn{local: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 40000}}, nil
		},
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "fake0"}}, nil
		},
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
	r = ops.targetTCPProbe(443)(context.Background(), deps)
	if r.Status != StatusPass || !r.SelectedIP.Equal(dst) || r.Iface != "fake0" {
		t.Errorf("connect = %+v, want PASS pinned to 192.0.2.1 via fake0", r)
	}
	// The fake dial returns instantly, so the detail exercises the Ms floor: a
	// connect that happened must not read the same 0ms as one that never ran.
	if !strings.Contains(r.Detail, "connected to 192.0.2.1:443 in 1ms") {
		t.Errorf("detail = %q, want it to mention the connect at the 1ms floor", r.Detail)
	}

	// Refuse both the TCP attempt and the UDP path-identity fallback.
	ops = &netops{dialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("refused")
	}}
	r = ops.targetTCPProbe(443)(context.Background(), deps)
	if r.Status != StatusFail || !strings.Contains(r.Detail, "port 443 unreachable on all 1 address(es)") {
		t.Errorf("all refused = %+v, want FAIL port unreachable", r)
	}
	if !strings.Contains(r.Fix, "firewall") {
		t.Errorf("fix = %q, want the firewall hint", r.Fix)
	}
	if len(r.Attempts) != 1 || r.Attempts[0].Err == nil {
		t.Errorf("attempts = %+v, want the single failed attempt recorded", r.Attempts)
	}
}

// Probes hand their results to buildProbes' wrapper, which is the only place
// external text gets sanitized, so a probe that emits raw escapes must come
// out clean anyway.
func TestCleanResultScrubsEveryTextField(t *testing.T) {
	hostile := "boom\x1b[31m\x07"
	r := cleanResult(ProbeResult{
		Detail:   hostile,
		Fix:      hostile,
		Iface:    hostile,
		Network:  hostile,
		Portal:   &Portal{RedirectURL: "https://portal.example/" + hostile},
		Attempts: []Attempt{{Err: errors.New(hostile)}},
	})
	for name, got := range map[string]string{
		"Detail":  r.Detail,
		"Fix":     r.Fix,
		"Iface":   r.Iface,
		"Network": r.Network,
		"Portal":  r.Portal.RedirectURL,
		"Attempt": r.Attempts[0].Err.Error(),
	} {
		want := "boom"
		if name == "Portal" {
			want = "https://portal.example/boom"
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// A measured attempt must never render as the 0ms that means "never ran". Only
// fails where the clock is coarse enough to return 0 for back-to-back calls,
// which is Windows, the platform that regressed TestTargetTCPProbe.
func TestSinceNeverZero(t *testing.T) {
	if d := since(time.Now()); Ms(d) < 1 {
		t.Errorf("since(now) = %v, Ms = %d, want at least 1ms", d, Ms(d))
	}
}

// hasGlobalUnicast answers an address-configuration question, not a link-state
// one: FlagUp (administratively up) gates it, FlagRunning (carrier/operational)
// deliberately does not. A cable pulled from a configured NIC leaves the
// address assigned, and that is exactly the black-holed case the caller warns
// about, and requiring FlagRunning here would silence it.
func TestHasGlobalUnicastIgnoresRunningState(t *testing.T) {
	addr := func(s string) []net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", s, err)
		}
		n.IP = ip
		return []net.Addr{n}
	}
	for _, tc := range []struct {
		name  string
		flags net.Flags
		addrs []net.Addr
		v4    bool
		want  bool
	}{
		{"up without carrier still counts", net.FlagUp, addr("192.0.2.5/24"), true, true},
		{"up and running counts", net.FlagUp | net.FlagRunning, addr("192.0.2.5/24"), true, true},
		{"administratively down does not", 0, addr("192.0.2.5/24"), true, false},
		{"running but admin down does not", net.FlagRunning, addr("192.0.2.5/24"), true, false},
		{"loopback never counts", net.FlagUp | net.FlagRunning | net.FlagLoopback, addr("127.0.0.1/8"), true, false},
		{"link-local v4 is not configured egress", net.FlagUp, addr("169.254.1.2/16"), true, false},
		{"v6 up without carrier still counts", net.FlagUp, addr("2001:db8::1/64"), false, true},
		{"v6 ULA does not count", net.FlagUp | net.FlagRunning, addr("fd00::1/64"), false, false},
		{"wrong family does not count", net.FlagUp | net.FlagRunning, addr("192.0.2.5/24"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := &netops{
				interfaces: func() ([]net.Interface, error) {
					return []net.Interface{{Name: "eth0", Flags: tc.flags}}, nil
				},
				interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return tc.addrs, nil },
			}
			if got := ops.hasGlobalUnicast(tc.v4); got != tc.want {
				t.Errorf("hasGlobalUnicast(v4=%v) = %v, want %v", tc.v4, got, tc.want)
			}
		})
	}
}

// closeTrackingConn records that the code under test closed it. A second Close
// panics, which is the point: a discarded connection is closed exactly once.
type closeTrackingConn struct {
	fakeConn
	closed chan struct{}
}

func (c *closeTrackingConn) Close() error { close(c.closed); return nil }

// TestDualFamilyDialCancellationDoesNotStrandFanIn pins the invariant that every
// launched family goroutine reports exactly once. The ordering is forced, not
// raced: IPv4 cancels the context and then releases IPv6, so the IPv6 dial is
// guaranteed to succeed with the context already done, which is the branch that
// used to return without sending anything and wedge the receive loop forever.
func TestDualFamilyDialCancellationDoesNotStrandFanIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cancelled := make(chan struct{})
	late := &closeTrackingConn{closed: make(chan struct{})}
	var mu sync.Mutex
	var dialed []string

	restore := dialFamily
	defer func() { dialFamily = restore }()
	dialFamily = func(dctx context.Context, _ net.IP, network, _ string, _ func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, network)
		mu.Unlock()
		if strings.HasSuffix(network, "6") {
			<-cancelled
			if dctx.Err() == nil {
				t.Error("IPv6 dial finished with a live context, ordering seam broke")
			}
			return late, nil
		}
		cancel()
		close(cancelled)
		return nil, errors.New("v4 refused")
	}

	type outcome struct {
		conn net.Conn
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		conn, err := dialContextFromSources(&SourceAddresses{
			IPv4: net.ParseIP("127.0.0.1"),
			IPv6: net.ParseIP("::1"),
		})(ctx, "tcp", "example.invalid:443")
		done <- outcome{conn, err}
	}()

	select {
	case got := <-done:
		if got.conn != nil {
			t.Errorf("conn = %v, want nil after cancellation", got.conn)
		}
		if !errors.Is(got.err, context.Canceled) {
			t.Errorf("err = %v, want it to carry context.Canceled", got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial never returned: a family goroutine reported no result")
	}

	select {
	case <-late.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("connection dialed after cancellation was leaked")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 2 || !slices.Contains(dialed, "tcp4") || !slices.Contains(dialed, "tcp6") {
		t.Fatalf("dialed families = %v, want both tcp4 and tcp6", dialed)
	}
}

// TestDualFamilyDialClosesTheLosingConnection covers the other half of the
// completion invariant: when both families connect, one connection goes to the
// caller and the other is closed by the goroutine that owns it. Repeated so the
// two families interleave differently, and closeTrackingConn panics on a second
// Close, so a double completion is caught too.
func TestDualFamilyDialClosesTheLosingConnection(t *testing.T) {
	restore := dialFamily
	defer func() { dialFamily = restore }()

	for range 50 {
		conns := map[string]*closeTrackingConn{
			"tcp4": {closed: make(chan struct{})},
			"tcp6": {closed: make(chan struct{})},
		}
		dialFamily = func(_ context.Context, _ net.IP, network, _ string, _ func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
			return conns[network], nil
		}
		conn, err := dialContextFromSources(&SourceAddresses{
			IPv4: net.ParseIP("127.0.0.1"),
			IPv6: net.ParseIP("::1"),
		})(context.Background(), "tcp", "example.invalid:443")
		if err != nil || conn == nil {
			t.Fatalf("dial = (%v, %v), want a connection", conn, err)
		}
		for network, c := range conns {
			if net.Conn(c) == conn {
				continue
			}
			select {
			case <-c.closed:
			case <-time.After(5 * time.Second):
				t.Fatalf("losing %s connection was never closed", network)
			}
		}
	}
}

// TestLoneFamilyDialIsNotDiscarded covers the fan-out with a single selected
// family, which is what an IPv4-only interface gets. Nothing competes for the
// claim, so the connection has to reach the caller. A claim that discarded its
// own winner would fail every hostname dial on such an interface and would push
// errFamilyLost out into a probe error, which the dual-family tests cannot see.
func TestLoneFamilyDialIsNotDiscarded(t *testing.T) {
	restore := dialFamily
	defer func() { dialFamily = restore }()

	only := &closeTrackingConn{closed: make(chan struct{})}
	dialFamily = func(_ context.Context, _ net.IP, _, _ string, _ func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
		return only, nil
	}
	conn, err := dialContextFromSources(&SourceAddresses{IPv4: net.ParseIP("127.0.0.1")})(
		context.Background(), "tcp", "example.invalid:443")
	if err != nil || net.Conn(only) != conn {
		t.Fatalf("dial = (%v, %v), want the dialed connection and no error", conn, err)
	}
	select {
	case <-only.closed:
		t.Error("the only connection was closed instead of returned")
	default:
	}
}

// Ambiguous interface selection is structured state, not the display string.
// A source address held by two interfaces warns through a real probe, and an
// interface whose actual name matches the placeholder text does not, while the
// placeholder still shows up where a human reads it.
func TestAmbiguousIfaceIsStateNotDisplayText(t *testing.T) {
	src := net.ParseIP("192.0.2.7")
	twoIfaces := func() ([]net.Interface, error) {
		return []net.Interface{{Name: "fake0", Flags: net.FlagUp | net.FlagRunning}, {Name: "fake1", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	holdsSrc := func(*net.Interface) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: src, Mask: net.CIDRMask(24, 32)}}, nil
	}

	// The producer that renders the placeholder: --iface pinned an address that
	// two interfaces hold, so the row shows "(ambiguous)" and records the state.
	pinned := netops{interfaces: twoIfaces, interfaceAddrs: holdsSrc, sources: &SourceAddresses{IPv4: src}}
	r := pinned.ifaceProbe(context.Background(), nil)
	if r.Status != StatusWarn || r.Iface != "(ambiguous)" || !r.ifaceAmbiguous {
		t.Fatalf("ifaceProbe(two matches) = %v iface %q ambiguous %t, want WARN, the placeholder, and the state set", r.Status, r.Iface, r.ifaceAmbiguous)
	}

	// The consumer: a dial whose source maps to two interfaces still warns.
	ops := netops{interfaces: twoIfaces, interfaceAddrs: holdsSrc}
	conn := fakeConn{local: &net.TCPAddr{IP: src, Port: 40000}}
	r = ops.proxyTunnelOK(context.Background(), conn, "proxy.example:8080", time.Millisecond)
	if r.Status != StatusWarn || !r.ifaceAmbiguous || !strings.Contains(r.Detail, "ambiguous source interface") {
		t.Fatalf("proxyTunnelOK(two matches) = %v ambiguous %t detail %q, want a WARN naming the ambiguous source interface", r.Status, r.ifaceAmbiguous, r.Detail)
	}

	// The regression: one interface, whose real name happens to be the
	// placeholder. Unambiguous, so no warning, even though Iface matches.
	ops.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "(ambiguous)", Flags: net.FlagUp | net.FlagRunning}}, nil
	}
	r = ops.proxyTunnelOK(context.Background(), conn, "proxy.example:8080", time.Millisecond)
	if r.Iface != "(ambiguous)" {
		t.Fatalf("proxyTunnelOK iface = %q, want the interface name reported as-is", r.Iface)
	}
	if r.Status != StatusPass || r.ifaceAmbiguous || strings.Contains(r.Detail, "ambiguous source interface") {
		t.Fatalf("proxyTunnelOK(interface named %q) = %v ambiguous %t detail %q, want a clean PASS", r.Iface, r.Status, r.ifaceAmbiguous, r.Detail)
	}
}
