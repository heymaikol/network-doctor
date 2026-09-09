// Shape checks for the probe DAG that BuildProbesFromSources returns per protocol.

package diagnostic

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustTarget(t *testing.T, s string) *Target {
	t.Helper()
	tg, err := ParseTarget(s)
	if err != nil {
		t.Fatalf("ParseTarget(%q): %v", s, err)
	}
	return tg
}

func TestInternetProbeEndpointsAreDefensiveCopies(t *testing.T) {
	ipv4, ipv6 := InternetProbeEndpoints()
	ipv4[0][0] ^= 0xff
	ipv4[1] = net.IPv4zero
	ipv6[0][0] ^= 0xff
	ipv6[1] = net.IPv6zero

	ipv4, ipv6 = InternetProbeEndpoints()
	if got := joinIPs(ipv4); got != "1.1.1.1, 8.8.8.8" {
		t.Errorf("IPv4 endpoints after caller mutation = %q", got)
	}
	if got := joinIPs(ipv6); got != "2606:4700:4700::1111, 2001:4860:4860::8888" {
		t.Errorf("IPv6 endpoints after caller mutation = %q", got)
	}
}

// A target adds iface, TCP and QUIC Internet checks, proxy, system/public/
// encrypted DNS, target_tcp, ssid, plus path_mtu and protocol rows when the
// protocol is known.
func TestBuildProbesShape(t *testing.T) {
	cases := []struct {
		target string // empty means no target
		want   int
	}{
		{"", 8},                    // no target, so no target_tcp/path_mtu/protocol rows
		{"github.com", 13},         // + tls, http, https
		{"http://example.com", 11}, // + http
		{"host:22", 11},            // + ssh banner
		{"ssh://host:2222", 11},    // + ssh banner
		{"host:25", 11},            // + smtp banner
		{"host:587", 11},           // + smtp banner
		{"smtp://host:2525", 11},   // + smtp banner
		{"host:9999", 9},           // ProtoNone, stops at target_tcp
	}
	for _, c := range cases {
		var tg *Target
		if c.target != "" {
			tg = mustTarget(t, c.target)
		}
		if got := len(BuildProbesFromSources(tg, nil, DefaultPublicDNS, true)); got != c.want {
			t.Errorf("BuildProbesFromSources(%q) = %d probes, want %d", c.target, got, c.want)
		}
	}
}

// --public-dns names the second-opinion resolver, and both target and generic
// mode have to honor it. An empty value removes the row from the DAG rather
// than emitting a skipped one: a row that still had to dial in order to report
// itself skipped would not be an opt-out. The default names no resolver at all,
// so its row cannot name one either; an address the user typed is on the row
// even when it is the same address the default would have reached first.
func TestBuildProbesPublicDNSIsConfigurable(t *testing.T) {
	for _, tc := range []struct {
		name, publicDNS string
		auto            bool
		want            string
	}{
		{"default", DefaultPublicDNS, true, "DNS (public)"}, // no resolver decided yet
		{"explicit default address", "8.8.8.8", false, "DNS (public 8.8.8.8)"},
		{"custom IPv4", "9.9.9.9", false, "DNS (public 9.9.9.9)"},
		{"custom IPv6", "2620:fe::fe", false, "DNS (public 2620:fe::fe)"},
		{"disabled", "", false, ""}, // absent, so the loop below leaves want empty
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, target := range []*Target{nil, mustTarget(t, "example.com:443")} {
				got := ""
				for _, p := range BuildProbesFromSources(target, nil, tc.publicDNS, tc.auto) {
					if p.ID == ProbeDNSPublic {
						got = p.Name
					}
				}
				if got != tc.want {
					t.Errorf("target %v: public DNS row = %q, want %q", target, got, tc.want)
				}
			}
		})
	}
}

// The opt-out has to be real rather than cosmetic: with the row disabled, no
// probe in the DAG may quietly reach a resolver. Port 53 is the assertion:
// 8.8.8.8:443 stays a fixed direct-egress endpoint, which is a different row
// with a different question.
func TestDisabledPublicDNSNeverQueriesTheResolver(t *testing.T) {
	var (
		mu     sync.Mutex
		dialed []string
	)
	o := &netops{
		interfaces:     func() ([]net.Interface, error) { return nil, nil },
		interfaceAddrs: func(*net.Interface) ([]net.Addr, error) { return nil, nil },
		lookupIP: func(context.Context, string) ([]net.IP, []string, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, []string{"192.0.2.53:53"}, nil
		},
		lookupPublicIP: func(_ context.Context, _, server string) ([]net.IP, []string, error) {
			t.Errorf("queried %q with the public-DNS check disabled", server)
			return nil, nil, nil
		},
		proxyFromEnv: func(*http.Request) (*url.URL, error) { return nil, nil },
		ssid:         func(context.Context, string) string { return "" },
		dialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			return nil, errors.New("no network in tests")
		},
	}
	for _, p := range o.buildProbes(nil, "", false) {
		if p.ID == ProbeDNSPublic {
			t.Fatal("the public DNS probe is still in the DAG")
		}
		p.Run(context.Background(), map[ProbeID]ProbeResult{})
	}
	mu.Lock()
	defer mu.Unlock()
	for _, addr := range dialed {
		if strings.HasSuffix(addr, ":53") {
			t.Errorf("dialed resolver %q with the public-DNS check disabled", addr)
		}
	}
}

func TestSSIDDoesNotGateNetworkProbes(t *testing.T) {
	probes := BuildProbesFromSources(nil, nil, DefaultPublicDNS, true)
	deps := make(map[ProbeID][]ProbeID, len(probes))
	for _, p := range probes {
		deps[p.ID] = p.Deps
	}
	if got := deps[ProbeSSID]; len(got) != 1 || got[0] != ProbeIface {
		t.Fatalf("ssid deps = %v, want [iface]", got)
	}
	for _, id := range []ProbeID{ProbeInternet, ProbeQUIC, ProbeProxy, ProbeDNS, ProbeDNSPublic, ProbeDNSEncrypted} {
		got := deps[id]
		if len(got) != 1 || got[0] != ProbeIface {
			t.Errorf("%s deps = %v, want [iface]", id, got)
		}
	}
}

func TestQUICProbeIsConcurrentSiblingAfterInternetTCP(t *testing.T) {
	probes := BuildProbesFromSources(nil, nil, DefaultPublicDNS, true)
	for i, probe := range probes {
		if probe.ID != ProbeQUIC {
			continue
		}
		if i == 0 || probes[i-1].ID != ProbeInternet {
			t.Fatalf("QUIC row index = %d, want immediately after Internet TCP", i)
		}
		if len(probe.Deps) != 1 || probe.Deps[0] != ProbeIface {
			t.Fatalf("QUIC deps = %v, want [iface] so TCP and QUIC run independently", probe.Deps)
		}
		return
	}
	t.Fatal("QUIC probe missing from DAG")
}

func TestBuildProbesNamesProtocolApplicationRow(t *testing.T) {
	https := BuildProbesFromSources(mustTarget(t, "https://example.com"), nil, DefaultPublicDNS, true)
	want := []struct {
		id   ProbeID
		name string
		dep  ProbeID
	}{
		{id: ProbeTLS, name: "TLS example.com", dep: ProbeTargetTCP},
		{id: ProbeHTTP, name: "HTTP example.com", dep: ProbeDNS},
		{id: ProbeHTTPS, name: "HTTPS example.com", dep: ProbeTLS},
	}
	for i, tt := range want {
		got := https[len(https)-len(want)+i]
		if got.ID != tt.id || got.Name != tt.name {
			t.Errorf("probe %d = (%q, %q), want (%q, %q)", i, got.ID, got.Name, tt.id, tt.name)
		}
		if len(got.Deps) != 1 || got.Deps[0] != tt.dep {
			t.Errorf("probe %s deps = %v, want [%s]", got.ID, got.Deps, tt.dep)
		}
	}

	http := BuildProbesFromSources(mustTarget(t, "http://example.com"), nil, DefaultPublicDNS, true)
	got := http[len(http)-1]
	if got.ID != ProbeHTTP || got.Name != "HTTP example.com" || len(got.Deps) != 1 || got.Deps[0] != ProbeTargetTCP {
		t.Errorf("plain HTTP application probe = %+v, want HTTP depending on target TCP", got)
	}
}

// Every probe is timed by the same wrapper that sanitizes it, so both runners
// report durations without either one keeping its own stopwatch.
func TestWrapRunTimesAndCleans(t *testing.T) {
	run := wrapRun(func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
		time.Sleep(2 * time.Millisecond)
		return ProbeResult{Detail: "hello\x1b[31mworld"}
	})
	r := run(context.Background(), nil)
	if r.Dur < 2*time.Millisecond {
		t.Errorf("Dur = %v, want at least 2ms", r.Dur)
	}
	if strings.Contains(r.Detail, "\x1b") {
		t.Errorf("Detail = %q, want the escape sanitized away", r.Detail)
	}
}

func TestConnectionFailureCause(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{context.Canceled, ConnectionCauseCanceled},
		{context.DeadlineExceeded, ConnectionCauseTimeout},
		{connectionRefusedErrno, ConnectionCauseRefused},
		{errors.New("no route"), ConnectionCauseUnreachable},
	} {
		if got := ConnectionFailureCause(test.err); got != test.want {
			t.Errorf("ConnectionFailureCause(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
