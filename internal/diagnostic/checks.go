// Package diagnostic implements target parsing, native network probes, and
// diagnosis without depending on terminal presentation.
package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mplaczek99/network-doctor/internal/textsafe"
)

// Status is a probe's five-state outcome. Warn = degraded but functional
// (high latency, some addresses failing, ambiguous source interface, missing
// service banner, or direct egress blocked while another path works) — never
// counted as a failure. Skip = a prerequisite failed (an
// independent probe is never Skipped for an unrelated sibling's failure).
// NotApplicable = the probe doesn't apply at all (DNS on an IP literal, a
// protocol row absent for this port) — not counted as a failure.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
	StatusSkip
	StatusNA
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	case StatusSkip:
		return "SKIP"
	case StatusNA:
		return "N/A"
	}
	return "?"
}

// Attempt is one connection attempt against a single address.
type Attempt struct {
	IP  net.IP
	Dur time.Duration
	Err error
}

// ProbeID is a stable DAG node id.
type ProbeID string

const (
	ProbeIface     ProbeID = "iface"
	ProbeInternet  ProbeID = "internet_tcp"
	ProbeProxy     ProbeID = "proxy_connect"
	ProbeDNS       ProbeID = "dns"
	ProbeTargetTCP ProbeID = "target_tcp"
	ProbeTLS       ProbeID = "tls"
	ProbeHTTP      ProbeID = "http"
	ProbeHTTPS     ProbeID = "https"
	ProbeSSH       ProbeID = "ssh_banner"
	ProbeSMTP      ProbeID = "smtp_banner"
)

// ProbeResult is the typed contract the diagnosis engine and renderer consume.
// Detail/Fix are derived human text, never parsed back.
type ProbeResult struct {
	ID         ProbeID
	Status     Status
	Addrs      []net.IP // DNS publishes all A records here
	SelectedIP net.IP   // winning/pinned IP used by this probe
	Source     net.IP
	Iface      string
	Network    string // connected Wi-Fi SSID, empty when wired/unknown
	Attempts   []Attempt
	Detail     string
	Fix        string
}

// Probe is one DAG node. Run receives an immutable snapshot of just its
// dependency outputs and must honor ctx and never panic.
type Probe struct {
	ID   ProbeID
	Name string
	Deps []ProbeID
	Run  func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult
}

const (
	// ProbeTimeout bounds a single probe (the model wraps each in a child ctx).
	ProbeTimeout = 4 * time.Second
	// attemptDelay is the Happy Eyeballs (RFC 8305) connection-attempt stagger:
	// the next address starts this long after the previous one, or immediately
	// once the previous attempt fails.
	attemptDelay = 250 * time.Millisecond
	// maxAttempts bounds the recorded/attempted addresses per probe.
	maxAttempts = 16
	// warnRTT is the connect latency above which a successful dial is reported
	// as degraded rather than a clean pass.
	warnRTT = 500 * time.Millisecond
)

// probeHost is the host used by the generic (no-target) DNS + egress probes.
const probeHost = "connectivitycheck.gstatic.com"

// internetEndpoints4/6 are the ordered direct-egress endpoints per address
// family; first connect wins within a family. Honestly "direct TCP egress" —
// proxy-only networks can fail this.
var (
	internetEndpoints4 = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}
	internetEndpoints6 = []net.IP{net.ParseIP("2606:4700:4700::1111"), net.ParseIP("2001:4860:4860::8888")}
)

// netops holds every network/OS touchpoint the probes use, as function fields
// so tests can stub them and run probes deterministically without real
// network access. Production code always goes through defaultOps.
type netops struct {
	interfaces     func() ([]net.Interface, error)
	interfaceAddrs func(*net.Interface) ([]net.Addr, error)
	lookupIP       func(ctx context.Context, host string) ([]net.IP, error)
	dialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	dialTLS        func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)
	ssid           func(ctx context.Context, iface string) string
	defaultRoute   func(ctx context.Context) (string, bool, error)
	proxyFromEnv   func(*http.Request) (*url.URL, error)
}

var defaultOps = &netops{
	interfaces:     net.Interfaces,
	interfaceAddrs: (*net.Interface).Addrs,
	lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip", host)
	},
	dialContext: new(net.Dialer).DialContext,
	dialTLS: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		d := tls.Dialer{NetDialer: new(net.Dialer), Config: cfg}
		return d.DialContext(ctx, network, addr)
	},
	ssid:         ssid,
	defaultRoute: defaultRoute,
	proxyFromEnv: http.ProxyFromEnvironment,
}

// BuildProbes constructs the DAG for the given target (nil = generic mode).
func BuildProbes(t *Target) []Probe { return defaultOps.buildProbes(t) }

func (o *netops) buildProbes(t *Target) []Probe {
	iface := Probe{ID: ProbeIface, Name: "Interface", Run: o.ifaceProbe}
	internet := Probe{ID: ProbeInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{ProbeIface}, Run: o.internetProbe}
	// Direct and proxied egress are reported separately: the native probes
	// deliberately bypass proxies, so on a proxy-only network the direct row
	// fails while this row proves the environment proxy carries traffic.
	proxy := Probe{ID: ProbeProxy, Name: "Internet (env proxy)", Deps: []ProbeID{ProbeIface}, Run: o.proxyProbe}

	if t == nil {
		// Egress, proxy egress, and DNS are siblings: each depends only on the
		// interface, so one failure never hides another.
		dns := Probe{ID: ProbeDNS, Name: "DNS", Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(probeHost, false, nil)}
		return []Probe{iface, internet, proxy, dns}
	}

	host, port := t.Host, t.Port
	hp := net.JoinHostPort(host, strconv.Itoa(port)) // brackets IPv6 literals
	dns := Probe{ID: ProbeDNS, Name: "DNS " + host, Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(host, t.IsLiteral, t.IP)}
	ttcp := Probe{ID: ProbeTargetTCP, Name: "TCP " + hp, Deps: []ProbeID{ProbeDNS}, Run: o.targetTCPProbe(port)}
	probes := []Probe{iface, internet, proxy, dns, ttcp}

	switch t.Proto {
	case ProtoTLSHTTP:
		probes = append(probes,
			Probe{ID: ProbeTLS, Name: "TLS " + host, Deps: []ProbeID{ProbeTargetTCP}, Run: o.tlsProbe(host, port)},
			Probe{ID: ProbeHTTP, Name: "HTTP " + host, Deps: []ProbeID{ProbeDNS}, Run: o.httpProbe(ProbeHTTP, host, 80, "http", ProbeDNS)},
			Probe{ID: ProbeHTTPS, Name: "HTTPS " + host, Deps: []ProbeID{ProbeTLS}, Run: o.httpProbe(ProbeHTTPS, host, port, "https", ProbeTLS)},
		)
	case ProtoHTTP:
		probes = append(probes,
			Probe{ID: ProbeHTTP, Name: "HTTP " + host, Deps: []ProbeID{ProbeTargetTCP}, Run: o.httpProbe(ProbeHTTP, host, port, "http", ProbeTargetTCP)},
		)
	case ProtoSSH:
		probes = append(probes, o.bannerProbe(ProbeSSH, "SSH banner "+hp, port))
	case ProtoSMTP:
		probes = append(probes, o.bannerProbe(ProbeSMTP, "SMTP banner "+hp, port))
	}
	return probes
}

// ---- probe implementations ----

func (o *netops) ifaceProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	r := ProbeResult{ID: ProbeIface}
	ifaces, err := o.interfaces()
	if err != nil {
		r.Status = StatusFail
		r.Detail, r.Fix = "cannot list interfaces: "+err.Error(), "check permissions / network stack"
		return r
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0 {
			r.Status, r.Iface, r.Detail = StatusPass, ifi.Name, "interface "+ifi.Name+" is up"
			r.Network = o.ssid(ctx, ifi.Name)
			return r
		}
	}
	r.Status = StatusFail
	r.Detail, r.Fix = "no interface up", ifaceFix(runtime.GOOS)
	return r
}

func (o *netops) internetProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	r := ProbeResult{ID: ProbeInternet}
	type famResult struct {
		conn     net.Conn
		sel      net.IP
		attempts []Attempt
		rtt      time.Duration
	}
	// Each family is probed independently and in parallel: a black-holing
	// family only spends its own share of the probe deadline, and IPv4 and
	// IPv6 egress are diagnosed separately.
	var v4, v6 famResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		v4.conn, v4.sel, v4.attempts, v4.rtt = o.dialIPs(ctx, internetEndpoints4, 443)
	}()
	go func() {
		defer wg.Done()
		v6.conn, v6.sel, v6.attempts, v6.rtt = o.dialIPs(ctx, internetEndpoints6, 443)
	}()
	wg.Wait()

	prim, sec, primName, secName := v4, v6, "IPv4", "IPv6"
	if v4.conn == nil && v6.conn != nil {
		prim, sec, primName, secName = v6, v4, "IPv6", "IPv4"
	}
	if prim.conn == nil {
		r.Attempts = append(v4.attempts, v6.attempts...)
		src, iface := o.pathIdentity(ctx, nil, internetEndpoints4[0], 443)
		r.Status, r.Source, r.Iface = StatusFail, src, iface
		r.Detail = "no direct TCP egress on IPv4 (1.1.1.1, 8.8.8.8:443) or IPv6"
		r.Fix = "no internet egress — proxy-only/filtered network? check upstream"
		return r
	}
	defer prim.conn.Close()
	if sec.conn != nil {
		sec.conn.Close()
	}
	src, iface := o.pathIdentity(ctx, prim.conn, prim.sel, 443)
	r.Status, r.SelectedIP, r.Source, r.Iface = StatusPass, prim.sel, src, iface
	r.Detail = fmt.Sprintf("%s egress via %s in %dms (src %s %s)", primName, prim.sel, prim.rtt.Milliseconds(), src, iface)
	if sec.conn != nil {
		r.Detail += fmt.Sprintf("; %s egress via %s in %dms", secName, sec.sel, sec.rtt.Milliseconds())
	} else {
		r.Detail += "; no " + secName + " egress"
	}
	if gw, found, _ := o.defaultRoute(ctx); found {
		r.Detail += "; default route via " + gw
	}
	// Warnings judge only the winning family: a network without the other
	// family at all is normal, not degraded. The other family's attempts are
	// appended afterwards so the details panel still shows them.
	r.Attempts = prim.attempts
	applyDialWarnings(&r, prim.rtt)
	r.Attempts = append(prim.attempts, sec.attempts...)
	return r
}

// envProxyURL returns the proxy the environment configures for outbound
// HTTPS (falling back to plain HTTP), or nil when none applies. NO_PROXY and
// lowercase variants are honored via the stdlib rules.
func (o *netops) envProxyURL() (*url.URL, error) {
	for _, scheme := range []string{"https", "http"} {
		u, err := o.proxyFromEnv(&http.Request{URL: &url.URL{Scheme: scheme, Host: probeHost}})
		if err != nil || u != nil {
			return u, err
		}
	}
	return nil, nil
}

// proxyProbe checks egress through the environment-configured proxy: dial the
// proxy and ask for a CONNECT tunnel to probeHost:443. This is exactly what
// proxied HTTPS clients do, minus the TLS handshake inside the tunnel.
func (o *netops) proxyProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	r := ProbeResult{ID: ProbeProxy}
	proxyURL, err := o.envProxyURL()
	if err != nil {
		r.Status = StatusFail
		r.Detail = "bad proxy configuration: " + textsafe.Clean(err.Error())
		r.Fix = "fix the HTTPS_PROXY/HTTP_PROXY value"
		return r
	}
	if proxyURL == nil {
		r.Status = StatusNA
		r.Detail = "no proxy in environment (HTTPS_PROXY/HTTP_PROXY unset)"
		return r
	}
	addr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	start := time.Now()
	var conn net.Conn
	if proxyURL.Scheme == "https" {
		conn, err = o.dialTLS(ctx, "tcp", addr, &tls.Config{ServerName: proxyURL.Hostname()})
	} else {
		conn, err = o.dialContext(ctx, "tcp", addr)
	}
	if err != nil {
		r.Status = StatusFail
		r.Detail = "cannot reach proxy " + textsafe.Clean(addr) + ": " + textsafe.Clean(err.Error())
		r.Fix = "proxy configured but unreachable — check HTTPS_PROXY/HTTP_PROXY and the proxy host"
		return r
	}
	defer conn.Close()
	req := "CONNECT " + probeHost + ":443 HTTP/1.1\r\nHost: " + probeHost + ":443\r\n"
	if u := proxyURL.User; u != nil {
		pw, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)) + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		r.Status = StatusFail
		r.Detail = "proxy write failed: " + textsafe.Clean(err.Error())
		return r
	}
	conn.SetReadDeadline(time.Now().Add(remaining(ctx)))
	// Bounded read: the response is attacker-controlled.
	resp, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 4096)), &http.Request{Method: http.MethodConnect})
	if err != nil {
		r.Status = StatusFail
		r.Detail = "no CONNECT response from proxy " + textsafe.Clean(addr) + ": " + textsafe.Clean(err.Error())
		r.Fix = "proxy reachable but not speaking HTTP — wrong port or scheme?"
		return r
	}
	resp.Body.Close()
	rtt := time.Since(start)
	if resp.StatusCode/100 != 2 {
		r.Status = StatusFail
		r.Detail = "proxy " + textsafe.Clean(addr) + " refused CONNECT: " + textsafe.Clean(resp.Status)
		if resp.StatusCode == http.StatusProxyAuthRequired {
			r.Fix = "proxy requires credentials — set user:pass@host in HTTPS_PROXY"
		} else {
			r.Fix = "proxy reachable but refusing tunnels — check proxy policy"
		}
		return r
	}
	src, iface := o.pathIdentity(ctx, conn, nil, 0)
	r.Status, r.Source, r.Iface = StatusPass, src, iface
	r.Detail = fmt.Sprintf("proxy %s tunnels to %s:443 in %dms", addr, probeHost, rtt.Milliseconds())
	applyDialWarnings(&r, rtt)
	return r
}

func (o *netops) dnsProbe(host string, literal bool, litIP net.IP) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: ProbeDNS}
		if literal {
			r.Status, r.Addrs, r.SelectedIP = StatusNA, []net.IP{litIP}, litIP
			r.Detail = "literal IP " + litIP.String() + " — no DNS needed"
			return r
		}
		ips, err := o.lookupIP(ctx, host)
		if err != nil {
			r.Status = StatusFail
			r.Detail = "cannot resolve " + host + ": " + textsafe.Clean(err.Error())
			r.Fix = dnsFix(runtime.GOOS)
			return r
		}
		if len(ips) == 0 {
			r.Status = StatusFail
			r.Detail, r.Fix = "no A/AAAA records for "+host, "no address returned — check the hostname / DNS"
			return r
		}
		r.Status, r.Addrs = StatusPass, ips
		r.Detail = host + " → " + joinIPs(ips)
		return r
	}
}

func (o *netops) targetTCPProbe(port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: ProbeTargetTCP}
		addrs := deps[ProbeDNS].Addrs
		if len(addrs) == 0 {
			r.Status, r.Detail = StatusFail, "no resolved addresses"
			return r
		}
		conn, sel, attempts, rtt := o.dialIPs(ctx, addrs, port)
		r.Attempts = attempts
		if conn != nil {
			defer conn.Close()
			src, iface := o.pathIdentity(ctx, conn, sel, port)
			r.Status, r.SelectedIP, r.Source, r.Iface = StatusPass, sel, src, iface
			r.Detail = fmt.Sprintf("connected to %s:%d in %dms (src %s %s)", sel, port, rtt.Milliseconds(), src, iface)
			applyDialWarnings(&r, rtt)
			return r
		}
		// All addresses failed: deterministic fallback path = first address.
		src, iface := o.pathIdentity(ctx, nil, addrs[0], port)
		r.Status, r.Source, r.Iface = StatusFail, src, iface
		r.Detail = fmt.Sprintf("port %d unreachable on all %d address(es)", port, len(addrs))
		r.Fix = fmt.Sprintf("port %d blocked/refused — firewall, wrong network, or VPN routing?", port)
		return r
	}
}

func (o *netops) tlsProbe(host string, port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: ProbeTLS}
		ip := deps[ProbeTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		conn, err := o.dialTLS(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), &tls.Config{ServerName: host})
		if err != nil {
			r.Status = StatusFail
			r.Detail = "TLS handshake failed: " + textsafe.Clean(err.Error())
			r.Fix = "TLS broken — clock skew, bad/expired cert, or MITM proxy?"
			return r
		}
		conn.Close()
		r.Status, r.SelectedIP, r.Detail = StatusPass, ip, "TLS handshake OK (SNI "+host+")"
		return r
	}
}

func (o *netops) httpProbe(id ProbeID, host string, port int, scheme string, addressDep ProbeID) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: id}
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
		tr := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				conn, selected, attempts, _ := o.dialIPs(ctx, addrs, port)
				r.SelectedIP, r.Attempts = selected, attempts
				if conn == nil {
					if len(attempts) > 0 && attempts[len(attempts)-1].Err != nil {
						return nil, attempts[len(attempts)-1].Err
					}
					return nil, fmt.Errorf("all %s addresses failed", protocol)
				}
				return conn, nil
			},
			TLSClientConfig:        &tls.Config{ServerName: host},
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
		}
		client := &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			r.Status, r.Detail = StatusFail, "cannot build request: "+err.Error()
			return r
		}
		resp, err := client.Do(req)
		if err != nil {
			r.Status = StatusFail
			r.Detail = "no " + protocol + " response: " + textsafe.Clean(err.Error())
			r.Fix = protocol + " blocked — proxy or firewall?"
			return r
		}
		resp.Body.Close()
		r.Status = StatusPass
		r.Detail = fmt.Sprintf("%s %d (responded)", protocol, resp.StatusCode)
		return r
	}
}

func (o *netops) bannerProbe(id ProbeID, label string, port int) Probe {
	return Probe{ID: id, Name: label, Deps: []ProbeID{ProbeTargetTCP}, Run: func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: id}
		ip := deps[ProbeTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		conn, err := o.dialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			r.Status, r.Detail = StatusFail, "connect failed: "+textsafe.Clean(err.Error())
			return r
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// Strict byte limit: a hostile server streaming without a newline can't
		// exhaust memory.
		br := bufio.NewReader(io.LimitReader(conn, 1024))
		line, _ := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		r.SelectedIP = ip
		if line == "" {
			// Port answered but the service said nothing: functional, degraded.
			r.Status, r.Detail = StatusWarn, "connected, no banner within deadline"
		} else {
			r.Status, r.Detail = StatusPass, "banner: "+textsafe.Clean(line)
		}
		return r
	}}
}

// ---- shared helpers ----

// applyDialWarnings downgrades a successful dial result to Warn when it is
// degraded: high connect latency, sibling addresses that failed before one
// won, or an ambiguous source interface. Notes are appended to Detail.
func applyDialWarnings(r *ProbeResult, rtt time.Duration) {
	var notes []string
	if rtt >= warnRTT {
		notes = append(notes, fmt.Sprintf("high latency (%dms)", rtt.Milliseconds()))
	}
	// dialIPs records completed attempts plus the winner (last), so every
	// earlier attempt genuinely failed before the win.
	if n := len(r.Attempts) - 1; n > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d address(es) failed%s", n, len(r.Attempts), familyNote(r.Attempts, r.SelectedIP)))
	}
	if r.Iface == "(ambiguous)" {
		notes = append(notes, "ambiguous source interface")
	}
	if len(notes) > 0 {
		r.Status = StatusWarn
		r.Detail += " — warning: " + strings.Join(notes, ", ")
	}
}

// familyNote names the broken-family signature: every failed attempt was in
// the other address family than the winner. Mixed or same-family failures
// return no note.
func familyNote(attempts []Attempt, sel net.IP) string {
	if sel == nil {
		return ""
	}
	selV4 := sel.To4() != nil
	other := 0
	for _, a := range attempts {
		if a.Err == nil {
			continue
		}
		if (a.IP.To4() != nil) == selV4 {
			return ""
		}
		other++
	}
	if other == 0 {
		return ""
	}
	if selV4 {
		return " (IPv6 unreachable, connected via IPv4)"
	}
	return " (IPv4 unreachable, connected via IPv6)"
}

// interleaveFamilies orders addresses IPv6-first, alternating families
// (RFC 8305 §4), so one broken family can't monopolize the attempt sequence.
func interleaveFamilies(ips []net.IP) []net.IP {
	var v6, v4 []net.IP
	for _, ip := range ips {
		if ip.To4() == nil {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	if len(v6) == 0 || len(v4) == 0 {
		return ips
	}
	out := make([]net.IP, 0, len(ips))
	for i := 0; i < len(v6) || i < len(v4); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out
}

// dialIPs races ip:port connection attempts Happy Eyeballs style (RFC 8305):
// addresses are interleaved by family (IPv6 first), each attempt starts
// attemptDelay after the previous one (sooner once it fails), and the first
// success cancels the rest. Returns the winning conn, the IP that won (pinned
// for protocol probes), the attempts that completed before the win, and the
// winning RTT. A cancelled/expired ctx dials nothing.
func (o *netops) dialIPs(ctx context.Context, ips []net.IP, port int) (net.Conn, net.IP, []Attempt, time.Duration) {
	ips = interleaveFamilies(ips)
	if len(ips) > maxAttempts {
		ips = ips[:maxAttempts]
	}
	if len(ips) == 0 {
		return nil, nil, nil, 0
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel() // unblocks pending winner hand-offs so losers close their conns

	type result struct {
		conn net.Conn
		att  Attempt
	}
	winner := make(chan result)           // unbuffered: hand off or close, never leak
	fails := make(chan Attempt, len(ips)) // buffered: a failure never blocks its goroutine
	next := make(chan struct{}, len(ips)) // a failure fast-forwards the stagger

	go func() {
		for i, ip := range ips {
			if i > 0 {
				t := time.NewTimer(attemptDelay)
				select {
				case <-t.C:
				case <-next:
				case <-dctx.Done():
					t.Stop()
					return
				}
				t.Stop()
			}
			if dctx.Err() != nil {
				return
			}
			go func(ip net.IP) {
				start := time.Now()
				conn, err := o.dialContext(dctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
				att := Attempt{IP: ip, Dur: time.Since(start), Err: err}
				if err != nil {
					fails <- att
					next <- struct{}{}
					return
				}
				select {
				case winner <- result{conn, att}:
				case <-dctx.Done():
					conn.Close() // lost the race
				}
			}(ip)
		}
	}()

	var attempts []Attempt
	for pending := len(ips); pending > 0; pending-- {
		select {
		case w := <-winner:
			attempts = append(attempts, w.att)
			return w.conn, w.att.IP, attempts, w.att.Dur
		case att := <-fails:
			attempts = append(attempts, att)
		case <-ctx.Done():
			return nil, nil, attempts, 0
		}
	}
	return nil, nil, attempts, 0
}

// pathIdentity returns the source IP + interface for a destination. On a
// successful connect it reads the winning LocalAddr (ground truth); otherwise it
// falls back to a UDP "connect" (sends no packets) for path identity only — not
// a reachability claim.
func (o *netops) pathIdentity(ctx context.Context, conn net.Conn, dstIP net.IP, port int) (net.IP, string) {
	var src net.IP
	if conn != nil {
		if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			src = la.IP
		}
	} else if dstIP != nil {
		if c, err := o.dialContext(ctx, "udp", net.JoinHostPort(dstIP.String(), strconv.Itoa(port))); err == nil {
			if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
				src = la.IP
			}
			c.Close()
		}
	}
	if src == nil {
		return nil, ""
	}
	return src, o.ifaceForIP(src)
}

// ifaceForIP maps a source IP back to an interface name. LocalAddr gives an IP,
// not a name, so ambiguity (same IP on >1 iface) and no-match are explicit
// states, not a guess.
func (o *netops) ifaceForIP(ip net.IP) string {
	ifaces, err := o.interfaces()
	if err != nil {
		return ""
	}
	name, count := "", 0
	for _, ifi := range ifaces {
		addrs, err := o.interfaceAddrs(&ifi)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				name, count = ifi.Name, count+1
			}
		}
	}
	switch {
	case count == 0:
		return "(unknown iface)"
	case count > 1:
		return "(ambiguous)"
	default:
		return name
	}
}

func joinIPs(ips []net.IP) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}

// remaining returns the time left on ctx's deadline, or ProbeTimeout if none.
func remaining(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
		return 0
	}
	return ProbeTimeout
}
