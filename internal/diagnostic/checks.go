// Package diagnostic implements target parsing, native network probes, and
// diagnosis without depending on terminal presentation.
package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mplaczek99/network-doctor/internal/textsafe"
)

// Status is a probe's four-state outcome. Skip = a prerequisite failed (an
// independent probe is never Skipped for an unrelated sibling's failure).
// NotApplicable = the probe doesn't apply at all (DNS on an IP literal, a
// protocol row absent for this port) — not counted as a failure.
type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkip
	StatusNA
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
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
	// minBudget floors the per-address dial budget so a many-A-record host
	// doesn't shrink each attempt to nothing.
	minBudget = 700 * time.Millisecond
	// maxAttempts bounds the recorded/attempted addresses per probe.
	maxAttempts = 16
)

// probeHost is the host used by the generic (no-target) DNS + egress probes.
const probeHost = "connectivitycheck.gstatic.com"

// internetEndpoints is the ordered direct-egress endpoint list; first connect
// wins. Honestly "direct TCP egress" — proxy-only networks can fail this.
var internetEndpoints = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}

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
}

var defaultOps = &netops{
	interfaces:     net.Interfaces,
	interfaceAddrs: (*net.Interface).Addrs,
	lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
		return net.DefaultResolver.LookupIP(ctx, "ip4", host)
	},
	dialContext: new(net.Dialer).DialContext,
	dialTLS: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		d := tls.Dialer{NetDialer: new(net.Dialer), Config: cfg}
		return d.DialContext(ctx, network, addr)
	},
	ssid:         ssid,
	defaultRoute: defaultRoute,
}

// BuildProbes constructs the DAG for the given target (nil = generic mode).
func BuildProbes(t *Target) []Probe { return defaultOps.buildProbes(t) }

func (o *netops) buildProbes(t *Target) []Probe {
	iface := Probe{ID: ProbeIface, Name: "Interface", Run: o.ifaceProbe}
	internet := Probe{ID: ProbeInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{ProbeIface}, Run: o.internetProbe}

	if t == nil {
		// Egress and DNS are siblings: each depends only on the interface, so an
		// egress failure never hides a DNS failure (or vice-versa).
		dns := Probe{ID: ProbeDNS, Name: "DNS", Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(probeHost, false, nil)}
		return []Probe{iface, internet, dns}
	}

	host, port := t.Host, t.Port
	dns := Probe{ID: ProbeDNS, Name: "DNS " + host, Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(host, t.IsLiteral, t.IP)}
	ttcp := Probe{ID: ProbeTargetTCP, Name: fmt.Sprintf("TCP %s:%d", host, port), Deps: []ProbeID{ProbeDNS}, Run: o.targetTCPProbe(port)}
	probes := []Probe{iface, internet, dns, ttcp}

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
		probes = append(probes, o.bannerProbe(ProbeSSH, fmt.Sprintf("SSH banner %s:%d", host, port), port))
	case ProtoSMTP:
		probes = append(probes, o.bannerProbe(ProbeSMTP, fmt.Sprintf("SMTP banner %s:%d", host, port), port))
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
	conn, sel, attempts, rtt := o.dialIPs(ctx, internetEndpoints, 443)
	r.Attempts = attempts
	if conn != nil {
		defer conn.Close()
		src, iface := o.pathIdentity(ctx, conn, sel, 443)
		r.Status, r.SelectedIP, r.Source, r.Iface = StatusPass, sel, src, iface
		r.Detail = fmt.Sprintf("direct egress via %s in %dms (src %s %s)", sel, rtt.Milliseconds(), src, iface)
		if gw, found, _ := o.defaultRoute(ctx); found {
			r.Detail += "; default route via " + gw
		}
		return r
	}
	src, iface := o.pathIdentity(ctx, nil, internetEndpoints[0], 443)
	r.Status, r.Source, r.Iface = StatusFail, src, iface
	r.Detail = "no direct TCP egress to 1.1.1.1/8.8.8.8:443"
	r.Fix = "no internet egress — proxy-only/filtered network? check upstream"
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
			r.Detail, r.Fix = "no A record for "+host, "no IPv4 address returned — check the hostname / DNS"
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
		conn, err := o.dialTLS(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)), &tls.Config{ServerName: host})
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
		conn, err := o.dialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
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
		r.Status, r.SelectedIP = StatusPass, ip
		if line == "" {
			r.Detail = "connected, no banner within deadline"
		} else {
			r.Detail = "banner: " + textsafe.Clean(line)
		}
		return r
	}}
}

// ---- shared helpers ----

// dialIPs dials each ip:port in order, giving each address a per-destination
// budget within ctx's deadline, and returns the first successful conn, the IP
// that won (pinned for protocol probes), the bounded attempt record, and the
// winning RTT. ponytail: serial dial; happy-eyeballs parallelism is a later opt.
func (o *netops) dialIPs(ctx context.Context, ips []net.IP, port int) (net.Conn, net.IP, []Attempt, time.Duration) {
	var attempts []Attempt
	n := len(ips)
	if n == 0 {
		return nil, nil, attempts, 0
	}
	if n > maxAttempts {
		n = maxAttempts
	}
	budget := remaining(ctx) / time.Duration(n)
	if budget < minBudget {
		budget = minBudget
	}
	for i := 0; i < n; i++ {
		ip := ips[i]
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		actx, cancel := context.WithTimeout(ctx, budget)
		start := time.Now()
		conn, err := o.dialContext(actx, "tcp4", addr)
		dur := time.Since(start)
		cancel()
		attempts = append(attempts, Attempt{IP: ip, Dur: dur, Err: err})
		if err == nil {
			return conn, ip, attempts, dur
		}
		if ctx.Err() != nil {
			break // overall deadline/cancel reached
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
		if c, err := o.dialContext(ctx, "udp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port))); err == nil {
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
