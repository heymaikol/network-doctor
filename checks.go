package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
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

// FailClass categorises a failure for the diagnosis engine without parsing
// display strings.
type FailClass int

const (
	FailNone FailClass = iota
	FailTimeout
	FailRefused
	FailNoRoute
	FailDNS
	FailTLS
	FailOther
)

// Attempt is one connection attempt against a single address.
type Attempt struct {
	IP  net.IP
	Dur time.Duration
	Err error
}

// ProbeID is a stable DAG node id.
type ProbeID string

const (
	pIface     ProbeID = "iface"
	pInternet  ProbeID = "internet_tcp"
	pDNS       ProbeID = "dns"
	pTargetTCP ProbeID = "target_tcp"
	pTLS       ProbeID = "tls"
	pHTTP      ProbeID = "http"
	pSSH       ProbeID = "ssh_banner"
	pSMTP      ProbeID = "smtp_banner"
)

// ProbeResult is the typed contract the diagnosis engine and renderer consume.
// Detail/Fix are derived human text, never parsed back.
type ProbeResult struct {
	ID         ProbeID
	Status     Status
	Fail       FailClass
	Addrs      []net.IP // DNS publishes all A records here
	SelectedIP net.IP   // Target TCP publishes the pinned IP
	Source     net.IP
	Iface      string
	Attempts   []Attempt
	RTT        time.Duration
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
	// probeTimeout bounds a single probe (the model wraps each in a child ctx).
	probeTimeout = 4 * time.Second
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

// buildProbes constructs the DAG for the given target (nil = generic mode).
func buildProbes(t *Target) []Probe {
	iface := Probe{ID: pIface, Name: "Interface", Run: ifaceProbe}
	internet := Probe{ID: pInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{pIface}, Run: internetProbe}

	if t == nil {
		// Egress and DNS are siblings: each depends only on the interface, so an
		// egress failure never hides a DNS failure (or vice-versa).
		dns := Probe{ID: pDNS, Name: "DNS", Deps: []ProbeID{pIface}, Run: dnsProbe(probeHost, false, nil)}
		return []Probe{iface, internet, dns}
	}

	host, port := t.Host, t.Port
	dns := Probe{ID: pDNS, Name: "DNS " + host, Deps: []ProbeID{pIface}, Run: dnsProbe(host, t.IsLiteral, t.IP)}
	ttcp := Probe{ID: pTargetTCP, Name: fmt.Sprintf("TCP %s:%d", host, port), Deps: []ProbeID{pDNS}, Run: targetTCPProbe(port)}
	probes := []Probe{iface, internet, dns, ttcp}

	switch t.Proto {
	case ProtoTLSHTTP:
		probes = append(probes,
			Probe{ID: pTLS, Name: "TLS " + host, Deps: []ProbeID{pTargetTCP}, Run: tlsProbe(host, port)},
			Probe{ID: pHTTP, Name: "HTTP " + host, Deps: []ProbeID{pTargetTCP}, Run: httpProbe(host, port, "https")},
		)
	case ProtoHTTP:
		probes = append(probes,
			Probe{ID: pHTTP, Name: "HTTP " + host, Deps: []ProbeID{pTargetTCP}, Run: httpProbe(host, port, "http")},
		)
	case ProtoSSH:
		probes = append(probes, bannerProbe(pSSH, fmt.Sprintf("SSH banner %s:%d", host, port), port))
	case ProtoSMTP:
		probes = append(probes, bannerProbe(pSMTP, fmt.Sprintf("SMTP banner %s:%d", host, port), port))
	}
	return probes
}

// ---- probe implementations ----

func ifaceProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	r := ProbeResult{ID: pIface}
	ifaces, err := net.Interfaces()
	if err != nil {
		r.Status, r.Fail = StatusFail, FailOther
		r.Detail, r.Fix = "cannot list interfaces: "+err.Error(), "check permissions / network stack"
		return r
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0 {
			r.Status, r.Detail = StatusPass, "interface "+ifi.Name+" is up"
			return r
		}
	}
	r.Status, r.Fail = StatusFail, FailNoRoute
	r.Detail, r.Fix = "no interface up", "bring up an interface (cable/Wi-Fi) or `ip link set <iface> up`"
	return r
}

func internetProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	r := ProbeResult{ID: pInternet}
	conn, sel, attempts, rtt := dialIPs(ctx, internetEndpoints, 443)
	r.Attempts, r.RTT = attempts, rtt
	if conn != nil {
		defer conn.Close()
		src, iface := pathIdentity(conn, sel, 443)
		r.Status, r.SelectedIP, r.Source, r.Iface = StatusPass, sel, src, iface
		r.Detail = fmt.Sprintf("direct egress via %s in %dms (src %s %s)", sel, rtt.Milliseconds(), src, iface)
		if gw, found, _ := defaultRoute(); found {
			r.Detail += "; default route via " + gw
		}
		return r
	}
	src, iface := pathIdentity(nil, internetEndpoints[0], 443)
	r.Status, r.Fail, r.Source, r.Iface = StatusFail, classify(lastErr(attempts)), src, iface
	r.Detail = "no direct TCP egress to 1.1.1.1/8.8.8.8:443"
	r.Fix = "no internet egress — proxy-only/filtered network? check upstream"
	return r
}

func dnsProbe(host string, literal bool, litIP net.IP) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: pDNS}
		if literal {
			r.Status, r.Addrs, r.SelectedIP = StatusNA, []net.IP{litIP}, litIP
			r.Detail = "literal IP " + litIP.String() + " — no DNS needed"
			return r
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			r.Status, r.Fail = StatusFail, FailDNS
			r.Detail = "cannot resolve " + host + ": " + sanitize(err.Error())
			r.Fix = "name resolution failing — check /etc/resolv.conf / DNS"
			return r
		}
		if len(ips) == 0 {
			r.Status, r.Fail = StatusFail, FailDNS
			r.Detail, r.Fix = "no A record for "+host, "no IPv4 address returned — check the hostname / DNS"
			return r
		}
		r.Status, r.Addrs = StatusPass, ips
		r.Detail = host + " → " + joinIPs(ips)
		return r
	}
}

func targetTCPProbe(port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: pTargetTCP}
		addrs := deps[pDNS].Addrs
		if len(addrs) == 0 {
			r.Status, r.Fail, r.Detail = StatusFail, FailDNS, "no resolved addresses"
			return r
		}
		conn, sel, attempts, rtt := dialIPs(ctx, addrs, port)
		r.Attempts, r.RTT = attempts, rtt
		if conn != nil {
			defer conn.Close()
			src, iface := pathIdentity(conn, sel, port)
			r.Status, r.SelectedIP, r.Source, r.Iface = StatusPass, sel, src, iface
			r.Detail = fmt.Sprintf("connected to %s:%d in %dms (src %s %s)", sel, port, rtt.Milliseconds(), src, iface)
			return r
		}
		// All addresses failed: deterministic fallback path = first address.
		src, iface := pathIdentity(nil, addrs[0], port)
		r.Status, r.Fail, r.Source, r.Iface = StatusFail, classify(lastErr(attempts)), src, iface
		r.Detail = fmt.Sprintf("port %d unreachable on all %d address(es)", port, len(addrs))
		r.Fix = fmt.Sprintf("port %d blocked/refused — firewall, wrong network, or VPN routing?", port)
		return r
	}
}

func tlsProbe(host string, port int) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: pTLS}
		ip := deps[pTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		d := tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{ServerName: host}}
		conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			r.Status, r.Fail = StatusFail, FailTLS
			r.Detail = "TLS handshake failed: " + sanitize(err.Error())
			r.Fix = "TLS broken — clock skew, bad/expired cert, or MITM proxy?"
			return r
		}
		conn.Close()
		r.Status, r.SelectedIP, r.Detail = StatusPass, ip, "TLS handshake OK (SNI "+host+")"
		return r
	}
}

func httpProbe(host string, port int, scheme string) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: pHTTP}
		ip := deps[pTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		dialAddr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		// Fresh, non-reusing transport pinned to the selected IP; redirects and
		// proxy off; bounded response headers (attacker-controlled).
		tr := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", dialAddr)
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
			r.Status, r.Fail, r.Detail = StatusFail, FailOther, "cannot build request: "+err.Error()
			return r
		}
		resp, err := client.Do(req)
		if err != nil {
			r.Status, r.Fail = StatusFail, classify(err)
			r.Detail, r.Fix = "no HTTP response: "+sanitize(err.Error()), "HTTP blocked — proxy or firewall?"
			return r
		}
		resp.Body.Close()
		r.Status, r.SelectedIP = StatusPass, ip
		r.Detail = fmt.Sprintf("HTTP %d (responded)", resp.StatusCode)
		return r
	}
}

func bannerProbe(id ProbeID, label string, port int) Probe {
	return Probe{ID: id, Name: label, Deps: []ProbeID{pTargetTCP}, Run: func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := ProbeResult{ID: id}
		ip := deps[pTargetTCP].SelectedIP
		if ip == nil {
			r.Status, r.Detail = StatusSkip, "no pinned IP from Target TCP"
			return r
		}
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			r.Status, r.Fail, r.Detail = StatusFail, classify(err), "connect failed: "+sanitize(err.Error())
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
			r.Detail = "banner: " + sanitize(line)
		}
		return r
	}}
}

// ---- shared helpers ----

// dialIPs dials each ip:port in order, giving each address a per-destination
// budget within ctx's deadline, and returns the first successful conn, the IP
// that won (pinned for protocol probes), the bounded attempt record, and the
// winning RTT. ponytail: serial dial; happy-eyeballs parallelism is a later opt.
func dialIPs(ctx context.Context, ips []net.IP, port int) (net.Conn, net.IP, []Attempt, time.Duration) {
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
	var d net.Dialer
	for i := 0; i < n; i++ {
		ip := ips[i]
		addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
		actx, cancel := context.WithTimeout(ctx, budget)
		start := time.Now()
		conn, err := d.DialContext(actx, "tcp4", addr)
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
func pathIdentity(conn net.Conn, dstIP net.IP, port int) (net.IP, string) {
	var src net.IP
	if conn != nil {
		if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			src = la.IP
		}
	} else if dstIP != nil {
		if c, err := net.Dial("udp4", net.JoinHostPort(dstIP.String(), strconv.Itoa(port))); err == nil {
			if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
				src = la.IP
			}
			c.Close()
		}
	}
	if src == nil {
		return nil, ""
	}
	return src, ifaceForIP(src)
}

// ifaceForIP maps a source IP back to an interface name. LocalAddr gives an IP,
// not a name, so ambiguity (same IP on >1 iface) and no-match are explicit
// states, not a guess.
func ifaceForIP(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	name, count := "", 0
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
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

func classify(err error) FailClass {
	switch {
	case err == nil:
		return FailNone
	case errors.Is(err, context.DeadlineExceeded):
		return FailTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return FailRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETDOWN):
		return FailNoRoute
	default:
		return FailOther
	}
}

func lastErr(attempts []Attempt) error {
	for i := len(attempts) - 1; i >= 0; i-- {
		if attempts[i].Err != nil {
			return attempts[i].Err
		}
	}
	return nil
}

func joinIPs(ips []net.IP) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = ip.String()
	}
	return strings.Join(parts, ", ")
}

// remaining returns the time left on ctx's deadline, or probeTimeout if none.
func remaining(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			return d
		}
		return 0
	}
	return probeTimeout
}
