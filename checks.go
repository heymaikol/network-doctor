package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Status is true when a check passes.
type Status bool

const (
	Fail Status = false
	Pass Status = true
)

// Result is what a Check reports: an outcome, a human-readable detail, and a
// remediation hint shown only on failure.
type Result struct {
	Status Status
	Detail string
	Fix    string
}

// Check is one diagnostic. Run must honor ctx (timeout/cancel) and never panic.
type Check struct {
	Name string
	Run  func(ctx context.Context) Result
}

// checkTimeout bounds every individual check. The model wires this into a
// per-check context.WithTimeout.
const checkTimeout = 4 * time.Second

// probeHost is the single host used by both name-resolution and internet
// checks, so a blocked unrelated host can't cause a false negative.
const probeHost = "connectivitycheck.gstatic.com"

// httpClient is dedicated to the internet check:
//   - Timeout bounds the whole request as a backstop to ctx.
//   - CheckRedirect refuses redirects: a captive portal 30x/200 must not be
//     mistaken for a real 204.
//   - Proxy nil: we test host connectivity, not a proxy.
//   - DialContext forces tcp4 for IPv4-only consistency.
var httpClient = &http.Client{
	Timeout: checkTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr)
		},
	},
}

// httpsPort and sshPort are the target ports probed in target mode.
const (
	httpsPort = 443
	sshPort   = 22
)

// checks returns the ordered diagnostic chain. Order is the narrative: the
// first Fail read top-down is the earliest observed symptom (layered bottom-up:
// link -> IP -> route -> gateway -> DNS -> TCP -> TLS -> HTTP -> SSH).
//
// With no target it runs the generic local+internet chain. With a target it
// keeps the local-infra prefix, then probes the path to that specific host.
func checks(target string) []Check {
	if target == "" {
		return []Check{
			{Name: "Link", Run: checkLink},
			{Name: "IP address", Run: checkIP},
			{Name: "Gateway", Run: checkGateway},
			{Name: "Name resolution", Run: checkResolve},
			{Name: "Internet", Run: checkInternet},
		}
	}
	tcpFix := "port " + strconv.Itoa(httpsPort) + " blocked/refused — firewall or wrong network?"
	return []Check{
		{Name: "Link", Run: checkLink},
		{Name: "IP address", Run: checkIP},
		{Name: "Default route", Run: checkGateway},
		{Name: "Gateway reachable", Run: checkGatewayReachable},
		{Name: "DNS " + target, Run: targetResolve(target)},
		{Name: "TCP " + target + ":" + strconv.Itoa(httpsPort), Run: targetTCP(target, httpsPort, tcpFix)},
		{Name: "TLS " + target, Run: targetTLS(target)},
		{Name: "HTTP " + target, Run: targetHTTP(target)},
		{Name: "SSH " + target + ":" + strconv.Itoa(sshPort), Run: targetTCP(target, sshPort, sshFix(target))},
	}
}

// normalizeTarget strips a scheme and trailing slash so `netdoc https://github.com/`
// and `netdoc github.com` behave the same.
// ponytail: bare host only — doesn't parse out a port or path in the arg, add if needed.
func normalizeTarget(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return strings.TrimSuffix(s, "/")
}

// sshFix is the remediation hint shown when SSH to the target is blocked.
// github.com gets its known ssh-over-443 fallback; other hosts get the generic form.
func sshFix(host string) string {
	if host == "github.com" {
		return "SSH to github.com:22 blocked/refused. Try:\n      ssh -T git@github.com\n      ssh -T -p 443 git@ssh.github.com"
	}
	return "SSH to " + host + ":22 blocked/refused — firewall? try over 443 if the host supports it"
}

// checkLink: at least one non-loopback interface that is up and running.
func checkLink(ctx context.Context) Result {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Result{Fail, "cannot list interfaces: " + err.Error(), "check permissions / network stack"}
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0 {
			return Result{Pass, "interface " + ifi.Name + " is up", ""}
		}
	}
	return Result{Fail, "no interface up", "bring up an interface (cable/Wi-Fi) or `ip link set <iface> up`"}
}

// checkIP: at least one non-loopback, non-link-local IPv4 address.
func checkIP(ctx context.Context) Result {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return Result{Fail, "cannot list addresses: " + err.Error(), "check network stack"}
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue // not IPv4 (rejects IPv6)
		}
		if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue // reject 127/8 and 169.254/16
		}
		return Result{Pass, "have IPv4 " + ip4.String(), ""}
	}
	return Result{Fail, "no usable IPv4 address", "no usable IPv4 (DHCP?) — check DHCP / static config"}
}

// checkGateway: an IPv4 default route exists. Distinguishes an unreadable route
// table (internal error) from a readable table with no default route.
func checkGateway(ctx context.Context) Result {
	gw, found, err := defaultRoute()
	if err != nil {
		return Result{Fail, "cannot read route table: " + err.Error(), "internal: /proc/net/route unreadable"}
	}
	if !found {
		return Result{Fail, "no IPv4 default route", "add a default route / check gateway (DHCP?)"}
	}
	return Result{Pass, "default route via " + gw, ""}
}

// checkResolve: resolve the same host the internet check hits, IPv4-only.
// Honestly tests system name resolution (/etc/hosts + resolvers), not pure DNS.
func checkResolve(ctx context.Context) Result {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", probeHost)
	if err != nil {
		return Result{Fail, "cannot resolve " + probeHost + ": " + err.Error(), "name resolution failing — check /etc/resolv.conf / DNS"}
	}
	if len(ips) == 0 {
		return Result{Fail, "no IPv4 address for " + probeHost, "name resolution failing — no A record returned"}
	}
	return Result{Pass, probeHost + " resolves to " + ips[0].String(), ""}
}

// checkInternet: HTTP GET the generate_204 endpoint; require status exactly 204.
// A captive portal returning 200+body (or a redirect) is correctly a Fail.
func checkInternet(ctx context.Context) Result {
	url := "http://" + probeHost + "/generate_204"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Fail, "cannot build request: " + err.Error(), "internal error"}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Fail, "request failed: " + err.Error(), "no internet — check upstream connectivity"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return Result{Fail, fmt.Sprintf("unexpected status %d", resp.StatusCode), "no internet / captive portal — open a browser to sign in"}
	}
	return Result{Pass, "reached internet (204)", ""}
}

// checkGatewayReachable: the default gateway has a complete ARP entry — proof
// we've exchanged L2 frames with it (unprivileged, no ICMP/raw socket needed).
func checkGatewayReachable(ctx context.Context) Result {
	ok, err := gatewayReachable()
	if err != nil {
		return Result{Fail, "cannot check gateway: " + err.Error(), "internal: route/arp table unreadable"}
	}
	if !ok {
		return Result{Fail, "gateway not answering at L2", "gateway down — check cable/Wi-Fi link or DHCP lease"}
	}
	return Result{Pass, "gateway answered (ARP)", ""}
}

// targetResolve resolves the user-supplied target, IPv4-only (system resolution).
func targetResolve(host string) func(context.Context) Result {
	return func(ctx context.Context) Result {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return Result{Fail, "cannot resolve " + host + ": " + err.Error(), "DNS failing — check /etc/resolv.conf / DNS"}
		}
		if len(ips) == 0 {
			return Result{Fail, "no IPv4 for " + host, "no A record — check the hostname / DNS"}
		}
		return Result{Pass, host + " → " + ips[0].String(), ""}
	}
}

// targetTCP dials host:port over IPv4; an open connection => Pass. Used for both
// the HTTPS (443) and SSH (22) reachability checks, with a port-specific fix.
func targetTCP(host string, port int, fix string) func(context.Context) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return func(ctx context.Context) Result {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp4", addr)
		if err != nil {
			return Result{Fail, addr + " unreachable: " + err.Error(), fix}
		}
		conn.Close()
		return Result{Pass, addr + " open", ""}
	}
}

// targetTLS does a full TLS handshake to host:443 with SNI and cert verification
// (the default tls.Config). A bad/expired cert or MITM proxy is correctly a Fail.
func targetTLS(host string) func(context.Context) Result {
	addr := net.JoinHostPort(host, strconv.Itoa(httpsPort))
	return func(ctx context.Context) Result {
		d := tls.Dialer{Config: &tls.Config{ServerName: host}}
		conn, err := d.DialContext(ctx, "tcp4", addr)
		if err != nil {
			return Result{Fail, "TLS handshake failed: " + err.Error(), "TLS broken — clock skew, bad cert, or MITM proxy?"}
		}
		conn.Close()
		return Result{Pass, "TLS handshake OK", ""}
	}
}

// targetHTTP GETs https://host; any HTTP response (incl. 3xx/4xx/5xx) => Pass.
// Reuses httpClient, whose CheckRedirect returns the redirect response rather
// than following it, so a 30x still counts as "a response was received".
func targetHTTP(host string) func(context.Context) Result {
	url := "https://" + host
	return func(ctx context.Context) Result {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return Result{Fail, "cannot build request: " + err.Error(), "internal error"}
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return Result{Fail, "no HTTP response: " + err.Error(), "HTTP blocked — proxy or firewall?"}
		}
		defer resp.Body.Close()
		return Result{Pass, fmt.Sprintf("HTTP %d", resp.StatusCode), ""}
	}
}
