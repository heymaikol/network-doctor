package diagnostic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// proxyFromEnvironment is http.ProxyFromEnvironment plus ALL_PROXY, which Go
// ignores but curl, ssh and the SOCKS ecosystem honor. A box whose only proxy
// setting is ALL_PROXY=socks5h://... is proxied, and the report has to say so.
func proxyFromEnvironment(req *http.Request) (*url.URL, error) {
	u, err := http.ProxyFromEnvironment(req)
	if u != nil || err != nil {
		return u, err
	}
	// net/http already applied NO_PROXY to HTTP(S)_PROXY, so a nil here can
	// equally mean "exempted", and falling back to ALL_PROXY on that would report
	// a proxy nothing would use for this host.
	if noProxyBypasses(req.URL) {
		return nil, nil
	}
	all := os.Getenv("ALL_PROXY")
	if all == "" {
		all = os.Getenv("all_proxy")
	}
	if all == "" {
		return nil, nil
	}
	// Same tolerance net/http grants HTTP_PROXY: a bare host:port means http.
	if u, err := url.Parse(all); err == nil && u.Scheme != "" && u.Host != "" {
		return u, nil
	}
	return url.Parse("http://" + all)
}

// noProxyBypasses reports whether NO_PROXY exempts reqURL from proxying, the
// check net/http applies to HTTP(S)_PROXY and this file has to apply itself to
// the ALL_PROXY fallback. It defers to httpproxy, the same matcher net/http
// builds ProxyFromEnvironment out of, so an entry carrying a port, a CIDR
// block or a bare IP reads here exactly as it reads there. The sentinel proxy
// is what turns ProxyFunc into a bypass oracle: with a proxy configured for
// both schemes, a nil answer can only mean this request is exempt.
func noProxyBypasses(reqURL *url.URL) bool {
	np := os.Getenv("NO_PROXY")
	if np == "" {
		np = os.Getenv("no_proxy")
	}
	if np == "" {
		return false
	}
	const sentinel = "http://proxy.invalid"
	proxy, err := (&httpproxy.Config{HTTPProxy: sentinel, HTTPSProxy: sentinel, NoProxy: np}).ProxyFunc()(reqURL)
	return err == nil && proxy == nil
}

// proxyProbe checks egress through the environment-configured proxy: dial the
// proxy and ask it to tunnel to ConnectivityProbeHost:443, by HTTP CONNECT or a SOCKS5
// handshake. This is exactly what proxied HTTPS clients do, minus the TLS
// handshake inside the tunnel.
func (o *netops) proxyProbe(ctx context.Context, _ map[ProbeID]ProbeResult) ProbeResult {
	var r ProbeResult
	var proxyURL *url.URL
	var err error
	// Only https:// decides this probe, since it stands in for an HTTPS
	// client, and net/http reads HTTP_PROXY only for plain http:// requests.
	// The http:// lookup below explains an N/A; that proxy is never dialed.
	proxyURL, err = o.proxyFromEnv(&http.Request{URL: &url.URL{Scheme: "https", Host: ConnectivityProbeHost}})
	plainHTTPProxy := false
	if err == nil && proxyURL == nil {
		var httpURL *url.URL
		httpURL, err = o.proxyFromEnv(&http.Request{URL: &url.URL{Scheme: "http", Host: ConnectivityProbeHost}})
		plainHTTPProxy = httpURL != nil
	}
	if err != nil {
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "bad proxy configuration: HTTPS_PROXY/HTTP_PROXY/ALL_PROXY is not a valid proxy URL"
		r.Fix = "fix the HTTPS_PROXY/HTTP_PROXY/ALL_PROXY value"
		return r
	}
	if proxyURL == nil {
		r.Status = StatusNA
		r.Detail = "no proxy in environment (HTTPS_PROXY/HTTP_PROXY/ALL_PROXY unset)"
		if plainHTTPProxy {
			r.Detail = "no proxy applies to HTTPS requests, but one applies to plain HTTP"
		}
		return r
	}
	// A bare root path ("http://proxy:3128/") is the same endpoint as none.
	if proxyURL.Hostname() == "" || (proxyURL.Path != "" && proxyURL.Path != "/") || proxyURL.RawQuery != "" || proxyURL.ForceQuery || proxyURL.Fragment != "" {
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "bad proxy configuration: proxy URL must have a valid host and no path, query, or fragment"
		r.Fix = "fix the HTTPS_PROXY/HTTP_PROXY/ALL_PROXY value"
		return r
	}
	socks := proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h"
	if !socks && proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		r.Status = StatusNA
		r.Detail = "proxy scheme " + proxyURL.Scheme + " is not supported by this probe"
		return r
	}
	if port := proxyURL.Port(); port != "" {
		if _, err := parsePort(port); err != nil {
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "bad proxy configuration: " + err.Error()
			r.Fix = "fix the HTTPS_PROXY/HTTP_PROXY/ALL_PROXY value"
			return r
		}
	}
	addr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		switch proxyURL.Scheme {
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
		addr = net.JoinHostPort(proxyURL.Hostname(), port)
	}
	start := time.Now()
	var conn net.Conn
	// A ctx without a deadline yields the zero time, which *clears* the conn
	// deadlines rather than setting them, so the CONNECT read would then block
	// forever. Fall back to the probe budget.
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(DefaultProbeTimeout)
	}
	if socks {
		return o.socks5Probe(ctx, addr, proxyURL.Scheme == "socks5h", dl, start)
	}
	var resp *http.Response
	auth := false
	for {
		if proxyURL.Scheme == "https" {
			conn, err = o.dialTLS(ctx, "tcp", addr, &tls.Config{ServerName: proxyURL.Hostname()})
		} else {
			conn, err = o.dialContext(ctx, "tcp", addr)
		}
		if err != nil {
			r.Status = StatusFail
			r.Cause = ProxyCauseUnreachable
			r.Detail = "cannot reach proxy " + addr + ": " + err.Error()
			r.Fix = "proxy configured but unreachable: check HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and the proxy host"
			return r
		}
		req := "CONNECT " + ConnectivityProbeHost + ":443 HTTP/1.1\r\nHost: " + ConnectivityProbeHost + ":443\r\n"
		if auth {
			pw, _ := proxyURL.User.Password()
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+pw)) + "\r\n"
		}
		if err := conn.SetWriteDeadline(dl); err != nil {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "cannot set proxy write deadline: " + err.Error()
			return r
		}
		if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "proxy write failed: " + err.Error()
			return r
		}
		// net.Conn reads don't know ctx exists; the read deadline is the only leash.
		if err := conn.SetReadDeadline(dl); err != nil {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "cannot set proxy read deadline: " + err.Error()
			return r
		}
		// Bound the entire response sequence, sharing buffered read-ahead across replies.
		reader := bufio.NewReader(io.LimitReader(conn, 4096))
		for {
			resp, err = http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			// 101 switches protocols rather than preceding another HTTP reply.
			// We did not request Upgrade, and CONNECT success requires a 2xx.
			if err != nil || resp.StatusCode/100 != 1 || resp.StatusCode == http.StatusSwitchingProtocols {
				break
			}
			_ = resp.Body.Close()
		}
		if err != nil {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "no CONNECT response from proxy " + addr + ": " + err.Error()
			r.Fix = "proxy reachable but not speaking HTTP: wrong port or scheme?"
			return r
		}
		// This connection is never reused. Close it on retry or return instead
		// of draining the body; after a successful CONNECT, bytes belong to
		// the tunnel rather than an HTTP response body.
		if resp.StatusCode != http.StatusProxyAuthRequired || proxyURL.User == nil || auth {
			break
		}
		if basic, _ := proxyAuthChallenges(resp.Header); !basic {
			break
		}
		_ = conn.Close()
		if proxyURL.Scheme == "http" {
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "proxy " + addr + " requires authentication; refusing to send credentials unencrypted"
			r.Fix = "use an https:// proxy before supplying credentials"
			return r
		}
		auth = true
	}
	defer conn.Close()
	rtt := since(start)
	if resp.StatusCode/100 != 2 {
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "proxy " + addr + " refused CONNECT: " + resp.Status
		if resp.StatusCode == http.StatusProxyAuthRequired {
			basic, unsupported := proxyAuthChallenges(resp.Header)
			switch {
			case !basic:
				if len(unsupported) > 0 {
					r.Detail += "; unsupported proxy authentication schemes: " + strings.Join(unsupported, ", ")
				} else {
					r.Detail += "; proxy did not offer a supported Basic authentication challenge"
				}
				r.Fix = "this probe only supports Basic proxy authentication; check the proxy's authentication policy and Proxy-Authenticate response for supported Basic challenges"
			case auth:
				r.Fix = "proxy rejected Basic authentication: check the configured credentials and proxy authentication policy"
			default:
				r.Fix = "proxy requires credentials: set user:pass@host in the proxy URL"
			}
		} else {
			r.Fix = "proxy reachable but refusing tunnels: check proxy policy"
		}
		return r
	}
	r = o.proxyTunnelOK(ctx, conn, addr, rtt)
	// An http:// proxy carried the CONNECT, and its destination line, over a bare
	// TCP hop: the destination hostname reached the proxy without TLS. Record the
	// observation on the working row. This is the transport the configuration
	// chose, not a statement that anything read the name; the SOCKS and https://
	// paths do not reach here.
	if proxyURL.Scheme == "http" {
		r.ConnectCleartext = true
		r.Detail += "; the CONNECT destination hostname is sent to the proxy without TLS"
		r.Fix = cleartextConnectAdvice
	}
	return r
}

// proxyAuthChallenges reports Basic support and unsupported scheme names from
// the RFC 9110 challenge list, discarding both on invalid syntax. It never returns
// parameter values or token68 data. A comma can separate parameters or challenges,
// and quoted values can contain commas. A token followed by '=' is a parameter.
func proxyAuthChallenges(header http.Header) (bool, []string) {
	s := strings.Join(header.Values("Proxy-Authenticate"), ",")
	basic := false
	var unsupported []string
	for {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			return basic, unsupported
		}
		scheme, rest := proxyAuthToken(s)
		if scheme == "" {
			return false, nil
		}
		if strings.EqualFold(scheme, "Basic") {
			basic = true
		} else if !slices.ContainsFunc(unsupported, func(known string) bool { return strings.EqualFold(known, scheme) }) {
			unsupported = append(unsupported, scheme)
		}
		s = rest
		if tail := strings.TrimLeft(s, " \t"); tail == "" || tail[0] == ',' {
			s = tail
			continue
		}
		if s[0] != ' ' {
			return false, nil
		}
		s = strings.TrimLeft(s, " ")
		// token68 is opaque challenge data, with optional trailing '=' padding.
		n := 0
		for n < len(s) && (s[n] >= 'a' && s[n] <= 'z' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= '0' && s[n] <= '9' || strings.ContainsRune("-._~+/", rune(s[n]))) {
			n++
		}
		if tail := strings.TrimLeft(strings.TrimLeft(s[n:], "="), " \t"); n > 0 && (tail == "" || tail[0] == ',') {
			// RFC 7617 Basic challenges use parameters, not token68 data.
			if strings.EqualFold(scheme, "Basic") {
				return false, nil
			}
			s = tail
			continue
		}
		for {
			name, tail := proxyAuthToken(s)
			tail = strings.TrimLeft(tail, " \t")
			if name == "" || !strings.HasPrefix(tail, "=") {
				return false, nil
			}
			var ok bool
			s, ok = proxyAuthValue(strings.TrimLeft(tail[1:], " \t"))
			if !ok {
				return false, nil
			}
			s = strings.TrimLeft(s, " \t")
			if s == "" {
				break
			}
			if s[0] != ',' {
				return false, nil
			}
			s = strings.TrimLeft(s, " \t,")
			_, tail = proxyAuthToken(s)
			if !strings.HasPrefix(strings.TrimLeft(tail, " \t"), "=") {
				break
			}
		}
	}
}

func proxyAuthToken(s string) (string, string) {
	n := 0
	for n < len(s) && (s[n] >= 'a' && s[n] <= 'z' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= '0' && s[n] <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(s[n]))) {
		n++
	}
	return s[:n], s[n:]
}

// proxyAuthValue consumes a token or HTTP quoted-string, including quoted-pair.
func proxyAuthValue(s string) (string, bool) {
	if !strings.HasPrefix(s, "\"") {
		token, rest := proxyAuthToken(s)
		return rest, token != ""
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			return s[i+1:], true
		case '\\':
			i++
			if i == len(s) {
				return "", false
			}
		}
		if s[i] < ' ' && s[i] != '\t' || s[i] == 0x7f {
			return "", false
		}
	}
	return "", false
}

// cleartextConnectAdvice hangs off a working http:// proxy row. It does not
// assert that an https:// endpoint exists, because this probe never tested one;
// it names the hop that is exposed and what to check.
const cleartextConnectAdvice = "an http:// proxy sends the CONNECT destination hostname in cleartext on the client-to-proxy hop; if this proxy also offers a TLS listener, an https:// proxy URL encrypts that hop, but verify the TLS endpoint works before relying on it"

// proxyTunnelOK builds the PASS result shared by the CONNECT and SOCKS5 paths.
func (o *netops) proxyTunnelOK(ctx context.Context, conn net.Conn, addr string, rtt time.Duration) ProbeResult {
	var r ProbeResult
	src, iface, ambiguous := o.pathIdentity(ctx, conn, nil, 0)
	r.Status, r.Source, r.Iface, r.ifaceAmbiguous = StatusPass, src, iface, ambiguous
	r.Detail = fmt.Sprintf("proxy %s tunnels to %s:443 in %dms", addr, ConnectivityProbeHost, Ms(rtt))
	applyDialWarnings(&r, rtt)
	return r
}

// socks5Probe dials a SOCKS5 proxy and asks it to tunnel to ConnectivityProbeHost:443.
// socks5 resolves the destination with the client's configured resolver and
// sends an address request; socks5h sends the hostname so the proxy resolves
// it. The distinction is observable on split-DNS networks and is why both
// schemes exist. A socks5 CONNECT the proxy refuses only rules out that one
// answer, so the next locally resolved address gets a fresh session, all under
// the one deadline.
func (o *netops) socks5Probe(ctx context.Context, addr string, remoteDNS bool, dl, start time.Time) ProbeResult {
	conn, r := o.socks5Session(ctx, addr, dl)
	if conn == nil {
		return r
	}
	destinations := []socks5Destination{{host: ConnectivityProbeHost, port: 443, remoteDNS: remoteDNS}}
	resolved := 0
	if !remoteDNS {
		ips, targets, lookupErr := o.lookupIP(ctx, ConnectivityProbeHost)
		if lookupErr != nil || len(ips) == 0 {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseClientDNS
			r.Detail = "SOCKS5 proxy " + addr + " is reachable, but local DNS cannot resolve " + ConnectivityProbeHost + resolverTargetsNote(targets)
			if lookupErr != nil {
				r.Detail += ": " + lookupErr.Error()
			}
			r.Fix = "fix the client's DNS resolver, or use socks5h:// to resolve names through the proxy"
			return r
		}
		resolved = len(ips)
		ips = interleaveFamilies(ips)
		if len(ips) > maxAttempts {
			ips = ips[:maxAttempts]
		}
		destinations = destinations[:0]
		for _, ip := range ips {
			destinations = append(destinations, socks5Destination{host: ConnectivityProbeHost, ip: ip, port: 443})
		}
	}
	tried := 0
	for _, destination := range destinations {
		if tried > 0 {
			if ctx.Err() != nil || !time.Now().Before(dl) {
				break
			}
			if conn, r = o.socks5Session(ctx, addr, dl); conn == nil {
				return r
			}
		}
		tried++
		err := socks5Request(conn, destination)
		if err == nil {
			defer conn.Close()
			return o.proxyTunnelOK(ctx, conn, addr, since(start))
		}
		_ = conn.Close()
		r.Status = StatusFail
		r.Cause = proxyCauseForSOCKSError(err)
		r.Detail = "SOCKS5 proxy " + addr + ": " + err.Error()
		r.Fix = "check that the proxy URL names a SOCKS5 port and that the proxy allows this destination"
		if !socks5RetryOtherDestination(err) {
			return r
		}
	}
	if tried > 1 {
		r.Detail += fmt.Sprintf(" (%d of %d locally resolved addresses tried)", tried, resolved)
	}
	return r
}

// socks5RetryOtherDestination reports whether a failed CONNECT refused only the
// address it carried, so another locally resolved address could still tunnel.
// Anything else (a malformed reply, a general server failure, an unsupported
// command, an unassigned code) describes the proxy itself, and trying another
// address would hide it.
func socks5RetryOtherDestination(err error) bool {
	var reply socks5ReplyError
	if !errors.As(err, &reply) {
		return false
	}
	switch reply.code {
	case 2, // ruleset: proxy policy can allow one address and not another
		3, 4, 5, 6, // network/host unreachable, refused, TTL expired: path to this address
		8: // address type not supported: the other family may be
		return true
	}
	return false
}

// socks5Session dials the proxy and completes the no-auth greeting. On failure
// the conn is nil and the result says which stage broke.
func (o *netops) socks5Session(ctx context.Context, addr string, dl time.Time) (net.Conn, ProbeResult) {
	var r ProbeResult
	conn, err := o.dialContext(ctx, "tcp", addr)
	if err != nil {
		r.Status = StatusFail
		r.Cause = ProxyCauseUnreachable
		r.Detail = "cannot reach proxy " + addr + ": " + err.Error()
		r.Fix = "proxy configured but unreachable: check HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and the proxy host"
		return nil, r
	}
	// net.Conn reads don't know ctx exists; the deadline is the only leash.
	if err := conn.SetDeadline(dl); err != nil {
		_ = conn.Close()
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "cannot set proxy deadline: " + err.Error()
		return nil, r
	}
	if err := socks5Greeting(conn); err != nil {
		_ = conn.Close()
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "SOCKS5 proxy " + addr + ": " + err.Error()
		r.Fix = "check that the proxy URL names a SOCKS5 port and that the proxy allows this destination"
		return nil, r
	}
	return conn, r
}

type socks5Destination struct {
	host      string
	ip        net.IP
	port      int
	remoteDNS bool
}

// socks5Greeting runs the RFC 1928 no-auth negotiation. Every read is a fixed,
// small size because replies are attacker-controlled.
func socks5Greeting(conn net.Conn) error {
	// VER 5, offering exactly one method: 0 (no authentication).
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fmt.Errorf("greeting failed: %w", err)
	}
	hello := make([]byte, 2)
	if _, err := io.ReadFull(conn, hello); err != nil {
		return fmt.Errorf("no SOCKS5 greeting reply: %w", err)
	}
	if hello[0] != 5 {
		return fmt.Errorf("not a SOCKS5 proxy (reply version %d): wrong port or scheme?", hello[0])
	}
	if hello[1] != 0 {
		return errors.New("requires authentication; SOCKS5 credentials travel in cleartext, so this probe does not send them")
	}
	return nil
}

func socks5Request(conn net.Conn, destination socks5Destination) error {
	// CONNECT, reserved, followed by the destination address and port.
	req := []byte{5, 1, 0}
	if destination.remoteDNS {
		if len(destination.host) == 0 || len(destination.host) > 255 {
			return errors.New("destination hostname is too long for SOCKS5")
		}
		// #nosec G115 -- the preceding bound proves the length fits one SOCKS byte.
		req = append(req, 3, byte(len(destination.host)))
		req = append(req, destination.host...)
	} else if ip4 := destination.ip.To4(); ip4 != nil {
		req = append(req, 1)
		req = append(req, ip4...)
	} else if ip6 := destination.ip.To16(); ip6 != nil {
		req = append(req, 4)
		req = append(req, ip6...)
	} else {
		return errors.New("local DNS returned an invalid address")
	}
	// #nosec G115 -- the only caller supplies the fixed HTTPS port 443.
	req = binary.BigEndian.AppendUint16(req, uint16(destination.port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("CONNECT failed: %w", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("no CONNECT reply: %w", err)
	}
	if reply[0] != 5 || reply[2] != 0 {
		return fmt.Errorf("invalid CONNECT reply header (version %d, reserved %d)", reply[0], reply[2])
	}
	if reply[1] != 0 {
		return socks5ReplyError{code: reply[1]}
	}
	// Drain the bound address so the conn sits at the tunnel's first byte.
	var n int
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return fmt.Errorf("truncated CONNECT reply: %w", err)
		}
		n = int(b[0])
	default:
		return fmt.Errorf("bad address type %d in CONNECT reply", reply[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return fmt.Errorf("truncated CONNECT reply: %w", err)
	}
	return nil
}

type socks5ReplyError struct{ code byte }

func (e socks5ReplyError) Error() string { return "refused CONNECT: " + socks5Error(e.code) }

func proxyCauseForSOCKSError(err error) string {
	var reply socks5ReplyError
	if errors.As(err, &reply) {
		switch reply.code {
		case 3, 4, 5, 6:
			// Code 4 is "host unreachable" even for a domain-form request. The proxy
			// may have resolved the name and failed to reach the host, so the code
			// does not prove a proxy-side DNS failure.
			return ProxyCauseDestinationUnreachable
		}
	}
	return ProxyCauseProtocol
}

// socks5Error names an RFC 1928 reply code; unassigned codes fall through to
// the number.
func socks5Error(code byte) string {
	msgs := [...]string{1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable", 4: "host unreachable", 5: "connection refused", 6: "TTL expired", 7: "command not supported", 8: "address type not supported"}
	if int(code) < len(msgs) && msgs[code] != "" {
		return msgs[code]
	}
	return "reply code " + strconv.Itoa(int(code))
}
