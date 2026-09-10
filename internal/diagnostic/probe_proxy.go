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
	"strconv"
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
	// ProxyFromEnvironment answers per request scheme (HTTPS_PROXY vs
	// HTTP_PROXY), so ask for both; https first since that's what almost all
	// tunneled traffic is.
	for _, scheme := range []string{"https", "http"} {
		proxyURL, err = o.proxyFromEnv(&http.Request{URL: &url.URL{Scheme: scheme, Host: ConnectivityProbeHost}})
		if err != nil || proxyURL != nil {
			break
		}
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
		return r
	}
	if proxyURL.Hostname() == "" || proxyURL.Path != "" || proxyURL.RawQuery != "" || proxyURL.ForceQuery || proxyURL.Fragment != "" {
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
		// Bounded read: the response is attacker-controlled.
		resp, err = http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 4096)), &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			r.Status = StatusFail
			r.Cause = ProxyCauseProtocol
			r.Detail = "no CONNECT response from proxy " + addr + ": " + err.Error()
			r.Fix = "proxy reachable but not speaking HTTP: wrong port or scheme?"
			return r
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired || proxyURL.User == nil || auth {
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
			r.Fix = "proxy requires credentials: set user:pass@host in the proxy URL"
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
// schemes exist.
func (o *netops) socks5Probe(ctx context.Context, addr string, remoteDNS bool, dl, start time.Time) ProbeResult {
	var r ProbeResult
	conn, err := o.dialContext(ctx, "tcp", addr)
	if err != nil {
		r.Status = StatusFail
		r.Cause = ProxyCauseUnreachable
		r.Detail = "cannot reach proxy " + addr + ": " + err.Error()
		r.Fix = "proxy configured but unreachable: check HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and the proxy host"
		return r
	}
	defer conn.Close()
	// net.Conn reads don't know ctx exists; the deadline is the only leash.
	if err := conn.SetDeadline(dl); err != nil {
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "cannot set proxy deadline: " + err.Error()
		return r
	}
	if err := socks5Greeting(conn); err != nil {
		r.Status = StatusFail
		r.Cause = ProxyCauseProtocol
		r.Detail = "SOCKS5 proxy " + addr + ": " + err.Error()
		r.Fix = "check that the proxy URL names a SOCKS5 port and that the proxy allows this destination"
		return r
	}
	destination := socks5Destination{host: ConnectivityProbeHost, port: 443, remoteDNS: remoteDNS}
	if !remoteDNS {
		ips, targets, lookupErr := o.lookupIP(ctx, ConnectivityProbeHost)
		if lookupErr != nil || len(ips) == 0 {
			r.Status = StatusFail
			r.Cause = ProxyCauseClientDNS
			r.Detail = "SOCKS5 proxy " + addr + " is reachable, but local DNS cannot resolve " + ConnectivityProbeHost + resolverTargetsNote(targets)
			if lookupErr != nil {
				r.Detail += ": " + lookupErr.Error()
			}
			r.Fix = "fix the client's DNS resolver, or use socks5h:// to resolve names through the proxy"
			return r
		}
		destination.ip = ips[0]
	}
	if err := socks5Request(conn, destination); err != nil {
		r.Status = StatusFail
		r.Cause = proxyCauseForSOCKSError(err, remoteDNS)
		r.Detail = "SOCKS5 proxy " + addr + ": " + err.Error()
		r.Fix = "check that the proxy URL names a SOCKS5 port and that the proxy allows this destination"
		return r
	}
	return o.proxyTunnelOK(ctx, conn, addr, since(start))
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

func proxyCauseForSOCKSError(err error, remoteDNS bool) string {
	var reply socks5ReplyError
	if errors.As(err, &reply) {
		switch reply.code {
		case 3, 5:
			return ProxyCauseDestinationUnreachable
		case 4:
			// RFC 1928 names code 4 "host unreachable"; it can only
			// represent proxy-side name resolution in this probe when the
			// request actually carried a domain name. A locally resolving
			// socks5 request sent an address and must not be labelled DNS.
			if remoteDNS {
				return ProxyCauseProxyDNS
			}
			return ProxyCauseDestinationUnreachable
		}
	}
	return ProxyCauseProtocol
}

// socks5Error names an RFC 1928 reply code. Codes 6-7 can't come back from a
// CONNECT, so they fall through to the number; 8 can, because this probe always
// asks for ATYP 3.
func socks5Error(code byte) string {
	msgs := [...]string{1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable", 4: "host unreachable", 5: "connection refused", 8: "address type not supported"}
	if int(code) < len(msgs) && msgs[code] != "" {
		return msgs[code]
	}
	return "reply code " + strconv.Itoa(int(code))
}
