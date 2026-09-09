package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// Per-GOOS fix hints for failures whose remedy is OS-specific. goos is a
// parameter so all branches are testable from one OS.

func ifaceFix(goos string) string {
	switch goos {
	case "darwin":
		return "bring up an interface: turn on Wi-Fi or plug in a cable (`networksetup -listallhardwareports`)"
	case "windows":
		return "bring up an interface: enable Wi-Fi/Ethernet in Settings → Network & internet"
	default:
		return "bring up an interface (cable/Wi-Fi) or `ip link set <iface> up`"
	}
}

func dnsFix(goos string) string {
	switch goos {
	case "darwin":
		return "name resolution failing: check DNS in System Settings → Network (`networksetup -getdnsservers Wi-Fi`)"
	case "windows":
		return "name resolution failing: check DNS in `ipconfig /all` or Settings → Network & internet"
	default:
		return "name resolution failing: check /etc/resolv.conf / DNS"
	}
}

// clockHedgeSuffix is the maybe that a measured offset can settle. It hangs off
// the end of the certificate-date hint so reconcileClockSkew can drop it when
// the reading points the way that rules the clock out, without having to
// rebuild a string only tlsFix holds the certificate to build.
const clockHedgeSuffix = ", or check this machine's clock"

// tlsFix names what actually broke the handshake. Go's verification errors
// carry the offending certificate, so an expiry or a name mismatch can be
// answered with dates and names instead of a list of maybes. Unrecognized
// failures fall back to the list.
func tlsFix(err error) string {
	var (
		hostErr x509.HostnameError
		invalid x509.CertificateInvalidError
		unknown x509.UnknownAuthorityError
		record  tls.RecordHeaderError
	)
	switch {
	case errors.As(err, &hostErr):
		return "cert is for " + certNames(hostErr.Certificate) + ", not " + hostErr.Host + ": wrong SNI/vhost, or the address belongs to someone else"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return certWindow(invalid.Cert) + ": renew the cert" + clockHedgeSuffix
	case errors.As(err, &unknown):
		return "cert signed by an unknown CA: MITM proxy, self-signed cert, or a missing root store"
	case errors.As(err, &record):
		return "the port answered but not with TLS: plaintext service or wrong port?"
	case timeoutError(err):
		return "TLS timed out after TCP connected; read the Path MTU row: it says whether full-size packets are reaching the far end (VPN, PPPoE, or tunnel)"
	}
	return "TLS broken: clock skew, bad/expired cert, or MITM proxy?"
}

// pmtuFix suggests the usual confirmation/remedy for a bulk stall that is
// consistent with a PMTU black hole. The probe cannot determine an exact path
// MTU from an ordinary TCP socket, so the hint must not claim that it did.
func pmtuFix(goos string) string {
	const why = "bulk TCP stalled after the handshake; if lowering MTU makes it drain, "
	switch goos {
	case "darwin":
		return why + "lower the tunnel/interface MTU (`sudo ifconfig <iface> mtu 1400`)"
	case "windows":
		return why + "lower the interface MTU (`netsh interface ipv4 set subinterface \"<iface>\" mtu=1400 store=persistent`)"
	default:
		return why + "lower the interface MTU (`sudo ip link set <iface> mtu 1400`), or clamp MSS on the router (`iptables -t mangle -A FORWARD -p tcp --syn -j TCPMSS --clamp-mss-to-pmtu`)"
	}
}

func timeoutError(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout()
}

// certNames renders who a cert actually claims to be. Long SAN lists get
// truncated; the point is to recognize the wrong server, not to audit it.
func certNames(c *x509.Certificate) string {
	if c == nil {
		return "another name"
	}
	names := c.DNSNames
	if len(names) == 0 && c.Subject.CommonName != "" {
		names = []string{c.Subject.CommonName}
	}
	if len(names) == 0 {
		return "another name"
	}
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}

func certWindow(c *x509.Certificate) string {
	if c == nil {
		return "cert is outside its validity window"
	}
	return "cert is only valid " + c.NotBefore.Format("2006-01-02") + " → " + c.NotAfter.Format("2006-01-02")
}

// egressFix is what a dead direct path gets when the routing table has nothing
// specific to say, and what downgradeEgress restores once another path proves
// the network usable. It names the endpoints rather than the internet on
// purpose: this row dials a fixed pair of reference addresses, and their
// silence is a fact about them until something else in the run widens it.
const egressFix = "no egress to the reference endpoints: proxy-only/filtered network? check upstream"

// routeFix turns a route cause the local kernel supplied into advice about the
// observed state, without treating route selection as proof of a break. The
// prose lives here so all three platforms share one vocabulary. An empty or
// unrecognized cause keeps the generic hint rather than guessing.
func routeFix(cause string) string {
	switch cause {
	case RouteCauseNoDefaultRoute:
		return "no default route: nothing in the routing table leads off this network, check DHCP, the VPN, or a static route"
	case RouteCauseGatewayUnreachable:
		return "the default gateway is not answering at the link layer: check the cable/Wi-Fi link, the gateway itself, or a wrong static IP/subnet"
	case RouteCauseSelectedPathFailed:
		return "a default route exists, but the failed reference connections do not locate the break: check the gateway and upstream connectivity"
	case RouteCausePreferredPathFailed:
		return "multiple default routes exist with a metric preference; the failed reference connections do not prove which route is broken: test each path before changing preference"
	case RouteCausePreferredPathAlternateReachable:
		return "compare the preferred path's gateway and upstream with the working alternate; target reachability alone does not guarantee that changing the default will restore reference connectivity"
	}
	return egressFix
}
