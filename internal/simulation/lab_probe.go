package simulation

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

type labProbe struct {
	network *labNetwork
	view    Test
	target  *diagnostic.Target
	id      diagnostic.ProbeID
	trace   []LabExchange
}

func labProbeSupported(id diagnostic.ProbeID) bool {
	return slices.Contains([]diagnostic.ProbeID{diagnostic.ProbeIface, diagnostic.ProbeSSID, diagnostic.ProbeInternet, diagnostic.ProbeQUIC, diagnostic.ProbeProxy, diagnostic.ProbeDNS, diagnostic.ProbeDNSPublic, diagnostic.ProbeDNSEncrypted, diagnostic.ProbeTargetTCP, diagnostic.ProbePMTU, diagnostic.ProbeTLS, diagnostic.ProbeHTTP, diagnostic.ProbeHTTPS, diagnostic.ProbeSSH, diagnostic.ProbeSMTP}, id)
}

func labIP(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}
	return net.ParseIP(a.String())
}
func labIPAddr(a net.IP) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	return labAddr(a.String())
}

func (p *labProbe) send(from string, ip netip.Addr, protocol string, port, size int) string {
	segment := ""
	if from == p.view.Node {
		segment = p.view.SourceSegment
	}
	x := p.network.exchange(string(p.id), from, ip.String(), segment, protocol, port, size, len(p.trace))
	p.trace = append(p.trace, x)
	return x.Outcome
}
func (p *labProbe) resultOutcome(outcome string) {
	if len(p.trace) > 0 {
		p.trace[len(p.trace)-1].Outcome = outcome
	}
}

func (p *labProbe) connect(from string, ip netip.Addr, port int) string {
	outcome := p.send(from, ip, "tcp", port, 64)
	if outcome != labDelivered {
		return outcome
	}
	s := p.network.service(ip, port, "tcp")
	if s == nil {
		p.resultOutcome(diagnostic.ConnectionCauseRefused)
		return diagnostic.ConnectionCauseRefused
	}
	return outcome
}

func (p *labProbe) route(ip netip.Addr) diagnostic.RouteDecision {
	r := diagnostic.RouteDecision{Destination: labIP(ip), Family: labFamily(ip), TableKnown: true}
	i, src, via, _, ok := p.network.route(p.network.scenario.Topology.node(p.view.Node), ip, p.view.SourceSegment)
	r.Unreachable = !ok
	if ok {
		r.Iface = i.Segment
		r.Source = labIP(src)
		r.MTU = 1500
		r.Tunnel = diagnostic.TunnelDirect
		if slices.Contains(p.network.tunnels, i.Segment) {
			r.Tunnel = diagnostic.TunnelKnown
		}
		if via != ip {
			r.Gateway = labIP(via)
		}
	}
	return r
}

func (p *labProbe) hasFamily(v4 bool) bool {
	for _, i := range p.network.scenario.Topology.node(p.view.Node).Interfaces {
		if (p.view.SourceSegment == "" || p.view.SourceSegment == i.Segment) && p.network.up(p.view.Node, i.Segment) && labInterfaceAddr(i, v4).IsValid() {
			return true
		}
	}
	return false
}

// Match the live probe's global-address eligibility, excluding IPv6 ULA.
func (p *labProbe) hasGlobalFamily(v4 bool) bool {
	for _, i := range p.network.scenario.Topology.node(p.view.Node).Interfaces {
		if !p.network.up(p.view.Node, i.Segment) || p.view.SourceSegment != "" && i.Segment != p.view.SourceSegment {
			continue
		}
		ip := labInterfaceAddr(i, v4)
		if ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() && (v4 || !ip.IsPrivate()) {
			return true
		}
	}
	return false
}

// resolve asks the chosen modeled resolver over its routed path. No hosts file,
// environment variable, net.Resolver, or external name lookup participates.
func (p *labProbe) resolve(from, resolver, host string) ([]netip.Addr, string) {
	ip := labAddr(resolver)
	if outcome := p.send(from, ip, "udp", 53, 128); outcome != labDelivered {
		if outcome == "no_route" || outcome == "not_forwarding" {
			return nil, diagnostic.DNSCauseTemporaryFailure
		}
		return nil, diagnostic.DNSCauseTimeout
	}
	s := p.network.service(ip, 53, "udp")
	if s == nil || s.Type != ServiceDNS {
		p.resultOutcome(diagnostic.DNSCauseTimeout)
		return nil, diagnostic.DNSCauseTimeout
	}
	answers := p.network.records(s, host)
	if len(answers) == 0 {
		p.resultOutcome("nxdomain")
		return nil, "nxdomain"
	}
	return answers, ""
}

func (p *labProbe) observe(deps map[diagnostic.ProbeID]diagnostic.ProbeResult) diagnostic.ProbeResult {
	r := diagnostic.ProbeResult{Status: diagnostic.StatusPass}
	host := diagnostic.ConnectivityProbeHost
	port := 443
	if p.target != nil {
		host, port = p.target.Host, p.target.Port
	}
	node := p.network.scenario.Topology.node(p.view.Node)
	switch p.id {
	case diagnostic.ProbeIface:
		if !p.hasFamily(true) && !p.hasFamily(false) {
			return diagnostic.ProbeResult{Status: diagnostic.StatusFail, Detail: "no usable modeled interface"}
		}
		v4, v6 := diagnostic.InternetProbeEndpoints()
		for _, ips := range [][]net.IP{v4, v6} {
			for _, ip := range ips {
				if p.hasFamily(ip.To4() != nil) {
					r.Routes = append(r.Routes, p.route(labIPAddr(ip)))
				}
			}
		}
		for _, i := range node.Interfaces {
			if p.network.up(node.Name, i.Segment) && (p.view.SourceSegment == "" || p.view.SourceSegment == i.Segment) {
				r.Iface = i.Segment
				src := labInterfaceAddr(i, true)
				if !src.IsValid() {
					src = labInterfaceAddr(i, false)
				}
				r.Source = labIP(src)
				break
			}
		}
		r.Detail = "modeled interface and route lookup"
	case diagnostic.ProbeSSID:
		r.Status = diagnostic.StatusNA
		r.Detail = "modeled wired interfaces"
	case diagnostic.ProbeDNS, diagnostic.ProbeDNSPublic:
		if p.target != nil && p.target.IP != nil {
			r.Status = diagnostic.StatusNA
			r.Addrs = []net.IP{p.target.IP}
			r.Detail = "IP literal"
			return r
		}
		resolver := node.Resolver
		if p.id == diagnostic.ProbeDNSPublic {
			resolver = diagnostic.DefaultPublicDNS
		}
		answers, cause := p.resolve(node.Name, resolver, host)
		r.ResolverTargets = []string{net.JoinHostPort(resolver, "53")}
		r.Routes = []diagnostic.RouteDecision{p.route(labAddr(resolver))}
		for _, a := range answers {
			r.Addrs = append(r.Addrs, labIP(a))
		}
		if cause != "" {
			r.Status = diagnostic.StatusFail
			r.Cause = cause
			if cause == "nxdomain" {
				r.Cause = ""
				r.DNSNotFound = true
			}
			if p.id == diagnostic.ProbeDNSPublic {
				r.Status = diagnostic.StatusNA
			}
		}
		r.Detail = fmt.Sprintf("resolver %s answers %v (%s)", resolver, answers, cause)
	case diagnostic.ProbeInternet:
		v4, v6 := diagnostic.InternetProbeEndpoints()
		r = p.tcpFamilies([][]net.IP{v4, v6}, 443, true)
		intercepted := 0
		for _, name := range []string{diagnostic.ConnectivityProbeHost, "www.msftconnecttest.com"} {
			answers, _ := p.resolve(node.Name, node.Resolver, name)
			for _, a := range answers {
				if p.connect(node.Name, a, 80) != labDelivered {
					continue
				}
				service := p.network.service(a, 80, "tcp")
				if service.Type == ServiceHTTP && !slices.Contains(p.network.silentHTTP, service.Name) {
					if service.Portal {
						intercepted++
						p.resultOutcome("http_redirect")
					}
					break
				}
			}
		}
		if intercepted == 2 {
			r.Status = diagnostic.StatusFail
			r.Portal = &diagnostic.Portal{RedirectURL: portalSignInURL}
		} else if intercepted == 1 && r.Status == diagnostic.StatusPass {
			r.Status = diagnostic.StatusWarn
		}
		// The live egress probe distinguishes an unconfigured family from a
		// globally addressed family whose reference connections all fail.
		if r.Status != diagnostic.StatusFail {
			for _, family := range []struct {
				v4                 bool
				state, cause, name string
			}{
				{true, r.Families.IPv4, diagnostic.FamilyCauseIPv4Unreachable, "ipv4"},
				{false, r.Families.IPv6, diagnostic.FamilyCauseIPv6Unreachable, "ipv6"},
			} {
				if family.state == diagnostic.FamilyUnreachable && p.hasGlobalFamily(family.v4) {
					r.Status = diagnostic.StatusWarn
					r.SetFailureCause(family.cause, family.name)
				}
			}
		}
	case diagnostic.ProbeTargetTCP:
		var v4, v6 []net.IP
		for _, a := range deps[diagnostic.ProbeDNS].Addrs {
			if a.To4() != nil {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
		}
		r = p.tcpFamilies([][]net.IP{v4, v6}, port, false)
	case diagnostic.ProbeTLS:
		ip := labIPAddr(deps[diagnostic.ProbeTargetTCP].SelectedIP)
		r.SelectedIP = labIP(ip)
		if outcome := p.connect(node.Name, ip, port); outcome != labDelivered {
			r.Status = diagnostic.StatusFail
			r.Cause = diagnostic.TLSCauseTCPUnreachable
			if outcome == "timeout" {
				r.Cause = diagnostic.TLSCauseTimeout
			}
			return r
		}
		// SYN is 64 bytes; the modeled TLS exchange sends a full-sized flight.
		if p.send(node.Name, ip, "tcp", port, 1500) != labDelivered {
			r.Status = diagnostic.StatusFail
			r.Cause = diagnostic.TLSCauseTimeout
			// The connection opened, so this is a handshake stall, unlike the
			// connect timeout above.
			r.SetProtocolTimeout(true)
			return r
		}
		s := p.network.service(ip, port, "tcp")
		r.Cause = labTLSCause(s, host)
		if r.Cause != "" {
			r.Status = diagnostic.StatusFail
			p.resultOutcome(r.Cause)
		}
		r.Detail = "modeled TLS identity: " + r.Cause
	case diagnostic.ProbePMTU:
		ip := labIPAddr(deps[diagnostic.ProbeTargetTCP].SelectedIP)
		if p.connect(node.Name, ip, port) != labDelivered {
			r.Status = diagnostic.StatusNA
			return r
		}
		r.SelectedIP = labIP(ip)
		if p.send(node.Name, ip, "tcp", port, 1500) != labDelivered {
			r.Status = diagnostic.StatusWarn
			r.Detail = "small handshake completed; full-sized payload remains unacknowledged"
		} else {
			r.Detail = "full-sized payload acknowledged"
		}
	case diagnostic.ProbeHTTP, diagnostic.ProbeHTTPS:
		var ips []net.IP
		requestPort := port
		if p.id == diagnostic.ProbeHTTPS {
			ips = []net.IP{deps[diagnostic.ProbeTLS].SelectedIP}
		} else if p.target.Proto == diagnostic.ProtoTLSHTTP {
			ips = deps[diagnostic.ProbeDNS].Addrs
			requestPort = 80
		} else {
			ips = []net.IP{deps[diagnostic.ProbeTargetTCP].SelectedIP}
		}
		r.Status = diagnostic.StatusFail
		timedOut := false
		for _, a := range ips {
			ip := labIPAddr(a)
			if outcome := p.connect(node.Name, ip, requestPort); outcome != labDelivered {
				timedOut = timedOut || outcome == "timeout"
				continue
			}
			if outcome := p.send(node.Name, ip, "tcp", requestPort, 256); outcome != labDelivered {
				timedOut = timedOut || outcome == "timeout"
				continue
			}
			s := p.network.service(ip, requestPort, "tcp")
			if slices.Contains(p.network.silentHTTP, s.Name) {
				timedOut = true
				p.resultOutcome("http_no_response")
				continue
			}
			if s.Type == ServiceHTTP || p.id == diagnostic.ProbeHTTPS && s.Type == ServiceTLS {
				r.Status = diagnostic.StatusPass
				r.SelectedIP = a
				status := s.Status
				if s.Type == ServiceTLS {
					status = 204
				}
				r.Detail = fmt.Sprintf("HTTP response %d", status)
				break
			}
		}
		r.SetProtocolTimeout(r.Status == diagnostic.StatusFail && timedOut)
	case diagnostic.ProbeProxy:
		if p.view.Proxy == nil {
			r.Status = diagnostic.StatusNA
			r.Detail = "no proxy configured"
			return r
		}
		proxy := p.view.Proxy
		proxyNode := p.network.scenario.Topology.node(proxy.Node)
		ip := labAddr(proxyNode.Address)
		if p.connect(node.Name, ip, proxy.Port) != labDelivered {
			r.Status = diagnostic.StatusFail
			r.Cause = diagnostic.ProxyCauseUnreachable
			return r
		}
		from := proxy.Node
		resolver := proxyNode.Resolver
		if proxy.Scheme == "socks5" {
			from = node.Name
			resolver = node.Resolver
		}
		answers, cause := p.resolve(from, resolver, diagnostic.ConnectivityProbeHost)
		if cause != "" {
			r.Status = diagnostic.StatusFail
			r.Cause = diagnostic.ProxyCauseProxyDNS
			if from == node.Name {
				r.Cause = diagnostic.ProxyCauseClientDNS
			}
			return r
		}
		r.Status = diagnostic.StatusFail
		r.Cause = diagnostic.ProxyCauseDestinationUnreachable
		for _, a := range answers {
			if p.connect(proxy.Node, a, 443) == labDelivered {
				r.Status = diagnostic.StatusPass
				r.Cause = ""
				break
			}
		}
		r.Detail = "modeled proxy tunnel"
	case diagnostic.ProbeQUIC:
		answers, _ := p.resolve(node.Name, node.Resolver, diagnostic.ConnectivityProbeHost)
		r.Status = diagnostic.StatusFail
		r.Cause = diagnostic.QUICCauseTimeout
		for _, a := range answers {
			if p.send(node.Name, a, "udp", 443, 1200) == labDelivered {
				if s := p.network.service(a, 443, "quic"); s != nil && s.Type == ServiceQUIC {
					r.Status = diagnostic.StatusPass
					r.Cause = ""
					r.SelectedIP = labIP(a)
					break
				}
			}
		}
	case diagnostic.ProbeDNSEncrypted:
		r.Status = diagnostic.StatusFail
		for _, endpoint := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
			ip := labAddr(endpoint)
			if !p.hasFamily(ip.Is4()) {
				continue
			}
			for _, endpointPort := range []int{443, 853} {
				if p.connect(node.Name, ip, endpointPort) == labDelivered {
					if s := p.network.service(ip, endpointPort, "tcp"); s != nil && s.Type == ServiceEncryptedDNS {
						// A listening encrypted resolver is not itself a DNS answer.
						// Its trusted synthetic transport carries a small query/response.
						if p.send(node.Name, ip, "tcp", endpointPort, 256) != labDelivered {
							continue
						}
						r.SelectedIP = labIP(ip)
						r.Status = diagnostic.StatusPass
						if len(p.network.records(s, diagnostic.ConnectivityProbeHost)) == 0 {
							r.Status = diagnostic.StatusWarn
							p.resultOutcome("nxdomain")
						}
						return r
					}
				}
			}
		}
	case diagnostic.ProbeSSH, diagnostic.ProbeSMTP:
		ip := labIPAddr(deps[diagnostic.ProbeTargetTCP].SelectedIP)
		if !ip.IsValid() || p.connect(node.Name, ip, port) != labDelivered {
			r.Status = diagnostic.StatusFail
			return r
		}
		s := p.network.service(ip, port, "tcp")
		r.Status = diagnostic.StatusWarn
		prefix := "SSH-"
		if p.id == diagnostic.ProbeSMTP {
			prefix = "220"
		}
		if strings.HasPrefix(s.Banner, prefix) {
			r.Status = diagnostic.StatusPass
		}
	}
	return r
}

func labTLSCause(s *Service, host string) string {
	if s == nil || s.Type != ServiceTLS || s.Certificate == nil {
		return diagnostic.TLSCauseHandshake
	}
	switch s.Certificate.Mode {
	case TLSCertificateExpired:
		return diagnostic.TLSCauseCertificateExpired
	case TLSCertificateNotYetValid:
		return diagnostic.TLSCauseCertificateNotYet
	case TLSCertificateHostnameMismatch:
		return diagnostic.TLSCauseHostnameMismatch
	}
	if !slices.Contains(s.Certificate.DNSNames, host) {
		return diagnostic.TLSCauseHostnameMismatch
	}
	return ""
}

func (p *labProbe) tcpFamilies(families [][]net.IP, port int, reference bool) diagnostic.ProbeResult {
	r := diagnostic.ProbeResult{Status: diagnostic.StatusFail, Families: &diagnostic.FamilyConnectivity{}}
	refused := true
	for index, ips := range families {
		state := ""
		var winner net.IP
		if reference && !p.hasFamily(index == 0) {
			continue
		}
		for _, ip := range ips {
			state = diagnostic.FamilyUnreachable
			outcome := p.connect(p.view.Node, labIPAddr(ip), port)
			attempt := diagnostic.Attempt{IP: ip, Dur: time.Millisecond}
			r.Routes = append(r.Routes, p.route(labIPAddr(ip)))
			if outcome != labDelivered {
				attempt.Cause = diagnostic.ConnectionCauseUnreachable
				if outcome == "timeout" || outcome == diagnostic.ConnectionCauseRefused {
					attempt.Cause = outcome
				}
				attempt.Err = errors.New(attempt.Cause)
				if attempt.Cause != diagnostic.ConnectionCauseRefused {
					refused = false
				}
			} else {
				winner = ip
				state = diagnostic.FamilyReachable
			}
			r.Attempts = append(r.Attempts, attempt)
			if winner != nil {
				break
			}
		}
		if index == 0 {
			r.Families.IPv4 = state
		} else {
			r.Families.IPv6 = state
		}
		// Deterministic equal-latency tie, matching targetTCPProbe's IPv6 preference.
		if winner != nil && (r.SelectedIP == nil || !reference) {
			r.SelectedIP = winner
			r.Status = diagnostic.StatusPass
		}
	}
	if r.SelectedIP != nil {
		route := p.route(labIPAddr(r.SelectedIP))
		r.Source, r.Iface = route.Source, route.Iface
	} else if len(r.Routes) > 0 {
		r.Source, r.Iface = r.Routes[0].Source, r.Routes[0].Iface
	}
	if r.Status == diagnostic.StatusFail && refused && len(r.Attempts) > 0 && !reference {
		r.Cause = diagnostic.ConnectionCauseRefused
	}
	if r.Status == diagnostic.StatusPass {
		for _, a := range r.Attempts {
			if a.Err != nil && (a.IP.To4() != nil && r.Families.IPv4 == diagnostic.FamilyReachable || a.IP.To4() == nil && r.Families.IPv6 == diagnostic.FamilyReachable) {
				r.Status = diagnostic.StatusWarn
			}
		}
	}
	r.Detail = fmt.Sprintf("modeled TCP attempts=%d selected=%s", len(r.Attempts), r.SelectedIP)
	return r
}
