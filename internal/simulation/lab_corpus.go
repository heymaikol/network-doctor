package simulation

import (
	"fmt"
	"slices"

	"github.com/heymaikol/network-doctor/internal/compare"
	d "github.com/heymaikol/network-doctor/internal/diagnostic"
)

const labHost = "app.test"
const labTarget4 = "93.184.216.34"
const labTarget6 = "2606:2800:220:1:248:1893:25c8:1946"

// LabScenarios builds fresh values on each call. The healthy topology is shared
// construction, never shared mutable state. Faults do not contain probe IDs,
// statuses, findings, or diagnosis text.
func LabScenarios() []LabScenario {
	healthy := func(name, description string, dual bool) LabScenario {
		return LabScenario{Name: name, Description: description, Network: labBase(dual), Views: []LabView{{Node: "client", SourceSegment: "ethernet", Target: "https://" + labHost, Expected: LabExpected{Verdict: d.VerdictOK, Checks: []ExpectedCheck{{ID: "target_tcp", Status: "PASS"}, {ID: "tls", Status: "PASS"}, {ID: "https", Status: "PASS"}}}}}}
	}
	expect := func(s *LabScenario, verdict string, id d.DiagnosisID, checks ...ExpectedCheck) {
		s.Views[0].Expected = LabExpected{Verdict: verdict, Required: []d.DiagnosisID{id}, Forbidden: []d.DiagnosisID{d.DiagnosisOffline}, Checks: checks}
	}
	drop := func(id, layer, node, to, protocol string, port int) LabFault {
		return LabFault{ID: id, Layer: layer, Scope: node, Network: &Fault{Type: FaultDrop, Node: node, To: to, Protocol: protocol, Port: port, Direction: DirectionInbound}}
	}
	service := func(s LabScenario, name string) Service {
		for _, n := range cloneScenario(&s.Network).Topology.Nodes {
			for _, svc := range n.Services {
				if svc.Name == name {
					return svc
				}
			}
		}
		panic("unknown lab service " + name)
	}
	replace := func(id, layer string, svc Service) LabFault {
		return LabFault{ID: id, Layer: layer, Scope: svc.Name, Service: &svc}
	}
	var out []LabScenario
	out = append(out, healthy("healthy-ipv4", "Working IPv4 network with independent DNS and reference controls.", false), healthy("healthy-dual-stack", "Both routed address families work.", true))
	out[1].Views[0].Expected.Checks[0].IPv4 = d.FamilyReachable
	out[1].Views[0].Expected.Checks[0].IPv6 = d.FamilyReachable
	out[1].Views[0].Expected.Checks = append(out[1].Views[0].Expected.Checks, ExpectedCheck{ID: "internet_tcp", Status: "PASS", IPv4: d.FamilyReachable, IPv6: d.FamilyReachable})
	s := healthy("dns-resolver-unreachable", "The configured resolver silently drops queries; independent DNS still answers.", false)
	s.Faults = []LabFault{drop("resolver-drop", "dns", "resolver", "", "udp", 53)}
	expect(&s, d.VerdictDNS, d.DiagnosisSystemDNSFailure, ExpectedCheck{ID: "dns", Status: "FAIL", Cause: d.DNSCauseTimeout}, ExpectedCheck{ID: "dns_public", Status: "PASS"}, ExpectedCheck{ID: "target_tcp", Status: "SKIP"})
	s.Views[0].Expected.Evidence = []LabEvidenceRequirement{{Finding: d.DiagnosisSystemDNSFailure, Check: d.ProbeDNSPublic, Observation: d.ObservationDNSAnswers}}
	s.BlindSpots = []string{"Resolver failure and a dropped path to that resolver are indistinguishable; a client timeout does not locate the drop."}
	out = append(out, s)
	s = healthy("dns-hijack", "System DNS is rewritten to a different, working endpoint; independent answers disagree.", false)
	svc := service(s, "system-dns")
	svc.Records = labRecords(false, "203.0.113.99")
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, labServer("decoy", "10.20.2.99", "203.0.113.99"))
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "gateway", Destination: "203.0.113.99/32", Via: "10.20.2.99"}, Route{Node: "decoy", Destination: "0.0.0.0/0", Via: "10.20.2.1"})
	s.Faults = []LabFault{replace("rewrite-answer", "dns", svc)}
	expect(&s, d.VerdictDegraded, d.DiagnosisDNSDisagreement, ExpectedCheck{ID: "dns_public", Status: "WARN"}, ExpectedCheck{ID: "target_tcp", Status: "PASS"})
	s.Views[0].Expected.Confidence = []LabConfidence{{Finding: d.DiagnosisDNSDisagreement, Min: d.ConfidenceLow, Max: d.ConfidenceMedium}}
	s.BlindSpots = []string{"Disagreement does not distinguish hijacking from intentional split DNS. Resolver authenticity and intended answer policy are missing."}
	out = append(out, s)
	s = healthy("ipv6-unavailable", "IPv6 reference and target traffic time out while IPv4 works.", true)
	s.Faults = []LabFault{drop("drop-ipv6", "transport", "gateway", "", "", 0)}
	s.Faults[0].Network.Family = "ipv6"
	expect(&s, d.VerdictDegraded, d.DiagnosisDirectEgressDegraded,
		ExpectedCheck{ID: "internet_tcp", Status: "WARN", Cause: d.FamilyCauseIPv6Unreachable, IPv4: d.FamilyReachable, IPv6: d.FamilyUnreachable},
		ExpectedCheck{ID: "target_tcp", Status: "PASS", IPv4: d.FamilyReachable}, ExpectedCheck{ID: "tls", Status: "PASS"}, ExpectedCheck{ID: "https", Status: "PASS"})
	s.BlindSpots = []string{"A configured global IPv6 address without IPv6 egress is observable degradation. Target-specific family claims remain suppressed when the reference family also fails; the exact failing hop is unknown."}
	out = append(out, s)
	s = healthy("reference-egress-unreachable", "Only reference TCP/443 destinations are filtered; the public target works.", false)
	s.Faults = []LabFault{drop("reference-drop", "transport", "internet", "", "tcp", 443)}
	expect(&s, d.VerdictDegraded, d.DiagnosisReferenceEgressUnreachable, ExpectedCheck{ID: "internet_tcp", Status: "WARN"}, ExpectedCheck{ID: "target_tcp", Status: "PASS"})
	out = append(out, s)
	s = healthy("tcp-port-blocked", "Target TCP/443 is silently filtered while independent egress works.", false)
	s.Faults = []LabFault{drop("target-port-drop", "transport", "target", "", "tcp", 443)}
	expect(&s, d.VerdictService, d.DiagnosisTargetUnreachable, ExpectedCheck{ID: "target_tcp", Status: "FAIL"}, ExpectedCheck{ID: "tls", Status: "SKIP"})
	s.Views[0].Expected.Confidence = []LabConfidence{{Finding: d.DiagnosisTargetUnreachable, Min: d.ConfidenceInsufficientEvidence, Max: d.ConfidenceLow}}
	s.BlindSpots = []string{"Silent filtering, silent server failure and a broken return path cannot be localized by a failed TCP connection."}
	out = append(out, s)
	s = healthy("proxy-required", "A proxy can reach the reference endpoint while client direct paths are filtered.", false)
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, Node{Name: "proxy", Resolver: "10.20.2.20", Interfaces: []Interface{{Segment: "ethernet", IPv4: "10.20.1.40/24"}}, Services: []Service{{Name: "proxy-connect", Type: ServiceHTTPConnect, Port: 3128}}})
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "proxy", Destination: "0.0.0.0/0", Via: "10.20.1.1"})
	// The client loses its upstream path, not the gateway's forwarding service.
	s.Faults = []LabFault{{ID: "client-direct-policy", Layer: "transport", Scope: "client", Network: &Fault{Type: FaultDrop, Node: "client", Protocol: "tcp", Port: 443, Direction: DirectionOutbound}}}
	s.Views[0].Proxy = &TestProxy{Node: "proxy", Scheme: "http", Port: 3128}
	expect(&s, d.VerdictNetwork, d.DiagnosisProxyOnlyNetwork, ExpectedCheck{ID: "proxy_connect", Status: "PASS"}, ExpectedCheck{ID: "internet_tcp", Status: "WARN"})
	s.BlindSpots = []string{"Proxy success establishes a working alternative, not that an administrator intended it to be mandatory."}
	out = append(out, s)
	s = healthy("captive-portal", "Both independent HTTP connectivity controls redirect to a sign-in page.", false)
	svc = service(s, "reference-http")
	svc.Portal = true
	s.Faults = []LabFault{replace("portal-interception", "http", svc)}
	expect(&s, d.VerdictNetwork, d.DiagnosisCaptivePortal, ExpectedCheck{ID: "internet_tcp", Status: "FAIL"})
	s.BlindSpots = []string{"Corroborated HTTP interception cannot distinguish a captive portal from a transparent filter synthesizing the same responses."}
	out = append(out, s)
	s = healthy("tls-certificate-mismatch", "The server presents a certificate for a different name.", false)
	svc = service(s, "target-tls")
	svc.Certificate = &TLSCertificate{Mode: TLSCertificateHostnameMismatch, DNSNames: []string{"wrong.test"}}
	f := replace("wrong-certificate", "tls", svc)
	f.Localizable = true
	s.Faults = []LabFault{f}
	expect(&s, d.VerdictService, d.DiagnosisTLSHostnameMismatch, ExpectedCheck{ID: "target_tcp", Status: "PASS"}, ExpectedCheck{ID: "tls", Status: "FAIL", Cause: d.TLSCauseHostnameMismatch})
	s.BlindSpots = []string{"A hostname mismatch proves identity validation failed, not whether a server misconfiguration or interceptor supplied the certificate."}
	out = append(out, s)
	s = healthy("mtu-blackhole", "The gateway loses full-sized packets and suppresses PMTU feedback; SYN packets pass.", false)
	s.Faults = []LabFault{{ID: "narrow-silent-hop", Layer: "transport", Scope: "gateway/uplink", Network: &Fault{Type: FaultPMTUBlackhole, Node: "gateway", Segment: "uplink", MTU: 1280}}}
	expect(&s, d.VerdictNetwork, d.DiagnosisProbablePathMTU, ExpectedCheck{ID: "target_tcp", Status: "PASS"}, ExpectedCheck{ID: "path_mtu", Status: "WARN"}, ExpectedCheck{ID: "tls", Status: "FAIL", Cause: d.TLSCauseTimeout})
	s.Views[0].Expected.Confidence = []LabConfidence{{Finding: d.DiagnosisProbablePathMTU, Min: d.ConfidenceLow, Max: d.ConfidenceMedium}}
	s.BlindSpots = []string{"Bulk ACK loss and protocol timeout suggest PMTU trouble but do not prove an exact MTU or the failing hop; a stalled peer can mimic them."}
	out = append(out, s)
	s = healthy("vpn-split-tunnel", "The target takes a separate tunneled route; public references retain the default route.", false)
	labAddVPN(&s)
	out = append(out, s)
	s = healthy("vpn-dns-leak", "Application traffic is tunneled but the configured DNS resolver stays on ethernet.", false)
	labAddVPN(&s)
	s.Faults = []LabFault{{ID: "dns-outside-tunnel", Layer: "dns", Scope: "client/resolver", ResolverNode: "client", Resolver: "10.20.1.53"}}
	s.Network.Topology.Nodes[0].Resolver = "10.20.3.53"
	s.BlindSpots = []string{"Different DNS and application interfaces are observable. A leak requires intended DNS routing/privacy policy, which Network Doctor does not collect; healthy split DNS can look identical."}
	out = append(out, s)
	s = healthy("asymmetric-routing", "The remote target's return traffic takes a separate, broken path; the remote observer still reaches it.", false)
	labAddVPN(&s)
	// Target receives client traffic through the tunnel, but its reply to the
	// tunnel source goes to an on-link address with no router there.
	s.Faults = []LabFault{{ID: "wrong-return-gateway", Layer: "routing", Scope: "target/return-path", Route: &Route{Node: "target", Destination: "10.20.3.0/24", Via: "10.20.2.254"}}}
	expect(&s, d.VerdictService, d.DiagnosisTargetUnreachable, ExpectedCheck{ID: "target_tcp", Status: "FAIL"})
	s.Views = append(s.Views, LabView{Node: "remote", Target: "https://" + labHost, Expected: LabExpected{Verdict: d.VerdictOK}})
	s.TwoSided = compare.SideA
	s.BlindSpots = []string{"The simulator sees the broken return path. Client route evidence only describes outbound decisions; two-sided comparison places the failing vantage, not an asymmetric hop."}
	out = append(out, s)
	s = healthy("remote-side-broken", "The local client works; only the remote observer locally rejects target TCP/443.", false)
	s.Faults = []LabFault{{ID: "remote-target-drop", Layer: "transport", Scope: "remote", Network: &Fault{Type: FaultDrop, Node: "remote", To: labTarget4, Port: 443, Protocol: "tcp", Direction: DirectionOutbound}}}
	s.Views = append(s.Views, LabView{Node: "remote", Target: "https://" + labHost, Expected: LabExpected{Verdict: d.VerdictService, Required: []d.DiagnosisID{d.DiagnosisTCPConnectionRefused}, Forbidden: []d.DiagnosisID{d.DiagnosisOffline}}})
	s.TwoSided = compare.SideB
	out = append(out, s)
	s = healthy("unrelated-dns-answers", "Two observers resolve the same name to disjoint but working server addresses.", false)
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, labServer("decoy", "10.20.2.99", "203.0.113.99"))
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "gateway", Destination: "203.0.113.99/32", Via: "10.20.2.99"}, Route{Node: "decoy", Destination: "0.0.0.0/0", Via: "10.20.2.1"}, Route{Node: "remote", Destination: "203.0.113.99/32", Via: "10.20.2.99"})
	svc = service(s, "system-dns")
	svc.Records = labRecords(false, "203.0.113.99")
	s.Faults = []LabFault{replace("split-dns-answer", "dns", svc)}
	expect(&s, d.VerdictDegraded, d.DiagnosisDNSDisagreement)
	s.Views = append(s.Views, LabView{Node: "remote", Target: "https://" + labHost, Expected: LabExpected{Verdict: d.VerdictOK}})
	s.TwoSided = compare.SideNone
	s.BlindSpots = []string{"Two-sided matching uses the named target, not common resolved addresses. It can compare different servers; a shared-address control would be needed for endpoint-level localization."}
	out = append(out, s)
	// Counterexample: the name is shared but the servers are not. A dead
	// decoy alone explains side A's failure, so endpoint exclusion is unsupported.
	s.Network = *cloneScenario(&s.Network)
	s.Views = append([]LabView(nil), s.Views...)
	s.Name = "unrelated-dns-failure"
	s.Description = "Split DNS sends the local observer to a server with no TLS listener; the remote observer reaches a different healthy server."
	for i := range s.Network.Topology.Nodes {
		if s.Network.Topology.Nodes[i].Name == "decoy" {
			svc := s.Network.Topology.Nodes[i].Services[0]
			svc.Port = 8443
			s.Faults = append(append([]LabFault(nil), s.Faults...), replace("decoy-listener-moved", "transport", svc))
		}
	}
	s.Views[0].Expected = LabExpected{Verdict: d.VerdictService, Required: []d.DiagnosisID{d.DiagnosisTCPConnectionRefused, d.DiagnosisDNSDisagreement}}
	// Side is the observed failing vantage, not endpoint or path causation.
	// Disjoint endpoints do not erase the measured failure on A alone.
	s.TwoSided = compare.SideA
	s.BlindSpots = []string{"Disjoint resolved addresses mean these target rows did not measure one endpoint. Side A identifies the failing observation; endpoint-specific failure remains possible."}
	out = append(out, s)
	s = healthy("dns-nxdomain", "Only the target name is absent from both resolvers; connectivity control names still exist.", false)
	for _, name := range []string{"system-dns", "public-dns"} {
		svc = service(s, name)
		svc.Records = slices.DeleteFunc(svc.Records, func(r DNSRecord) bool { return r.Name == labHost })
		s.Faults = append(s.Faults, replace("missing-name-"+name, "dns", svc))
	}
	expect(&s, d.VerdictDNS, d.DiagnosisDNSNameNotFound, ExpectedCheck{ID: "dns", Status: "FAIL"}, ExpectedCheck{ID: "target_tcp", Status: "SKIP"})
	out = append(out, s)
	s = healthy("connection-refused", "No service listens on target TCP/8443; the host and other ports work.", false)
	s.Views[0].Target = "https://" + labHost + ":8443"
	// An absent listener is base service state, declared independently of expected results.
	expect(&s, d.VerdictService, d.DiagnosisTCPConnectionRefused, ExpectedCheck{ID: "target_tcp", Status: "FAIL", Cause: d.ConnectionCauseRefused})
	out = append(out, s)
	// Two runs whose only reachable endpoint is one no traffic leaves the site
	// to arrive at, with the gateway's uplink administratively down so nothing
	// public can answer. Reaching either endpoint says nothing about egress,
	// so the egress row has to stay a failure and the reference-endpoint
	// reading has to stay off the table.
	deadUplink := LabFault{ID: "uplink-down", Layer: "link", Scope: "gateway/uplink", Network: &Fault{Type: FaultLinkDown, Node: "gateway", Segment: "uplink"}}
	strandedExpectation := LabExpected{
		Verdict:  d.VerdictDegraded,
		Required: []d.DiagnosisID{d.DiagnosisDirectEgressBlocked},
		// Not merely absent: this is the claim the topology refutes, since no
		// public destination is reachable to have answered anything.
		Forbidden: []d.DiagnosisID{d.DiagnosisReferenceEgressUnreachable, d.DiagnosisOffline, d.DiagnosisProxyOnlyNetwork},
		Checks: []ExpectedCheck{
			// FAIL rather than WARN: a relaxed egress row is what drops the
			// failure out of the report's ok field and the exit status, and
			// nothing here carried traffic off this network to earn that.
			{ID: "internet_tcp", Status: "FAIL"},
			{ID: "target_tcp", Status: "PASS"},
		},
		// A two-address sample cannot be generalized to every destination,
		// whichever way the endpoint row went.
		Confidence: []LabConfidence{{Finding: d.DiagnosisDirectEgressBlocked, Min: d.ConfidenceLow, Max: d.ConfidenceMedium}},
	}
	strandedBlindSpot := "The model knows the uplink is down. The client only knows two reference addresses did not answer, so it names the rung and not the hop; a filtered pair and a dead uplink look the same from here."
	s = healthy("lan-target-dead-uplink", "A device on the client's own segment answers while the gateway's uplink is down.", false)
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, Node{Name: "printer", Interfaces: []Interface{{Segment: "ethernet", IPv4: "10.20.1.60/24"}}, Services: []Service{{Name: "printer-jetdirect", Type: ServiceHTTP, Port: 9100}}})
	s.Faults = []LabFault{deadUplink}
	s.Views[0].Target = "10.20.1.60:9100"
	s.Views[0].Expected = strandedExpectation
	s.BlindSpots = []string{strandedBlindSpot}
	out = append(out, s)
	// RFC 6598 shared address space on a tunnel, which is the shape a tailnet
	// has: every node carries a 100.64.0.0/10 address, and reaching one of
	// them is not reaching the internet.
	s = healthy("shared-space-target-dead-uplink", "A peer in RFC 6598 shared address space answers over a tunnel while the gateway's uplink is down.", false)
	s.Network.Topology.Segments = append(s.Network.Topology.Segments, Segment{Name: "tailnet", IPv4: "100.100.0.0/16"})
	s.Network.Topology.Nodes[0].Interfaces = append(s.Network.Topology.Nodes[0].Interfaces, Interface{Segment: "tailnet", IPv4: "100.100.0.10/16"})
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, Node{Name: "peer", Interfaces: []Interface{{Segment: "tailnet", IPv4: "100.100.0.60/16"}}, Services: []Service{{Name: "peer-app", Type: ServiceHTTP, Port: 9100}}})
	s.Tunnels = []string{"tailnet"}
	s.Faults = []LabFault{deadUplink}
	s.Views[0].Target = "100.100.0.60:9100"
	s.Views[0].SourceSegment = ""
	s.Views[0].Expected = strandedExpectation
	s.BlindSpots = []string{strandedBlindSpot, "Shared address space is not globally routable, but nothing observable says whether a given 100.64.0.0/10 peer sits on this link or at the far end of a carrier's NAT."}
	out = append(out, s)
	s = healthy("tls-http-no-response", "The TLS identity verifies but the application never returns HTTP.", false)
	s.Faults = []LabFault{{ID: "silent-application", Layer: "http", Scope: "target-tls", HTTPNoResponse: "target-tls"}}
	expect(&s, d.VerdictService, d.DiagnosisHTTPSNoResponse, ExpectedCheck{ID: "tls", Status: "PASS"}, ExpectedCheck{ID: "https", Status: "FAIL"})
	out = append(out, s)
	// Each expected identity has an independently chosen observation anchor.
	// This table is an oracle only; no adapter or diagnostic reads it.
	anchors := map[d.DiagnosisID][]LabEvidenceRequirement{
		d.DiagnosisSystemDNSFailure:           {{Check: d.ProbeDNS, Observation: d.ObservationCause}, {Check: d.ProbeDNSPublic, Observation: d.ObservationDNSAnswers}},
		d.DiagnosisDNSDisagreement:            {{Check: d.ProbeDNS, Observation: d.ObservationDNSAnswers}, {Check: d.ProbeDNSPublic, Observation: d.ObservationDNSAnswers}},
		d.DiagnosisDirectEgressDegraded:       {{Check: d.ProbeInternet, Observation: d.ObservationCause}},
		d.DiagnosisReferenceEgressUnreachable: {{Check: d.ProbeInternet, Observation: d.ObservationStatusDowngraded}, {Check: d.ProbeTargetTCP, Observation: d.ObservationStatusPass}},
		d.DiagnosisTargetUnreachable:          {{Check: d.ProbeTargetTCP, Observation: d.ObservationStatusFail}, {Check: d.ProbeInternet, Observation: d.ObservationStatusPass}, {Check: d.ProbeDNS, Observation: d.ObservationDNSAnswers}},
		d.DiagnosisProxyOnlyNetwork:           {{Check: d.ProbeProxy, Observation: d.ObservationStatusPass}, {Check: d.ProbeInternet, Observation: d.ObservationStatusDowngraded}},
		d.DiagnosisCaptivePortal:              {{Check: d.ProbeInternet, Observation: d.ObservationCaptivePortal}},
		d.DiagnosisTLSHostnameMismatch:        {{Check: d.ProbeTLS, Observation: d.ObservationCause}, {Check: d.ProbeTargetTCP, Observation: d.ObservationStatusPass}},
		d.DiagnosisProbablePathMTU:            {{Check: d.ProbePMTU, Observation: d.ObservationStatusWarn}, {Check: d.ProbeTLS, Observation: d.ObservationCause}, {Check: d.ProbeTargetTCP, Observation: d.ObservationStatusPass}},
		d.DiagnosisTCPConnectionRefused:       {{Check: d.ProbeTargetTCP, Observation: d.ObservationCause}},
		d.DiagnosisDNSNameNotFound:            {{Check: d.ProbeDNS, Observation: d.ObservationDNSNotFound}, {Check: d.ProbeDNSPublic, Observation: d.ObservationDNSNotFound}},
		d.DiagnosisHTTPSNoResponse:            {{Check: d.ProbeHTTPS, Observation: d.ObservationTimeout}, {Check: d.ProbeTLS, Observation: d.ObservationStatusPass}},
	}
	for i := range out {
		for j := range out[i].Views {
			e := &out[i].Views[j].Expected
			for _, id := range e.Required {
				for _, anchor := range anchors[id] {
					anchor.Finding = id
					e.Evidence = append(e.Evidence, anchor)
				}
				if !slices.ContainsFunc(e.Confidence, func(c LabConfidence) bool { return c.Finding == id }) {
					max := d.ConfidenceHigh
					switch id {
					case d.DiagnosisSystemDNSFailure, d.DiagnosisDNSDisagreement, d.DiagnosisHTTPSNoResponse:
						max = d.ConfidenceMedium
					case d.DiagnosisTargetUnreachable:
						max = d.ConfidenceLow
					}
					e.Confidence = append(e.Confidence, LabConfidence{Finding: id, Min: d.ConfidenceLow, Max: max})
				}
			}
			// A healthy verdict alone would allow silent skipped/unmeasured rows.
			if e.Verdict == d.VerdictOK {
				for _, check := range []string{"iface", "internet_tcp", "dns", "dns_public", "target_tcp", "tls", "http", "https", "path_mtu", "dns_encrypted", "quic_udp_443"} {
					if !slices.ContainsFunc(e.Checks, func(c ExpectedCheck) bool { return c.ID == check }) {
						e.Checks = append(e.Checks, ExpectedCheck{ID: check, Status: "PASS"})
					}
				}
			}
		}
	}
	return out
}

func FindLabScenario(name string) (LabScenario, error) {
	for _, s := range LabScenarios() {
		if s.Name == name {
			return s, nil
		}
	}
	return LabScenario{}, fmt.Errorf("unknown lab scenario %q", name)
}

func labRecords(dual bool, target string) []DNSRecord {
	r := []DNSRecord{{Name: labHost, Address: target}, {Name: d.ConnectivityProbeHost, Address: "10.20.2.20"}, {Name: "www.msftconnecttest.com", Address: "10.20.2.20"}}
	if dual {
		r = append(r, DNSRecord{Name: labHost, Address: labTarget6})
	}
	return r
}
func labServer(name, ip, alias string) Node {
	return Node{Name: name, Role: "server", Interfaces: []Interface{{Segment: "uplink", IPv4: ip + "/24"}}, Aliases: []string{alias}, Services: []Service{{Name: name + "-tls", Type: ServiceTLS, Port: 443, Certificate: &TLSCertificate{Mode: TLSCertificateValid, DNSNames: []string{labHost}}}, {Name: name + "-http", Type: ServiceHTTP, Port: 80}}}
}

func labBase(dual bool) Scenario {
	s := Scenario{Topology: Topology{Segments: []Segment{{Name: "ethernet", IPv4: "10.20.1.0/24"}, {Name: "uplink", IPv4: "10.20.2.0/24"}}, Nodes: []Node{
		{Name: "client", Role: "client", Resolver: "10.20.1.53", Interfaces: []Interface{{Segment: "ethernet", IPv4: "10.20.1.10/24"}}},
		{Name: "gateway", Role: "router", Interfaces: []Interface{{Segment: "ethernet", IPv4: "10.20.1.1/24"}, {Segment: "uplink", IPv4: "10.20.2.1/24"}}},
		{Name: "resolver", Resolver: "10.20.1.53", Interfaces: []Interface{{Segment: "ethernet", IPv4: "10.20.1.53/24"}}, Services: []Service{{Name: "system-dns", Type: ServiceDNS, Port: 53, Records: labRecords(dual, labTarget4)}}},
		{Name: "internet", Resolver: "10.20.2.20", Interfaces: []Interface{{Segment: "uplink", IPv4: "10.20.2.20/24"}}, Aliases: []string{"1.1.1.1", "8.8.8.8"}, Services: []Service{
			{Name: "public-dns", Type: ServiceDNS, Port: 53, Records: labRecords(dual, labTarget4)},
			{Name: "reference-http", Type: ServiceHTTP, Port: 80},
			{Name: "reference-doh", Type: ServiceEncryptedDNS, Port: 443, Certificate: &TLSCertificate{Mode: TLSCertificateValid, DNSNames: []string{"cloudflare-dns.com"}}, Records: labRecords(dual, labTarget4)},
			{Name: "reference-quic", Type: ServiceQUIC, Port: 443, Certificate: &TLSCertificate{Mode: TLSCertificateValid, DNSNames: []string{d.ConnectivityProbeHost}}},
		}},
		labServer("target", "10.20.2.21", labTarget4),
		{Name: "remote", Resolver: "10.20.2.20", Interfaces: []Interface{{Segment: "uplink", IPv4: "10.20.2.30/24"}}},
	}}}
	for _, r := range []Route{{Node: "client", Via: "10.20.1.1"}, {Node: "resolver", Via: "10.20.1.1"}, {Node: "target", Via: "10.20.2.1"}, {Node: "internet", Via: "10.20.2.1"}, {Node: "remote", Via: "10.20.2.1"}} {
		r.Destination = "0.0.0.0/0"
		s.Topology.Routes = append(s.Topology.Routes, r)
	}
	for _, node := range []string{"gateway", "remote"} {
		for _, ip := range []string{"1.1.1.1", "8.8.8.8", labTarget4} {
			via := "10.20.2.20"
			if ip == labTarget4 {
				via = "10.20.2.21"
			}
			s.Topology.Routes = append(s.Topology.Routes, Route{Node: node, Destination: ip + "/32", Via: via})
		}
	}
	if dual {
		for i := range s.Topology.Segments {
			s.Topology.Segments[i].IPv6 = fmt.Sprintf("2001:db8:20:%d::/64", i+1)
		}
		for i := range s.Topology.Nodes {
			for j := range s.Topology.Nodes[i].Interfaces {
				iface := &s.Topology.Nodes[i].Interfaces[j]
				var a, b, c, last int
				_, _ = fmt.Sscanf(iface.IPv4, "%d.%d.%d.%d/24", &a, &b, &c, &last)
				iface.IPv6 = fmt.Sprintf("2001:db8:20:%d::%x/64", c, last)
			}
		}
		for i := range s.Topology.Nodes {
			n := &s.Topology.Nodes[i]
			switch n.Name {
			case "target":
				n.Aliases = append(n.Aliases, labTarget6)
			case "internet":
				n.Aliases = append(n.Aliases, "2606:4700:4700::1111", "2001:4860:4860::8888")
			}
			if n.Name != "gateway" {
				via := "2001:db8:20:2::1"
				if n.Name == "client" || n.Name == "resolver" {
					via = "2001:db8:20:1::1"
				}
				s.Topology.Routes = append(s.Topology.Routes, Route{Node: n.Name, Destination: "::/0", Via: via})
			}
		}
		for _, ip := range []string{"2606:4700:4700::1111", "2001:4860:4860::8888", labTarget6} {
			via := "2001:db8:20:2::14"
			if ip == labTarget6 {
				via = "2001:db8:20:2::15"
			}
			s.Topology.Routes = append(s.Topology.Routes, Route{Node: "gateway", Destination: ip + "/128", Via: via})
		}
	}
	return s
}

func labAddVPN(s *LabScenario) {
	s.Views[0].SourceSegment = ""
	s.Network.Topology.Segments = append(s.Network.Topology.Segments, Segment{Name: "vpn", IPv4: "10.20.3.0/24"})
	s.Network.Topology.Nodes[0].Interfaces = append(s.Network.Topology.Nodes[0].Interfaces, Interface{Segment: "vpn", IPv4: "10.20.3.10/24"})
	s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, Node{Name: "corp-gw", Role: "router", Interfaces: []Interface{{Segment: "vpn", IPv4: "10.20.3.1/24"}, {Segment: "uplink", IPv4: "10.20.2.2/24"}}}, Node{Name: "corp-dns", Interfaces: []Interface{{Segment: "vpn", IPv4: "10.20.3.53/24"}}, Services: []Service{{Name: "corp-dns", Type: ServiceDNS, Records: labRecords(false, labTarget4)}}})
	s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: "client", Destination: labTarget4 + "/32", Via: "10.20.3.1"}, Route{Node: "corp-gw", Destination: labTarget4 + "/32", Via: "10.20.2.21"}, Route{Node: "target", Destination: "10.20.3.0/24", Via: "10.20.2.2"}, Route{Node: "corp-dns", Destination: "0.0.0.0/0", Via: "10.20.3.1"}, Route{Node: "corp-gw", Destination: "0.0.0.0/0", Via: "10.20.2.1"})
	s.Tunnels = []string{"vpn"}
}
