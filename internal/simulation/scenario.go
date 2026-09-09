// Package simulation builds a throwaway virtual network, runs netdoc inside
// it, and compares the diagnosis against what the scenario said should break.
//
// Nothing here touches the host's networking. Every interface, route, resolver
// and firewall rule lives inside namespaces the simulator created and owns, and
// they cease to exist when the process tree that holds them dies. See
// netns_linux.go for the mechanism.
package simulation

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"gopkg.in/yaml.v3"
)

// Scenario is one simulation: a topology to build, faults to inject, netdoc
// runs to make, and the diagnosis those runs should produce.
type Scenario struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Topology    Topology      `yaml:"topology"`
	Faults      []Fault       `yaml:"faults"`
	Tests       []Test        `yaml:"tests"`
	Expect      Expect        `yaml:"expect"`
	Campaign    *CampaignSpec `yaml:"campaign,omitempty"`
}

// Topology describes L2 segments, node interfaces, and routes. Subnet remains
// the backward-compatible shorthand used by the original single-segment
// scenarios; validation normalizes it into Segments, Interfaces, and Routes.
type Topology struct {
	Subnet   string    `yaml:"subnet"`
	Segments []Segment `yaml:"segments"`
	Nodes    []Node    `yaml:"nodes"`
	Routes   []Route   `yaml:"routes"`
}

// Segment is one simulator-owned Linux bridge.
type Segment struct {
	Name string `yaml:"name"`
	// Subnet is the backward-compatible IPv4 spelling used by the original
	// routed scenarios. IPv4 and IPv6 let one logical L2 segment carry both
	// families without manufacturing a second interface.
	Subnet string `yaml:"subnet"`
	IPv4   string `yaml:"ipv4"`
	IPv6   string `yaml:"ipv6"`
}

// Interface attaches a node to one logical segment. Scenario authors never
// provide the kernel interface name; the backend derives a short safe name.
type Interface struct {
	Segment string `yaml:"segment"`
	// Address is the backward-compatible IPv4 spelling. IPv4 and IPv6 are
	// installed on this same generated kernel interface.
	Address string `yaml:"address"`
	IPv4    string `yaml:"ipv4"`
	IPv6    string `yaml:"ipv6"`
}

// Route is a validated unicast route. Destination is either "default" or a
// canonical prefix; free-form iproute expressions are deliberately impossible.
type Route struct {
	Node        string `yaml:"node"`
	Destination string `yaml:"destination"`
	Via         string `yaml:"via"`
	Metric      int    `yaml:"metric"`
	Default     bool   `yaml:"-"`
	Family      string `yaml:"-"`
}

// Node is one network namespace on the segment.
type Node struct {
	Name string `yaml:"name"`
	// Role client marks the namespace netdoc runs in; every other node is
	// scenery. Exactly one client per scenario.
	Role    string `yaml:"role"`
	Address string `yaml:"address"`
	// Interfaces is the explicit multi-segment form. Address is retained only
	// for legacy single-segment scenario compatibility.
	Interfaces []Interface `yaml:"interfaces"`
	// Aliases are extra addresses put on the node's loopback, which is how the
	// simulated internet claims diagnostic's production probe endpoints without
	// anything leaving the namespace.
	Aliases  []string  `yaml:"aliases"`
	Gateway  string    `yaml:"gateway"`
	Resolver string    `yaml:"resolver"`
	Services []Service `yaml:"services"`
}

// Service is a test server the node runs. Ports are bound inside the node's
// namespace, so two nodes may both serve :53 or :443.
type Service struct {
	// Name is optional for existing scenarios, but required when another
	// scenario object needs to identify the service. Non-empty names are unique
	// across the topology.
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Port int    `yaml:"port"`
	// Banner makes a TCP fixture write one bounded, newline-terminated protocol
	// greeting before it drains the client connection.
	Banner string `yaml:"banner"`
	// Zone maps a name to an address for ServiceDNS. A name that is absent
	// answers NXDOMAIN, which is how "DNS returns NXDOMAIN" is expressed.
	Zone map[string]string `yaml:"zone"`
	// Records is the ordered multi-record form. Zone remains the compatible
	// single-record shorthand; both forms describe static address records only.
	Records []DNSRecord `yaml:"records"`
	// Body and Status shape the ServiceHTTP reply on every path but the
	// connectivity check, which answers 204 so netdoc's captive-portal check
	// passes unless Portal says otherwise.
	Status int    `yaml:"status"`
	Body   string `yaml:"body"`
	// DateOffset moves the HTTP Date header relative to the server's wall clock.
	// It uses Go duration syntax and is empty when the ordinary net/http header
	// should be left untouched.
	DateOffset string `yaml:"date_offset"`
	// Portal makes ServiceHTTP intercept the connectivity checks the way a
	// captive portal does: both /generate_204 and /connecttest.txt redirect to
	// a fixed sign-in page instead of answering what they document, since a
	// portal intercepts plain HTTP rather than one provider's name. Pointing
	// the two names at a portal node and a plain one is how a scenario models
	// interception aimed at a single provider.
	// Intent only, as every other fixture mode is:
	// the sign-in URL is the simulator's, since a scenario-supplied one would
	// be a raw URL in a file that is otherwise not allowed to carry any.
	Portal bool `yaml:"portal"`
	// Certificate describes simulator-generated TLS identity. Scenario files
	// select intent only; they cannot provide keys, PEM, paths, or algorithms.
	Certificate *TLSCertificate `yaml:"certificate"`
	// DNSFault is a bounded, precomputed response schedule. It is consumed per
	// queried name and query type, never generated by a service goroutine.
	DNSFault *DNSFault `yaml:"dns_fault"`
	// DoHResponse is the encrypted-DNS fixture's response mode. Empty serves a
	// valid DNS message; invalid serves deterministic protocol-invalid bytes on
	// DoH only so DoT remains an independent control.
	DoHResponse string `yaml:"doh_response"`
}

// DNSRecord is one static A or AAAA answer. Type is derived from Address so a
// scenario cannot claim an A record while supplying IPv6 bytes, or vice versa.
type DNSRecord struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

// TLSCertificate is the narrow certificate intent accepted by a TLS service.
type TLSCertificate struct {
	Mode     string   `yaml:"mode"`
	DNSNames []string `yaml:"dns_names"`
}

// Service types.
const (
	ServiceDNS  = "dns"
	ServiceHTTP = "http"
	// ServiceTCP accepts a connection and closes it, enough for the direct
	// egress probe, which only proves a handshake completes.
	ServiceTCP = "tcp"
	// ServiceSOCKS5 is a simulator-owned, no-auth CONNECT proxy. It supports
	// address and domain destinations; BIND and UDP ASSOCIATE are intentionally
	// outside the simulator's needs.
	ServiceSOCKS5 = "socks5"
	// ServiceHTTPConnect is a simulator-owned, no-auth HTTP CONNECT proxy. It
	// tunnels one host:port authority per connection and refuses everything
	// else with a status code; forward proxying of ordinary methods, upstream
	// chaining and authentication are outside the simulator's needs.
	ServiceHTTPConnect = "http_connect"
	// ServiceTLS generates an in-memory private CA and leaf key, writes only the
	// public CA certificate to the simulator workspace, and serves bounded TLS.
	ServiceTLS = "tls"
	// ServiceQUIC completes a real QUIC handshake with h3 ALPN over UDP.
	ServiceQUIC = "quic"
	// ServiceEncryptedDNS answers netdoc's encrypted-DNS probe over both
	// transports from one static zone: RFC 8484 DoH on the service port and RFC
	// 7858 DoT on 853. It also accepts the plain TCP connect the direct-egress
	// probe makes, so it stands in for a tcp service on the same port.
	ServiceEncryptedDNS = "encrypted_dns"
	// ServiceTCPReset accepts a TCP handshake and closes with SO_LINGER=0 so a
	// protocol probe observes ECONNRESET rather than connection refusal.
	ServiceTCPReset = "tcp_reset"
)

const (
	// Default listen ports for the two proxy fixtures. 1080 is the registered
	// SOCKS port; 3128 is the conventional HTTP proxy port and keeps a CONNECT
	// proxy visibly distinct from an ordinary web server on 80 or 8080.
	defaultSOCKSProxyPort   = 1080
	defaultCONNECTProxyPort = 3128

	TLSCertificateValid            = "valid"
	TLSCertificateExpired          = "expired"
	TLSCertificateNotYetValid      = "not_yet_valid"
	TLSCertificateHostnameMismatch = "hostname_mismatch"
	DoHResponseInvalid             = "invalid"
	tlsMaxDNSNames                 = 16
	maxServiceBannerBytes          = 1024
	dnsMaxRecords                  = 64
	dnsMaxScheduledOutcomes        = 256
	maxNetemDuration               = 10 * time.Second
)

// Fault types.
const (
	// FaultDrop discards matching packets with an nftables rule. Direction
	// decides whether the sender is refused or left waiting; see Fault.
	FaultDrop = "drop"
	// FaultNetem attaches delay/jitter/loss to the node's segment interface.
	FaultNetem = "netem"
	// FaultNoDefaultRoute deletes the node's default route.
	FaultNoDefaultRoute = "no_default_route"
	// FaultReplaceDefaultRoute replaces every default route on a node with one
	// validated on-link next hop.
	FaultReplaceDefaultRoute = "replace_default_route"
	// FaultLinkDown administratively lowers one logical node interface.
	FaultLinkDown = "link_down"
	// FaultPMTUBlackhole narrows one router interface and drops the ICMP
	// fragmentation-needed replies that router would send about it, which is
	// the pair of conditions a path-MTU black hole is made of. Narrowing alone
	// is not one: a router that reports the smaller MTU is discovered and
	// worked around, and narrowing an endpoint instead makes the local kernel
	// refuse the send. Both endpoints must keep believing the path is wide,
	// and the hop that knows better must stay silent.
	FaultPMTUBlackhole = "pmtu_blackhole"
)

// PMTU black hole bounds.
const (
	// minBlackholeMTU is the smallest IPv4 datagram every host must accept, so
	// a narrower hop models nothing real.
	minBlackholeMTU = 576
	// maxBlackholeMTU is one below the Ethernet default the endpoints keep, so
	// a fault that narrows nothing is rejected instead of silently passing.
	maxBlackholeMTU = 1499
	// minIPv6MTU is the floor IPv6 requires of a link. Below it the kernel
	// stops carrying IPv6 on the interface entirely, which is a dead segment
	// rather than a black hole.
	minIPv6MTU = 1280
)

// FaultDrop directions.
const (
	DirectionOutbound = "outbound"
	DirectionInbound  = "inbound"
)

// Fault is one impairment applied after the topology is up and healthy.
type Fault struct {
	Type string `yaml:"type"`
	Node string `yaml:"node"`
	// Segment identifies an interface by logical topology name. Via and Metric
	// are used only by replace_default_route.
	Segment string `yaml:"segment"`
	Via     string `yaml:"via"`
	Metric  int    `yaml:"metric"`
	// Family restricts route faults to ipv4 or ipv6. Empty preserves the
	// original IPv4 behavior of existing scenarios.
	Family string `yaml:"family"`
	// To, Protocol and Port select the traffic FaultDrop discards. An empty To
	// matches every destination; a zero Port matches every port.
	To       string `yaml:"to"`
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
	// Direction chooses where FaultDrop bites, and the two are not
	// interchangeable. Outbound drops the packet on the way out of this node,
	// which the kernel reports to the sender as a refusal, the way a local firewall behaves.
	// Inbound drops it as it arrives at this node, so the sender hears nothing
	// and waits out its timeout, the way a black hole in the path behaves. Default outbound.
	Direction string `yaml:"direction"`
	// Delay, Jitter and Loss configure FaultNetem. Delay and Jitter are Go
	// durations; Loss is a percentage such as "10%".
	Delay  string `yaml:"delay"`
	Jitter string `yaml:"jitter"`
	Loss   string `yaml:"loss"`
	// Seed makes tc netem's pseudo-random sequence reproducible. Zero asks tc
	// for its default; campaign compilation always supplies a non-zero seed.
	Seed uint32 `yaml:"seed,omitempty"`
	// MTU is the size FaultPMTUBlackhole narrows the named interface to. The
	// endpoints are left alone, so they keep offering full-size packets to a
	// hop that can no longer carry them.
	MTU int `yaml:"mtu,omitempty"`
	// Service names the simulator DNS service a scheduled_dns fault drives. The
	// node is derived from it; a scenario never names one for this fault type.
	Service string `yaml:"service,omitempty"`
	// Events is the timed transition list of a scheduled_* fault. It is fully
	// resolved before the topology exists and immutable once T0 passes.
	Events []ScheduledEvent `yaml:"events,omitempty"`
}

const (
	DNSOutcomeAnswer      = "answer"
	DNSOutcomeSERVFAIL    = "servfail"
	DNSOutcomeREFUSED     = "refused"
	DNSOutcomeTruncated   = "truncated"
	DNSOutcomeWrongAnswer = "wrong_answer"
)

// DNSFault carries one deterministic response sequence per DNS query family.
// Every queried name walks that sequence independently, so a query for one name
// cannot advance another name's schedule. When a sequence is exhausted, the
// service answers normally. WrongA and WrongAAAA are required only when their
// family schedule contains wrong_answer.
type DNSFault struct {
	A         []string `yaml:"a"`
	AAAA      []string `yaml:"aaaa"`
	WrongA    string   `yaml:"wrong_a"`
	WrongAAAA string   `yaml:"wrong_aaaa"`
}

// CampaignSpec declares bounded ranges only. Compilation resolves every range
// before a node or goroutine starts; scenario files cannot contain expressions
// or executable material.
type CampaignSpec struct {
	Runs  int            `yaml:"runs"`
	Netem *CampaignNetem `yaml:"netem"`
	DNS   *CampaignDNS   `yaml:"dns"`
	// Timeline generates a bounded flapping fault timeline per iteration.
	Timeline *CampaignTimeline `yaml:"timeline"`
	// DNSDelay sweeps one resolver delay, which is how a campaign walks a probe
	// timeout boundary without varying anything else.
	DNSDelay *CampaignDNSDelay `yaml:"dns_delay"`
}

// CampaignTimeline generates one flapping timeline per iteration. The shape is
// fixed and only three dimensions vary (when degradation starts, how bad it
// is, and how long the total outage lasts) so a failing iteration is still
// something a person can read.
//
//	+0                          healthy
//	+degrade_at                 degraded (loss = degrade_loss_percent)
//	+degrade_at+400ms           healthy
//	+degrade_at+800ms           outage (100% loss, and the resolver silent)
//	+degrade_at+800ms+outage_for healthy again
type CampaignTimeline struct {
	Node    string `yaml:"node"`
	Segment string `yaml:"segment"`
	// Service, when named, loses its DNS responses for the outage window too.
	Service string `yaml:"service"`
	// ResolverHold is the delay that service opens with. It paces the run so
	// the generated phases actually overlap a probe: netdoc issues all of its
	// resolver queries in the first few milliseconds of a run, so without
	// something holding it there, a timeline measured in hundreds of
	// milliseconds would be changing a network nobody was looking at.
	ResolverHold string `yaml:"resolver_hold"`
	// Latency is the fixed healthy latency every phase carries.
	Latency     string        `yaml:"latency"`
	DegradeAt   DurationRange `yaml:"degrade_at"`
	DegradeLoss NumberRange   `yaml:"degrade_loss_percent"`
	OutageFor   DurationRange `yaml:"outage_for"`
}

// campaignTimelineShape is the fixed part of a flapping timeline: how long the
// degraded phase lasts, and how long the network is healthy again before the
// total outage begins.
const (
	campaignDegradedFor = 400 * time.Millisecond
	campaignHealthyGap  = 400 * time.Millisecond
)

type CampaignDNSDelay struct {
	Service string        `yaml:"service"`
	Delay   DurationRange `yaml:"delay"`
}

type CampaignNetem struct {
	Node        string        `yaml:"node"`
	Segment     string        `yaml:"segment"`
	Latency     DurationRange `yaml:"latency"`
	Jitter      DurationRange `yaml:"jitter"`
	LossPercent NumberRange   `yaml:"loss_percent"`
}

type CampaignDNS struct {
	Service        string      `yaml:"service"`
	QueriesPerType int         `yaml:"queries_per_type"`
	FailurePercent NumberRange `yaml:"failure_percent"`
}

type DurationRange struct {
	Min string `yaml:"min"`
	Max string `yaml:"max"`
}

type NumberRange struct {
	Min float64 `yaml:"min"`
	Max float64 `yaml:"max"`
}

// Test is one netdoc run inside a node. An empty Target runs the generic
// (no-target) checks, exactly as `netdoc` with no argument does.
type Test struct {
	Name          string     `yaml:"name"`
	Type          string     `yaml:"type"`
	Node          string     `yaml:"node"`
	Target        string     `yaml:"target"`
	SourceSegment string     `yaml:"source_segment"`
	Proxy         *TestProxy `yaml:"proxy"`
	Trust         *TestTrust `yaml:"trust"`
	Expect        *Expect    `yaml:"expect"`
}

// TestProxy selects one SOCKS service and the public URL scheme netdoc should
// receive. The address is derived from the validated node; scenarios cannot
// supply a raw proxy URL or environment variable.
type TestProxy struct {
	Scheme  string `yaml:"scheme"`
	Node    string `yaml:"node"`
	Port    int    `yaml:"port"`
	address string
}

// TestTrust selects the public root generated by one validated TLS service.
// The runner turns it into SSL_CERT_FILE; scenarios cannot supply environment
// names, paths, or certificate bytes.
type TestTrust struct {
	Service string `yaml:"service"`
}

// TestNetdoc is the only test type. Named so a scenario can be explicit, and
// so an unknown type is rejected rather than silently treated as this one.
const TestNetdoc = "netdoc"

// Expect is the diagnosis the scenario claims netdoc should reach. Verdict and
// checks match netdoc's stable machine-readable contract; Summary optionally
// pins the user-facing diagnosis.
type Expect struct {
	Verdict string          `yaml:"verdict"`
	Summary string          `yaml:"summary"`
	Checks  []ExpectedCheck `yaml:"checks"`
}

// ExpectedCheck names one probe row and the result it should carry. Fix
// optionally pins the user-facing remedy.
type ExpectedCheck struct {
	ID     string `yaml:"id"`
	Status string `yaml:"status"`
	Cause  string `yaml:"cause"`
	Fix    string `yaml:"fix"`
	IPv4   string `yaml:"ipv4"`
	IPv6   string `yaml:"ipv6"`
}

// knownProbeIDs is the set a scenario may name. It references the constants so
// a rename breaks the build; a newly added probe has to be listed here before
// a scenario can assert on it.
var knownProbeIDs = []diagnostic.ProbeID{
	diagnostic.ProbeIface, diagnostic.ProbeSSID, diagnostic.ProbeInternet,
	diagnostic.ProbeQUIC, diagnostic.ProbeProxy, diagnostic.ProbeDNS, diagnostic.ProbeDNSPublic,
	diagnostic.ProbeDNSEncrypted,
	diagnostic.ProbeTargetTCP, diagnostic.ProbePMTU, diagnostic.ProbeTLS,
	diagnostic.ProbeHTTP, diagnostic.ProbeHTTPS, diagnostic.ProbeSSH,
	diagnostic.ProbeSMTP,
}

// statuses is netdoc's status vocabulary as it appears in the JSON report.
var statuses = []string{"PASS", "WARN", "FAIL", "SKIP", "N/A"}

var knownCauses = []string{
	diagnostic.ProxyCauseUnreachable,
	diagnostic.ProxyCauseClientDNS,
	diagnostic.ProxyCauseProxyDNS,
	diagnostic.ProxyCauseDestinationUnreachable,
	diagnostic.ProxyCauseProtocol,
	diagnostic.QUICCauseHandshake,
	diagnostic.EncryptedDNSCauseUnavailable,
	diagnostic.TLSCauseCertificateExpired,
	diagnostic.TLSCauseCertificateNotYet,
	diagnostic.TLSCauseHostnameMismatch,
	diagnostic.TLSCauseUntrustedIssuer,
	diagnostic.TLSCauseHandshake,
	diagnostic.TLSCauseTCPUnreachable,
	diagnostic.TLSCauseTimeout,
	diagnostic.TLSCauseConnectionClosed,
	diagnostic.RouteCauseNoDefaultRoute,
	diagnostic.RouteCauseGatewayUnreachable,
	diagnostic.RouteCauseSelectedPathFailed,
	diagnostic.RouteCausePreferredPathFailed,
	diagnostic.RouteCausePreferredPathAlternateReachable,
	diagnostic.FamilyCauseIPv4Unreachable,
	diagnostic.FamilyCauseIPv6Unreachable,
	diagnostic.DNSCauseTimeout,
	diagnostic.DNSCauseTemporaryFailure,
	diagnostic.ConnectionCauseRefused,
	diagnostic.ConnectionCauseReset,
}

// verdicts is netdoc's verdict vocabulary. Incomplete is omitted on purpose:
// a finished run never reports it, so expecting it is always a scenario bug.
var verdicts = []string{
	diagnostic.VerdictOK, diagnostic.VerdictDegraded, diagnostic.VerdictDNS,
	diagnostic.VerdictNetwork, diagnostic.VerdictService,
}

// LoadScenario reads and validates a scenario file.
func LoadScenario(path string) (*Scenario, error) {
	// #nosec G304 -- arbitrary user-selected files are intentional CLI input; this unprivileged read is read-only, then parsed and validated as simulator configuration.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := ParseScenario(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ParseScenario decodes YAML and validates it. Unknown fields are an error, so
// a typo'd key fails loudly instead of being silently ignored.
func ParseScenario(r io.Reader) (*Scenario, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty scenario")
		}
		return nil, err
	}
	// A second document would be silently dropped, and a scenario file is one
	// scenario.
	var extra Scenario
	if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
		// Whitespace and comments after the document are allowed.
	} else if err == nil {
		return nil, errors.New("scenario file must contain exactly one document")
	} else {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate reports the first thing wrong with the scenario. It runs before any
// namespace exists, so a bad scenario costs nothing.
func (s *Scenario) Validate() error {
	if s.Name == "" {
		return errors.New("name is required")
	}
	if len(s.Topology.Nodes) == 0 {
		return errors.New("topology.nodes: at least one node is required")
	}
	seen := make(map[string]bool, len(s.Topology.Nodes))
	nodes := make(map[string]*Node, len(s.Topology.Nodes))
	clients := 0
	for i := range s.Topology.Nodes {
		n := &s.Topology.Nodes[i]
		switch {
		case n.Name == "":
			return fmt.Errorf("topology.nodes[%d].name is required", i)
		case seen[n.Name]:
			return fmt.Errorf("duplicate node name %q", n.Name)
		case !isSafeName(n.Name):
			return fmt.Errorf("node %q: name must be letters, digits or dashes", n.Name)
		}
		seen[n.Name] = true
		nodes[n.Name] = n
		switch n.Role {
		case "client":
			clients++
		case "server", "router":
		case "":
			n.Role = "server"
		default:
			return fmt.Errorf("node %q: unknown role %q (client, server or router)", n.Name, n.Role)
		}
	}
	if clients != 1 {
		return fmt.Errorf("exactly one node must have role client, found %d", clients)
	}
	if err := s.Topology.normalizeAndValidate(nodes); err != nil {
		return err
	}
	serviceNames := make(map[string]bool)
	for i := range s.Topology.Nodes {
		if err := s.Topology.Nodes[i].validateServices(serviceNames); err != nil {
			return err
		}
	}
	for i := range s.Faults {
		if err := s.Faults[i].validate(&s.Topology, seen); err != nil {
			return fmt.Errorf("faults[%d]: %w", i, err)
		}
	}
	if n := len(timelineFrom(s.Faults)); n > maxTimelineEvents {
		return fmt.Errorf("faults: %d scheduled events, maximum is %d", n, maxTimelineEvents)
	}
	if len(s.Tests) == 0 {
		return errors.New("tests: at least one test is required")
	}
	for i := range s.Tests {
		if err := s.Tests[i].validate(nodes); err != nil {
			return fmt.Errorf("tests[%d]: %w", i, err)
		}
	}
	if s.Campaign != nil {
		if err := s.Campaign.validate(s); err != nil {
			return fmt.Errorf("campaign: %w", err)
		}
	}
	return s.Expect.validate()
}

func (t Topology) subnetOrDefault() string {
	if t.Subnet == "" {
		return "10.77.0.0/24"
	}
	return t.Subnet
}

// parseAddr is the only way an address from a scenario becomes a string this
// package will use. It rejects what ParseAddr alone would let through and
// returns the canonical rendering, so what reaches an `ip` argv or a generated
// resolv.conf is the kernel's own spelling of the address rather than the bytes
// that were in the file.
//
// The zone is the part worth refusing: netip.ParseAddr accepts an essentially
// arbitrary string after "%", and while a zone could only ever reach a command
// as one argv element, since nothing here builds a shell string, an unbounded value
// has no business in an interface name or a nameserver line.
func parseAddr(raw string) (netip.Addr, string, error) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, "", err
	}
	if addr.Zone() != "" {
		return netip.Addr{}, "", fmt.Errorf("%q: scoped addresses (the %%zone suffix) are not supported", raw)
	}
	if addr.Is4In6() {
		return netip.Addr{}, "", fmt.Errorf("%q: IPv4-mapped IPv6 addresses are not supported", raw)
	}
	return addr, addr.String(), nil
}

func (n *Node) validateServices(names map[string]bool) error {
	for i := range n.Services {
		svc := &n.Services[i]
		if svc.Banner != "" && svc.Type != ServiceTCP {
			return fmt.Errorf("node %q: banner is only supported by tcp services", n.Name)
		}
		if svc.DateOffset != "" && svc.Type != ServiceHTTP {
			return fmt.Errorf("node %q: date_offset is only supported by http services", n.Name)
		}
		if svc.Name != "" {
			if !isSafeName(svc.Name) {
				return fmt.Errorf("node %q: service name %q must be letters, digits or dashes", n.Name, svc.Name)
			}
			if names[svc.Name] {
				return fmt.Errorf("duplicate service name %q", svc.Name)
			}
			names[svc.Name] = true
		}
		switch svc.Type {
		case ServiceDNS:
			if svc.Port == 0 {
				svc.Port = 53
			}
			if svc.Certificate != nil || svc.Status != 0 || svc.Body != "" || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: dns service has unsupported options", n.Name)
			}
			if len(svc.Zone)+len(svc.Records) > dnsMaxRecords {
				return fmt.Errorf("node %q: dns service has %d records, maximum is %d", n.Name, len(svc.Zone)+len(svc.Records), dnsMaxRecords)
			}
			zoneFamilies := make(map[string]string, len(svc.Zone))
			for name, ip := range svc.Zone {
				if !isSafeHostname(name) {
					return fmt.Errorf("node %q: zone name %q is not a hostname", n.Name, name)
				}
				addr, canonical, err := parseAddr(ip)
				if err != nil {
					return fmt.Errorf("node %q: zone %s: %w", n.Name, name, err)
				}
				if err := validateInterfaceAddr(addr); err != nil {
					return fmt.Errorf("node %q: zone %s: %w", n.Name, name, err)
				}
				key := dnsKey(name) + "\x00" + addressFamily(addr)
				if previous, exists := zoneFamilies[key]; exists {
					return fmt.Errorf("node %q: duplicate DNS record %q conflicts with %q", n.Name, name, previous)
				}
				zoneFamilies[key] = name
				svc.Zone[name] = canonical
			}
			recordAddresses := make(map[string]string, len(svc.Records))
			for ri := range svc.Records {
				record := &svc.Records[ri]
				if !isSafeHostname(record.Name) {
					return fmt.Errorf("node %q: record name %q is not a hostname", n.Name, record.Name)
				}
				addr, canonical, err := parseAddr(record.Address)
				if err != nil {
					return fmt.Errorf("node %q: record %s: %w", n.Name, record.Name, err)
				}
				if err := validateInterfaceAddr(addr); err != nil {
					return fmt.Errorf("node %q: record %s: %w", n.Name, record.Name, err)
				}
				familyKey := dnsKey(record.Name) + "\x00" + addressFamily(addr)
				if previous, exists := zoneFamilies[familyKey]; exists {
					return fmt.Errorf("node %q: duplicate DNS record %q conflicts with %q", n.Name, record.Name, previous)
				}
				addressKey := dnsKey(record.Name) + "\x00" + canonical
				if previous, exists := recordAddresses[addressKey]; exists {
					return fmt.Errorf("node %q: duplicate DNS record %q conflicts with %q", n.Name, record.Name, previous)
				}
				recordAddresses[addressKey] = record.Name
				record.Name, record.Address = dnsKey(record.Name), canonical
			}
			if err := validateDNSFault(svc.DNSFault); err != nil {
				return fmt.Errorf("node %q: dns service fault: %w", n.Name, err)
			}
			if svc.DNSFault != nil {
				for _, wrong := range []string{svc.DNSFault.WrongA, svc.DNSFault.WrongAAAA} {
					for name, address := range svc.Zone {
						if wrong != "" && wrong == address {
							return fmt.Errorf("node %q: dns service wrong answer %s matches zone address for %q", n.Name, wrong, name)
						}
					}
					for _, record := range svc.Records {
						if wrong != "" && wrong == record.Address {
							return fmt.Errorf("node %q: dns service wrong answer %s matches zone address for %q", n.Name, wrong, record.Name)
						}
					}
				}
			}
		case ServiceHTTP:
			if svc.Port == 0 {
				svc.Port = 80
			}
			if svc.Status == 0 {
				svc.Status = 200
			}
			if svc.Status < 100 || svc.Status > 599 {
				return fmt.Errorf("node %q: http status %d is out of range", n.Name, svc.Status)
			}
			if svc.DateOffset != "" {
				if _, err := time.ParseDuration(svc.DateOffset); err != nil {
					return fmt.Errorf("node %q: http date_offset: %w", n.Name, err)
				}
			}
			if svc.Certificate != nil || svc.DNSFault != nil || len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.DoHResponse != "" {
				return fmt.Errorf("node %q: http service has unsupported options", n.Name)
			}
		case ServiceTCP:
			if svc.Port == 0 {
				return fmt.Errorf("node %q: tcp service needs a port", n.Name)
			}
			if len(svc.Banner) > maxServiceBannerBytes {
				return fmt.Errorf("node %q: tcp banner must be at most %d bytes", n.Name, maxServiceBannerBytes)
			}
			if svc.Banner != "" && !strings.HasSuffix(svc.Banner, "\n") {
				return fmt.Errorf("node %q: tcp banner must end with a newline", n.Name)
			}
			if svc.Certificate != nil || svc.DNSFault != nil || len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.Status != 0 || svc.Body != "" || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: tcp service has unsupported options", n.Name)
			}
		case ServiceTCPReset:
			if svc.Port == 0 {
				return fmt.Errorf("node %q: tcp_reset service needs a port", n.Name)
			}
			if svc.Certificate != nil || svc.DNSFault != nil || len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.Status != 0 || svc.Body != "" || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: tcp_reset service has unsupported options", n.Name)
			}
		case ServiceSOCKS5:
			if svc.Port == 0 {
				svc.Port = defaultSOCKSProxyPort
			}
			if n.Resolver == "" {
				return fmt.Errorf("node %q: socks5 service needs the node resolver", n.Name)
			}
			if len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.Status != 0 || svc.Body != "" || svc.Certificate != nil || svc.DNSFault != nil || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: socks5 service has unsupported options", n.Name)
			}
		case ServiceHTTPConnect:
			if svc.Port == 0 {
				svc.Port = defaultCONNECTProxyPort
			}
			// The proxy resolves the CONNECT authority itself, so it needs a
			// resolver of its own exactly as the SOCKS fixture does.
			if n.Resolver == "" {
				return fmt.Errorf("node %q: http_connect service needs the node resolver", n.Name)
			}
			if len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.Status != 0 || svc.Body != "" || svc.Certificate != nil || svc.DNSFault != nil || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: http_connect service has unsupported options", n.Name)
			}
		case ServiceTLS, ServiceQUIC:
			if svc.Port == 0 {
				svc.Port = 443
			}
			if svc.Name == "" {
				return fmt.Errorf("node %q: %s service needs a name", n.Name, svc.Type)
			}
			if len(svc.Zone) != 0 || len(svc.Records) != 0 || svc.Status != 0 || svc.Body != "" || svc.DNSFault != nil || svc.DoHResponse != "" || svc.Portal {
				return fmt.Errorf("node %q: %s service has unsupported options", n.Name, svc.Type)
			}
			if err := validateTLSCertificate(svc.Certificate); err != nil {
				return fmt.Errorf("node %q: %s service certificate: %w", n.Name, svc.Type, err)
			}
		case ServiceEncryptedDNS:
			// The zone is the answer the probe correlates against, so this
			// service takes one exactly as the plaintext DNS service does.
			if svc.Port == 0 {
				svc.Port = 443
			}
			if svc.Name == "" {
				return fmt.Errorf("node %q: encrypted_dns service needs a name", n.Name)
			}
			if svc.Status != 0 || svc.Body != "" || svc.DNSFault != nil || svc.Portal {
				return fmt.Errorf("node %q: encrypted_dns service has unsupported options", n.Name)
			}
			if svc.DoHResponse != "" && svc.DoHResponse != DoHResponseInvalid {
				return fmt.Errorf("node %q: encrypted_dns service has unknown doh_response %q", n.Name, svc.DoHResponse)
			}
			if err := validateTLSCertificate(svc.Certificate); err != nil {
				return fmt.Errorf("node %q: encrypted_dns service certificate: %w", n.Name, err)
			}
		default:
			return fmt.Errorf("node %q: unknown service type %q", n.Name, svc.Type)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("node %q: port %d is out of range", n.Name, svc.Port)
		}
	}
	return nil
}

func (f *Fault) validate(topology *Topology, nodes map[string]bool) error {
	// A scheduled_dns fault names a service; the node that serves it is derived,
	// so a scenario cannot point one service's schedule at another node.
	if f.Type == FaultScheduledDNS {
		owner := topology.dnsServiceNode(f.Service)
		if owner == "" {
			return fmt.Errorf("unknown named dns service %q", f.Service)
		}
		if f.Node != "" && f.Node != owner {
			return fmt.Errorf("dns service %q is served by node %q, not %q", f.Service, owner, f.Node)
		}
		f.Node = owner
	}
	if !nodes[f.Node] {
		return fmt.Errorf("unknown node %q", f.Node)
	}
	node := topology.node(f.Node)
	if f.Type != FaultScheduledDNS && f.Service != "" {
		return fmt.Errorf("%s does not accept service", f.Type)
	}
	if len(f.Events) > 0 && f.Type != FaultScheduledNetem && f.Type != FaultScheduledDNS && f.Type != FaultScheduledLink {
		return fmt.Errorf("%s does not accept events", f.Type)
	}
	if f.MTU != 0 && f.Type != FaultPMTUBlackhole {
		return fmt.Errorf("%s does not accept mtu", f.Type)
	}
	if f.Family != "" && f.Family != "ipv4" && f.Family != "ipv6" {
		return fmt.Errorf("unknown family %q (ipv4 or ipv6)", f.Family)
	}
	switch f.Type {
	case FaultDrop:
		if f.Segment != "" || f.Via != "" || f.Metric != 0 {
			return errors.New("drop has unsupported route or segment options")
		}
		switch f.Direction {
		case DirectionOutbound, DirectionInbound:
		case "":
			f.Direction = DirectionOutbound
		default:
			return fmt.Errorf("unknown direction %q (%s or %s)", f.Direction, DirectionOutbound, DirectionInbound)
		}
		if f.To != "" {
			var err error
			var addr netip.Addr
			if addr, f.To, err = parseAddr(f.To); err != nil {
				return fmt.Errorf("to: %w", err)
			}
			if f.Family == "" {
				f.Family = addressFamily(addr)
			} else if addressFamily(addr) != f.Family {
				return fmt.Errorf("to address is %s but family is %s", addressFamily(addr), f.Family)
			}
		}
		switch f.Protocol {
		case "tcp", "udp":
		case "":
			if f.Port != 0 {
				return errors.New("port needs a protocol (tcp or udp)")
			}
		default:
			return fmt.Errorf("unknown protocol %q (tcp or udp)", f.Protocol)
		}
		if f.Port < 0 || f.Port > 65535 {
			return fmt.Errorf("port %d is out of range", f.Port)
		}
	case FaultNetem:
		if f.Via != "" || f.Metric != 0 || f.Family != "" {
			return errors.New("netem has unsupported route options")
		}
		if f.Segment == "" {
			if len(node.Interfaces) != 1 {
				return errors.New("netem on a multi-interface node requires segment")
			}
			f.Segment = node.Interfaces[0].Segment
		} else if _, ok := node.interfaceOn(f.Segment); !ok {
			return fmt.Errorf("node %q has no interface on segment %q", f.Node, f.Segment)
		}
		if f.Delay == "" && f.Jitter == "" && f.Loss == "" {
			return errors.New("netem needs delay, jitter or loss")
		}
		for label, v := range map[string]string{"delay": f.Delay, "jitter": f.Jitter} {
			if v == "" {
				continue
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
			if d < 0 {
				return fmt.Errorf("%s must not be negative", label)
			}
			if d > maxNetemDuration {
				return fmt.Errorf("%s must not exceed %s", label, maxNetemDuration)
			}
		}
		if f.Jitter != "" && f.Delay == "" {
			return errors.New("jitter needs a delay to vary")
		}
		if f.Loss != "" {
			normalized, ok := normalizePercent(f.Loss)
			if !ok {
				return fmt.Errorf("loss: %q is not a percentage such as \"10%%\"", f.Loss)
			}
			f.Loss = normalized
		}
	case FaultNoDefaultRoute:
		if f.Segment != "" || f.Via != "" || f.Metric != 0 {
			return errors.New("no_default_route has unsupported options")
		}
		if f.Family == "" {
			f.Family = "ipv4"
		}
	case FaultReplaceDefaultRoute:
		if f.Segment != "" {
			return errors.New("replace_default_route does not accept segment; it is derived from via")
		}
		if f.Metric < 0 || f.Metric > maxRouteMetric {
			return fmt.Errorf("metric %d is out of range", f.Metric)
		}
		via, canonical, err := parseAddr(f.Via)
		if err != nil {
			return fmt.Errorf("via: %w", err)
		}
		if _, ok := nodeSegmentForAddress(node, via); !ok {
			return fmt.Errorf("gateway %s is not on a directly connected subnet for node %q", via, f.Node)
		}
		if err := validateGateway(via); err != nil {
			return fmt.Errorf("via: %w", err)
		}
		if f.Family == "" {
			f.Family = addressFamily(via)
		} else if addressFamily(via) != f.Family {
			return fmt.Errorf("gateway is %s but family is %s", addressFamily(via), f.Family)
		}
		f.Via = canonical
	case FaultLinkDown:
		if f.Via != "" || f.Metric != 0 || f.Family != "" {
			return errors.New("link_down has unsupported options")
		}
		if _, ok := node.interfaceOn(f.Segment); !ok {
			return fmt.Errorf("node %q has no interface on segment %q", f.Node, f.Segment)
		}
	case FaultPMTUBlackhole:
		if f.Via != "" || f.Metric != 0 || f.Family != "" || f.To != "" || f.Protocol != "" ||
			f.Port != 0 || f.Direction != "" || f.Delay != "" || f.Jitter != "" || f.Loss != "" {
			return errors.New("pmtu_blackhole takes node, segment and mtu only")
		}
		// A black hole is a transit condition. On a node that does not forward,
		// a narrowed interface only makes the local kernel refuse oversized
		// sends, which is the opposite of the silence being modeled.
		if node.Role != "router" {
			return fmt.Errorf("node %q has role %q; a pmtu_blackhole hop must be a router", f.Node, node.Role)
		}
		iface, ok := node.interfaceOn(f.Segment)
		if !ok {
			return fmt.Errorf("node %q has no interface on segment %q", f.Node, f.Segment)
		}
		if f.MTU < minBlackholeMTU || f.MTU > maxBlackholeMTU {
			return fmt.Errorf("mtu %d is out of range (%d-%d)", f.MTU, minBlackholeMTU, maxBlackholeMTU)
		}
		if iface.IPv6 != "" && f.MTU < minIPv6MTU {
			return fmt.Errorf("mtu %d would disable IPv6 on segment %q; use at least %d", f.MTU, f.Segment, minIPv6MTU)
		}
	case FaultScheduledNetem, FaultScheduledLink:
		if f.Via != "" || f.Metric != 0 || f.Family != "" || f.Delay != "" || f.Jitter != "" || f.Loss != "" {
			return fmt.Errorf("%s takes node, segment and events only", f.Type)
		}
		if f.Segment == "" {
			if len(node.Interfaces) != 1 {
				return fmt.Errorf("%s on a multi-interface node requires segment", f.Type)
			}
			f.Segment = node.Interfaces[0].Segment
		} else if _, ok := node.interfaceOn(f.Segment); !ok {
			return fmt.Errorf("node %q has no interface on segment %q", f.Node, f.Segment)
		}
		check := validateNetemEvent
		if f.Type == FaultScheduledLink {
			check = validateLinkEvent
		}
		return f.validateEvents(check)
	case FaultScheduledDNS:
		if f.Segment != "" || f.Via != "" || f.Metric != 0 || f.Family != "" || f.Delay != "" || f.Jitter != "" || f.Loss != "" {
			return errors.New("scheduled_dns takes service and events only")
		}
		return f.validateEvents(validateDNSEvent)
	default:
		return fmt.Errorf("unknown fault type %q", f.Type)
	}
	return nil
}

// dnsServiceNode names the node serving a named DNS service, or "".
func (t *Topology) dnsServiceNode(service string) string {
	if service == "" {
		return ""
	}
	for i := range t.Nodes {
		for _, svc := range t.Nodes[i].Services {
			if svc.Type == ServiceDNS && svc.Name == service {
				return t.Nodes[i].Name
			}
		}
	}
	return ""
}

func (t *Topology) node(name string) *Node {
	for i := range t.Nodes {
		if t.Nodes[i].Name == name {
			return &t.Nodes[i]
		}
	}
	return nil
}

func (t *Test) validate(nodes map[string]*Node) error {
	if t.Type == "" {
		t.Type = TestNetdoc
	}
	if t.Type != TestNetdoc {
		return fmt.Errorf("unknown test type %q", t.Type)
	}
	if nodes[t.Node] == nil {
		return fmt.Errorf("unknown node %q", t.Node)
	}
	if t.SourceSegment != "" {
		if _, ok := nodes[t.Node].interfaceOn(t.SourceSegment); !ok {
			return fmt.Errorf("source_segment %q is not an interface on node %q", t.SourceSegment, t.Node)
		}
	}
	if t.Proxy != nil {
		if err := t.Proxy.validate(nodes); err != nil {
			return fmt.Errorf("proxy: %w", err)
		}
	}
	if t.Trust != nil {
		if err := t.Trust.validate(nodes); err != nil {
			return fmt.Errorf("trust: %w", err)
		}
	}
	if t.Name == "" {
		t.Name = t.Node + " " + t.Target
		if t.Target == "" {
			t.Name = t.Node + " (generic)"
		}
	}
	if t.Expect != nil {
		if err := t.Expect.validate(); err != nil {
			return fmt.Errorf("expect: %w", err)
		}
	}
	if t.Target == "" {
		return nil
	}
	// The same parser the CLI uses, so a scenario can never ask netdoc for a
	// target netdoc would reject.
	_, err := diagnostic.ParseTarget(t.Target)
	return err
}

func validateTLSCertificate(c *TLSCertificate) error {
	if c == nil {
		return errors.New("configuration is required")
	}
	switch c.Mode {
	case TLSCertificateValid, TLSCertificateExpired, TLSCertificateNotYetValid, TLSCertificateHostnameMismatch:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	if len(c.DNSNames) == 0 {
		return errors.New("dns_names must not be empty")
	}
	if len(c.DNSNames) > tlsMaxDNSNames {
		return fmt.Errorf("dns_names has %d entries, maximum is %d", len(c.DNSNames), tlsMaxDNSNames)
	}
	seen := make(map[string]bool, len(c.DNSNames))
	for i, name := range c.DNSNames {
		if netipAddr, err := netip.ParseAddr(name); err == nil && netipAddr.IsValid() {
			return fmt.Errorf("dns_names[%d] %q is an IP literal", i, name)
		}
		if !isSafeHostname(name) {
			return fmt.Errorf("dns_names[%d] %q is not a hostname", i, name)
		}
		key := dnsKey(name)
		if seen[key] {
			return fmt.Errorf("duplicate DNS name %q", name)
		}
		seen[key] = true
		c.DNSNames[i] = key
	}
	return nil
}

func validateDNSFault(f *DNSFault) error {
	if f == nil {
		return nil
	}
	if len(f.A)+len(f.AAAA) == 0 {
		return errors.New("at least one A or AAAA outcome is required")
	}
	if len(f.A)+len(f.AAAA) > dnsMaxScheduledOutcomes {
		return fmt.Errorf("has %d outcomes, maximum is %d", len(f.A)+len(f.AAAA), dnsMaxScheduledOutcomes)
	}
	for _, family := range []struct {
		name     string
		outcomes []string
		wrong    *string
		wantIPv4 bool
	}{{"a", f.A, &f.WrongA, true}, {"aaaa", f.AAAA, &f.WrongAAAA, false}} {
		usesWrong := false
		for i, outcome := range family.outcomes {
			switch outcome {
			case DNSOutcomeAnswer, DNSOutcomeSERVFAIL, DNSOutcomeREFUSED, DNSOutcomeTruncated:
			case DNSOutcomeWrongAnswer:
				usesWrong = true
			default:
				return fmt.Errorf("%s[%d]: unknown outcome %q (answer, servfail, refused, truncated or wrong_answer)", family.name, i, outcome)
			}
		}
		if !usesWrong && *family.wrong != "" {
			return fmt.Errorf("wrong_%s requires a wrong_answer outcome in %s", family.name, family.name)
		}
		if usesWrong && *family.wrong == "" {
			return fmt.Errorf("wrong_%s is required by the wrong_answer outcome in %s", family.name, family.name)
		}
		if *family.wrong == "" {
			continue
		}
		addr, canonical, err := parseAddr(*family.wrong)
		if err != nil {
			return fmt.Errorf("wrong_%s: %w", family.name, err)
		}
		if err := validateInterfaceAddr(addr); err != nil {
			return fmt.Errorf("wrong_%s: %w", family.name, err)
		}
		if addr.Is4() != family.wantIPv4 {
			return fmt.Errorf("wrong_%s has the wrong address family", family.name)
		}
		*family.wrong = canonical
	}
	return nil
}

func (c *CampaignSpec) validate(s *Scenario) error {
	if c.Runs == 0 {
		c.Runs = 10
	}
	if c.Runs < 1 || c.Runs > 1000 {
		return fmt.Errorf("runs must be between 1 and 1000")
	}
	if c.Netem == nil && c.DNS == nil && c.Timeline == nil && c.DNSDelay == nil {
		return errors.New("netem, dns, timeline or dns_delay variables are required")
	}
	if t := c.Timeline; t != nil {
		node := s.Topology.node(t.Node)
		if node == nil {
			return fmt.Errorf("timeline: unknown node %q", t.Node)
		}
		if _, ok := node.interfaceOn(t.Segment); !ok {
			return fmt.Errorf("timeline: node %q has no interface on segment %q", t.Node, t.Segment)
		}
		if t.Service != "" && s.Topology.dnsServiceNode(t.Service) == "" {
			return fmt.Errorf("timeline: unknown named dns service %q", t.Service)
		}
		if t.Service != "" {
			hold, err := time.ParseDuration(t.ResolverHold)
			if err != nil {
				return fmt.Errorf("timeline.resolver_hold: %w", err)
			}
			if hold <= 0 || hold > maxDNSResponseDelay {
				return fmt.Errorf("timeline.resolver_hold must satisfy 0 < hold <= %s", maxDNSResponseDelay)
			}
		}
		if _, err := time.ParseDuration(t.Latency); err != nil {
			return fmt.Errorf("timeline.latency: %w", err)
		}
		if err := t.DegradeAt.validate("timeline.degrade_at", maxScheduledOffset); err != nil {
			return err
		}
		if err := t.OutageFor.validate("timeline.outage_for", maxScheduledOffset); err != nil {
			return err
		}
		if err := t.DegradeLoss.validate("timeline.degrade_loss_percent", 0, 100); err != nil {
			return err
		}
		// The generated shape must fit inside the bound no matter which end of
		// each range an iteration lands on.
		start, _ := time.ParseDuration(t.DegradeAt.Min)
		if start <= 0 {
			return errors.New("timeline.degrade_at.min must be positive")
		}
		last, _ := time.ParseDuration(t.DegradeAt.Max)
		longest, _ := time.ParseDuration(t.OutageFor.Max)
		if last+campaignDegradedFor+campaignHealthyGap+longest > maxScheduledOffset {
			return fmt.Errorf("timeline: the longest generated timeline exceeds %s", maxScheduledOffset)
		}
	}
	if d := c.DNSDelay; d != nil {
		if s.Topology.dnsServiceNode(d.Service) == "" {
			return fmt.Errorf("dns_delay: unknown named dns service %q", d.Service)
		}
		if err := d.Delay.validate("dns_delay.delay", maxDNSResponseDelay); err != nil {
			return err
		}
		if min, _ := time.ParseDuration(d.Delay.Min); min <= 0 {
			return errors.New("dns_delay.delay.min must be positive")
		}
	}
	if c.Netem != nil {
		node := s.Topology.node(c.Netem.Node)
		if node == nil {
			return fmt.Errorf("netem: unknown node %q", c.Netem.Node)
		}
		if _, ok := node.interfaceOn(c.Netem.Segment); !ok {
			return fmt.Errorf("netem: node %q has no interface on segment %q", c.Netem.Node, c.Netem.Segment)
		}
		if err := c.Netem.Latency.validate("latency", maxNetemDuration); err != nil {
			return err
		}
		if err := c.Netem.Jitter.validate("jitter", maxNetemDuration); err != nil {
			return err
		}
		if err := c.Netem.LossPercent.validate("loss_percent", 0, 100); err != nil {
			return err
		}
	}
	if c.DNS != nil {
		if c.DNS.QueriesPerType < 1 || c.DNS.QueriesPerType > dnsMaxScheduledOutcomes/2 {
			return fmt.Errorf("dns.queries_per_type must be between 1 and %d", dnsMaxScheduledOutcomes/2)
		}
		found := false
		for _, node := range s.Topology.Nodes {
			for _, svc := range node.Services {
				if svc.Name == c.DNS.Service && svc.Type == ServiceDNS {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("dns: unknown named DNS service %q", c.DNS.Service)
		}
		if err := c.DNS.FailurePercent.validate("dns.failure_percent", 0, 100); err != nil {
			return err
		}
	}
	return nil
}

func (r DurationRange) validate(label string, max time.Duration) error {
	min, err := time.ParseDuration(r.Min)
	if err != nil {
		return fmt.Errorf("%s.min: %w", label, err)
	}
	maximum, err := time.ParseDuration(r.Max)
	if err != nil {
		return fmt.Errorf("%s.max: %w", label, err)
	}
	if min < 0 || maximum < min || maximum > max {
		return fmt.Errorf("%s must satisfy 0 <= min <= max <= %s", label, max)
	}
	return nil
}

func (r NumberRange) validate(label string, min, max float64) error {
	if math.IsNaN(r.Min) || math.IsNaN(r.Max) || math.IsInf(r.Min, 0) || math.IsInf(r.Max, 0) ||
		r.Min < min || r.Max < r.Min || r.Max > max {
		return fmt.Errorf("%s must satisfy %g <= min <= max <= %g", label, min, max)
	}
	return nil
}

func (t *TestTrust) validate(nodes map[string]*Node) error {
	if t.Service == "" {
		return errors.New("service is required")
	}
	for _, node := range nodes {
		for _, svc := range node.Services {
			if svc.Name == t.Service && svc.Type == ServiceTLS {
				return nil
			}
		}
	}
	return fmt.Errorf("unknown tls service %q", t.Service)
}

func (p *TestProxy) validate(nodes map[string]*Node) error {
	var service string
	var defaultPort int
	switch p.Scheme {
	case "socks5", "socks5h":
		service, defaultPort = ServiceSOCKS5, defaultSOCKSProxyPort
	case "http":
		service, defaultPort = ServiceHTTPConnect, defaultCONNECTProxyPort
	default:
		return fmt.Errorf("unsupported scheme %q (socks5, socks5h or http)", p.Scheme)
	}
	n := nodes[p.Node]
	if n == nil {
		return fmt.Errorf("unknown node %q", p.Node)
	}
	if p.Port == 0 {
		p.Port = defaultPort
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("port %d is out of range", p.Port)
	}
	for _, svc := range n.Services {
		if svc.Type == service && svc.Port == p.Port {
			p.address = n.Address
			return nil
		}
	}
	return fmt.Errorf("node %q has no %s service on port %d", p.Node, service, p.Port)
}

// envName is the environment variable the runner hands this proxy to netdoc
// through. A SOCKS proxy arrives as ALL_PROXY, which is where the SOCKS
// ecosystem puts it and the only variable net/http itself ignores. An HTTP
// CONNECT proxy arrives as HTTPS_PROXY, which is what a proxy-only network sets
// for tunneled TLS and the scheme netdoc's proxy row asks about first.
func (p *TestProxy) envName() string {
	if p.Scheme == "http" {
		return "HTTPS_PROXY"
	}
	return "ALL_PROXY"
}

func (e *Expect) validate() error {
	if e.Verdict != "" && !slices.Contains(verdicts, e.Verdict) {
		return fmt.Errorf("expect.verdict: unknown verdict %q (one of %s)", e.Verdict, strings.Join(verdicts, ", "))
	}
	seen := make(map[string]bool, len(e.Checks))
	for i, c := range e.Checks {
		if c.ID == "" {
			return fmt.Errorf("expect.checks[%d].id is required", i)
		}
		known := false
		for _, id := range knownProbeIDs {
			if string(id) == c.ID {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("expect.checks[%d]: unknown probe id %q", i, c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("expect.checks: duplicate probe id %q", c.ID)
		}
		seen[c.ID] = true
		if !slices.Contains(statuses, c.Status) {
			return fmt.Errorf("expect.checks[%d]: unknown status %q (one of %s)", i, c.Status, strings.Join(statuses, ", "))
		}
		if c.Cause != "" {
			if c.Status != "FAIL" && c.Status != "WARN" {
				return fmt.Errorf("expect.checks[%d]: cause requires FAIL or WARN status", i)
			}
			if !slices.Contains(knownCauses, c.Cause) {
				return fmt.Errorf("expect.checks[%d]: unknown cause %q", i, c.Cause)
			}
		}
		for family, value := range map[string]string{"ipv4": c.IPv4, "ipv6": c.IPv6} {
			if value != "" && value != diagnostic.FamilyReachable && value != diagnostic.FamilyUnreachable {
				return fmt.Errorf("expect.checks[%d].%s: unknown family status %q", i, family, value)
			}
		}
	}
	if e.Verdict == "" && e.Summary == "" && len(e.Checks) == 0 {
		return errors.New("expect: a scenario must expect a verdict, summary, some checks, or a combination")
	}
	return nil
}

// Client returns the node netdoc runs in. Validate guarantees there is one.
func (s *Scenario) Client() *Node {
	for i := range s.Topology.Nodes {
		if s.Topology.Nodes[i].Role == "client" {
			return &s.Topology.Nodes[i]
		}
	}
	return nil
}

// isSafeName gates every string that reaches an argv as a namespace or
// interface name. Conservative on purpose: these end up in command arguments.
func isSafeName(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, r := range s {
		alnum := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
		if !alnum && (r != '-' || i == 0) {
			return false
		}
	}
	return true
}

// isSafeHostname gates zone names, which are compared against queries and
// written into DNS answers.
func isSafeHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlnum(label[0]) || !isASCIIAlnum(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isASCIIAlnum(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// normalizePercent accepts the percentage spelling tc accepts, decimal digits
// with an optional fraction, and returns the canonical rendering of it.
//
// strconv.ParseFloat on its own is too generous here. "1e2%", "+5%" and
// "0x1p6%" are all valid Go floats inside the range, and all three are rejected
// by tc after the whole topology has been built. Validation runs before any
// namespace exists precisely so that an accepted scenario is one the simulator
// can execute, so the syntax it accepts has to be the syntax tc parses.
func normalizePercent(s string) (string, bool) {
	num, ok := strings.CutSuffix(s, "%")
	if !ok || num == "" {
		return "", false
	}
	for i := 0; i < len(num); i++ {
		if c := num[i]; (c < '0' || c > '9') && c != '.' {
			return "", false
		}
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || v < 0 || v > 100 {
		return "", false
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + "%", true
}
