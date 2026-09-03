// Package diagnostic implements target parsing, native network probes, and
// diagnosis without depending on terminal presentation.
package diagnostic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Status is a probe's five-state outcome. Warn = degraded but functional
// (high latency, some addresses failing, ambiguous source interface, missing
// service banner, or direct egress blocked while another path works), never
// counted as a failure. Skip = a prerequisite failed (an
// independent probe is never Skipped for an unrelated sibling's failure).
// NotApplicable = the probe doesn't apply at all (DNS on an IP literal, a
// protocol row absent for this port), not counted as a failure.
type Status int

const (
	StatusPass Status = iota
	StatusWarn
	StatusFail
	StatusSkip
	StatusNA
)

var statusNames = [...]string{"PASS", "WARN", "FAIL", "SKIP", "N/A"}

// Route failure causes are attached to the existing direct-egress row. They
// describe only evidence the local kernel exposes; none claims an alternate
// path works without a successful probe proving that separately.
const (
	RouteCauseNoDefaultRoute      = "no_default_route"
	RouteCauseGatewayUnreachable  = "gateway_unreachable"
	RouteCauseSelectedPathFailed  = "selected_path_failed"
	RouteCausePreferredPathFailed = "preferred_route_failed"
	FamilyCauseIPv4Unreachable    = "ipv4_unreachable"
	FamilyCauseIPv6Unreachable    = "ipv6_unreachable"
	DNSCauseTimeout               = "dns_timeout"
	DNSCauseTemporaryFailure      = "dns_temporary_failure"
	ConnectionCauseRefused        = "connection_refused"
	ConnectionCauseReset          = "connection_reset"
	ConnectionCauseTimeout        = "timeout"
	ConnectionCauseUnreachable    = "unreachable"
	ConnectionCauseCanceled       = "canceled"
)

const (
	FamilyReachable   = "reachable"
	FamilyUnreachable = "unreachable"
)

// FamilyConnectivity records independently tested reachability for each
// address family. An empty value means that family was not tested.
type FamilyConnectivity struct {
	IPv4 string
	IPv6 string
}

func (s Status) String() string {
	if s < 0 || s >= Status(len(statusNames)) {
		return "?"
	}
	return statusNames[s]
}

// Attempt is one connection attempt against a single address.
type Attempt struct {
	IP      net.IP
	Dur     time.Duration
	Err     error
	Cause   string
	Aborted bool // cancellation or the enclosing probe deadline, not this address
}

// Ms renders a duration that actually elapsed as at least 1ms. Milliseconds()
// truncates, so a fast local check (an interface lookup, a cached resolve) or a
// LAN connect would report the same 0 as work that never happened at all, and
// 0 is the only signal a reader has for the latter.
func Ms(d time.Duration) int64 {
	if d > 0 && d < time.Millisecond {
		return 1
	}
	return d.Milliseconds()
}

// since is time.Since with a nonzero floor. Windows' clock granularity is
// coarse enough to report 0 for a fast connect, which Ms would then render as
// the 0ms that means "never ran". A tick that coarse can't tell us anything
// finer than "under a millisecond", and Ms already says that as 1ms.
func since(start time.Time) time.Duration {
	if d := time.Since(start); d > 0 {
		return d
	}
	return time.Nanosecond
}

// ProbeID is a stable DAG node id.
type ProbeID string

const (
	ProbeIface     ProbeID = "iface"
	ProbeSSID      ProbeID = "ssid"
	ProbeInternet  ProbeID = "internet_tcp"
	ProbeQUIC      ProbeID = "quic_udp_443"
	ProbeProxy     ProbeID = "proxy_connect"
	ProbeDNS       ProbeID = "dns"
	ProbeDNSPublic ProbeID = "dns_public"
	// ProbeDNSEncrypted is an independent branch off the interface, not a child
	// of the plaintext rows: plain and encrypted DNS are separate capabilities,
	// and either can work while the other is blocked.
	ProbeDNSEncrypted ProbeID = "dns_encrypted"
	ProbeTargetTCP    ProbeID = "target_tcp"
	ProbePMTU         ProbeID = "path_mtu"
	ProbeTLS          ProbeID = "tls"
	ProbeHTTP         ProbeID = "http"
	ProbeHTTPS        ProbeID = "https"
	ProbeSSH          ProbeID = "ssh_banner"
	ProbeSMTP         ProbeID = "smtp_banner"
)

// QUIC failure causes distinguish a silent UDP/443 path from endpoint or
// protocol failures without claiming that a firewall was proven responsible.
const (
	QUICCauseTimeout   = "timeout"
	QUICCauseHandshake = "quic_handshake_failure"
)

// answerComparison is the outcome of one DNS answer-set comparison. The zero
// value is deliberately "not recorded" rather than either result, so a run
// that compared nothing can never be read as one whose answers agreed.
type answerComparison uint8

const (
	comparisonUnrecorded answerComparison = iota
	comparisonAgree
	comparisonDisagree
)

// ProbeResult is the typed contract the diagnosis engine and renderer consume.
// Detail/Fix are derived human text, never parsed back.
type ProbeResult struct {
	ID     ProbeID
	Status Status
	// Cause is an optional stable machine-readable reason for failures where a
	// single probe has materially different remediation paths.
	Cause       string
	causeFamily string // address family that supplied Cause; empty when shared or family-neutral
	Families    *FamilyConnectivity
	downgraded  bool // downgradeEgress rewrote a direct-egress failure to Warn.
	// answerComparison is what reconcileDNS concluded when it compared this
	// row's answers with the system resolver's. Unrecorded when there was
	// nothing to compare, which is never the same as agreement. Private, and
	// restored from the snapshot on replay, because it is derived state rather
	// than anything a probe measured.
	answerComparison answerComparison
	Portal           *Portal  // non-nil when egress is intercepted, not dead.
	Addrs            []net.IP // DNS publishes all A records here
	DNSNotFound      bool     // the resolver found no A/AAAA records
	// ResolverTargets are DNS service addresses recorded as passed to the Go
	// resolver's Dial hook. They prove where a lookup was attempted, not which
	// target answered or supplied any returned address.
	ResolverTargets []string
	SelectedIP      net.IP // winning/pinned IP used by this probe
	Source          net.IP
	Iface           string
	Network         string // connected Wi-Fi SSID, empty when wired/unknown
	// Routes are the operating system's own route decisions for the
	// destinations this row is about: the reference Internet endpoints on the
	// interface row, each resolver target recorded on the DNS row, and every
	// resolved address on the target row. Empty where the platform cannot
	// answer, which is never the same as "there is no route".
	Routes   []RouteDecision
	Attempts []Attempt
	Dur      time.Duration // wall time the probe took; zero for probes that never ran
	Detail   string
	Fix      string
	// timedOut marks an HTTP/HTTPS failure that was a timeout, which is half
	// the PMTU black-hole correlation. TLS reports the same fact through
	// Cause, so it has no flag of its own.
	timedOut bool
	// clockOffset is this machine's clock minus the Date of a connectivity
	// endpoint's documented clean response: positive when the local clock runs
	// fast. Zero means there was no usable reading, which behaves the same as a
	// correct clock because both leave nothing to say.
	clockOffset time.Duration
	// resolver is the second-opinion DNS server ProbeDNSPublic queried, so the
	// cross-probe pass can name it in prose without reaching for a constant.
	resolver string
	// ifaceAmbiguous records that the source address resolved to more than one
	// interface. Iface carries display text for that case, so this flag is what
	// the warning path reads: an interface whose real name happens to match
	// that text is not ambiguous.
	ifaceAmbiguous bool
}

// Portal is structured captive-portal evidence. RedirectURL is empty when the
// interception did not advertise a valid HTTP(S) sign-in URL.
type Portal struct {
	RedirectURL string
}

// Probe is one DAG node. Run receives an immutable snapshot of just its
// dependency outputs and must honor ctx and never panic.
type Probe struct {
	ID   ProbeID
	Name string
	Deps []ProbeID
	Run  func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult
	// Reference marks a node whose traffic goes to Network Doctor's own
	// built-in reference infrastructure rather than to anything the user or
	// this machine's configuration named. reference_policy.go decides it, for
	// the shape of the run the graph was built for, and ProbeSelection drops
	// the marked nodes when the run asked for no reference egress.
	Reference bool
}

// DefaultProbeTimeout bounds a single probe when the caller names no other
// value. The runners take the effective timeout as an argument (RunAll) or a
// field (the TUI model), so two diagnoses in one process keep separate budgets;
// this is only the default the -timeout flag starts from, and the fallback for
// the rare probe handed a context with no deadline at all.
const DefaultProbeTimeout = 4 * time.Second

const (
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

// Proxy failure causes. Detail and Fix remain the user-facing explanation;
// these values let reports and simulators distinguish the failing stage
// without parsing prose.
const (
	ProxyCauseUnreachable            = "proxy_unreachable"
	ProxyCauseClientDNS              = "client_dns_failure"
	ProxyCauseProxyDNS               = "proxy_side_dns_failure"
	ProxyCauseDestinationUnreachable = "destination_unreachable_from_proxy"
	ProxyCauseProtocol               = "proxy_protocol_failure"
)

// TLS failure causes preserve the existing TLS row while making its distinct
// remediation paths available to JSON consumers without parsing Go errors.
const (
	TLSCauseCertificateExpired = "certificate_expired"
	TLSCauseCertificateNotYet  = "certificate_not_yet_valid"
	TLSCauseHostnameMismatch   = "hostname_mismatch"
	TLSCauseUntrustedIssuer    = "untrusted_issuer"
	TLSCauseHandshake          = "tls_handshake_failure"
	TLSCauseTCPUnreachable     = "tcp_unreachable"
	TLSCauseTimeout            = "timeout"
	TLSCauseConnectionClosed   = "connection_closed"
)

// Path-MTU probe sizes. See pmtuProbe for what the asymmetry between them
// proves.
const (
	// pmtuSendBuffer is the SO_SNDBUF the probe asks for. Small on purpose:
	// with the kernel's autotuned buffer a Write returns hundreds of KiB before
	// any acknowledgement is due, and an unacknowledged Write proves nothing.
	pmtuSendBuffer = 4 << 10
	// pmtuPayloadSize is pushed at the target in a single Write. Enough to
	// require multiple ordinary TCP segments, small enough to stay a polite
	// amount of traffic.
	pmtuPayloadSize = 24 << 10
	// pmtuWriteWait bounds the stall the probe is willing to sit through.
	pmtuWriteWait = 2 * time.Second
	// pmtuHeadroom keeps the write deadline inside the probe budget, so a stall
	// is reported as evidence instead of as a cancelled probe.
	pmtuHeadroom = 250 * time.Millisecond
)

// tlsRecordHeader frames a handshake record declaring a full 16 KiB body, and
// prefixes the PMTU payload on TLS targets. An OpenSSL-based server buffers,
// and so acknowledges, the whole declared record before rejecting the garbage
// inside it, where an unprefixed write gets reset after a few bytes and leaves
// the path question unanswered.
var tlsRecordHeader = []byte{0x16, 0x03, 0x01, 0x40, 0x00}

// ConnectivityProbeHost is the host used by the generic (no-target) DNS and
// connectivity probes.
const ConnectivityProbeHost = "connectivitycheck.gstatic.com"

// quicProbePort is separate from the target port: this Internet-health probe
// always asks the fixed connectivity endpoint whether QUIC works on UDP/443.
const quicProbePort = 443

// DefaultPublicDNS is the second-opinion resolver used unless --public-dns
// names another. Every label and detail string derives from the configured
// value, and an empty one drops the probe entirely, so a network with a strict
// egress policy never dials it.
const DefaultPublicDNS = "8.8.8.8"

// autoPublicDNSFallback is the resolver tried after DefaultPublicDNS when the
// run named none, so a host with only IPv6 still gets a second opinion instead
// of losing the row to an IPv4 dial it cannot make. It is Google Public DNS,
// the operator the default already names, so the second opinion still comes
// from one place.
//
// Spelled out rather than taken from the direct-egress endpoints below, which
// happen to be the same address. Those are a reference sample of the Internet
// and this is a resolver to ask a question of: moving one has never been a
// reason to move the other.
const autoPublicDNSFallback = "2001:4860:4860::8888"

// PublicDNSCandidates is the resolver list one run queries, in attempt order.
// An empty publicDNS switches the row off and asks nothing at all. Otherwise
// that address is asked first, and auto adds the other family behind it when
// it is not already the address in hand.
//
// auto means the run named no resolver, so the choice is still open and may
// follow whichever family this machine can reach. A user who named an address
// gets that address and nothing else: "--public-dns 8.8.8.8" is a choice, not
// a preference, and it must not quietly acquire a second resolver just because
// the default happens to be spelled the same way.
func PublicDNSCandidates(publicDNS string, auto bool) []string {
	switch {
	case publicDNS == "":
		return nil
	case auto && publicDNS != autoPublicDNSFallback:
		return []string{publicDNS, autoPublicDNSFallback}
	default:
		return []string{publicDNS}
	}
}

// publicDNSRowName labels the second-opinion row. An automatic run names no
// resolver there, because which one answered is not decided until the probe has
// run, and the finished row says so itself.
func publicDNSRowName(publicDNS string, auto bool) string {
	if auto {
		return "DNS (public)"
	}
	return "DNS (public " + publicDNS + ")"
}

// publicDNSServer is the dial address for a second-opinion resolver IP; it
// brackets IPv6 literals.
func publicDNSServer(ip string) string { return net.JoinHostPort(ip, "53") }

// ncsiProbeHost is the second connectivity endpoint, operated by someone else
// entirely. One provider is not enough to establish interception: a block, an
// outage, a hijacked DNS answer, or any other treatment aimed at that one name
// looks identical to a portal from here, and none of them is a portal.
const ncsiProbeHost = "www.msftconnecttest.com"

// ncsiCleanBody is what ncsiProbeHost serves on an unintercepted path. The real
// payload ends in CRLF; this prefix is all that is read, so an interceptor's
// page is never searched for it.
const ncsiCleanBody = "Microsoft Connect Test"

// portalEndpoint is one plain-HTTP connectivity observation point. want and
// body spell out the clean response that endpoint documents; anything else is
// an unexpected answer, which on its own is a fact about that endpoint.
type portalEndpoint struct {
	url  string
	want int
	// body is what a clean response begins with, empty where a clean response
	// carries none. That is the 204's whole contract, and checking a 200 for
	// its documented payload is what keeps a filter's "OK" page off the clean
	// side of the ledger.
	body string
}

// portalEndpoints are the two fixed observations, in the order that breaks
// ties. Plain HTTP on purpose, since that's the request a captive portal grabs.
// Google stays first, so a pass with both endpoints clean reads the same remote
// clock netdoc has always read. A var only so tests can point them at a local
// server; nothing else reassigns it.
var portalEndpoints = []portalEndpoint{
	{url: "http://" + ConnectivityProbeHost + "/generate_204", want: http.StatusNoContent},
	{url: "http://" + ncsiProbeHost + "/connecttest.txt", want: http.StatusOK, body: ncsiCleanBody},
}

// internetEndpoints4/6 are the ordered direct-egress endpoints per address
// family; first connect wins within a family. Honestly "direct TCP egress":
// proxy-only networks can fail this.
//
// They are a fixed reference sample and not the internet. Two operators and
// two families is enough to make an unlucky single outage unlikely, and it is
// still a handful of addresses that a filter, a policy route, or their own bad
// day can take out while everything else this machine dials keeps working.
// What this row observes is therefore a fact about these destinations;
// diagnosis.go is where that is weighed against the rest of a run, and adding
// more addresses here would not change the shape of the claim.
const (
	internetEndpointCloudflareIPv4 = "1.1.1.1"
	internetEndpointGoogleIPv4     = "8.8.8.8"
	internetEndpointCloudflareIPv6 = "2606:4700:4700::1111"
	internetEndpointGoogleIPv6     = "2001:4860:4860::8888"
)

var (
	internetEndpoints4 = []net.IP{net.ParseIP(internetEndpointCloudflareIPv4), net.ParseIP(internetEndpointGoogleIPv4)}
	internetEndpoints6 = []net.IP{net.ParseIP(internetEndpointCloudflareIPv6), net.ParseIP(internetEndpointGoogleIPv6)}
)

// InternetProbeEndpoints returns the ordered direct-egress reference endpoints
// for IPv4 and IPv6. The slices and every IP in them are defensive copies.
func InternetProbeEndpoints() (ipv4, ipv6 []net.IP) {
	return cloneIPs(internetEndpoints4), cloneIPs(internetEndpoints6)
}

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

// netops holds every network/OS touchpoint the probes use, as function fields
// so tests can stub them and run probes deterministically without real
// network access. Production code always goes through defaultOps.
type netops struct {
	interfaces     func() ([]net.Interface, error)
	interfaceAddrs func(*net.Interface) ([]net.Addr, error)
	sources        *SourceAddresses
	// lookupIP resolves host and reports every resolver target its Dial hook
	// saw. An empty list means no DNS connection was attempted.
	lookupIP func(ctx context.Context, host string) ([]net.IP, []string, error)
	// lookupPublicIP resolves host against server (a host:port second-opinion
	// resolver), bypassing whatever the system is configured to use.
	lookupPublicIP func(ctx context.Context, host, server string) ([]net.IP, []string, error)
	dialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
	quicHandshake  func(context.Context, net.Conn, *tls.Config) (quicState, error)
	sendBuffer     func(net.Conn) (int, error)
	// queued reports the bytes a socket has written but not had acknowledged.
	// It fails on platforms with no such query, and on anything that is not a
	// real socket, which is how the PMTU probe picks its inference.
	queued       func(net.Conn) (int, error)
	tcpMSS       func(net.Conn) (int, error)
	dialTLS      func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error)
	tlsRootCAs   *x509.CertPool
	ssid         func(ctx context.Context, iface string) string
	proxyFromEnv func(*http.Request) (*url.URL, error)
	// portalCheck performs one connectivity observation against one fixed
	// endpoint. An error is an endpoint that did not answer, which is the
	// absence of an observation rather than an observation of trouble.
	// Nil means "don't ask", which is how tests opt out of the HTTP round trips.
	portalCheck func(ctx context.Context, ep portalEndpoint) (portalObservation, error)
	// routeCause classifies a failed direct path from OS route/neighbor state.
	// Nil keeps deterministic probe unit tests independent of the host.
	routeCause func(net.IP) string
	// routeFor asks the operating system which route one destination takes,
	// from the local source address this pass's probes dial with, or from nil
	// where the run binds nothing. Nil, or a false second return, means this
	// platform cannot answer, and every consumer then reports nothing rather
	// than a guessed path. A platform whose route API takes no source ignores
	// the argument rather than pretending the constraint was applied.
	routeFor func(dst, source net.IP) (RouteDecision, bool)
	// defaultRoutes lists this family's usable default routes, which is what
	// lets a decision name the competitor it beat. Nil on a platform that
	// exposes no comparable preference.
	defaultRoutes func(family string) []defaultRouteState
	// routes memoizes routeFor for one pass. BuildProbesFromSources installs a
	// fresh one per pass, so Watch Mode never serves a stale path.
	routes *routeCache
}

// SourceAddresses are the usable IPv4 and IPv6 addresses selected by
// --iface. An exact-IP selection sets only its own family.
type SourceAddresses struct {
	IPv4 net.IP
	IPv6 net.IP
	// Iface is the selected interface name. It is empty when --iface was
	// omitted or given an exact local IP; probes bind by the addresses above,
	// while drill-down tools may bind by this name.
	Iface string
}

var defaultOps = &netops{
	interfaces:     net.Interfaces,
	interfaceAddrs: (*net.Interface).Addrs,
	lookupIP: func(ctx context.Context, host string) ([]net.IP, []string, error) {
		return lookupIPWithDial(ctx, host, new(net.Dialer).DialContext)
	},
	lookupPublicIP: func(ctx context.Context, host, server string) ([]net.IP, []string, error) {
		return lookupIPPublicWithDial(ctx, host, new(net.Dialer).DialContext, server)
	},
	dialContext:   new(net.Dialer).DialContext,
	quicHandshake: handshakeQUIC,
	sendBuffer:    socketSendBuffer,
	queued:        socketQueued,
	tcpMSS:        socketMSS,
	dialTLS: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		d := tls.Dialer{NetDialer: new(net.Dialer), Config: cfg}
		return d.DialContext(ctx, network, addr)
	},
	ssid:         ssid,
	proxyFromEnv: proxyFromEnvironment,
	portalCheck: func(ctx context.Context, ep portalEndpoint) (portalObservation, error) {
		return portalCheckWithDial(ctx, ep, new(net.Dialer).DialContext)
	},
	routeCause:    routeFailureCause,
	routeFor:      lookupRouteDecision,
	defaultRoutes: defaultRoutesFor,
}

// dialFamily performs one source-bound dial. It is a variable so tests can
// order per-family results without a live network.
var dialFamily = func(ctx context.Context, source net.IP, network, addr string, resolverDial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	return dialerFromSource(source, network, resolverDial).DialContext(ctx, network, addr)
}

// errFamilyLost stands in for a connection discarded because the other address
// family answered first. It never reaches a caller: the winning family's
// connection is in the same channel and ends the fan-in loop.
var errFamilyLost = errors.New("connection superseded by the other address family")

// BuildProbesFromSources constructs the DAG with separate selected-interface
// addresses for IPv4 and IPv6. publicDNS is a bare IP, or "" to leave the
// second-opinion probe out of the DAG altogether, since a skipped row would
// still have had to dial to be skipped. publicDNSAuto says nobody named that
// resolver, which is what lets the row cross to the other address family.
//
// The candidates are worked out here rather than at the flag, so they are
// worked out by the machine that runs the probes: --via builds this graph on
// the far end, and an IPv6-only remote must not be pinned to the caller's
// address family.
func BuildProbesFromSources(t *Target, sources *SourceAddresses, publicDNS string, publicDNSAuto bool) []Probe {
	// A copy either way, so the per-pass route cache installed below belongs
	// to this pass rather than to the package-level ops every pass shares.
	o := opsFromSources(sources)
	// One cache per pass. Route intelligence is asked the same question by
	// several probes, and a pass must not pay for the same kernel lookup more
	// than once; a later pass must not be answered from an earlier one, since
	// the whole point of Watch Mode is to see the route change.
	o.routes = newRouteCache(o.routeFor, o.sources)
	probes := o.buildProbes(t, publicDNS, publicDNSAuto)
	for i := range probes {
		probes[i].Run = wrapRun(probes[i].Run)
	}
	return probes
}

// wrapRun times and sanitizes one probe's Run.
func wrapRun(run func(context.Context, map[ProbeID]ProbeResult) ProbeResult) func(context.Context, map[ProbeID]ProbeResult) ProbeResult {
	return func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		start := time.Now()
		r := cleanResult(run(ctx, deps))
		r.Dur = since(start)
		return r
	}
}

// cleanResult scrubs the human-readable fields of a probe result. Names and
// IPs are not here: probe names are ours, and net.IP renders itself.
func cleanResult(r ProbeResult) ProbeResult {
	r.Detail, r.Fix = textsafe.Clean(r.Detail), textsafe.Clean(r.Fix)
	r.Iface, r.Network = textsafe.Clean(r.Iface), textsafe.Clean(r.Network)
	if r.Portal != nil {
		portal := *r.Portal
		portal.RedirectURL = textsafe.Clean(portal.RedirectURL)
		r.Portal = &portal
	}
	for i, a := range r.Attempts {
		if a.Err != nil {
			// Replaced, not wrapped: nothing downstream unwraps an attempt
			// error, it only ever gets printed.
			r.Attempts[i].Err = errors.New(textsafe.Clean(a.Err.Error()))
		}
	}
	return r
}

// buildProbes assembles the DAG and marks which of its nodes are built-in
// reference egress. The mark is applied here, over the finished graph, so
// there is one place a new probe has to pass through to acquire it, and so it
// is decided against the shape of the run the graph was actually built for.
func (o *netops) buildProbes(t *Target, publicDNS string, publicDNSAuto bool) []Probe {
	probes := o.buildProbeGraph(t, publicDNS, publicDNSAuto)
	for i := range probes {
		probes[i].Reference = referenceEgress(probes[i].ID, t != nil, !publicDNSAuto)
	}
	return probes
}

// buildProbeGraph assembles the DAG. publicDNS is the second-opinion resolver;
// "" leaves the row out entirely rather than emitting a skipped one, and
// publicDNSAuto lets an unnamed one cross to the other address family.
func (o *netops) buildProbeGraph(t *Target, publicDNS string, publicDNSAuto bool) []Probe {
	publicDNSResolvers := PublicDNSCandidates(publicDNS, publicDNSAuto)
	// The interface row carries the run's reference paths: where traffic to
	// the general Internet goes, per family. Every other route decision in the
	// run is explained against these, so they belong on the row that is about
	// the machine's own links rather than on any one destination's row.
	iface := Probe{ID: ProbeIface, Name: "Interface", Run: func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
		r := o.ifaceProbe(ctx, deps)
		r.Routes = o.referenceRouteDecisions()
		return r
	}}
	network := Probe{ID: ProbeSSID, Name: "Wi-Fi network", Deps: []ProbeID{ProbeIface}, Run: o.ssidProbe}
	internet := Probe{ID: ProbeInternet, Name: "Internet (TCP egress)", Deps: []ProbeID{ProbeIface}, Run: o.internetProbe}
	quicProbe := Probe{ID: ProbeQUIC, Name: "QUIC / UDP 443", Deps: []ProbeID{ProbeIface}, Run: o.quicProbe(ConnectivityProbeHost, quicProbePort)}
	// Direct and proxied egress are reported separately: the native probes
	// deliberately bypass proxies, so on a proxy-only network the direct row
	// fails while this row proves the environment proxy carries traffic.
	proxy := Probe{ID: ProbeProxy, Name: "Internet (env proxy)", Deps: []ProbeID{ProbeIface}, Run: o.proxyProbe}
	// Encrypted DNS is its own branch off the interface, beside the plaintext
	// rows rather than under them: a network can carry ordinary DNS while
	// blocking DoH/DoT, which is what makes "DNS works but the browser cannot
	// resolve" diagnosable at all.
	encryptedDNS := Probe{ID: ProbeDNSEncrypted, Name: "DNS (encrypted DoH/DoT)", Deps: []ProbeID{ProbeIface}, Run: o.encryptedDNSProbe(defaultEncryptedDNS, ConnectivityProbeHost)}

	if t == nil {
		// Egress, proxy egress, system DNS, and public DNS are siblings: each
		// depends only on the interface, so one failure never hides another.
		dns := Probe{ID: ProbeDNS, Name: "DNS", Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(ConnectivityProbeHost, nil)}
		probes := []Probe{iface, internet, quicProbe, proxy, dns}
		if len(publicDNSResolvers) > 0 {
			probes = append(probes, Probe{ID: ProbeDNSPublic, Name: publicDNSRowName(publicDNS, publicDNSAuto), Deps: []ProbeID{ProbeIface}, Run: o.publicDNSProbe(ConnectivityProbeHost, nil, publicDNSResolvers)})
		}
		probes = append(probes, encryptedDNS)
		return append(probes, network)
	}

	host, port := t.Host, t.Port
	hp := net.JoinHostPort(host, strconv.Itoa(port)) // brackets IPv6 literals
	dns := Probe{ID: ProbeDNS, Name: "DNS " + host, Deps: []ProbeID{ProbeIface}, Run: o.dnsProbe(host, t.IP)}
	ttcp := Probe{ID: ProbeTargetTCP, Name: "TCP " + hp, Deps: []ProbeID{ProbeDNS}, Run: o.targetTCPProbe(port)}
	// Path MTU hangs off the TCP connect rather than off any protocol row: a
	// black hole breaks SSH and SMTP exactly as thoroughly as it breaks TLS.
	pmtu := Probe{ID: ProbePMTU, Name: "Path MTU " + hp, Deps: []ProbeID{ProbeTargetTCP}, Run: o.pmtuProbe(port, t.Proto)}
	probes := []Probe{iface, internet, quicProbe, proxy, dns}
	if len(publicDNSResolvers) > 0 {
		probes = append(probes, Probe{ID: ProbeDNSPublic, Name: publicDNSRowName(publicDNS, publicDNSAuto), Deps: []ProbeID{ProbeIface}, Run: o.publicDNSProbe(host, t.IP, publicDNSResolvers)})
	}
	probes = append(probes, encryptedDNS, ttcp, pmtu, network)

	switch t.Proto {
	case ProtoTLSHTTP:
		probes = append(probes,
			Probe{ID: ProbeTLS, Name: "TLS " + host, Deps: []ProbeID{ProbeTargetTCP}, Run: o.tlsProbe(host, port)},
			Probe{ID: ProbeHTTP, Name: "HTTP " + host, Deps: []ProbeID{ProbeDNS}, Run: o.httpProbe(host, 80, "http", ProbeDNS)},
			Probe{ID: ProbeHTTPS, Name: "HTTPS " + host, Deps: []ProbeID{ProbeTLS}, Run: o.httpProbe(host, port, "https", ProbeTLS)},
		)
	case ProtoHTTP:
		probes = append(probes,
			Probe{ID: ProbeHTTP, Name: "HTTP " + host, Deps: []ProbeID{ProbeTargetTCP}, Run: o.httpProbe(host, port, "http", ProbeTargetTCP)},
		)
	case ProtoSSH:
		probes = append(probes, o.bannerProbe(ProbeSSH, "SSH banner "+hp, port))
	case ProtoSMTP:
		probes = append(probes, o.bannerProbe(ProbeSMTP, "SMTP banner "+hp, port))
	}
	return probes
}
