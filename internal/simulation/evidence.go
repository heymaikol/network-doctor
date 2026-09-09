package simulation

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Evidence is simulator-owned proof collected from services inside node
// namespaces. It complements netdoc's report; it is never used to manufacture
// a diagnostic result.
type Evidence struct {
	ResolverLookups  []ResolverLookupEvidence  `json:"resolver_lookups,omitempty"`
	DNS              []DNSEvidence             `json:"dns"`
	DNSQueries       []DNSQueryEvidence        `json:"dns_queries"`
	SOCKSRequests    []SOCKSEvidence           `json:"socks_requests"`
	TLS              []TLSEvidence             `json:"tls"`
	ServiceStates    []ServiceStateEvidence    `json:"service_states"`
	ServiceReplies   []ServiceReplyEvidence    `json:"service_replies"`
	TCPResets        []TCPResetEvidence        `json:"tcp_resets"`
	PacketConditions []PacketConditionEvidence `json:"packet_conditions"`
	PacketDrops      []PacketDropEvidence      `json:"packet_drops"`
	Links            []LinkEvidence            `json:"links"`
	Routes           []RouteEvidence           `json:"routes"`
	RouteTables      []RouteTableEvidence      `json:"route_tables"`
	Routers          []RouterEvidence          `json:"routers"`
	// ControlledTargets and FamilyReachability are both measured, never
	// derived. See their type comments.
	ControlledTargets  []ControlledTargetEvidence   `json:"controlled_targets"`
	FamilyReachability []FamilyReachabilityEvidence `json:"family_reachability"`
}

type PacketConditionEvidence struct {
	Node           string        `json:"node"`
	Segment        string        `json:"segment"`
	Latency        time.Duration `json:"latency_ms,omitempty"`
	Jitter         time.Duration `json:"jitter_ms,omitempty"`
	LossPercent    float64       `json:"loss_percent,omitempty"`
	Seed           uint32        `json:"seed,omitempty"`
	Active         bool          `json:"active"`
	DroppedPackets uint64        `json:"dropped_packets"`
	ObservedMinRTT time.Duration `json:"observed_min_rtt_ms,omitempty"`
	ObservedMaxRTT time.Duration `json:"observed_max_rtt_ms,omitempty"`
	RTTSamples     int           `json:"rtt_samples"`
}

// PacketDropEvidence is the kernel's own count of the packets one drop fault's
// rule matched, read back from that rule's nftables counter once the run ended.
// A rule that was installed but never matched anything reports zero: a fault
// that was injected and a fault that took effect are different claims, and only
// the counter can tell them apart.
type PacketDropEvidence struct {
	Node      string `json:"node"`
	Family    string `json:"family,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
	To        string `json:"to,omitempty"`
	Direction string `json:"direction"`
	Packets   uint64 `json:"packets"`
}

// LinkEvidence describes one actual namespace interface using its logical
// segment name. Kernel implementation names are intentionally absent.
type LinkEvidence struct {
	Node    string `json:"node"`
	Segment string `json:"segment"`
	Address string `json:"address"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Up      bool   `json:"up"`
	// MTU is what the kernel reports for this interface, which is the reading a
	// path-MTU black hole is made of: one hop carrying less than the endpoints
	// still offer. Zero means the link was read and reported none, so a fault
	// that narrows nothing cannot confirm itself from a missing number.
	MTU int `json:"mtu,omitempty"`
}

// RouteEvidence combines the validated route with the kernel's selected path.
// GatewayReachable is omitted when no neighbor observation was available.
type RouteEvidence struct {
	Node             string `json:"node"`
	Destination      string `json:"destination"`
	Via              string `json:"via,omitempty"`
	Segment          string `json:"segment"`
	Metric           int    `json:"metric"`
	Family           string `json:"family,omitempty"`
	Selected         bool   `json:"selected"`
	Source           string `json:"source,omitempty"`
	GatewayReachable *bool  `json:"gateway_reachable,omitempty"`
}

// RouteTableEvidence is the routing table one node's kernel actually held when
// the run ended, read back with `ip route show` from inside that node's own
// namespace. RouteEvidence answers "where does this destination go"; this
// answers the different question of "what routes exist at all", which is the
// only thing that can establish an absence: a route that was deleted, or one
// that was never installed, leaves no trace in a per-destination lookup beyond
// the lookup failing, and a failed lookup is not the same claim as a missing
// route.
//
// A record exists for every family the node has an address in, so an empty
// Routes list is the positive statement "this table was read and held nothing",
// not "nobody looked". Families the node has no address in get no record.
type RouteTableEvidence struct {
	Node   string        `json:"node"`
	Family string        `json:"family"`
	Routes []KernelRoute `json:"routes"`
}

// KernelRoute is one line of a node's real routing table, in the simulator's
// logical vocabulary: interfaces are named by topology segment rather than by
// the kernel name the run happened to allocate.
type KernelRoute struct {
	Destination string `json:"destination"`
	Via         string `json:"via,omitempty"`
	Segment     string `json:"segment,omitempty"`
	Metric      int    `json:"metric,omitempty"`
}

type RouterEvidence struct {
	Node           string `json:"node"`
	IPv4Forwarding bool   `json:"ipv4_forwarding"`
	IPv6Forwarding bool   `json:"ipv6_forwarding"`
}

// ControlledTargetEvidence is the simulator's own TCP dial of one literal
// address and port that a simulator fixture serves, taken from inside a node's
// namespace. To is always an address:port the scenario owns, which is what
// keeps a diagnosis out: netdoc's target may be a hostname or anything on the
// public internet, and its target_tcp verdict is a claim about a run, not a
// dial the simulator performed. The single producer is the node holder, which
// never sees netdoc's report.
type ControlledTargetEvidence struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Family    string   `json:"family"`
	Via       []string `json:"via"`
	Reachable bool     `json:"reachable"`
	// Outcome is what the dial did, not merely whether it worked. A port that
	// answered a SYN with a reset and a port that swallowed it are both
	// unreachable and are different faults with different fixes, and the dialing
	// end is the only place that difference is visible. Reachable is the same
	// observation narrowed to a bool, kept because most readers only want that.
	Outcome string `json:"outcome"`
}

// Address family states a FamilyReachabilityEvidence can carry. Unavailable and
// unreachable are deliberately distinct: a family the node was never given an
// address in was not tested, which is not the same claim as a family that was
// dialed and did not answer.
//
// TargetStateRefused is a third outcome only a dial of one specific port can
// produce, so it is not a family state: a family is reachable when any endpoint
// answers, and "refused" is a fact about a port.
const (
	FamilyStateReachable   = "reachable"
	FamilyStateUnreachable = "unreachable"
	FamilyStateUnavailable = "unavailable"
	TargetStateRefused     = "refused"
)

// FamilyReachabilityEvidence is the simulator's own point-in-time answer to one
// question: from inside this node's namespace, does a TCP connection to the
// controlled endpoints of this address family complete?
//
// It is a state rather than a bool because there are three outcomes, and it is
// its own type rather than a ControlledTargetEvidence so that the only way to fill
// it in is to dial. The single producer is the node holder, which never sees
// netdoc's report; anything derived from a diagnosis, a scenario expectation or
// a fault record belongs somewhere else. Absence of a record for a family is
// not "unavailable"; it means no observation was taken at all.
type FamilyReachabilityEvidence struct {
	Node   string   `json:"node"`
	Family string   `json:"family"`
	Target string   `json:"target,omitempty"`
	Via    []string `json:"via,omitempty"`
	State  string   `json:"state"`
}

// DNSEvidence aggregates identical queries observed by a DNS service.
type DNSEvidence struct {
	Node      string `json:"node"`
	Service   string `json:"service,omitempty"`
	Source    string `json:"source"`
	Name      string `json:"name"`
	QueryType string `json:"query_type"`
	Result    string `json:"result"`
	Count     int    `json:"count"`
}

// DNSQueryEvidence preserves scheduled query order rather than aggregating it.
// Sequence is scoped to service, queried name, and query type.
type DNSQueryEvidence struct {
	Node             string `json:"node"`
	Service          string `json:"service"`
	Source           string `json:"source"`
	Name             string `json:"name"`
	QueryType        string `json:"query_type"`
	Sequence         int    `json:"sequence"`
	ScheduledOutcome string `json:"scheduled_outcome"`
	ActualOutcome    string `json:"actual_outcome"`
	// Offset places the query on the fault timeline, relative to T0. It is
	// filled in by the director once the run's epoch is known, and only means
	// anything when OffsetKnown is set.
	Offset time.Duration `json:"offset_ms"`
	// OffsetKnown reports whether the holder's observation carried a wall clock
	// the director could place on the timeline. Without it Offset is zero
	// because there is nothing to put there, which is a different claim from a
	// query observed exactly at T0, so the two are not left to share a value.
	OffsetKnown bool  `json:"offset_known"`
	DelayMs     int64 `json:"delay_ms,omitempty"`
	at          time.Time
}

// placedWithin reports whether this query is known to have been observed in
// [start, end). A query the director could not place is left out rather than
// read as T0: unknown timing must never be enough to satisfy an interval a
// caller asked about.
func (q DNSQueryEvidence) placedWithin(start, end time.Duration) bool {
	return q.OffsetKnown && q.Offset >= start && q.Offset < end
}

type TCPResetEvidence struct {
	Node    string `json:"node"`
	Service string `json:"service,omitempty"`
	Event   string `json:"event"`
	Result  string `json:"result"`
	Count   int    `json:"count"`
}

// SOCKSEvidence aggregates protocol events observed by a SOCKS service.
// A greeting proves proxy reachability even when local DNS fails before the
// client can send a CONNECT request.
type SOCKSEvidence struct {
	Node        string `json:"node"`
	Service     string `json:"service,omitempty"`
	Event       string `json:"event"`
	AddressType string `json:"address_type,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        int    `json:"port,omitempty"`
	Result      string `json:"result"`
	Count       int    `json:"count"`
}

// TLSEvidence aggregates handshakes observed by a simulator TLS service. It
// contains certificate metadata only; private keys never enter the recorder.
type TLSEvidence struct {
	Node                 string    `json:"node"`
	Service              string    `json:"service"`
	CertificateMode      string    `json:"certificate_mode"`
	RequestedServer      string    `json:"requested_server,omitempty"`
	CertificateDNS       []string  `json:"certificate_dns"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	CertificatePresented bool      `json:"certificate_presented"`
	Result               string    `json:"result"`
	Count                int       `json:"count"`
}

// ServiceStateEvidence records the mode of a successfully started controlled
// service. It is emitted by the node holder, not copied into the report from a
// hunt manifest or diagnosis.
type ServiceStateEvidence struct {
	Node    string `json:"node"`
	Service string `json:"service,omitempty"`
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Mode    string `json:"mode,omitempty"`
	Status  int    `json:"status,omitempty"`
}

// ServiceReplyEvidence counts the replies a controlled service actually sent,
// in the shape it sent them. It is the companion to ServiceStateEvidence and
// deliberately not the same record: a service that came up in a faulty mode has
// a state, but until a client reaches it and it answers, nothing was done to
// anyone. Only a reply proves the fault reached the wire.
type ServiceReplyEvidence struct {
	Node    string `json:"node"`
	Service string `json:"service,omitempty"`
	Type    string `json:"type"`
	Port    int    `json:"port"`
	Status  int    `json:"status,omitempty"`
	Result  string `json:"result"`
	Count   int    `json:"count"`
}

const (
	evidenceServiceState = "service_state"
	evidenceServiceReply = "service_reply"
	// replyResponded is the reply result of a service that answered normally,
	// whatever the answer said. A faulty mode names itself instead.
	replyResponded = "responded"
)

type evidenceEvent struct {
	Kind             string `json:"kind"`
	Node             string `json:"node"`
	Service          string `json:"service,omitempty"`
	Name             string `json:"name,omitempty"`
	Source           string `json:"source,omitempty"`
	QueryType        string `json:"query_type,omitempty"`
	Event            string `json:"event,omitempty"`
	AddressType      string `json:"address_type,omitempty"`
	Destination      string `json:"destination,omitempty"`
	Port             int    `json:"port,omitempty"`
	Result           string `json:"result"`
	Sequence         int    `json:"sequence,omitempty"`
	ScheduledOutcome string `json:"scheduled_outcome,omitempty"`
	ActualOutcome    string `json:"actual_outcome,omitempty"`
	DelayMs          int64  `json:"delay_ms,omitempty"`
	// At is the wall clock the holder observed the event at. Holders and the
	// director share one machine's clock, which is the only thing they can
	// correlate across processes; it never orders the fault scheduler, which
	// runs off a single monotonic epoch.
	At time.Time `json:"at"`

	CertificateMode      string    `json:"certificate_mode,omitempty"`
	RequestedServer      string    `json:"requested_server,omitempty"`
	CertificateDNS       []string  `json:"certificate_dns,omitempty"`
	NotBefore            time.Time `json:"not_before,omitempty"`
	NotAfter             time.Time `json:"not_after,omitempty"`
	CertificatePresented bool      `json:"certificate_presented,omitempty"`
	ServiceType          string    `json:"service_type,omitempty"`
	ServicePort          int       `json:"service_port,omitempty"`
	ServiceMode          string    `json:"service_mode,omitempty"`
	ServiceStatus        int       `json:"service_status,omitempty"`
}

// evidenceRecorder serializes events from concurrent service goroutines into
// one JSONL file owned by the node holder. The director only reads it after a
// netdoc process has exited.
type evidenceRecorder struct {
	mu     sync.Mutex
	node   string
	file   *os.File
	err    error
	failed chan error
}

func openEvidenceRecorder(path, node string) (*evidenceRecorder, error) {
	if path == "" {
		return &evidenceRecorder{node: node}, nil
	}
	// #nosec G304 -- production paths are generated inside this run's private workspace.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &evidenceRecorder{node: node, file: f, failed: make(chan error, 1)}, nil
}

func (r *evidenceRecorder) record(event evidenceEvent) error {
	if r == nil || r.file == nil {
		return nil
	}
	event.Node = r.node
	if event.At.IsZero() {
		event.At = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	if err := json.NewEncoder(r.file).Encode(event); err != nil {
		r.err = fmt.Errorf("record evidence for node %q: %w", r.node, err)
		select {
		case r.failed <- r.err:
		default:
		}
	}
	return r.err
}

func (r *evidenceRecorder) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *evidenceRecorder) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.err
	if closeErr := r.file.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("finalize evidence recording for node %q: %w", r.node, closeErr))
	}
	return err
}

func readEvidence(paths []string) (Evidence, error) {
	var events []evidenceEvent
	for _, path := range paths {
		// #nosec G304 -- callers supply only run-owned evidence paths or test temp files.
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Evidence{}, err
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var event evidenceEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				_ = f.Close()
				return Evidence{}, fmt.Errorf("%s: %w", path, err)
			}
			events = append(events, event)
		}
		err = scanner.Err()
		_ = f.Close()
		if err != nil {
			return Evidence{}, err
		}
	}
	return aggregateEvidence(events), nil
}

func aggregateEvidence(events []evidenceEvent) Evidence {
	dns := make(map[string]DNSEvidence)
	socks := make(map[string]SOCKSEvidence)
	tlsEvents := make(map[string]TLSEvidence)
	resets := make(map[string]TCPResetEvidence)
	replies := make(map[string]ServiceReplyEvidence)
	for _, event := range events {
		switch event.Kind {
		case ServiceDNS:
			key := event.Node + "\x00" + event.Service + "\x00" + event.Source + "\x00" + event.Name + "\x00" + event.QueryType + "\x00" + event.Result
			item := dns[key]
			item.Node, item.Service, item.Name = event.Node, event.Service, event.Name
			item.Source = event.Source
			item.QueryType, item.Result, item.Count = event.QueryType, event.Result, item.Count+1
			dns[key] = item
		case ServiceSOCKS5:
			key := event.Node + "\x00" + event.Service + "\x00" + event.Event + "\x00" + event.AddressType + "\x00" + event.Destination + "\x00" + strconv.Itoa(event.Port) + "\x00" + event.Result
			item := socks[key]
			item.Node, item.Service, item.Event = event.Node, event.Service, event.Event
			item.AddressType, item.Destination, item.Port = event.AddressType, event.Destination, event.Port
			item.Result, item.Count = event.Result, item.Count+1
			socks[key] = item
		case ServiceTLS:
			key := event.Node + "\x00" + event.Service + "\x00" + event.CertificateMode + "\x00" +
				event.RequestedServer + "\x00" + strings.Join(event.CertificateDNS, "\x00") + "\x00" +
				event.NotBefore.UTC().Format(time.RFC3339Nano) + "\x00" + event.NotAfter.UTC().Format(time.RFC3339Nano) +
				"\x00" + strconv.FormatBool(event.CertificatePresented) + "\x00" + event.Result
			item := tlsEvents[key]
			item.Node, item.Service = event.Node, event.Service
			item.CertificateMode, item.RequestedServer = event.CertificateMode, event.RequestedServer
			item.CertificateDNS = append([]string(nil), event.CertificateDNS...)
			item.NotBefore, item.NotAfter = event.NotBefore, event.NotAfter
			item.CertificatePresented, item.Result = event.CertificatePresented, event.Result
			item.Count++
			tlsEvents[key] = item
		case ServiceTCPReset:
			key := event.Node + "\x00" + event.Service + "\x00" + event.Event + "\x00" + event.Result
			item := resets[key]
			item.Node, item.Service, item.Event, item.Result = event.Node, event.Service, event.Event, event.Result
			item.Count++
			resets[key] = item
		case evidenceServiceReply:
			key := strings.Join([]string{event.Node, event.Service, event.ServiceType,
				strconv.Itoa(event.ServicePort), strconv.Itoa(event.ServiceStatus), event.Result}, "\x00")
			item := replies[key]
			item.Node, item.Service, item.Type = event.Node, event.Service, event.ServiceType
			item.Port, item.Status, item.Result = event.ServicePort, event.ServiceStatus, event.Result
			item.Count++
			replies[key] = item
		}
	}
	var out Evidence
	for _, item := range dns {
		out.DNS = append(out.DNS, item)
	}
	for _, item := range socks {
		out.SOCKSRequests = append(out.SOCKSRequests, item)
	}
	for _, item := range tlsEvents {
		out.TLS = append(out.TLS, item)
	}
	for _, event := range events {
		if event.Kind == evidenceServiceState {
			out.ServiceStates = append(out.ServiceStates, ServiceStateEvidence{Node: event.Node, Service: event.Service,
				Type: event.ServiceType, Port: event.ServicePort, Mode: event.ServiceMode, Status: event.ServiceStatus})
		}
		if event.Kind == ServiceDNS && event.Sequence > 0 {
			out.DNSQueries = append(out.DNSQueries, DNSQueryEvidence{Node: event.Node, Service: event.Service,
				Source: event.Source, Name: event.Name, QueryType: event.QueryType, Sequence: event.Sequence,
				ScheduledOutcome: event.ScheduledOutcome, ActualOutcome: event.ActualOutcome,
				DelayMs: event.DelayMs, at: event.At})
		}
	}
	for _, item := range resets {
		out.TCPResets = append(out.TCPResets, item)
	}
	for _, item := range replies {
		out.ServiceReplies = append(out.ServiceReplies, item)
	}
	sort.Slice(out.DNS, func(i, j int) bool {
		a, b := out.DNS[i], out.DNS[j]
		return a.Node+a.Service+a.Source+a.Name+a.QueryType+a.Result < b.Node+b.Service+b.Source+b.Name+b.QueryType+b.Result
	})
	sort.Slice(out.SOCKSRequests, func(i, j int) bool {
		a, b := out.SOCKSRequests[i], out.SOCKSRequests[j]
		return a.Node+a.Service+a.Event+a.AddressType+a.Destination+strconv.Itoa(a.Port)+a.Result <
			b.Node+b.Service+b.Event+b.AddressType+b.Destination+strconv.Itoa(b.Port)+b.Result
	})
	sort.Slice(out.TLS, func(i, j int) bool {
		a, b := out.TLS[i], out.TLS[j]
		return a.Node+a.Service+a.CertificateMode+a.RequestedServer+strings.Join(a.CertificateDNS, "\x00")+a.Result <
			b.Node+b.Service+b.CertificateMode+b.RequestedServer+strings.Join(b.CertificateDNS, "\x00")+b.Result
	})
	sort.Slice(out.ServiceStates, func(i, j int) bool {
		a, b := out.ServiceStates[i], out.ServiceStates[j]
		return strings.Join([]string{a.Node, a.Service, a.Type, strconv.Itoa(a.Port), a.Mode, strconv.Itoa(a.Status)}, "\x00") <
			strings.Join([]string{b.Node, b.Service, b.Type, strconv.Itoa(b.Port), b.Mode, strconv.Itoa(b.Status)}, "\x00")
	})
	sort.Slice(out.ServiceReplies, func(i, j int) bool {
		a, b := out.ServiceReplies[i], out.ServiceReplies[j]
		return strings.Join([]string{a.Node, a.Service, a.Type, strconv.Itoa(a.Port), strconv.Itoa(a.Status), a.Result}, "\x00") <
			strings.Join([]string{b.Node, b.Service, b.Type, strconv.Itoa(b.Port), strconv.Itoa(b.Status), b.Result}, "\x00")
	})
	sort.Slice(out.DNSQueries, func(i, j int) bool {
		a, b := out.DNSQueries[i], out.DNSQueries[j]
		if a.Node+a.Service+a.Name+a.QueryType != b.Node+b.Service+b.Name+b.QueryType {
			return a.Node+a.Service+a.Name+a.QueryType < b.Node+b.Service+b.Name+b.QueryType
		}
		return a.Sequence < b.Sequence
	})
	sort.Slice(out.TCPResets, func(i, j int) bool {
		a, b := out.TCPResets[i], out.TCPResets[j]
		return a.Node+a.Service+a.Event+a.Result < b.Node+b.Service+b.Event+b.Result
	})
	if out.DNS == nil {
		out.DNS = []DNSEvidence{}
	}
	if out.SOCKSRequests == nil {
		out.SOCKSRequests = []SOCKSEvidence{}
	}
	if out.TLS == nil {
		out.TLS = []TLSEvidence{}
	}
	if out.ServiceStates == nil {
		out.ServiceStates = []ServiceStateEvidence{}
	}
	if out.ServiceReplies == nil {
		out.ServiceReplies = []ServiceReplyEvidence{}
	}
	if out.DNSQueries == nil {
		out.DNSQueries = []DNSQueryEvidence{}
	}
	if out.TCPResets == nil {
		out.TCPResets = []TCPResetEvidence{}
	}
	out.PacketConditions = []PacketConditionEvidence{}
	out.PacketDrops = []PacketDropEvidence{}
	out.Links = []LinkEvidence{}
	out.Routes = []RouteEvidence{}
	out.RouteTables = []RouteTableEvidence{}
	out.Routers = []RouterEvidence{}
	out.ControlledTargets = []ControlledTargetEvidence{}
	out.FamilyReachability = []FamilyReachabilityEvidence{}
	return out
}
