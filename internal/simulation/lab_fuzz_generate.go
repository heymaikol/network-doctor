package simulation

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/heymaikol/network-doctor/v2/internal/compare"
)

// LabFuzzVersion versions this experimental construction algorithm. Artifacts
// carry concrete worlds as well, so replay does not invoke the generator.
const LabFuzzVersion = "reasoning-v1"

type LabFuzzCase struct {
	Version  string
	Seed     uint64
	Index    uint64
	Worlds   []LabScenario
	Relation string // empty, or endpoint-vs-transit-silence
}

// labMaxInt is math.MaxInt as a uint64. It is spelled out rather than imported
// because the lab model files pin their imports to the offline set the guard
// test allows.
const labMaxInt = uint64(^uint(0) >> 1)

// SplitMix64, including overflow modulo 2^64, is part of reasoning-v1.
type labRandom uint64

func (r *labRandom) next() uint64 {
	*r += 0x9e3779b97f4a7c15
	z := uint64(*r)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// n draws a value in [0,n). The bound is a positive count the generator
// computed, so a non-positive one is a generator bug rather than input. The
// remainder is already below that bound; the mask states the same limit to the
// conversion and changes no drawn value.
func (r *labRandom) n(n int) int {
	if n <= 0 {
		panic("lab fuzz generator: draw bound must be positive")
	}
	return int(r.next() % uint64(n) & labMaxInt)
}

func labCopy[T any](v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// GenerateLabFuzz constructs bounded valid primitives. No status, diagnosis,
// confidence or inferred expected outcome participates in generation.
func GenerateLabFuzz(seed, index uint64, maxFaults int, twoSided bool) (LabFuzzCase, error) {
	if maxFaults < 0 || maxFaults > 12 {
		return LabFuzzCase{}, fmt.Errorf("max-faults must be 0..12")
	}
	r := labRandom(seed ^ (index * 0xd1342543de82ef95))
	familyMode := r.n(3)
	dual := familyMode != 0
	s := LabScenario{Name: "generated", Network: labBase(dual), Views: []LabView{{Node: "client", Target: "https://" + labHost, SourceSegment: "ethernet", Expected: LabExpected{Verdict: "ok"}}}}
	if familyMode != 2 && r.n(4) == 0 {
		labAddVPN(&s)
	}
	if twoSided && r.n(2) == 1 {
		s.Views = append(s.Views, LabView{Node: "remote", Target: s.Views[0].Target, Expected: LabExpected{Verdict: "ok"}})
		s.TwoSided = compare.SideNone
	}
	// Multiple concrete endpoints with independently chosen resolver answer sets.
	count := 1 + r.n(3)
	if familyMode == 2 {
		count = 1
	}
	addresses := []string{labTarget4}
	for i := 1; i < count; i++ {
		name, ip, alias := fmt.Sprintf("extra%d", i), fmt.Sprintf("10.20.2.%d", 100+i), fmt.Sprintf("203.0.113.%d", 100+i)
		s.Network.Topology.Nodes = append(s.Network.Topology.Nodes, labServer(name, ip, alias))
		s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: name, Destination: "0.0.0.0/0", Via: "10.20.2.1"})
		for _, node := range []string{"gateway", "remote"} {
			s.Network.Topology.Routes = append(s.Network.Topology.Routes, Route{Node: node, Destination: alias + "/32", Via: ip})
		}
		addresses = append(addresses, alias)
	}
	for ni := range s.Network.Topology.Nodes {
		for si := range s.Network.Topology.Nodes[ni].Services {
			svc := &s.Network.Topology.Nodes[ni].Services[si]
			if svc.Type != ServiceDNS && svc.Type != ServiceEncryptedDNS {
				continue
			}
			svc.Records = slices.DeleteFunc(svc.Records, func(d DNSRecord) bool { return d.Name == labHost })
			mask := 1 + r.n((1<<count)-1)
			for i, a := range addresses {
				if mask&(1<<i) != 0 {
					svc.Records = append(svc.Records, DNSRecord{Name: labHost, Address: a})
				}
			}
			if dual && r.n(2) == 1 {
				svc.Records = append(svc.Records, DNSRecord{Name: labHost, Address: labTarget6})
			}
		}
	}
	if familyMode == 2 {
		labRemoveFamily(&s, false)
		for i := range s.Views {
			s.Views[i].Target = "https://[" + labTarget6 + "]"
		}
	}
	routeFamily := "ipv4"
	if familyMode == 2 {
		routeFamily = "ipv6"
	}
	var choices []LabFault
	drop := func(id, node, to, proto string, port int) {
		choices = append(choices, LabFault{ID: id, Layer: "transport", Scope: node, Network: &Fault{Type: FaultDrop, Node: node, To: to, Protocol: proto, Port: port, Direction: DirectionInbound}})
	}
	choices = append(choices,
		LabFault{ID: "link-down", Layer: "link", Scope: "client", Network: &Fault{Type: FaultLinkDown, Node: "client", Segment: "ethernet"}},
		LabFault{ID: "no-default", Layer: "routing", Scope: "client", Network: &Fault{Type: FaultNoDefaultRoute, Node: "client", Family: routeFamily}},
		LabFault{ID: "loss", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultNetem, Node: "gateway", Segment: "uplink", Loss: fmt.Sprintf("%d%%", 1+r.n(60)), Seed: uint32(r.next() & 0xffffffff)}},
	)
	drop("system-dns-drop", "resolver", "", "udp", 53)
	drop("public-dns-drop", "internet", "", "udp", 53)
	drop("reference-drop", "internet", "", "tcp", 443)
	drop("target-drop", "target", "", "tcp", 443)
	drop("remote-drop", "remote", "", "tcp", 40000)
	choices = append(choices, LabFault{ID: "mtu", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultPMTUBlackhole, Node: "gateway", Segment: "uplink", MTU: 1280 + r.n(200)}}, LabFault{ID: "return-route", Layer: "routing", Scope: "target", Route: &Route{Node: "target", Destination: "10.20.1.0/24", Via: "10.20.2.254"}}, LabFault{ID: "http-silence", Layer: "http", Scope: "target", HTTPNoResponse: "target-tls"})
	if dual {
		choices = append(choices, LabFault{ID: "family-drop", Layer: "transport", Scope: "gateway", Network: &Fault{Type: FaultDrop, Node: "gateway", Family: "ipv6", Direction: DirectionInbound}})
	}
	for _, node := range s.Network.Topology.Nodes {
		for _, svc := range node.Services {
			svc = labCopy(svc)
			switch svc.Name {
			case "system-dns", "public-dns":
				svc.Records = slices.DeleteFunc(svc.Records, func(d DNSRecord) bool { return d.Name == labHost })
			case "target-tls":
				switch r.n(3) {
				case 0:
					svc.Port = 8443
				case 1:
					svc.Certificate = &TLSCertificate{Mode: TLSCertificateHostnameMismatch, DNSNames: []string{"wrong.test"}}
				case 2:
					svc.Certificate = &TLSCertificate{Mode: TLSCertificateExpired, DNSNames: []string{labHost}}
				}
			case "reference-http":
				svc.Portal = true
			default:
				continue
			}
			layer := "http"
			switch svc.Type {
			case ServiceDNS:
				layer = "dns"
			case ServiceTLS:
				layer = "tls"
			}
			choices = append(choices, LabFault{ID: "replace-" + svc.Name, Layer: layer, Scope: svc.Name, Service: &svc})
		}
	}
	if familyMode == 2 {
		choices = slices.DeleteFunc(choices, func(f LabFault) bool { return f.Route != nil })
	}
	// Fisher-Yates over a stable declaration-order pool; no map iteration.
	for i := len(choices) - 1; i > 0; i-- {
		j := r.n(i + 1)
		choices[i], choices[j] = choices[j], choices[i]
	}
	n := r.n(maxFaults + 1)
	if n > len(choices) {
		n = len(choices)
	}
	s.Faults = append(s.Faults, choices[:n]...)
	c := LabFuzzCase{Version: LabFuzzVersion, Seed: seed, Index: index, Worlds: []LabScenario{s}}
	// A first-class paired stratum: same packets lost at two different locations.
	// Both worlds are run and equality is established, never assumed.
	if maxFaults > 0 && familyMode != 2 && r.n(8) == 0 {
		s.Views = s.Views[:1]
		s.TwoSided = ""
		s.Faults = []LabFault{{ID: "paired-silence", Layer: "transport", Scope: "target", Network: &Fault{Type: FaultDrop, Node: "target", To: labTarget4, Protocol: "tcp", Port: 443, Direction: DirectionInbound}}}
		other := labCopy(s)
		other.Faults[0].Scope = "gateway"
		other.Faults[0].Network.Node = "gateway"
		c.Worlds = []LabScenario{s, other}
		c.Relation = "endpoint-vs-transit-silence"
	}
	return c, c.Validate()
}

func (c LabFuzzCase) Validate() error {
	if c.Version != LabFuzzVersion || len(c.Worlds) < 1 || len(c.Worlds) > 2 {
		return fmt.Errorf("unsupported version or world count")
	}
	if (len(c.Worlds) == 2) != (c.Relation == "endpoint-vs-transit-silence") || len(c.Worlds) == 1 && c.Relation != "" {
		return fmt.Errorf("invalid world relation")
	}
	for _, s := range c.Worlds {
		if len(s.Network.Topology.Nodes) > 24 || len(s.Network.Topology.Routes) > 100 || len(s.Faults) > 12 {
			return fmt.Errorf("world exceeds experimental bounds")
		}
		for _, n := range s.Network.Topology.Nodes {
			if len(n.Interfaces) > 8 || len(n.Services) > 32 || len(n.Aliases) > 32 {
				return fmt.Errorf("node exceeds experimental bounds")
			}
			for _, svc := range n.Services {
				if len(svc.Records) > 64 || len(svc.Zone) > 64 {
					return fmt.Errorf("service exceeds experimental bounds")
				}
			}
		}
		if _, err := s.compile(); err != nil {
			return err
		}
	}
	if len(c.Worlds) == 2 {
		a, b := labCopy(c.Worlds[0]), labCopy(c.Worlds[1])
		if len(a.Faults) != 1 || len(b.Faults) != 1 {
			return fmt.Errorf("paired worlds require one distinguishing fault")
		}
		x, y := a.Faults[0], b.Faults[0]
		if x.Network == nil || y.Network == nil || x.Network.Node != "target" || y.Network.Node != "gateway" || x.Network.Type != FaultDrop || x.Network.Direction != DirectionInbound || x.Network.To != labTarget4 || x.Network.Protocol != "tcp" || x.Network.Port != 443 {
			return fmt.Errorf("invalid counterfactual witness")
		}
		y.Scope = x.Scope
		y.Network.Node = x.Network.Node
		if !labEqual(x, y) {
			return fmt.Errorf("counterfactual mutations differ beyond location")
		}
		a.Faults = nil
		b.Faults = nil
		if !labEqual(a, b) {
			return fmt.Errorf("paired bases differ")
		}
	}
	return nil
}
func labEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
