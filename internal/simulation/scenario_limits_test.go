package simulation

// The scenario resource budget. A custom scenario is an arbitrary file, so
// these tests pin both halves of the bound: that a scenario at exactly the
// documented ceiling still loads, and that one entry more is refused before
// anything is built.
//
// Every fixture is constructed rather than checked in, because a file with 65
// nodes or 257 routes in it is not something a person should have to read to
// know what the test proves.

import (
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// limitCase builds one semantically valid scenario carrying n entries in the
// collection it names, so the same builder can be asked for the limit and for
// one past it.
type limitCase struct {
	collection string
	max        int
	build      func(n int) *Scenario
	// want is the substring the over-budget error must carry, which is what
	// makes a scenario rejected for the wrong reason a failure rather than a
	// pass.
	want string
}

// legacyBase is the shorthand single-segment form, which is the cheapest
// starting point for a scenario whose point is a count.
func legacyBase() *Scenario {
	return &Scenario{
		Name: "limits",
		Topology: Topology{
			Subnet: "10.77.0.0/24",
			Nodes: []Node{
				{Name: "client", Role: "client", Address: "10.77.0.10", Gateway: "10.77.0.1"},
				{Name: "server", Address: "10.77.0.1"},
			},
		},
		Tests:  []Test{{Node: "client", Target: "example.test:80"}},
		Expect: Expect{Verdict: diagnostic.VerdictOK},
	}
}

// segmentedBase is the explicit form, needed by anything about segments,
// interfaces or routes.
func segmentedBase(segments int) *Scenario {
	s := &Scenario{
		Name:     "limits",
		Topology: Topology{},
		Tests:    []Test{{Node: "client", Target: "example.test:80"}},
		Expect:   Expect{Verdict: diagnostic.VerdictOK},
	}
	for i := 0; i < segments; i++ {
		s.Topology.Segments = append(s.Topology.Segments, Segment{
			Name: "s" + strconv.Itoa(i),
			IPv4: fmt.Sprintf("10.77.%d.0/24", i),
		})
	}
	s.Topology.Nodes = []Node{
		{Name: "client", Role: "client", Interfaces: []Interface{{Segment: "s0", IPv4: "10.77.0.10/24"}}},
		{Name: "server", Interfaces: []Interface{{Segment: "s0", IPv4: "10.77.0.1/24"}}},
	}
	return s
}

func scenarioLimitCases() []limitCase {
	return []limitCase{{
		collection: "nodes",
		max:        maxTopologyNodes,
		want:       "topology.nodes",
		build: func(n int) *Scenario {
			s := legacyBase()
			s.Topology.Nodes = s.Topology.Nodes[:0]
			for i := 0; i < n; i++ {
				node := Node{Name: "n" + strconv.Itoa(i), Address: fmt.Sprintf("10.77.0.%d", 10+i)}
				if i == 0 {
					node.Role, node.Gateway = "client", "10.77.0.1"
				}
				s.Topology.Nodes = append(s.Topology.Nodes, node)
			}
			s.Tests[0].Node = "n0"
			return s
		},
	}, {
		collection: "segments",
		max:        maxTopologySegments,
		want:       "topology.segments",
		build:      func(n int) *Scenario { return segmentedBase(n) },
	}, {
		collection: "interfaces on one node",
		max:        maxNodeInterfaces,
		want:       "topology.nodes[0].interfaces",
		build: func(n int) *Scenario {
			// The per-node ceiling is the segment ceiling, because one
			// interface per segment is already the rule. So the over-budget
			// case reuses a segment rather than declaring a segment too many:
			// this is a test about the interface count, and the segment count
			// has its own case above.
			segments := min(n, maxTopologySegments)
			s := segmentedBase(segments)
			s.Topology.Nodes[0].Interfaces = nil
			for i := 0; i < n; i++ {
				s.Topology.Nodes[0].Interfaces = append(s.Topology.Nodes[0].Interfaces, Interface{
					Segment: "s" + strconv.Itoa(i%segments),
					IPv4:    fmt.Sprintf("10.77.%d.10/24", i%segments),
				})
			}
			return s
		},
	}, {
		collection: "aliases on one node",
		max:        maxNodeAliases,
		want:       "topology.nodes[1].aliases",
		build: func(n int) *Scenario {
			s := legacyBase()
			for i := 0; i < n; i++ {
				s.Topology.Nodes[1].Aliases = append(s.Topology.Nodes[1].Aliases,
					fmt.Sprintf("192.0.2.%d", 1+i))
			}
			return s
		},
	}, {
		collection: "routes",
		max:        maxTopologyRoutes,
		want:       "topology.routes",
		build: func(n int) *Scenario {
			s := segmentedBase(1)
			for i := 0; i < n; i++ {
				s.Topology.Routes = append(s.Topology.Routes, Route{
					Node:        "client",
					Destination: fmt.Sprintf("198.%d.%d.0/24", 18+i/128, i%128),
					Via:         "10.77.0.1",
				})
			}
			return s
		},
	}, {
		collection: "services on one node",
		max:        maxNodeServices,
		want:       "topology.nodes[1].services",
		build: func(n int) *Scenario {
			s := legacyBase()
			for i := 0; i < n; i++ {
				s.Topology.Nodes[1].Services = append(s.Topology.Nodes[1].Services,
					Service{Type: ServiceTCP, Port: 9000 + i})
			}
			return s
		},
	}, {
		collection: "tests",
		max:        maxScenarioTests,
		want:       "tests",
		build: func(n int) *Scenario {
			s := legacyBase()
			s.Tests = nil
			for i := 0; i < n; i++ {
				s.Tests = append(s.Tests, Test{Node: "client", Target: "example.test:80"})
			}
			return s
		},
	}, {
		collection: "faults",
		max:        maxScenarioFaults,
		want:       "faults",
		build: func(n int) *Scenario {
			s := legacyBase()
			for i := 0; i < n; i++ {
				s.Faults = append(s.Faults, Fault{
					Type: FaultDrop, Node: "client", Protocol: "tcp", Port: 9000 + i,
				})
			}
			return s
		},
	}}
}

// TestScenarioAtItsCardinalityLimitIsAccepted is the half of the budget that
// protects scenario authors: a ceiling nobody can reach is not a ceiling, but
// one that rejects the shape it documents is worse than none.
func TestScenarioAtItsCardinalityLimitIsAccepted(t *testing.T) {
	for _, c := range scenarioLimitCases() {
		t.Run(c.collection, func(t *testing.T) {
			if err := c.build(c.max).Validate(); err != nil {
				t.Fatalf("%d %s is the documented maximum but was rejected: %v", c.max, c.collection, err)
			}
		})
	}
}

func TestScenarioOverItsCardinalityLimitIsRejected(t *testing.T) {
	for _, c := range scenarioLimitCases() {
		t.Run(c.collection, func(t *testing.T) {
			err := c.build(c.max + 1).Validate()
			if err == nil {
				t.Fatalf("%d %s is one past the maximum but was accepted", c.max+1, c.collection)
			}
			for _, want := range []string{c.want, strconv.Itoa(c.max + 1), strconv.Itoa(c.max)} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not identify %q", err, want)
				}
			}
		})
	}
}

// TestScenarioLimitsAreCheckedBeforeNormalization pins the ordering the budget
// depends on: the counts reported are the ones the author wrote, so a shorthand
// topology cannot be normalized into more routes and interfaces than the file
// asked for before anyone has looked at how much it asked for.
func TestScenarioLimitsAreCheckedBeforeNormalization(t *testing.T) {
	s := scenarioLimitCases()[0].build(maxTopologyNodes + 1)
	before := len(s.Topology.Segments)
	if err := s.Validate(); err == nil {
		t.Fatal("an over-budget scenario was accepted")
	}
	if len(s.Topology.Segments) != before || len(s.Topology.Routes) != 0 {
		t.Fatalf("normalization ran on a rejected scenario: %d segments, %d routes",
			len(s.Topology.Segments), len(s.Topology.Routes))
	}
	if s.Topology.Nodes[0].Interfaces != nil {
		t.Fatal("normalization built interfaces for a rejected scenario")
	}
}

// countingReader records how much of an oversized scenario was consumed, which
// is what proves the limit bounds the read rather than measuring a file that
// was already in memory.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

// scenarioPaddedTo returns a scenario of exactly size bytes. The padding is
// comment lines, so the fixture stays a scenario that would parse and validate
// if it were small enough: size is the only thing left to object to, and any
// other error would mean the limit is applied somewhere after the YAML decoder
// rather than before it.
func scenarioPaddedTo(t *testing.T, size int) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(minimalScenario)
	if b.Len() > size {
		t.Fatalf("the smallest scenario is %d bytes, which already exceeds %d", b.Len(), size)
	}
	const line = 121 // 120 comment characters and the newline
	for size-b.Len() > line {
		b.WriteString(strings.Repeat("#", line-1) + "\n")
	}
	// The last line closes the gap exactly. A one-byte gap is a blank line,
	// anything wider is a comment.
	if gap := size - b.Len(); gap > 0 {
		b.WriteString(strings.Repeat("#", gap-1) + "\n")
	}
	if b.Len() != size {
		t.Fatalf("padded fixture is %d bytes, want exactly %d", b.Len(), size)
	}
	return b.String()
}

// TestScenarioAtTheInputLimitIsAccepted pins the accepting side of the byte
// boundary: a scenario of exactly maxScenarioBytes still loads.
func TestScenarioAtTheInputLimitIsAccepted(t *testing.T) {
	if _, err := ParseScenario(strings.NewReader(scenarioPaddedTo(t, maxScenarioBytes))); err != nil {
		t.Fatalf("a scenario of exactly %d bytes was rejected: %v", maxScenarioBytes, err)
	}
}

// TestScenarioOneByteOverTheInputLimitIsRejected pins the rejecting side: one
// byte more than the maximum is refused for its size and nothing else.
func TestScenarioOneByteOverTheInputLimitIsRejected(t *testing.T) {
	_, err := ParseScenario(strings.NewReader(scenarioPaddedTo(t, maxScenarioBytes+1)))
	if err == nil {
		t.Fatalf("a scenario of %d bytes was accepted under a %d-byte limit",
			maxScenarioBytes+1, maxScenarioBytes)
	}
	if !strings.Contains(err.Error(), "exceeds the supported maximum") ||
		!strings.Contains(err.Error(), strconv.Itoa(maxScenarioBytes)) {
		t.Fatalf("error %q does not identify the scenario input maximum", err)
	}
}

func TestOversizedScenarioIsRejectedBeforeYAMLDecoding(t *testing.T) {
	// Far past the limit, so what the reader consumed is evidence about the
	// limit rather than about the size of the fixture.
	blob := scenarioPaddedTo(t, 4*maxScenarioBytes)
	r := &countingReader{r: strings.NewReader(blob)}
	_, err := ParseScenario(r)
	if err == nil {
		t.Fatal("an oversized scenario was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds the supported maximum") ||
		!strings.Contains(err.Error(), strconv.Itoa(maxScenarioBytes)) {
		t.Fatalf("error %q does not identify the scenario input maximum", err)
	}
	// One byte past the limit is all the decision needs, so the rest of an
	// arbitrarily large file is never read.
	if r.read > maxScenarioBytes+1 {
		t.Fatalf("read %d bytes of a %d-byte input, limit is %d",
			r.read, len(blob), maxScenarioBytes+1)
	}
}

// TestFullCardinalityScenarioFitsTheInputLimit keeps the two halves of the
// budget consistent. A byte ceiling that cannot hold a scenario populated to
// every cardinality ceiling would make the cardinalities unreachable, and the
// documented shape a lie.
func TestFullCardinalityScenarioFitsTheInputLimit(t *testing.T) {
	s := segmentedBase(maxTopologySegments)
	s.Topology.Nodes = s.Topology.Nodes[:1]
	for i := 1; i < maxTopologyNodes; i++ {
		node := Node{Name: "n" + strconv.Itoa(i), Interfaces: []Interface{
			{Segment: "s0", IPv4: fmt.Sprintf("10.77.0.%d/24", 100+i)},
		}}
		for j := 1; j < maxNodeInterfaces; j++ {
			node.Interfaces = append(node.Interfaces, Interface{
				Segment: "s" + strconv.Itoa(j),
				IPv4:    fmt.Sprintf("10.77.%d.%d/24", j, 100+i),
			})
		}
		for j := 0; j < maxNodeAliases; j++ {
			addr := netip.AddrFrom4([4]byte{192, 0, byte(i), byte(j + 1)})
			node.Aliases = append(node.Aliases, addr.String())
		}
		for j := 0; j < maxNodeServices; j++ {
			node.Services = append(node.Services, Service{Type: ServiceTCP, Port: 9000 + j})
		}
		s.Topology.Nodes = append(s.Topology.Nodes, node)
	}
	for i := 0; i < maxTopologyRoutes; i++ {
		s.Topology.Routes = append(s.Topology.Routes, Route{
			Node:        "client",
			Destination: fmt.Sprintf("198.%d.%d.0/24", 18+i/128, i%128),
			Via:         "10.77.0.101",
		})
	}
	for i := 0; i < maxScenarioFaults; i++ {
		s.Faults = append(s.Faults, Fault{Type: FaultDrop, Node: "client", Protocol: "tcp", Port: 9000 + i})
	}
	s.Tests = nil
	for i := 0; i < maxScenarioTests; i++ {
		s.Tests = append(s.Tests, Test{Node: "client", Target: "example.test:80"})
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("a scenario at every cardinality limit was rejected: %v", err)
	}
	blob, err := yaml.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) > maxScenarioBytes {
		t.Fatalf("a scenario at every cardinality limit is %d bytes, over the %d-byte input limit",
			len(blob), maxScenarioBytes)
	}
}
