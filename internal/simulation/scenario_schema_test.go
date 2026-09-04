// Guards for schema/simulation-scenario-v1.schema.json, the published JSON
// Schema for `netdoc-sim` scenario YAML.
//
// The schema describes input, which makes it a different problem from the
// report schema. A report is what the producer wrote, so its fields and their
// requiredness can be read off the structs. A scenario is what a person may
// write, and the parser accepts a good deal more than the normalized value it
// ends up with: an omitted role becomes server, an omitted or zero port becomes
// the type's default, `subnet` stands in for a whole segment list, and Go's
// decoder cannot tell a field left out from one written as its zero value. So
// requiredness here is not derived from the structs; it comes from what
// Validate actually rejects, and the tests below are arranged to catch the
// schema drifting in either direction.
//
// Every built-in scenario is validated, because those 50 files are the largest
// body of known-good input in the repository and a schema that rejects one of
// them is wrong by definition. Alongside them a set of hand-written scenarios
// covers what the built-ins do not: explicit zero values, empty collections and
// null pointer fields, each of which the parser accepts and none of which the
// schema may refuse.
//
// The other direction is covered by rejecting the same malformed input the
// parser rejects, and by two drift audits: one comparing every frozen enum with
// the Go vocabulary it came from, read out of the source rather than copied
// here, and one comparing every schema property with the yaml tags on the input
// structs, so a new field cannot silently leave the published file stale.

package simulation

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

const (
	// scenarioSchemaPath is a constant so reading it needs no gosec exemption.
	scenarioSchemaPath = "../../schema/simulation-scenario-v1.schema.json"
	scenarioSchemaID   = "https://raw.githubusercontent.com/heymaikol/network-doctor/main/schema/simulation-scenario-v1.schema.json"
)

// compileScenarioSchema parses and compiles the published file, which is what
// makes malformed schema syntax impossible to land: a broken $ref, an unknown
// keyword shape or invalid JSON fails here before any scenario is validated.
func compileScenarioSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(scenarioSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s is not valid JSON: %v", scenarioSchemaPath, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(scenarioSchemaID, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(scenarioSchemaID)
	if err != nil {
		t.Fatalf("compiling %s: %v", scenarioSchemaPath, err)
	}
	return sch
}

// validateYAML runs one scenario file through the schema. The document is
// decoded by the same library the parser uses, so the scalars the validator
// sees are the ones the scenario author actually gets, and is re-encoded as
// JSON only to hand the validator the number and string types it expects.
// Nothing here applies Scenario normalization: this is the file as written.
func validateYAML(sch *jsonschema.Schema, data []byte) error {
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	return sch.Validate(inst)
}

func TestScenarioSchemaCompiles(t *testing.T) {
	compileScenarioSchema(t)
}

// TestBuiltInScenariosValidateAgainstSchema is the schema's main obligation.
// The files are discovered through the same embedded filesystem the simulator
// loads them from, so a scenario added to the library is validated the moment
// it ships, and a failure names the file.
func TestBuiltInScenariosValidateAgainstSchema(t *testing.T) {
	sch := compileScenarioSchema(t)
	entries, err := fs.ReadDir(library, "scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(LibraryNames()) {
		t.Fatalf("read %d scenario files but the library lists %d", len(entries), len(LibraryNames()))
	}
	if len(entries) < 40 {
		t.Fatalf("only %d built-in scenarios found; the library is not being read", len(entries))
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			data, err := fs.ReadFile(library, "scenarios/"+e.Name())
			if err != nil {
				t.Fatal(err)
			}
			// Both halves of the contract on the same bytes: the parser is what
			// the schema describes, so a file only proves something when it
			// passes both.
			if _, err := ParseScenario(bytes.NewReader(data)); err != nil {
				t.Fatalf("built-in scenario does not parse: %v", err)
			}
			if err := validateYAML(sch, data); err != nil {
				t.Fatalf("built-in scenario does not validate against %s: %v", scenarioSchemaPath, err)
			}
		})
	}
}

// TestSchemaAcceptsEveryScenarioShape pins one built-in per specialized input
// shape, so the coverage above cannot quietly narrow to the simple scenarios if
// a file is renamed or removed.
func TestSchemaAcceptsEveryScenarioShape(t *testing.T) {
	sch := compileScenarioSchema(t)
	for shape, file := range map[string]string{
		"legacy single segment":  "healthy.yaml",
		"routed multi segment":   "two-router-healthy.yaml",
		"dual stack":             "dual-stack-healthy.yaml",
		"explicit routes":        "missing-subnet-route.yaml",
		"socks5 proxy":           "socks5-local-dns-fails.yaml",
		"http connect proxy":     "proxy-only-network.yaml",
		"tls certificate":        "tls-expired-certificate.yaml",
		"encrypted dns":          "encrypted-dns-blocked.yaml",
		"tcp banner":             "service-banners.yaml",
		"captive portal":         "captive-portal.yaml",
		"dns fault schedule":     "dns-hijacking.yaml",
		"scheduled faults":       "latency-spike.yaml",
		"scheduled link":         "transient-connectivity-loss.yaml",
		"pmtu blackhole":         "pmtu-blackhole.yaml",
		"campaign netem and dns": "unstable-connectivity.yaml",
		"campaign timeline":      "flapping-connectivity.yaml",
		"campaign dns delay":     "dns-timeout-boundary.yaml",
		"per test expect":        "two-router-healthy.yaml",
		"source segment":         "multiple-interfaces-wrong-preferred-route.yaml",
	} {
		t.Run(shape, func(t *testing.T) {
			data, err := fs.ReadFile(library, "scenarios/"+file)
			if err != nil {
				t.Fatalf("%s no longer exists, so the %s shape is unvalidated: %v", file, shape, err)
			}
			if err := validateYAML(sch, data); err != nil {
				t.Fatalf("%s does not validate: %v", file, err)
			}
		})
	}
}

// acceptedScenarios are inputs the parser accepts that no built-in happens to
// contain. Most of them exist because Go's decoder cannot tell an omitted field
// from one written as its zero value: the validator sees 0, false, "" or an
// empty list either way, and accepts them, so the schema has to as well. They
// are the cases that would break if the schema were tightened towards the
// normalized value a scenario ends up with rather than the file as written.
var acceptedScenarios = map[string]string{
	"minimal legacy scenario": `
name: minimal
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	"explicit zero values on a dns service": `
name: explicit-zeros
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - name: resolver
      address: 10.77.0.1
      services:
        - {type: dns, port: 0, status: 0, body: "", portal: false, doh_response: "", certificate: ~, dns_fault: ~}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	"empty collections and empty strings": `
name: empty-collections
topology:
  subnet: ""
  nodes:
    - {name: client, role: client, address: 10.77.0.10, aliases: [], interfaces: [], resolver: ""}
    - name: server
      address: 10.77.0.1
      services:
        - {type: http, zone: {}, records: [], banner: "", date_offset: "", name: ""}
faults: []
tests:
  - {node: client, name: "", type: "", target: "", source_segment: "", proxy: ~, trust: ~, expect: ~}
expect:
  verdict: ""
  summary: ""
  checks:
    - {id: iface, status: PASS, cause: "", fix: "", ipv4: "", ipv6: ""}
`,
	"null campaign": `
name: null-campaign
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
campaign: ~
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	// A netem fault reads neither direction nor protocol nor port, and the
	// validator never looks at them, so anything at all is accepted there. The
	// schema closes those three vocabularies only for the drop fault that
	// actually reads them.
	"unread drop options on a netem fault": `
name: unread-options
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
faults:
  - {type: netem, node: client, delay: 10ms, direction: sideways, protocol: sctp, port: 99999}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	// A scheduled_dns fault names a service and derives its node from it, so
	// this is the one fault type that may leave node out entirely.
	"scheduled dns fault without a node": `
name: scheduled-dns
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, resolver: 10.77.0.1}
    - name: resolver
      address: 10.77.0.1
      services:
        - {name: sched, type: dns}
faults:
  - type: scheduled_dns
    service: sched
    events:
      - {at: 0ms, outcome: delay, delay: 200ms}
      - {at: 300ms, outcome: answer, latency: "", jitter: "", loss_percent: 0, state: ""}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	// events on a non-scheduled fault are rejected only when the list is not
	// empty, so an empty one survives.
	"empty event list on an ordinary fault": `
name: empty-events
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
faults:
  - {type: no_default_route, node: client, events: []}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
	// A campaign whose loss range is left out entirely: the zero NumberRange is
	// a valid 0-to-0 sweep, so the range is not required.
	"campaign without an optional range": `
name: campaign-defaults
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
campaign:
  netem: {node: client, segment: lan, latency: {min: 1ms, max: 2ms}, jitter: {min: 0s, max: 0s}}
tests:
  - {node: client}
expect:
  checks:
    - {id: iface, status: PASS}
`,
}

// TestSchemaAcceptsWhatTheParserAccepts is the compatibility direction, and the
// one that matters most: a schema stricter than the parser rejects scenarios
// that work, which is worse than one that is merely incomplete.
func TestSchemaAcceptsWhatTheParserAccepts(t *testing.T) {
	sch := compileScenarioSchema(t)
	for name, src := range acceptedScenarios {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScenario(strings.NewReader(src)); err != nil {
				t.Fatalf("the parser rejects this, so it proves nothing about the schema: %v", err)
			}
			if err := validateYAML(sch, []byte(src)); err != nil {
				t.Errorf("the parser accepts this and the schema does not: %v", err)
			}
		})
	}
}

// rejectedScenarios are malformed inputs. Each one has to be refused by both
// halves, since a schema that accepts what `netdoc-sim validate` refuses gives
// an editor nothing to say.
var rejectedScenarios = map[string]string{
	"unknown top level key": `
name: bad
nodes: []
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown nested key": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10, hostname: c}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown route field": `
name: bad
topology:
  segments: [{name: lan, subnet: 10.77.0.0/24}]
  nodes: [{name: client, role: client, interfaces: [{segment: lan, address: 10.77.0.10/24}]}]
  routes: [{node: client, destination: default, via: 10.77.0.1, default: true}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown service type": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - {name: server, address: 10.77.0.1, services: [{type: gopher, port: 70}]}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown fault type": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
faults: [{type: unplug, node: client}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown test type": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client, type: ping}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown node role": `
name: bad
topology:
  nodes: [{name: client, role: gateway, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown probe id": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: traceroute, status: PASS}]}
`,
	"unknown status": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: BROKEN}]}
`,
	"unknown verdict": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {verdict: catastrophe, checks: [{id: iface, status: PASS}]}
`,
	"unknown cause": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: FAIL, cause: cosmic_rays}]}
`,
	"unknown family state": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS, ipv4: maybe}]}
`,
	"unknown certificate mode": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - name: server
      address: 10.77.0.1
      services: [{name: web, type: tls, port: 443, certificate: {mode: self_signed, dns_names: [a.test]}}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown drop direction": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
faults: [{type: drop, node: client, direction: sideways}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown drop protocol": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
faults: [{type: drop, node: client, protocol: sctp, port: 53}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown fault family": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
faults: [{type: no_default_route, node: client, family: ipv7}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown scheduled dns outcome": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, resolver: 10.77.0.1}
    - {name: resolver, address: 10.77.0.1, services: [{name: sched, type: dns}]}
faults: [{type: scheduled_dns, service: sched, events: [{at: 0ms, outcome: nxdomain}]}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown scheduled link state": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
faults: [{type: scheduled_link, node: client, events: [{at: 0ms, state: flapping}]}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown dns fault outcome": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - {name: resolver, address: 10.77.0.1, services: [{type: dns, dns_fault: {a: [lies]}}]}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"unknown proxy scheme": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - {name: proxy, address: 10.77.0.1, resolver: 10.77.0.1, services: [{type: socks5, port: 1080}]}
tests: [{node: client, proxy: {scheme: socks4, node: proxy, port: 1080}}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"node name is not a safe name": `
name: bad
topology:
  nodes: [{name: my_client, role: client, address: 10.77.0.10}]
tests: [{node: my_client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"missing scenario name": `
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"no tests": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: []
expect: {checks: [{id: iface, status: PASS}]}
`,
	"no nodes": `
name: bad
topology:
  nodes: []
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"expected check without a status": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{id: iface}]}
`,
	"expected check without an id": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: [{node: client}]
expect: {checks: [{status: PASS}]}
`,
	"certificate without dns names": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - name: server
      address: 10.77.0.1
      services: [{name: web, type: tls, port: 443, certificate: {mode: valid, dns_names: []}}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"service port out of range": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - {name: server, address: 10.77.0.1, services: [{type: http, port: 70000}]}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"negative route metric": `
name: bad
topology:
  segments: [{name: lan, subnet: 10.77.0.0/24}]
  nodes: [{name: client, role: client, interfaces: [{segment: lan, address: 10.77.0.10/24}]}]
  routes: [{node: client, destination: default, via: 10.77.0.1, metric: -1}]
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"duration range missing a bound": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
campaign:
  netem: {node: client, segment: lan, latency: {min: 1ms}, jitter: {min: 0s, max: 0s}}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"structurally wrong type for tests": `
name: bad
topology:
  nodes: [{name: client, role: client, address: 10.77.0.10}]
tests: everything
expect: {checks: [{id: iface, status: PASS}]}
`,
	"structurally wrong type for nodes": `
name: bad
topology:
  nodes: {client: {role: client}}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
	"structurally wrong type for a port": `
name: bad
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - {name: server, address: 10.77.0.1, services: [{type: http, port: "80"}]}
tests: [{node: client}]
expect: {checks: [{id: iface, status: PASS}]}
`,
}

func TestSchemaAndParserRejectTheSameScenarios(t *testing.T) {
	sch := compileScenarioSchema(t)
	for name, src := range rejectedScenarios {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScenario(strings.NewReader(src)); err == nil {
				t.Error("the parser accepts this, so the schema must not reject it")
			}
			if err := validateYAML(sch, []byte(src)); err == nil {
				t.Error("the schema accepts this and the parser does not")
			}
		})
	}
}

// requiredBases are valid scenarios rich enough that every key the schema calls
// required appears in one of them.
var requiredBases = map[string]string{
	"legacy": `
name: base
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10}
    - name: server
      address: 10.77.0.1
      resolver: 10.77.0.1
      services:
        - {name: web, type: tls, port: 443, certificate: {mode: valid, dns_names: [a.test]}}
        - {name: res, type: dns, records: [{name: a.test, address: 10.77.0.1}]}
        - {name: prox, type: socks5, port: 1080}
faults:
  - {type: drop, node: client, direction: outbound}
  - {type: scheduled_dns, service: res, events: [{at: 0ms, outcome: answer}]}
tests:
  - {node: client, proxy: {scheme: socks5, node: server, port: 1080}, trust: {service: web}}
expect:
  checks: [{id: iface, status: PASS}]
`,
	"routed": `
name: base
topology:
  segments: [{name: lan, subnet: 10.77.0.0/24}, {name: wan, subnet: 10.78.0.0/24}]
  nodes:
    - {name: client, role: client, interfaces: [{segment: lan, address: 10.77.0.10/24}]}
    - {name: gw, role: router, interfaces: [{segment: lan, address: 10.77.0.1/24}, {segment: wan, address: 10.78.0.1/24}]}
  routes:
    - {node: client, destination: default, via: 10.77.0.1}
tests:
  - {node: client}
expect:
  checks: [{id: iface, status: PASS}]
`,
	"campaign": `
name: base
topology:
  nodes:
    - {name: client, role: client, address: 10.77.0.10, resolver: 10.77.0.1}
    - {name: server, address: 10.77.0.1, services: [{name: res, type: dns}]}
campaign:
  runs: 2
  netem: {node: client, segment: lan, latency: {min: 1ms, max: 2ms}, jitter: {min: 0s, max: 0s}}
  dns: {service: res, queries_per_type: 4}
  dns_delay: {service: res, delay: {min: 1ms, max: 2ms}}
  timeline: {node: client, segment: lan, service: res, resolver_hold: 600ms, latency: 10ms, degrade_at: {min: 150ms, max: 350ms}, outage_for: {min: 300ms, max: 700ms}}
tests:
  - {node: client}
expect:
  checks: [{id: iface, status: PASS}]
`,
}

// requiredCases names, for one required key of one definition, a valid scenario
// and the path at which that key sits in it.
type requiredCase struct{ def, key, base, path string }

var requiredCases = []requiredCase{
	{"Scenario", "name", "legacy", "name"},
	{"Scenario", "topology", "legacy", "topology"},
	{"Scenario", "tests", "legacy", "tests"},
	{"Scenario", "expect", "legacy", "expect"},
	{"Topology", "nodes", "legacy", "topology.nodes"},
	{"Node", "name", "legacy", "topology.nodes.0.name"},
	{"Service", "type", "legacy", "topology.nodes.1.services.0.type"},
	{"TLSCertificate", "mode", "legacy", "topology.nodes.1.services.0.certificate.mode"},
	{"TLSCertificate", "dns_names", "legacy", "topology.nodes.1.services.0.certificate.dns_names"},
	{"DNSRecord", "name", "legacy", "topology.nodes.1.services.1.records.0.name"},
	{"DNSRecord", "address", "legacy", "topology.nodes.1.services.1.records.0.address"},
	{"Fault", "type", "legacy", "faults.0.type"},
	{"ScheduledEvent", "at", "legacy", "faults.1.events.0.at"},
	{"Test", "node", "legacy", "tests.0.node"},
	{"TestProxy", "scheme", "legacy", "tests.0.proxy.scheme"},
	{"TestProxy", "node", "legacy", "tests.0.proxy.node"},
	{"TestTrust", "service", "legacy", "tests.0.trust.service"},
	{"ExpectedCheck", "id", "legacy", "expect.checks.0.id"},
	{"ExpectedCheck", "status", "legacy", "expect.checks.0.status"},
	{"Segment", "name", "routed", "topology.segments.0.name"},
	{"Interface", "segment", "routed", "topology.nodes.0.interfaces.0.segment"},
	{"Route", "node", "routed", "topology.routes.0.node"},
	{"Route", "destination", "routed", "topology.routes.0.destination"},
	{"Route", "via", "routed", "topology.routes.0.via"},
	{"CampaignNetem", "node", "campaign", "campaign.netem.node"},
	{"CampaignNetem", "segment", "campaign", "campaign.netem.segment"},
	{"CampaignNetem", "latency", "campaign", "campaign.netem.latency"},
	{"CampaignNetem", "jitter", "campaign", "campaign.netem.jitter"},
	{"DurationRange", "min", "campaign", "campaign.netem.latency.min"},
	{"DurationRange", "max", "campaign", "campaign.netem.latency.max"},
	{"CampaignDNS", "service", "campaign", "campaign.dns.service"},
	{"CampaignDNS", "queries_per_type", "campaign", "campaign.dns.queries_per_type"},
	{"CampaignDNSDelay", "service", "campaign", "campaign.dns_delay.service"},
	{"CampaignDNSDelay", "delay", "campaign", "campaign.dns_delay.delay"},
	{"CampaignTimeline", "node", "campaign", "campaign.timeline.node"},
	{"CampaignTimeline", "segment", "campaign", "campaign.timeline.segment"},
	{"CampaignTimeline", "latency", "campaign", "campaign.timeline.latency"},
	{"CampaignTimeline", "degrade_at", "campaign", "campaign.timeline.degrade_at"},
	{"CampaignTimeline", "outage_for", "campaign", "campaign.timeline.outage_for"},
}

// TestSchemaRequiresOnlyWhatTheParserRequires is the requiredness audit. A
// yaml tag says nothing about whether a key can be left out, so every entry in
// every required list is justified the only way it can be: by deleting that key
// from a scenario the parser accepts and watching the parser refuse the result.
// A key the parser tolerates has no business being required, because the schema
// would then reject a scenario that works.
//
// The coverage check at the end is what keeps this honest: a required entry
// added to the published file without a case here fails, rather than going
// unexamined.
func TestSchemaRequiresOnlyWhatTheParserRequires(t *testing.T) {
	for base, src := range requiredBases {
		if _, err := ParseScenario(strings.NewReader(src)); err != nil {
			t.Fatalf("base scenario %q is not valid, so nothing below proves anything: %v", base, err)
		}
	}
	covered := map[string]bool{}
	for _, tc := range requiredCases {
		covered[tc.def+"."+tc.key] = true
		t.Run(tc.def+"."+tc.key, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(requiredBases[tc.base]), &doc); err != nil {
				t.Fatal(err)
			}
			deleteAt(t, doc, strings.Split(tc.path, "."))
			out, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseScenario(bytes.NewReader(out)); err == nil {
				t.Errorf("the parser accepts a scenario without %s, so $defs/%s must not require %q",
					tc.path, tc.def, tc.key)
			}
		})
	}

	for name, def := range scenarioSchemaDefs(t) {
		object, ok := def.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range requiredNames(t, object) {
			if !covered[name+"."+key] {
				t.Errorf("$defs/%s requires %q and nothing here shows the parser does too", name, key)
			}
		}
	}
}

// deleteAt removes the value at a path through decoded YAML, walking maps by
// key and lists by single-digit index.
func deleteAt(t *testing.T, doc any, path []string) {
	t.Helper()
	switch node := doc.(type) {
	case map[string]any:
		if len(path) == 1 {
			if _, present := node[path[0]]; !present {
				t.Fatalf("%q is not in the base scenario", path[0])
			}
			delete(node, path[0])
			return
		}
		deleteAt(t, node[path[0]], path[1:])
	case []any:
		index, err := strconv.Atoi(path[0])
		if err != nil || index >= len(node) {
			t.Fatalf("%q does not index the list", path[0])
		}
		deleteAt(t, node[index], path[1:])
	default:
		t.Fatalf("the path runs past the end of the document at %q", path[0])
	}
}

// TestSchemaEnumsMatchGoVocabularies compares each frozen enum with the Go
// declaration it describes. Where the vocabulary is a slice or a block of
// constants it is read from the package or its source rather than copied here,
// so a value added or removed fails this test instead of shipping a stale file.
func TestSchemaEnumsMatchGoVocabularies(t *testing.T) {
	defs := scenarioSchemaDefs(t)
	scenarioConsts := constPrefixes(t, "scenario.go")
	timelineConsts := constPrefixes(t, "timeline.go")
	cases := switchCases(t, "scenario.go")

	probes := make([]string, len(knownProbeIDs))
	for i, id := range knownProbeIDs {
		probes[i] = string(id)
	}
	// A scheduled resolver moves between the two outcomes it shares with the
	// per-query schedule and the two that only exist for a timeline.
	scheduledDNS := append([]string{DNSOutcomeAnswer, DNSOutcomeSERVFAIL}, timelineConsts["DNSOutcome"]...)

	for _, tt := range []struct {
		def string
		// want is the authoritative Go vocabulary. The empty string is not part
		// of any of them; allowEmpty marks the enums that carry it anyway,
		// because the parser accepts an explicitly empty value there and
		// supplies a default, or treats it as "asserts nothing".
		want       []string
		allowEmpty bool
	}{
		{def: "serviceType", want: scenarioConsts["Service"]},
		{def: "faultType", want: append(slices.Clone(scenarioConsts["Fault"]), timelineConsts["Fault"]...)},
		{def: "tlsCertificateMode", want: scenarioConsts["TLSCertificate"]},
		{def: "dnsFaultOutcome", want: scenarioConsts["DNSOutcome"]},
		{def: "dohResponse", want: scenarioConsts["DoHResponse"], allowEmpty: true},
		{def: "testType", want: scenarioConsts["Test"], allowEmpty: true},
		{def: "scheduledDNSOutcome", want: scheduledDNS, allowEmpty: true},
		{def: "linkState", want: timelineConsts["LinkState"], allowEmpty: true},
		{def: "dropDirection", want: cases["f.Direction"], allowEmpty: true},
		{def: "dropProtocol", want: cases["f.Protocol"], allowEmpty: true},
		{def: "nodeRole", want: cases["n.Role"], allowEmpty: true},
		{def: "proxyScheme", want: cases["p.Scheme"]},
		{def: "probeID", want: probes},
		{def: "status", want: statuses},
		{def: "verdict", want: verdicts, allowEmpty: true},
		{def: "cause", want: knownCauses, allowEmpty: true},
		{def: "familyState", want: []string{diagnostic.FamilyReachable, diagnostic.FamilyUnreachable}, allowEmpty: true},
	} {
		t.Run(tt.def, func(t *testing.T) {
			def, ok := defs[tt.def].(map[string]any)
			if !ok {
				t.Fatalf("the schema has no $defs/%s", tt.def)
			}
			members, ok := def["enum"].([]any)
			if !ok {
				t.Fatalf("$defs/%s has no enum", tt.def)
			}
			var got []string
			for _, v := range members {
				got = append(got, v.(string))
			}
			want := slices.Clone(tt.want)
			if len(want) == 0 {
				t.Fatalf("the Go vocabulary for %s came back empty, so this comparison proves nothing", tt.def)
			}
			// The switch that accepts an empty value spells it as a case of its
			// own; every other source of a vocabulary never contains one.
			want = slices.DeleteFunc(want, func(s string) bool { return s == "" })
			if tt.allowEmpty {
				want = append(want, "")
			}
			slices.Sort(got)
			slices.Sort(want)
			got, want = slices.Compact(got), slices.Compact(want)
			if !slices.Equal(got, want) {
				t.Errorf("$defs/%s enum is %v, and the Go vocabulary is %v", tt.def, got, want)
			}
		})
	}
}

// TestSchemaNamePatternMatchesIsSafeName is the one place the schema restates a
// Go predicate rather than a vocabulary, so the two are compared directly. The
// pattern is only worth publishing while it agrees with isSafeName exactly: a
// pattern that is looser is merely incomplete, but one that is tighter rejects
// node and segment names the simulator accepts.
func TestSchemaNamePatternMatchesIsSafeName(t *testing.T) {
	def, ok := scenarioSchemaDefs(t)["safeName"].(map[string]any)
	if !ok {
		t.Fatal("the schema has no $defs/safeName")
	}
	pattern, ok := def["pattern"].(string)
	if !ok {
		t.Fatal("$defs/safeName has no pattern")
	}
	re := regexp.MustCompile(pattern)
	maximum := int(def["maxLength"].(float64))

	for _, name := range []string{
		"", "a", "A", "0", "client", "client-lan", "target-gateway", "a-b-c",
		"-a", "a-", "-", "--", "a_b", "a.b", "a b", "a/b", "a;b", "a:b", "a$b",
		"café", "клиент", "a\nb", "0-9", "Z9",
		strings.Repeat("a", 32), strings.Repeat("a", 33), strings.Repeat("a", 64),
	} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			if got, want := re.MatchString(name) && len(name) <= maximum, isSafeName(name); got != want {
				t.Errorf("the schema pattern accepts %q = %v, and isSafeName says %v", name, got, want)
			}
		})
	}
}

// yamlInputTypes is every struct a scenario file decodes into, named rather
// than discovered, so the reflection walk below has to reach all of them.
var yamlInputTypes = []string{
	"Scenario", "Topology", "Segment", "Node", "Interface", "Route", "Service",
	"DNSRecord", "TLSCertificate", "DNSFault", "Fault", "ScheduledEvent", "Test",
	"TestProxy", "TestTrust", "Expect", "ExpectedCheck", "CampaignSpec",
	"CampaignTimeline", "CampaignDNSDelay", "CampaignNetem", "CampaignDNS",
	"DurationRange", "NumberRange",
}

// TestSchemaDescribesEveryYAMLField walks the input structs and compares their
// yaml tags with the published properties, so a new field cannot be added to a
// scenario without the schema being told about it.
//
// Requiredness is deliberately not derived here. A yaml tag says nothing about
// whether the parser needs the key: most fields are optional because their zero
// value is accepted or a default is supplied. What the schema calls required is
// checked instead by the scenarios above, which the parser accepts and which
// therefore have to validate.
func TestSchemaDescribesEveryYAMLField(t *testing.T) {
	defs := scenarioSchemaDefs(t)
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt.Name()] {
			return
		}
		seen[rt.Name()] = true
		def, ok := defs[rt.Name()].(map[string]any)
		if !ok {
			t.Errorf("$defs has no %q, so that input type is undescribed", rt.Name())
			return
		}
		properties, _ := def["properties"].(map[string]any)
		if def["additionalProperties"] != false {
			t.Errorf("$defs/%s permits additional properties, but the parser decodes with KnownFields(true)", rt.Name())
		}
		documented := map[string]bool{}
		for i := range rt.NumField() {
			field := rt.Field(i)
			// An unexported field is not decoded from YAML at all, and a "-"
			// tag makes an exported one just as invisible: the key is unknown
			// to the decoder, so publishing it would invite a scenario the
			// parser rejects.
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if field.PkgPath != "" || name == "-" {
				if _, published := properties[strings.ToLower(field.Name)]; published {
					t.Errorf("%s.%s is not decoded from YAML but the schema publishes it", rt.Name(), field.Name)
				}
				continue
			}
			if name == "" {
				t.Errorf("%s.%s has no yaml tag, so the key it decodes from is not knowable here", rt.Name(), field.Name)
				continue
			}
			documented[name] = true
			if _, ok := properties[name]; !ok {
				t.Errorf("%s.%s decodes from %q and the schema does not describe it", rt.Name(), field.Name, name)
			}
			// A map's element type is a scalar in every scenario field, so only
			// the struct-bearing kinds are worth following.
			walk(field.Type)
		}
		for name := range properties {
			if !documented[name] {
				t.Errorf("the schema describes %s.%s, which nothing decodes any more", rt.Name(), name)
			}
		}
		for _, name := range requiredNames(t, def) {
			if _, ok := properties[name]; !ok {
				t.Errorf("$defs/%s requires %q, which it does not describe", rt.Name(), name)
			}
		}
	}
	walk(reflect.TypeOf(Scenario{}))

	for _, name := range yamlInputTypes {
		if !seen[name] {
			t.Errorf("%s was never reached from Scenario, so the walk missed it", name)
		}
	}
	for name := range defs {
		// The remaining definitions are the shared scalar vocabularies, which
		// no struct owns.
		if slices.Contains(yamlInputTypes, name) {
			continue
		}
		if def, ok := defs[name].(map[string]any); ok && def["properties"] != nil {
			t.Errorf("$defs/%s describes an object that no input struct decodes", name)
		}
	}
}

func requiredNames(t *testing.T, def map[string]any) []string {
	t.Helper()
	var out []string
	names, _ := def["required"].([]any)
	for _, name := range names {
		out = append(out, name.(string))
	}
	return out
}

// scenarioSchemaDefs returns the published file's $defs, which both audits read.
func scenarioSchemaDefs(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(scenarioSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]any `json:"$defs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Defs
}

// constPrefixes groups the string constants declared in one file of this
// package by the prefix of their name, which is how the vocabularies are
// spelled here: ServiceDNS and ServiceHTTP are the service types, FaultDrop and
// FaultNetem the fault types, and so on. Reading them out of the source is what
// makes a newly declared constant fail the comparison above.
func constPrefixes(t *testing.T, file string) map[string][]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			literal, ok := stringConst(value.Values[0])
			if !ok {
				continue
			}
			name := value.Names[0].Name
			for _, prefix := range []string{
				"Service", "Fault", "TLSCertificate", "DNSOutcome", "DoHResponse", "LinkState", "Test",
			} {
				if strings.HasPrefix(name, prefix) && name != prefix {
					out[prefix] = append(out[prefix], literal)
				}
			}
		}
	}
	return out
}

// switchCases collects the string literals each switch in one file of this
// package accepts, keyed by the expression being switched on. The role, proxy
// scheme, drop direction and drop protocol vocabularies are spelled as case
// clauses rather than constants, so this is where they have to be read from.
func switchCases(t *testing.T, file string) map[string][]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		tag := types.ExprString(sw.Tag)
		for _, stmt := range sw.Body.List {
			clause, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range clause.List {
				if literal, ok := stringConst(expr); ok {
					out[tag] = append(out[tag], literal)
				}
			}
		}
		return true
	})
	return out
}

// stringConst renders a string literal, or the value of a constant in this
// package named by an identifier, so a case clause spelled either way is read.
func stringConst(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		unquoted, err := strconv.Unquote(e.Value)
		return unquoted, err == nil
	case *ast.Ident:
		return constantValues[e.Name], constantValues[e.Name] != ""
	}
	return "", false
}

// constantValues resolves the constants a case clause names instead of
// spelling its literal. Referencing the constants themselves keeps a rename a
// build failure rather than a silent gap in the comparison.
var constantValues = map[string]string{
	"DirectionOutbound":  DirectionOutbound,
	"DirectionInbound":   DirectionInbound,
	"ServiceDNS":         ServiceDNS,
	"ServiceSOCKS5":      ServiceSOCKS5,
	"ServiceHTTPConnect": ServiceHTTPConnect,
	"TestNetdoc":         TestNetdoc,
}
