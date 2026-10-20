package simulation

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

const (
	// HuntGeneratorVersion is part of every manifest and seed domain. A future
	// algorithm change must increment it instead of silently changing old cases.
	HuntGeneratorVersion = "v7"
	huntSeedDomain       = "netdoc-sim-hunt-v3"
	HuntMaxFaults        = 3
	HuntMaxCases         = 500
	HuntMaxCaseNumber    = 999999
)

// huntGeneratorVersions is every generator this build can still materialize a
// case for, oldest first. A version pins the operator universe, lane rules and
// case identity algorithm. Changing any of them adds a version here rather
// than editing one, so a shared challenge id or filed triage finding keeps
// resolving through the rules it was minted under.
//
// The seed domain is deliberately not versioned. A case seed depends on the
// base and the case number only, so every version draws the same numbers and
// they differ exactly where the operator list differs, which is the smallest
// possible difference between two generators.
//
// Literals, not HuntGeneratorVersion. A published version has to stay
// resolvable after the constant moves on, so a bump appends an entry here
// rather than replacing the last one.
var huntGeneratorVersions = []string{"v3", "v4", "v5", "v6", "v7"}

// HuntGeneratorVersions returns every generator version this build can replay.
func HuntGeneratorVersions() []string { return slices.Clone(huntGeneratorVersions) }

// huntGeneratorIndex places a version on that list. An operator with no `since`
// belongs to the first version, which is where all of them started.
func huntGeneratorIndex(version string) int {
	if version == "" {
		return 0
	}
	return slices.Index(huntGeneratorVersions, version)
}

func validateHuntGeneratorVersion(version string) error {
	if version == "" || huntGeneratorIndex(version) < 0 {
		return fmt.Errorf("unknown hunt generator version %q (have: %s)", version, strings.Join(huntGeneratorVersions, ", "))
	}
	return nil
}

type HuntLane string

const (
	HuntLaneBugOracle    HuntLane = "bug-oracle"
	HuntLaneStress       HuntLane = "stress"
	HuntLaneAllOperators HuntLane = "all"
	huntLaneFirstVersion          = "v6"
)

// HuntLaneNames returns the CLI vocabulary. The all-operator lane exists only
// for exact replay of generators published before the lane split.
func HuntLaneNames() []string {
	return []string{string(HuntLaneBugOracle), string(HuntLaneStress), string(HuntLaneAllOperators)}
}

func splitHuntGenerator(version string) bool {
	return huntGeneratorIndex(version) >= huntGeneratorIndex(huntLaneFirstVersion)
}

// ResolveHuntLane applies the deliberate command/API default. Current
// generators default to bug-oracle; historical generators default to their
// original all-operator universe.
func ResolveHuntLane(version string, lane HuntLane) (HuntLane, error) {
	if err := validateHuntGeneratorVersion(version); err != nil {
		return "", err
	}
	if lane == "" {
		if splitHuntGenerator(version) {
			lane = HuntLaneBugOracle
		} else {
			lane = HuntLaneAllOperators
		}
	}
	if splitHuntGenerator(version) {
		if lane != HuntLaneBugOracle && lane != HuntLaneStress {
			return "", fmt.Errorf("hunt generator %s requires lane %q or %q", version, HuntLaneBugOracle, HuntLaneStress)
		}
		return lane, nil
	}
	if lane != HuntLaneAllOperators {
		return "", fmt.Errorf("historical hunt generator %s requires lane %q", version, HuntLaneAllOperators)
	}
	return lane, nil
}

// resolveRecordedHuntLane accepts missing lane metadata only for artifacts from
// generators that predate lanes. A current artifact must name its lane.
func resolveRecordedHuntLane(version string, lane HuntLane) (HuntLane, error) {
	if lane == "" && splitHuntGenerator(version) {
		return "", fmt.Errorf("hunt generator %s artifact has no lane metadata", version)
	}
	return ResolveHuntLane(version, lane)
}

// Sorted: validHuntBase binary-searches this list.
var huntBaseNames = []string{"dual-stack-healthy", "healthy", "healthy-routed-network",
	"socks5h-remote-dns-succeeds", "tls-valid", "two-path-healthy", "two-path-ipv6-healthy",
	"two-router-healthy"}

// HuntBaseNames returns the deliberately small set of known-good controls the
// first generator is allowed to mutate.
func HuntBaseNames() []string { return append([]string(nil), huntBaseNames...) }

func validHuntBase(name string) bool {
	i := sort.SearchStrings(huntBaseNames, name)
	return i < len(huntBaseNames) && huntBaseNames[i] == name
}

// GeneratedMutation is a completely materialized semantic operation. It has
// no command strings, kernel interface names, paths, or deferred randomness.
type GeneratedMutation struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	Node             string `json:"node,omitempty"`
	TargetNode       string `json:"target_node,omitempty"`
	Segment          string `json:"segment,omitempty"`
	Service          string `json:"service,omitempty"`
	Family           string `json:"family,omitempty"`
	PreferredVia     string `json:"preferred_via,omitempty"`
	PreferredSegment string `json:"preferred_segment,omitempty"`
	PreferredMetric  int    `json:"preferred_metric,omitempty"`
	AlternateVia     string `json:"alternate_via,omitempty"`
	AlternateSegment string `json:"alternate_segment,omitempty"`
	AlternateMetric  int    `json:"alternate_metric,omitempty"`
	ControlTarget    string `json:"control_target,omitempty"`
	// TargetEndpoint is the address:port the client's primary test dials, which
	// is what a simulator-side dial of that endpoint is matched against. It is
	// the endpoint a mutation is about; ControlTarget stays what it has always
	// been, the endpoint whose reachability proves some other path still works.
	TargetEndpoint string `json:"target_endpoint,omitempty"`
	// RouteDestination and RouteVia describe the route a routing family acts on:
	// which route, and the next hop it ends up with. An empty RouteVia means the
	// route was taken away rather than repointed. The next hop it had before is
	// PreferredVia, which already means exactly that.
	RouteDestination string  `json:"route_destination,omitempty"`
	RouteVia         string  `json:"route_via,omitempty"`
	LossPercent      float64 `json:"loss_percent,omitempty"`
	LatencyMS        int64   `json:"latency_ms,omitempty"`
	JitterMS         int64   `json:"jitter_ms,omitempty"`
	StartMS          int64   `json:"start_ms,omitempty"`
	DurationMS       int64   `json:"duration_ms,omitempty"`
	NetemSeed        uint32  `json:"netem_seed,omitempty"`
	TargetPort       int     `json:"target_port,omitempty"`
	Status           int     `json:"status,omitempty"`
	// MTU is the size a path-MTU black hole narrows its hop to. The endpoints
	// keep their own, which is what leaves them offering packets that hop can no
	// longer carry.
	MTU int `json:"mtu,omitempty"`
}

// GeneratedCaseManifest is the stable, display-safe reproduction artifact.
type GeneratedCaseManifest struct {
	GeneratorVersion string   `json:"generator_version"`
	Lane             HuntLane `json:"lane,omitempty"`
	BaseScenario     string   `json:"base_scenario"`
	HuntSeed         int64    `json:"hunt_seed"`
	Case             int      `json:"case"`
	CaseSeed         int64    `json:"case_seed"`
	// MaxFaults is the fault ceiling this case was drawn under. It is part of
	// the experiment, not a preference: the first number drawn from the case
	// seed is how many mutations to take, and it is drawn modulo this ceiling,
	// so the same scenario, seed and case under a different ceiling is a
	// different network. It is recorded here so a reproduction command can name
	// it rather than inherit whatever the CLI default happens to be.
	MaxFaults       int                 `json:"max_faults"`
	Mutations       []GeneratedMutation `json:"mutations"`
	CaseFingerprint string              `json:"case_fingerprint"`
}

// GeneratedCase couples a public manifest to the validated scenario that will
// execute. Scenario is intentionally omitted from JSON: reports contain the
// normal simulation artifact, while the manifest is the reproduction contract.
type GeneratedCase struct {
	Manifest GeneratedCaseManifest `json:"manifest"`
	Scenario *Scenario             `json:"-"`
}

type mutationOperator struct {
	id string
	// since is the generator version this operator first appeared in. Empty
	// means the first one. An older generator does not see it at all, which is
	// what lets a new family be added without moving any case a published
	// artifact already names.
	since string
	// findingContract is the direct diagnosis comparison this operator can
	// reach. huntNoFindingContract puts it in the stress lane. It is required
	// metadata, so a new operator cannot enter the bug-oracle lane by default.
	findingContract huntFindingContract
	// oracleSince is the generator version from which findingContract counts.
	// Empty means it always did. It exists because promoting an operator into
	// the bug-oracle lane changes which universe a generator draws from, and a
	// published case has to keep materializing the mutation set it named: an
	// operator promoted here leaves every earlier generator seeing it exactly
	// where it was, in the stress lane with no contract at all.
	oracleSince  string
	description  string
	conflictTags []string
	applicable   func(*Scenario) bool
	generate     func(*mathrand.Rand, *Scenario) (GeneratedMutation, error)
}

type huntFindingContract string

const (
	huntNoFindingContract  huntFindingContract = "none"
	huntDNSFailureContract huntFindingContract = "observed_dns_failure_reported_healthy"
	huntTCPResetContract   huntFindingContract = "tcp_reset_not_distinguished"
)

// contractFor is the contract one generator version sees. Before oracleSince
// there is none, which is the whole of what a promotion changes.
func (o mutationOperator) contractFor(version string) huntFindingContract {
	if o.oracleSince != "" && huntGeneratorIndex(version) < huntGeneratorIndex(o.oracleSince) {
		return huntNoFindingContract
	}
	if o.findingContract == "" {
		return huntNoFindingContract
	}
	return o.findingContract
}

func (o mutationOperator) laneFor(version string) HuntLane {
	if o.contractFor(version) == huntNoFindingContract {
		return HuntLaneStress
	}
	return HuntLaneBugOracle
}

// huntMutationRegistry is ordered API. Selection may shuffle indices, never a
// map, and generated manifests are sorted back into this stable ID vocabulary.
var huntMutationRegistry = []mutationOperator{
	{id: "netem.loss", findingContract: huntNoFindingContract, description: "bounded packet loss", conflictTags: []string{"link-shaping"}, applicable: hasDataPath, generate: generateLoss},
	{id: "netem.latency", findingContract: huntNoFindingContract, description: "bounded path latency", conflictTags: []string{"link-shaping"}, applicable: hasDataPath, generate: generateLatency},
	{id: "netem.jitter", findingContract: huntNoFindingContract, description: "bounded path jitter", conflictTags: []string{"link-shaping"}, applicable: hasDataPath, generate: generateJitter},
	{id: "timeline.netem_spike", findingContract: huntNoFindingContract, description: "temporary latency and loss spike", conflictTags: []string{"link-shaping", "resolver-state", "timeline"}, applicable: hasTimedDataPath, generate: generateNetemSpike},
	{id: "dns.servfail", findingContract: huntDNSFailureContract, description: "resolver returns SERVFAIL", conflictTags: []string{"resolver-state"}, applicable: hasNamedResolver, generate: generateDNSSERVFAIL},
	{id: "dns.drop", findingContract: huntDNSFailureContract, description: "resolver drops responses", conflictTags: []string{"resolver-state"}, applicable: hasNamedResolver, generate: generateDNSDrop},
	{id: "timeline.dns_outage", findingContract: huntDNSFailureContract, description: "temporary resolver outage", conflictTags: []string{"resolver-state", "timeline"}, applicable: hasNamedResolver, generate: generateDNSOutage},
	{id: "service.tcp_reset", findingContract: huntTCPResetContract, description: "target accepts then resets TCP", conflictTags: []string{"target-service"}, applicable: hasHTTPTestTarget, generate: generateTCPReset},
	{id: "service.tls_expired", findingContract: huntFindingContract(ConditionTLSCertificateExpired), description: "target presents an expired TLS certificate", conflictTags: []string{"target-service"}, applicable: hasValidTLSTestTarget, generate: generateTLSExpired},
	{id: "proxy.connect_refused", findingContract: huntFindingContract(ConditionProxyDestinationRefused), description: "proxy refuses its CONNECT destination", conflictTags: []string{"proxy-state"}, applicable: hasSOCKS5TestProxy, generate: generateProxyCONNECTRefused},
	{id: "quic.udp_443_block", findingContract: huntFindingContract(ConditionQUICUDP443Blocked), description: "QUIC UDP/443 is blocked while TCP/443 remains reachable", conflictTags: []string{"quic-state"}, applicable: hasWorkingQUICFixture, generate: generateQUICUDP443Block},
	{id: "encrypted_dns.doh_invalid", findingContract: huntNoFindingContract, description: "DoH returns a protocol-invalid DNS message", conflictTags: []string{"encrypted-dns-state"}, applicable: hasWorkingDoHFixture, generate: generateInvalidDoHResponse},
	{id: "http.status_503", findingContract: huntNoFindingContract, description: "HTTP target returns status 503", conflictTags: []string{"target-service"}, applicable: hasSuccessfulHTTPTestTarget, generate: generateHTTP503},
	{id: "family.ipv4_drop", findingContract: huntFindingContract(ConditionIPv4InternetUnreachable), description: "IPv4 path fails while IPv6 remains configured", conflictTags: []string{"family-path"}, applicable: hasDualStackPath, generate: generateIPv4Drop},
	{id: "family.ipv6_drop", findingContract: huntFindingContract(ConditionIPv6InternetUnreachable), description: "IPv6 path fails while IPv4 remains configured", conflictTags: []string{"family-path"}, applicable: hasDualStackPath, generate: generateIPv6Drop},
	{id: "link.transient_down", findingContract: huntNoFindingContract, description: "temporary non-client link loss", conflictTags: []string{"path-outage", "resolver-state", "timeline"}, applicable: hasNonClientDataLink, generate: generateTransientLink},
	// Promoted into the bug-oracle lane in v7, which is what oracleSince says:
	// v3 to v6 keep drawing it from the stress lane with no contract, so no
	// published case moves. The condition it reaches is the second of netdoc's
	// four route causes the hunt can grade, and the only oracle condition the
	// two-path bases can host at all.
	{id: "routing.preferred_path_failure", findingContract: huntFindingContract(ConditionPreferredRouteFailed), oracleSince: "v7", description: "preferred path fails while an alternate remains", conflictTags: []string{"path-outage", "route-choice"}, applicable: hasPreferredPathFailureCandidate, generate: generatePreferredPathFailure},
	// v4. Appended, never interleaved: an older generator is exactly this list
	// truncated at its own version, so where a v3 case landed cannot move.
	{id: "service.connection_refused", since: "v4", findingContract: huntNoFindingContract, description: "nothing listens on the target port", conflictTags: []string{"target-service"}, applicable: hasBriefedHTTPTarget, generate: generateConnectionRefused},
	{id: "service.tcp_port_blocked", since: "v4", findingContract: huntNoFindingContract, description: "the target port silently discards inbound connections", conflictTags: []string{"target-service"}, applicable: hasBriefedHTTPTarget, generate: generateTCPPortBlocked},
	{id: "service.tls_hostname_mismatch", since: "v4", findingContract: huntFindingContract(ConditionTLSHostnameMismatch), description: "target presents a certificate for a different name", conflictTags: []string{"target-service"}, applicable: hasValidTLSTestTarget, generate: generateTLSHostnameMismatch},
	{id: "routing.no_default_route", since: "v4", findingContract: huntFindingContract(ConditionNoDefaultRoute), description: "the client's only default route is deleted", conflictTags: []string{"path-outage", "route-choice"}, applicable: hasSoleDefaultRoute, generate: generateNoDefaultRoute},
	{id: "routing.wrong_default_route", since: "v4", findingContract: huntNoFindingContract, description: "the default route is repointed at an on-link router that goes nowhere", conflictTags: []string{"path-outage", "route-choice"}, applicable: hasWrongDefaultRouteCandidate, generate: generateWrongDefaultRoute},
	{id: "routing.missing_subnet_route", since: "v4", findingContract: huntNoFindingContract, description: "the specific route to the target's subnet is removed", conflictTags: []string{"route-choice"}, applicable: hasMissingSubnetRouteCandidate, generate: generateMissingSubnetRoute},
	// v5. The condition the path-MTU probe exists for, and the one major fault
	// the hunt could not invent.
	{id: "pmtu.blackhole", since: "v5", findingContract: huntNoFindingContract, description: "a forwarding hop carries less than the endpoints offer and stays silent about it", conflictTags: []string{"link-shaping", "path-outage"}, applicable: hasPMTUBlackholeHop, generate: generatePMTUBlackhole},
}

// huntOperators is the operator list one generator version sees: this registry
// truncated at that version. Order and length are preserved, which is the whole
// point: selection draws from a permutation of the applicable list, so an
// operator appearing earlier or a list growing longer would move every case.
func huntOperators(version string) []mutationOperator {
	want := huntGeneratorIndex(version)
	out := make([]mutationOperator, 0, len(huntMutationRegistry))
	for _, op := range huntMutationRegistry {
		if index := huntGeneratorIndex(op.since); index >= 0 && index <= want {
			out = append(out, op)
		}
	}
	return out
}

func huntOperatorsForLane(version string, lane HuntLane) ([]mutationOperator, error) {
	lane, err := ResolveHuntLane(version, lane)
	if err != nil {
		return nil, err
	}
	operators := huntOperators(version)
	if lane == HuntLaneAllOperators {
		return operators, nil
	}
	return slices.DeleteFunc(operators, func(op mutationOperator) bool { return op.laneFor(version) != lane }), nil
}

// DeriveHuntCaseSeed makes case N independent of every earlier PRNG stream.
func DeriveHuntCaseSeed(seed int64, base string, caseNumber int) int64 {
	h := sha256.New()
	h.Write([]byte(huntSeedDomain))
	h.Write([]byte{0})
	var raw [8]byte
	// #nosec G115 -- two's-complement seed bits are part of the reproduction contract.
	binary.BigEndian.PutUint64(raw[:], uint64(seed))
	h.Write(raw[:])
	h.Write([]byte{0})
	h.Write([]byte(base))
	h.Write([]byte{0})
	// #nosec G115 -- deterministic seed derivation hashes the stable two's-complement bits of every case number, including negatives; no numeric value is narrowed.
	binary.BigEndian.PutUint64(raw[:], uint64(caseNumber))
	h.Write(raw[:])
	// #nosec G115 -- all 64 hash bits are intentionally preserved in the signed seed.
	return int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
}

// generateHuntCase is the same thing at a named version, which is what an
// artifact minted under an older generator has to be replayed through.
func generateHuntCase(version, baseID string, base *Scenario, huntSeed int64, caseNumber, maxFaults int) (*GeneratedCase, error) {
	return generateHuntCaseInLane(version, "", baseID, base, huntSeed, caseNumber, maxFaults)
}

func generateHuntCaseInLane(version string, lane HuntLane, baseID string, base *Scenario, huntSeed int64, caseNumber, maxFaults int) (*GeneratedCase, error) {
	if err := validateHuntGeneratorVersion(version); err != nil {
		return nil, err
	}
	lane, err := ResolveHuntLane(version, lane)
	if err != nil {
		return nil, err
	}
	if !validHuntBase(baseID) {
		return nil, fmt.Errorf("unsupported hunt base %q (have: %s)", baseID, strings.Join(huntBaseNames, ", "))
	}
	if base == nil {
		return nil, errors.New("hunt base scenario is nil")
	}
	if caseNumber < 0 || caseNumber > HuntMaxCaseNumber {
		return nil, fmt.Errorf("case must be between 0 and %d", HuntMaxCaseNumber)
	}
	if maxFaults < 1 || maxFaults > HuntMaxFaults {
		return nil, fmt.Errorf("max faults must be between 1 and %d", HuntMaxFaults)
	}
	validatedBase := cloneScenario(base)
	canonicalScenarioInput(validatedBase)
	if err := validatedBase.Validate(); err != nil {
		return nil, fmt.Errorf("base scenario: %w", err)
	}
	caseSeed := DeriveHuntCaseSeed(huntSeed, baseID, caseNumber)
	// #nosec G404 -- hunt cases must reproduce exactly from their published seed.
	rng := mathrand.New(mathrand.NewSource(caseSeed))
	var applicable []mutationOperator
	operators, err := huntOperatorsForLane(version, lane)
	if err != nil {
		return nil, err
	}
	for _, op := range operators {
		if op.applicable(validatedBase) {
			applicable = append(applicable, op)
		}
	}
	if len(applicable) == 0 {
		return nil, fmt.Errorf("base scenario %q has no applicable %s hunt mutations", baseID, lane)
	}
	want := 1 + rng.Intn(min(maxFaults, len(applicable)))
	perm := rng.Perm(len(applicable))
	selected := make([]mutationOperator, 0, want)
	for _, index := range perm {
		candidate := applicable[index]
		if operatorsCompatible(selected, candidate) {
			selected = append(selected, candidate)
			if len(selected) == want {
				break
			}
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("no compatible hunt mutation could be selected")
	}
	mutations := make([]GeneratedMutation, 0, len(selected))
	for _, op := range selected {
		mutation, err := op.generate(rng, validatedBase)
		if err != nil {
			return nil, fmt.Errorf("generate %s: %w", op.id, err)
		}
		mutation.ID = op.id
		if mutation.Description == "" {
			mutation.Description = op.description
		}
		mutations = append(mutations, mutation)
	}
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].ID < mutations[j].ID })
	generated := cloneScenario(validatedBase)
	generated.Campaign = nil
	for _, mutation := range mutations {
		if err := applyGeneratedMutation(generated, mutation); err != nil {
			return nil, fmt.Errorf("apply %s: %w", mutation.ID, err)
		}
	}
	generated.Name = fmt.Sprintf("hunt-%s-%d", baseID, caseNumber)
	generated.Description = fmt.Sprintf("Generated by netdoc-sim hunt %s from %s case %d.", version, baseID, caseNumber)
	canonicalScenarioInput(generated)
	if err := generated.Validate(); err != nil {
		return nil, fmt.Errorf("generated scenario validation: %w", err)
	}
	manifestLane := lane
	if lane == HuntLaneAllOperators {
		// Published v3-v5 manifests had no lane field. Keep them byte-for-byte
		// compatible; their generator version resolves the missing value to all.
		manifestLane = ""
	}
	manifest := GeneratedCaseManifest{GeneratorVersion: version, Lane: manifestLane, BaseScenario: baseID,
		HuntSeed: huntSeed, Case: caseNumber, CaseSeed: caseSeed, MaxFaults: maxFaults, Mutations: mutations}
	manifest.CaseFingerprint = huntCaseFingerprint(manifest)
	return &GeneratedCase{Manifest: manifest, Scenario: generated}, nil
}

// Validate normalizes compatibility shorthands into explicit fields. A loaded
// scenario therefore carries both views in memory and cannot be passed to
// Validate a second time verbatim. This removes only those derived aliases,
// then ordinary validation reconstructs them. The source base is never touched.
func canonicalScenarioInput(s *Scenario) {
	if len(s.Topology.Segments) == 0 {
		return
	}
	s.Topology.Subnet = ""
	for i := range s.Topology.Segments {
		if s.Topology.Segments[i].IPv4 != "" {
			s.Topology.Segments[i].Subnet = ""
		}
	}
	for ni := range s.Topology.Nodes {
		node := &s.Topology.Nodes[ni]
		if len(node.Interfaces) == 0 {
			continue
		}
		node.Address, node.Gateway = "", ""
		for ii := range node.Interfaces {
			if node.Interfaces[ii].IPv4 != "" {
				node.Interfaces[ii].Address = ""
			}
		}
	}
}

func operatorsCompatible(selected []mutationOperator, candidate mutationOperator) bool {
	for _, existing := range selected {
		for _, a := range existing.conflictTags {
			for _, b := range candidate.conflictTags {
				if a == b {
					return false
				}
			}
		}
	}
	return true
}

func huntCaseFingerprint(manifest GeneratedCaseManifest) string {
	if splitHuntGenerator(manifest.GeneratorVersion) {
		semantic := struct {
			Version   string              `json:"version"`
			Lane      HuntLane            `json:"lane"`
			Base      string              `json:"base"`
			Case      int                 `json:"case"`
			Mutations []GeneratedMutation `json:"mutations"`
		}{manifest.GeneratorVersion, manifest.Lane, manifest.BaseScenario, manifest.Case, manifest.Mutations}
		blob, _ := json.Marshal(semantic)
		sum := sha256.Sum256(blob)
		return hex.EncodeToString(sum[:8])
	}
	// Keep the exact pre-lane fingerprint input for v3-v5 artifacts.
	semantic := struct {
		Version   string              `json:"version"`
		Base      string              `json:"base"`
		Mutations []GeneratedMutation `json:"mutations"`
	}{manifest.GeneratorVersion, manifest.BaseScenario, manifest.Mutations}
	blob, _ := json.Marshal(semantic)
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:8])
}

func int64n(rng *mathrand.Rand, minValue, maxValue int64) int64 {
	if minValue == maxValue {
		return minValue
	}
	return minValue + rng.Int63n(maxValue-minValue+1)
}

func nonzeroUint32(rng *mathrand.Rand) uint32 {
	v := rng.Uint32()
	if v == 0 {
		return 1
	}
	return v
}

func dataPathTarget(s *Scenario) (string, string, bool) {
	for _, node := range s.Topology.Nodes {
		if node.Role != "router" {
			continue
		}
		for _, iface := range node.Interfaces {
			if iface.Segment == "upstream" {
				return node.Name, iface.Segment, true
			}
		}
	}
	for _, node := range s.Topology.Nodes {
		if node.Role == "client" && len(node.Interfaces) > 0 {
			return node.Name, node.Interfaces[0].Segment, true
		}
	}
	return "", "", false
}

func hasDataPath(s *Scenario) bool { _, _, ok := dataPathTarget(s); return ok }

func namedResolver(s *Scenario) (string, bool) {
	var resolver string
	for _, node := range s.Topology.Nodes {
		if node.Role == "client" {
			resolver = node.Resolver
			break
		}
	}
	for _, node := range s.Topology.Nodes {
		if resolver != "" && !nodeOwnsAddress(node, resolver) {
			continue
		}
		for _, service := range node.Services {
			if service.Type == ServiceDNS && service.Name != "" {
				return service.Name, true
			}
		}
	}
	return "", false
}

func nodeOwnsAddress(node Node, raw string) bool {
	want, err := netip.ParseAddr(raw)
	if err != nil {
		return false
	}
	for _, iface := range node.Interfaces {
		for _, candidate := range []string{iface.Address, iface.IPv4, iface.IPv6} {
			address, _, _ := strings.Cut(candidate, "/")
			if got, err := netip.ParseAddr(address); err == nil && got == want {
				return true
			}
		}
	}
	for _, candidate := range node.Aliases {
		if got, err := netip.ParseAddr(candidate); err == nil && got == want {
			return true
		}
	}
	return false
}

func hasNamedResolver(s *Scenario) bool { _, ok := namedResolver(s); return ok }

func hasTimedDataPath(s *Scenario) bool { return hasDataPath(s) && hasNamedResolver(s) }

func nonClientDataLink(s *Scenario) (string, string, bool) {
	for _, node := range s.Topology.Nodes {
		if node.Role != "router" {
			continue
		}
		for _, iface := range node.Interfaces {
			if iface.Segment == "upstream" {
				return node.Name, iface.Segment, true
			}
		}
	}
	return "", "", false
}

func hasNonClientDataLink(s *Scenario) bool { _, _, ok := nonClientDataLink(s); return ok }

func dualStackGateway(s *Scenario) (string, bool) {
	for _, node := range s.Topology.Nodes {
		if node.Role != "router" {
			continue
		}
		for _, iface := range node.Interfaces {
			if iface.IPv4 != "" && iface.IPv6 != "" {
				return node.Name, true
			}
		}
	}
	return "", false
}

func hasDualStackPath(s *Scenario) bool { _, ok := dualStackGateway(s); return ok }

type httpTarget struct {
	node    string
	service int
	port    int
}

// findHTTPTestTarget returns the first HTTP service one of tests names. tests
// is a parameter rather than s.Tests so a caller can ask the narrower question
// of what one particular test is pointed at.
func findHTTPTestTarget(s *Scenario, tests []Test) (httpTarget, bool) {
	for _, test := range tests {
		target, err := diagnostic.ParseTarget(test.Target)
		if err != nil {
			continue
		}
		if target.Proto != diagnostic.ProtoHTTP {
			continue
		}
		address := target.Host
		if target.IP == nil {
			address = dnsAddress(s, target.Host)
		}
		for ni, node := range s.Topology.Nodes {
			if address == "" || !nodeOwnsAddress(node, address) {
				continue
			}
			for si, service := range node.Services {
				if service.Type == ServiceHTTP && service.Port == target.Port {
					return httpTarget{node: s.Topology.Nodes[ni].Name, service: si, port: target.Port}, true
				}
			}
		}
	}
	return httpTarget{}, false
}

func dnsAddress(s *Scenario, name string) string {
	for _, address := range scenarioTargetAddresses(s, &diagnostic.Target{Host: name}) {
		if parsed, err := netip.ParseAddr(address); err == nil && parsed.Is4() {
			return address
		}
	}
	return ""
}

func hasHTTPTestTarget(s *Scenario) bool { _, ok := findHTTPTestTarget(s, s.Tests); return ok }

func hasSuccessfulHTTPTestTarget(s *Scenario) bool {
	target, ok := findHTTPTestTarget(s, s.Tests)
	return ok && s.Topology.node(target.node).Services[target.service].Status/100 == 2
}

type serviceTarget struct{ node, service string }

func findValidTLSTestTarget(s *Scenario) (serviceTarget, bool) {
	for _, test := range s.Tests {
		if test.Trust == nil {
			continue
		}
		target, err := diagnostic.ParseTarget(test.Target)
		if err != nil || target.Proto != diagnostic.ProtoTLSHTTP {
			continue
		}
		address := target.Host
		if target.IP == nil {
			address = dnsAddress(s, target.Host)
		}
		for _, node := range s.Topology.Nodes {
			if address == "" || !nodeOwnsAddress(node, address) {
				continue
			}
			for _, service := range node.Services {
				if service.Name == test.Trust.Service && service.Type == ServiceTLS && service.Port == target.Port &&
					service.Certificate != nil && service.Certificate.Mode == TLSCertificateValid &&
					target.IP == nil && certificateCoversHost(service.Certificate, target.Host) {
					return serviceTarget{node.Name, service.Name}, true
				}
			}
		}
	}
	return serviceTarget{}, false
}

func hasValidTLSTestTarget(s *Scenario) bool { _, ok := findValidTLSTestTarget(s); return ok }

type proxyTarget struct{ node, service, targetNode string }

const proxyCONNECTTarget = diagnostic.ConnectivityProbeHost

func findSOCKS5TestProxy(s *Scenario) (proxyTarget, bool) {
	for _, test := range s.Tests {
		if test.Proxy == nil || test.Proxy.Scheme != "socks5h" {
			continue
		}
		for _, node := range s.Topology.Nodes {
			if node.Name != test.Proxy.Node {
				continue
			}
			for _, service := range node.Services {
				if service.Type != ServiceSOCKS5 || service.Port != test.Proxy.Port {
					continue
				}
				address := ""
				for _, resolver := range node.Services {
					if resolver.Type != ServiceDNS {
						continue
					}
					for name, candidate := range resolver.Zone {
						if dnsKey(name) == dnsKey(proxyCONNECTTarget) {
							address = candidate
						}
					}
				}
				for _, destination := range s.Topology.Nodes {
					if !nodeOwnsAddress(destination, address) {
						continue
					}
					for _, target := range destination.Services {
						if target.Type == ServiceTCP && target.Port == 443 {
							return proxyTarget{node.Name, service.Name, destination.Name}, true
						}
					}
				}
			}
		}
	}
	return proxyTarget{}, false
}

func hasSOCKS5TestProxy(s *Scenario) bool { _, ok := findSOCKS5TestProxy(s); return ok }

func certificateCoversHost(certificate *TLSCertificate, host string) bool {
	for _, name := range certificate.DNSNames {
		if dnsKey(name) == dnsKey(host) {
			return true
		}
	}
	return false
}

func findProbeFixture(s *Scenario, serviceType, name, certificateHost string) (serviceTarget, bool) {
	for _, node := range s.Topology.Nodes {
		for _, service := range node.Services {
			if service.Type == serviceType && service.Name == name && service.Port == 443 &&
				service.Certificate != nil && service.Certificate.Mode == TLSCertificateValid &&
				certificateCoversHost(service.Certificate, certificateHost) {
				return serviceTarget{node.Name, service.Name}, true
			}
		}
	}
	return serviceTarget{}, false
}

func hasWorkingQUICFixture(s *Scenario) bool {
	target, ok := findProbeFixture(s, ServiceQUIC, quicProbeService, proxyCONNECTTarget)
	if !ok {
		return false
	}
	if !nodeOwnsAddress(*s.Topology.node(target.node), dnsAddress(s, proxyCONNECTTarget)) {
		return false
	}
	for _, fault := range s.Faults {
		if fault.Type == FaultDrop && fault.Node == target.node && fault.Direction == DirectionInbound &&
			fault.Protocol == "udp" && fault.Port == 443 {
			return false
		}
	}
	return true
}

func hasWorkingDoHFixture(s *Scenario) bool {
	target, ok := findProbeFixture(s, ServiceEncryptedDNS, encryptedDNSProbeService, diagnostic.EncryptedDNSHost)
	if !ok {
		return false
	}
	for _, node := range s.Topology.Nodes {
		if node.Name != target.node {
			continue
		}
		for _, service := range node.Services {
			if service.Name == target.service {
				return service.DoHResponse == ""
			}
		}
	}
	return false
}

type routeFamily string

const (
	familyIPv4 routeFamily = "ipv4"
	familyIPv6 routeFamily = "ipv6"
)

type preferredPathCandidate struct {
	family                    routeFamily
	preferred, alternate      Route
	preferredRouter, upstream string
	controlTarget             string
}

func hasWorkingAlternatePath(s *Scenario, family routeFamily) bool {
	_, ok := findPreferredPathCandidate(s, family)
	return ok
}

func hasPreferredPathFailureCandidate(s *Scenario) bool {
	return hasWorkingAlternatePath(s, familyIPv4) || hasWorkingAlternatePath(s, familyIPv6)
}

func findPreferredPathCandidate(s *Scenario, family routeFamily) (preferredPathCandidate, bool) {
	client := clientNode(s)
	var defaults []Route
	for _, route := range s.Topology.Routes {
		if route.Default && route.Node == client && route.Family == string(family) {
			defaults = append(defaults, route)
		}
	}
	sort.SliceStable(defaults, func(i, j int) bool { return defaults[i].Metric < defaults[j].Metric })
	if len(defaults) < 2 || defaults[0].Metric == defaults[1].Metric {
		return preferredPathCandidate{}, false
	}
	preferred := defaults[0]
	preferredRouter, _, upstream, ok := routeGatewayPath(s, preferred, family)
	if !ok {
		return preferredPathCandidate{}, false
	}
	for _, alternate := range defaults[1:] {
		if alternate.Metric <= preferred.Metric || alternate.Via == preferred.Via {
			continue
		}
		alternateRouter, alternateSegment, alternateUpstream, alternateOK := routeGatewayPath(s, alternate, family)
		if !alternateOK || alternateRouter == preferredRouter || alternateSegment == mustRouteSegment(s, preferred) ||
			alternateUpstream == upstream {
			continue
		}
		control, controlOK := controlledTargetOnRoute(s, client, family, alternate)
		if controlOK {
			return preferredPathCandidate{family: family, preferred: preferred, alternate: alternate,
				preferredRouter: preferredRouter, upstream: upstream, controlTarget: control}, true
		}
	}
	return preferredPathCandidate{}, false
}

func routeGatewayPath(s *Scenario, route Route, family routeFamily) (router, clientSegment, upstream string, ok bool) {
	via, err := netip.ParseAddr(route.Via)
	if err != nil || addressFamily(via) != string(family) {
		return "", "", "", false
	}
	clientSegment, ok = nodeSegmentForAddress(s.Topology.node(route.Node), via)
	if !ok {
		return "", "", "", false
	}
	for _, node := range s.Topology.Nodes {
		if node.Role != "router" || !nodeOwnsAddress(node, route.Via) {
			continue
		}
		if gatewaySegment, owns := nodeSegmentForAddress(&node, via); !owns || gatewaySegment != clientSegment {
			continue
		}
		for _, iface := range node.Interfaces {
			if iface.Segment != clientSegment {
				if _, familyOK := iface.addressForFamily(string(family)); familyOK {
					return node.Name, clientSegment, iface.Segment, true
				}
			}
		}
	}
	return "", "", "", false
}

func mustRouteSegment(s *Scenario, route Route) string {
	segment, _ := nodeSegmentForAddress(s.Topology.node(route.Node), netip.MustParseAddr(route.Via))
	return segment
}

func controlledTargetOnRoute(s *Scenario, client string, family routeFamily, want Route) (string, bool) {
	for _, test := range s.Tests {
		target, err := diagnostic.ParseTarget(test.Target)
		if err != nil || test.Node != client || target.IP == nil || addressFamily(netip.MustParseAddr(target.IP.String())) != string(family) ||
			!scenarioControlledTCPPort(s, target.IP.String(), target.Port) {
			continue
		}
		selected, ok := configuredRouteTo(s.Topology.Routes, client, netip.MustParseAddr(target.IP.String()))
		if ok && selected.Via == want.Via {
			// #nosec G115 -- ParseTarget already restricts ports to 1..65535.
			return netip.AddrPortFrom(netip.MustParseAddr(target.IP.String()), uint16(target.Port)).String(), true
		}
	}
	return "", false
}

func scenarioControlledTCPPort(s *Scenario, address string, port int) bool {
	for _, node := range s.Topology.Nodes {
		if !nodeOwnsAddress(node, address) {
			continue
		}
		for _, service := range node.Services {
			if service.Port == port && service.Type != ServiceQUIC {
				return true
			}
		}
	}
	return false
}

func configuredRouteTo(routes []Route, node string, destination netip.Addr) (Route, bool) {
	bestBits := -1
	var best Route
	for _, route := range routes {
		if route.Node != node || route.Family != addressFamily(destination) {
			continue
		}
		bits := 0
		if !route.Default {
			prefix, err := netip.ParsePrefix(route.Destination)
			if err != nil || !prefix.Contains(destination) {
				continue
			}
			bits = prefix.Bits()
		}
		if bits > bestBits || bits == bestBits && route.Metric < best.Metric {
			bestBits, best = bits, route
		}
	}
	return best, bestBits >= 0
}

func clientNode(s *Scenario) string {
	for _, node := range s.Topology.Nodes {
		if node.Role == "client" {
			return node.Name
		}
	}
	return ""
}

func generateLoss(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, segment, _ := dataPathTarget(s)
	loss := float64(int64n(rng, 500, 3000)) / 100
	return GeneratedMutation{Node: node, Segment: segment, LossPercent: loss, NetemSeed: nonzeroUint32(rng),
		Description: fmt.Sprintf("inject %.2f%% packet loss on %s/%s", loss, node, segment)}, nil
}

func generateLatency(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, segment, _ := dataPathTarget(s)
	latency := int64n(rng, 50, 800)
	return GeneratedMutation{Node: node, Segment: segment, LatencyMS: latency,
		Description: fmt.Sprintf("add %d ms latency on %s/%s", latency, node, segment)}, nil
}

func generateJitter(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, segment, _ := dataPathTarget(s)
	jitter := int64n(rng, 10, 250)
	latency := int64n(rng, jitter+10, 800)
	return GeneratedMutation{Node: node, Segment: segment, LatencyMS: latency, JitterMS: jitter, NetemSeed: nonzeroUint32(rng),
		Description: fmt.Sprintf("add %d ms latency with %d ms jitter on %s/%s", latency, jitter, node, segment)}, nil
}

func generateNetemSpike(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, segment, _ := dataPathTarget(s)
	start := int64n(rng, 150, 250)
	duration := int64n(rng, 700, 1200)
	latency := int64n(rng, 300, 800)
	loss := float64(int64n(rng, 500, 3000)) / 100
	service, _ := namedResolver(s)
	return GeneratedMutation{Node: node, Segment: segment, Service: service, StartMS: start, DurationMS: duration,
		LatencyMS: latency, LossPercent: loss, NetemSeed: nonzeroUint32(rng),
		Description: fmt.Sprintf("spike %s/%s to %d ms latency and %.2f%% loss for %d ms", node, segment, latency, loss, duration)}, nil
}

func generateDNSSERVFAIL(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	service, _ := namedResolver(s)
	return GeneratedMutation{Service: service, Description: "make resolver " + service + " return SERVFAIL"}, nil
}

func generateDNSDrop(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	service, _ := namedResolver(s)
	return GeneratedMutation{Service: service, Description: "make resolver " + service + " drop responses"}, nil
}

func generateDNSOutage(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	service, _ := namedResolver(s)
	duration := int64n(rng, 450, 900)
	return GeneratedMutation{Service: service, StartMS: 150, DurationMS: duration,
		Description: fmt.Sprintf("delay, then silence resolver %s for %d ms before recovery", service, duration)}, nil
}

func generateTCPReset(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findHTTPTestTarget(s, s.Tests)
	return GeneratedMutation{Node: target.node, TargetPort: target.port,
		Description: fmt.Sprintf("replace %s TCP port %d with an accept-then-reset service", target.node, target.port)}, nil
}

func generateTLSExpired(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findValidTLSTestTarget(s)
	return GeneratedMutation{Node: target.node, Service: target.service,
		Description: "make TLS service " + target.service + " present an expired certificate"}, nil
}

func generateProxyCONNECTRefused(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findSOCKS5TestProxy(s)
	return GeneratedMutation{Node: target.node, TargetNode: target.targetNode, Service: target.service, TargetPort: 443,
		Description: "make proxy " + target.service + " return CONNECT refused for " + target.targetNode + " TCP/443"}, nil
}

func generateQUICUDP443Block(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findProbeFixture(s, ServiceQUIC, quicProbeService, proxyCONNECTTarget)
	return GeneratedMutation{Node: target.node, Service: target.service, TargetPort: 443,
		Description: "silently drop inbound QUIC UDP/443 at " + target.node + " while preserving TCP/443"}, nil
}

func generateInvalidDoHResponse(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findProbeFixture(s, ServiceEncryptedDNS, encryptedDNSProbeService, diagnostic.EncryptedDNSHost)
	return GeneratedMutation{Node: target.node, Service: target.service,
		Description: "make DoH service " + target.service + " return protocol-invalid DNS bytes while preserving DoT"}, nil
}

func generateHTTP503(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, _ := findHTTPTestTarget(s, s.Tests)
	return GeneratedMutation{Node: target.node, TargetPort: target.port, Status: http.StatusServiceUnavailable,
		Description: fmt.Sprintf("make %s HTTP port %d return status 503", target.node, target.port)}, nil
}

func generateIPv4Drop(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, _ := dualStackGateway(s)
	return GeneratedMutation{Node: node, Family: "ipv4", Description: "drop IPv4 forwarding at " + node + " while preserving IPv6"}, nil
}

func generateIPv6Drop(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, _ := dualStackGateway(s)
	return GeneratedMutation{Node: node, Family: "ipv6", Description: "drop IPv6 forwarding at " + node + " while preserving IPv4"}, nil
}

func generateTransientLink(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	node, segment, _ := nonClientDataLink(s)
	duration := int64n(rng, 450, 900)
	return GeneratedMutation{Node: node, Segment: segment, DurationMS: duration,
		Description: fmt.Sprintf("lower non-client link %s/%s for %d ms, then restore it", node, segment, duration)}, nil
}

func generatePreferredPathFailure(rng *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	var candidates []preferredPathCandidate
	for _, family := range []routeFamily{familyIPv4, familyIPv6} {
		if candidate, ok := findPreferredPathCandidate(s, family); ok {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		return GeneratedMutation{}, errors.New("preferred default route with a working alternate disappeared")
	}
	candidate := candidates[0]
	if len(candidates) > 1 {
		candidate = candidates[rng.Intn(len(candidates))]
	}
	return GeneratedMutation{Node: candidate.preferredRouter, TargetNode: clientNode(s), Segment: candidate.upstream,
		Family: string(candidate.family), PreferredVia: candidate.preferred.Via,
		PreferredSegment: mustRouteSegment(s, candidate.preferred), PreferredMetric: candidate.preferred.Metric,
		AlternateVia: candidate.alternate.Via, AlternateSegment: mustRouteSegment(s, candidate.alternate),
		AlternateMetric: candidate.alternate.Metric, ControlTarget: candidate.controlTarget,
		Description: fmt.Sprintf("disable %s preferred router %s upstream %s while retaining the alternate default", candidate.family, candidate.preferredRouter, candidate.upstream)}, nil
}

// --- v4 families: the target's own port, and the client's own route table ---

// briefedHTTPTarget is the HTTP service the client's primary test names, which
// is the only target a fault may be placed on: a fault on some other test's
// target is a clue the briefing never showed and a question the graded netdoc
// run never asked. Asking the primary test directly is what makes these
// families fair by construction rather than by a later eligibility check.
func briefedHTTPTarget(s *Scenario) (httpTarget, bool) {
	primary, ok := primaryTest(s)
	if !ok {
		return httpTarget{}, false
	}
	return findHTTPTestTarget(s, []Test{primary})
}

func hasBriefedHTTPTarget(s *Scenario) bool {
	_, ok := briefedHTTPTarget(s)
	return ok && briefedTargetEndpoint(s) != ""
}

// briefedTargetEndpoint is the address:port the client dials for the primary
// test, resolved from the scenario's own zone. It is what the simulator's
// independent dial of that endpoint is matched against, so it uses the same
// rule that dial does: scenario-owned addresses only, lowest sorted first.
func briefedTargetEndpoint(s *Scenario) string {
	primary, ok := primaryTest(s)
	if !ok {
		return ""
	}
	target, err := diagnostic.ParseTarget(primary.Target)
	if err != nil {
		return ""
	}
	var owned []string
	for _, raw := range scenarioTargetAddresses(s, target) {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		// #nosec G115 -- ParseTarget already restricts ports to 1..65535.
		owned = append(owned, netip.AddrPortFrom(addr, uint16(target.Port)).String())
	}
	if len(owned) == 0 {
		return ""
	}
	sort.Strings(owned)
	return owned[0]
}

// scenarioTargetAddresses resolves a target to every address a scenario node
// owns for it, sorted. Names are looked up in the scenario's own zone rather
// than through anybody's resolver.
func scenarioTargetAddresses(s *Scenario, target *diagnostic.Target) []string {
	var found []string
	if target.IP != nil {
		found = []string{target.IP.String()}
	} else {
		for _, node := range s.Topology.Nodes {
			for _, service := range node.Services {
				if service.Type != ServiceDNS {
					continue
				}
				for name, raw := range service.Zone {
					if dnsKey(name) == dnsKey(target.Host) {
						found = append(found, raw)
					}
				}
				for _, record := range service.Records {
					if dnsKey(record.Name) == dnsKey(target.Host) {
						found = append(found, record.Address)
					}
				}
			}
		}
	}
	owned := make([]string, 0, len(found))
	for _, raw := range found {
		addr, err := netip.ParseAddr(raw)
		if err != nil || slices.Contains(owned, addr.String()) {
			continue
		}
		for _, node := range s.Topology.Nodes {
			if nodeOwnsAddress(node, addr.String()) {
				owned = append(owned, addr.String())
				break
			}
		}
	}
	sort.Strings(owned)
	return owned
}

func generateConnectionRefused(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, ok := briefedHTTPTarget(s)
	if !ok {
		return GeneratedMutation{}, errors.New("the briefed HTTP target disappeared")
	}
	return GeneratedMutation{Node: target.node, TargetPort: target.port, TargetEndpoint: briefedTargetEndpoint(s),
		Description: fmt.Sprintf("take the listener off %s TCP port %d so the host answers connections with a refusal",
			target.node, target.port)}, nil
}

func generateTCPPortBlocked(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, ok := briefedHTTPTarget(s)
	if !ok {
		return GeneratedMutation{}, errors.New("the briefed HTTP target disappeared")
	}
	return GeneratedMutation{Node: target.node, TargetPort: target.port, TargetEndpoint: briefedTargetEndpoint(s),
		Description: fmt.Sprintf("silently discard inbound TCP port %d at %s while the host stays up",
			target.port, target.node)}, nil
}

// tlsMismatchedDNSName is the name a mismatched certificate is reissued for. It
// is a fixed non-name so the certificate cannot accidentally cover anything the
// scenario resolves, which is the whole condition being generated.
const tlsMismatchedDNSName = "not-the-requested-name.test"

func generateTLSHostnameMismatch(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	target, ok := findValidTLSTestTarget(s)
	if !ok {
		return GeneratedMutation{}, errors.New("valid TLS target disappeared")
	}
	return GeneratedMutation{Node: target.node, Service: target.service,
		Description: "reissue TLS service " + target.service + " for " + tlsMismatchedDNSName +
			", a name the client is not asking for"}, nil
}

// clientDefaults reports the client's default next hops per address family,
// covering both spellings a scenario may use: explicit default routes, and the
// single-segment `gateway:` shorthand that never becomes one.
func clientDefaults(s *Scenario) (string, map[routeFamily][]string) {
	client := clientNode(s)
	out := map[routeFamily][]string{}
	if client == "" {
		return "", out
	}
	for _, route := range s.Topology.Routes {
		if route.Node == client && route.Default {
			family := routeFamily(route.Family)
			out[family] = append(out[family], route.Via)
		}
	}
	if len(out) > 0 {
		return client, out
	}
	if node := s.Topology.node(client); node != nil && node.Gateway != "" {
		if addr, err := netip.ParseAddr(node.Gateway); err == nil {
			out[routeFamily(addressFamily(addr))] = []string{addr.String()}
		}
	}
	return client, out
}

// soleDefaultRoute is the client's one default route in the one family it has
// defaults in. Both halves matter. A client with defaults in two families that
// loses one has lost a family, not its way out, and a client with two defaults
// in one family that loses one still has the other, and either would be a
// different fault wearing this one's name.
func soleDefaultRoute(s *Scenario) (client string, family routeFamily, via, segment string, ok bool) {
	client, defaults := clientDefaults(s)
	if len(defaults) != 1 {
		return "", "", "", "", false
	}
	for candidateFamily, vias := range defaults {
		if len(vias) != 1 {
			return "", "", "", "", false
		}
		addr, err := netip.ParseAddr(vias[0])
		if err != nil {
			return "", "", "", "", false
		}
		segment, ok := nodeSegmentForAddress(s.Topology.node(client), addr)
		if !ok {
			return "", "", "", "", false
		}
		return client, candidateFamily, vias[0], segment, true
	}
	return "", "", "", "", false
}

func hasSoleDefaultRoute(s *Scenario) bool {
	_, _, _, _, ok := soleDefaultRoute(s)
	return ok
}

func generateNoDefaultRoute(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	client, family, via, segment, ok := soleDefaultRoute(s)
	if !ok {
		return GeneratedMutation{}, errors.New("the client's single default route disappeared")
	}
	return GeneratedMutation{Node: client, Family: string(family), RouteDestination: "default",
		PreferredVia: via, PreferredSegment: segment,
		Description: "delete the " + string(family) + " default route on " + client}, nil
}

// routerReachesPrefix reports whether this router has any configured way to a
// prefix: an interface on it, or a route covering it. It is a question about
// the scenario rather than about a run, and it is what makes "wrong" mean
// something: a next hop that does reach the destination is a working gateway,
// however unusual a choice it would be.
func routerReachesPrefix(s *Scenario, router string, prefix netip.Prefix) bool {
	node := s.Topology.node(router)
	if node == nil {
		return false
	}
	for _, iface := range node.Interfaces {
		for _, family := range []string{"ipv4", "ipv6"} {
			if owned, ok := iface.addressForFamily(family); ok && prefixesOverlap(owned.Masked(), prefix) {
				return true
			}
		}
	}
	for _, route := range s.Topology.Routes {
		if route.Node != router {
			continue
		}
		if route.Default {
			return true
		}
		if configured, err := netip.ParsePrefix(route.Destination); err == nil && prefixesOverlap(configured, prefix) {
			return true
		}
	}
	return false
}

func routerReachesInternet(s *Scenario, router string, family routeFamily) bool {
	for _, endpoint := range internetEndpointsForFamily(string(family)) {
		addr, err := netip.ParseAddr(endpoint)
		if err != nil {
			continue
		}
		if routerReachesPrefix(s, router, netip.PrefixFrom(addr, addr.BitLen())) {
			return true
		}
	}
	return false
}

// controlOnSpecificRoute is a client test target that a non-default route
// carries through the named next hop. Non-default is the point: it is the one
// endpoint whose reachability survives the default being taken away or
// repointed, so it can prove that next hop still forwards while the default's
// own path does not.
func controlOnSpecificRoute(s *Scenario, client string, family routeFamily, via string) (string, bool) {
	for _, test := range s.Tests {
		target, err := diagnostic.ParseTarget(test.Target)
		if err != nil || test.Node != client || target.IP == nil {
			continue
		}
		addr, err := netip.ParseAddr(target.IP.String())
		if err != nil || addressFamily(addr) != string(family) || !scenarioControlledTCPPort(s, addr.String(), target.Port) {
			continue
		}
		selected, ok := configuredRouteTo(s.Topology.Routes, client, addr)
		if ok && !selected.Default && selected.Via == via {
			// #nosec G115 -- ParseTarget already restricts ports to 1..65535.
			return netip.AddrPortFrom(addr, uint16(target.Port)).String(), true
		}
	}
	return "", false
}

type wrongDefaultRouteCandidate struct {
	client, segment, control string
	family                   routeFamily
	correctVia, wrongVia     string
}

// findWrongDefaultRouteCandidate looks for a second router on the client's own
// link that answers but cannot reach the internet. The router the default
// already names is skipped, and so is any router that can reach the internet
// endpoints, since a default pointed at those would still work, which is not this
// fault.
func findWrongDefaultRouteCandidate(s *Scenario) (wrongDefaultRouteCandidate, bool) {
	client, family, via, segment, ok := soleDefaultRoute(s)
	if !ok {
		return wrongDefaultRouteCandidate{}, false
	}
	control, ok := controlOnSpecificRoute(s, client, family, via)
	if !ok {
		return wrongDefaultRouteCandidate{}, false
	}
	for _, node := range s.Topology.Nodes {
		if node.Role != "router" {
			continue
		}
		for _, iface := range node.Interfaces {
			owned, hasAddress := iface.addressForFamily(string(family))
			if iface.Segment != segment || !hasAddress || owned.Addr().String() == via ||
				routerReachesInternet(s, node.Name, family) {
				continue
			}
			return wrongDefaultRouteCandidate{client: client, segment: segment, control: control,
				family: family, correctVia: via, wrongVia: owned.Addr().String()}, true
		}
	}
	return wrongDefaultRouteCandidate{}, false
}

func hasWrongDefaultRouteCandidate(s *Scenario) bool {
	_, ok := findWrongDefaultRouteCandidate(s)
	return ok
}

func generateWrongDefaultRoute(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	candidate, ok := findWrongDefaultRouteCandidate(s)
	if !ok {
		return GeneratedMutation{}, errors.New("an on-link router that goes nowhere disappeared")
	}
	return GeneratedMutation{Node: candidate.client, Family: string(candidate.family), RouteDestination: "default",
		PreferredVia: candidate.correctVia, PreferredSegment: candidate.segment, RouteVia: candidate.wrongVia,
		ControlTarget: candidate.control,
		Description: fmt.Sprintf("repoint the %s default route on %s from %s to on-link router %s, which goes nowhere",
			candidate.family, candidate.client, candidate.correctVia, candidate.wrongVia)}, nil
}

type missingSubnetRouteCandidate struct {
	client, segment, control string
	family                   routeFamily
	destination, via         string
}

// findMissingSubnetRouteCandidate looks for a specific route the briefed target
// genuinely depends on: one the client needs because its default gateway has no
// way to that prefix. A route whose destination the default would reach anyway
// is not a route anything depends on, and removing it would change nothing.
func findMissingSubnetRouteCandidate(s *Scenario) (missingSubnetRouteCandidate, bool) {
	client, family, defaultVia, segment, ok := soleDefaultRoute(s)
	if !ok {
		return missingSubnetRouteCandidate{}, false
	}
	control, ok := controlOnSpecificRoute(s, client, family, defaultVia)
	if !ok {
		return missingSubnetRouteCandidate{}, false
	}
	defaultRouter, ok := routerOwning(s, defaultVia)
	if !ok {
		return missingSubnetRouteCandidate{}, false
	}
	endpoint := briefedTargetEndpoint(s)
	target, err := netip.ParseAddrPort(endpoint)
	if err != nil || addressFamily(target.Addr()) != string(family) {
		return missingSubnetRouteCandidate{}, false
	}
	for _, route := range s.Topology.Routes {
		if route.Node != client || route.Default || route.Via == defaultVia {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(target.Addr()) || routerReachesPrefix(s, defaultRouter, prefix) {
			continue
		}
		return missingSubnetRouteCandidate{client: client, segment: segment, control: control, family: family,
			destination: route.Destination, via: route.Via}, true
	}
	return missingSubnetRouteCandidate{}, false
}

func routerOwning(s *Scenario, address string) (string, bool) {
	for _, node := range s.Topology.Nodes {
		if node.Role == "router" && nodeOwnsAddress(node, address) {
			return node.Name, true
		}
	}
	return "", false
}

func hasMissingSubnetRouteCandidate(s *Scenario) bool {
	_, ok := findMissingSubnetRouteCandidate(s)
	return ok
}

// --- v5: the path-MTU black hole ---

// huntBlackholeMTU is the size a generated black hole narrows its hop to. Fixed
// at the smallest datagram every IPv4 host must accept, which is the widest
// margin the schema allows below the 1500-byte MTU the endpoints keep, so no
// full-size segment the client offers can cross the hop.
const huntBlackholeMTU = minBlackholeMTU

// pmtuBlackholeHop is the forwarding hop the client reaches its briefed target
// through, and the interface that hop forwards out of. Both halves matter. A
// black hole is a transit condition, so narrowing an endpoint would only make
// the local kernel refuse the send, and narrowing a hop the path-MTU probe's
// bulk write never crosses would leave that write untouched.
type pmtuBlackholeHop struct{ router, segment string }

// findPMTUBlackholeHop walks the client's own route to the briefed endpoint to
// the first router, then takes that router's one interface off the client's
// link. Exactly one, so which way it forwards is read rather than guessed: a
// router with two ways onward would need the choice made from its own table,
// which is a different question from the one this family asks.
//
// IPv4 only. minIPv6MTU is the floor IPv6 requires of a link, so a hop carrying
// IPv6 cannot be narrowed to anything an IPv6 sender would not already fit
// inside, and a black hole that black-holes nothing is not this fault.
func findPMTUBlackholeHop(s *Scenario) (pmtuBlackholeHop, bool) {
	client := clientNode(s)
	if client == "" {
		return pmtuBlackholeHop{}, false
	}
	target, err := netip.ParseAddrPort(briefedTargetEndpoint(s))
	if err != nil || !target.Addr().Is4() {
		return pmtuBlackholeHop{}, false
	}
	route, ok := configuredRouteTo(s.Topology.Routes, client, target.Addr())
	if !ok {
		return pmtuBlackholeHop{}, false
	}
	via, err := netip.ParseAddr(route.Via)
	if err != nil {
		return pmtuBlackholeHop{}, false
	}
	clientSegment, ok := nodeSegmentForAddress(s.Topology.node(client), via)
	if !ok {
		return pmtuBlackholeHop{}, false
	}
	// routerOwning already requires the router role, which is what the schema
	// requires of a black-holing hop for the same reason.
	router, ok := routerOwning(s, route.Via)
	if !ok {
		return pmtuBlackholeHop{}, false
	}
	var egress []Interface
	for _, iface := range s.Topology.node(router).Interfaces {
		if iface.Segment != clientSegment {
			egress = append(egress, iface)
		}
	}
	if len(egress) != 1 {
		return pmtuBlackholeHop{}, false
	}
	if _, carriesIPv6 := egress[0].addressForFamily("ipv6"); carriesIPv6 {
		return pmtuBlackholeHop{}, false
	}
	return pmtuBlackholeHop{router: router, segment: egress[0].Segment}, true
}

func hasPMTUBlackholeHop(s *Scenario) bool {
	_, ok := findPMTUBlackholeHop(s)
	return ok
}

func generatePMTUBlackhole(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	hop, ok := findPMTUBlackholeHop(s)
	if !ok {
		return GeneratedMutation{}, errors.New("the forwarding hop to the briefed target disappeared")
	}
	client := clientNode(s)
	return GeneratedMutation{Node: hop.router, Segment: hop.segment, TargetNode: client, MTU: huntBlackholeMTU,
		Description: fmt.Sprintf("narrow %s/%s to %d bytes and swallow the fragmentation-needed replies about it, leaving %s offering packets that hop cannot carry",
			hop.router, hop.segment, huntBlackholeMTU, client)}, nil
}

func generateMissingSubnetRoute(_ *mathrand.Rand, s *Scenario) (GeneratedMutation, error) {
	candidate, ok := findMissingSubnetRouteCandidate(s)
	if !ok {
		return GeneratedMutation{}, errors.New("the briefed target's specific route disappeared")
	}
	return GeneratedMutation{Node: candidate.client, Family: string(candidate.family),
		RouteDestination: candidate.destination, PreferredVia: candidate.via, PreferredSegment: candidate.segment,
		ControlTarget: candidate.control, TargetEndpoint: briefedTargetEndpoint(s),
		Description: fmt.Sprintf("remove the %s route to %s via %s on %s, leaving only a default that cannot reach it",
			candidate.family, candidate.destination, candidate.via, candidate.client)}, nil
}

func applyGeneratedMutation(s *Scenario, m GeneratedMutation) error {
	switch m.ID {
	case "netem.loss", "netem.latency", "netem.jitter":
		fault := Fault{Type: FaultNetem, Node: m.Node, Segment: m.Segment, Seed: m.NetemSeed}
		if m.LatencyMS > 0 {
			fault.Delay = (time.Duration(m.LatencyMS) * time.Millisecond).String()
		}
		if m.JitterMS > 0 {
			fault.Jitter = (time.Duration(m.JitterMS) * time.Millisecond).String()
		}
		if m.LossPercent > 0 {
			fault.Loss = formatPercent(m.LossPercent)
		}
		s.Faults = append(s.Faults, fault)
	case "timeline.netem_spike":
		end := m.StartMS + m.DurationMS
		s.Faults = append(s.Faults,
			Fault{Type: FaultScheduledDNS, Service: m.Service, Events: []ScheduledEvent{
				{At: "0ms", Outcome: DNSOutcomeDelay, Delay: "300ms"},
				{At: (time.Duration(end) * time.Millisecond).String(), Outcome: DNSOutcomeAnswer},
			}},
			Fault{Type: FaultScheduledNetem, Node: m.Node, Segment: m.Segment, Seed: m.NetemSeed, Events: []ScheduledEvent{
				{At: "0ms"},
				{At: (time.Duration(m.StartMS) * time.Millisecond).String(), Latency: (time.Duration(m.LatencyMS) * time.Millisecond).String(), LossPercent: m.LossPercent},
				{At: (time.Duration(end) * time.Millisecond).String()},
			}},
		)
	case "dns.servfail":
		s.Faults = append(s.Faults, Fault{Type: FaultScheduledDNS, Service: m.Service,
			Events: []ScheduledEvent{{At: "0ms", Outcome: DNSOutcomeSERVFAIL}}})
	case "dns.drop":
		s.Faults = append(s.Faults, Fault{Type: FaultScheduledDNS, Service: m.Service,
			Events: []ScheduledEvent{{At: "0ms", Outcome: DNSOutcomeDrop}}})
	case "timeline.dns_outage":
		end := m.StartMS + m.DurationMS
		s.Faults = append(s.Faults, Fault{Type: FaultScheduledDNS, Service: m.Service, Events: []ScheduledEvent{
			{At: "0ms", Outcome: DNSOutcomeDelay, Delay: "200ms"},
			{At: (time.Duration(m.StartMS) * time.Millisecond).String(), Outcome: DNSOutcomeDrop},
			{At: (time.Duration(end) * time.Millisecond).String(), Outcome: DNSOutcomeAnswer},
		}})
		if len(s.Tests) > 0 {
			base := cloneTest(s.Tests[0])
			first, second, third := cloneTest(base), cloneTest(base), cloneTest(base)
			first.Name = "hunt resolver before outage"
			second.Name = "hunt resolver during outage"
			third.Name = "hunt resolver after recovery"
			s.Tests = []Test{first, second, third}
		}
	case "service.tcp_reset":
		for ni := range s.Topology.Nodes {
			if s.Topology.Nodes[ni].Name != m.Node {
				continue
			}
			for si := range s.Topology.Nodes[ni].Services {
				service := &s.Topology.Nodes[ni].Services[si]
				if service.Type == ServiceHTTP && service.Port == m.TargetPort {
					service.Type, service.Status, service.Body = ServiceTCPReset, 0, ""
					return nil
				}
			}
		}
		return errors.New("HTTP target disappeared")
	case "service.tls_expired":
		for ni := range s.Topology.Nodes {
			for si := range s.Topology.Nodes[ni].Services {
				service := &s.Topology.Nodes[ni].Services[si]
				if s.Topology.Nodes[ni].Name == m.Node && service.Name == m.Service && service.Type == ServiceTLS &&
					service.Certificate != nil && service.Certificate.Mode == TLSCertificateValid {
					service.Certificate.Mode = TLSCertificateExpired
					return nil
				}
			}
		}
		return errors.New("valid TLS target disappeared")
	case "proxy.connect_refused":
		for ni := range s.Topology.Nodes {
			if s.Topology.Nodes[ni].Name != m.TargetNode {
				continue
			}
			for si, service := range s.Topology.Nodes[ni].Services {
				if service.Type == ServiceTCP && service.Port == m.TargetPort {
					s.Topology.Nodes[ni].Services = append(s.Topology.Nodes[ni].Services[:si], s.Topology.Nodes[ni].Services[si+1:]...)
					return nil
				}
			}
		}
		return errors.New("proxy CONNECT destination disappeared")
	case "quic.udp_443_block":
		s.Faults = append(s.Faults, Fault{Type: FaultDrop, Node: m.Node, Direction: DirectionInbound,
			Protocol: "udp", Port: m.TargetPort})
	case "encrypted_dns.doh_invalid":
		for ni := range s.Topology.Nodes {
			for si := range s.Topology.Nodes[ni].Services {
				service := &s.Topology.Nodes[ni].Services[si]
				if s.Topology.Nodes[ni].Name == m.Node && service.Name == m.Service && service.Type == ServiceEncryptedDNS && service.DoHResponse == "" {
					service.DoHResponse = DoHResponseInvalid
					return nil
				}
			}
		}
		return errors.New("working DoH fixture disappeared")
	case "http.status_503":
		for ni := range s.Topology.Nodes {
			if s.Topology.Nodes[ni].Name != m.Node {
				continue
			}
			for si := range s.Topology.Nodes[ni].Services {
				service := &s.Topology.Nodes[ni].Services[si]
				if service.Type == ServiceHTTP && service.Port == m.TargetPort && service.Status/100 == 2 {
					service.Status = m.Status
					return nil
				}
			}
		}
		return errors.New("successful HTTP target disappeared")
	case "family.ipv4_drop", "family.ipv6_drop":
		s.Faults = append(s.Faults, Fault{Type: FaultDrop, Node: m.Node, Family: m.Family, Direction: DirectionOutbound})
	case "link.transient_down":
		s.Faults = append(s.Faults, Fault{Type: FaultScheduledLink, Node: m.Node, Segment: m.Segment, Events: []ScheduledEvent{
			{At: "0ms", State: LinkStateDown},
			{At: (time.Duration(m.DurationMS) * time.Millisecond).String(), State: LinkStateUp},
		}})
	case "routing.preferred_path_failure":
		s.Faults = append(s.Faults, Fault{Type: FaultLinkDown, Node: m.Node, Segment: m.Segment})
	// A refusal is the absence of a listener, not a rule that rejects: the host
	// is up and its kernel answers the SYN with a reset because nothing is bound
	// there. Anything else would be a filter wearing a refusal's clothes.
	case "service.connection_refused":
		for ni := range s.Topology.Nodes {
			if s.Topology.Nodes[ni].Name != m.Node {
				continue
			}
			for si, service := range s.Topology.Nodes[ni].Services {
				if service.Type == ServiceHTTP && service.Port == m.TargetPort {
					s.Topology.Nodes[ni].Services = append(s.Topology.Nodes[ni].Services[:si], s.Topology.Nodes[ni].Services[si+1:]...)
					return nil
				}
			}
		}
		return errors.New("HTTP target disappeared")
	// Inbound at the target, and deliberately not scoped to one address: the
	// port is filtered for every family the host answers on, so a dual-stack
	// name cannot be half blocked.
	case "service.tcp_port_blocked":
		s.Faults = append(s.Faults, Fault{Type: FaultDrop, Node: m.Node, Direction: DirectionInbound,
			Protocol: "tcp", Port: m.TargetPort})
	case "service.tls_hostname_mismatch":
		for ni := range s.Topology.Nodes {
			for si := range s.Topology.Nodes[ni].Services {
				service := &s.Topology.Nodes[ni].Services[si]
				if s.Topology.Nodes[ni].Name == m.Node && service.Name == m.Service && service.Type == ServiceTLS &&
					service.Certificate != nil && service.Certificate.Mode == TLSCertificateValid {
					service.Certificate.Mode = TLSCertificateHostnameMismatch
					service.Certificate.DNSNames = []string{tlsMismatchedDNSName}
					return nil
				}
			}
		}
		return errors.New("valid TLS target disappeared")
	case "routing.no_default_route":
		s.Faults = append(s.Faults, Fault{Type: FaultNoDefaultRoute, Node: m.Node, Family: m.Family})
	case "routing.wrong_default_route":
		s.Faults = append(s.Faults, Fault{Type: FaultReplaceDefaultRoute, Node: m.Node, Via: m.RouteVia, Family: m.Family})
	// One fault, not two: the schema pairs the narrowed hop with the suppressed
	// fragmentation-needed replies, because narrowing alone is a small link that
	// gets discovered and worked around rather than a black hole. Nothing is
	// done to the endpoints, which is what leaves them offering full-size
	// packets to a hop that can no longer carry them.
	case "pmtu.blackhole":
		s.Faults = append(s.Faults, Fault{Type: FaultPMTUBlackhole, Node: m.Node, Segment: m.Segment, MTU: m.MTU})
	// Removed from the topology rather than deleted by a fault: there is no
	// route the client ever had, which is what a machine that was configured
	// without one looks like. The kernel table read back at the end is what
	// proves it, either way.
	case "routing.missing_subnet_route":
		for i, route := range s.Topology.Routes {
			if route.Node == m.Node && route.Destination == m.RouteDestination && route.Via == m.PreferredVia {
				s.Topology.Routes = append(s.Topology.Routes[:i], s.Topology.Routes[i+1:]...)
				return nil
			}
		}
		return errors.New("the briefed target's specific route disappeared")
	default:
		return fmt.Errorf("unknown generated mutation %q", m.ID)
	}
	return nil
}

func cloneTest(in Test) Test {
	out := in
	if in.Proxy != nil {
		copy := *in.Proxy
		out.Proxy = &copy
	}
	if in.Trust != nil {
		copy := *in.Trust
		out.Trust = &copy
	}
	if in.Expect != nil {
		copy := *in.Expect
		copy.Checks = append([]ExpectedCheck(nil), in.Expect.Checks...)
		out.Expect = &copy
	}
	return out
}
