package routepath

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// PolicySelector names a proposed attachment of a recorded policy. Existing
// policy replacement is refused because its baseline semantics are not captured.
type PolicySelector struct {
	Node      string `json:"node"`
	VRF       string `json:"vrf"`
	Direction string `json:"direction"`
	Peer      string `json:"peer"`
	Policy    string `json:"policy"`
}

// ParsePolicySelector reads five explicit colon-separated names. This producer
// supports IPv4 peers only, so no address delimiter is ambiguous.
func ParsePolicySelector(spec string) (PolicySelector, error) {
	parts := strings.Split(spec, ":")
	if len(parts) != 5 {
		return PolicySelector{}, errors.New("policy selector must be node:vrf:import|export:peer:policy")
	}
	s := PolicySelector{parts[0], parts[1], parts[2], parts[3], parts[4]}
	return s, s.Validate()
}

// PolicyCapture embeds an unmodified FRR transcript. SHA256 proves integrity,
// not the authenticity of the operator's source or collection time.
type PolicyCapture struct {
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
	FRRVersion  string    `json:"frr_version"`
	Command     string    `json:"command"`
	SHA256      string    `json:"sha256"`
	Raw         string    `json:"raw"`
}

// PolicyChange carries candidate policy definitions and baseline BGP evidence.
// The verified producer and supported subset are documented in bgp/policy/README.md.
type PolicyChange struct {
	PolicySelector
	Captures []PolicyCapture `json:"captures"`
}

func (p *PolicyChange) UnmarshalJSON(data []byte) error {
	if err := CheckPolicyDocument(data); err != nil {
		return err
	}
	type wire PolicyChange
	var w wire
	if err := policyObject(data, &w, "node", "vrf", "direction", "peer", "policy", "captures"); err != nil {
		return err
	}
	*p = PolicyChange(w)
	return nil
}

func (c *PolicyCapture) UnmarshalJSON(data []byte) error {
	type wire PolicyCapture
	var w wire
	if err := policyObject(data, &w, "source", "collected_at", "frr_version", "command", "sha256", "raw"); err != nil {
		return err
	}
	*c = PolicyCapture(w)
	return nil
}

// CheckPolicyDocument checks the containing topology only when it opts into
// policy evidence. Legacy topology decoding keeps its existing acceptance set.
func CheckPolicyDocument(data []byte) error {
	if len(data) > policyMaxBytes || !utf8.Valid(data) {
		return errors.New("policy document exceeds its byte limit or is not UTF-8")
	}
	return checkPolicyJSON(data)
}

type PolicyRoute struct {
	Prefix             string `json:"prefix"`
	SelectedBefore     string `json:"selected_before"`
	SelectionAfter     string `json:"selection_after"`
	AdvertisementAfter string `json:"advertisement_after,omitempty"`
	Outcome            string `json:"outcome"`
	Reason             string `json:"reason"`
}

type PolicySupport struct {
	Source      string    `json:"source"`
	CollectedAt time.Time `json:"collected_at"`
	Command     string    `json:"command"`
	SHA256      string    `json:"sha256"`
}

// PolicyEvaluation names the applying node only. Unknown selections never name
// an alternate; downstream BGP propagation and forwarding are not recomputed.
type PolicyEvaluation struct {
	PolicySelector
	Considered      int             `json:"considered"`
	Unchanged       int             `json:"unchanged"`
	Affected        int             `json:"affected"`
	UnrecordedAfter string          `json:"unrecorded_after"`
	Routes          []PolicyRoute   `json:"routes"`
	Evidence        []PolicySupport `json:"evidence"`
}

func (s PolicySelector) Validate() error {
	for _, v := range []string{s.Node, s.VRF, s.Policy} {
		if v == "" || !utf8.ValidString(v) || textsafe.Clean(v) != v || strings.TrimSpace(v) != v {
			return errors.New("policy selector needs clean node, vrf, and policy names")
		}
	}
	if s.Direction != "import" && s.Direction != "export" {
		return errors.New("policy direction must be import or export")
	}
	if !policyIPv4(s.Peer) {
		return errors.New("policy peer must be a canonical unicast IPv4 address")
	}
	// The verified producer queries the default IPv4 unicast instance only.
	if s.VRF != "default" {
		return errors.New("policy evidence producer supports only the default VRF")
	}
	return nil
}

const policyMapCommand = "show route-map json"
const policyListCommand = "show ip prefix-list json"

func policyBody(c PolicyCapture, node, command string, enabled bool) ([]byte, error) {
	if c.Source == "" || strings.TrimSpace(c.Source) != c.Source || textsafe.Clean(c.Source) != c.Source || !utf8.ValidString(c.Source) || c.CollectedAt.IsZero() || c.FRRVersion != "10.7.0" || c.Command != command {
		return nil, errors.New("policy capture needs a clean source, collection time, FRR 10.7.0, and exact command")
	}
	if len(c.Raw) > policyMaxBytes || !utf8.ValidString(c.Raw) {
		return nil, errors.New("policy transcript exceeds its byte limit or is not UTF-8")
	}
	sum := sha256.Sum256([]byte(c.Raw))
	if hex.EncodeToString(sum[:]) != c.SHA256 {
		return nil, errors.New("policy transcript SHA-256 mismatch")
	}
	prompt := node + "> "
	if enabled {
		prompt = node + "# "
	}
	head, tail := command+"\r\n", "\r\n"+prompt
	if !strings.HasPrefix(c.Raw, head) || !strings.HasSuffix(c.Raw, tail) || len(c.Raw) < len(head)+len(tail) {
		return nil, errors.New("policy transcript command or node prompt mismatch")
	}
	body := []byte(c.Raw[len(head) : len(c.Raw)-len(tail)])
	if err := checkPolicyJSON(body); err != nil {
		return nil, err
	}
	return body, nil
}

// policyObject refuses unknown clause keys as well as spelling changes. Metrics
// and counters listed here are telemetry; no unrecognized field supplies semantics.
func policyObject(data []byte, out any, keys ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return errors.New("policy evidence needs a JSON object")
	}
	for k, v := range fields {
		if !slices.Contains(keys, k) || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("unsupported or null policy field %q", k)
		}
	}
	return json.Unmarshal(data, out)
}

type policyRule struct {
	Sequence uint32   `json:"sequenceNumber"`
	Type     string   `json:"type"`
	Match    []string `json:"matchClauses"`
	Set      []string `json:"setClauses"`
	Action   string   `json:"action"`
	Invoked  uint64   `json:"invoked"`
	CPU      uint64   `json:"cpuTimeMS"`
	list     string
	weight   *uint32
}

type policyPrefix struct {
	Sequence uint32 `json:"sequenceNumber"`
	Type     string `json:"type"`
	Prefix   string `json:"prefix"`
}

func policyRules(body []byte, name string) ([]policyRule, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(body, &all); err != nil || all[name] == nil {
		return nil, errors.New("named route-map is missing")
	}
	var m struct {
		Invoked   uint64            `json:"invoked"`
		Disabled  bool              `json:"disabledOptimization"`
		Processed *bool             `json:"processedChange"`
		CPU       uint64            `json:"cpuTimeMS"`
		Rules     []json.RawMessage `json:"rules"`
	}
	if err := policyObject(all[name], &m, "invoked", "disabledOptimization", "processedChange", "cpuTimeMS", "rules"); err != nil {
		return nil, err
	}
	if m.Processed == nil || *m.Processed || len(m.Rules) == 0 {
		return nil, errors.New("route-map is incomplete or has a pending change")
	}
	var rules []policyRule
	var last uint32
	for _, raw := range m.Rules {
		var r policyRule
		if err := policyObject(raw, &r, "sequenceNumber", "type", "matchClauses", "setClauses", "action", "invoked", "cpuTimeMS"); err != nil {
			return nil, err
		}
		if r.Sequence <= last || r.Sequence > 65535 || r.Match == nil || r.Set == nil || (r.Type != "permit" && r.Type != "deny") || r.Action != "Exit routemap" || len(r.Match) > 1 || len(r.Set) > 1 {
			return nil, errors.New("route-map rules are incomplete, ambiguous, unordered, or unsupported")
		}
		last = r.Sequence
		if len(r.Match) == 1 {
			const prefix = "ip address prefix-list "
			r.list = strings.TrimPrefix(r.Match[0], prefix)
			if !strings.HasPrefix(r.Match[0], prefix) || r.list == "" || strings.ContainsAny(r.list, " \t\r\n") {
				return nil, errors.New("only one exact IPv4 prefix-list match is supported")
			}
		}
		if len(r.Set) == 1 {
			const prefix = "weight "
			val := strings.TrimPrefix(r.Set[0], prefix)
			n, err := strconv.ParseUint(val, 10, 16)
			if !strings.HasPrefix(r.Set[0], prefix) || err != nil || strconv.FormatUint(n, 10) != val || r.Type != "permit" {
				return nil, errors.New("only a canonical permit weight assignment is supported")
			}
			v := uint32(n)
			r.weight = &v
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func policyLists(body []byte, rules []policyRule) (map[string]map[netip.Prefix]bool, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(body, &all); err != nil || all == nil {
		return nil, errors.New("prefix-list evidence needs an object")
	}
	lists := map[string]map[netip.Prefix]bool{}
	for _, r := range rules {
		if r.list == "" || lists[r.list] != nil {
			continue
		}
		var list struct {
			Family  string            `json:"addressFamily"`
			Entries []json.RawMessage `json:"entries"`
		}
		if err := policyObject(all[r.list], &list, "addressFamily", "entries"); err != nil {
			return nil, err
		}
		if list.Family != "IPv4" || len(list.Entries) == 0 {
			return nil, errors.New("referenced IPv4 prefix-list is incomplete")
		}
		var last uint32
		lists[r.list] = map[netip.Prefix]bool{}
		for _, raw := range list.Entries {
			var e policyPrefix
			if err := policyObject(raw, &e, "sequenceNumber", "type", "prefix"); err != nil {
				return nil, err
			}
			p, err := netip.ParsePrefix(e.Prefix)
			if e.Sequence <= last || err != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != e.Prefix || (e.Type != "permit" && e.Type != "deny") {
				return nil, errors.New("prefix-list entry is incomplete, ambiguous, or noncanonical")
			}
			last = e.Sequence
			if _, exists := lists[r.list][p]; !exists {
				lists[r.list][p] = e.Type == "permit"
			}
		}
	}
	return lists, nil
}

func policyAction(prefix netip.Prefix, rules []policyRule, lists map[string]map[netip.Prefix]bool) (bool, *uint32) {
	for _, r := range rules {
		match := r.list == ""
		if r.list != "" {
			match = lists[r.list][prefix]
		}
		if match {
			return r.Type == "permit", r.weight
		}
	}
	return false, nil // FRR's implicit final deny.
}

// EvaluatePolicy reads the recorded candidate policy against an unfiltered
// baseline table. It never runs BGP bestpath or correlates a BGP path to a FIB.
func EvaluatePolicy(change PolicyChange) (PolicyEvaluation, error) {
	s := change.PolicySelector
	if err := s.Validate(); err != nil {
		return PolicyEvaluation{}, err
	}
	out := PolicyEvaluation{PolicySelector: s, Routes: []PolicyRoute{}, Evidence: []PolicySupport{}}
	commands := []string{policyMapCommand, policyListCommand, "show ip bgp neighbors " + s.Peer + " json", policyTableCommand}
	bodies := map[string][]byte{}
	captures := map[string]PolicyCapture{}
	sources := map[string]bool{}
	if len(change.Captures) != len(commands) {
		return out, errors.New("policy change needs exactly four authoritative captures")
	}
	for _, c := range change.Captures {
		if !slices.Contains(commands, c.Command) || bodies[c.Command] != nil || sources[c.Source] {
			return out, errors.New("policy capture command or source is unknown or duplicated")
		}
		b, err := policyBody(c, s.Node, c.Command, c.Command == policyMapCommand || c.Command == policyListCommand)
		if err != nil {
			return out, fmt.Errorf("%s: %w", c.Source, err)
		}
		bodies[c.Command] = b
		captures[c.Command] = c
		sources[c.Source] = true
	}
	for _, cmd := range commands {
		c := captures[cmd]
		out.Evidence = append(out.Evidence, PolicySupport{c.Source, c.CollectedAt, c.Command, c.SHA256})
	}
	rules, err := policyRules(bodies[policyMapCommand], s.Policy)
	if err != nil {
		return out, err
	}
	lists, err := policyLists(bodies[policyListCommand], rules)
	if err != nil {
		return out, err
	}
	var table struct {
		RouterID    string                                  `json:"routerId"`
		LocalAS     uint32                                  `json:"localAS"`
		VRFName     string                                  `json:"vrfName"`
		Routes      map[string][]map[string]json.RawMessage `json:"routes"`
		TotalRoutes *int                                    `json:"totalRoutes"`
		TotalPaths  *int                                    `json:"totalPaths"`
		NumRoutes   *int                                    `json:"numRoutes"`
	}
	if err := json.Unmarshal(bodies[policyTableCommand], &table); err != nil {
		return out, err
	}
	var tableFields map[string]json.RawMessage
	if err := json.Unmarshal(bodies[policyTableCommand], &tableFields); err != nil {
		return out, err
	}
	for _, key := range []string{"routerId", "localAS", "vrfName", "routes", "totalRoutes", "totalPaths", "numRoutes"} {
		if tableFields[key] == nil || bytes.Equal(bytes.TrimSpace(tableFields[key]), []byte("null")) {
			return out, fmt.Errorf("baseline table field %s is missing or null", key)
		}
	}
	if table.VRFName != s.VRF || !policyIPv4(table.RouterID) || table.LocalAS == 0 || table.LocalAS == math.MaxUint32 {
		return out, errors.New("BGP table identity is incomplete or contradicts the selector")
	}
	var neighbors map[string]struct {
		Addr     string                                `json:"neighborAddr"`
		LocalAS  uint32                                `json:"localAs"`
		RemoteAS uint32                                `json:"remoteAs"`
		RouterID string                                `json:"localRouterId"`
		RemoteID string                                `json:"remoteRouterId"`
		State    string                                `json:"bgpState"`
		AF       map[string]map[string]json.RawMessage `json:"addressFamilyInfo"`
	}
	if err := json.Unmarshal(bodies[commands[2]], &neighbors); err != nil {
		return out, err
	}
	peer, ok := neighbors[s.Peer]
	var peerFields map[string]map[string]json.RawMessage
	if err := json.Unmarshal(bodies[commands[2]], &peerFields); err != nil {
		return out, err
	}
	for _, key := range []string{"neighborAddr", "localAs", "remoteAs", "localRouterId", "remoteRouterId", "bgpState", "addressFamilyInfo"} {
		if peerFields[s.Peer][key] == nil {
			return out, fmt.Errorf("peer identity field %s is missing", key)
		}
	}
	af := peer.AF["ipv4Unicast"]
	if !ok || len(neighbors) != 1 || peer.Addr != s.Peer || peer.LocalAS != table.LocalAS || peer.RouterID != table.RouterID || peer.RemoteAS == 0 || peer.RemoteAS == math.MaxUint32 || !policyIPv4(peer.RemoteID) || peer.State != "Established" || af == nil {
		return out, errors.New("peer is unknown, not Established, or contradicts the BGP table")
	}
	var acceptedPrefixes *uint64
	if json.Unmarshal(af["acceptedPrefixCounter"], &acceptedPrefixes) != nil || acceptedPrefixes == nil {
		return out, errors.New("peer accepted-prefix count must be a nonnegative integer")
	}
	for k, v := range af {
		// Only the observed telemetry and explicit false policy flags establish
		// an unfiltered baseline. A policy identifier is never a boolean.
		switch k {
		case "updateGroupId", "subGroupId", "packetQueueLength", "commAttriSentToNbr", "acceptedPrefixCounter", "sentPrefixCounter", "receivedPrefixDup":
		case "inboundPathPolicyConfig", "outboundPathPolicyConfig":
			if string(v) != "false" {
				return out, errors.New("baseline peer already has path policy; replacement is not proven")
			}
		default:
			return out, fmt.Errorf("baseline peer has unsupported policy or address-family field %q", k)
		}
	}
	for _, cmd := range commands[:2] {
		if captures[cmd].CollectedAt.Before(captures[policyTableCommand].CollectedAt) || captures[cmd].CollectedAt.Before(captures[commands[2]].CollectedAt) {
			return out, errors.New("candidate policy predates the baseline captures")
		}
	}
	if table.TotalRoutes == nil || table.TotalPaths == nil || table.NumRoutes == nil || *table.TotalRoutes != len(table.Routes) || *table.NumRoutes != len(table.Routes) {
		return out, errors.New("baseline route inventory is incomplete or contradictory")
	}
	var prefixes []netip.Prefix
	for key, paths := range table.Routes {
		prefix, err := netip.ParsePrefix(key)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != key || len(paths) == 0 {
			return out, errors.New("baseline route key is not a canonical IPv4 prefix or its paths are missing")
		}
		prefixes = append(prefixes, prefix)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	paths, peerPrefixes := 0, uint64(0)
	for _, routePrefix := range prefixes {
		row := PolicyRoute{Prefix: routePrefix.String(), SelectionAfter: "unchanged", Outcome: "unchanged", Reason: "the policy leaves every recorded candidate for this prefix unchanged"}
		permit, set := policyAction(routePrefix, rules, lists)
		selected := 0
		fromPeer := false
		for _, path := range table.Routes[row.Prefix] {
			paths++
			var network, prefix string
			var bits *int
			if json.Unmarshal(path["network"], &network) != nil || json.Unmarshal(path["prefix"], &prefix) != nil || json.Unmarshal(path["prefixLen"], &bits) != nil || bits == nil || network != row.Prefix || prefix != routePrefix.Addr().String() || *bits != routePrefix.Bits() {
				return out, errors.New("baseline path identity is incomplete or contradicts its route-table key")
			}
			var valid, best bool
			var weight uint32
			if err := json.Unmarshal(path["valid"], &valid); err != nil || !valid {
				return out, errors.New("baseline path validity is missing or unproven")
			}
			if b, ok := path["bestpath"]; ok {
				if string(b) != "true" && string(b) != "false" {
					return out, errors.New("invalid bestpath flag")
				}
				best = string(b) == "true"
			}
			if string(path["weight"]) == "null" || json.Unmarshal(path["weight"], &weight) != nil || weight > 65535 {
				return out, errors.New("baseline path weight, freshness, or peer identity is incomplete")
			}
			var peerID string
			if json.Unmarshal(path["peerId"], &peerID) != nil || peerID != "(unspec)" && !policyIPv4(peerID) {
				return out, errors.New("baseline path peer identity is incomplete or invalid")
			}
			if stale, ok := path["stale"]; ok && string(stale) != "false" {
				return out, errors.New("baseline path freshness is unproven or invalid")
			}
			if best {
				selected++
				row.SelectedBefore = peerID
			}
			if peerID == s.Peer {
				fromPeer = true
			}
			applies := peerID == s.Peer
			if s.Direction == "import" && applies && (!permit || set != nil && *set != weight) {
				row.SelectionAfter = "unknown"
				row.Outcome = "unknown"
				row.Reason = "policy changes a recorded candidate; protocol recomputation is required and no replacement route is proven"
			}
		}
		if fromPeer {
			peerPrefixes++
		}
		if selected != 1 {
			return out, errors.New("baseline selected path is missing or ambiguous")
		}
		if s.Direction == "export" {
			row.AdvertisementAfter, row.Outcome = "unknown", "unknown"
			row.Reason = "the local selected path stays recorded; no per-peer advertisement evidence proves export eligibility or remote protocol recomputation, so export impact is unknown and downstream forwarding stays recorded"
		}
		out.Considered++
		if row.Outcome == "unchanged" {
			out.Unchanged++
		} else {
			out.Affected++
		}
		out.Routes = append(out.Routes, row)
	}
	if paths != *table.TotalPaths || peerPrefixes != *acceptedPrefixes || s.Direction == "import" && peerPrefixes == 0 {
		return PolicyEvaluation{}, errors.New("baseline path or peer prefix inventory is contradictory or names no path from the import peer")
	}
	// Equal counts cannot prove route identities or attributes across captures.
	out.UnrecordedAfter = "unknown"
	if s.Direction == "import" {
		for _, rule := range rules {
			if rule.Type != "permit" || rule.weight != nil {
				break
			}
			if rule.list == "" {
				out.UnrecordedAfter = "unchanged"
				break
			}
		}
	}
	return out, nil
}

const policyMaxBytes = 1 << 20
const policyTableCommand = "show ip bgp json"

func policyIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return false
	}
	first := a.As4()[0]
	return first > 0 && first < 224
}

// checkPolicyJSON rejects duplicate keys at every depth, including case variants.
// It is opt-in so the legacy topology decoder's acceptance set stays unchanged.
func checkPolicyJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkPolicyJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data follows the policy object")
	}
	return nil
}

func walkPolicyJSON(dec *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("policy JSON nests deeper than 16 levels")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delimiter, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if delimiter == '{' {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := tok.(string)
			folded := strings.ToLower(strings.ToUpper(key))
			if seen[folded] {
				return fmt.Errorf("duplicate policy key %q", key)
			}
			seen[folded] = true
		}
		if err := walkPolicyJSON(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
