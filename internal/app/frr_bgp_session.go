package app

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/frrbgp"
	"github.com/heymaikol/network-doctor/internal/frrospf"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// The values of a session-loss path's stale_flag: what the path's stale key
// recorded, kept as strings so a consumer cannot read an absent key as false.
const (
	staleRecordedTrue  = "recorded_true"
	staleRecordedFalse = "recorded_false"
	staleNotRecorded   = "not_recorded"
)

// staleFlagNames names each frrbgp.StaleFlag.
var staleFlagNames = [...]string{
	frrbgp.StaleNotRecorded: staleNotRecorded,
	frrbgp.StaleFalse:       staleRecordedFalse,
	frrbgp.StaleTrue:        staleRecordedTrue,
}

// The readings of the simulated peer's session. Each classifies only what the
// node's summary printed, and none changes an outcome.
const (
	sessionEstablished    = "established"     // the summary lists the peer Established
	sessionNotEstablished = "not_established" // the summary lists the peer in another state
	sessionNotListed      = "not_listed"      // the summary does not list the peer
	sessionNotCaptured    = "not_captured"    // the manifest names no summary for the node
)

// frrBGPSessionLossLimitations adds to the report's limitations when it carries
// a session loss.
var frrBGPSessionLossLimitations = []string{
	"a session loss is an assumption applied to the named node's recorded BGP table only: every path the table attributes to the peer, for every prefix, is removed, and nothing else changes; no NOTIFICATION is sent, no best path is recomputed, and nothing propagates",
	"the peer's session state is what the summary printed at its collection time; a state other than Established is reported as observed and is not treated as a session newly lost",
	"whether and when the node would remove the peer's paths is not modeled: it depends on how the session ends and when the node detects it, and graceful restart or long-lived graceful restart may keep them as stale for a negotiated time; no capture read shows those capabilities",
	"a stale flag is reported as FRR printed it; what set it is not read, and a path recorded stale is not counted as remaining",
	"a remaining path is a candidate FRR listed; whether it is valid, selected, or installed is not read, and no alternate path is invented",
	"no_recorded_path is not a route loss: another peer may send a path once the loss propagates; an empty result means the table attributes no path to the peer, not that the peer advertised nothing",
	"the forwarding impact of a session loss is always unknown: the import reads no zebra RIB, kernel FIB, or topology, and ties no BGP path to a forwarding entry",
	"only IPv4 unicast in the default VRF is read, though the same session may carry other families or VRFs; routes at other routers, next hops that resolve through removed prefixes, aggregates, and conditional advertisement are not rated",
}

// bgpSession is the --fail-bgp-session selector: node loses its session with peer.
type bgpSession struct {
	node string
	peer netip.Addr
}

// parseBGPSession reads NODE:PEER. The node ends at the first colon, so an IPv6
// peer address can be named. A zone is refused.
func parseBGPSession(spec string) (bgpSession, error) {
	node, peer, _ := strings.Cut(spec, ":")
	if node == "" || peer == "" {
		return bgpSession{}, fmt.Errorf("%q is not node:peer", spec)
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || addr.Zone() != "" {
		return bgpSession{}, fmt.Errorf("peer %q is not an IP address", peer)
	}
	return bgpSession{node: node, peer: addr}, nil
}

// frrBGPSessionLoss is what removing every path a node's recorded BGP table
// attributes to one peer does to that table. The removal is the assumption the
// outcomes rest on; the peer's session state is only what the summary printed.
// StaleRetention and ForwardingImpact are always "unknown".
type frrBGPSessionLoss struct {
	Node                 string                `json:"node"`
	VRF                  string                `json:"vrf"`
	Family               string                `json:"family"`
	Peer                 string                `json:"peer"`
	Assumption           string                `json:"assumption"`
	PeerSessionState     string                `json:"peer_session_state,omitempty"`
	PeerSessionReading   string                `json:"peer_session_reading"`
	PeerSessionReason    string                `json:"peer_session_reason"`
	RemovedReason        string                `json:"removed_reason"`
	StaleRetention       string                `json:"stale_retention"`
	StaleRetentionReason string                `json:"stale_retention_reason"`
	Prefixes             []frrBGPSessionPrefix `json:"prefixes"`
	UnattributedPrefixes []string              `json:"unattributed_prefixes"`
	ForwardingImpact     string                `json:"forwarding_impact"`
	ForwardingReason     string                `json:"forwarding_reason"`
	Evidence             []frrBGPEvidence      `json:"evidence"`
}

// frrBGPSessionPrefix is one prefix with at least one path from the peer.
// Removed and Remaining keep FRR's path order, and every path carries its
// stale flag.
type frrBGPSessionPrefix struct {
	Prefix    string           `json:"prefix"`
	Outcome   string           `json:"outcome"`
	Reason    string           `json:"reason"`
	Removed   []frrBGPPathRead `json:"removed"`
	Remaining []frrBGPPathRead `json:"remaining"`
}

// sessionLossFromReport reads the node's route table and summary and simulates
// the session loss against them.
func sessionLossFromReport(s bgpSession, m frrospf.Manifest, captures []frrospf.Capture) (*frrBGPSessionLoss, error) {
	table, tc, sum, sc, err := nodeBGPCaptures(s.node, m, captures)
	if err != nil {
		return nil, err
	}
	return failFRRBGPSession(s, table, tc, sum, sc)
}

// failFRRBGPSession removes every path that names s.peer from the node's route
// table t, for every prefix, and rates each prefix that had one. sum is the
// node's summary, or nil when the manifest names none. A peer neither capture
// names is refused, so a mistyped selector never reads as a loss that changes
// nothing. t and sum are only read.
func failFRRBGPSession(s bgpSession, t frrbgp.RouteTable, tc frrospf.ManifestCapture, sum *frrbgp.Summary, sc frrospf.ManifestCapture) (*frrBGPSessionLoss, error) {
	peer := s.peer.String()
	out := &frrBGPSessionLoss{
		Node:                 tc.Node,
		VRF:                  tc.VRF,
		Family:               frrbgp.Family,
		Peer:                 peer,
		Assumption:           fmt.Sprintf("every path %s's recorded BGP table attributes to peer %s, for every prefix, is removed, and nothing else in the table changes; the outcomes rest on this assumption, not on an observed session loss", tc.Node, peer),
		StaleRetention:       withdrawUnknown,
		StaleRetentionReason: fmt.Sprintf("whether %s would keep these paths as stale, and for how long, depends on the graceful-restart and long-lived graceful-restart capabilities the session negotiated and on how it ends; no capture read shows either", tc.Node),
		Prefixes:             []frrBGPSessionPrefix{},
		UnattributedPrefixes: []string{},
		ForwardingImpact:     withdrawUnknown,
		ForwardingReason:     "the capture is FRR's BGP table, not zebra's RIB or the kernel FIB; which path FRR selected and whether any was installed are not read, so what forwarding does after the assumed loss is unknown",
		Evidence:             []frrBGPEvidence{{Source: tc.Source, CollectedAt: tc.CollectedAt.Format(time.RFC3339Nano)}},
	}
	states := map[netip.Addr]string{}
	listed := false
	if sum != nil {
		out.Evidence = append(out.Evidence, frrBGPEvidence{Source: sc.Source, CollectedAt: sc.CollectedAt.Format(time.RFC3339Nano)})
		for _, p := range sum.Peers {
			states[p.Address] = p.State
		}
		out.PeerSessionState, listed = states[s.peer]
	}
	removed, stale, unattributed := 0, 0, 0
	for _, e := range t.Routes {
		p := frrBGPSessionPrefix{Prefix: e.Prefix.String(), Removed: []frrBGPPathRead{}, Remaining: []frrBGPPathRead{}}
		noPeer := false
		for _, path := range e.Paths {
			if path.Source == frrbgp.RouteSourceLearned && path.Peer == s.peer {
				p.Removed = append(p.Removed, sessionPathRead(path, pathLearned, states))
				if path.Stale == frrbgp.StaleTrue {
					stale++
				}
				continue
			}
			kind := pathKind(path, sum != nil, states)
			if kind == pathUnattributed {
				unattributed++
				noPeer = true
			}
			p.Remaining = append(p.Remaining, sessionPathRead(path, kind, states))
		}
		switch {
		case len(p.Removed) > 0:
			removed += len(p.Removed)
			p.Outcome, p.Reason = sessionOutcome(tc.Node, peer, p)
			out.Prefixes = append(out.Prefixes, p)
		case noPeer:
			out.UnattributedPrefixes = append(out.UnattributedPrefixes, p.Prefix)
		}
	}
	if removed == 0 && !listed {
		msg := fmt.Sprintf("the route table of node %q attributes no path to peer %s, and ", tc.Node, peer)
		if sum == nil {
			msg += fmt.Sprintf("the manifest names no summary for node %q", tc.Node)
		} else {
			msg += fmt.Sprintf("the summary of node %q does not list it", tc.Node)
		}
		if unattributed > 0 {
			msg += fmt.Sprintf("; %d of the table's paths name no peer, so the table cannot show whether one came from it", unattributed)
		}
		return nil, errors.New(msg)
	}

	switch {
	case sum == nil:
		out.PeerSessionReading = sessionNotCaptured
		out.PeerSessionReason = fmt.Sprintf("observed: nothing; the manifest names no summary for %s, so the state of its session with peer %s is not captured", tc.Node, peer)
	case !listed:
		out.PeerSessionReading = sessionNotListed
		out.PeerSessionReason = fmt.Sprintf("observed: %s's summary does not list peer %s, while the table attributes %s to it; the captures do not show why, and they may describe different moments", tc.Node, peer, countOf(removed, "path", "paths"))
	case out.PeerSessionState == frrbgp.StateEstablished:
		out.PeerSessionReading = sessionEstablished
		out.PeerSessionReason = fmt.Sprintf("observed: %s's summary printed state %s for peer %s; the loss of this session is assumed, not observed", tc.Node, out.PeerSessionState, peer)
	default:
		out.PeerSessionReading = sessionNotEstablished
		out.PeerSessionReason = fmt.Sprintf("observed: %s's summary printed state %s for peer %s, so the session was not Established when the summary was taken; this is not read as an established session being lost", tc.Node, out.PeerSessionState, peer)
		if removed > 0 {
			out.PeerSessionReason += fmt.Sprintf("; the table attributes %s to it, and the captures do not show why it lists them", countOf(removed, "path", "paths"))
		}
		if stale > 0 {
			out.PeerSessionReason += fmt.Sprintf("; %d of them carry FRR's stale flag, and the captures do not show what set it", stale)
		}
	}

	if removed > 0 {
		out.RemovedReason = fmt.Sprintf("%s's recorded table attributes %s for %s to peer %s", tc.Node, countOf(removed, "path", "paths"), countOf(len(out.Prefixes), "prefix", "prefixes"), peer)
	} else {
		out.RemovedReason = fmt.Sprintf("%s's recorded table attributes no path to peer %s, so the assumption removes nothing from it; this is what the table recorded, not a finding that the peer advertised nothing", tc.Node, peer)
	}
	if n := len(out.UnattributedPrefixes); n > 0 {
		out.RemovedReason += fmt.Sprintf("; the table lists paths that name no peer for %s with no path attributed to it, and it cannot show whether any of them came from this peer", countOf(n, "prefix", "prefixes"))
	}
	return out, nil
}

// sessionPathRead is pathRead with the path's stale flag.
func sessionPathRead(p frrbgp.RoutePath, kind string, states map[netip.Addr]string) frrBGPPathRead {
	r := pathRead(p, kind, states[p.Peer])
	r.StaleFlag = staleFlagNames[p.Stale]
	return r
}

// sessionOutcome rates the paths that remain for one prefix. A remaining path
// counts only when it is learned or from no peer and not recorded stale. Each
// other path is named in the first group that fits: recorded stale, naming no
// peer, or from a peer the summary does not show Established. None of the groups
// claims a cause.
func sessionOutcome(node, peer string, p frrBGPSessionPrefix) (string, string) {
	counted, stale, unattributed, notEstablished := 0, 0, 0, 0
	for _, r := range p.Remaining {
		switch {
		case r.StaleFlag == staleRecordedTrue:
			stale++
		case r.Kind == pathLearned || r.Kind == pathNoPeer:
			counted++
		case r.Kind == pathUnattributed:
			unattributed++
		default:
			notEstablished++
		}
	}
	switch {
	case counted > 0:
		return withdrawPathsRemain, fmt.Sprintf("if %s removes peer %s's paths, its recorded table still lists a path for %s from no peer or from another peer, not recorded stale; which path FRR would select, and whether it is valid or installed, is not read", node, peer, p.Prefix)
	case stale+unattributed+notEstablished > 0:
		var why []string
		if stale > 0 {
			why = append(why, fmt.Sprintf("%d recorded stale, and what FRR later does with a stale path is not in the evidence, so they are not counted", stale))
		}
		if unattributed > 0 {
			why = append(why, fmt.Sprintf("%d naming no peer, so any of them may be peer %s's own", unattributed, peer))
		}
		if notEstablished > 0 {
			why = append(why, fmt.Sprintf("%d from peers the summary does not show Established, and the captures do not show why the table lists them, so they are not counted", notEstablished))
		}
		return withdrawUnknown, fmt.Sprintf("of the other paths %s's recorded table lists for %s: %s; whether any path for it would remain is unknown", node, p.Prefix, strings.Join(why, "; "))
	}
	return withdrawNoRecordedPath, fmt.Sprintf("if %s removes peer %s's paths, its recorded table lists no other path for %s; another peer may still send one, which no capture shows, so no route loss is claimed", node, peer, p.Prefix)
}

// countOf writes n with the noun that agrees with it.
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// renderFRRBGPSessionLoss writes the session-loss block of the text report. It
// lists frrBGPLearnedLimit prefixes, paths per list, and unattributed prefixes,
// and the JSON report keeps all.
func renderFRRBGPSessionLoss(b *strings.Builder, s frrBGPSessionLoss) {
	clean := textsafe.Clean
	b.WriteString("\nBGP session loss (hypothetical, against the recorded BGP table; nothing was sent):\n")
	fmt.Fprintf(b, "  peer %s at %s (vrf %s, %s)\n", clean(s.Peer), clean(s.Node), clean(s.VRF), s.Family)
	fmt.Fprintf(b, "  %s\n", clean(s.PeerSessionReason))
	fmt.Fprintf(b, "  assumed: %s\n", clean(s.Assumption))
	fmt.Fprintf(b, "  recorded: %s\n", clean(s.RemovedReason))
	if len(s.Prefixes) > 0 {
		flags := map[string]int{}
		outcomes := map[string]int{}
		for _, p := range s.Prefixes {
			outcomes[p.Outcome]++
			for _, r := range p.Removed {
				flags[r.StaleFlag]++
			}
		}
		fmt.Fprintf(b, "  stale flags on the removed paths: %d recorded true, %d recorded false, %d not recorded\n", flags[staleRecordedTrue], flags[staleRecordedFalse], flags[staleNotRecorded])
		fmt.Fprintf(b, "  outcomes: %d %s, %d %s, %d %s\n", outcomes[withdrawPathsRemain], withdrawPathsRemain, outcomes[withdrawUnknown], withdrawUnknown, outcomes[withdrawNoRecordedPath], withdrawNoRecordedPath)
	}
	fmt.Fprintf(b, "  stale retention %s: %s\n", s.StaleRetention, clean(s.StaleRetentionReason))
	for i, p := range s.Prefixes {
		if i == frrBGPLearnedLimit {
			fmt.Fprintf(b, "  %d more prefixes; see --json\n", len(s.Prefixes)-i)
			break
		}
		fmt.Fprintf(b, "  prefix %s %s: %s\n", clean(p.Prefix), p.Outcome, clean(p.Reason))
		renderPathReads(b, "    ", "removed", p.Removed)
		renderPathReads(b, "    ", "remains", p.Remaining)
	}
	if n := len(s.UnattributedPrefixes); n > 0 {
		shown := s.UnattributedPrefixes[:min(n, frrBGPLearnedLimit)]
		fmt.Fprintf(b, "  not rated, no path from the peer and some paths name no peer: %s\n", clean(strings.Join(shown, ", ")))
		if n > len(shown) {
			fmt.Fprintf(b, "  not rated: %d more prefixes; see --json\n", n-len(shown))
		}
	}
	fmt.Fprintf(b, "  forwarding impact %s: %s\n", s.ForwardingImpact, s.ForwardingReason)
	for _, e := range s.Evidence {
		fmt.Fprintf(b, "  evidence: %s, collected %s\n", clean(e.Source), clean(e.CollectedAt))
	}
}
