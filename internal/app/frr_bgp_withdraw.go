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

// The outcomes of a simulated prefix withdrawal. Each is a reading of the node's
// recorded BGP table, never of its forwarding.
const (
	// withdrawPathsRemain: a path for the prefix remains that FRR recorded from
	// no peer, or from another peer whose session the summary does not contradict.
	withdrawPathsRemain = "paths_remain"
	// withdrawNoRecordedPath: the table records no other path for the prefix.
	withdrawNoRecordedPath = "no_recorded_path"
	// withdrawUnknown: the only other paths name no peer, or come from a peer the
	// summary does not show Established, so whether any remains is unknown.
	withdrawUnknown = "unknown"
)

// The kinds of path a withdrawal reads.
const (
	pathLearned      = "learned"      // from a peer the summary shows Established, or with no summary captured
	pathNoPeer       = "no_peer"      // FRR recorded no peer, such as a locally originated prefix
	pathContradicted = "contradicted" // from a peer the summary lists in another state, or does not list
	pathUnattributed = "unattributed" // no peer ID names a peer, so it may come from the withdrawing peer
)

// frrBGPWithdrawLimitations adds to the report's limitations when it carries a
// withdrawal.
var frrBGPWithdrawLimitations = []string{
	"a prefix withdrawal is simulated against the named node's recorded BGP table only: every path for the prefix that names the peer is removed, and nothing else changes; no UPDATE is sent, no best path is recomputed, and propagation to other routers is not modeled",
	"a remaining path is a candidate FRR listed; whether it is valid, selected, or installed is not read, and no alternate path is invented",
	"no_recorded_path means the recorded table lists no other path; a path can still arrive from another peer once the withdrawal propagates, which no capture shows, so no route loss is claimed",
	"the forwarding impact of a withdrawal is always unknown: the import reads no zebra RIB, kernel FIB, or topology, and ties no BGP path to a forwarding entry",
	"other prefixes are not rated: aggregation, conditional advertisement, policy, and next-hop resolution through the withdrawn prefix are not in the evidence",
}

// bgpWithdraw is the --withdraw-bgp selector: peer withdraws prefix from node.
type bgpWithdraw struct {
	node   string
	peer   netip.Addr
	prefix netip.Prefix
}

// parseBGPWithdraw reads NODE:PEER:PREFIX. The node ends at the first colon and
// the prefix starts after the last, so an IPv6 peer address can be named. The
// prefix must be a canonical IPv4 prefix, the only kind the route table holds.
// Text with no colon parses only as IPv4, and ParsePrefix refuses leading zeros,
// so a masked prefix is canonical.
func parseBGPWithdraw(spec string) (bgpWithdraw, error) {
	node, rest, _ := strings.Cut(spec, ":")
	cut := strings.LastIndex(rest, ":")
	if node == "" || cut <= 0 || cut == len(rest)-1 {
		return bgpWithdraw{}, fmt.Errorf("%q is not node:peer:prefix", spec)
	}
	peer, err := netip.ParseAddr(rest[:cut])
	if err != nil || peer.Zone() != "" {
		return bgpWithdraw{}, fmt.Errorf("peer %q is not an IP address", rest[:cut])
	}
	text := rest[cut+1:]
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix != prefix.Masked() {
		return bgpWithdraw{}, fmt.Errorf("prefix %q is not a canonical IPv4 prefix", text)
	}
	return bgpWithdraw{node: node, peer: peer, prefix: prefix}, nil
}

// frrBGPWithdrawal is what a simulated prefix withdrawal does to one node's
// recorded BGP table. Removed and Remaining keep FRR's path order. PeerOtherPaths
// counts the peer's learned paths for other prefixes, which a prefix withdrawal
// leaves in place. ForwardingImpact is always "unknown".
type frrBGPWithdrawal struct {
	Node             string           `json:"node"`
	VRF              string           `json:"vrf"`
	Family           string           `json:"family"`
	Peer             string           `json:"peer"`
	Prefix           string           `json:"prefix"`
	Outcome          string           `json:"outcome"`
	Reason           string           `json:"reason"`
	Removed          []frrBGPPathRead `json:"removed"`
	Remaining        []frrBGPPathRead `json:"remaining"`
	PeerSessionState string           `json:"peer_session_state,omitempty"`
	PeerOtherPaths   int              `json:"peer_other_paths"`
	ForwardingImpact string           `json:"forwarding_impact"`
	ForwardingReason string           `json:"forwarding_reason"`
	Evidence         []frrBGPEvidence `json:"evidence"`
}

// frrBGPPathRead is one path of the withdrawn prefix. SessionState is the state
// the node's summary printed for the path's peer; it is absent when the node has
// no summary, or the summary does not list the peer. StaleFlag is set only by a
// simulated session loss, so a withdrawal never writes it.
type frrBGPPathRead struct {
	Kind         string   `json:"kind"`
	Peer         string   `json:"peer,omitempty"`
	SessionState string   `json:"session_state,omitempty"`
	StaleFlag    string   `json:"stale_flag,omitempty"`
	PathFrom     string   `json:"path_from"`
	ASPath       string   `json:"as_path"`
	BGPOrigin    string   `json:"bgp_origin"`
	NextHops     []string `json:"next_hops"`
}

// withdrawFromReport reads the node's route table and summary and simulates the
// withdrawal against them.
func withdrawFromReport(w bgpWithdraw, m frrospf.Manifest, captures []frrospf.Capture) (*frrBGPWithdrawal, error) {
	table, tc, sum, sc, err := nodeBGPCaptures(w.node, m, captures)
	if err != nil {
		return nil, err
	}
	return withdrawFRRBGP(w, table, tc, sum, sc)
}

// nodeBGPCaptures reads one node's route table and summary from the captures
// buildFRRBGPReport accepted, which holds at most one of each per node. sum is
// nil when the manifest names no summary for the node, and a node with no route
// table is refused.
func nodeBGPCaptures(node string, m frrospf.Manifest, captures []frrospf.Capture) (frrbgp.RouteTable, frrospf.ManifestCapture, *frrbgp.Summary, frrospf.ManifestCapture, error) {
	var table *frrbgp.RouteTable
	var sum *frrbgp.Summary
	var tc, sc frrospf.ManifestCapture
	for i, c := range captures {
		if c.Node != node {
			continue
		}
		switch c.Command {
		case frrbgp.CommandRoute:
			t, err := frrbgp.DecodeRouteCapture(c.Data, c.Node)
			if err != nil {
				return frrbgp.RouteTable{}, tc, nil, sc, err
			}
			table, tc = &t, m.Captures[i]
		case frrbgp.CommandSummary:
			s, err := frrbgp.Decode(c.Data, c.Node)
			if err != nil {
				return frrbgp.RouteTable{}, tc, nil, sc, err
			}
			sum, sc = &s, m.Captures[i]
		}
	}
	if table == nil {
		return frrbgp.RouteTable{}, tc, nil, sc, fmt.Errorf("the manifest names no %q capture for node %q", frrbgp.CommandRoute, node)
	}
	return *table, tc, sum, sc, nil
}

// withdrawFRRBGP removes every path for w.prefix that names w.peer from the
// node's route table t, and reads what remains. sum is the node's summary, or
// nil when the manifest names none. A withdrawal the table does not describe is
// refused, so a mistyped selector never reads as a withdrawal that changes
// nothing. t and sum are only read.
func withdrawFRRBGP(w bgpWithdraw, t frrbgp.RouteTable, tc frrospf.ManifestCapture, sum *frrbgp.Summary, sc frrospf.ManifestCapture) (*frrBGPWithdrawal, error) {
	out := &frrBGPWithdrawal{
		Node:             tc.Node,
		VRF:              tc.VRF,
		Family:           frrbgp.Family,
		Peer:             w.peer.String(),
		Prefix:           w.prefix.String(),
		Removed:          []frrBGPPathRead{},
		Remaining:        []frrBGPPathRead{},
		ForwardingImpact: withdrawUnknown,
		ForwardingReason: "the capture is FRR's BGP table, not zebra's RIB or the kernel FIB; which path FRR selected and whether any was installed are not read, so what forwarding does after the withdrawal is unknown",
		Evidence:         []frrBGPEvidence{{Source: tc.Source, CollectedAt: tc.CollectedAt.Format(time.RFC3339Nano)}},
	}
	states := map[netip.Addr]string{}
	if sum != nil {
		out.Evidence = append(out.Evidence, frrBGPEvidence{Source: sc.Source, CollectedAt: sc.CollectedAt.Format(time.RFC3339Nano)})
		for _, p := range sum.Peers {
			states[p.Address] = p.State
		}
		out.PeerSessionState = states[w.peer]
	}
	unattributed := 0
	for _, e := range t.Routes {
		for _, p := range e.Paths {
			fromPeer := p.Source == frrbgp.RouteSourceLearned && p.Peer == w.peer
			switch {
			case e.Prefix != w.prefix:
				if fromPeer {
					out.PeerOtherPaths++
				}
			case fromPeer:
				out.Removed = append(out.Removed, pathRead(p, pathLearned, states[p.Peer]))
			default:
				kind := pathKind(p, sum != nil, states)
				if kind == pathUnattributed {
					unattributed++
				}
				out.Remaining = append(out.Remaining, pathRead(p, kind, states[p.Peer]))
			}
		}
	}
	if len(out.Removed) == 0 {
		msg := fmt.Sprintf("the route table of node %q lists no path for %s learned from peer %s", tc.Node, w.prefix, w.peer)
		if unattributed > 0 {
			msg += fmt.Sprintf("; %d of its paths for that prefix name no peer, so the table cannot show whether one came from it", unattributed)
		}
		return nil, errors.New(msg)
	}
	out.Outcome, out.Reason = withdrawOutcome(out)
	return out, nil
}

// withdrawOutcome rates the paths that remain. Only a path from no peer, or from
// a peer whose recorded session does not contradict the table, counts as
// remaining. A path that names no peer may be the withdrawing peer's own, and a
// path from a peer the summary does not show Established may already be gone, so
// either leaves the outcome unknown when nothing else remains.
func withdrawOutcome(w *frrBGPWithdrawal) (string, string) {
	counted, unattributed, contradicted := 0, 0, 0
	for _, p := range w.Remaining {
		switch p.Kind {
		case pathLearned, pathNoPeer:
			counted++
		case pathUnattributed:
			unattributed++
		default:
			contradicted++
		}
	}
	at := fmt.Sprintf("%s's recorded BGP table", w.Node)
	switch {
	case counted > 0:
		return withdrawPathsRemain, fmt.Sprintf("after peer %s withdraws %s, %s still lists a path for it from no peer or from another peer; which path FRR would select, and whether it is valid or installed, is not read", w.Peer, w.Prefix, at)
	case unattributed+contradicted > 0:
		var why []string
		if unattributed > 0 {
			why = append(why, fmt.Sprintf("%d name no peer, so any of them may be peer %s's own", unattributed, w.Peer))
		}
		if contradicted > 0 {
			why = append(why, fmt.Sprintf("%d come from peers the summary does not show Established, so the summary and the table disagree about them", contradicted))
		}
		return withdrawUnknown, fmt.Sprintf("of the other paths %s lists for %s, %s; whether any path for it remains is unknown", at, w.Prefix, strings.Join(why, ", and "))
	}
	return withdrawNoRecordedPath, fmt.Sprintf("after peer %s withdraws %s, %s lists no other path for it; another peer may still send one once the withdrawal propagates, which no capture shows, so no route loss is claimed", w.Peer, w.Prefix, at)
}

// pathKind reads a path that is not the simulated peer's. haveSummary says the
// manifest names a summary for the node, and states holds the state it printed
// for each peer it lists. Both simulations call it, so their kinds cannot drift.
func pathKind(p frrbgp.RoutePath, haveSummary bool, states map[netip.Addr]string) string {
	switch {
	case p.Source == frrbgp.RouteSourceNoPeer:
		return pathNoPeer
	case p.Source == frrbgp.RouteSourceUnknown:
		return pathUnattributed
	case !haveSummary || states[p.Peer] == frrbgp.StateEstablished:
		return pathLearned
	}
	return pathContradicted
}

// pathRead is one path for the report. state is the summary's state for the
// path's peer; a path that names no peer has none, since no summary key is the
// zero address.
func pathRead(p frrbgp.RoutePath, kind, state string) frrBGPPathRead {
	r := frrBGPPathRead{Kind: kind, SessionState: state, PathFrom: p.PathFrom, ASPath: p.ASPath, BGPOrigin: p.Origin, NextHops: make([]string, 0, len(p.NextHops))}
	if p.Source == frrbgp.RouteSourceLearned {
		r.Peer = p.Peer.String()
	}
	for _, h := range p.NextHops {
		r.NextHops = append(r.NextHops, h.String())
	}
	return r
}

// renderFRRBGPWithdrawal writes the withdrawal block of the text report. Each
// path list stops at frrBGPLearnedLimit entries, and the JSON report keeps all.
func renderFRRBGPWithdrawal(b *strings.Builder, w frrBGPWithdrawal) {
	clean := textsafe.Clean
	b.WriteString("\nPrefix withdrawal (simulated against the recorded BGP table; nothing was sent):\n")
	fmt.Fprintf(b, "  peer %s withdraws %s at %s (vrf %s, %s)\n", clean(w.Peer), clean(w.Prefix), clean(w.Node), clean(w.VRF), w.Family)
	fmt.Fprintf(b, "  outcome %s: %s\n", w.Outcome, clean(w.Reason))
	renderPathReads(b, "  ", "removed", w.Removed)
	renderPathReads(b, "  ", "remains", w.Remaining)
	// The summary, when one was read, is the second evidence row.
	switch {
	case len(w.Evidence) < 2:
		fmt.Fprintf(b, "  peer %s session: not captured; the manifest names no summary for %s\n", clean(w.Peer), clean(w.Node))
	case w.PeerSessionState == "":
		fmt.Fprintf(b, "  peer %s session: the summary does not list this peer, while the table lists paths from it; the captures disagree, and the withdrawal is read against the table as recorded\n", clean(w.Peer))
	case w.PeerSessionState != frrbgp.StateEstablished:
		fmt.Fprintf(b, "  peer %s session: the summary printed state %s, while the table lists paths from it; the captures disagree, and the withdrawal is read against the table as recorded\n", clean(w.Peer), clean(w.PeerSessionState))
	default:
		fmt.Fprintf(b, "  peer %s session: the summary printed state %s, and a prefix withdrawal leaves the session as recorded\n", clean(w.Peer), clean(w.PeerSessionState))
	}
	fmt.Fprintf(b, "  not withdrawn: the peer's learned paths for other prefixes (%d); a prefix withdrawal is not a session loss\n", w.PeerOtherPaths)
	fmt.Fprintf(b, "  forwarding impact %s: %s\n", w.ForwardingImpact, w.ForwardingReason)
	for _, e := range w.Evidence {
		fmt.Fprintf(b, "  evidence: %s, collected %s\n", clean(e.Source), clean(e.CollectedAt))
	}
}

// renderPathReads writes one path list, each line after indent. A path's stale
// flag is written only when the capture recorded one, and only a session loss
// sets it.
func renderPathReads(b *strings.Builder, indent, label string, paths []frrBGPPathRead) {
	clean := textsafe.Clean
	if len(paths) == 0 {
		fmt.Fprintf(b, "%s%s: no path\n", indent, label)
	}
	for i, p := range paths {
		if i == frrBGPLearnedLimit {
			fmt.Fprintf(b, "%s%s: %d more; see --json\n", indent, label, len(paths)-i)
			break
		}
		from := "no peer recorded"
		switch p.Kind {
		case pathLearned, pathContradicted:
			from = "peer " + clean(p.Peer)
			if p.SessionState != "" {
				from += ", session " + clean(p.SessionState)
			}
		case pathUnattributed:
			from = "no peer ID names a peer"
		}
		path := clean(p.ASPath)
		if path == "" {
			path = "(empty)"
		}
		hops := strings.Join(p.NextHops, ", ")
		if hops == "" {
			hops = "none"
		}
		stale := ""
		switch p.StaleFlag {
		case staleRecordedTrue:
			stale = ", stale flag recorded true"
		case staleRecordedFalse:
			stale = ", stale flag recorded false"
		}
		fmt.Fprintf(b, "%s%s: %s path from %s, AS path %s, BGP origin %s, next hops %s%s\n", indent, label, p.Kind, from, path, clean(p.BGPOrigin), hops, stale)
	}
}
