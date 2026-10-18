package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/frrbgp"
	"github.com/heymaikol/network-doctor/internal/frrospf"
)

// withdrawLab is the three-router withdrawal run described in
// "Withdrawal run" in testdata/frr/10.7.0/bgp/README.md: r1's summary and table before r2
// withdrew anything, after it withdrew 10.10.2.0/24, and after it also withdrew
// 10.10.9.0/24 and 10.10.1.0/24.
const withdrawLab = "../../testdata/frr/10.7.0/bgp/withdraw"

// stageWithdrawPhase copies r1's summary and table of one lab phase into a new
// directory, byte for byte, and writes a manifest that names both.
func stageWithdrawPhase(t *testing.T, phase string) string {
	t.Helper()
	return stageLabPhase(t, withdrawLab, phase)
}

// stageLabPhase stages r1's summary and table of one phase of the lab run in
// labDir, as stageWithdrawPhase does.
func stageLabPhase(t *testing.T, labDir, phase string) string {
	t.Helper()
	dir := t.TempDir()
	lab, staged := openRoot(t, labDir), openRoot(t, dir)
	var captures []any
	for _, cmd := range []string{frrbgp.CommandSummary, frrbgp.CommandRoute} {
		stem := "r1-" + phase + "-" + strings.ReplaceAll(cmd, " ", "_")
		raw, err := lab.ReadFile(stem + ".raw")
		if err != nil {
			t.Fatal(err)
		}
		stamp, err := lab.ReadFile(stem + ".collected_at")
		if err != nil {
			t.Fatal(err)
		}
		if err := staged.WriteFile(stem+".raw", raw, 0o600); err != nil {
			t.Fatal(err)
		}
		captures = append(captures, map[string]any{
			"file": stem + ".raw", "source": stem, "node": "r1", "vrf": "default",
			"frr_version": "10.7.0", "command": cmd, "collected_at": strings.TrimSpace(string(stamp)),
		})
	}
	manifest := filepath.Join(dir, "manifest.json")
	writeFRRJSON(t, manifest, map[string]any{"version": 1, "captures": captures})
	return manifest
}

// runWithdrawJSON runs the import with --withdraw-bgp and --json and returns the
// withdrawal. Every withdrawal leaves forwarding unknown, so each call checks it.
func runWithdrawJSON(t *testing.T, manifest, spec string) frrBGPWithdrawal {
	t.Helper()
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", spec, "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	var rep frrBGPReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	w := rep.Withdrawal
	if w == nil {
		t.Fatalf("no withdrawal in %s", stdout)
	}
	if w.ForwardingImpact != "unknown" || !strings.Contains(w.ForwardingReason, "not zebra's RIB or the kernel FIB") {
		t.Errorf("forwarding = %q (%q), want unknown with the reason", w.ForwardingImpact, w.ForwardingReason)
	}
	if !slices.Equal(rep.Limitations[len(rep.Limitations)-len(frrBGPWithdrawLimitations):], frrBGPWithdrawLimitations) {
		t.Errorf("limitations do not end with the withdrawal limitations: %q", rep.Limitations)
	}
	// A state other than Established beside the peer's paths, or a path from such
	// a peer, is reported as observed, never as the captures disagreeing.
	_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", spec)
	if strings.Contains(text, "disagree") || strings.Contains(w.Reason, "disagree") {
		t.Errorf("withdrawal calls the captures a disagreement:\n%s", text)
	}
	return *w
}

// pathPeers lists each path's peer, or its kind when it names none.
func pathPeers(paths []frrBGPPathRead) []string {
	var out []string
	for _, p := range paths {
		out = append(out, p.Kind+" "+p.Peer)
	}
	return out
}

// TestWithdrawLabFixturesArePreservedBytes checks every lab file against the
// digest SHA256SUMS records, so a test never reads a rewritten capture.
func TestWithdrawLabFixturesArePreservedBytes(t *testing.T) {
	lab := openRoot(t, withdrawLab)
	sums, err := lab.ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != 20 {
		t.Fatalf("SHA256SUMS lists %d files, want 20", len(lines))
	}
	for _, line := range lines {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("malformed line %q", line)
		}
		raw, err := lab.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(raw)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s does not match SHA256SUMS", name)
		}
	}
}

// TestWithdrawPredictionsMatchTheLiveLab reads each prediction from one lab
// phase and checks it against r1's table in the next phase, which FRR printed
// after r2 really withdrew the prefix. The paths the prediction keeps must be
// exactly the paths FRR still lists, and a prediction of no recorded path must
// find the prefix gone. The lab has no peer that sends a path only once another
// is withdrawn, so this shows the table arithmetic, not that no path can arrive.
func TestWithdrawPredictionsMatchTheLiveLab(t *testing.T) {
	cases := []struct {
		from, to, spec, outcome string
		remaining               []string
		// sole says the lab withdrew only this prefix in the step, so the peer's
		// other paths must all still be listed afterwards.
		sole bool
	}{
		{"before", "after1", "r1:10.0.1.2:10.10.2.0/24", withdrawPathsRemain, []string{"learned 10.0.3.3"}, true},
		{"after1", "after2", "r1:10.0.1.2:10.10.9.0/24", withdrawNoRecordedPath, nil, false},
		{"after1", "after2", "r1:10.0.1.2:10.10.1.0/24", withdrawPathsRemain, []string{"no_peer "}, false},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			w := runWithdrawJSON(t, stageWithdrawPhase(t, c.from), c.spec)
			if w.Outcome != c.outcome || !slices.Equal(pathPeers(w.Remaining), c.remaining) {
				t.Fatalf("outcome %s, remaining %q; want %s, %q", w.Outcome, pathPeers(w.Remaining), c.outcome, c.remaining)
			}
			if !slices.Equal(pathPeers(w.Removed), []string{"learned 10.0.1.2"}) || w.PeerSessionState != frrbgp.StateEstablished {
				t.Fatalf("removed %q, peer session %q", pathPeers(w.Removed), w.PeerSessionState)
			}

			lab := openRoot(t, withdrawLab)
			raw, err := lab.ReadFile("r1-" + c.to + "-show_ip_bgp_json.raw")
			if err != nil {
				t.Fatal(err)
			}
			after, err := frrbgp.DecodeRouteCapture(raw, "r1")
			if err != nil {
				t.Fatal(err)
			}
			var listed []string
			others := 0
			for _, e := range after.Routes {
				for _, p := range e.Paths {
					kind, peer := pathNoPeer, ""
					if p.Source == frrbgp.RouteSourceLearned {
						kind, peer = pathLearned, p.Peer.String()
					}
					if e.Prefix.String() == w.Prefix {
						listed = append(listed, kind+" "+peer)
					} else if peer == w.Peer {
						others++
					}
				}
			}
			if !slices.Equal(listed, c.remaining) {
				t.Errorf("FRR lists %q for %s after the withdrawal; predicted %q", listed, w.Prefix, c.remaining)
			}
			if c.sole && others != w.PeerOtherPaths {
				t.Errorf("FRR lists %d of the peer's paths for other prefixes after the withdrawal; predicted %d stay", others, w.PeerOtherPaths)
			}

			summary, err := lab.ReadFile("r1-" + c.to + "-show_ip_bgp_summary_json.raw")
			if err != nil {
				t.Fatal(err)
			}
			s, err := frrbgp.Decode(summary, "r1")
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range s.Peers {
				if p.Address.String() == w.Peer && p.State != frrbgp.StateEstablished {
					t.Errorf("peer %s is %s after a prefix withdrawal; the lab expects the session to stay up", w.Peer, p.State)
				}
			}
		})
	}
}

// TestWithdrawFromSteadyCaptureLeavesNoRecordedPath reads the steady capture: r1
// learned 10.10.2.0/24 only from r2. r2's table lists the same prefix, from no
// peer, and the withdrawal never reads it.
func TestWithdrawFromSteadyCaptureLeavesNoRecordedPath(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	w := runWithdrawJSON(t, manifest, "r1:10.0.1.2:10.10.2.0/24")
	if w.Outcome != withdrawNoRecordedPath || len(w.Remaining) != 0 || w.PeerOtherPaths != 0 || w.Node != "r1" || w.VRF != "default" || w.Family != "IPv4 unicast" {
		t.Fatalf("withdrawal = %+v", w)
	}
	if len(w.Evidence) != 2 || w.Evidence[0].Source != "r1 bgp table" || w.Evidence[1].Source != "r1 bgp summary" {
		t.Errorf("evidence = %+v, want r1's table, then its summary", w.Evidence)
	}
	if !strings.Contains(w.Reason, "no route loss is claimed") {
		t.Errorf("reason %q claims more than the table shows", w.Reason)
	}

	code, _, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", "r2:10.0.1.1:10.10.2.0/24")
	if code != 2 || !strings.Contains(stderr, `the route table of node "r2" lists no path for 10.10.2.0/24 learned from peer 10.0.1.1`) {
		t.Fatalf("r2's table holds only its own path, so exit = %d, want 2; stderr: %s", code, stderr)
	}
}

// bgpPath is one path object in the shape show ip bgp json prints. An empty
// peerID leaves the key out.
func bgpPath(peerID, asPath, origin, nextHop string) string {
	peer := ""
	if peerID != "" {
		peer = fmt.Sprintf(`"peerId":%q,`, peerID)
	}
	return fmt.Sprintf(`{"valid":true,"pathFrom":"external",%s"path":%q,"origin":%q,"nexthops":[{"ip":%q,"afi":"ipv4","used":true}]}`, peer, asPath, origin, nextHop)
}

// bgpTableBody is a route table for r1 that matches the steady r1 summary's
// router ID and local AS.
func bgpTableBody(routes map[string][]string) string {
	var entries []string
	for _, prefix := range slices.Sorted(maps.Keys(routes)) {
		entries = append(entries, fmt.Sprintf("%q: [%s]", prefix, strings.Join(routes[prefix], ",")))
	}
	return `{"vrfName":"default","routerId":"1.1.1.1","localAS":65001,"routes":{` + strings.Join(entries, ",") + "}}"
}

// stageSyntheticTable stages the steady r1 and r2 summaries and an edited r1
// table. The table is hand-written, not FRR output. With summary false, r1's
// summary is dropped from the manifest.
func stageSyntheticTable(t *testing.T, routes map[string][]string, summary bool) string {
	t.Helper()
	dir, manifest := stageFRRBGP(t)
	if !summary {
		editFRRJSON(t, manifest, func(m map[string]any) { m["captures"] = m["captures"].([]any)[1:] })
	}
	addFRRBGPCapture(t, dir, manifest, frrBGPRouteEntry("r1", "2026-10-13T01:22:30Z"), frrBGPTableFrame("r1", bgpTableBody(routes)))
	return manifest
}

// TestWithdrawReadsEachRemainingPath covers every kind of remaining path. The
// steady r1 summary shows 10.0.1.2 Established and 10.0.1.3 Active, and lists
// no other peer.
func TestWithdrawReadsEachRemainingPath(t *testing.T) {
	const prefix = "10.20.0.0/16"
	cases := []struct {
		name      string
		peer      string
		paths     []string
		summary   bool
		outcome   string
		remaining []string
		states    []string
		reason    string
	}{
		{"alternate from an established peer", "10.0.1.7", []string{bgpPath("10.0.1.7", "65007", "IGP", "10.0.1.7"), bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}, true,
			withdrawPathsRemain, []string{"learned 10.0.1.2"}, []string{"Established"}, "still lists a path"},
		{"no replacement", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9")}, true,
			withdrawNoRecordedPath, nil, nil, "no route loss is claimed"},
		{"no peer recorded", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("(unspec)", "", "incomplete", "0.0.0.0")}, true,
			withdrawPathsRemain, []string{"no_peer "}, []string{""}, "still lists a path"},
		{"missing peer attribution", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("", "65009", "IGP", "10.0.1.9")}, true,
			withdrawUnknown, []string{"unattributed "}, []string{""}, "1 name no peer, so any of them may be peer 10.0.1.9's own"},
		{"unspecified peer address", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("0.0.0.0", "65009", "IGP", "10.0.1.9")}, true,
			withdrawUnknown, []string{"unattributed "}, []string{""}, "may be peer 10.0.1.9's own"},
		{"alternate from a peer the summary shows Active", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")}, true,
			withdrawUnknown, []string{"contradicted 10.0.1.3"}, []string{"Active"}, "1 come from peers the summary does not show Established"},
		{"alternate from a peer the summary does not list", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.8", "65008", "IGP", "10.0.1.8")}, true,
			withdrawUnknown, []string{"contradicted 10.0.1.8"}, []string{""}, "and the captures do not show why the table lists them"},
		{"both kinds of doubt", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")}, true,
			withdrawUnknown, []string{"unattributed ", "contradicted 10.0.1.3"}, []string{"", "Active"}, "1 name no peer, so any of them may be peer 10.0.1.9's own; 1 come from peers"},
		{"alternate with no summary captured", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")}, false,
			withdrawPathsRemain, []string{"learned 10.0.1.3"}, []string{""}, "still lists a path"},
		{"mixed sources and origins", "10.0.1.9", []string{bgpPath("", "65008", "EGP", "10.0.1.8"), bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "incomplete", "10.0.1.3"), bgpPath("(unspec)", "", "incomplete", "0.0.0.0")}, true,
			withdrawPathsRemain, []string{"unattributed ", "contradicted 10.0.1.3", "no_peer "}, []string{"", "Active", ""}, "still lists a path"},
		{"two paths from the withdrawing peer", "10.0.1.9", []string{bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.9", "65009 65010", "IGP", "10.0.1.9")}, true,
			withdrawNoRecordedPath, nil, nil, "lists no other path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string][]string{prefix: c.paths, "10.30.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}
			peer := c.peer
			w := runWithdrawJSON(t, stageSyntheticTable(t, routes, c.summary), "r1:"+peer+":"+prefix)
			if peer == "10.0.1.7" || peer == "10.0.1.9" {
				// Neither peer is in the steady summary, so the session is not shown.
				if w.PeerSessionState != "" {
					t.Errorf("peer session %q, want none", w.PeerSessionState)
				}
			}
			var states []string
			for _, p := range w.Remaining {
				states = append(states, p.SessionState)
			}
			if w.Outcome != c.outcome || !slices.Equal(pathPeers(w.Remaining), c.remaining) || !slices.Equal(states, c.states) {
				t.Fatalf("outcome %s, remaining %q with states %q; want %s, %q, %q", w.Outcome, pathPeers(w.Remaining), states, c.outcome, c.remaining, c.states)
			}
			if !strings.Contains(w.Reason, c.reason) {
				t.Errorf("reason %q, want it to say %q", w.Reason, c.reason)
			}
			for _, p := range w.Removed {
				if p.Peer != peer {
					t.Errorf("removed a path from %s", p.Peer)
				}
			}
			if w.PeerOtherPaths != 0 {
				t.Errorf("peer %s has no path for another prefix, but %d are counted", peer, w.PeerOtherPaths)
			}
		})
	}
}

// TestWithdrawIsNotASessionLoss withdraws one prefix of a peer that sends three,
// and checks that only that prefix's path goes, and that every other prefix,
// the peer's included, is neither removed nor read as remaining.
func TestWithdrawIsNotASessionLoss(t *testing.T) {
	routes := map[string][]string{
		"10.20.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2"), bgpPath("(unspec)", "", "IGP", "0.0.0.0")},
		"10.30.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")},
		"10.40.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")},
		"10.50.0.0/16": {bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")},
	}
	manifest := stageSyntheticTable(t, routes, true)
	w := runWithdrawJSON(t, manifest, "r1:10.0.1.2:10.20.0.0/16")
	if w.Outcome != withdrawPathsRemain || !slices.Equal(pathPeers(w.Removed), []string{"learned 10.0.1.2"}) || !slices.Equal(pathPeers(w.Remaining), []string{"no_peer "}) {
		t.Fatalf("withdrawal = %+v", w)
	}
	if w.PeerOtherPaths != 2 || w.PeerSessionState != frrbgp.StateEstablished {
		t.Errorf("peer other paths %d, session %q; want 2 and Established", w.PeerOtherPaths, w.PeerSessionState)
	}
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", "r1:10.0.1.2:10.20.0.0/16")
	if code != 0 {
		t.Fatalf("exit = %d; stderr: %s", code, stderr)
	}
	for _, want := range []string{
		"peer 10.0.1.2 withdraws 10.20.0.0/16 at r1 (vrf default, IPv4 unicast)",
		"  removed: learned path from peer 10.0.1.2, session Established, AS path 65002, BGP origin IGP, next hops 10.0.1.2\n",
		"  remains: no_peer path from no peer recorded, AS path (empty), BGP origin IGP, next hops 0.0.0.0\n",
		"the summary printed state Established, and a prefix withdrawal leaves the session as recorded",
		"not withdrawn: the peer's learned paths for other prefixes (2); a prefix withdrawal is not a session loss",
		"forwarding impact unknown:",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("text lacks %q:\n%s", want, stdout)
		}
	}
	for _, never := range []string{"reachability_lost", "redundancy_lost", "session loss of", "withdrawn from the FIB"} {
		if strings.Contains(stdout, never) {
			t.Errorf("text claims %q:\n%s", never, stdout)
		}
	}
}

// TestWithdrawingPeerSessionIsReportedNotJudged checks that the withdrawing
// peer's own recorded state is shown, and does not change the outcome, which
// rests on the paths that remain.
func TestWithdrawingPeerSessionIsReportedNotJudged(t *testing.T) {
	for _, c := range []struct{ peer, state, text string }{
		{"10.0.1.3", "Active", "session: the summary printed state Active, while the table lists paths from it; the captures do not show why"},
		{"10.0.1.7", "", "session: the summary does not list this peer, while the table lists paths from it; the captures do not show why"},
	} {
		routes := map[string][]string{"10.20.0.0/16": {bgpPath(c.peer, "65003", "IGP", c.peer), bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}
		manifest := stageSyntheticTable(t, routes, true)
		w := runWithdrawJSON(t, manifest, "r1:"+c.peer+":10.20.0.0/16")
		if w.Outcome != withdrawPathsRemain || w.PeerSessionState != c.state {
			t.Errorf("%s: outcome %s, session %q; want paths_remain, %q", c.peer, w.Outcome, w.PeerSessionState, c.state)
		}
		_, stdout, _ := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", "r1:"+c.peer+":10.20.0.0/16")
		if !strings.Contains(stdout, c.text) {
			t.Errorf("%s: text lacks %q:\n%s", c.peer, c.text, stdout)
		}
	}
	routes := map[string][]string{"10.20.0.0/16": {bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")}}
	_, stdout, _ := runNetdoc(t, "--import-frr-bgp", stageSyntheticTable(t, routes, false), "--withdraw-bgp", "r1:10.0.1.3:10.20.0.0/16")
	if !strings.Contains(stdout, "session: not captured; the manifest names no summary for r1") {
		t.Errorf("text does not say the session was not captured:\n%s", stdout)
	}
}

// TestWithdrawRemovedPathKeepsItsSessionState checks that a removed path carries
// the state the node's summary printed for its peer, as a remaining path does,
// and none when no summary lists the peer. The state is reported, never judged:
// the outcome and the forwarding uncertainty are the same in every case.
func TestWithdrawRemovedPathKeepsItsSessionState(t *testing.T) {
	for _, c := range []struct {
		name, peer string
		summary    bool
		state      string
	}{
		{"established peer", "10.0.1.2", true, "Established"},
		{"active peer", "10.0.1.3", true, "Active"},
		{"peer the summary does not list", "10.0.1.7", true, ""},
		{"no summary captured", "10.0.1.2", false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			routes := map[string][]string{"10.20.0.0/16": {bgpPath(c.peer, "65002", "IGP", c.peer), bgpPath("(unspec)", "", "IGP", "0.0.0.0")}}
			manifest := stageSyntheticTable(t, routes, c.summary)
			spec := "r1:" + c.peer + ":10.20.0.0/16"
			w := runWithdrawJSON(t, manifest, spec)
			if w.Outcome != withdrawPathsRemain || !slices.Equal(pathPeers(w.Remaining), []string{"no_peer "}) || w.PeerSessionState != c.state {
				t.Fatalf("outcome %s, remaining %q, peer session %q; want paths_remain, [no_peer], %q", w.Outcome, pathPeers(w.Remaining), w.PeerSessionState, c.state)
			}
			if len(w.Removed) != 1 || w.Removed[0].Kind != pathLearned || w.Removed[0].Peer != c.peer || w.Removed[0].SessionState != c.state {
				t.Fatalf("removed %+v, want one learned path from %s with session state %q", w.Removed, c.peer, c.state)
			}

			// The JSON key is present only when a state was recorded.
			_, stdout, _ := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", spec, "--json")
			var rep struct {
				Withdrawal struct {
					Removed []map[string]any `json:"removed"`
				} `json:"withdrawal"`
			}
			if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
				t.Fatal(err)
			}
			got, present := rep.Withdrawal.Removed[0]["session_state"]
			if present != (c.state != "") || (present && got != c.state) {
				t.Errorf("removed session_state = %v (present %v), want %q", got, present, c.state)
			}

			_, text, _ := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", spec)
			want := "  removed: learned path from peer " + c.peer + ", AS path"
			if c.state != "" {
				want = "  removed: learned path from peer " + c.peer + ", session " + c.state + ", AS path"
			}
			if !strings.Contains(text, want) {
				t.Errorf("text lacks %q:\n%s", want, text)
			}
		})
	}
}

// TestWithdrawRefusesWhatTheTableDoesNotDescribe checks that a withdrawal the
// capture does not describe exits 2, so it never reads as changing nothing.
func TestWithdrawRefusesWhatTheTableDoesNotDescribe(t *testing.T) {
	routes := map[string][]string{"10.20.0.0/16": {bgpPath("", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")}}
	manifest := stageSyntheticTable(t, routes, true)
	for _, c := range []struct{ spec, want string }{
		{"r1:10.0.1.9:10.20.0.0/16", `the route table of node "r1" lists no path for 10.20.0.0/16 learned from peer 10.0.1.9; 1 of its paths for that prefix name no peer, so the table cannot show whether one came from it`},
		{"r1:10.0.1.3:10.21.0.0/16", `the route table of node "r1" lists no path for 10.21.0.0/16 learned from peer 10.0.1.3`},
		{"r2:10.0.1.1:10.20.0.0/16", `the manifest names no "show ip bgp json" capture for node "r2"`},
		{"r9:10.0.1.3:10.20.0.0/16", `the manifest names no "show ip bgp json" capture for node "r9"`},
	} {
		code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", c.spec)
		if code != 2 || stdout != "" || stderr != "netdoc: -withdraw-bgp: "+c.want+"\n" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 and %q", c.spec, code, stdout, stderr, c.want)
		}
	}
}

func TestParseBGPWithdraw(t *testing.T) {
	got, err := parseBGPWithdraw("r1:fe80::1:10.20.0.0/16")
	if err != nil || got != (bgpWithdraw{"r1", netip.MustParseAddr("fe80::1"), netip.MustParsePrefix("10.20.0.0/16")}) {
		t.Fatalf("IPv6 peer: %+v, %v", got, err)
	}
	for spec, want := range map[string]string{
		"r1":                         "is not node:peer:prefix",
		"r1:10.0.1.2":                "is not node:peer:prefix",
		":10.0.1.2:10.20.0.0/16":     "is not node:peer:prefix",
		"r1::10.20.0.0/16":           "is not node:peer:prefix",
		"r1:10.0.1.2:":               "is not node:peer:prefix",
		"r1:peer:10.20.0.0/16":       `peer "peer" is not an IP address`,
		"r1:fe80::1%e1:10.20.0.0/16": `peer "fe80::1%e1" is not an IP address`,
		"r1:10.0.1.2:10.20.0.1/16":   `prefix "10.20.0.1/16" is not a canonical IPv4 prefix`,
		"r1:10.0.1.2:10.20.0.0":      `prefix "10.20.0.0" is not a canonical IPv4 prefix`,
		"r1:10.0.1.2:2001:db8::/32":  `peer "10.0.1.2:2001:db8:" is not an IP address`,
		"r1:10.0.1.2:010.20.0.0/16":  `prefix "010.20.0.0/16" is not a canonical IPv4 prefix`,
	} {
		if _, err := parseBGPWithdraw(spec); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", spec, err, want)
		}
	}
}

// TestWithdrawFlagNeedsTheBGPImport checks the CLI refusals. A malformed
// selector is refused before the manifest is read.
func TestWithdrawFlagNeedsTheBGPImport(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	topology := writeTopology(t, explainTopology)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24"}, "netdoc: -withdraw-bgp needs -import-frr-bgp and node:peer:prefix\n"},
		{[]string{"--explain", topology, "10.20.40.8", "--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24"}, "netdoc: -withdraw-bgp needs -import-frr-bgp and node:peer:prefix\n"},
		{[]string{"--import-frr-ospf", manifest, "--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24"}, "netdoc: -withdraw-bgp needs -import-frr-bgp and node:peer:prefix\n"},
		{[]string{"--import-frr-bgp", manifest, "--withdraw-bgp", ""}, "netdoc: -withdraw-bgp needs -import-frr-bgp and node:peer:prefix\n"},
		{[]string{"--import-frr-bgp", "/nonexistent/manifest.json", "--withdraw-bgp", "r1:10.0.1.2"}, "netdoc: -withdraw-bgp: \"r1:10.0.1.2\" is not node:peer:prefix\n"},
		{[]string{"--import-frr-bgp", manifest, "--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24", "--fail", "r1"}, "netdoc: -fail needs -explain and a node or node:interface\n"},
	} {
		code, stdout, stderr := runNetdoc(t, c.args...)
		if code != 2 || stdout != "" || stderr != c.want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2 and %q", c.args, code, stdout, stderr, c.want)
		}
	}
}

func TestUsageNamesTheWithdrawal(t *testing.T) {
	code, stdout, _ := runNetdoc(t, "--help")
	if code != 0 || !strings.Contains(stdout, "netdoc --import-frr-bgp manifest.json --withdraw-bgp NODE:PEER:PREFIX [--json]") {
		t.Errorf("exit = %d; usage does not name the withdrawal:\n%s", code, stdout)
	}
}

// TestWithdrawLeavesOtherReportsUnchanged checks that the report gains a
// withdrawal only with the flag, and that the rest of the report is the same.
func TestWithdrawLeavesOtherReportsUnchanged(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	for _, jsonOut := range []bool{false, true} {
		args := []string{"--import-frr-bgp", manifest}
		if jsonOut {
			args = append(args, "--json")
		}
		_, plain, _ := runNetdoc(t, args...)
		_, with, _ := runNetdoc(t, append(args, "--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24")...)
		if strings.Contains(plain, "Prefix withdrawal") || strings.Contains(plain, `"withdrawal"`) {
			t.Errorf("report without the flag mentions a withdrawal:\n%s", plain)
		}
		if !jsonOut {
			// The block runs from its heading to the blank line before the next
			// section, and the limitations section is last.
			start := strings.Index(with, "\nPrefix withdrawal")
			end := start + 1 + strings.Index(with[start+1:], "\n\n") + 1
			want := plain
			for _, l := range frrBGPWithdrawLimitations {
				want += "  " + l + "\n"
			}
			if start < 0 || with[:start]+with[end:] != want {
				t.Errorf("text with the flag differs beyond the withdrawal block and limitations:\n%s", with)
			}
			continue
		}
		var a, b map[string]any
		if err := json.Unmarshal([]byte(plain), &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(with), &b); err != nil {
			t.Fatal(err)
		}
		delete(b, "withdrawal")
		b["limitations"] = b["limitations"].([]any)[:len(a["limitations"].([]any))]
		if !reflect.DeepEqual(a, b) {
			t.Errorf("JSON with the flag differs beyond withdrawal and limitations")
		}
	}
}

// TestWithdrawIsDeterministicAndBounded runs one withdrawal twice and with the
// manifest reversed, and checks that the text lists at most frrBGPLearnedLimit
// paths of each list while the JSON keeps them all.
func TestWithdrawIsDeterministicAndBounded(t *testing.T) {
	var paths []string
	for i := range 25 {
		paths = append(paths, bgpPath("(unspec)", "", "IGP", fmt.Sprintf("10.0.9.%d", i)))
	}
	paths = append(paths, bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2"))
	manifest := stageSyntheticTable(t, map[string][]string{"10.20.0.0/16": paths}, true)
	args := []string{"--import-frr-bgp", manifest, "--withdraw-bgp", "r1:10.0.1.2:10.20.0.0/16", "--json"}
	_, first, _ := runNetdoc(t, args...)
	_, second, _ := runNetdoc(t, args...)
	editFRRJSON(t, manifest, func(m map[string]any) { slices.Reverse(m["captures"].([]any)) })
	_, reversed, _ := runNetdoc(t, args...)
	withdrawalOf := func(s string) string {
		var rep map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &rep); err != nil {
			t.Fatal(err)
		}
		return string(rep["withdrawal"])
	}
	if first != second || withdrawalOf(first) != withdrawalOf(reversed) {
		t.Fatal("the withdrawal differs between runs or with the manifest reversed")
	}
	if w := runWithdrawJSON(t, manifest, "r1:10.0.1.2:10.20.0.0/16"); len(w.Remaining) != 25 || w.Remaining[24].NextHops[0] != "10.0.9.24" {
		t.Fatalf("JSON keeps %d remaining paths, want all 25 in FRR's order", len(w.Remaining))
	}
	_, text, _ := runNetdoc(t, args[:len(args)-1]...)
	if n := strings.Count(text, "  remains: no_peer path"); n != frrBGPLearnedLimit || !strings.Contains(text, "  remains: 5 more; see --json\n") {
		t.Errorf("text lists %d remaining paths, want %d and a count of the rest:\n%s", n, frrBGPLearnedLimit, text)
	}
}

// TestWithdrawDoesNotChangeItsInputs checks that the table and summary it reads
// are unchanged afterwards.
func TestWithdrawDoesNotChangeItsInputs(t *testing.T) {
	raw, _ := committedRouteTable(t, "r1")
	table, err := frrbgp.DecodeRouteCapture(raw, "r1")
	if err != nil {
		t.Fatal(err)
	}
	summaryRaw, err := openRoot(t, frrBGPSteady).ReadFile("r1-show_ip_bgp_summary_json.raw")
	if err != nil {
		t.Fatal(err)
	}
	sum, err := frrbgp.Decode(summaryRaw, "r1")
	if err != nil {
		t.Fatal(err)
	}
	tableCopy, _ := frrbgp.DecodeRouteCapture(raw, "r1")
	sumCopy, _ := frrbgp.Decode(summaryRaw, "r1")
	capture := frrospf.ManifestCapture{Node: "r1", VRF: "default", Source: "t", CollectedAt: time.Unix(0, 0)}
	sel, err := parseBGPWithdraw("r1:10.0.1.2:10.10.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withdrawFRRBGP(sel, table, capture, &sum, capture); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(table, tableCopy) || !reflect.DeepEqual(sum, sumCopy) {
		t.Fatal("withdrawFRRBGP changed its inputs")
	}
}
