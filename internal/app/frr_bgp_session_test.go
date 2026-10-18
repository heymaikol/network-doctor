package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/frrbgp"
)

// sessionLab holds the three session-loss runs described in "Session-loss
// runs" in testdata/frr/10.7.0/bgp/README.md. Each arm is one run of
// lab/bgp-session.sh, and r1 loses its session with r2 at 10.0.1.2.
const sessionLab = "../../testdata/frr/10.7.0/bgp/session/"

// sessionLabPeer is the peer whose session each arm ends.
const sessionLabPeer = "10.0.1.2"

// sessionLabPhases lists each arm's phases in the order they were captured.
var sessionLabPhases = map[string][]string{
	"plain": {"before", "after"},
	"gr":    {"before", "during", "expired"},
	"admin": {"before", "after"},
}

// sessionLabRaw reads one file of an arm.
func sessionLabRaw(t *testing.T, arm, file string) []byte {
	t.Helper()
	raw, err := openRoot(t, sessionLab+arm).ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// sessionLabJSON reads the JSON object of one r1 vty capture of an arm, with
// every field FRR printed, for checks on fields the decoders do not read.
func sessionLabJSON(t *testing.T, arm, phase, cmd string) map[string]any {
	t.Helper()
	raw := sessionLabRaw(t, arm, "r1-"+phase+"-"+strings.ReplaceAll(cmd, " ", "_")+".raw")
	body := bytes.TrimSuffix(bytes.TrimPrefix(raw, []byte(cmd+"\r\n")), []byte("\r\nr1> "))
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%s %s %s: %v", arm, phase, cmd, err)
	}
	return v
}

// TestSessionLabFixturesArePreservedBytes checks every lab file against the
// digest SHA256SUMS records, so a test never reads a rewritten capture.
func TestSessionLabFixturesArePreservedBytes(t *testing.T) {
	for arm, files := range map[string]int{"plain": 28, "gr": 36, "admin": 29} {
		lines := strings.Split(strings.TrimSpace(string(sessionLabRaw(t, arm, "SHA256SUMS"))), "\n")
		if len(lines) != files {
			t.Errorf("%s: SHA256SUMS lists %d files, want %d", arm, len(lines), files)
		}
		for _, line := range lines {
			sum, name, ok := strings.Cut(line, "  ")
			if !ok {
				t.Fatalf("%s: malformed line %q", arm, line)
			}
			got := sha256.Sum256(sessionLabRaw(t, arm, name))
			if hex.EncodeToString(got[:]) != sum {
				t.Errorf("%s/%s does not match SHA256SUMS", arm, name)
			}
		}
	}
}

// stablePaths lists each path of a decoded table that is not from skip, by
// the attributes a lost session elsewhere does not change: prefix, source,
// peer, pathFrom, AS path, BGP origin, and next-hop addresses.
func stablePaths(table frrbgp.RouteTable, skip string) []string {
	var out []string
	for _, e := range table.Routes {
		for _, p := range e.Paths {
			if p.Source == frrbgp.RouteSourceLearned && p.Peer.String() == skip {
				continue
			}
			out = append(out, fmt.Sprintf("%s %d %s %s %q %s %v", e.Prefix, p.Source, p.Peer, p.PathFrom, p.ASPath, p.Origin, p.NextHops))
		}
	}
	slices.Sort(out)
	return out
}

// dynamicFields are path fields FRR may change when another path for the
// prefix goes. The lab keeps them and no check depends on them.
var dynamicFields = []string{"bestpath", "selectionReason", "version", "multipath"}

// TestSessionLabUnrelatedPathsKeepTheirAttributes checks, in every phase after
// before, that each path not from the lost peer is still listed with the same
// stable attributes, and that no other path appears. It also lists how the
// dynamic fields of those paths changed, which FRR may legitimately do, and
// requires the comparison to hold while they change.
func TestSessionLabUnrelatedPathsKeepTheirAttributes(t *testing.T) {
	for arm, phases := range sessionLabPhases {
		before, err := frrbgp.DecodeRouteCapture(sessionLabRaw(t, arm, "r1-before-show_ip_bgp_json.raw"), "r1")
		if err != nil {
			t.Fatal(err)
		}
		want := stablePaths(before, sessionLabPeer)
		if len(want) != 3 {
			t.Fatalf("%s before: %d unrelated paths, want 3: %q", arm, len(want), want)
		}
		for _, phase := range phases[1:] {
			table, err := frrbgp.DecodeRouteCapture(sessionLabRaw(t, arm, "r1-"+phase+"-show_ip_bgp_json.raw"), "r1")
			if err != nil {
				t.Fatal(err)
			}
			if got := stablePaths(table, sessionLabPeer); !slices.Equal(got, want) {
				t.Errorf("%s %s: unrelated paths %q, want %q", arm, phase, got, want)
			}
		}
		// Dynamic fields are inspected, never required to stay the same.
		changed := 0
		first := sessionLabJSON(t, arm, "before", "show ip bgp json")["routes"].(map[string]any)
		for _, phase := range phases[1:] {
			routes := sessionLabJSON(t, arm, phase, "show ip bgp json")["routes"].(map[string]any)
			for prefix, paths := range routes {
				for _, p := range paths.([]any) {
					path := p.(map[string]any)
					if path["peerId"] == sessionLabPeer {
						continue
					}
					for _, q := range first[prefix].([]any) {
						old := q.(map[string]any)
						if old["peerId"] != path["peerId"] {
							continue
						}
						for _, f := range dynamicFields {
							if fmt.Sprint(old[f]) != fmt.Sprint(path[f]) {
								changed++
								t.Logf("%s %s: %s from %v: %s %v -> %v", arm, phase, prefix, path["peerId"], f, old[f], path[f])
							}
						}
					}
				}
			}
		}
		// Once r2's path for 10.10.2.0/24 is gone in every arm, r3's path there is
		// the only one, and FRR reselects it. That change must not fail the check above.
		if changed == 0 {
			t.Errorf("%s: no dynamic field of an unrelated path changed; the stable comparison was not exercised", arm)
		}
	}
}

// TestSessionLabRecordsWhatTheDesignRestsOn checks the facts the session-loss
// design takes from the runs, in fields netdoc does not read: which paths carry
// a stale key, the lost peer's state, and the remote graceful-restart mode FRR
// printed. Kernel routes are lab context and are not read.
func TestSessionLabRecordsWhatTheDesignRestsOn(t *testing.T) {
	cases := []struct {
		arm, phase, state, grMode string
		stale                     int // paths with a stale key, all from the lost peer and true
	}{
		{"plain", "before", "Established", "Helper", 0},
		{"plain", "after", "Active", "NotApplicable", 0},
		{"gr", "before", "Established", "Restart", 0},
		{"gr", "during", "Active", "NotApplicable", 3},
		{"gr", "expired", "Active", "NotApplicable", 0},
		{"admin", "before", "Established", "Restart", 0},
		{"admin", "after", "Idle (Admin)", "NotApplicable", 0},
	}
	for _, c := range cases {
		name := c.arm + " " + c.phase
		peers := sessionLabJSON(t, c.arm, c.phase, frrbgp.CommandSummary)["ipv4Unicast"].(map[string]any)["peers"].(map[string]any)
		if got := peers[sessionLabPeer].(map[string]any)["state"]; got != c.state {
			t.Errorf("%s: peer %s state %v, want %s", name, sessionLabPeer, got, c.state)
		}
		if got := peers["10.0.3.3"].(map[string]any)["state"]; got != "Established" {
			t.Errorf("%s: peer 10.0.3.3 state %v, want Established", name, got)
		}
		nbr := sessionLabJSON(t, c.arm, c.phase, "show ip bgp neighbors "+sessionLabPeer+" json")[sessionLabPeer].(map[string]any)
		if got := nbr["gracefulRestartInfo"].(map[string]any)["remoteGrMode"]; got != c.grMode {
			t.Errorf("%s: remoteGrMode %v, want %s", name, got, c.grMode)
		}
		stale := 0
		for prefix, paths := range sessionLabJSON(t, c.arm, c.phase, frrbgp.CommandRoute)["routes"].(map[string]any) {
			for _, p := range paths.([]any) {
				path := p.(map[string]any)
				v, ok := path["stale"]
				if !ok {
					continue
				}
				stale++
				if v != true || path["peerId"] != sessionLabPeer {
					t.Errorf("%s: %s path from %v has stale %v", name, prefix, path["peerId"], v)
				}
			}
		}
		if stale != c.stale {
			t.Errorf("%s: %d paths carry a stale key, want %d", name, stale, c.stale)
		}
	}
}

// runSession runs the import with --fail-bgp-session, in JSON and in text, and
// returns the session loss and the text report. Every call checks what each
// session loss must say: the removal is assumed, stale retention and forwarding
// stay unknown, and no sentence claims more than the captures show.
func runSession(t *testing.T, manifest, spec string) (frrBGPSessionLoss, string) {
	t.Helper()
	code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--fail-bgp-session", spec, "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	var rep frrBGPReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.SessionLoss == nil || rep.Withdrawal != nil {
		t.Fatalf("report does not carry only a session loss: %s", stdout)
	}
	if !slices.Equal(rep.Limitations[len(rep.Limitations)-len(frrBGPSessionLossLimitations):], frrBGPSessionLossLimitations) {
		t.Errorf("limitations do not end with the session-loss limitations: %q", rep.Limitations)
	}
	code, text, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--fail-bgp-session", spec)
	if code != 0 {
		t.Fatalf("text exit = %d, want 0; stderr: %s", code, stderr)
	}
	checkSessionClaims(t, *rep.SessionLoss, text)
	return *rep.SessionLoss, text
}

// checkSessionClaims checks the meaning of every sentence a session loss
// writes, in its text block, its JSON reasons, and its limitations. Words such
// as "selected" may appear, but only where the sentence says the thing is not
// read.
func checkSessionClaims(t *testing.T, s frrBGPSessionLoss, text string) {
	t.Helper()
	start := strings.Index(text, "\nBGP session loss (hypothetical, against the recorded BGP table; nothing was sent):\n")
	if start < 0 {
		t.Fatalf("no session-loss block in:\n%s", text)
	}
	block := text[start+1:]
	block = block[:strings.Index(block, "\n\n")]
	for _, want := range []string{
		"\n  " + s.PeerSessionReason + "\n",
		"\n  assumed: " + s.Assumption + "\n",
		"\n  recorded: " + s.RemovedReason + "\n",
		"\n  stale retention unknown: ",
		"\n  forwarding impact unknown: ",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("text block lacks %q:\n%s", want, block)
		}
	}
	if s.ForwardingImpact != "unknown" || s.StaleRetention != "unknown" {
		t.Errorf("forwarding %q, stale retention %q; both must stay unknown", s.ForwardingImpact, s.StaleRetention)
	}
	if !strings.HasPrefix(s.PeerSessionReason, "observed: ") || !strings.HasSuffix(s.Assumption, "not on an observed session loss") {
		t.Errorf("observation %q or assumption %q is not stated as one", s.PeerSessionReason, s.Assumption)
	}
	if (s.PeerSessionReading == sessionNotEstablished || s.PeerSessionReading == sessionNotListed) && len(s.Prefixes) > 0 && !strings.Contains(s.PeerSessionReason, "do not show why") {
		t.Errorf("reading %s: reason %q claims to know why the table lists the paths", s.PeerSessionReading, s.PeerSessionReason)
	}
	if s.PeerSessionReading == sessionNotEstablished && !strings.Contains(s.PeerSessionReason, "this is not read as an established session being lost") {
		t.Errorf("reason %q does not say an already down session is not a new loss", s.PeerSessionReason)
	}
	sentences := append(strings.Split(block, "\n"), frrBGPSessionLossLimitations...)
	sentences = append(sentences, s.Assumption, s.PeerSessionReason, s.RemovedReason, s.StaleRetentionReason, s.ForwardingReason)
	for _, p := range s.Prefixes {
		sentences = append(sentences, p.Reason)
		for _, r := range slices.Concat(p.Removed, p.Remaining) {
			if r.StaleFlag != staleRecordedTrue && r.StaleFlag != staleRecordedFalse && r.StaleFlag != staleNotRecorded {
				t.Errorf("%s: path %+v has stale_flag %q", p.Prefix, r, r.StaleFlag)
			}
		}
	}
	has := func(s string, words ...string) bool {
		return slices.ContainsFunc(words, func(w string) bool { return strings.Contains(s, w) })
	}
	for _, sentence := range sentences {
		for clause := range strings.SplitSeq(strings.ToLower(sentence), ";") {
			switch {
			case has(clause, "disagree", "conflict", "inconsistent", "reachability_lost", "redundancy_lost"):
				t.Errorf("clause %q reads the captures as disagreeing or rates forwarding", clause)
			case has(clause, "select", "install", "valid", "reachab", "usable") && !strings.Contains(clause, "not read"):
				t.Errorf("clause %q makes a selection, installation, or reachability claim", clause)
			case strings.Contains(clause, "stale") && has(clause, "fail", "lost", "loss", "down", "dropped", "prove", "means", "shows that"):
				t.Errorf("clause %q ties a stale flag to a session failure", clause)
			case has(clause, "newly", "was lost", "being lost", "went down", "has failed", "failed") && !strings.Contains(clause, "not "):
				t.Errorf("clause %q says a session failed", clause)
			}
		}
	}
}

// sessionShape lists each rated prefix as its outcome and the kind, peer, and
// stale flag of each remaining path.
func sessionShape(s frrBGPSessionLoss) []string {
	var out []string
	for _, p := range s.Prefixes {
		line := p.Prefix + " " + p.Outcome
		for _, r := range p.Remaining {
			line += " [" + r.Kind + " " + r.Peer + " " + r.StaleFlag + "]"
		}
		out = append(out, line)
	}
	return out
}

// TestSessionLossRatesEachPrefix covers each kind of remaining path and each
// stale flag beside it, over the steady r1 summary: 10.0.1.2 Established,
// 10.0.1.3 Active, and no other peer. Tables are hand-written, not FRR output.
func TestSessionLossRatesEachPrefix(t *testing.T) {
	p := func(peer string) string { return bgpPath(peer, "65009", "IGP", "10.0.1.9") }
	sp := func(value, peer string) string { return stalePath(value, peer, "65009", "IGP", "10.0.1.9") }
	cases := []struct {
		name, spec   string
		routes       map[string][]string
		summary      bool
		reading      string
		want         []string
		unattributed []string
	}{
		{"S1 several prefixes from one peer", "r1:10.0.1.2", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.2")},
			"10.30.0.0/16": {p("10.0.1.2"), p("(unspec)")},
			"10.40.0.0/16": {p("10.0.1.9"), p("10.0.1.2")},
			"10.50.0.0/16": {p("10.0.1.9")},
		}, true, sessionEstablished, []string{
			"10.20.0.0/16 no_recorded_path",
			"10.30.0.0/16 paths_remain [no_peer  not_recorded]",
			"10.40.0.0/16 unknown [contradicted 10.0.1.9 not_recorded]",
		}, nil},
		{"S2 another Established peer remains", "r1:10.0.1.3", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.3"), p("10.0.1.2")},
		}, true, sessionNotEstablished, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 not_recorded]"}, nil},
		{"S4 a path that names no peer", "r1:10.0.1.2", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.2"), p("")},
			"10.30.0.0/16": {p(""), p("(unspec)")},
		}, true, sessionEstablished, []string{"10.20.0.0/16 unknown [unattributed  not_recorded]"}, []string{"10.30.0.0/16"}},
		{"S5 no summary", "r1:10.0.1.2", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.2"), p("10.0.1.3")},
		}, false, sessionNotCaptured, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.3 not_recorded]"}, nil},
		{"S6a Active peer with paths", "r1:10.0.1.3", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.3")},
		}, true, sessionNotEstablished, []string{"10.20.0.0/16 no_recorded_path"}, nil},
		{"S6b Active peer with stale paths", "r1:10.0.1.3", map[string][]string{
			"10.20.0.0/16": {sp("true", "10.0.1.3"), p("(unspec)")},
		}, true, sessionNotEstablished, []string{"10.20.0.0/16 paths_remain [no_peer  not_recorded]"}, nil},
		{"S7 peer the summary does not list", "r1:10.0.1.9", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.9"), p("10.0.1.2")},
		}, true, sessionNotListed, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 not_recorded]"}, nil},
		{"S8a only a stale Established path remains", "r1:10.0.1.9", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.9"), sp("true", "10.0.1.2")},
		}, true, sessionNotListed, []string{"10.20.0.0/16 unknown [learned 10.0.1.2 recorded_true]"}, nil},
		{"S8b stale and other survivors", "r1:10.0.1.9", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.9"), sp("true", "10.0.1.2"), p("(unspec)")},
		}, true, sessionNotListed, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 recorded_true] [no_peer  not_recorded]"}, nil},
		{"S8c stale local path", "r1:10.0.1.2", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.2"), sp("true", "(unspec)")},
		}, true, sessionEstablished, []string{"10.20.0.0/16 unknown [no_peer  recorded_true]"}, nil},
		{"S8d recorded false counts", "r1:10.0.1.9", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.9"), sp("false", "10.0.1.2")},
		}, true, sessionNotListed, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 recorded_false]"}, nil},
		{"S8e stale path from an Active peer", "r1:10.0.1.2", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.2"), sp("true", "10.0.1.3"), p("")},
		}, true, sessionEstablished, []string{"10.20.0.0/16 unknown [contradicted 10.0.1.3 recorded_true] [unattributed  not_recorded]"}, nil},
		{"S9 an alternate FRR marks invalid", "r1:10.0.1.9", map[string][]string{
			"10.20.0.0/16": {p("10.0.1.9"), strings.Replace(p("10.0.1.2"), `"valid":true`, `"valid":false`, 1)},
		}, true, sessionNotListed, []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 not_recorded]"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, text := runSession(t, stageSyntheticTable(t, c.routes, c.summary), c.spec)
			if got := sessionShape(s); !slices.Equal(got, c.want) {
				t.Errorf("prefixes %q, want %q", got, c.want)
			}
			if !slices.Equal(s.UnattributedPrefixes, c.unattributed) {
				t.Errorf("unattributed prefixes %q, want %q", s.UnattributedPrefixes, c.unattributed)
			}
			if s.PeerSessionReading != c.reading {
				t.Errorf("reading %s, want %s", s.PeerSessionReading, c.reading)
			}
			for _, p := range s.Prefixes {
				for _, r := range p.Removed {
					if r.Kind != pathLearned || r.Peer != s.Peer {
						t.Errorf("%s: removed %+v is not a learned path from %s", p.Prefix, r, s.Peer)
					}
				}
			}
			if c.name == "S8d recorded false counts" && !strings.Contains(text, "remains: learned path from peer 10.0.1.2, session Established, AS path 65009, BGP origin IGP, next hops 10.0.1.9, stale flag recorded false\n") {
				t.Errorf("text does not report the recorded false flag:\n%s", text)
			}
			if c.name == "S6b Active peer with stale paths" {
				if s.Prefixes[0].Removed[0].StaleFlag != staleRecordedTrue || !strings.Contains(s.PeerSessionReason, "1 of them carry FRR's stale flag, and the captures do not show what set it") {
					t.Errorf("removed %+v, reason %q", s.Prefixes[0].Removed, s.PeerSessionReason)
				}
			}
			if c.name == "S8a only a stale Established path remains" && !strings.Contains(s.Prefixes[0].Reason, "1 recorded stale, and what FRR later does with a stale path is not in the evidence") {
				t.Errorf("reason %q does not name the stale group", s.Prefixes[0].Reason)
			}
		})
	}
}

// TestSessionLossOfAListedPeerWithNoPath checks the qualified empty result: the
// summary lists the peer, and the table attributes no path to it.
func TestSessionLossOfAListedPeerWithNoPath(t *testing.T) {
	_, steady := stageFRRBGPRoutes(t)
	s, _ := runSession(t, steady, "r1:10.0.1.3")
	if len(s.Prefixes) != 0 || s.PeerSessionReading != sessionNotEstablished || s.PeerSessionState != "Active" {
		t.Fatalf("session loss = %+v", s)
	}
	if !strings.Contains(s.RemovedReason, "attributes no path to peer 10.0.1.3, so the assumption removes nothing from it; this is what the table recorded, not a finding that the peer advertised nothing") || strings.Contains(s.RemovedReason, "name no peer") {
		t.Errorf("removed reason %q", s.RemovedReason)
	}

	manifest := stageSyntheticTable(t, map[string][]string{"10.20.0.0/16": {bgpPath("", "65009", "IGP", "10.0.1.9")}}, true)
	s, _ = runSession(t, manifest, "r1:10.0.1.3")
	if !slices.Equal(s.UnattributedPrefixes, []string{"10.20.0.0/16"}) || !strings.HasSuffix(s.RemovedReason, "; the table lists paths that name no peer for 1 prefix with no path attributed to it, and it cannot show whether any of them came from this peer") {
		t.Errorf("unattributed %q, removed reason %q", s.UnattributedPrefixes, s.RemovedReason)
	}

	manifest = stageSyntheticTable(t, map[string][]string{"10.20.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}, true)
	replaceStaged(t, filepath.Dir(manifest), "r1-show_ip_bgp_summary_json.raw", `"state":"Active"`, `"state":"Established"`)
	s, _ = runSession(t, manifest, "r1:10.0.1.3")
	if len(s.Prefixes) != 0 || s.PeerSessionReading != sessionEstablished {
		t.Errorf("listed Established peer with no path: %+v", s)
	}
}

// TestSessionLossKeepsCaptureTimesApart checks that a summary taken hours after
// the table is listed with its own time, and changes nothing else.
func TestSessionLossKeepsCaptureTimesApart(t *testing.T) {
	routes := map[string][]string{"10.20.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2"), bgpPath("(unspec)", "", "IGP", "0.0.0.0")}}
	manifest := stageSyntheticTable(t, routes, true)
	near, _ := runSession(t, manifest, "r1:10.0.1.2")
	editFRRJSON(t, manifest, func(m map[string]any) {
		m["captures"].([]any)[0].(map[string]any)["collected_at"] = "2026-10-13T07:00:00Z"
	})
	far, _ := runSession(t, manifest, "r1:10.0.1.2")
	if far.Evidence[0] != near.Evidence[0] || far.Evidence[1].CollectedAt != "2026-10-13T07:00:00Z" {
		t.Errorf("evidence %+v", far.Evidence)
	}
	far.Evidence = near.Evidence
	if !reflect.DeepEqual(far, near) {
		t.Errorf("a later summary changed the result:\n%+v\n%+v", far, near)
	}
}

// TestSessionLossNamesAnIPv6Peer checks that an IPv6 peer is matched exactly
// against the summary key and peerId, and that a zone or an IPv4-mapped
// spelling matches nothing.
func TestSessionLossNamesAnIPv6Peer(t *testing.T) {
	routes := map[string][]string{"10.20.0.0/16": {bgpPath("2001:db8::3", "65003", "IGP", "10.0.1.3"), bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}
	manifest := stageSyntheticTable(t, routes, true)
	replaceStaged(t, filepath.Dir(manifest), "r1-show_ip_bgp_summary_json.raw", `"10.0.1.3":{`, `"2001:db8::3":{`)
	s, _ := runSession(t, manifest, "r1:2001:db8::3")
	if s.Peer != "2001:db8::3" || s.PeerSessionState != "Active" || !slices.Equal(sessionShape(s), []string{"10.20.0.0/16 paths_remain [learned 10.0.1.2 not_recorded]"}) {
		t.Errorf("session loss = %+v", s)
	}
	for spec, want := range map[string]string{
		"r1:fe80::1%e1":      `peer "fe80::1%e1" is not an IP address`,
		"r1:::ffff:10.0.1.2": `the route table of node "r1" attributes no path to peer ::ffff:10.0.1.2, and the summary of node "r1" does not list it`,
	} {
		code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--fail-bgp-session", spec)
		if code != 2 || stdout != "" || stderr != "netdoc: -fail-bgp-session: "+want+"\n" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 and %q", spec, code, stdout, stderr, want)
		}
	}
}

// TestSessionLossRefusesWhatNoCaptureNames checks that a peer neither capture
// names, a node with no table, and a malformed selector exit 2 with nothing on
// standard output.
func TestSessionLossRefusesWhatNoCaptureNames(t *testing.T) {
	routes := map[string][]string{
		"10.20.0.0/16": {bgpPath("", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.3", "65003", "IGP", "10.0.1.3")},
		"10.30.0.0/16": {bgpPath("", "65009", "IGP", "10.0.1.9")},
	}
	withSummary, without := stageSyntheticTable(t, routes, true), stageSyntheticTable(t, routes, false)
	for _, c := range []struct{ manifest, spec, want string }{
		{withSummary, "r1:10.0.1.9", `the route table of node "r1" attributes no path to peer 10.0.1.9, and the summary of node "r1" does not list it; 2 of the table's paths name no peer, so the table cannot show whether one came from it`},
		{without, "r1:10.0.1.2", `the route table of node "r1" attributes no path to peer 10.0.1.2, and the manifest names no summary for node "r1"; 2 of the table's paths name no peer, so the table cannot show whether one came from it`},
		{withSummary, "r2:10.0.1.1", `the manifest names no "show ip bgp json" capture for node "r2"`},
		{withSummary, "r9:10.0.1.1", `the manifest names no "show ip bgp json" capture for node "r9"`},
		{"/nonexistent/manifest.json", "r1", `"r1" is not node:peer`},
		{"/nonexistent/manifest.json", "r1:", `"r1:" is not node:peer`},
		{"/nonexistent/manifest.json", ":10.0.1.2", `":10.0.1.2" is not node:peer`},
		{"/nonexistent/manifest.json", "r1:peer", `peer "peer" is not an IP address`},
		{"/nonexistent/manifest.json", "r1:10.0.1.2:10.20.0.0/16", `peer "10.0.1.2:10.20.0.0/16" is not an IP address`},
	} {
		code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", c.manifest, "--fail-bgp-session", c.spec)
		if code != 2 || stdout != "" || stderr != "netdoc: -fail-bgp-session: "+c.want+"\n" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 and %q", c.spec, code, stdout, stderr, c.want)
		}
	}
	manifest := stageSyntheticTable(t, map[string][]string{"10.20.0.0/16": {bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}, false)
	code, _, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--fail-bgp-session", "r1:10.0.1.9")
	if code != 2 || strings.Contains(stderr, "name no peer") {
		t.Errorf("exit %d, stderr %q; a table with no unattributed path names none", code, stderr)
	}
}

// TestSessionLossFlagNeedsTheBGPImport checks the CLI refusals.
func TestSessionLossFlagNeedsTheBGPImport(t *testing.T) {
	_, manifest := stageFRRBGPRoutes(t)
	topology := writeTopology(t, explainTopology)
	const want = "netdoc: -fail-bgp-session needs -import-frr-bgp and node:peer, and no -withdraw-bgp\n"
	for _, args := range [][]string{
		{"--fail-bgp-session", "r1:10.0.1.2"},
		{"--explain", topology, "10.20.40.8", "--fail-bgp-session", "r1:10.0.1.2"},
		{"--import-frr-ospf", manifest, "--fail-bgp-session", "r1:10.0.1.2"},
		{"--import-frr-bgp", manifest, "--fail-bgp-session", ""},
		{"--import-frr-bgp", manifest, "--fail-bgp-session", "r1:10.0.1.2", "--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24"},
	} {
		code, stdout, stderr := runNetdoc(t, args...)
		if code != 2 || stdout != "" || stderr != want {
			t.Errorf("%q: exit %d, stdout %q, stderr %q; want 2 and %q", args, code, stdout, stderr, want)
		}
	}
	code, stdout, _ := runNetdoc(t, "--help")
	if code != 0 || !strings.Contains(stdout, "netdoc --import-frr-bgp manifest.json --fail-bgp-session NODE:PEER [--json]") {
		t.Errorf("exit = %d; usage does not name the session loss:\n%s", code, stdout)
	}
}

// TestSessionLossLeavesOtherReportsUnchanged checks that the flag adds only the
// session_loss object and its limitations to the JSON report, and only its block
// and limitations to the text report.
func TestSessionLossLeavesOtherReportsUnchanged(t *testing.T) {
	manifest := stageWithdrawPhase(t, "before")
	args := []string{"--import-frr-bgp", manifest}
	_, plain, _ := runNetdoc(t, args...)
	_, with, _ := runNetdoc(t, append(args, "--fail-bgp-session", "r1:10.0.1.2")...)
	start := strings.Index(with, "\nBGP session loss")
	end := start + 1 + strings.Index(with[start+1:], "\n\n") + 1
	want := plain
	for _, l := range frrBGPSessionLossLimitations {
		want += "  " + l + "\n"
	}
	if start < 0 || with[:start]+with[end:] != want {
		t.Errorf("text with the flag differs beyond the session-loss block and limitations:\n%s", with)
	}

	_, plainJSON, _ := runNetdoc(t, append(args, "--json")...)
	_, withJSON, _ := runNetdoc(t, append(args, "--json", "--fail-bgp-session", "r1:10.0.1.2")...)
	var a, b map[string]any
	if err := json.Unmarshal([]byte(plainJSON), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(withJSON), &b); err != nil {
		t.Fatal(err)
	}
	if _, ok := b["session_loss"]; !ok {
		t.Fatal("no session_loss object")
	}
	delete(b, "session_loss")
	lims := b["limitations"].([]any)
	b["limitations"] = lims[:len(lims)-len(frrBGPSessionLossLimitations)]
	if !reflect.DeepEqual(a, b) || strings.Contains(plainJSON, "stale_flag") {
		t.Errorf("JSON with the flag differs beyond session_loss and limitations")
	}
}

// TestWithdrawKeepsItsWording pins where the rest of the follow-up to the
// withdrawal starts: it writes no stale flag. The golden files hold the bytes.
func TestWithdrawKeepsItsWording(t *testing.T) {
	for _, c := range withdrawGoldenCases() {
		text, js := runWithdrawGolden(t, c)
		if strings.Contains(js, "stale_flag") || strings.Contains(text, "stale flag") || strings.Contains(text, "session loss (") {
			t.Errorf("%s: the withdrawal reports a stale flag or a session loss", c.name)
		}
	}
}

// TestSessionLossTextIsBounded checks the text caps: 20 rated prefixes, 20
// paths per list, and 20 unattributed prefixes, while JSON keeps every one.
func TestSessionLossTextIsBounded(t *testing.T) {
	routes := map[string][]string{}
	for i := 1; i <= 25; i++ {
		routes[fmt.Sprintf("10.%d.0.0/16", i)] = []string{bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}
		routes[fmt.Sprintf("11.%d.0.0/16", i)] = []string{bgpPath("", "65009", "IGP", "10.0.1.9")}
		routes["10.1.0.0/16"] = append(routes["10.1.0.0/16"], bgpPath(fmt.Sprintf("10.0.2.%d", i), "65009", "IGP", "10.0.1.9"))
	}
	manifest := stageSyntheticTable(t, routes, true)
	s, text := runSession(t, manifest, "r1:10.0.1.2")
	if len(s.Prefixes) != 25 || len(s.Prefixes[0].Remaining) != 25 || len(s.UnattributedPrefixes) != 25 {
		t.Fatalf("JSON holds %d prefixes, %d remaining paths, %d unattributed prefixes; want 25 of each", len(s.Prefixes), len(s.Prefixes[0].Remaining), len(s.UnattributedPrefixes))
	}
	for _, want := range []string{"\n  5 more prefixes; see --json\n", "\n    remains: 5 more; see --json\n", "\n  not rated: 5 more prefixes; see --json\n"} {
		if strings.Count(text, want) != 1 {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "\n  prefix ") != 20 {
		t.Errorf("text lists %d prefixes, want 20", strings.Count(text, "\n  prefix "))
	}
}

// TestSessionLossIsDeterministicAndReadOnly runs one case twice and checks that
// the reports match and that no staged capture changed.
func TestSessionLossIsDeterministicAndReadOnly(t *testing.T) {
	manifest := stageSyntheticTable(t, staleTable(), true)
	dir := filepath.Dir(manifest)
	sums := func() map[string][32]byte {
		out := map[string][32]byte{}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			raw, err := openRoot(t, dir).ReadFile(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			out[e.Name()] = sha256.Sum256(raw)
		}
		return out
	}
	before := sums()
	var outs []string
	for range 2 {
		for _, extra := range [][]string{nil, {"--json"}} {
			_, stdout, _ := runNetdoc(t, append([]string{"--import-frr-bgp", manifest, "--fail-bgp-session", "r1:10.0.1.9"}, extra...)...)
			outs = append(outs, stdout)
		}
	}
	if outs[0] != outs[2] || outs[1] != outs[3] || outs[0] == "" {
		t.Error("two runs gave different reports")
	}
	if !maps.Equal(before, sums()) {
		t.Error("a staged capture changed")
	}
}

// stageSessionPhase stages r1's summary and table of one session-lab phase.
func stageSessionPhase(t *testing.T, arm, phase string) string {
	t.Helper()
	return stageLabPhase(t, sessionLab+arm, phase)
}

// sessionLabListed reads r1's table of one phase as each prefix's paths, by
// kind, peer, and stale flag, in FRR's order.
func sessionLabListed(t *testing.T, arm, phase string) map[string][]string {
	t.Helper()
	table, err := frrbgp.DecodeRouteCapture(sessionLabRaw(t, arm, "r1-"+phase+"-show_ip_bgp_json.raw"), "r1")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, e := range table.Routes {
		for _, p := range e.Paths {
			kind, peer := pathNoPeer, ""
			if p.Source == frrbgp.RouteSourceLearned {
				kind, peer = pathLearned, p.Peer.String()
			}
			out[e.Prefix.String()] = append(out[e.Prefix.String()], kind+" "+peer+" "+staleFlagNames[p.Stale])
		}
	}
	return out
}

// TestSessionLossPredictionsMatchTheLiveLab reads each prediction from one phase
// of a session-loss run and checks it against r1's table in a later phase, which
// FRR printed after the session really ended. Where FRR had removed the peer's
// paths, each rated prefix lists exactly the predicted remaining paths, a
// prefix predicted to have no recorded path is gone, and no path names the
// peer. Where graceful restart kept them, the table lists every predicted
// removal, recorded stale, so the assumed removal had not happened yet.
func TestSessionLossPredictionsMatchTheLiveLab(t *testing.T) {
	want := []string{
		"10.10.1.0/24 paths_remain [no_peer  not_recorded]",
		"10.10.2.0/24 paths_remain [learned 10.0.3.3 not_recorded]",
		"10.10.9.0/24 no_recorded_path",
	}
	cases := []struct {
		arm, from, to, reading string
		retained               bool
	}{
		{"plain", "before", "after", sessionEstablished, false},   // L1
		{"gr", "before", "during", sessionEstablished, true},      // L2
		{"gr", "before", "expired", sessionEstablished, false},    // L3
		{"gr", "during", "expired", sessionNotEstablished, false}, // L4
		{"admin", "before", "after", sessionEstablished, false},   // L6
	}
	for _, c := range cases {
		t.Run(c.arm+" "+c.from+" to "+c.to, func(t *testing.T) {
			s, text := runSession(t, stageSessionPhase(t, c.arm, c.from), "r1:"+sessionLabPeer)
			if got := sessionShape(s); !slices.Equal(got, want) || s.PeerSessionReading != c.reading {
				t.Fatalf("prediction %q, reading %s; want %q, %s", got, s.PeerSessionReading, want, c.reading)
			}
			if len(s.UnattributedPrefixes) != 0 {
				t.Errorf("unattributed prefixes %q", s.UnattributedPrefixes)
			}
			if c.from == "during" {
				// L4: the session was already down, and FRR had kept r2's paths stale.
				for _, p := range s.Prefixes {
					if len(p.Removed) != 1 || p.Removed[0].StaleFlag != staleRecordedTrue || p.Removed[0].SessionState != "Active" {
						t.Errorf("%s: removed %+v, want r2's path recorded stale from an Active session", p.Prefix, p.Removed)
					}
				}
				if !strings.Contains(s.PeerSessionReason, "state Active") || !strings.Contains(text, "3 recorded true, 0 recorded false, 0 not recorded") {
					t.Errorf("reason %q, text:\n%s", s.PeerSessionReason, text)
				}
			}
			listed := sessionLabListed(t, c.arm, c.to)
			for _, p := range s.Prefixes {
				var predicted []string
				for _, r := range p.Remaining {
					predicted = append(predicted, r.Kind+" "+r.Peer+" "+staleNotRecorded)
				}
				var removed []string
				for _, r := range p.Removed {
					removed = append(removed, r.Kind+" "+r.Peer+" "+staleRecordedTrue)
				}
				got := listed[p.Prefix]
				if c.retained {
					for _, r := range removed {
						if !slices.Contains(got, r) {
							t.Errorf("%s %s lists %q, want the predicted removal %q still there, recorded stale", c.arm, c.to, got, r)
						}
					}
					continue
				}
				if !slices.Equal(got, predicted) {
					t.Errorf("FRR lists %q for %s in %s %s; predicted %q", got, p.Prefix, c.arm, c.to, predicted)
				}
			}
			if !c.retained {
				for prefix, paths := range listed {
					for _, path := range paths {
						if strings.Contains(path, " "+sessionLabPeer+" ") {
							t.Errorf("%s %s still lists %s from the lost peer", c.arm, c.to, prefix)
						}
					}
				}
			}
		})
	}
}
