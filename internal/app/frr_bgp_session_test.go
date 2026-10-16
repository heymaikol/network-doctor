package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
