package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/frrbgp"
)

const policyLab = "../../testdata/frr/10.7.0/bgp/policy"

func policyLabObject(t *testing.T, node, phase, command string, enabled bool) map[string]any {
	t.Helper()
	raw := readCommitted(t, policyLab, node+"-"+phase+"-"+strings.ReplaceAll(command, " ", "_")+".raw")
	prompt := node + "> "
	if enabled {
		prompt = node + "# "
	}
	if code := policyJSON(t, raw, command, prompt, nil); code != 0 {
		t.Fatalf("%s %s %s: checker exit %d", node, phase, command, code)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(raw, command+"\r\n"), "\r\n"+prompt)
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPolicyLiveEvidenceChecksums(t *testing.T) {
	sums := readCommitted(t, policyLab, "SHA256SUMS")
	lines := strings.Split(strings.TrimSpace(sums), "\n")
	if len(lines) != 68 {
		t.Fatalf("got %d checksums, want 68", len(lines))
	}
	seen := map[string]bool{}
	for _, line := range lines {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || seen[name] {
			t.Fatalf("bad checksum row %q", line)
		}
		seen[name] = true
		got := sha256.Sum256([]byte(readCommitted(t, policyLab, name)))
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s checksum mismatch", name)
		}
	}
	if got := readCommitted(t, policyLab, "terminal.log"); !strings.HasSuffix(got, "DONE\n") {
		t.Fatal("lab did not finish")
	}
	for _, node := range []string{"r1", "r2", "r3"} {
		for _, phase := range []string{"before", "after"} {
			stamp := readCommitted(t, policyLab, node+"-"+phase+"-show_ip_bgp_json.collected_at")
			if !utcStamp.MatchString(stamp) {
				t.Errorf("bad stamp %q", stamp)
			}
		}
	}
}

// This grades the producer independently of its shell checks, without predicting a FIB from BGP.
func TestPolicyLiveObservedChanges(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		terms := policyBeforeTable
		if phase == "after" {
			terms = policyAfterTable
		}
		if code := policyJSON(t, readCommitted(t, policyLab, "r1-"+phase+"-show_ip_bgp_json.raw"), "show ip bgp json", "r1> ", terms); code != 0 {
			t.Fatalf("%s table fails: %d", phase, code)
		}
	}
	for _, node := range []string{"r1", "r2", "r3"} {
		before, err := frrbgp.DecodeRouteCapture([]byte(readCommitted(t, policyLab, node+"-before-show_ip_bgp_json.raw")), node)
		if err != nil {
			t.Fatal(err)
		}
		after, err := frrbgp.DecodeRouteCapture([]byte(readCommitted(t, policyLab, node+"-after-show_ip_bgp_json.raw")), node)
		if err != nil {
			t.Fatal(err)
		}
		// Propagation changes an unselected candidate on each downstream router.
		// Their selected paths and independently captured kernel routes stay put.
		if node != "r1" {
			table, peer, path := &after, "10.0.1.1", "65001 65003"
			if node == "r3" {
				table, peer, path = &before, "10.0.3.1", "65001 65002"
			}
			removed := 0
			for i := range table.Routes {
				r := &table.Routes[i]
				if r.Prefix.String() != "10.10.2.0/24" {
					continue
				}
				for j, p := range r.Paths {
					if p.Peer.String() == peer && p.ASPath == path {
						r.Paths = append(r.Paths[:j:j], r.Paths[j+1:]...)
						removed++
						break
					}
				}
			}
			if removed != 1 {
				t.Fatalf("%s did not record the expected propagated candidate", node)
			}
			for _, phase := range []string{"before", "after"} {
				raw := readCommitted(t, policyLab, node+"-"+phase+"-show_ip_bgp_json.raw")
				if code := policyJSON(t, raw, "show ip bgp json", node+"> ", []string{"best:10.10.2.0/24=(unspec)"}); code != 0 {
					t.Fatalf("%s %s selected path changed", node, phase)
				}
			}
		}
		if !reflect.DeepEqual(stablePaths(before, ""), stablePaths(after, "")) {
			t.Errorf("%s changed candidate paths", node)
		}
		var b, a []map[string]any
		if err := json.Unmarshal([]byte(readCommitted(t, policyLab, node+"-before-ip-route.json")), &b); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(readCommitted(t, policyLab, node+"-after-ip-route.json")), &a); err != nil {
			t.Fatal(err)
		}
		if node == "r1" {
			changed := 0
			for _, r := range b {
				if r["dst"] == "10.10.2.0/24" {
					if r["gateway"] != "10.0.1.2" {
						t.Fatal("unexpected before gateway")
					}
					r["gateway"] = "10.0.3.3"
					r["dev"] = "e3"
					changed++
				}
			}
			if changed != 1 {
				t.Fatal("target route missing or ambiguous")
			}
			// Kernel nexthop IDs are handles, not forwarding semantics.
			for _, rows := range [][]map[string]any{b, a} {
				for _, r := range rows {
					delete(r, "nhid")
				}
			}
		}
		if !reflect.DeepEqual(b, a) {
			t.Errorf("%s kernel route changes differ from the independent expectation", node)
		}
	}
	for _, cmd := range []string{"show route-map json", "show ip prefix-list json"} {
		if got := policyLabObject(t, "r1", "before", cmd, true); len(got) != 0 {
			t.Errorf("before %s is not empty", cmd)
		}
	}
	maps := policyLabObject(t, "r1", "after", "show route-map json", true)
	lists := policyLabObject(t, "r1", "after", "show ip prefix-list json", true)
	if maps["R3-IN"] == nil || lists["P10-2"] == nil {
		t.Fatal("policy JSON source missing")
	}
	for _, phase := range []string{"before", "after"} {
		peer := policyLabObject(t, "r1", phase, "show ip bgp neighbors 10.0.3.3 json", false)["10.0.3.3"].(map[string]any)
		af := peer["addressFamilyInfo"].(map[string]any)["ipv4Unicast"].(map[string]any)
		want := any(nil)
		if phase == "after" {
			want = "R3-IN"
		}
		if !reflect.DeepEqual(af["routeMapForIncomingAdvertisements"], want) {
			t.Errorf("%s binding = %v", phase, af)
		}
	}
	if bytes.Contains([]byte(readCommitted(t, policyLab, "r1-policy-change.raw")), []byte("% ")) {
		t.Fatal("FRR rejected a policy command")
	}
}
