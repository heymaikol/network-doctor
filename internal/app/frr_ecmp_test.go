package app

import (
	"encoding/json"
	"testing"
)

// frrECMPDir holds the ECMP bracket of the lsdb lab's ecmp mode: three links
// between r1 and r2, with r1 e5 at cost 50.
const frrECMPDir = "../../testdata/frr/10.7.0/ecmp"

// Gate B1. The committed ECMP bracket passes the existing guard through the
// existing import, and a healthy bracket raises no finding and no
// lsdb_incomplete. The guard is not changed for this gate.
func TestFRRImportECMPBracketPassesTheGuard(t *testing.T) {
	dir, manifest := stageFRRBcast(t)
	addFRRLSDBFrom(t, dir, manifest, frrECMPDir, "ecmp", "r1")
	addFRRLSDBFrom(t, dir, manifest, frrECMPDir, "ecmp", "r2")
	code, stdout, stderr := runNetdoc(t, "--import-frr-ospf", manifest, "--json")
	if code != 0 {
		t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var report struct {
		OSPFLSDB struct {
			Nodes []struct {
				Node  string `json:"node"`
				Guard struct {
					Passed  bool     `json:"passed"`
					Reasons []string `json:"reasons"`
				} `json:"guard"`
				Findings []struct {
					Kind string `json:"kind"`
				} `json:"findings"`
			} `json:"nodes"`
		} `json:"ospf_lsdb"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.OSPFLSDB.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(report.OSPFLSDB.Nodes))
	}
	for _, n := range report.OSPFLSDB.Nodes {
		if !n.Guard.Passed {
			t.Errorf("%s guard refused: %v", n.Node, n.Guard.Reasons)
		}
		for _, f := range n.Findings {
			t.Errorf("%s raised %s on a healthy bracket", n.Node, f.Kind)
		}
	}
}
