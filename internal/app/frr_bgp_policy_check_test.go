package app

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// policyCheck is the checker that lab/bgp-policy.sh runs over each capture. These tests run the
// same file, over committed FRR output and over edited copies, so the lab and the tests cannot
// disagree about what a term means.
const policyCheck = "../../testdata/frr/10.7.0/lab/bgp-policy-check.py"

// policyBeforeTable is r1's route table before the policy. It is the withdrawal run's before
// phase, which has the same topology and no policy, so bestpath for 10.10.2.0/24 is r2's path.
var policyBeforeTable = []string{
	"paths:10.10.1.0/24=(unspec),10.0.1.2",
	"paths:10.10.2.0/24=10.0.1.2,10.0.3.3",
	"paths:10.10.3.0/24=10.0.3.3",
	"paths:10.10.9.0/24=10.0.1.2",
	"best:10.10.1.0/24=(unspec)",
	"best:10.10.2.0/24=10.0.1.2",
	"best:10.10.3.0/24=10.0.3.3",
	"best:10.10.9.0/24=10.0.1.2",
}

// policyAfterTable is the lab's expectation for r1's route table after the policy. No capture of
// it is committed. Only 10.10.2.0/24 moves: r3's path for it gains weight 100 and becomes
// bestpath, and r2's path stays listed. The weight-0 terms show that the other paths are untouched,
// since weight 0 is the value the before capture prints for them.
var policyAfterTable = []string{
	"paths:10.10.1.0/24=(unspec),10.0.1.2",
	"paths:10.10.2.0/24=10.0.1.2,10.0.3.3",
	"paths:10.10.3.0/24=10.0.3.3",
	"paths:10.10.9.0/24=10.0.1.2",
	"best:10.10.1.0/24=(unspec)",
	"best:10.10.2.0/24=10.0.3.3",
	"best:10.10.3.0/24=10.0.3.3",
	"best:10.10.9.0/24=10.0.1.2",
	"weight:10.10.2.0/24=10.0.3.3=100",
	"weight:10.10.2.0/24=10.0.1.2=0",
	"weight:10.10.3.0/24=10.0.3.3=0",
}

// runPolicyCheck runs the checker on args and returns its exit status: 0 when the file and every
// term pass, 1 when one does not, and 2 for a usage error.
func runPolicyCheck(t *testing.T, args []string) int {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not on PATH, so the policy checker cannot run")
	}
	cmd := exec.Command("python3", slices.Concat([]string{"-I", policyCheck}, args)...) //nolint:gosec // G204: python3 is the host interpreter the lab uses, and the arguments are test data.
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return exit.ExitCode()
}

// policyJSON checks file as a JSON capture of cmd from r1, which ends at prompt, against terms.
func policyJSON(t *testing.T, file, cmd, prompt string, terms []string) int {
	t.Helper()
	return runPolicyCheck(t, slices.Concat([]string{file, "json", cmd, prompt}, terms))
}

// policyText checks file as a text transcript that ends at prompt, against terms.
func policyText(t *testing.T, file, prompt string, terms []string) int {
	t.Helper()
	return runPolicyCheck(t, slices.Concat([]string{file, "text", prompt}, terms))
}

// writePolicyFixture writes body to a new file and returns its path. Each caller says that its
// body is hand-written, not FRR output.
func writePolicyFixture(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPolicyCheckAcceptsCommittedFRROutput runs the checker over FRR output that is already
// committed: the withdrawal run's before table, a neighbor capture, and the admin arm's shutdown
// transcript. Each one passes the terms that describe it.
func TestPolicyCheckAcceptsCommittedFRROutput(t *testing.T) {
	const (
		table    = withdrawLab + "/r1-before-show_ip_bgp_json.raw"
		neighbor = "../../testdata/frr/10.7.0/bgp/session/plain/r1-before-show_ip_bgp_neighbors_10.0.1.2_json.raw"
		shutdown = "../../testdata/frr/10.7.0/bgp/session/admin/r1-shutdown.raw"
	)
	if code := policyJSON(t, table, "show ip bgp json", "r1> ", policyBeforeTable); code != 0 {
		t.Errorf("the before table fails its terms: exit %d, want 0", code)
	}
	if code := policyJSON(t, neighbor, "show ip bgp neighbors 10.0.1.2 json", "r1> ", []string{"key:10.0.1.2"}); code != 0 {
		t.Errorf("the neighbor capture fails key:10.0.1.2: exit %d, want 0", code)
	}
	if code := policyText(t, shutdown, "r1# ", []string{"has:neighbor 10.0.1.2 shutdown"}); code != 0 {
		t.Errorf("the shutdown transcript fails has: exit %d, want 0", code)
	}
}

// TestPolicyCheckRefusesTermsTheTableDoesNotShow checks that each term the committed table does
// not meet fails it. The after-change terms are included, since the before table cannot meet them.
func TestPolicyCheckRefusesTermsTheTableDoesNotShow(t *testing.T) {
	table := withdrawLab + "/r1-before-show_ip_bgp_json.raw"
	for _, c := range []struct {
		name  string
		terms []string
	}{
		{"after-change terms on the before table", policyAfterTable},
		{"a path missing", []string{"paths:10.10.2.0/24=10.0.1.2"}},
		{"a bestpath list that names another path", []string{"best:10.10.2.0/24=10.0.1.2,10.0.3.3"}},
		{"a weight that is not printed", []string{"weight:10.10.2.0/24=10.0.1.2=100"}},
		{"an absent prefix that is listed", []string{"absent:10.10.9.0/24"}},
		{"an unknown op", []string{"nope:10.10.9.0/24"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code := policyJSON(t, table, "show ip bgp json", "r1> ", c.terms); code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
		})
	}
}

// TestPolicyCheckRefusesMalformedJSONCaptures checks the framing and the strict-JSON rules on
// the committed table. Each edit is one rule: a duplicate key, NaN, a wrong prompt, and a wrong
// echoed command. The unedited framing passes with no terms.
func TestPolicyCheckRefusesMalformedJSONCaptures(t *testing.T) {
	raw, err := openRoot(t, withdrawLab).ReadFile("r1-before-show_ip_bgp_json.raw")
	if err != nil {
		t.Fatal(err)
	}
	dup := bytes.Replace(raw, []byte(`"totalRoutes": 4`), []byte(`"totalRoutes": 4, "totalRoutes": 4`), 1)
	if bytes.Equal(dup, raw) {
		t.Fatal("the duplicate key was not inserted")
	}
	table := withdrawLab + "/r1-before-show_ip_bgp_json.raw"
	duplicate := writePolicyFixture(t, "duplicate.raw", string(dup))
	nan := writePolicyFixture(t, "nan.raw", "show ip bgp json\r\n{\"routes\": {}, \"x\": NaN}\r\nr1> ")
	plain := writePolicyFixture(t, "plain.raw", "show ip bgp json\r\n{\"routes\": {}}\r\nr1> ")
	for _, c := range []struct {
		name   string
		file   string
		cmd    string
		prompt string
		want   int
	}{
		{"the framing alone", plain, "show ip bgp json", "r1> ", 0},
		{"a duplicate key", duplicate, "show ip bgp json", "r1> ", 1},
		{"NaN", nan, "show ip bgp json", "r1> ", 1},
		{"the wrong prompt", table, "show ip bgp json", "r1# ", 1},
		{"the wrong echoed command", table, "show ip bgp summary json", "r1> ", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code := policyJSON(t, c.file, c.cmd, c.prompt, nil); code != c.want {
				t.Errorf("exit %d, want %d", code, c.want)
			}
		})
	}
}

// TestPolicyCheckReadsTranscriptsAsText checks the text rules on hand-written transcripts, which
// are not FRR output. Each one tests a single rule: a rejected line, a missing trailing prompt,
// whether the binding is inside the IPv4 unicast address family, and whether an empty
// configuration can pass the anchors that a before phase requires.
func TestPolicyCheckReadsTranscriptsAsText(t *testing.T) {
	const shutdown = "../../testdata/frr/10.7.0/bgp/session/admin/r1-shutdown.raw"
	rejected := writePolicyFixture(t, "rejected.raw", "enable\r\nr1# configure terminal\r\nr1(config)# route-map R3-IN permit 10\r\n% Unknown command.\r\nr1(config)# end\r\nr1# ")
	noPrompt := writePolicyFixture(t, "noprompt.raw", "enable\r\nr1# end\r\n")
	inside := writePolicyFixture(t, "inside.raw", "router bgp 65001\r\n address-family ipv4 unicast\r\n  neighbor 10.0.3.3 route-map R3-IN in\r\n exit-address-family\r\nend\r\nr1# ")
	outside := writePolicyFixture(t, "outside.raw", "router bgp 65001\r\n neighbor 10.0.3.3 route-map R3-IN in\r\n address-family ipv4 unicast\r\n exit-address-family\r\nend\r\nr1# ")
	// An empty configuration passes every "lacks" term, so the before phase also anchors on r1's own
	// lines. Those anchors must fail here.
	empty := writePolicyFixture(t, "empty.raw", "enable\r\nr1# show running-config\r\nr1# ")
	binding := []string{"inaf:neighbor 10.0.3.3 route-map R3-IN in"}
	anchors := []string{"has:router bgp 65001", "inaf:network 10.10.1.0/24"}
	for _, c := range []struct {
		name  string
		file  string
		terms []string
		want  int
	}{
		{"a rejected line", rejected, nil, 1},
		{"no trailing prompt", noPrompt, nil, 1},
		{"binding inside the IPv4 unicast family", inside, binding, 0},
		{"binding outside the IPv4 unicast family", outside, binding, 1},
		{"empty configuration passes lacks alone", empty, []string{"lacks:route-map R3-IN"}, 0},
		{"empty configuration fails the anchors", empty, anchors, 1},
		{"binding absent from the committed shutdown transcript", shutdown, []string{"has:neighbor 10.0.3.3 route-map R3-IN in"}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code := policyText(t, c.file, "r1# ", c.terms); code != c.want {
				t.Errorf("exit %d, want %d", code, c.want)
			}
		})
	}
}
