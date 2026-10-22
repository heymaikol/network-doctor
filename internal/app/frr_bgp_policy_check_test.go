package app

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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

// policyBeforeConfig and policyAfterConfig are the CFG terms that lab/bgp-policy.sh checks r1's
// running configuration against, before and after the change. They are copied from the script.
var policyBeforeConfig = []string{
	"has:router bgp 65001",
	"inaf:network 10.10.1.0/24",
	"lacks:route-map R3-IN",
	"lacks:neighbor 10.0.3.3 route-map R3-IN in",
}

var policyAfterConfig = []string{
	"has:router bgp 65001",
	"inaf:network 10.10.1.0/24",
	"has:ip prefix-list P10-2 seq 5 permit 10.10.2.0/24",
	"has:route-map R3-IN permit 10",
	"has:match ip address prefix-list P10-2",
	"has:set weight 100",
	"has:route-map R3-IN permit 20",
	"inaf:neighbor 10.0.3.3 route-map R3-IN in",
}

// policyBinding is the line that binds R3-IN inbound under the IPv4 unicast family of r1.
const policyBinding = "  neighbor 10.0.3.3 route-map R3-IN in\r\n"

// policyAfterConfigBody is a hand-written running configuration with the change applied, laid out
// the way FRR prints a running configuration. It is not FRR output, and that layout is not verified
// against FRR 10.7.0. It is the positive control for the negative cases below.
const policyAfterConfigBody = "r1# show running-config\r\n" +
	"hostname r1\r\n" +
	"router bgp 65001\r\n" +
	" bgp router-id 1.1.1.1\r\n" +
	" neighbor 10.0.1.2 remote-as 65002\r\n" +
	" neighbor 10.0.3.3 remote-as 65003\r\n" +
	" address-family ipv4 unicast\r\n" +
	"  network 10.10.1.0/24\r\n" +
	"  neighbor 10.0.1.2 activate\r\n" +
	"  neighbor 10.0.3.3 activate\r\n" +
	policyBinding +
	" exit-address-family\r\n" +
	"!\r\n" +
	"ip prefix-list P10-2 seq 5 permit 10.10.2.0/24\r\n" +
	"!\r\n" +
	"route-map R3-IN permit 10\r\n" +
	" match ip address prefix-list P10-2\r\n" +
	" set weight 100\r\n" +
	"!\r\n" +
	"route-map R3-IN permit 20\r\n" +
	"!\r\n" +
	"end\r\n" +
	"r1# "

// policyEchoBody is a hand-written transcript of the policy change on r1. Each command is echoed
// after its prompt, and nothing else is printed, so it holds the requested commands and no
// configuration output. The first line is bare, as in the committed shutdown transcript.
const policyEchoBody = "enable\r\n" +
	"r1# configure terminal\r\n" +
	"r1(config)# ip prefix-list P10-2 seq 5 permit 10.10.2.0/24\r\n" +
	"r1(config)# route-map R3-IN permit 10\r\n" +
	"r1(config-route-map)# match ip address prefix-list P10-2\r\n" +
	"r1(config-route-map)# set weight 100\r\n" +
	"r1(config-route-map)# exit\r\n" +
	"r1(config)# route-map R3-IN permit 20\r\n" +
	"r1(config-route-map)# exit\r\n" +
	"r1(config)# router bgp 65001\r\n" +
	"r1(config-router)# address-family ipv4 unicast\r\n" +
	"r1(config-router-af)# neighbor 10.0.3.3 route-map R3-IN in\r\n" +
	"r1(config-router-af)# exit-address-family\r\n" +
	"r1(config-router)# exit\r\n" +
	"r1(config)# end\r\n" +
	"r1# clear ip bgp 10.0.3.3 soft in\r\n" +
	"r1# "

// policyEdit returns body with its one occurrence of old replaced by repl. It fails the test when
// old does not occur exactly once, so an edit that did not apply cannot pass as a clean case.
func policyEdit(t *testing.T, body, old, repl string) string {
	t.Helper()
	if n := strings.Count(body, old); n != 1 {
		t.Fatalf("%q occurs %d times in the body, want 1", old, n)
	}
	return strings.Replace(body, old, repl, 1)
}

// TestPolicyCheckAcceptsPolicyConfigBody is the positive control. The hand-written body with the
// change applied passes every after-change CFG term, and the before-change terms refuse it. Without
// this case, the negative cases could pass only because their terms can never match.
func TestPolicyCheckAcceptsPolicyConfigBody(t *testing.T) {
	file := writePolicyFixture(t, "after-config.raw", policyAfterConfigBody)
	if code := policyText(t, file, "r1# ", policyAfterConfig); code != 0 {
		t.Errorf("the after-change body fails the after-change terms: exit %d, want 0", code)
	}
	if code := policyText(t, file, "r1# ", policyBeforeConfig); code != 1 {
		t.Errorf("the after-change body passes the before-change terms: exit %d, want 1", code)
	}
}

// TestPolicyCheckRefusesMutatedPolicyConfig edits one part of the positive control. Each edit must
// fail the after-change terms. The old checker already refused every case, so these pin behavior
// that was already right.
func TestPolicyCheckRefusesMutatedPolicyConfig(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
	}{
		{"a missing binding", policyEdit(t, policyAfterConfigBody, policyBinding, "")},
		{"a binding for another peer", policyEdit(t, policyAfterConfigBody, policyBinding, "  neighbor 10.0.1.2 route-map R3-IN in\r\n")},
		{"a binding in the other direction", policyEdit(t, policyAfterConfigBody, "route-map R3-IN in\r\n", "route-map R3-IN out\r\n")},
		{"no route-map definition", policyEdit(t, policyAfterConfigBody, "route-map R3-IN permit 10\r\n match ip address prefix-list P10-2\r\n set weight 100\r\n", "")},
		{"no weight set", policyEdit(t, policyAfterConfigBody, " set weight 100\r\n", " set weight 0\r\n")},
		{"a prefix list for another prefix", policyEdit(t, policyAfterConfigBody, "permit 10.10.2.0/24", "permit 10.10.9.0/24")},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := writePolicyFixture(t, "mutant.raw", c.body)
			if code := policyText(t, file, "r1# ", policyAfterConfig); code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
		})
	}
}

// TestPolicyCheckRefusesWrongFamily checks a binding under the wrong family or peer. The bodies are
// hand-written, not FRR output. The first two rows were already refused by the old checker. The nested row is a malformed transcript: an ipv6
// family opened inside the ipv4 family with no exit. The old checker read that binding as still
// inside ipv4, so it passed.
func TestPolicyCheckRefusesWrongFamily(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
	}{
		{"a binding in ipv6 only", "router bgp 65001\r\n address-family ipv6 unicast\r\n  neighbor 10.0.3.3 route-map R3-IN in\r\n exit-address-family\r\nend\r\nr1# "},
		{"a binding for another peer in ipv4", "router bgp 65001\r\n address-family ipv4 unicast\r\n  neighbor 10.0.1.2 route-map R3-IN in\r\n exit-address-family\r\nend\r\nr1# "},
		{"an ipv6 family nested in ipv4 with no exit", "router bgp 65001\r\n address-family ipv4 unicast\r\n address-family ipv6 unicast\r\n  neighbor 10.0.3.3 route-map R3-IN in\r\n exit-address-family\r\nend\r\nr1# "},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := writePolicyFixture(t, "family.raw", c.body)
			if code := policyText(t, file, "r1# ", []string{"inaf:neighbor 10.0.3.3 route-map R3-IN in"}); code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
		})
	}
}

// TestPolicyCheckRefusesPrefixOfLongerToken checks that has: matches whole tokens. The old checker
// read a longer number or name as the shorter one: permit 10 in permit 100, weight 100 in weight
// 1000, and R3-IN in R3-IN-old. The bodies are hand-written, not FRR output. The last two rows are
// positive cases that check only that "," and ":" end a token. The real layout of show route-map
// and show ip prefix-list output is not verified against FRR 10.7.0.
func TestPolicyCheckRefusesPrefixOfLongerToken(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		term string
		want int
	}{
		{"permit 10 inside permit 100", policyEdit(t, policyAfterConfigBody, "route-map R3-IN permit 10\r\n", "route-map R3-IN permit 100\r\n"), "has:route-map R3-IN permit 10", 1},
		{"weight 100 inside weight 1000", policyEdit(t, policyAfterConfigBody, " set weight 100\r\n", " set weight 1000\r\n"), "has:set weight 100", 1},
		{"R3-IN inside R3-IN-old", "route-map R3-IN-old permit 10\r\nr1# ", "has:route-map R3-IN", 1},
		{"R3-IN before a comma", "route-map R3-IN, permit, sequence 10\r\nr1# ", "has:R3-IN", 0},
		{"P10-2 before a colon", "ip prefix-list P10-2: 1 entries\r\nr1# ", "has:P10-2", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := writePolicyFixture(t, "token.raw", c.body)
			if code := policyText(t, file, "r1# ", []string{c.term}); code != c.want {
				t.Errorf("exit %d, want %d", code, c.want)
			}
		})
	}
}

// TestPolicyCheckRefusesEmptyTerms checks that a term with an empty arg fails. The old checker let an
// empty has: match every file, an empty inaf: match any blank line inside a family, and an empty
// absent: pass on the committed table. The text bodies are hand-written, not FRR output.
func TestPolicyCheckRefusesEmptyTerms(t *testing.T) {
	framed := writePolicyFixture(t, "framed.raw", "enable\r\nr1# ")
	blank := writePolicyFixture(t, "blank.raw", "address-family ipv4 unicast\r\n\r\n exit-address-family\r\nend\r\nr1# ")
	table := withdrawLab + "/r1-before-show_ip_bgp_json.raw"
	if code := policyText(t, framed, "r1# ", []string{"has:"}); code != 1 {
		t.Errorf("has: with no arg: exit %d, want 1", code)
	}
	if code := policyText(t, blank, "r1# ", []string{"inaf:"}); code != 1 {
		t.Errorf("inaf: with no arg: exit %d, want 1", code)
	}
	if code := policyJSON(t, table, "show ip bgp json", "r1> ", []string{"absent:"}); code != 1 {
		t.Errorf("absent: with no arg: exit %d, want 1", code)
	}
}

// TestPolicyCheckRequiresTextTerm checks that a text transcript with no TERM exits 2, a usage error,
// because its framing alone is not a check. A transcript that breaks the framing still exits 1 first.
// The bodies are hand-written.
func TestPolicyCheckRequiresTextTerm(t *testing.T) {
	framed := writePolicyFixture(t, "framed.raw", "enable\r\nr1# ")
	rejected := writePolicyFixture(t, "rejected.raw", "enable\r\nr1# \r\n% Unknown command.\r\nr1# ")
	if code := policyText(t, framed, "r1# ", nil); code != 2 {
		t.Errorf("framed text with no TERM: exit %d, want 2", code)
	}
	if code := policyText(t, rejected, "r1# ", nil); code != 1 {
		t.Errorf("rejected text with no TERM: exit %d, want 1", code)
	}
}

// TestPolicyCheckRefusesIncompleteTranscripts checks transcripts that end early or hold an error line.
// Each one fails the framing or the "% " rule, even where its terms would otherwise match. The error
// row is hand-written, not FRR output.
func TestPolicyCheckRefusesIncompleteTranscripts(t *testing.T) {
	cut := strings.Index(policyAfterConfigBody, "route-map R3-IN permit 20")
	for _, c := range []struct {
		name string
		body string
	}{
		{"an empty file", ""},
		{"a file cut before its prompt", strings.TrimSuffix(policyAfterConfigBody, "r1# ")},
		{"a file cut inside a line", policyAfterConfigBody[:cut+len("route-map R3-IN")]},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := writePolicyFixture(t, "incomplete.raw", c.body)
			if code := policyText(t, file, "r1# ", policyAfterConfig); code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
		})
	}
	t.Run("an error line inside a matching family", func(t *testing.T) {
		body := "router bgp 65001\r\n address-family ipv4 unicast\r\n  neighbor 10.0.3.3 route-map R3-IN in\r\n% Unknown command.\r\n exit-address-family\r\nend\r\nr1# "
		file := writePolicyFixture(t, "rejected-family.raw", body)
		if code := policyText(t, file, "r1# ", []string{"inaf:neighbor 10.0.3.3 route-map R3-IN in"}); code != 1 {
			t.Errorf("exit %d, want 1", code)
		}
	})
}

// TestPolicyCheckRefusesEchoOnlyTranscripts checks transcripts that echo the requested commands and
// print no configuration. The configuration terms must not pass on the echo. policy() checks only
// that the change was sent and not rejected, so its acceptance terms do pass on the echo. That is not
// configuration proof, and the configuration comes from the after-change running configuration.
// The old checker already refused every row but the last, so those rows pin behavior that was right.
// The last row pins only that the echo passes the acceptance terms. The bodies are hand-written, not
// FRR output.
func TestPolicyCheckRefusesEchoOnlyTranscripts(t *testing.T) {
	captxt := "terminal length 0\r\nr1> enable\r\nr1# show running-config\r\nr1# "
	route := "terminal length 0\r\nr1> enable\r\nr1# show route-map\r\nr1# "
	prefix := "terminal length 0\r\nr1> enable\r\nr1# show ip prefix-list\r\nr1# "
	for _, c := range []struct {
		name  string
		body  string
		terms []string
		want  int
	}{
		{"running configuration before the change", captxt, policyBeforeConfig, 1},
		{"running configuration after the change", captxt, policyAfterConfig, 1},
		{"route map", route, []string{"has:R3-IN"}, 1},
		{"prefix list", prefix, []string{"has:P10-2"}, 1},
		// The echoed family line keeps its prompt, so inaf: never opens the family for the echoed binding.
		{"policy change, binding inside the family", policyEchoBody, []string{"inaf:neighbor 10.0.3.3 route-map R3-IN in"}, 1},
		{"policy change, acceptance terms", policyEchoBody, []string{"has:set weight 100", "has:clear ip bgp 10.0.3.3 soft in"}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			file := writePolicyFixture(t, "echo.raw", c.body)
			if code := policyText(t, file, "r1# ", c.terms); code != c.want {
				t.Errorf("exit %d, want %d", code, c.want)
			}
		})
	}
}
