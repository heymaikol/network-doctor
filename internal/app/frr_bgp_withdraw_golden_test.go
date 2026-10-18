package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// frrBGPWithdrawGoldenDir holds the pinned BGP import and --withdraw-bgp reports.
// The golden files were written at 0317503, before the route decoder read any
// stale flag, so a change to either report shows up here. The withdrawal files
// were rewritten for #374, which stopped counting a path recorded stale as
// remaining, gave every withdrawal path its stale_flag, and stopped calling a
// state other than Established a disagreement between the captures; the import
// files are as written.
const frrBGPWithdrawGoldenDir = "testdata/bgpwithdraw/golden"

// stalePath is bgpPath with a stale key written first, as raw JSON. The value
// is written verbatim, so a test can give it any JSON value.
func stalePath(value, peerID, asPath, origin, nextHop string) string {
	return strings.Replace(bgpPath(peerID, asPath, origin, nextHop), "{", `{"stale":`+value+",", 1)
}

// staleTable is a hand-written r1 table, not FRR output, that carries every
// stale form the decoder may meet beside each kind of path a withdrawal reads.
// The steady r1 summary shows 10.0.1.2 Established and 10.0.1.3 Active, and
// does not list 10.0.1.9.
func staleTable() map[string][]string {
	return map[string][]string{
		"10.20.0.0/16": {
			stalePath("true", "10.0.1.9", "65009", "IGP", "10.0.1.9"),
			stalePath("true", "10.0.1.2", "65002", "IGP", "10.0.1.2"),
			stalePath("false", "10.0.1.3", "65003", "IGP", "10.0.1.3"),
			bgpPath("", "65008", "IGP", "10.0.1.8"),
			stalePath("true", "(unspec)", "", "IGP", "0.0.0.0"),
		},
		"10.30.0.0/16": {stalePath("true", "10.0.1.9", "65009", "IGP", "10.0.1.9")},
		"10.40.0.0/16": {stalePath("true", "10.0.1.9", "65009", "IGP", "10.0.1.9"), stalePath("true", "10.0.1.2", "65002", "IGP", "10.0.1.2")},
		"10.50.0.0/16": {stalePath("true", "10.0.1.3", "65003", "IGP", "10.0.1.3"), bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")},
	}
}

// withdrawGoldenCase is one pinned report: the staged manifest and the flags
// after it.
type withdrawGoldenCase struct {
	name  string
	stage func(t *testing.T) string
	args  []string
}

func withdrawGoldenCases() []withdrawGoldenCase {
	lab := func(phase string) func(t *testing.T) string {
		return func(t *testing.T) string { return stageWithdrawPhase(t, phase) }
	}
	stale := func(summary bool) func(t *testing.T) string {
		return func(t *testing.T) string { return stageSyntheticTable(t, staleTable(), summary) }
	}
	return []withdrawGoldenCase{
		{"import-lab-before", lab("before"), nil},
		{"import-stale", stale(true), nil},
		{"withdraw-lab-before", lab("before"), []string{"--withdraw-bgp", "r1:10.0.1.2:10.10.2.0/24"}},
		{"withdraw-lab-after1", lab("after1"), []string{"--withdraw-bgp", "r1:10.0.1.2:10.10.9.0/24"}},
		// Every kind of remaining path, with the withdrawing peer's path stale.
		{"withdraw-stale-mixed", stale(true), []string{"--withdraw-bgp", "r1:10.0.1.9:10.20.0.0/16"}},
		// The only alternate is stale and from an Established peer.
		{"withdraw-stale-alternate", stale(true), []string{"--withdraw-bgp", "r1:10.0.1.9:10.40.0.0/16"}},
		// The withdrawing peer is Active and its path is stale.
		{"withdraw-stale-active-peer", stale(true), []string{"--withdraw-bgp", "r1:10.0.1.3:10.50.0.0/16"}},
		{"withdraw-stale-no-summary", stale(false), []string{"--withdraw-bgp", "r1:10.0.1.9:10.20.0.0/16"}},
	}
}

// runWithdrawGolden runs one case in text and JSON and returns both reports,
// with the staged manifest path replaced by manifest.json.
func runWithdrawGolden(t *testing.T, c withdrawGoldenCase) (text, js string) {
	t.Helper()
	manifest := c.stage(t)
	escaped, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	quoted := strings.Trim(string(escaped), `"`)
	norm := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, quoted, "manifest.json"), manifest, "manifest.json")
	}
	args := append([]string{"--import-frr-bgp", manifest}, c.args...)
	code, stdout, stderr := runNetdoc(t, args...)
	if code != 0 {
		t.Fatalf("text exit %d, want 0; stderr %q", code, stderr)
	}
	codeJ, stdoutJ, stderrJ := runNetdoc(t, append(args, "--json")...)
	if codeJ != 0 {
		t.Fatalf("json exit %d, want 0; stderr %q", codeJ, stderrJ)
	}
	return norm(stdout), norm(stdoutJ)
}

// TestWithdrawReportIsByteStable pins the BGP import and --withdraw-bgp
// reports, in text and JSON, for the lab captures and for tables that carry
// stale flags. The import does not read the flag, and a later change must not
// alter either report for any input accepted when the files were written.
func TestWithdrawReportIsByteStable(t *testing.T) {
	for _, c := range withdrawGoldenCases() {
		t.Run(c.name, func(t *testing.T) {
			text, js := runWithdrawGolden(t, c)
			dir := filepath.Join(frrBGPWithdrawGoldenDir, c.name)
			assertGolden(t, filepath.Join(dir, "text.txt"), text)
			assertGolden(t, filepath.Join(dir, "json.json"), js)
		})
	}
}

// TestBGPImportRefusesMalformedStaleKeys checks the one approved change to what
// the BGP import accepts since 0317503: a stale key FRR does not print, which the
// decoder skipped then, is now refused, with or without a simulation. Every
// other input keeps the reports pinned above.
func TestBGPImportRefusesMalformedStaleKeys(t *testing.T) {
	good := bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")
	for key, want := range map[string]string{
		`"stale":null`:   `route "10.20.0.0/16": stale is null`,
		`"stale":"true"`: `route "10.20.0.0/16": stale: json: cannot unmarshal string`,
		`"stale":1`:      `route "10.20.0.0/16": stale: json: cannot unmarshal number`,
		`"Stale":true`:   `key "Stale" differs from "stale" only in case`,
	} {
		odd := strings.Replace(bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), "{", "{"+key+",", 1)
		manifest := stageSyntheticTable(t, map[string][]string{"10.20.0.0/16": {odd, good}}, true)
		for _, extra := range [][]string{nil, {"--withdraw-bgp", "r1:10.0.1.9:10.20.0.0/16"}} {
			code, stdout, stderr := runNetdoc(t, append([]string{"--import-frr-bgp", manifest}, extra...)...)
			if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "netdoc: -import-frr-bgp: captures[2] r1-show_ip_bgp_json.raw: ") || !strings.Contains(stderr, want) {
				t.Errorf("%s %q: exit %d, stdout %q, stderr %q; want 2 and %q", key, extra, code, stdout, stderr, want)
			}
		}
	}
}
