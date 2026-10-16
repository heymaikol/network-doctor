package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// frrBGPWithdrawGoldenDir holds the pinned BGP import and --withdraw-bgp reports.
// The golden files were written at 0317503, before the route decoder read any
// stale flag, so a change to either report shows up here.
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
// stale flags. Neither report reads the flag, and a later change must not
// alter either for any input accepted when the files were written.
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

// TestWithdrawSkipsMalformedStaleKeys pins what 0317503 does with a stale key
// FRR does not print: the decoder skips it, so the report is the one for the
// same table without it.
func TestWithdrawSkipsMalformedStaleKeys(t *testing.T) {
	plain := map[string][]string{"10.20.0.0/16": {bgpPath("10.0.1.9", "65009", "IGP", "10.0.1.9"), bgpPath("10.0.1.2", "65002", "IGP", "10.0.1.2")}}
	run := func(routes map[string][]string) (int, string, string) {
		manifest := stageSyntheticTable(t, routes, true)
		code, stdout, stderr := runNetdoc(t, "--import-frr-bgp", manifest, "--withdraw-bgp", "r1:10.0.1.9:10.20.0.0/16", "--json")
		return code, strings.ReplaceAll(stdout, manifest, "manifest.json"), stderr
	}
	_, want, _ := run(plain)
	for _, key := range []string{`"stale":null`, `"stale":"true"`, `"stale":1`, `"Stale":true`} {
		odd := map[string][]string{"10.20.0.0/16": {strings.Replace(plain["10.20.0.0/16"][0], "{", "{"+key+",", 1), plain["10.20.0.0/16"][1]}}
		code, got, stderr := run(odd)
		if code != 0 || got != want {
			t.Errorf("%s: exit %d, stderr %q; want the report for the table without it", key, code, stderr)
		}
	}
}
