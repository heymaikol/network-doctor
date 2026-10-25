package app

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// tunnelLinks is the ip -d -j link capture of r1 in omittedInterfaceTopology: two
// plain devices, so the import has nothing to refuse.
const tunnelLinks = `[{"ifname":"lo","link_type":"loopback"},{"ifname":"eth1","link_type":"ether"}]`

// tunnelEntry is one capture object of a manifest.
func tunnelEntry(file, source, node, command string) string {
	return fmt.Sprintf(`{"file": %q, "source": %q, "node": %q, "command": %q, "collected_at": "2026-10-09T12:00:00Z"}`, file, source, node, command)
}

// tunnelManifest is a manifest that names topology as its base and the given
// capture objects.
func tunnelManifestText(topology string, captures ...string) string {
	return `{"version": 1, "topology": "` + topology + `", "captures": [` + strings.Join(captures, ",") + `]}`
}

// writeTunnelFiles writes each named file into a fresh directory and returns the
// directory and the path of manifest.json, which the caller must include.
func writeTunnelFiles(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "manifest.json")
}

// runTunnel runs netdoc with -import-tunnels on manifest and the extra arguments.
func runTunnel(t *testing.T, manifest string, extra ...string) (int, string, string) {
	t.Helper()
	return runNetdoc(t, append([]string{"--import-tunnels", manifest}, extra...)...)
}

// TestTunnelImportWritesACompleteBaseUnchanged imports a capture with nothing to
// refuse. The written file must be the base topology encoded as Encode writes
// any topology, with no tunnels key, and the report must name the node that has
// no capture.
func TestTunnelImportWritesACompleteBaseUnchanged(t *testing.T) {
	dir, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     omittedInterfaceTopology,
		"links.json":    tunnelLinks,
		"links-r2.json": tunnelLinks,
		"manifest.json": tunnelManifestText("base.json",
			tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"),
			tunnelEntry("links-r2.json", "ip-link-r2", "r2", "ip -d -j link")),
	})
	out := filepath.Join(dir, "out.json")
	code, stdout, stderr := runTunnel(t, manifest, "--write-topology", out)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stdout %q stderr %q", code, stdout, stderr)
	}
	base, err := routepath.Decode([]byte(omittedInterfaceTopology))
	if err != nil {
		t.Fatal(err)
	}
	want, err := routepath.Encode(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("written topology differs from the base encoded as Encode writes it:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(string(got), `"tunnels"`) {
		t.Error("written topology has a tunnels key, though no tunnel was recorded")
	}

	code, outcome := reportOutcome(t, manifest)
	if code != 0 || !outcome.Complete || len(outcome.NoCapture) != 0 {
		t.Errorf("exit %d, report %+v; want exit 0, complete, every modeled node captured", code, outcome)
	}
}

// tunnelOutcome is the part of the JSON report that the completeness contract reads.
type tunnelOutcome struct {
	Complete  bool     `json:"complete"`
	NoCapture []string `json:"nodes_without_capture"`
}

// reportOutcome runs a manifest in both report modes. The two must agree on the exit
// code, on whether the import is complete, and on the nodes without a capture. It
// returns the exit code and the JSON outcome.
func reportOutcome(t *testing.T, manifest string) (int, tunnelOutcome) {
	t.Helper()
	code, text, stderr := runTunnel(t, manifest)
	jsonCode, js, jsonStderr := runTunnel(t, manifest, "--json")
	if code != jsonCode {
		t.Fatalf("text exit %d, json exit %d; stderr %q, %q", code, jsonCode, stderr, jsonStderr)
	}
	var outcome tunnelOutcome
	if err := json.Unmarshal([]byte(js), &outcome); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, js)
	}
	complete := "Complete: no"
	if outcome.Complete {
		complete = "Complete: yes"
	}
	nodes := cmp.Or(strings.Join(outcome.NoCapture, ", "), "none")
	for _, want := range []string{complete, "Nodes without a usable ip -d -j link capture: " + nodes} {
		if !strings.Contains(text, want) {
			t.Errorf("text report lacks %q, which the JSON report implies:\n%s", want, text)
		}
	}
	return code, outcome
}

// TestTunnelImportNeedsACaptureForEveryModeledNode gives a base with two modeled
// nodes and a capture for one. The import is incomplete: it exits 1, writes nothing,
// and names the node it could not check.
func TestTunnelImportNeedsACaptureForEveryModeledNode(t *testing.T) {
	dir, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     omittedInterfaceTopology,
		"links.json":    tunnelLinks,
		"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link")),
	})
	code, outcome := reportOutcome(t, manifest)
	if code != 1 || outcome.Complete || !slices.Equal(outcome.NoCapture, []string{"r2"}) {
		t.Errorf("exit %d, report %+v; want exit 1, incomplete, r2 without a capture", code, outcome)
	}
	topology := filepath.Join(dir, "out.json")
	code, stdout, stderr := runTunnel(t, manifest, "--write-topology", topology)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %q stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(topology); err == nil {
		t.Error("an incomplete import left a topology file behind")
	}
	if !strings.Contains(stdout, "not written: the import is incomplete") {
		t.Errorf("text report lacks the reason no file was written:\n%s", stdout)
	}
}

// TestTunnelImportWritesNothingForAnUnusableInventory gives r1 an ip -d -j link
// capture with no device inventory. The capture is refused and r1 is left uncovered,
// so the import is incomplete and writes nothing.
func TestTunnelImportWritesNothingForAnUnusableInventory(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"JSON null", "null", "is not ip -d -j link output"},
		{"empty array", "[]", "lists no devices"},
		{"entry with no ifname", `[{}]`, "has a device with no ifname"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, manifest := writeTunnelFiles(t, map[string]string{
				"base.json":     omittedInterfaceTopology,
				"links.json":    c.data,
				"links-r2.json": tunnelLinks,
				"manifest.json": tunnelManifestText("base.json",
					tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"),
					tunnelEntry("links-r2.json", "ip-link-r2", "r2", "ip -d -j link")),
			})
			code, outcome := reportOutcome(t, manifest)
			if code != 1 || outcome.Complete || !slices.Equal(outcome.NoCapture, []string{"r1"}) {
				t.Errorf("exit %d, report %+v; want exit 1, incomplete, r1 without a usable capture", code, outcome)
			}
			_, stdout, _ := runTunnel(t, manifest)
			if !strings.Contains(stdout, "refused ip-link-r1 r1: "+c.want) {
				t.Errorf("text report lacks the refusal %q:\n%s", c.want, stdout)
			}
			topology := filepath.Join(dir, "out.json")
			code, stdout, stderr := runTunnel(t, manifest, "--write-topology", topology)
			if code != 1 {
				t.Fatalf("exit %d, want 1; stdout %q stderr %q", code, stdout, stderr)
			}
			if _, err := os.Stat(topology); err == nil {
				t.Error("an incomplete import left a topology file behind")
			}
		})
	}
}

// TestTunnelImportWritesNothingWhenIncomplete gives a device kind the import does
// not read. The import is incomplete, so it exits 1 and leaves no file.
func TestTunnelImportWritesNothingWhenIncomplete(t *testing.T) {
	dir, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     omittedInterfaceTopology,
		"links.json":    `[{"ifname":"vx0","link_type":"ether","linkinfo":{"info_kind":"vxlan"}}]`,
		"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link")),
	})
	out := filepath.Join(dir, "out.json")
	code, stdout, stderr := runTunnel(t, manifest, "--write-topology", out)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %q stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an incomplete import left a topology file behind")
	}
	if !strings.Contains(stdout, `has kind "vxlan", which the import does not read`) || !strings.Contains(stdout, "not written: the import is incomplete") {
		t.Errorf("text report lacks the refusal or the reason no file was written:\n%s", stdout)
	}
}

// oneNodeTopology is a base of r1 alone, so the captures of r1 are the whole import.
const oneNodeTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "config:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r1", "vrf": "default",
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}]}
  ]
}`

// TestTunnelImportWritesNothingBesideAMalformedCapture gives r1 only ordinary devices
// and a malformed IPv4 route capture, with no address or IPv6 route capture. The
// malformed capture is refused, so the import is incomplete and writes no file.
func TestTunnelImportWritesNothingBesideAMalformedCapture(t *testing.T) {
	dir, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     oneNodeTopology,
		"links.json":    tunnelLinks,
		"routes4.json":  `{}`,
		"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"), tunnelEntry("routes4.json", "ip-route4-r1", "r1", "ip -4 -j route show table all")),
	})
	out := filepath.Join(dir, "out.json")
	code, stdout, stderr := runTunnel(t, manifest, "--write-topology", out)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stdout %q stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("an incomplete import left a topology file behind")
	}
	if !strings.Contains(stdout, "is not ip -4 -j route show table all output") || !strings.Contains(stdout, "not written: the import is incomplete") {
		t.Errorf("text report lacks the refusal or the reason no file was written:\n%s", stdout)
	}
}

// TestTunnelImportRefusesFlagsItCannotUse names each setting the import does not
// accept, and an argument with no place to go. Each is refused with exit 2.
func TestTunnelImportRefusesFlagsItCannotUse(t *testing.T) {
	_, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     omittedInterfaceTopology,
		"links.json":    tunnelLinks,
		"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link")),
	})
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"with -import-frr-ospf", []string{"--import-frr-ospf", manifest}, "-import-frr-ospf cannot be combined with -import-tunnels"},
		{"with -import-frr-bgp", []string{"--import-frr-bgp", manifest}, "-import-frr-bgp cannot be combined with -import-tunnels"},
		{"with -iface", []string{"--iface", "eth0"}, "-iface cannot be combined with -import-tunnels"},
		{"with a positional argument", []string{"extra.json"}, "unexpected arguments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runNetdoc(t, append([]string{"--import-tunnels", manifest}, c.args...)...)
			if code != 2 || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", code, stdout, stderr, c.want)
			}
		})
	}
}

// TestTunnelImportRefusesAnUnsafeTarget refuses a topology path that exists,
// and the base topology's own path. Both would overwrite a file, so both exit 2
// before any capture is read.
func TestTunnelImportRefusesAnUnsafeTarget(t *testing.T) {
	dir, manifest := writeTunnelFiles(t, map[string]string{
		"base.json":     omittedInterfaceTopology,
		"links.json":    tunnelLinks,
		"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link")),
		"taken.json":    "{}",
	})
	for _, target := range []string{filepath.Join(dir, "taken.json"), filepath.Join(dir, "base.json")} {
		code, stdout, stderr := runTunnel(t, manifest, "--write-topology", target)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "already exists; netdoc does not overwrite it") {
			t.Errorf("target %s: exit %d, stdout %q, stderr %q; want exit 2 and no overwrite", filepath.Base(target), code, stdout, stderr)
		}
	}
}

// TestTunnelImportRefusesUnsafeCaptures gives each unsafe layout its own
// directory: a symbolic link, a path that climbs out, a repeated file name, and
// one file under two names. Each exits 2.
func TestTunnelImportRefusesUnsafeCaptures(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string) string
		want  string
	}{
		{"symbolic link", func(t *testing.T, dir string) string {
			if err := os.Symlink(filepath.Join(dir, "links.json"), filepath.Join(dir, "via.json")); err != nil {
				t.Fatal(err)
			}
			return tunnelManifestText("base.json", tunnelEntry("via.json", "ip-link-r1", "r1", "ip -d -j link"))
		}, "is a symbolic link"},
		{"path that climbs out", func(t *testing.T, dir string) string {
			return tunnelManifestText("base.json", tunnelEntry("../outside.json", "ip-link-r1", "r1", "ip -d -j link"))
		}, "must be a relative path"},
		{"repeated file name", func(t *testing.T, dir string) string {
			return tunnelManifestText("base.json",
				tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"),
				tunnelEntry("links.json", "ip-link-r1b", "r1", "ip -d -j link"))
		}, "name the same file"},
		{"one file under two names", func(t *testing.T, dir string) string {
			if err := os.Link(filepath.Join(dir, "links.json"), filepath.Join(dir, "again.json")); err != nil {
				t.Fatal(err)
			}
			return tunnelManifestText("base.json",
				tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"),
				tunnelEntry("again.json", "ip-link-r1b", "r1", "ip -d -j link"))
		}, "are the same file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, _ := writeTunnelFiles(t, map[string]string{"base.json": omittedInterfaceTopology, "links.json": tunnelLinks})
			manifest := filepath.Join(dir, "manifest.json")
			if err := os.WriteFile(manifest, []byte(c.setup(t, dir)), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runTunnel(t, manifest)
			if code != 2 || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", code, stdout, stderr, c.want)
			}
		})
	}
}

// TestTunnelImportManifestIsStrict gives each manifest fault its own row. The
// decoder refuses every one with exit 2 and the reason.
func TestTunnelImportManifestIsStrict(t *testing.T) {
	entry := tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link")
	cases := []struct {
		name     string
		manifest string
		want     string
	}{
		{"repeated key", `{"version": 1, "version": 1, "topology": "base.json", "captures": [` + entry + `]}`, "duplicate key"},
		{"unknown key", `{"version": 1, "topology": "base.json", "extra": 1, "captures": [` + entry + `]}`, `has unknown key "extra"`},
		{"key differs in case", `{"version": 1, "Topology": "base.json", "captures": [` + entry + `]}`, "differs from"},
		{"capture node differs in case", `{"version": 1, "topology": "base.json", "captures": [{"file": "links.json", "source": "s", "Node": "r1", "command": "ip -d -j link", "collected_at": "2026-10-09T12:00:00Z"}]}`, `"Node" differs from "node" only in case`},
		{"capture time differs in case", `{"version": 1, "topology": "base.json", "captures": [{"file": "links.json", "source": "s", "node": "r1", "command": "ip -d -j link", "Collected_At": "2026-10-09T12:00:00Z"}]}`, `"Collected_At" differs from "collected_at" only in case`},
		{"no version", `{"topology": "base.json", "captures": [` + entry + `]}`, `needs "version"`},
		{"no topology", `{"version": 1, "captures": [` + entry + `]}`, `needs "topology"`},
		{"topology climbs out", `{"version": 1, "topology": "../base.json", "captures": [` + entry + `]}`, "must be a relative path"},
		{"no captures", `{"version": 1, "topology": "base.json", "captures": []}`, "lists no captures"},
		{"command is a number", `{"version": 1, "topology": "base.json", "captures": [{"file": "links.json", "source": "s", "node": "r1", "command": 5, "collected_at": "2026-10-09T12:00:00Z"}]}`, `"command" must be a string`},
		{"time has no offset", `{"version": 1, "topology": "base.json", "captures": [{"file": "links.json", "source": "s", "node": "r1", "command": "ip -d -j link", "collected_at": "2026-10-09T12:00:00"}]}`, "collected_at is not an RFC 3339 time with an offset"},
		{"two captures share a source", `{"version": 1, "topology": "base.json", "captures": [` + entry + `,` + entry + `]}`, "both use source label"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, _ := writeTunnelFiles(t, map[string]string{"base.json": omittedInterfaceTopology, "links.json": tunnelLinks})
			manifest := filepath.Join(dir, "manifest.json")
			if err := os.WriteFile(manifest, []byte(c.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runTunnel(t, manifest)
			if code != 2 || stdout != "" || !strings.Contains(stderr, c.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 and %q", code, stdout, stderr, c.want)
			}
		})
	}
}

// TestTunnelImportKeepsKeysOut reads two dumps that a key-bearing line makes
// refused. The text report, the JSON report, and stderr must carry no key
// sentinel, since a line with a key is never echoed.
func TestTunnelImportKeepsKeysOut(t *testing.T) {
	const sentinelLine = "wg0\tSENTINEL-PRIVATE\tSENTINEL-PUBLIC\t51820\toff\nwg0\tSENTINEL-PEER\tSENTINEL-PSK\t10.0.25.1:51820\n"
	dumps := map[string]string{
		"field count": sentinelLine + "wg0\tSENTINEL-KEY\tb\tc\td\te\n",
		"bad name":    "bad name\tSENTINEL-PRIVATE\tSENTINEL-PUBLIC\t51820\toff\n",
	}
	for name, dump := range dumps {
		t.Run(name, func(t *testing.T) {
			dir, manifest := writeTunnelFiles(t, map[string]string{
				"base.json":     omittedInterfaceTopology,
				"links.json":    `[{"ifname":"wg0","link_type":"none","linkinfo":{"info_kind":"wireguard"}}]`,
				"dump.txt":      dump,
				"manifest.json": tunnelManifestText("base.json", tunnelEntry("links.json", "ip-link-r1", "r1", "ip -d -j link"), tunnelEntry("dump.txt", "wg-r1", "r1", "wg show all dump")),
			})
			out := filepath.Join(dir, "out.json")
			codeText, text, stderr := runTunnel(t, manifest, "--write-topology", out)
			codeJSON, js, stderrJSON := runTunnel(t, manifest, "--json")
			if codeText != 1 || codeJSON != 1 {
				t.Fatalf("exit text %d, json %d; want 1 for both (stderr %q, %q)", codeText, codeJSON, stderr, stderrJSON)
			}
			for label, got := range map[string]string{"text": text, "json": js, "stderr": stderr + stderrJSON} {
				if strings.Contains(got, "SENTINEL") {
					t.Errorf("%s output carries a key sentinel:\n%s", label, got)
				}
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("an incomplete import left a topology file behind")
			}
		})
	}
}

// TestTunnelImportLimitsTheCapturesTogether gives 33 captures of one mebibyte
// each. Every file is within its own limit, but together they pass the import's
// aggregate limit, so the import exits 2 before it parses any of them.
func TestTunnelImportLimitsTheCapturesTogether(t *testing.T) {
	big := bytes.Repeat([]byte(" "), 1<<20)
	files := map[string]string{"base.json": omittedInterfaceTopology}
	var entries []string
	for i := range 33 {
		name := fmt.Sprintf("c%02d.json", i)
		files[name] = string(big)
		entries = append(entries, tunnelEntry(name, fmt.Sprintf("s%02d", i), "r1", "ip -d -j link"))
	}
	dir, manifest := writeTunnelFiles(t, files)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(tunnelManifestText("base.json", entries...)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runTunnel(t, manifest)
	if code != 2 || stdout != "" || !strings.Contains(stderr, "the captures together are larger than") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 for the aggregate limit", code, stdout, stderr)
	}
}

// TestTunnelReportNamesTheRulesBehindEachRecord checks that a record names the
// ip -d -j link capture it came from, the command that capture was, and the ip -j
// rule show capture that proves its underlay table. A node with no rules proof
// leaves both rules fields empty, not a zero time.
func TestTunnelReportNamesTheRulesBehindEachRecord(t *testing.T) {
	linkAt := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	ruleAt := linkAt.Add(time.Second)
	imp := routepath.TunnelImport{
		Tunnels: []routepath.Tunnel{{
			Provenance:  netmodel.Provenance{Source: "ip-link-r1", CollectedAt: linkAt},
			Node:        "r1",
			VRF:         "default",
			Interface:   "gre1",
			Remote:      netip.MustParseAddr("10.71.30.1"),
			UnderlayVRF: "default",
		}, {
			Provenance:  netmodel.Provenance{Source: "ip-link-r3", CollectedAt: linkAt},
			Node:        "r3",
			VRF:         "default",
			Interface:   "gre1",
			Remote:      netip.MustParseAddr("10.71.14.1"),
			UnderlayVRF: "default",
		}},
		Rules: []routepath.RulesProof{{Node: "r1", Rules: netmodel.Provenance{Source: "ip-rule-r1", CollectedAt: ruleAt}}},
	}
	r := buildTunnelReport("manifest.json", tunnelManifest{Topology: "base.json"}, imp)
	if len(r.Tunnels) != 2 {
		t.Fatalf("report has %d records, want 2", len(r.Tunnels))
	}
	r1, r3 := r.Tunnels[0], r.Tunnels[1]
	if r1.Command != routepath.TunnelCommandIPLink || r1.Source != "ip-link-r1" || r1.RulesSource != "ip-rule-r1" || r1.RulesCollectedAt != stampText(ruleAt) {
		t.Errorf("r1 record %+v names the wrong captures; want command %q, source ip-link-r1, rules ip-rule-r1 at %s", r1, routepath.TunnelCommandIPLink, stampText(ruleAt))
	}
	if r3.RulesSource != "" || r3.RulesCollectedAt != "" {
		t.Errorf("r3 record %+v names rules it has no proof for", r3)
	}
}

// TestTunnelReportListsInertFallbacks checks that an inert kernel fallback reaches
// both report modes with the captures that show it.
func TestTunnelReportListsInertFallbacks(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	imp := routepath.TunnelImport{Inert: []routepath.InertDevice{{
		Node:      "r2",
		Interface: "gre0",
		Kind:      "gre",
		Sources:   []string{"ip-link-r2", "ip-addr-r2"},
		From:      at,
		Until:     at.Add(time.Second),
	}}}
	r := buildTunnelReport("manifest.json", tunnelManifest{Topology: "base.json"}, imp)
	if len(r.Inert) != 1 || r.Inert[0].Kind != "gre" || r.Inert[0].From != stampText(at) {
		t.Fatalf("report inert = %+v, want one gre0 on r2 from %s", r.Inert, stampText(at))
	}
	if text := renderTunnelText(r); !strings.Contains(text, "inert r2 gre0 (gre) from "+stampText(at)) {
		t.Errorf("text report does not list the inert device:\n%s", text)
	}
}

// tunnelGRELinks is the ip -d -j link capture of r1 with gre1 over eth1, the
// underlay address of omittedInterfaceTopology.
const tunnelGRELinks = `[{"ifname":"lo","link_type":"loopback"},{"ifname":"eth1","link_type":"ether"},{"ifname":"gre1","link_type":"gre","link":"eth1","linkinfo":{"info_kind":"gre","info_data":{"local":"10.0.12.1","remote":"10.0.12.2","ikey":"0.0.0.0","okey":"0.0.0.0"}}}]`

// tunnelBaseTopology is omittedInterfaceTopology with r1 listing gre1, so the
// base names the tunnel device the import records on it.
const tunnelBaseTopology = `{
  "version": 1,
  "source": {"node": "r1", "vrf": "default"},
  "observations": [
    {"source": "control:r1", "collected_at": "2026-10-09T12:00:00Z", "plane": "control", "node": "r1", "vrf": "default", "routes_complete": true,
     "interfaces": [{"name": "eth1", "addresses": ["10.0.12.1/30"]}, {"name": "gre1", "addresses": ["172.31.0.1/30"]}],
     "routes": [{"prefix": "10.20.0.0/16", "origin": "ospf", "next_hops": [{"addr": "10.0.12.2"}]}]},
    {"source": "config:r2", "collected_at": "2026-10-09T12:00:00Z", "plane": "configured", "node": "r2", "vrf": "default",
     "interfaces": [{"name": "eth0", "addresses": ["10.0.12.2/30"]}, {"name": "lan", "addresses": ["10.20.40.8/24"]}]}
  ]
}`

// tunnelRules is the ip -j rule show capture of a node that has the kernel
// default IPv4 rules.
const tunnelRules = `[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`

// TestTunnelImportWritesTheRecordedTunnel imports a gre device whose underlay is
// proven by r1's default rules. The written topology must carry that one tunnel,
// and both report modes must name the link capture and the rules capture behind
// it.
func TestTunnelImportWritesTheRecordedTunnel(t *testing.T) {
	for _, kind := range []string{"gre", "ipip"} {
		t.Run(kind, func(t *testing.T) {
			dir, manifest := writeTunnelFiles(t, map[string]string{
				"base.json":     tunnelBaseTopology,
				"links-r1.json": strings.Replace(tunnelGRELinks, `"info_kind":"gre"`, `"info_kind":"`+kind+`"`, 1),
				"links-r2.json": tunnelLinks,
				"rules-r1.json": tunnelRules,
				"manifest.json": tunnelManifestText("base.json",
					tunnelEntry("links-r1.json", "ip-link-r1", "r1", "ip -d -j link"),
					tunnelEntry("links-r2.json", "ip-link-r2", "r2", "ip -d -j link"),
					tunnelEntry("rules-r1.json", "ip-rule-r1", "r1", "ip -j rule show")),
			})
			out := filepath.Join(dir, "out.json")
			code, stdout, stderr := runTunnel(t, manifest, "--write-topology", out)
			if code != 0 {
				t.Fatalf("exit %d, want 0; stdout %q stderr %q", code, stdout, stderr)
			}
			got, err := os.ReadFile(filepath.Clean(out))
			if err != nil {
				t.Fatal(err)
			}
			f, err := routepath.Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Tunnels) != 1 {
				t.Fatalf("written topology has %d tunnels, want 1: %s", len(f.Tunnels), got)
			}
			tun := f.Tunnels[0]
			if tun.Node != "r1" || tun.Interface != "gre1" || tun.VRF != "default" || tun.Remote != netip.MustParseAddr("10.0.12.2") || tun.UnderlayVRF != "default" {
				t.Errorf("tunnel %+v, want gre1 on r1 in default to 10.0.12.2 with underlay default", tun)
			}

			code, outcome := reportOutcome(t, manifest)
			if code != 0 || !outcome.Complete {
				t.Errorf("exit %d, outcome %+v; want exit 0 and complete", code, outcome)
			}
			code, js, stderr := runTunnel(t, manifest, "--json")
			if code != 0 {
				t.Fatalf("json exit %d; stderr %q", code, stderr)
			}
			var report struct {
				Tunnels []struct {
					Command          string `json:"command"`
					Source           string `json:"source"`
					RulesSource      string `json:"rules_source"`
					RulesCollectedAt string `json:"rules_collected_at"`
				} `json:"tunnels"`
			}
			if err := json.Unmarshal([]byte(js), &report); err != nil {
				t.Fatalf("report is not JSON: %v\n%s", err, js)
			}
			if len(report.Tunnels) != 1 {
				t.Fatalf("report has %d tunnels, want 1: %s", len(report.Tunnels), js)
			}
			rec := report.Tunnels[0]
			if rec.Command != routepath.TunnelCommandIPLink || rec.Source != "ip-link-r1" || rec.RulesSource != "ip-rule-r1" || rec.RulesCollectedAt != "2026-10-09T12:00:00Z" {
				t.Errorf("record %+v, want link ip-link-r1 and rules ip-rule-r1 at 2026-10-09T12:00:00Z", rec)
			}
			_, text, _ := runTunnel(t, manifest)
			if want := "rules ip-rule-r1 at 2026-10-09T12:00:00Z"; !strings.Contains(text, want) {
				t.Errorf("text report lacks %q:\n%s", want, text)
			}
		})
	}
}

// TestTunnelReportNamesTheCapturesBehindAWireGuardRecord checks that a WireGuard
// record carries the source and collection time of its dump and endpoint lookup, and
// the egress device the lookup named, in the JSON report and in the text. A gre record
// carries none of these fields, so its report is as it was.
func TestTunnelReportNamesTheCapturesBehindAWireGuardRecord(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	prov := func(source string, after time.Duration) netmodel.Provenance {
		return netmodel.Provenance{Source: source, CollectedAt: at.Add(after)}
	}
	remote := netip.MustParseAddr("10.0.25.1")
	tun := func(iface string) routepath.Tunnel {
		return routepath.Tunnel{Provenance: prov("ip-link-r1", 0), Node: "r1", VRF: "default", Interface: iface, Remote: remote, UnderlayVRF: "default"}
	}
	imp := routepath.TunnelImport{
		Tunnels: []routepath.Tunnel{tun("gre1"), tun("wg0")},
		WireGuard: []routepath.WireGuardProof{{
			Node: "r1", Interface: "wg0", Egress: "eth0",
			Device: prov("ip-link-r1", 0), Endpoint: prov("wg-r1", time.Minute), Lookup: prov("ip-route-get-r1", 2*time.Minute), Rules: prov("ip-rule-r1", 0),
		}},
		Rules: []routepath.RulesProof{{Node: "r1", Rules: prov("ip-rule-r1", 0)}},
	}
	r := buildTunnelReport("manifest.json", tunnelManifest{Topology: "base.json"}, imp)
	gre, wg := r.Tunnels[0], r.Tunnels[1]
	if gre.LookupSource != "" || gre.EndpointSource != "" || gre.EgressInterface != "" {
		t.Errorf("gre record carries WireGuard evidence: %+v", gre)
	}
	if wg.EndpointSource != "wg-r1" || wg.EndpointCollectedAt != stampText(at.Add(time.Minute)) ||
		wg.LookupSource != "ip-route-get-r1" || wg.LookupCollectedAt != stampText(at.Add(2*time.Minute)) ||
		wg.LookupCommand != routepath.TunnelCommandRouteGetFibmatchPrefix+"10.0.25.1" || wg.EgressInterface != "eth0" {
		t.Errorf("wireguard record = %+v, want the dump, the lookup, and the egress device named", wg)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), `"lookup_source"`); got != 1 {
		t.Errorf("report names a lookup source %d times, want once (for wg0 only): %s", got, raw)
	}
}
