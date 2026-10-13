package frrospf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The steady BGP capture is described in testdata/frr/10.7.0/bgp/README.md. These tests are
// untagged and portable, and they read the installed bytes without writing them. They check
// framing, checksums, pins, stamps, and the fields these tests read. They do not show that
// a route was installed or forwarded, or that the four captures describe one instant.

// bgpSteadyDir is the steady BGP capture: four VTY transcripts with their stamps, the daemon
// configurations and versions, and SHA256SUMS.
var bgpSteadyDir = filepath.Join(fixtureRoot, "bgp", "steady")

// bgpSteadySums is the manifest. Its digests are checked against the bytes. The pins below
// come from this file's constants, never from the manifest.
const bgpSteadySums = "SHA256SUMS"

// bgpSteadyFiles are the 14 source files, in the order SHA256SUMS lists them.
var bgpSteadyFiles = []string{
	"r1-show_ip_bgp_summary_json.raw", "r1-show_ip_bgp_summary_json.collected_at",
	"r2-show_ip_bgp_summary_json.raw", "r2-show_ip_bgp_summary_json.collected_at",
	"r1-show_ip_bgp_json.raw", "r1-show_ip_bgp_json.collected_at",
	"r2-show_ip_bgp_json.raw", "r2-show_ip_bgp_json.collected_at",
	"r1-bgpd.conf", "r2-bgpd.conf", "r1-zebra.conf", "r2-zebra.conf",
	"bgpd-version.txt", "zebra-version.txt",
}

// bgpSumLine is one manifest line as this capture writes it: 64 lowercase hex digits, two
// spaces, and the name. It is text mode, not the " *name" form of sha256sum --binary.
var bgpSumLine = regexp.MustCompile(`^([0-9a-f]{64})  (\S+)$`)

// bgpSteadyRaw is one VTY transcript: the node whose prompt ends it, the command its echo
// must hold, the file stem, and the SHA-256 of the original .raw.
type bgpSteadyRaw struct {
	node, command, stem, sum string
}

// bgpSteadyRaws are the transcripts in the order they were taken. The pins are the original
// .raw digests, written here so that a rewritten SHA256SUMS cannot move them.
var bgpSteadyRaws = []bgpSteadyRaw{
	{"r1", "show ip bgp summary json", "r1-show_ip_bgp_summary_json", "37b7a53f85746e3bc10beb74cbb77ce9ab3bb83ccda406f4347178a9c7ed178f"},
	{"r1", "show ip bgp json", "r1-show_ip_bgp_json", "313beb714d6f538726cbd3b518cabf703c90aeba53deb5849d52030a0223f65a"},
	{"r2", "show ip bgp summary json", "r2-show_ip_bgp_summary_json", "1899f4d7502d954211d61f123973ec6e5323b8edf55d1bfc271e1bbf4044eec7"},
	{"r2", "show ip bgp json", "r2-show_ip_bgp_json", "025d059a6755d1f6be889d5881ab0dac0650c9070f3ad2697408ec0d2dc40bee"},
}

// bgpSteadyStamps are the four collected_at files, exact to the byte with the LF included,
// in the order of bgpSteadyRaws.
var bgpSteadyStamps = []string{
	"2026-10-13T01:22:26.451780317Z\n",
	"2026-10-13T01:22:29.612752736Z\n",
	"2026-10-13T01:22:32.783183380Z\n",
	"2026-10-13T01:22:35.923164705Z\n",
}

// bgpSummary is the part of "show ip bgp summary json" that these tests read. Only these
// fields are declared, each named as FRR prints it.
type bgpSummary struct {
	IPv4Unicast struct {
		Peers map[string]struct {
			State    string `json:"state"`
			RemoteAS int    `json:"remoteAs"`
			LocalAS  int    `json:"localAs"`
		} `json:"peers"`
	} `json:"ipv4Unicast"`
}

// bgpTable is the part of "show ip bgp json" that these tests read. Origin is the BGP
// ORIGIN attribute, so IGP here is a BGP value and does not name the protocol that carried
// the route. r2 reports peerId "(unspec)" for the same prefix.
type bgpTable struct {
	Routes map[string][]struct {
		PeerID   string `json:"peerId"`
		PathFrom string `json:"pathFrom"`
		Path     string `json:"path"`
		Origin   string `json:"origin"`
		Nexthops []struct {
			IP string `json:"ip"`
		} `json:"nexthops"`
	} `json:"routes"`
}

// readBGPSteady reads SHA256SUMS and the 14 source files. readFile fails the test when one
// is missing.
func readBGPSteady(t *testing.T) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, name := range append([]string{bgpSteadySums}, bgpSteadyFiles...) {
		files[name] = readFile(t, filepath.Join(bgpSteadyDir, name))
	}
	return files
}

// bgpCheckSums checks SHA256SUMS against the bytes. It requires LF-only lines, one per source
// file with none repeated, each shaped "<hex>  <name>", and each digest equal to its file's
// SHA-256. It does not require byte order, since the manifest follows capture order.
func bgpCheckSums(sums []byte, files map[string][]byte) error {
	if len(sums) == 0 || sums[len(sums)-1] != '\n' || bytes.ContainsRune(sums, '\r') {
		return errors.New("SHA256SUMS is not LF-only and LF-terminated")
	}
	lines := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n")
	if len(lines) != len(bgpSteadyFiles) {
		return fmt.Errorf("SHA256SUMS has %d entries, want %d", len(lines), len(bgpSteadyFiles))
	}
	seen := map[string]bool{}
	for _, line := range lines {
		m := bgpSumLine.FindStringSubmatch(line)
		if m == nil {
			return fmt.Errorf("SHA256SUMS line %q is not <64 lowercase hex>  <name>", line)
		}
		digest, name := m[1], m[2]
		if !slices.Contains(bgpSteadyFiles, name) || seen[name] {
			return fmt.Errorf("SHA256SUMS names %s, which is not a source file listed once", name)
		}
		seen[name] = true
		sum := sha256.Sum256(files[name])
		if hex.EncodeToString(sum[:]) != digest {
			return fmt.Errorf("%s: SHA256SUMS digest %s does not match the file", name, digest)
		}
	}
	return nil
}

// bgpCheckPin checks one .raw against its pin: the SHA-256 of the whole file, in hex.
func bgpCheckPin(raw []byte, pin string) error {
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != pin {
		return fmt.Errorf("sha256 is %s, want %s", got, pin)
	}
	return nil
}

// bgpCheckTranscript checks one .raw and returns its JSON body. zebraRIBCheckFrame checks the
// echo, the CRLF framing, and the prompt with nothing after it. checkStrictJSON then checks
// that the body is one object with no repeated key at any depth. Its OSPF-only rules match no
// key in this capture.
func bgpCheckTranscript(raw []byte, command, node string) ([]byte, error) {
	body, err := zebraRIBCheckFrame(raw, command, node)
	if err != nil {
		return nil, err
	}
	if err = checkStrictJSON(body); err != nil {
		return nil, err
	}
	return body, nil
}

// bgpDecode checks one transcript, then decodes its body into v.
func bgpDecode(t *testing.T, raw []byte, command, node string, v any) {
	t.Helper()
	body, err := bgpCheckTranscript(raw, command, node)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatal(err)
	}
}

// TestBGPSteadyCaptureIsIntact applies the checks to the installed steady capture: the 14
// source files and SHA256SUMS, each transcript's framing, shape, and pin, and the stamps.
func TestBGPSteadyCaptureIsIntact(t *testing.T) {
	files := readBGPSteady(t)
	if err := bgpCheckSums(files[bgpSteadySums], files); err != nil {
		t.Errorf("SHA256SUMS: %v", err)
	}
	var prev time.Time
	for i, c := range bgpSteadyRaws {
		raw := files[c.stem+".raw"]
		if _, err := bgpCheckTranscript(raw, c.command, c.node); err != nil {
			t.Errorf("%s.raw: %v", c.stem, err)
		}
		if err := bgpCheckPin(raw, c.sum); err != nil {
			t.Errorf("%s.raw: %v", c.stem, err)
		}
		stamp := files[c.stem+".collected_at"]
		if string(stamp) != bgpSteadyStamps[i] {
			t.Errorf("%s.collected_at is %q, want %q", c.stem, stamp, bgpSteadyStamps[i])
		}
		at, err := zebraRIBParseStamp(stamp)
		if err != nil {
			t.Errorf("%s.collected_at: %v", c.stem, err)
		}
		if i > 0 && !at.After(prev) {
			t.Errorf("%s.collected_at is not after the capture before it", c.stem)
		}
		prev = at
	}
}

// TestBGPSteadyObservedFields decodes the fields these tests read from the installed
// transcripts and compares them with the values in the capture. A changed value, a missing
// peer, or an extra route fails. No installed-route or forwarding field is read.
func TestBGPSteadyObservedFields(t *testing.T) {
	files := readBGPSteady(t)
	var r1Sum, r2Sum bgpSummary
	var r1Table, r2Table bgpTable
	bgpDecode(t, files["r1-show_ip_bgp_summary_json.raw"], "show ip bgp summary json", "r1", &r1Sum)
	bgpDecode(t, files["r2-show_ip_bgp_summary_json.raw"], "show ip bgp summary json", "r2", &r2Sum)
	bgpDecode(t, files["r1-show_ip_bgp_json.raw"], "show ip bgp json", "r1", &r1Table)
	bgpDecode(t, files["r2-show_ip_bgp_json.raw"], "show ip bgp json", "r2", &r2Table)

	// r1 has an Established session to 10.0.1.2 and an Active one to 10.0.1.3.
	peers := r1Sum.IPv4Unicast.Peers
	if len(peers) != 2 {
		t.Fatalf("r1 has %d peers, want 2", len(peers))
	}
	if got := peers["10.0.1.2"]; got.State != "Established" || got.RemoteAS != 65002 || got.LocalAS != 65001 {
		t.Errorf("r1 peer 10.0.1.2 is %+v, want Established, remoteAs 65002, localAs 65001", got)
	}
	if got := peers["10.0.1.3"]; got.State != "Active" || got.RemoteAS != 65003 || got.LocalAS != 65001 {
		t.Errorf("r1 peer 10.0.1.3 is %+v, want Active, remoteAs 65003, localAs 65001", got)
	}

	// r2 has one Established session, to 10.0.1.1.
	peers = r2Sum.IPv4Unicast.Peers
	if len(peers) != 1 {
		t.Fatalf("r2 has %d peers, want 1", len(peers))
	}
	if got := peers["10.0.1.1"]; got.State != "Established" || got.RemoteAS != 65001 || got.LocalAS != 65002 {
		t.Errorf("r2 peer 10.0.1.1 is %+v, want Established, remoteAs 65001, localAs 65002", got)
	}

	// Each node reports one path for 10.10.2.0/24. r1 has peerId 10.0.1.2, AS path 65002, and
	// pathFrom external. r2 has peerId (unspec), an empty AS path, and next hop 0.0.0.0.
	if len(r1Table.Routes) != 1 || len(r1Table.Routes["10.10.2.0/24"]) != 1 {
		t.Fatalf("r1 has routes %+v, want one prefix with one path", r1Table.Routes)
	}
	r1Path := r1Table.Routes["10.10.2.0/24"][0]
	if r1Path.PeerID != "10.0.1.2" || r1Path.PathFrom != "external" || r1Path.Path != "65002" || r1Path.Origin != "IGP" {
		t.Errorf("r1 path is %+v, want peerId 10.0.1.2, pathFrom external, path 65002, origin IGP", r1Path)
	}
	if len(r1Path.Nexthops) != 1 || r1Path.Nexthops[0].IP != "10.0.1.2" {
		t.Errorf("r1 nexthops are %+v, want one, 10.0.1.2", r1Path.Nexthops)
	}
	if len(r2Table.Routes) != 1 || len(r2Table.Routes["10.10.2.0/24"]) != 1 {
		t.Fatalf("r2 has routes %+v, want one prefix with one path", r2Table.Routes)
	}
	r2Path := r2Table.Routes["10.10.2.0/24"][0]
	if r2Path.PeerID != "(unspec)" || r2Path.Path != "" || r2Path.Origin != "IGP" {
		t.Errorf("r2 path is %+v, want peerId (unspec), empty path, origin IGP", r2Path)
	}
	if len(r2Path.Nexthops) != 1 || r2Path.Nexthops[0].IP != "0.0.0.0" {
		t.Errorf("r2 nexthops are %+v, want one, 0.0.0.0", r2Path.Nexthops)
	}
}

// TestBGPSteadyMutationsAreRejected edits clones of the installed r1 summary in memory. Each
// edit must fail the check that targets it, and the pin must still fail when SHA256SUMS is
// rewritten to match the edit. No fixture file is written.
func TestBGPSteadyMutationsAreRejected(t *testing.T) {
	files := readBGPSteady(t)
	sums := files[bgpSteadySums]
	if err := bgpCheckSums(sums, files); err != nil {
		t.Fatalf("installed capture: %v", err)
	}
	// name, command, and pin are bgpSteadyRaws[0].
	const name = "r1-show_ip_bgp_summary_json.raw"
	const command = "show ip bgp summary json"
	const pin = "37b7a53f85746e3bc10beb74cbb77ce9ab3bb83ccda406f4347178a9c7ed178f"
	raw := files[name]
	if err := bgpCheckPin(raw, pin); err != nil {
		t.Fatalf("installed capture: %v", err)
	}
	if _, err := bgpCheckTranscript(raw, command, "r1"); err != nil {
		t.Fatalf("installed capture: %v", err)
	}

	t.Run("one byte changed, checksum and pin fail", func(t *testing.T) {
		changed := bytes.Clone(raw)
		changed[len(changed)/2] ^= 0x01
		altered := maps.Clone(files)
		altered[name] = changed
		zebraRIBExpectErr(t, bgpCheckSums(sums, altered), "does not match the file")
		zebraRIBExpectErr(t, bgpCheckPin(changed, pin), "sha256 is")
	})
	t.Run("one byte changed, manifest rewritten to match", func(t *testing.T) {
		changed := bytes.Clone(raw)
		changed[len(changed)/2] ^= 0x01
		sum := sha256.Sum256(changed)
		rewritten := bytes.Replace(sums, []byte(pin+"  "+name), []byte(hex.EncodeToString(sum[:])+"  "+name), 1)
		if bytes.Equal(rewritten, sums) {
			t.Fatal("the manifest line for the r1 summary was not found")
		}
		altered := maps.Clone(files)
		altered[name] = changed
		if err := bgpCheckSums(rewritten, altered); err != nil {
			t.Errorf("rewritten manifest should match its bytes: %v", err)
		}
		zebraRIBExpectErr(t, bgpCheckPin(changed, pin), "sha256 is")
	})
	t.Run("CRLF after the echo changed to LF", func(t *testing.T) {
		lf := bytes.Replace(raw, []byte("\r\n"), []byte("\n"), 1)
		_, err := bgpCheckTranscript(lf, command, "r1")
		zebraRIBExpectErr(t, err, "first line is not the echo")
	})
	t.Run("another command's echo", func(t *testing.T) {
		other := bytes.Replace(raw, []byte(command+"\r\n"), []byte("show ip bgp json\r\n"), 1)
		_, err := bgpCheckTranscript(other, command, "r1")
		zebraRIBExpectErr(t, err, "first line is not the echo")
	})
	t.Run("prompt of another node", func(t *testing.T) {
		_, err := bgpCheckTranscript(raw, command, "r2")
		zebraRIBExpectErr(t, err, "does not end with CRLF and the prompt")
	})
	t.Run("byte after the prompt", func(t *testing.T) {
		_, err := bgpCheckTranscript(append(bytes.Clone(raw), '\n'), command, "r1")
		zebraRIBExpectErr(t, err, "does not end with CRLF and the prompt")
	})
	t.Run("duplicate key", func(t *testing.T) {
		dup := replaceOnce(t, raw, `"state":"Established"`, `"state":"Established","state":"Idle"`)
		_, err := bgpCheckTranscript(dup, command, "r1")
		zebraRIBExpectErr(t, err, "duplicate key")
	})
}
