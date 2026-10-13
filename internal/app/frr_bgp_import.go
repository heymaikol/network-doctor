package app

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/frrbgp"
	"github.com/heymaikol/network-doctor/internal/frrospf"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// frrBGPReportVersion is the version of the --import-frr-bgp JSON report. It is
// a separate document from the OSPF report, so its version moves on its own.
const frrBGPReportVersion = 1

// frrBGPProtocol names the protocol the --import-frr-bgp report describes.
const frrBGPProtocol = "bgp"

// frrBGPFlags are the only settings a BGP import accepts beside its manifest.
// Every other setting describes a probe run, another reading, or the OSPF import,
// and this import would ignore it.
var frrBGPFlags = map[string]bool{"import-frr-bgp": true, "json": true}

// frrBGPNotRead says what the BGP import does not read. A reader checks it before
// they treat the report as the whole picture.
var frrBGPNotRead = []string{
	"routes and prefixes: not read; the summary carries none, so no route is claimed",
	"routing table, FIB, and kernel installation: not read",
	"nodes and peers that no capture names: unknown, not down",
	"session state after its collection time: not observed",
}

// frrBGPLimitations says what the BGP import result does not establish.
var frrBGPLimitations = []string{
	"declared metadata (source, node, VRF, FRR version, command, collection time) is the manifest's claim; netdoc checks the FRR version, the command, the VRF, and that the transcript prompt names the declared node, but cannot verify which router produced a capture",
	"each state is the JSON state field FRR printed at collection; peerState is not read",
	"exit 0 means every capture is valid; it does not mean any session is Established or that the network is healthy",
	"an empty peer collection is observed empty; it is not reported as a down session",
}

// runFRRBGPImport reads the FRR BGP summary captures a manifest names and reports
// each router's ID, local AS, and peer sessions as FRR printed them. It runs no
// probe and contacts no router. It exits 0 when every capture is valid and 2 when
// the manifest, a capture, or the output cannot be used. It writes no topology.
func runFRRBGPImport(setFlags map[string]bool, manifestPath string, jsonOut bool, stdout, stderr io.Writer) int {
	for _, name := range slices.Sorted(maps.Keys(setFlags)) {
		if !frrBGPFlags[name] {
			fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -import-frr-bgp\n", name)
			return 2
		}
	}
	if manifestPath == "" {
		fmt.Fprintln(stderr, "netdoc: -import-frr-bgp needs a manifest file name")
		return 2
	}

	// The manifest and its captures are read under one root, the manifest's own
	// directory, as the OSPF import reads them.
	root, err := os.OpenRoot(filepath.Dir(manifestPath))
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	defer func() { _ = root.Close() }() // read-only root; a close error cannot affect data already read

	data, _, err := readRegularFile(root, filepath.Base(manifestPath), frrospf.MaxManifestBytes)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	manifest, err := frrospf.DecodeManifest(data)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	// A BGP import writes no topology, so the node a topology is written from has
	// no meaning here. It is refused rather than ignored.
	if manifest.SourceNode != "" {
		fmt.Fprintln(stderr, "netdoc: -import-frr-bgp refuses source_node: a BGP import writes no topology, so the manifest must not name one")
		return 2
	}
	captures, err := loadFRRCaptures(root, manifest)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	report, err := buildFRRBGPReport(manifestPath, manifest, captures)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s\n", textsafe.Clean(err.Error()))
		return 2
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(report)
	} else {
		_, err = io.WriteString(stdout, renderFRRBGPText(report))
	}
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-bgp: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	return 0
}

// frrBGPReport is the --import-frr-bgp report. Every value in it is either a
// manifest's declared claim or a value FRR printed in a capture.
type frrBGPReport struct {
	Version     int             `json:"version"`
	Protocol    string          `json:"protocol"`
	Manifest    string          `json:"manifest"`
	Captures    []frrBGPCapture `json:"captures"`
	NotRead     []string        `json:"not_read"`
	Limitations []string        `json:"limitations"`
}

// frrBGPCapture is one accepted summary capture. Declared is the manifest's claim,
// and the router ID, local AS, and peers are what the transcript reported.
type frrBGPCapture struct {
	File     string       `json:"file"`
	Declared frrDeclared  `json:"declared"`
	RouterID string       `json:"router_id"`
	LocalAS  uint32       `json:"local_as"`
	Peers    []frrBGPPeer `json:"peers"`
}

// frrBGPPeer is one session as the summary reported it, in address order.
type frrBGPPeer struct {
	Address  string `json:"address"`
	LocalAS  uint32 `json:"local_as"`
	RemoteAS uint32 `json:"remote_as"`
	State    string `json:"state"`
}

// buildFRRBGPReport checks each capture against the one command, FRR version, and
// VRF this import reads, decodes it, and returns the report. Captures keep the
// manifest's order. loadFRRCaptures returns one capture per manifest entry, in the
// same order, so entry i of each describes the same capture. A node may have one
// summary capture: two could disagree about its state, and netdoc does not choose
// between them.
func buildFRRBGPReport(manifestPath string, m frrospf.Manifest, captures []frrospf.Capture) (frrBGPReport, error) {
	r := frrBGPReport{
		Version:     frrBGPReportVersion,
		Protocol:    frrBGPProtocol,
		Manifest:    manifestPath,
		Captures:    make([]frrBGPCapture, 0, len(captures)),
		NotRead:     frrBGPNotRead,
		Limitations: frrBGPLimitations,
	}
	nodes := map[string]bool{}
	for i, c := range captures {
		mc := m.Captures[i]
		switch {
		case c.Command != frrbgp.CommandSummary:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: command %q is not read by -import-frr-bgp; only %q is", i, mc.File, c.Command, frrbgp.CommandSummary)
		case c.FRRVersion != frrbgp.Version:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: FRR version %q is not %q", i, mc.File, c.FRRVersion, frrbgp.Version)
		case c.VRF != "default":
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: VRF %q is not \"default\"", i, mc.File, c.VRF)
		case nodes[c.Node]:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: node %q has more than one summary capture", i, mc.File, c.Node)
		}
		nodes[c.Node] = true
		s, err := frrbgp.Decode(c.Data, c.Node)
		if err != nil {
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: %w", i, mc.File, err)
		}
		peers := make([]frrBGPPeer, 0, len(s.Peers))
		for _, p := range s.Peers {
			peers = append(peers, frrBGPPeer{Address: p.Address.String(), LocalAS: p.LocalAS, RemoteAS: p.RemoteAS, State: p.State})
		}
		r.Captures = append(r.Captures, frrBGPCapture{
			File: mc.File,
			Declared: frrDeclared{
				Source:      mc.Source,
				Node:        mc.Node,
				VRF:         mc.VRF,
				FRRVersion:  mc.FRRVersion,
				Command:     mc.Command,
				CollectedAt: mc.CollectedAt.Format(time.RFC3339Nano),
			},
			RouterID: s.RouterID,
			LocalAS:  s.LocalAS,
			Peers:    peers,
		})
	}
	return r, nil
}

// renderFRRBGPText is the human report. Every value from a capture or a manifest
// passes through textsafe, so a crafted name cannot write control text to the
// terminal.
func renderFRRBGPText(r frrBGPReport) string {
	clean := textsafe.Clean
	var b strings.Builder
	fmt.Fprintf(&b, "FRR BGP import: %s\n", clean(r.Manifest))
	b.WriteString("Result: valid. Every capture was read and checked. Exit 0 does not mean any session is up.\n")
	fmt.Fprintf(&b, "\nCaptures (%d)\n", len(r.Captures))
	for _, c := range r.Captures {
		fmt.Fprintf(&b, "  %s\n", clean(c.Declared.Source))
		fmt.Fprintf(&b, "    file: %s\n", clean(c.File))
		fmt.Fprintf(&b, "    declared (not verified): node %s, vrf %s, FRR %s, command %q, collected %s\n",
			clean(c.Declared.Node), clean(c.Declared.VRF), clean(c.Declared.FRRVersion), clean(c.Declared.Command), clean(c.Declared.CollectedAt))
		fmt.Fprintf(&b, "    router ID %s, local AS %d\n", clean(c.RouterID), c.LocalAS)
		if len(c.Peers) == 0 {
			b.WriteString("    peers: none; the summary reported an empty peer collection, observed empty and not down\n")
		}
		for _, p := range c.Peers {
			fmt.Fprintf(&b, "    peer %s: remote AS %d, local AS %d, state %s\n", clean(p.Address), p.RemoteAS, p.LocalAS, clean(p.State))
		}
	}
	b.WriteString("\nNot read:\n")
	for _, line := range r.NotRead {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	b.WriteString("\nLimitations:\n")
	for _, line := range r.Limitations {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	return b.String()
}
