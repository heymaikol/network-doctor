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
// The route_tables key is written only when the manifest names a route table,
// which an earlier build refused, so no report without one changes.
const frrBGPReportVersion = 1

// frrBGPProtocol names the protocol the --import-frr-bgp report describes.
const frrBGPProtocol = "bgp"

// frrBGPLearnedLimit bounds the learned routes the text report lists for one
// route table. The counts are always printed, and the JSON report keeps them all.
const frrBGPLearnedLimit = 20

// frrBGPFlags are the only settings a BGP import accepts beside its manifest.
// Every other setting describes a probe run, another reading, or the OSPF import,
// and this import would ignore it.
var frrBGPFlags = map[string]bool{"import-frr-bgp": true, "json": true}

// frrBGPNotRead says what the BGP import does not read. A reader checks it before
// they treat the report as the whole picture. A report with route tables reads
// frrBGPNotReadRoutes instead.
var frrBGPNotRead = []string{
	"routes and prefixes: not read; the summary carries none, so no route is claimed",
	"routing table, FIB, and kernel installation: not read",
	"nodes and peers that no capture names: unknown, not down",
	"session state after its collection time: not observed",
}

// frrBGPNotReadRoutes says what the BGP import does not read when the report
// carries route tables. It replaces frrBGPNotRead for such a report only.
var frrBGPNotReadRoutes = []string{
	"routes: read only from the show ip bgp json captures named; a node with no such capture has its routes not read, which is not the same as having none, and a missing capture does not show that a route was withdrawn",
	"summary prefix counters (pfxRcd): not read; they identify no route",
	"paths with no peer recorded (peerId absent, \"(unspec)\", or an unspecified address): counted, never reported as learned",
	"best path, multipath, and the valid, bestpath, used, and selectionReason fields: not read; a learned route is one FRR listed, not the path it selected",
	"kernel routing table, FIB, and installation: not read; a learned route is FRR's BGP table, not an installed route",
	"nodes and peers that no capture names: unknown, not down",
	"session state after its collection time: not observed",
}

// frrBGPLimitations says what the BGP import result does not establish.
var frrBGPLimitations = []string{
	"declared metadata (source, node, VRF, FRR version, command, collection time) is the manifest's claim; netdoc checks the FRR version, the command, the VRF, and that the transcript prompt names the declared node, but cannot verify which router produced a capture",
	"each state is the JSON state field FRR printed at collection; peerState is not read",
	"the observed family names the summary section FRR printed; it does not establish which address families any session negotiated",
	"exit 0 means every capture is valid; it does not mean any session is Established or that the network is healthy",
	"an empty peer collection is observed empty; it is not reported as a down session",
}

// frrBGPRouteLimitations adds to frrBGPLimitations when the report carries route
// tables.
var frrBGPRouteLimitations = []string{
	"a learned route names the peer FRR recorded at the table's collection time; the table does not show that the session was Established",
	"route tables and summaries are separate commands with their own collection times; netdoc does not check that they describe one moment",
	"the BGP origin names no protocol, so the protocol that first carried a route is not identified beyond FRR's BGP table",
	"pathFrom is the label FRR printed for the path; it is not checked against the session type",
	"an empty table is observed empty at collection time; neither it nor a missing capture shows that a route was withdrawn",
}

// runFRRBGPImport reads the FRR BGP captures a manifest names and reports each
// router's ID, local AS, and peer sessions as FRR printed them, and the learned
// routes of each route table. It runs no probe and contacts no router. It exits 0
// when every capture is valid and 2 when the manifest, a capture, or the output
// cannot be used. It writes no topology.
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
// manifest's declared claim, a value FRR printed in a capture, or a label for
// the section FRR printed.
type frrBGPReport struct {
	Version     int                `json:"version"`
	Protocol    string             `json:"protocol"`
	Manifest    string             `json:"manifest"`
	Captures    []frrBGPCapture    `json:"captures"`
	RouteTables []frrBGPRouteTable `json:"route_tables,omitempty"`
	NotRead     []string           `json:"not_read"`
	Limitations []string           `json:"limitations"`
}

// frrBGPCapture is one accepted summary capture. Declared is the manifest's claim.
// Family names the summary section the transcript was read from, and the router
// ID, local AS, and peers are what the transcript reported.
type frrBGPCapture struct {
	File     string       `json:"file"`
	Declared frrDeclared  `json:"declared"`
	Family   string       `json:"observed_family"`
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

// frrBGPRouteTable is one accepted show ip bgp json capture. Declared is the
// manifest's claim. The identity fields are what the table printed, and a field
// the table did not print is left out. Learned lists each path whose peerId names
// a peer, in the order FRR printed them.
type frrBGPRouteTable struct {
	File         string               `json:"file"`
	Declared     frrDeclared          `json:"declared"`
	Protocol     string               `json:"protocol"`
	RouterID     string               `json:"router_id,omitempty"`
	LocalAS      uint32               `json:"local_as,omitempty"`
	VRFName      string               `json:"vrf_name,omitempty"`
	Prefixes     int                  `json:"prefixes"`
	NoPeerPaths  int                  `json:"no_peer_paths"`
	UnknownPaths int                  `json:"unknown_peer_paths"`
	Learned      []frrBGPLearnedRoute `json:"learned_routes"`
}

// frrBGPLearnedRoute is one path FRR listed for a prefix, whose peerId names a
// peer. Its fields are the values the table printed for that path. BGPOrigin is
// the BGP ORIGIN attribute, which names no protocol.
type frrBGPLearnedRoute struct {
	Prefix    string   `json:"prefix"`
	Peer      string   `json:"peer"`
	PathFrom  string   `json:"path_from"`
	ASPath    string   `json:"as_path"`
	BGPOrigin string   `json:"bgp_origin"`
	NextHops  []string `json:"next_hops"`
}

// buildFRRBGPReport checks each capture against the command, FRR version, and VRF
// this import reads, decodes it, and returns the report. Captures and route tables
// each keep the manifest's order. loadFRRCaptures returns one capture per manifest
// entry, in the same order, so entry i of each describes the same capture. A node
// may have one summary capture and one route table: two of either could disagree
// about its state, and netdoc does not choose between them. A route table must
// agree with the summary of its node on the router ID and local AS, since both
// name the same router.
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
	summaries := map[string]frrbgp.Summary{}
	var tables []int
	for i, c := range captures {
		mc := m.Captures[i]
		if c.Command == frrbgp.CommandRoute {
			tables = append(tables, i)
			continue
		}
		switch {
		case c.Command != frrbgp.CommandSummary:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: command %q is not read by -import-frr-bgp; only %q and %q are", i, mc.File, c.Command, frrbgp.CommandSummary, frrbgp.CommandRoute)
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
		summaries[c.Node] = s
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
			Family:   frrbgp.Family,
			RouterID: s.RouterID,
			LocalAS:  s.LocalAS,
			Peers:    peers,
		})
	}

	// Route tables are checked after every summary, since a table is compared with
	// the summary of its node, and the manifest may name the table first.
	routeNodes := map[string]bool{}
	for _, i := range tables {
		c, mc := captures[i], m.Captures[i]
		switch {
		case c.FRRVersion != frrbgp.Version:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: FRR version %q is not %q", i, mc.File, c.FRRVersion, frrbgp.Version)
		case c.VRF != "default":
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: VRF %q is not \"default\"", i, mc.File, c.VRF)
		case routeNodes[c.Node]:
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: node %q has more than one route table", i, mc.File, c.Node)
		}
		routeNodes[c.Node] = true
		table, err := frrbgp.DecodeRouteCapture(c.Data, c.Node)
		if err != nil {
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: %w", i, mc.File, err)
		}
		if table.VRFName != "" && table.VRFName != "default" {
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: vrfName %q is not \"default\"", i, mc.File, table.VRFName)
		}
		if s, ok := summaries[c.Node]; ok && ((table.RouterID != "" && table.RouterID != s.RouterID) || (table.LocalAS != 0 && table.LocalAS != s.LocalAS)) {
			return frrBGPReport{}, fmt.Errorf("captures[%d] %s: the route table of node %q names router ID %q and local AS %d, but its summary names %q and %d", i, mc.File, c.Node, table.RouterID, table.LocalAS, s.RouterID, s.LocalAS)
		}
		r.RouteTables = append(r.RouteTables, frrBGPRouteTableOf(mc, table))
	}
	if len(r.RouteTables) > 0 {
		r.NotRead = frrBGPNotReadRoutes
		r.Limitations = slices.Concat(frrBGPLimitations, frrBGPRouteLimitations)
	}
	return r, nil
}

// frrBGPRouteTableOf reports one accepted route table. A path is listed as learned
// only when its peerId names a peer. A path with no peer recorded, or with no peer
// ID that names one, is counted and never listed as learned.
func frrBGPRouteTableOf(mc frrospf.ManifestCapture, t frrbgp.RouteTable) frrBGPRouteTable {
	rt := frrBGPRouteTable{
		File: mc.File,
		Declared: frrDeclared{
			Source:      mc.Source,
			Node:        mc.Node,
			VRF:         mc.VRF,
			FRRVersion:  mc.FRRVersion,
			Command:     mc.Command,
			CollectedAt: mc.CollectedAt.Format(time.RFC3339Nano),
		},
		Protocol: frrBGPProtocol,
		RouterID: t.RouterID,
		LocalAS:  t.LocalAS,
		VRFName:  t.VRFName,
		Prefixes: len(t.Routes),
		Learned:  []frrBGPLearnedRoute{},
	}
	for _, entry := range t.Routes {
		for _, p := range entry.Paths {
			switch p.Source {
			case frrbgp.RouteSourceLearned:
				hops := make([]string, 0, len(p.NextHops))
				for _, hop := range p.NextHops {
					hops = append(hops, hop.String())
				}
				rt.Learned = append(rt.Learned, frrBGPLearnedRoute{
					Prefix:    entry.Prefix.String(),
					Peer:      p.Peer.String(),
					PathFrom:  p.PathFrom,
					ASPath:    p.ASPath,
					BGPOrigin: p.Origin,
					NextHops:  hops,
				})
			case frrbgp.RouteSourceNoPeer:
				rt.NoPeerPaths++
			case frrbgp.RouteSourceUnknown:
				rt.UnknownPaths++
			}
		}
	}
	return rt
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
		fmt.Fprintf(&b, "    observed family: %s (summary section %s); no peer's negotiated families are read\n", c.Family, frrbgp.Section)
		if len(c.Peers) == 0 {
			b.WriteString("    peers: none; the summary reported an empty peer collection, observed empty and not down\n")
		}
		for _, p := range c.Peers {
			fmt.Fprintf(&b, "    peer %s: remote AS %d, local AS %d, state %s\n", clean(p.Address), p.RemoteAS, p.LocalAS, clean(p.State))
		}
	}
	if len(r.RouteTables) > 0 {
		fmt.Fprintf(&b, "\nRoute tables (%d)\n", len(r.RouteTables))
		b.WriteString("  FRR's BGP table, not the zebra RIB or the kernel FIB. Paths keep FRR's order, which is not a preference.\n")
		for _, t := range r.RouteTables {
			renderFRRBGPRouteTable(&b, t)
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

// renderFRRBGPRouteTable writes one route table: what its manifest declares, what
// it printed, how its paths were classified, and each learned route up to the
// text limit.
func renderFRRBGPRouteTable(b *strings.Builder, t frrBGPRouteTable) {
	clean := textsafe.Clean
	fmt.Fprintf(b, "  %s\n", clean(t.Declared.Source))
	fmt.Fprintf(b, "    file: %s\n", clean(t.File))
	fmt.Fprintf(b, "    declared (not verified): node %s, vrf %s, FRR %s, command %q, collected %s\n",
		clean(t.Declared.Node), clean(t.Declared.VRF), clean(t.Declared.FRRVersion), clean(t.Declared.Command), clean(t.Declared.CollectedAt))
	routerID, localAS, vrf := "not printed", "not printed", "not printed"
	if t.RouterID != "" {
		routerID = clean(t.RouterID)
	}
	if t.LocalAS != 0 {
		localAS = fmt.Sprint(t.LocalAS)
	}
	if t.VRFName != "" {
		vrf = clean(t.VRFName)
	}
	fmt.Fprintf(b, "    printed by FRR: router ID %s, local AS %s, VRF %s\n", routerID, localAS, vrf)
	fmt.Fprintf(b, "    prefixes: %d; learned paths: %d; not learned: %d with peerId (unspec), %d with no peer ID naming a peer\n",
		t.Prefixes, len(t.Learned), t.NoPeerPaths, t.UnknownPaths)
	switch {
	case t.Prefixes == 0:
		b.WriteString("    table holds no prefixes: observed empty at collection time; this is not a withdrawal\n")
	case len(t.Learned) == 0:
		b.WriteString("    no path names a peer, so no route is reported as learned\n")
	}
	for i, l := range t.Learned {
		if i == frrBGPLearnedLimit {
			fmt.Fprintf(b, "    ... %d more learned routes; see --json\n", len(t.Learned)-i)
			break
		}
		path := clean(l.ASPath)
		if path == "" {
			path = "(empty)"
		}
		hops := strings.Join(l.NextHops, ", ")
		if hops == "" {
			hops = "none"
		}
		fmt.Fprintf(b, "    learned route %s from peer %s: path from %s, AS path %s, BGP origin %s, next hops %s\n",
			clean(l.Prefix), clean(l.Peer), clean(l.PathFrom), path, clean(l.BGPOrigin), hops)
	}
}
