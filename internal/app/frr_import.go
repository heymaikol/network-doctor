package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/frrospf"
	"github.com/heymaikol/network-doctor/internal/netmodel"
	"github.com/heymaikol/network-doctor/internal/ospf"
	"github.com/heymaikol/network-doctor/internal/routepath"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// frrAggregateLimit bounds all capture files of one import together. Each file
// is also bounded by frrospf.MaxCaptureBytes.
const frrAggregateLimit = 32 << 20

// frrReportVersion is the version of the --import-frr-ospf JSON report. A change
// to a field name or meaning raises it.
const frrReportVersion = 1

// frrImportFlags are the only settings an import accepts beside its manifest.
// Every other setting describes a probe run, another reading, or a finished run,
// and the import would ignore it.
var frrImportFlags = map[string]bool{"import-frr-ospf": true, "write-topology": true, "json": true}

// The link-state database line of frrNotImported. It changes only when the
// report carries the ospf_lsdb section, so a report without one reads as before.
const (
	frrLSDBNotRead = "the OSPF link-state database: not read"
	frrLSDBRead    = "the OSPF link-state database: read for the ospf_lsdb section only; not written to the topology"
)

// frrNotImported says what the import reads and does not carry into the
// topology. A reader checks it before they treat the topology as the whole
// network.
var frrNotImported = []string{
	"routes: the RIB and FIB are not read, so the topology has no routes",
	frrLSDBNotRead,
	"OSPF area of a neighbor record: reported, not written to the topology",
	"OSPF area of an interface: a plain dotted area is written as ospf.effective_area, one value per interface name; a qualified, incomplete, or missing area, or one that a neighbor contradicts, is not written",
	"secondary interface addresses: not read; only the primary address is used",
	"any other FRR output field: not read",
	"source address: not set, so the topology claims no address for the source node",
	"checks and boundaries: none written; OSPF output does not supply them",
}

// notImported returns frrNotImported, with the link-state database line changed
// when the import read the LSDB captures. The shared list is never changed.
func notImported(lsdb bool) []string {
	if !lsdb {
		return frrNotImported
	}
	out := slices.Clone(frrNotImported)
	for i, line := range out {
		if line == frrLSDBNotRead {
			out[i] = frrLSDBRead
		}
	}
	return out
}

// frrLimitations says what the import result does not establish.
var frrLimitations = []string{
	"declared metadata (source, node, VRF, FRR version, command, collection time) is the manifest's claim; netdoc checks the FRR version, the command, and the VRF it reads, but not which node produced a capture",
	"neighbors and routes are not claimed complete; the topology says so explicitly",
	"exit 0 means every capture was accepted and every neighbor record was mapped; it does not mean the network is healthy or that OSPF is complete on every node",
	"a neighbor record with no router ID (noNbrID) is never mapped, even when its address is unique",
	"an interface's ospf.effective_area is the one area FRR printed for that interface name; it is not a list of every area the interface runs OSPF in, and it may differ from the area of an adjacency on the same interface",
}

// runFRRImport imports offline FRR OSPF captures named by a manifest. It runs no
// probe and contacts no router, so no probe setting applies. It exits 0 when
// every capture is accepted and every neighbor record is mapped, 1 when one is
// not, and 2 when its input or output cannot be used. A topology is written only
// when the import is complete, so a partial import never leaves a file behind.
func runFRRImport(setFlags map[string]bool, manifestPath, topologyPath string, jsonOut bool, stdout, stderr io.Writer) int {
	for _, name := range slices.Sorted(maps.Keys(setFlags)) {
		if !frrImportFlags[name] {
			fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -import-frr-ospf\n", name)
			return 2
		}
	}
	if setFlags["write-topology"] && !setFlags["import-frr-ospf"] {
		fmt.Fprintln(stderr, "netdoc: -write-topology needs -import-frr-ospf")
		return 2
	}
	if manifestPath == "" {
		fmt.Fprintln(stderr, "netdoc: -import-frr-ospf needs a manifest file name")
		return 2
	}
	writing := setFlags["write-topology"]
	if writing {
		if topologyPath == "" {
			fmt.Fprintln(stderr, "netdoc: -write-topology needs a file name")
			return 2
		}
		if err := checkTopologyTarget(topologyPath); err != nil {
			fmt.Fprintf(stderr, "netdoc: -write-topology: %s\n", textsafe.Clean(err.Error()))
			return 2
		}
	}

	// The manifest and its captures are read under one root, the manifest's own
	// directory. A capture path that climbs out of it is refused when it is
	// opened, and the manifest decoder has already refused it as text.
	root, err := os.OpenRoot(filepath.Dir(manifestPath))
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-ospf: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	defer func() { _ = root.Close() }() // read-only root; a close error cannot affect data already read

	data, _, err := readRegularFile(root, filepath.Base(manifestPath), frrospf.MaxManifestBytes)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-ospf: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	manifest, err := frrospf.DecodeManifest(data)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-ospf: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	if writing && manifest.SourceNode == "" {
		fmt.Fprintln(stderr, "netdoc: -write-topology needs source_node in the manifest: it names the node the topology is written from")
		return 2
	}
	if writing && !hasDefaultInterfaceCapture(manifest, manifest.SourceNode) {
		fmt.Fprintf(stderr, "netdoc: -write-topology: source_node %s has no default-VRF interface capture in the manifest\n", textsafe.Clean(manifest.SourceNode))
		return 2
	}

	captures, err := loadFRRCaptures(root, manifest)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-ospf: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	result, err := frrospf.Import(captures)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-frr-ospf: %s\n", textsafe.Clean(err.Error()))
		return 2
	}

	report := buildFRRReport(manifestPath, manifest, result)
	code := 0
	switch {
	case !report.Complete:
		code = 1
		if writing {
			report.Topology.Reason = "not written: the import is incomplete"
		}
	case writing:
		if err := writeFRRTopology(manifest.SourceNode, result, topologyPath); err != nil {
			fmt.Fprintf(stderr, "netdoc: -write-topology: %s\n", textsafe.Clean(err.Error()))
			report.Topology.Reason = "not written: " + err.Error()
			code = 2
		} else {
			report.Topology.Written = true
		}
	}
	report.Topology.Requested = writing
	if writing {
		report.Topology.Path = topologyPath
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	} else {
		fmt.Fprint(stdout, renderFRRText(report))
	}
	return code
}

// hasDefaultInterfaceCapture reports whether the manifest declares an interface
// capture for node in the default VRF. The importer decides whether that capture
// is accepted, and an unaccepted one makes the import incomplete.
func hasDefaultInterfaceCapture(m frrospf.Manifest, node string) bool {
	return slices.ContainsFunc(m.Captures, func(c frrospf.ManifestCapture) bool {
		return c.Node == node && c.VRF == "default" && c.Command == frrospf.CommandInterface
	})
}

// loadFRRCaptures reads every capture file the manifest names. No two may be the
// same file, so a hard link cannot count one capture twice, and the captures
// together stay within frrAggregateLimit.
func loadFRRCaptures(root *os.Root, m frrospf.Manifest) ([]frrospf.Capture, error) {
	var captures []frrospf.Capture
	var infos []os.FileInfo
	var total int64
	for i, mc := range m.Captures {
		data, info, err := readRegularFile(root, mc.File, frrospf.MaxCaptureBytes)
		if err != nil {
			return nil, fmt.Errorf("captures[%d] %s: %w", i, mc.File, err)
		}
		total += int64(len(data))
		if total > frrAggregateLimit {
			return nil, fmt.Errorf("the captures together are larger than %d bytes", frrAggregateLimit)
		}
		for j, prior := range infos {
			if os.SameFile(prior, info) {
				return nil, fmt.Errorf("captures[%d] and captures[%d] are the same file", j, i)
			}
		}
		infos = append(infos, info)
		captures = append(captures, frrospf.Capture{
			Node:        mc.Node,
			VRF:         mc.VRF,
			Source:      mc.Source,
			CollectedAt: mc.CollectedAt,
			FRRVersion:  mc.FRRVersion,
			Command:     mc.Command,
			Data:        data,
		})
	}
	return captures, nil
}

// readRegularFile reads the regular file name under root, up to limit bytes.
// Lstat refuses a symbolic link and every other non-regular entry before the
// file is opened. The opened handle must also be regular, and the read stops one
// byte past the limit so an oversized file is refused without being read whole.
// The Lstat and the open are two steps, so a local process that swaps the file
// between them is not stopped; the handle check only confirms the file that was
// opened is regular.
func readRegularFile(root *os.Root, name string, limit int64) ([]byte, os.FileInfo, error) {
	st, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, errors.New("is a symbolic link; name the file itself")
	}
	if !st.Mode().IsRegular() {
		return nil, nil, errors.New("is not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close() // #nosec G104 -- read-only handle; a close error cannot affect data already read
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, nil, errors.New("is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return nil, nil, fmt.Errorf("is larger than %d bytes", limit)
	}
	return data, opened, nil
}

// writeFRRTopology encodes a complete import as a topology file and publishes
// it. Encode refuses anything the topology format cannot carry, and it confirms
// the bytes read back as the same evidence before they are returned.
func writeFRRTopology(sourceNode string, result frrospf.Result, path string) error {
	model, err := netmodel.New(result.Observations...)
	if err != nil {
		return err
	}
	data, err := routepath.Encode(routepath.File{
		Source: routepath.Start{Node: sourceNode, VRF: "default"},
		Model:  model,
	})
	if err != nil {
		return err
	}
	return publishFRRTopology(path, data)
}

// linkFile gives a finished temporary file its final name. A hard link fails
// when the name exists, so nothing is replaced. It is a variable so a test can
// refuse the link the way a filesystem without hard links does.
var linkFile = os.Link

// checkTopologyTarget refuses a topology path that cannot be published. Its
// directory must exist, and nothing may already be at the path. Lstat counts a
// dangling symbolic link as present, so one is refused too.
func checkTopologyTarget(path string) error {
	dir := filepath.Dir(path)
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; netdoc does not overwrite it", path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// publishFRRTopology writes data through a temporary file in the target's
// directory, then hard-links it to the target name. The final name never holds a
// partial file, and nothing replaces an existing one. There is no fallback when
// hard links are unavailable: the temporary file is removed and the error is
// returned. The file is not fsynced, as the snapshot writer does not fsync.
func publishFRRTopology(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".netdoc-topology-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // removing the temporary name is cleanup; the link is the result
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return err
	}
	if err := linkFile(name, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; nothing was written", path)
		}
		return fmt.Errorf("cannot publish %s without overwriting it: %w; hard links may be unsupported on this filesystem (FAT, SMB, and some network filesystems)", path, err)
	}
	return nil
}

// frrReport accounts for every capture and every neighbor record of one import.
// Declared fields are the manifest's claims. The fields after them are what the
// importer checked and wrote.
type frrReport struct {
	Version           int              `json:"version"`
	Manifest          string           `json:"manifest"`
	Complete          bool             `json:"complete"`
	SourceNode        string           `json:"source_node,omitempty"`
	NeighborsComplete bool             `json:"neighbors_complete"`
	RoutesComplete    bool             `json:"routes_complete"`
	Counts            frrCounts        `json:"counts"`
	Captures          []frrCapture     `json:"captures"`
	Records           []frrRecord      `json:"records"`
	OSPFLSDB          *ospf.LSDBReport `json:"ospf_lsdb,omitempty"`
	NotImported       []string         `json:"not_imported"`
	Limitations       []string         `json:"limitations"`
	Topology          frrTopology      `json:"topology"`
}

type frrCounts struct {
	Captures int `json:"captures"`
	Accepted int `json:"accepted"`
	Refused  int `json:"refused"`
	Records  int `json:"records"`
	Mapped   int `json:"mapped"`
	Unmapped int `json:"unmapped"`
}

type frrCapture struct {
	File       string      `json:"file"`
	Declared   frrDeclared `json:"declared"`
	Accepted   bool        `json:"accepted"`
	Reason     string      `json:"reason,omitempty"`
	Empty      bool        `json:"empty"`
	Interfaces int         `json:"interfaces"`
	Neighbors  int         `json:"neighbors"`
	Notes      []string    `json:"notes,omitempty"`
}

type frrDeclared struct {
	Source      string `json:"source"`
	Node        string `json:"node"`
	VRF         string `json:"vrf"`
	FRRVersion  string `json:"frr_version"`
	Command     string `json:"command"`
	CollectedAt string `json:"collected_at"`
}

type frrRecord struct {
	Source          string `json:"source"`
	Node            string `json:"node"`
	VRF             string `json:"vrf"`
	LocalInterface  string `json:"local_interface"`
	NeighborAddress string `json:"neighbor_address"`
	RouterID        string `json:"router_id,omitempty"`
	State           string `json:"state"`
	Area            string `json:"area"`
	Mapped          bool   `json:"mapped"`
	RemoteNode      string `json:"remote_node,omitempty"`
	RemoteInterface string `json:"remote_interface,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type frrTopology struct {
	Requested bool   `json:"requested"`
	Path      string `json:"path,omitempty"`
	Written   bool   `json:"written"`
	Reason    string `json:"reason,omitempty"`
}

// buildFRRReport turns an import result into the report. Captures follow the
// manifest's order, since that is the order a person wrote and reads. Import
// returns exactly one capture report per capture, matched here by source label,
// which the manifest decoder keeps unique.
func buildFRRReport(manifestPath string, m frrospf.Manifest, res frrospf.Result) frrReport {
	reports := map[string]frrospf.CaptureReport{}
	for _, cr := range res.Report.Captures {
		reports[cr.Source] = cr
	}
	r := frrReport{
		Version:           frrReportVersion,
		Manifest:          manifestPath,
		SourceNode:        m.SourceNode,
		NeighborsComplete: false,
		RoutesComplete:    false,
		OSPFLSDB:          res.LSDB,
		NotImported:       notImported(res.LSDB != nil),
		Limitations:       frrLimitations,
	}
	for _, mc := range m.Captures {
		cr := reports[mc.Source]
		r.Captures = append(r.Captures, frrCapture{
			File: mc.File,
			Declared: frrDeclared{
				Source:      mc.Source,
				Node:        mc.Node,
				VRF:         mc.VRF,
				FRRVersion:  mc.FRRVersion,
				Command:     mc.Command,
				CollectedAt: mc.CollectedAt.Format(time.RFC3339Nano),
			},
			Accepted:   cr.Accepted,
			Reason:     cr.Reason,
			Empty:      cr.Empty,
			Interfaces: cr.Interfaces,
			Neighbors:  cr.Neighbors,
			Notes:      cr.Notes,
		})
		r.Counts.Captures++
		if cr.Accepted {
			r.Counts.Accepted++
		} else {
			r.Counts.Refused++
		}
	}
	for _, rec := range res.Report.Records {
		r.Records = append(r.Records, frrRecord{
			Source:          rec.Source,
			Node:            rec.Node,
			VRF:             rec.VRF,
			LocalInterface:  rec.LocalInterface,
			NeighborAddress: rec.NeighborAddr,
			RouterID:        rec.RouterID,
			State:           rec.State,
			Area:            rec.Area,
			Mapped:          rec.Mapped,
			RemoteNode:      rec.RemoteNode,
			RemoteInterface: rec.RemoteInterface,
			Reason:          rec.Reason,
		})
		r.Counts.Records++
		if rec.Mapped {
			r.Counts.Mapped++
		} else {
			r.Counts.Unmapped++
		}
	}
	r.Complete = r.Counts.Refused == 0 && r.Counts.Unmapped == 0
	return r
}

// renderLSDB writes the OSPF LSDB comparison. Each node shows its guard, and each
// finding shows what the captures show beside the limit of that reading.
func renderLSDB(b *strings.Builder, rep *ospf.LSDBReport) {
	clean := textsafe.Clean
	b.WriteString("\nOSPF LSDB comparison:\n")
	for _, n := range rep.Nodes {
		if n.Guard.Passed {
			fmt.Fprintf(b, "  node %s vrf %s: guard passed\n", clean(n.Node), clean(n.VRF))
		} else {
			fmt.Fprintf(b, "  node %s vrf %s: guard failed: %s\n", clean(n.Node), clean(n.VRF), clean(strings.Join(n.Guard.Reasons, "; ")))
		}
		if len(n.Findings) == 0 {
			b.WriteString("    no finding\n")
		}
		for _, f := range n.Findings {
			fmt.Fprintf(b, "    %s (%s): %s\n", f.Kind, f.Strength, clean(f.Detail))
			fmt.Fprintf(b, "      limit: %s\n", f.Limit)
		}
	}
	b.WriteString("  limitations:\n")
	for _, line := range rep.Limitations {
		fmt.Fprintf(b, "    %s\n", line)
	}
}

// renderFRRText is the human report. Every value from a capture or a manifest
// passes through textsafe, so a crafted name cannot write control text to the
// terminal.
func renderFRRText(r frrReport) string {
	clean := textsafe.Clean
	var b strings.Builder
	fmt.Fprintf(&b, "FRR OSPF import: %s\n", clean(r.Manifest))
	if r.Complete {
		b.WriteString("Result: complete. Every capture was accepted and every neighbor record was mapped.\n")
		b.WriteString("Exit 0 means the import is complete. It does not mean the network is healthy.\n")
	} else {
		fmt.Fprintf(&b, "Result: incomplete. %d of %d captures refused; %d of %d neighbor records unmapped.\n",
			r.Counts.Refused, r.Counts.Captures, r.Counts.Unmapped, r.Counts.Records)
	}
	fmt.Fprintf(&b, "\nCaptures (%d): %d accepted, %d refused\n", r.Counts.Captures, r.Counts.Accepted, r.Counts.Refused)
	for _, c := range r.Captures {
		fmt.Fprintf(&b, "  %s\n", clean(c.Declared.Source))
		fmt.Fprintf(&b, "    file: %s\n", clean(c.File))
		fmt.Fprintf(&b, "    declared (not verified): node %s, vrf %s, FRR %s, command %q, collected %s\n",
			clean(c.Declared.Node), clean(c.Declared.VRF), clean(c.Declared.FRRVersion), clean(c.Declared.Command), clean(c.Declared.CollectedAt))
		if c.Accepted {
			fmt.Fprintf(&b, "    checked: accepted, %d interfaces, %d neighbors", c.Interfaces, c.Neighbors)
			if c.Empty {
				b.WriteString(" (empty)")
			}
			b.WriteString("\n")
		} else {
			fmt.Fprintf(&b, "    checked: refused: %s\n", clean(c.Reason))
		}
		for _, note := range c.Notes {
			fmt.Fprintf(&b, "    note: %s\n", clean(note))
		}
	}
	fmt.Fprintf(&b, "\nNeighbor records (%d): %d mapped, %d unmapped\n", r.Counts.Records, r.Counts.Mapped, r.Counts.Unmapped)
	for _, rec := range r.Records {
		if rec.Mapped {
			fmt.Fprintf(&b, "  mapped    %s %s %s state %s area %s router-id %s -> %s %s\n",
				clean(rec.Node), clean(rec.LocalInterface), clean(rec.NeighborAddress), clean(rec.State), clean(rec.Area),
				clean(rec.RouterID), clean(rec.RemoteNode), clean(rec.RemoteInterface))
		} else {
			fmt.Fprintf(&b, "  unmapped  %s %s %s state %s area %s router-id %s: %s\n",
				clean(rec.Node), clean(rec.LocalInterface), clean(rec.NeighborAddress), clean(rec.State), clean(rec.Area),
				clean(rec.RouterID), clean(rec.Reason))
		}
	}
	if r.OSPFLSDB != nil {
		renderLSDB(&b, r.OSPFLSDB)
	}
	b.WriteString("\nNot imported:\n")
	for _, line := range r.NotImported {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	b.WriteString("\nLimitations:\n")
	for _, line := range r.Limitations {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	switch {
	case r.Topology.Written:
		fmt.Fprintf(&b, "\nTopology: written to %s\n", clean(r.Topology.Path))
	case r.Topology.Requested:
		fmt.Fprintf(&b, "\nTopology: %s\n", clean(r.Topology.Reason))
	}
	return b.String()
}
