package app

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/frrospf"
	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"github.com/heymaikol/network-doctor/v2/internal/routepath"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// tunnelManifestVersion is the manifest format --import-tunnels reads. It is
// separate from the FRR manifest version, so the two can change independently.
const tunnelManifestVersion = 1

// tunnelReportVersion is the version of the --import-tunnels JSON report. A
// change to a field name or meaning raises it.
const tunnelReportVersion = 1

// tunnelManifestLimit bounds the manifest, which is read whole before it is parsed.
const tunnelManifestLimit = 1 << 20

// tunnelImportFlags are the only settings --import-tunnels accepts beside its
// manifest. Every other setting describes a probe run or another reading.
var tunnelImportFlags = map[string]bool{"import-tunnels": true, "write-topology": true, "json": true}

// tunnelNotImported says what the tunnel import reads and does not carry. A
// reader checks it before they treat the topology as the whole network.
var tunnelNotImported = []string{
	"base topology: kept as it is; the import adds tunnel records to it and changes nothing else",
	"routes: the route captures are read only to show whether a route names a kernel fallback device; no route is written to the topology",
	"policy rules: the IPv4 rules are read only to prove they are the kernel default set; any other rule, a second rules capture, or a missing one refuses every gre device of its node and each kernel fallback gre0, gretap0, erspan0, or tunl0 of it, since a record or an inert fallback needs those rules; a gretap, erspan, or ipip device that is not an inert fallback is refused by its kind whatever its rules, though a rules problem may be added to that reason; IPv6 rules are not read, since a gre device's outer packet is IPv4; a WireGuard record needs the same default rules, and an IPv6 WireGuard endpoint is refused because its rules are not read",
	"ipip devices: refused, since no ipip underlay has been validated live, except the kernel fallback tunl0 when its captures show it inert",
	"WireGuard: an endpoint is recorded only when one ip -j route get capture of it shows a single unicast route out of the main table, through an underlay device in the default domain that is neither the tunnel itself nor a VRF, under the kernel default IPv4 rules and with no fwmark; an endpoint with no such capture is reported as unproven; an IPv6 endpoint, and any route get capture that is malformed, duplicated, or not used, is refused",
	"devices of a kind the import does not read: refused by kind, never skipped and never read from their names, except a kernel fallback that its captures show inert",
	"keys: never kept; no key reaches the report, the topology, or an error",
}

// tunnelLimitations says what a complete import does not establish.
var tunnelLimitations = []string{
	"complete means every modeled node has a usable ip -d -j link capture, and no candidate was refused or left unproven",
	"a gre device is recorded only in the default routing domain, with no fwmark, under the kernel default IPv4 rules; a record names the underlay device's own domain, not a route the kernel chose",
	"the kernel creates fallback tunnel devices (gre0, gretap0, erspan0, tunl0) once their modules load; the lab saw them in every fresh network namespace, and real hosts were not tested; a fallback is listed inert only when its captures show it down, unaddressed, unrouted, and unsteered, and any other fallback is refused, so the import is incomplete and --write-topology writes no file",
	"a fallback's captures must be collected within 250 ms of one another; that narrows the window in which a change could go unseen, but the captures are not one atomic snapshot, so a change inside the window is not excluded",
	"a WireGuard record rests on four captures, the device list, the dump, the endpoint lookup, and the rules, each reported with its own source and time; the lookup is one recorded decision, and a later routing change is not excluded",
	"the captures are one recorded moment; netdoc does not check them against a live device",
}

// runTunnelImport imports the tunnel captures a manifest names onto the base
// topology the manifest names. It runs no probe and contacts no device, so no
// probe setting applies. It exits 0 when every modeled node has a usable capture
// and no candidate was refused or left unproven, 1 when one of those is not so, and
// 2 when its input or output cannot be used. A
// topology is written only when the import is complete, so a partial import
// never leaves a file behind.
func runTunnelImport(setFlags map[string]bool, manifestPath, topologyPath string, jsonOut bool, stdout, stderr io.Writer) int {
	for _, name := range slices.Sorted(maps.Keys(setFlags)) {
		if !tunnelImportFlags[name] {
			fmt.Fprintf(stderr, "netdoc: -%s cannot be combined with -import-tunnels\n", name)
			return 2
		}
	}
	if manifestPath == "" {
		fmt.Fprintln(stderr, "netdoc: -import-tunnels needs a manifest file name")
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

	// The manifest, the base topology, and every capture are read under one root,
	// the manifest's own directory, so a path that climbs out of it is refused.
	root, err := os.OpenRoot(filepath.Dir(manifestPath))
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	defer func() { _ = root.Close() }() // read-only root; a close error cannot affect data already read

	data, _, err := readRegularFile(root, filepath.Base(manifestPath), tunnelManifestLimit)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	manifest, err := decodeTunnelManifest(data)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: %s: %s\n", textsafe.Clean(manifestPath), textsafe.Clean(err.Error()))
		return 2
	}
	baseData, _, err := readRegularFile(root, manifest.Topology, routepath.MaxFileBytes)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: base topology %s: %s\n", textsafe.Clean(manifest.Topology), textsafe.Clean(err.Error()))
		return 2
	}
	base, err := routepath.Decode(baseData)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: base topology %s: %s\n", textsafe.Clean(manifest.Topology), textsafe.Clean(err.Error()))
		return 2
	}
	captures, err := loadTunnelCaptures(root, manifest)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	imp, err := routepath.ImportTunnels(base.Model, captures)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -import-tunnels: %s\n", textsafe.Clean(err.Error()))
		return 2
	}

	report := buildTunnelReport(manifestPath, manifest, imp)
	code := 0
	switch {
	case !report.Complete:
		code = 1
		if writing {
			report.Topology.Reason = "not written: the import is incomplete"
		}
	case writing:
		if err := writeTunnelTopology(base, imp, topologyPath); err != nil {
			fmt.Fprintf(stderr, "netdoc: -write-topology: %s\n", textsafe.Clean(err.Error()))
			report.Topology.Reason = "not written: " + textsafe.Clean(err.Error())
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
		fmt.Fprint(stdout, renderTunnelText(report))
	}
	return code
}

// writeTunnelTopology merges a complete import into the base topology and
// publishes the result. Encode reads its own bytes back before they are returned.
func writeTunnelTopology(base routepath.File, imp routepath.TunnelImport, path string) error {
	merged, err := routepath.MergeTunnelImport(base, imp)
	if err != nil {
		return err
	}
	data, err := routepath.Encode(merged)
	if err != nil {
		return err
	}
	return publishFRRTopology(path, data)
}

// tunnelManifest declares the base topology and the captures of one tunnel
// import. Topology is relative to the manifest's directory, as each capture file is.
type tunnelManifest struct {
	Topology string
	Captures []tunnelManifestCapture
}

// tunnelManifestCapture is one capture file and the facts its caller declares.
// The command must be one the import reads; a capture with any other is refused
// by the import, not here, as the FRR manifest leaves its commands to frrospf.
type tunnelManifestCapture struct {
	File        string
	Source      string
	Node        string
	Command     string
	CollectedAt time.Time
}

// decodeTunnelManifest reads manifest bytes with the checks the FRR manifest
// makes: no repeated key at any depth, no unknown key or case variant of one, a
// string where a string is required, local paths only, and unique labels.
func decodeTunnelManifest(data []byte) (tunnelManifest, error) {
	if len(data) > tunnelManifestLimit {
		return tunnelManifest{}, fmt.Errorf("manifest exceeds %d bytes", tunnelManifestLimit)
	}
	if err := frrospf.CheckUniqueKeys(data); err != nil {
		return tunnelManifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	m, err := decodeTunnelManifestObject(data)
	if err != nil {
		return tunnelManifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	return m, nil
}

func decodeTunnelManifestObject(data []byte) (tunnelManifest, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return tunnelManifest{}, errors.New("manifest is not a JSON object")
	}
	if err := frrospf.ExactKeys(top, "manifest", "version", "topology", "captures"); err != nil {
		return tunnelManifest{}, err
	}
	var v int
	if raw, ok := top["version"]; !ok || json.Unmarshal(raw, &v) != nil || v != tunnelManifestVersion {
		return tunnelManifest{}, fmt.Errorf(`manifest needs "version": %d`, tunnelManifestVersion)
	}

	var m tunnelManifest
	raw, ok := top["topology"]
	if !ok {
		return tunnelManifest{}, errors.New(`manifest needs "topology", the base topology file`)
	}
	topology, err := frrospf.PlainText(raw, `"topology"`)
	if err != nil {
		return tunnelManifest{}, err
	}
	if !localFile(topology) {
		return tunnelManifest{}, fmt.Errorf(`"topology" %q must be a relative path to a file inside the manifest directory`, textsafe.Clean(topology))
	}
	m.Topology = topology

	raw, ok = top["captures"]
	if !ok {
		return tunnelManifest{}, errors.New(`manifest needs "captures"`)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return tunnelManifest{}, errors.New(`"captures" must be an array of capture objects`)
	}
	switch {
	case len(entries) == 0:
		return tunnelManifest{}, errors.New("manifest lists no captures")
	case len(entries) > routepath.MaxTunnelCaptures:
		return tunnelManifest{}, fmt.Errorf("manifest lists %d captures; the limit is %d", len(entries), routepath.MaxTunnelCaptures)
	}
	for i, entry := range entries {
		c, err := decodeTunnelCapture(i, entry)
		if err != nil {
			return tunnelManifest{}, err
		}
		m.Captures = append(m.Captures, c)
	}
	if err := checkTunnelLabels(m); err != nil {
		return tunnelManifest{}, err
	}
	return m, nil
}

func decodeTunnelCapture(i int, raw json.RawMessage) (tunnelManifestCapture, error) {
	where := fmt.Sprintf("captures[%d]", i)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return tunnelManifestCapture{}, fmt.Errorf("%s is not an object", where)
	}
	if err := frrospf.ExactKeys(obj, where, "file", "source", "node", "command", "collected_at"); err != nil {
		return tunnelManifestCapture{}, err
	}
	field := func(key string) (string, error) {
		v, ok := obj[key]
		if !ok {
			return "", fmt.Errorf("%s needs %q", where, key)
		}
		return frrospf.PlainText(v, fmt.Sprintf("%s %q", where, key))
	}
	var c tunnelManifestCapture
	var err error
	if c.File, err = field("file"); err != nil {
		return tunnelManifestCapture{}, err
	}
	if !localFile(c.File) {
		return tunnelManifestCapture{}, fmt.Errorf("%s file %q must be a relative path to a file inside the manifest directory", where, textsafe.Clean(c.File))
	}
	if c.Source, err = field("source"); err != nil {
		return tunnelManifestCapture{}, err
	}
	if c.Node, err = field("node"); err != nil {
		return tunnelManifestCapture{}, err
	}
	if c.Command, err = field("command"); err != nil {
		return tunnelManifestCapture{}, err
	}
	stamp, err := field("collected_at")
	if err != nil {
		return tunnelManifestCapture{}, err
	}
	// time.Parse's own error quotes the value, so the message is written here.
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return tunnelManifestCapture{}, fmt.Errorf("%s collected_at is not an RFC 3339 time with an offset", where)
	}
	c.CollectedAt = at.UTC()
	return c, nil
}

// localFile reports whether name is a relative path inside the manifest's
// directory that names a file. filepath.IsLocal accepts "." by itself, which
// names the directory.
func localFile(name string) bool {
	return filepath.IsLocal(name) && filepath.Clean(name) != "."
}

// checkTunnelLabels refuses a source label that two captures share after
// sanitizing, and a file name that two captures spell the same way.
func checkTunnelLabels(m tunnelManifest) error {
	sources := map[string]int{}
	files := map[string]int{}
	for i, c := range m.Captures {
		src := textsafe.Clean(c.Source)
		if j, ok := sources[src]; ok {
			return fmt.Errorf("captures[%d] and captures[%d] both use source label %q", j, i, src)
		}
		sources[src] = i
		name := filepath.Clean(c.File)
		if j, ok := files[name]; ok {
			return fmt.Errorf("captures[%d] and captures[%d] name the same file %q", j, i, textsafe.Clean(c.File))
		}
		files[name] = i
	}
	return nil
}

// loadTunnelCaptures reads every capture the manifest names. No two may be the
// same file, so a hard link cannot count one capture twice, and the captures
// together stay within routepath.MaxTunnelImportBytes.
func loadTunnelCaptures(root *os.Root, m tunnelManifest) ([]routepath.TunnelCapture, error) {
	var captures []routepath.TunnelCapture
	var infos []os.FileInfo
	var total int64
	for i, mc := range m.Captures {
		data, info, err := readRegularFile(root, mc.File, routepath.MaxTunnelCaptureBytes)
		if err != nil {
			return nil, fmt.Errorf("captures[%d] %s: %w", i, textsafe.Clean(mc.File), err)
		}
		total += int64(len(data))
		if total > routepath.MaxTunnelImportBytes {
			return nil, fmt.Errorf("the captures together are larger than %d bytes", routepath.MaxTunnelImportBytes)
		}
		for j, prior := range infos {
			if os.SameFile(prior, info) {
				return nil, fmt.Errorf("captures[%d] and captures[%d] are the same file", j, i)
			}
		}
		infos = append(infos, info)
		captures = append(captures, routepath.TunnelCapture{
			Source:      mc.Source,
			Node:        mc.Node,
			Command:     mc.Command,
			CollectedAt: mc.CollectedAt,
			Data:        data,
		})
	}
	return captures, nil
}

// tunnelReport is the --import-tunnels JSON report. It names files, nodes,
// interfaces, and times, and never a key.
type tunnelReport struct {
	Version      int              `json:"version"`
	Manifest     string           `json:"manifest"`
	BaseTopology string           `json:"base_topology"`
	Complete     bool             `json:"complete"`
	Tunnels      []tunnelRecord   `json:"tunnels"`
	Unproven     []tunnelUnproven `json:"unproven"`
	Refused      []tunnelRefusal  `json:"refused"`
	Inert        []tunnelInert    `json:"inert_fallbacks"`
	NoCapture    []string         `json:"nodes_without_capture"`
	NotImported  []string         `json:"not_imported"`
	Limitations  []string         `json:"limitations"`
	Topology     tunnelOutput     `json:"topology"`
}

// tunnelOutput says what happened to the topology file the import was asked to write.
type tunnelOutput struct {
	Requested bool   `json:"requested"`
	Written   bool   `json:"written"`
	Path      string `json:"path,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// tunnelRecord is one record the import proved. Command and Source name the ip -d
// -j link capture the device came from, and the rules fields the capture that
// proves its underlay routing table.
type tunnelRecord struct {
	Node             string `json:"node"`
	VRF              string `json:"vrf"`
	Interface        string `json:"interface"`
	Remote           string `json:"remote"`
	UnderlayVRF      string `json:"underlay_vrf"`
	Command          string `json:"command"`
	Source           string `json:"source"`
	CollectedAt      string `json:"collected_at"`
	RulesSource      string `json:"rules_source"`
	RulesCollectedAt string `json:"rules_collected_at"`
	// The fields below are set only for a WireGuard record, and name the dump and
	// the endpoint lookup it rests on beside the device and rules captures above.
	EndpointSource      string `json:"endpoint_source,omitempty"`
	EndpointCollectedAt string `json:"endpoint_collected_at,omitempty"`
	LookupCommand       string `json:"lookup_command,omitempty"`
	LookupSource        string `json:"lookup_source,omitempty"`
	LookupCollectedAt   string `json:"lookup_collected_at,omitempty"`
	EgressInterface     string `json:"egress_interface,omitempty"`
}

type tunnelUnproven struct {
	Node           string `json:"node"`
	VRF            string `json:"vrf"`
	Interface      string `json:"interface"`
	Remote         string `json:"remote"`
	DeviceSource   string `json:"device_source"`
	DeviceAt       string `json:"device_collected_at"`
	EndpointSource string `json:"endpoint_source"`
	EndpointAt     string `json:"endpoint_collected_at"`
}

type tunnelRefusal struct {
	Source    string `json:"source"`
	Node      string `json:"node"`
	Interface string `json:"interface,omitempty"`
	Reason    string `json:"reason"`
}

// tunnelInert is a kernel fallback device the captures show inactive. From and Until
// bound the collection times of the captures that showed it.
type tunnelInert struct {
	Node      string   `json:"node"`
	Interface string   `json:"interface"`
	Kind      string   `json:"kind"`
	Sources   []string `json:"sources"`
	From      string   `json:"from"`
	Until     string   `json:"until"`
}

func buildTunnelReport(manifestPath string, m tunnelManifest, imp routepath.TunnelImport) tunnelReport {
	r := tunnelReport{
		Version:      tunnelReportVersion,
		Manifest:     manifestPath,
		BaseTopology: m.Topology,
		Complete:     len(imp.Unproven) == 0 && len(imp.Refused) == 0 && len(imp.Uncovered) == 0,
		Tunnels:      []tunnelRecord{},
		Unproven:     []tunnelUnproven{},
		Refused:      []tunnelRefusal{},
		Inert:        []tunnelInert{},
		NoCapture:    []string{},
		NotImported:  tunnelNotImported,
		Limitations:  tunnelLimitations,
	}
	rules := map[string]netmodel.Provenance{}
	for _, p := range imp.Rules {
		rules[p.Node] = p.Rules
	}
	proofs := map[[2]string]routepath.WireGuardProof{}
	for _, w := range imp.WireGuard {
		proofs[[2]string{w.Node, w.Interface}] = w
	}
	for _, t := range imp.Tunnels {
		p := rules[t.Node]
		rulesAt := ""
		if !p.CollectedAt.IsZero() {
			rulesAt = stampText(p.CollectedAt)
		}
		rec := tunnelRecord{
			Node:             t.Node,
			VRF:              t.VRF,
			Interface:        t.Interface,
			Remote:           t.Remote.String(),
			UnderlayVRF:      t.UnderlayVRF,
			Command:          routepath.TunnelCommandIPLink,
			Source:           t.Source,
			CollectedAt:      stampText(t.CollectedAt),
			RulesSource:      p.Source,
			RulesCollectedAt: rulesAt,
		}
		if w, ok := proofs[[2]string{t.Node, t.Interface}]; ok {
			rec.EndpointSource = w.Endpoint.Source
			rec.EndpointCollectedAt = stampText(w.Endpoint.CollectedAt)
			rec.LookupCommand = routepath.TunnelCommandRouteGetPrefix + t.Remote.String()
			rec.LookupSource = w.Lookup.Source
			rec.LookupCollectedAt = stampText(w.Lookup.CollectedAt)
			rec.EgressInterface = w.Egress
		}
		r.Tunnels = append(r.Tunnels, rec)
	}
	for _, u := range imp.Unproven {
		r.Unproven = append(r.Unproven, tunnelUnproven{
			Node:           u.Node,
			VRF:            u.VRF,
			Interface:      u.Interface,
			Remote:         u.Remote.String(),
			DeviceSource:   u.Device.Source,
			DeviceAt:       stampText(u.Device.CollectedAt),
			EndpointSource: u.Endpoint.Source,
			EndpointAt:     stampText(u.Endpoint.CollectedAt),
		})
	}
	for _, f := range imp.Refused {
		r.Refused = append(r.Refused, tunnelRefusal{Source: f.Source, Node: f.Node, Interface: f.Interface, Reason: f.Reason})
	}
	for _, d := range imp.Inert {
		r.Inert = append(r.Inert, tunnelInert{Node: d.Node, Interface: d.Interface, Kind: d.Kind, Sources: d.Sources, From: stampText(d.From), Until: stampText(d.Until)})
	}
	r.NoCapture = append(r.NoCapture, imp.Uncovered...)
	return r
}

func stampText(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// renderTunnelText renders the report for a person. Every line passes through
// textsafe.Clean, since names and paths come from the files the import read.
func renderTunnelText(r tunnelReport) string {
	var b strings.Builder
	line := func(format string, args ...any) {
		b.WriteString(textsafe.Clean(fmt.Sprintf(format, args...)))
		b.WriteByte('\n')
	}
	complete := "no"
	if r.Complete {
		complete = "yes"
	}
	line("Tunnel import of %s onto base topology %s", r.Manifest, r.BaseTopology)
	line("Complete: %s", complete)
	line("Tunnel records: %d", len(r.Tunnels))
	for _, t := range r.Tunnels {
		line("  tunnel %s (%s) %s remote %s underlay %s source %s at %s rules %s at %s", t.Node, t.VRF, t.Interface, t.Remote, t.UnderlayVRF, t.Source, t.CollectedAt, t.RulesSource, t.RulesCollectedAt)
		if t.LookupSource != "" {
			line("    wireguard dump %s at %s, lookup %s at %s leaving by %s", t.EndpointSource, t.EndpointCollectedAt, t.LookupSource, t.LookupCollectedAt, t.EgressInterface)
		}
	}
	line("Inert fallbacks: %d", len(r.Inert))
	for _, d := range r.Inert {
		line("  inert %s %s (%s) from %s until %s, by %s", d.Node, d.Interface, d.Kind, d.From, d.Until, strings.Join(d.Sources, ", "))
	}
	for _, u := range r.Unproven {
		line("  unproven %s (%s) %s remote %s device %s at %s endpoint %s at %s: underlay not shown",
			u.Node, u.VRF, u.Interface, u.Remote, u.DeviceSource, u.DeviceAt, u.EndpointSource, u.EndpointAt)
	}
	for _, f := range r.Refused {
		where := f.Source + " " + f.Node
		if f.Interface != "" {
			where += " " + f.Interface
		}
		line("  refused %s: %s", where, f.Reason)
	}
	line("Nodes without a usable ip -d -j link capture: %s", cmp.Or(strings.Join(r.NoCapture, ", "), "none"))
	line("Not imported:")
	for _, s := range r.NotImported {
		line("  %s", s)
	}
	line("Limits:")
	for _, s := range r.Limitations {
		line("  %s", s)
	}
	switch {
	case !r.Topology.Requested:
	case r.Topology.Written:
		line("Topology written to %s", r.Topology.Path)
	default:
		line("Topology: %s", r.Topology.Reason)
	}
	return b.String()
}
