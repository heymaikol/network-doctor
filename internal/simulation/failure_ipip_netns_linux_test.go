//go:build netns_integration && linux

package simulation

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
	"github.com/heymaikol/network-doctor/v2/internal/routepath"
)

// ipipAcceptanceDirector is set only on the copy of this test binary that
// TestIPIPAcceptanceAgainstLiveNamespaces launches as its director.
var ipipAcceptanceDirector = flag.Bool("ipip-acceptance-director", false, "internal: run the live IPIP acceptance cases inside a director")

// The overlay address r3 holds on its ipip1 device, which each case grades, and the
// two underlay addresses the tunnel's remotes are reached at, as the diamond lays them out.
const (
	ipipOverlay  = "172.32.0.2"
	ipipRemoteR1 = "10.71.30.1"
	ipipRemoteR3 = "10.71.14.1"
)

// TestIPIPAcceptanceAgainstLiveNamespaces builds the GRE import diamond with an IPIP
// tunnel from r1 to r3 instead, and grades the overlay the simulator predicts after each
// fault against what the kernel delivers. It also checks that the production importer
// still refuses the configured ipip devices, so these cases enable no IPIP record.
func TestIPIPAcceptanceAgainstLiveNamespaces(t *testing.T) {
	if *ipipAcceptanceDirector {
		for _, c := range ipipAcceptanceCases {
			t.Run(c.name, func(t *testing.T) { runIPIPAcceptanceCase(t, c) })
		}
		return
	}
	t.Parallel()
	requireBackend(t)
	requireIPIPModule(t, "ip link add type ipip cannot create a tunnel")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var names []string
	for _, c := range ipipAcceptanceCases {
		names = append(names, c.name)
	}
	launchTunnelDirector(ctx, t, "TestIPIPAcceptanceAgainstLiveNamespaces", "ipip-acceptance-director", names)
}

// runIPIPAcceptanceCase runs one case in its own namespaces: it builds the diamond with
// the IPIP tunnel, reads the kernel's state, and grades the overlay against the dials
// before and after the fault.
func runIPIPAcceptanceCase(t *testing.T, c ipipAcceptanceCase) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	e, s := startTunnelDiamond(ctx, t, c.segment)
	src := e.byName[s.Client().Name]
	// The scenario routes r1 nowhere past its links, so r1 gets the ECMP underlay route to
	// r3's LAN that the tunnel's remote is looked up in, as the GRE case does.
	addMultipath(ctx, t, e, "r1", "10.71.30.0/24", "10.71.12.2", "10.71.14.4")
	addTunnel(ctx, t, e, "r1", "ipip", ipipDevice, "10.71.14.1", ipipRemoteR1, "172.32.0.1/30", e.byName["r1"].interfaceForSegment("s14").iface)
	addTunnel(ctx, t, e, "r3", "ipip", ipipDevice, "10.71.30.1", ipipRemoteR3, ipipOverlay+"/30", e.byName["r3"].interfaceForSegment("s43").iface)
	awaitSettled(ctx, t, e)

	// The model and the captures are read before any fault, so the import and the dials
	// are graded against the same moment.
	obs := kernelObservations(ctx, t, e, ipipDevice)
	file := topologyFile(t, src.node.Name, obs)
	captures := tunnelCaptures(ctx, t, e)
	imp, err := routepath.ImportTunnels(file.Model, captures)
	if err != nil {
		t.Fatal(err)
	}
	checkIPIPRefusal(t, e, file, imp)

	// The tunnel records the simulator grades with are read from the kernel here. They
	// are not proven by the import, which still refuses the devices, and no topology
	// file the importer reads holds them.
	merged := file
	merged.Tunnels = []routepath.Tunnel{
		ipipRecordFrom(t, captures, "r1", ipipRemoteR1, e.byName["r1"].interfaceForSegment("s14").iface),
		ipipRecordFrom(t, captures, "r3", ipipRemoteR3, e.byName["r3"].interfaceForSegment("s43").iface),
	}
	data, err := routepath.Encode(merged)
	if err != nil {
		t.Fatal(err)
	}
	written, err := routepath.Decode(data)
	if err != nil {
		t.Fatalf("the ipip records do not decode: %v", err)
	}

	var outcome strings.Builder
	outcome.WriteString("tunnel records: constructed by this test from the live ip -d -j link captures, not proven by ImportTunnels\n")
	for _, r := range merged.Tunnels {
		fmt.Fprintf(&outcome, "  %s %s %s remote %s underlay %s, from %s at %s\n", r.Node, r.VRF, r.Interface, r.Remote, r.UnderlayVRF, r.Source, r.CollectedAt.UTC().Format(time.RFC3339Nano))
	}
	outcome.WriteString(tunnelImportSummary(imp))
	dests := heldAddresses(obs)
	before := map[string]bool{}
	for _, d := range dests {
		before[d] = dialDelivers(ctx, t, src, d)
	}
	if !before[ipipOverlay] {
		t.Fatalf("the overlay %s is not up before the fault", ipipOverlay)
	}
	tunnelPathState(ctx, t, e, &outcome, ipipDevice, "before the fault")

	// The same file with no tunnel record is the answer the simulation gives when the
	// tunnel is not believed. Both answers are graded.
	bare, err := routepath.Simulate(file, c.fault)
	if err != nil {
		t.Fatal(err)
	}

	device := ipipDevice
	if c.segment != "" {
		device = e.byName["r1"].interfaceForSegment(c.segment).iface
		if _, err := e.ApplyFaults(ctx, s.Faults); err != nil {
			t.Fatal(err)
		}
	} else if res := e.Exec(ctx, "r1", []string{"ip", "link", "set", "dev", ipipDevice, "down"}, nil); res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("bring r1 %s down: %v", ipipDevice, execResultError(res))
	}
	requireLinkDown(ctx, t, e, "r1", device)
	if c.segment != "" {
		// A link lost underneath leaves the tunnel's own device administratively up. If the
		// device went down too, the case no longer isolates the underlay.
		tun := e.Exec(ctx, "r1", []string{"ip", "-o", "link", "show", "dev", ipipDevice}, nil)
		if tun.Err != nil || tun.ExitCode != 0 || !parseLinkUp(string(tun.Stdout)) {
			t.Fatalf("r1 %s is not up in the kernel after its underlay fault: %s %v", ipipDevice, tun.Stdout, execResultError(tun))
		}
	}
	after := map[string]bool{}
	for _, d := range dests {
		after[d] = dialDelivers(ctx, t, src, d)
	}
	tunnelPathState(ctx, t, e, &outcome, ipipDevice, "after the fault")

	sim, err := routepath.Simulate(written, c.fault)
	if err != nil {
		t.Fatal(err)
	}
	rated, bareRated := gradeTunnelDestinations(ctx, t, e, src, dests, sim, bare, before, after, &outcome)
	if got := impactOr(rated, ipipOverlay); got != c.impact || after[ipipOverlay] != c.delivered {
		t.Errorf("%s: predicted %s and delivered %t after the fault, want %s and %t", ipipOverlay, got, after[ipipOverlay], c.impact, c.delivered)
	}
	if got := impactOr(bareRated, ipipOverlay); got != c.bare {
		t.Errorf("%s: predicted %s without the tunnel record, want %s", ipipOverlay, got, c.bare)
	}
	if d := c.unaffected; d != "" {
		if got := impactOr(rated, d); got != routepath.ImpactNone || !before[d] || !after[d] {
			t.Errorf("%s: predicted %s and delivered %t then %t, want none and delivered both times", d, got, before[d], after[d])
		}
	}

	dir := ""
	if root := *tunnelImportEvidence; root != "" {
		dir = ipipEvidenceDir(root, c.name)
	}
	keepTunnelEvidence(t, dir, captures, file, outcome.String())
}

// checkIPIPRefusal asserts what the production importer does with the two configured
// IPIP devices: each is refused with the reason that keeps ipip out of the topology,
// nothing is recorded, MergeTunnelImport refuses the import, and tunl0 stays an inert
// fallback on every node. A change to any of these means the importer's ipip handling
// moved, which this slice does not allow.
func checkIPIPRefusal(t *testing.T, e *netnsEnv, file routepath.File, imp routepath.TunnelImport) {
	t.Helper()
	const reason = "is an ipip device, which the import does not record: no ipip underlay has been validated live"
	want := map[string]string{"r1 " + ipipDevice: reason, "r3 " + ipipDevice: reason}
	got := map[string]string{}
	for _, r := range imp.Refused {
		got[r.Node+" "+r.Interface] = r.Reason
	}
	if len(got) != len(imp.Refused) || !maps.Equal(got, want) {
		t.Errorf("refusals:\n%s\nwant:\n%s", tunnelLines(got), tunnelLines(want))
	}
	if len(imp.Tunnels) != 0 {
		t.Errorf("the import recorded %d tunnels, want none while configured ipip is refused", len(imp.Tunnels))
	}
	if _, err := routepath.MergeTunnelImport(file, imp); err == nil {
		t.Error("MergeTunnelImport accepted an import that refuses the ipip devices")
	}
	inert := map[string]bool{}
	for _, d := range imp.Inert {
		if d.Interface == "tunl0" {
			inert[d.Node] = true
		}
	}
	for _, np := range e.nodes {
		if !inert[np.node.Name] {
			t.Errorf("tunl0 on %s is not an inert fallback", np.node.Name)
		}
	}
}

// ipipCapture returns the ip -d -j link capture of node, the one the import reads its
// devices from.
func ipipCapture(t *testing.T, captures []routepath.TunnelCapture, node string) routepath.TunnelCapture {
	t.Helper()
	for _, c := range captures {
		if c.Node == node && c.Command == routepath.TunnelCommandIPLink {
			return c
		}
	}
	t.Fatalf("%s has no ip -d -j link capture", node)
	return routepath.TunnelCapture{}
}

// ipipLink is the part of one ip -d -j link object the record reads.
type ipipLink struct {
	Name   string `json:"ifname"`
	Master string `json:"master"`
	Link   string `json:"link"`
	Info   struct {
		Kind string `json:"info_kind"`
		Data struct {
			Remote string `json:"remote"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

// ipipRecordFrom builds node's tunnel record from its live ip -d -j link capture. The
// device must be an ipip device in the default routing domain, with the remote and the
// underlay device the case built, or the case stops. The record is the test's reading of
// the kernel, not an import proof.
func ipipRecordFrom(t *testing.T, captures []routepath.TunnelCapture, node, remote, underlay string) routepath.Tunnel {
	t.Helper()
	c := ipipCapture(t, captures, node)
	var links []ipipLink
	if err := json.Unmarshal(c.Data, &links); err != nil {
		t.Fatalf("%s: ip -d -j link: %v", node, err)
	}
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.Name != ipipDevice {
			continue
		}
		if l.Info.Kind != "ipip" || l.Master != "" || l.Link != underlay || l.Info.Data.Remote != remote {
			t.Fatalf("%s %s is kind %q, enslaved to %q, over %q to %q; want kind ipip over %q to %s in the default routing domain",
				node, ipipDevice, l.Info.Kind, l.Master, l.Link, l.Info.Data.Remote, underlay, remote)
		}
		return routepath.Tunnel{
			Provenance:  netmodel.Provenance{Source: c.Source, CollectedAt: c.CollectedAt},
			Node:        node,
			VRF:         "default",
			Interface:   ipipDevice,
			Remote:      addr,
			UnderlayVRF: "default",
		}
	}
	t.Fatalf("%s holds no %s in its ip -d -j link capture", node, ipipDevice)
	return routepath.Tunnel{}
}
