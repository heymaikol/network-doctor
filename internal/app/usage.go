package app

import (
	"flag"
	"fmt"
	"io"

	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/profile"
)

// printUsage writes the full help text: usage line, the target grammar
// ParseTarget accepts, and the flags.
func printUsage(w io.Writer, fs *flag.FlagSet) {
	_, _ = io.WriteString(w, `Usage: netdoc [flags] [target]
       netdoc --profile github
       netdoc --profile ssh target
       netdoc --via ssh-destination [flags] [target]
       netdoc --peer-listen IP:port [--peer-listen IP:port]
       netdoc --peer-connect [--json]
       netdoc --compare before.ndoc after.ndoc [--json]
       netdoc --explain topology.json DEST [--fail NODE[:INTERFACE]] [--json]
       netdoc --explain topology.json DEST --fail-ospf NODE:INTERFACE:NEIGHBOR [--json]
       netdoc --explain topology.json DEST --fail-next-hop NODE[@VRF]:ADDRESS[%INTERFACE] [--json]
       netdoc --explain topology.json DEST --fail NODE[:INTERFACE] --sources LIST|all [--json]
       netdoc --explain topology.json DEST --fail-ospf NODE:INTERFACE:NEIGHBOR --sources LIST|all [--json]
       netdoc --explain topology.json DEST --fail-next-hop NODE[@VRF]:ADDRESS[%INTERFACE] --sources LIST|all [--json]
       netdoc --import-frr-ospf manifest.json [--write-topology topology.json] [--json]
       netdoc --import-tunnels manifest.json [--write-topology topology.json] [--json]
       netdoc --import-frr-bgp manifest.json [--json]
       netdoc --import-frr-bgp manifest.json --withdraw-bgp NODE:PEER:PREFIX [--json]
       netdoc --import-frr-bgp manifest.json --fail-bgp-session NODE:PEER [--json]
       netdoc --two-sided here.ndoc there.ndoc [--route-a topology.json] [--route-b topology.json] [--json]
       netdoc --two-sided --via ssh-destination [target] [--json]

Diagnoses network connectivity layer by layer. With no target it runs the
generic checks; with a target it also probes that endpoint. Flags may be
given before or after the target.

--profile runs a built-in service plan headlessly. Use --profile list to see
which profiles need a target and which fixed endpoints they test.

--via runs the checks on an SSH destination and presents the finished
diagnosis here. The destination goes to the system ssh client as typed, so
~/.ssh/config aliases work; the SSH host needs its own netdoc on the PATH of a
non-interactive session, or NETDOC_VIA_COMMAND set to its path. It is headless
and needs no terminal. With --two-sided, the same ordinary diagnosis also runs
locally and the two snapshots are localized together.

Peer mode is headless. The listener prints a temporary direct-connect pairing
string; the connector reads it from a hidden prompt so it does not enter argv.

Compare mode is headless and runs no probes: it reads two snapshots written by
--save or --support and reports what changed between them. It exits 0 when they describe the
same state and 1 when they do not.

--explain reads a topology file and a destination and says how traffic to that
destination should leave the network, where the forwarding table and the
control plane disagree, and which segments a recorded failure could lie in. It
is headless and runs no probe: the file is the only evidence, and the
destination must be an IP address, because a name would need a resolver. The
file's format is documented under Route path explanation in the reference.

--fail NODE or --fail NODE:INTERFACE adds a failure simulation to --explain. It
removes that router or interface from the recorded forwarding and lists the
destinations that lose redundancy, or lose reachability on some or all of their
forwarding branches, from the source. It recomputes no route and predicts no
convergence. An interface failure is an administrative down, not a carrier
loss. Only a node whose own interface is down is taken to stop using a next
hop through it, so a destination that keeps another next hop at any other
node is unknown, never redundancy_lost. A loss on a branch where some node
holds an OSPF or BGP route to the destination is unknown too, since that
protocol may compute another path, unless the failed router alone holds the
destination. A destination that would be unchanged, or keep only delivering
branches, is unknown when a node on its walk forwards by a BGP route, since the
file records no BGP session or next-hop resolution the failure could break.
See Failure simulation in the reference.

--fail-ospf NODE:INTERFACE:NEIGHBOR simulates losing the OSPF adjacency NODE
records on INTERFACE toward NEIGHBOR instead. The interface stays up, so only
OSPF next hops across its link stop, and only where the records prove the
link depends on the adjacency for transit: a point-to-point interface with the
neighbor full at one address. That is the recorded structure, not the FIB after
the loss. Where the records do not prove it, or a route is from BGP, the result
is unknown. No SPF is run, so a
destination left with no recorded next hop is unknown too, never lost.

--fail-next-hop NODE[@VRF]:ADDRESS[%INTERFACE] simulates NODE losing one next
hop instead: every leg of its recorded FIB through ADDRESS, in one routing
domain, and on INTERFACE when one is named. The interface and the node that
holds ADDRESS stay up, and nothing else changes. Only a next hop that a fib row
of NODE names can be selected. Whether NODE stops selecting a lost next hop
beside a surviving one is not in the file, so such a destination is unknown,
never redundancy_lost. It removes the recorded FIB next hop directly, simulates
no OSPF adjacency or BGP session loss, and assumes no protocol computes its
routes again.

--sources LIST, with one failure flag, simulates that failure from each source
in LIST, a comma-separated set of NODE[@VRF] names, or from every modeled node
with all. Each source gets the same ratings its own single-source run gives. The
affected nodes and routing domains are then counted by the recorded owner of
each destination, and a destination no modeled node holds is counted as
unowned. Under all, the failed router is excluded from the sources, since
nothing leaves a failed source; a named failed router exits 2. A run simulates
at most 64 sources, and each keeps the bounds of a single simulation. The walks
listed for all sources share one listing bound. A run that stops early says so.
It runs no probe.

--import-frr-ospf reads the FRR OSPF captures that a manifest names, checks each
one, and reports every capture and every neighbor record. With LSDB captures, it
also reports the OSPF LSDB comparison. It is headless and runs no probe and
contacts no router: the captures are the only evidence. The
manifest is JSON with "version": 1 and names each capture's file, source label,
node, VRF, FRR version, command, and collection time. Exit 0 means every
capture was accepted and every neighbor record was mapped; it does not mean the
network is healthy. Exit 1 means something was refused or left unmapped. With
--write-topology FILE, a complete import is written as a topology in the
--explain format, and an incomplete one writes nothing. The file is published
by hard link, so it never replaces an existing file, and a filesystem without
hard links refuses the write. The format is documented under FRR OSPF import in
the reference.

--import-tunnels reads the tunnel captures that a manifest names and adds the
tunnels they prove to the base topology the manifest names. It is headless and
runs no probe. Each capture is "ip -d -j link", "ip -j rule show", "ip -j addr show",
"ip -4 -j route show table all", "ip -6 -j route show table all", or "wg show all
dump" output for one node. Exit 0 means every modeled node has a
usable capture and no candidate was refused or left unproven; a complete import
writes the base topology with its tunnel records added. Exit 1 means the import
is incomplete, so nothing is written: something was refused or left unproven, or
a modeled node has no usable capture. Exit 2 means the manifest, the base
topology, or a capture cannot be used. A gre device is recorded only when its
node's IPv4 rules are the kernel default set, and an ipip device is refused unless it is an inert kernel fallback. A
kernel fallback device is listed as inert only when the address and route captures
show it inert, and is refused otherwise. A
WireGuard endpoint is reported as unproven. With
--write-topology FILE, a complete import is written, and the file is never
replaced. The format is documented under Tunnel import from captures in the
reference.

--import-frr-bgp reads the FRR BGP summary captures that a manifest names and
reports each router's ID, local AS, and peer sessions, with each state as FRR
printed it. A "show ip bgp json" capture adds the learned routes of that router,
the prefixes whose paths name a peer. It is headless, runs no probe, and contacts
no router. Its manifest is the version 1 format, and each capture names "command":
"show ip bgp summary json" or "show ip bgp json", "frr_version": "10.7.0", and
"vrf": "default". Exit 0 means every capture was valid; it does not mean a
session is up. Exit 2 means the manifest, a capture, or the output cannot be used.

--withdraw-bgp NODE:PEER:PREFIX adds a simulated withdrawal of PREFIX by PEER,
read against NODE's recorded BGP table only. Every path for PREFIX from PEER is
removed and nothing else changes: the peer's other prefixes stay, so it is not a
session loss. The outcome says whether a path not recorded stale remains from
no peer or from another peer (Established in NODE's summary, or any peer when
NODE has no summary), whether none is recorded, or whether that is unknown.
A result of no recorded path is not a route loss: another peer may still send one.
The forwarding impact is always unknown, because no RIB, FIB, or topology is
read. A selector the table does not describe exits 2.

--fail-bgp-session NODE:PEER adds a hypothetical loss of NODE's session with
PEER. It assumes every path NODE's recorded BGP table attributes to PEER, for
every prefix, is removed, and rates each such prefix the way --withdraw-bgp
does; a path FRR recorded stale is not counted as remaining. PEER's session
state is shown as the summary printed it, and whether or when NODE would remove
the paths, for example under graceful restart, stays unknown, as does the
forwarding impact. It needs --import-frr-bgp, not --explain, because a topology
file holds no BGP session or path. A peer that neither NODE's table nor its
summary names exits 2, and it cannot be combined with --withdraw-bgp.

--two-sided reads two snapshots as two machines looking at one target and says
whether the evidence places a failure on side A, side B, something shared, or
nowhere. With two file arguments it stays offline. With --via it concurrently
acquires side A locally and side B on the SSH host, then applies the same
snapshot localization. Both forms refuse different effective targets.

--route-a FILE and --route-b FILE add the routing context of one side to the
offline form. FILE is a topology in the --explain format, for the side it
describes. It is used only when the file ties to that side's own run: the
target must be an IP address, the file's source.address must be the source
that side recorded, and the file's rows must be within 24 hours of that run.
Otherwise the reading says why. The context never changes the placement. An
unreadable or invalid file exits 2.

Target forms:
`+diagnostic.TargetForms+"\n\nFlags:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func printProfiles(w io.Writer, registry profile.Registry) {
	fmt.Fprintln(w, "Available service profiles:")
	for _, definition := range registry.List() {
		target := "no target"
		if definition.Target == profile.TargetRequired {
			target = "target required"
		}
		fmt.Fprintf(w, "  %s (%s): %s\n", definition.Name, target, definition.Description)
	}
}
