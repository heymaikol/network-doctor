package routepath

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/netmodel"
)

// The commands the importer reads. A capture names one of them exactly. The
// WireGuard form is "wg show all dump", not "wg show <interface> dump": the all
// form prints the interface name on every line, so the source shows the
// interface rather than the caller declaring it. The rules form lists the IPv4
// policy rules only, which is the family a gre device's outer packet uses. The
// address and route forms never prove a tunnel. They show only whether a kernel
// fallback device is inert, so the device is not refused for its own kind.
// The "ip -j route get fibmatch" form shows the complete FIB route for a WireGuard
// endpoint, including its full nexthop set.
const (
	TunnelCommandIPLink                 = "ip -d -j link"
	TunnelCommandRules                  = "ip -j rule show"
	TunnelCommandAddr                   = "ip -j addr show"
	TunnelCommandRoute4                 = "ip -4 -j route show table all"
	TunnelCommandRoute6                 = "ip -6 -j route show table all"
	TunnelCommandWireGuard              = "wg show all dump"
	TunnelCommandRouteGetFibmatchPrefix = "ip -j route get fibmatch "
)

// tunnelCommands lists every exact command the importer reads, in the order a refusal
// names them.
var tunnelCommands = []string{TunnelCommandIPLink, TunnelCommandRules, TunnelCommandAddr, TunnelCommandRoute4, TunnelCommandRoute6, TunnelCommandWireGuard}

// tunnelCommandList quotes tunnelCommands as an English list, for a refusal.
func tunnelCommandList() string {
	quoted := make([]string, len(tunnelCommands))
	for i, c := range tunnelCommands {
		quoted[i] = fmt.Sprintf("%q", c)
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + ", " + quoted[len(quoted)-1] + ", and \"ip -j route get fibmatch <endpoint>\""
}

// isRouteGetFibmatchCommand reports whether command is an "ip -j route get fibmatch <endpoint>"
// command, and returns the endpoint address if it is. The endpoint must be written
// the way netip prints it, with no zone, so that one address has one command and a
// capture is never matched to an endpoint by a spelling accident.
func isRouteGetFibmatchCommand(command string) (netip.Addr, bool) {
	target, found := strings.CutPrefix(command, TunnelCommandRouteGetFibmatchPrefix)
	if !found {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(target)
	if err != nil || a.Zone() != "" || a.String() != target {
		return netip.Addr{}, false
	}
	return a, true
}

// isReadCommand reports whether command is one the import reads.
func isReadCommand(command string) bool {
	if slices.Contains(tunnelCommands, command) {
		return true
	}
	_, ok := isRouteGetFibmatchCommand(command)
	return ok
}

// Import limits. A capture is read whole, so its size is bounded before it is
// parsed, and the captures of one import are bounded together as well.
const (
	MaxTunnelCaptureBytes = 1 << 20
	MaxTunnelCaptures     = 256
	MaxTunnelImportBytes  = 32 << 20
)

// TunnelCapture is one captured tunnel source. Source labels it uniquely within
// one import, and names it in every record and refusal it produces. Node is the
// node it came from, and CollectedAt is when it was taken. The import knows no
// other time for its facts, and it takes no fact from the caller.
type TunnelCapture struct {
	Source      string
	Node        string
	Command     string
	CollectedAt time.Time
	Data        []byte
}

// TunnelImport is what one import proves and what it refuses. Tunnels are records
// that have passed the checks Decode applies to a tunnel record, and that the
// underlay proof of ImportTunnels accepts. Rules lists each node whose IPv4 policy
// rules the captures prove to be the kernel default set. Unproven lists WireGuard
// endpoints the captures show without the routing domain each is looked up in.
// Refused lists every other candidate that was not accepted, with its reason.
// Uncovered lists each modeled node with no usable ip -d -j link capture. Its
// devices are not known, so the import is incomplete until it has one. Inert lists
// each kernel fallback device the captures show to be inactive. It is not a tunnel,
// so it makes no record, and it is listed rather than left out silently. The lists
// are in a fixed order.
type TunnelImport struct {
	Tunnels   []Tunnel
	WireGuard []WireGuardProof
	Rules     []RulesProof
	Unproven  []UnprovenTunnel
	Refused   []TunnelRefusal
	Uncovered []string
	Inert     []InertDevice
}

// errIPv6Endpoint is the refusal for an IPv6 WireGuard endpoint. The rules capture
// lists IPv4 policy rules only, so nothing the import reads shows which table an
// IPv6 lookup ends in, and a route get capture cannot stand in for that.
const errIPv6Endpoint = "its peer endpoint is IPv6, and the import reads IPv4 policy rules only, so the routing table of its lookup is not proven"

var errAmbiguousFibRoute = errors.New("the full FIB route has multiple nexthops, so its underlay is not unique")
var errUnresolvedNexthop = errors.New("the full FIB route names a nexthop object whose complete path is not captured")

// WireGuardProof is the evidence behind one WireGuard Tunnel record: the captures
// that show the device, its peer endpoint, the routing lookup of that endpoint, and
// the node's policy rules, each with its own source and collection time. Egress is
// the underlay device the lookup named. The Tunnel record itself keeps the format
// every record has, so this is where the reporting finds what the record rests on.
type WireGuardProof struct {
	Node      string
	Interface string
	Egress    string
	Device    netmodel.Provenance
	Endpoint  netmodel.Provenance
	Lookup    netmodel.Provenance
	Rules     netmodel.Provenance
}

// InertDevice is a kernel-created fallback device the captures show inactive: down,
// unaddressed, unrouted, and unsteered. Sources names the captures that showed it,
// and From and Until bound their collection times.
type InertDevice struct {
	Node      string
	Interface string
	Kind      string
	Sources   []string
	From      time.Time
	Until     time.Time
}

// RulesProof is a node whose IPv4 policy rules are the kernel default set, so every
// IPv4 lookup on it ends in the main table. Rules is the capture that shows it.
type RulesProof struct {
	Node  string
	Rules netmodel.Provenance
}

// UnprovenTunnel is a WireGuard interface whose endpoint a dump shows, with the
// routing domain that endpoint is looked up in shown by no capture. Its overlay
// is unmodelled, not safe: a topology built without this entry reads the
// interface as a direct link, and an underlay failure then rates the overlay none.
// Nothing here writes it to a topology file. Device is the ip -d -j link capture
// that shows the interface and its own routing domain, and Endpoint is the wg dump
// that shows the remote. Each keeps the source and time of its own capture.
type UnprovenTunnel struct {
	Node      string
	VRF       string
	Interface string
	Remote    netip.Addr
	Device    netmodel.Provenance
	Endpoint  netmodel.Provenance
}

// TunnelRefusal says why one candidate was not accepted, or why a whole capture
// was not read. Interface is empty when the capture as a whole was refused.
type TunnelRefusal struct {
	Source    string
	Node      string
	Interface string
	Reason    string
}

// ImportTunnels proves tunnel records from captured tunnel sources of the nodes m
// describes. A capture of a node m does not describe is refused, so a mistyped
// name never reads as a clean import. A gre device is recorded only when its
// underlay routing table is proven: the device and its underlay device are in the
// default routing domain, it carries no fwmark, and its node's IPv4 policy rules
// are the kernel default set. Those rules send every IPv4 lookup to the main
// table, so the table is known without any other fact. Any other rule, a second
// rules capture, or a missing one refuses every gre device of that node. An ipip
// device is refused, since no ipip underlay has been run live. A WireGuard
// interface is recorded when its endpoint's underlay lookup is proven by an
// ip -j route get fibmatch capture under the default domain, default rules, and with
// no fwmark. An endpoint with no usable full FIB capture is listed in Unproven.
// Every other candidate is refused with its reason. Nothing is inferred from an
// interface name. An error means the import itself is malformed, not that a
// capture is.
func ImportTunnels(m netmodel.Model, captures []TunnelCapture) (TunnelImport, error) {
	if len(captures) > MaxTunnelCaptures {
		return TunnelImport{}, fmt.Errorf("%d tunnel captures; the limit is %d", len(captures), MaxTunnelCaptures)
	}
	sorted := slices.Clone(captures)
	slices.SortFunc(sorted, func(a, b TunnelCapture) int { return cmp.Compare(a.Source, b.Source) })
	total := 0
	for i, c := range sorted {
		switch {
		case c.Source == "":
			return TunnelImport{}, errors.New("a tunnel capture has no source label")
		case i > 0 && sorted[i-1].Source == c.Source:
			return TunnelImport{}, fmt.Errorf("two tunnel captures share source label %q", c.Source)
		}
		total += len(c.Data)
	}
	if total > MaxTunnelImportBytes {
		return TunnelImport{}, fmt.Errorf("the tunnel captures together are %d bytes; the limit is %d", total, MaxTunnelImportBytes)
	}

	var out TunnelImport
	var ipLinks, wgDumps, ruleCaps, addrCaps, route4Caps, route6Caps, routeGetCaps []TunnelCapture
	for _, c := range sorted {
		switch {
		case len(c.Data) > MaxTunnelCaptureBytes:
			out.refuse(c.Source, c.Node, "", fmt.Sprintf("is larger than %d bytes", MaxTunnelCaptureBytes))
		case !isReadCommand(c.Command):
			out.refuse(c.Source, c.Node, "", fmt.Sprintf("command %q is not one the import reads; it reads %s", c.Command, tunnelCommandList()))
		case c.Node == "":
			out.refuse(c.Source, c.Node, "", "has no node")
		case c.CollectedAt.IsZero():
			out.refuse(c.Source, c.Node, "", "has no collection time")
		case c.Command == TunnelCommandIPLink:
			ipLinks = append(ipLinks, c)
		case c.Command == TunnelCommandRules:
			ruleCaps = append(ruleCaps, c)
		case c.Command == TunnelCommandAddr:
			addrCaps = append(addrCaps, c)
		case c.Command == TunnelCommandRoute4:
			route4Caps = append(route4Caps, c)
		case c.Command == TunnelCommandRoute6:
			route6Caps = append(route6Caps, c)
		case strings.HasPrefix(c.Command, TunnelCommandRouteGetFibmatchPrefix):
			routeGetCaps = append(routeGetCaps, c)
		default:
			wgDumps = append(wgDumps, c)
		}
	}

	// A node's devices come from one ip -d -j link capture. Two captures would
	// give two answers for the same device, so every capture of such a node is
	// refused, and the dumps that need it are refused with them.
	byNode := perNode(ipLinks)
	modeled := modeledNodes(m)
	sets := map[string]linkSet{}
	for node, list := range byNode {
		if !slices.Contains(modeled, node) {
			for _, c := range list {
				out.refuse(c.Source, c.Node, "", fmt.Sprintf("no configured, control, or fib observation describes node %q", node))
			}
			continue
		}
		if len(list) > 1 {
			for _, c := range list {
				out.refuse(c.Source, c.Node, "", fmt.Sprintf("node %s has %d ip -d -j link captures; the import needs one", node, len(list)))
			}
			continue
		}
		c := list[0]
		entries, err := parseIPLink(c.Data)
		if err != nil {
			out.refuse(c.Source, c.Node, "", err.Error())
			continue
		}
		index, err := indexLinks(entries)
		if err != nil {
			out.refuse(c.Source, c.Node, "", err.Error())
			continue
		}
		sets[node] = linkSet{capture: c, links: index}
	}

	for _, node := range modeled {
		if _, ok := sets[node]; !ok {
			out.Uncovered = append(out.Uncovered, node)
		}
	}

	// A node's policy rules come from one ip -j rule show capture, for the same
	// reason its devices do. A rules capture of a node with no usable ip capture
	// proves nothing here, so it is refused.
	rulesByNode := map[string][]TunnelCapture{}
	for _, c := range ruleCaps {
		rulesByNode[c.Node] = append(rulesByNode[c.Node], c)
	}
	for node, list := range rulesByNode {
		if _, ok := sets[node]; !ok {
			for _, c := range list {
				out.refuse(c.Source, c.Node, "", fmt.Sprintf("needs one usable ip -d -j link capture of node %s in this import", node))
			}
		}
	}
	rules := map[string]ruleState{}
	for node := range sets {
		rules[node] = out.proveRules(node, rulesByNode[node])
	}

	// A node's addresses and routes are read only to show that its fallback devices
	// are inert. They never feed the underlay proof, so a gre device is recorded or
	// refused as it was before they were read.
	addrBy, r4By, r6By := perNode(addrCaps), perNode(route4Caps), perNode(route6Caps)
	for _, list := range [][]TunnelCapture{addrCaps, route4Caps, route6Caps} {
		for _, c := range list {
			if _, ok := sets[c.Node]; !ok {
				out.refuse(c.Source, c.Node, "", fmt.Sprintf("needs one usable ip -d -j link capture of node %s in this import", c.Node))
			}
		}
	}
	evidence := map[string]nodeEvidence{}
	for node := range sets {
		ev := out.proveFallbackEvidence(node, sets[node], addrBy[node], r4By[node], r6By[node])
		ev.window = append(ev.window, rulesByNode[node]...)
		ev.checkWindow(node)
		evidence[node] = ev
	}

	// Index fibmatch captures by (node, endpoint). A capture of a node with no
	// usable link capture proves nothing, so it is refused here. used marks each
	// capture that has been accepted into a proof or refused for a reason of its
	// own, and every capture still unmarked after the dumps are read is refused
	// below, so none disappears silently.
	routeGets := map[[2]string][]int{}
	used := make([]bool, len(routeGetCaps))
	for i, c := range routeGetCaps {
		if _, ok := sets[c.Node]; !ok {
			out.refuse(c.Source, c.Node, "", fmt.Sprintf("needs one usable ip -d -j link capture of node %s in this import", c.Node))
			used[i] = true
			continue
		}
		dst, _ := isRouteGetFibmatchCommand(c.Command)
		k := [2]string{c.Node, dst.String()}
		routeGets[k] = append(routeGets[k], i)
	}

	// Each dump that parses gives a fact about every interface it lists. The dumps
	// of one node must agree on each interface they both name. When they do not,
	// every dump naming that interface is refused, so source order never settles
	// the disagreement. When they agree, the first source keeps the interface and
	// the rest are refused as its duplicates.
	byIface := map[[2]string][]wgFact{}
	for _, c := range wgDumps {
		if _, ok := sets[c.Node]; !ok {
			out.refuse(c.Source, c.Node, "", fmt.Sprintf("needs one usable ip -d -j link capture of node %s in this import", c.Node))
			continue
		}
		ifaces, err := parseWGDump(c.Data)
		if err != nil {
			out.refuse(c.Source, c.Node, "", err.Error())
			continue
		}
		for _, w := range ifaces {
			k := [2]string{c.Node, w.name}
			byIface[k] = append(byIface[k], wgFact{capture: c, iface: w})
		}
	}
	// Every device of a node is read, so none is skipped by its kind. A gre or ipip
	// device that a parsed dump names contradicts the ip capture, so neither is
	// used. A wireguard device no usable dump names has no endpoint shown, so it is
	// refused. A device of any other kind is accepted only when it is plain.
	for _, node := range slices.Sorted(maps.Keys(sets)) {
		s := sets[node]
		for _, name := range slices.Sorted(maps.Keys(s.links)) {
			l := s.links[name]
			_, named := byIface[[2]string{node, name}]
			kind := l.kind()
			if fallbackKinds[kind] && !named {
				why := evidence[node].fallbackReason(l, name, rules[node])
				switch {
				case why == "":
					out.Inert = append(out.Inert, evidence[node].inert(node, name, kind))
					continue
				case kind == "gretap" || kind == "erspan" || isMultipoint(l):
					out.refuse(s.capture.Source, s.capture.Node, name, fallbackRefusal(kind, why))
					continue
				}
			}
			switch {
			case kind == "gre" || kind == "ipip":
				if named {
					out.refuse(s.capture.Source, s.capture.Node, name, fmt.Sprintf("the ip -d -j link capture shows a %s device, but a wg show all dump also names it", kind))
					continue
				}
				w, err := tunnelFromLink(s.capture, s.links, l)
				if err != nil {
					out.refuse(s.capture.Source, s.capture.Node, name, err.Error())
					continue
				}
				if kind == "ipip" {
					out.refuse(s.capture.Source, s.capture.Node, name, "is an ipip device, which the import does not record: no ipip underlay has been validated live")
					continue
				}
				if _, marked := l.Info.Data["fwmark"]; marked {
					out.refuse(s.capture.Source, s.capture.Node, name, "has a fwmark, which steers the encapsulated packet by policy rule, and marks are not validated")
					continue
				}
				t, err := decodeTunnel(w)
				if err == nil {
					err = tunnelRecorded(m, t)
				}
				if err == nil {
					err = underlayProven(w, rules[node])
				}
				if err != nil {
					out.refuse(w.Source, w.Node, w.Interface, err.Error())
					continue
				}
				out.Tunnels = append(out.Tunnels, t)
			case kind == "wireguard":
				if !named {
					out.refuse(s.capture.Source, s.capture.Node, name, "is a wireguard device, but no usable wg show all dump names it, so its endpoint is not shown")
				}
			case plainKinds[kind], kind == "" && (l.LinkType == "ether" || l.LinkType == "loopback"):
			case kind == "":
				out.refuse(s.capture.Source, s.capture.Node, name, fmt.Sprintf("has no kind and %s, which the import does not read", namedValue("link type", l.LinkType)))
			default:
				out.refuse(s.capture.Source, s.capture.Node, name, fmt.Sprintf("has %s, which the import does not read", namedValue("kind", kind)))
			}
		}
	}

	for _, node := range slices.Sorted(maps.Keys(sets)) {
		if rules[node].reason == "" {
			out.Rules = append(out.Rules, RulesProof{Node: node, Rules: rules[node].prov})
		}
	}

	keys := slices.SortedFunc(maps.Keys(byIface), func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	for _, k := range keys {
		group := byIface[k]
		kept := ""
		for _, f := range group {
			if other, ok := wgPartner(group, f); ok {
				out.refuse(f.capture.Source, f.capture.Node, k[1], "conflicts with source "+other+": the dumps disagree on the fwmark or endpoint of this interface, so neither is used")
				continue
			}
			u, err := wgEndpoint(sets[k[0]], f.capture, f.iface)
			if err == nil {
				err = tunnelRecorded(m, Tunnel{Node: u.Node, VRF: u.VRF, Interface: u.Interface, Remote: u.Remote})
			}
			if err != nil {
				out.refuse(f.capture.Source, f.capture.Node, k[1], err.Error())
				continue
			}
			if kept != "" {
				out.refuse(f.capture.Source, f.capture.Node, k[1], "the same interface is already reported from source "+kept)
				continue
			}
			kept = f.capture.Source

			// The endpoint's underlay proof comes from the fibmatch capture of
			// that endpoint. With none, the endpoint stays unproven. An IPv6
			// endpoint is refused outright, with its captures: the node's rules
			// are read for IPv4 only, so no capture here can prove its table.
			idx := routeGets[[2]string{u.Node, u.Remote.String()}]
			if !u.Remote.Is4() {
				out.refuse(f.capture.Source, f.capture.Node, k[1], errIPv6Endpoint)
				for _, i := range idx {
					rc := routeGetCaps[i]
					out.refuse(rc.Source, rc.Node, k[1], errIPv6Endpoint)
					used[i] = true
				}
				continue
			}
			if len(idx) == 0 {
				out.Unproven = append(out.Unproven, u)
				continue
			}
			if len(idx) > 1 {
				for _, i := range idx {
					if !used[i] {
						rc := routeGetCaps[i]
						out.refuse(rc.Source, rc.Node, k[1], fmt.Sprintf("node %s has %d route get captures for endpoint %s; the import needs one", rc.Node, len(idx), u.Remote))
						used[i] = true
					}
				}
				continue
			}
			used[idx[0]] = true
			rgCap := routeGetCaps[idx[0]]
			tun, proof, err := proveWGUnderlay(sets[k[0]], u, rgCap, rules[k[0]])
			if err != nil {
				if errors.Is(err, errAmbiguousFibRoute) || errors.Is(err, errUnresolvedNexthop) {
					out.Unproven = append(out.Unproven, u)
				}
				out.refuse(rgCap.Source, rgCap.Node, k[1], err.Error())
				continue
			}
			out.Tunnels = append(out.Tunnels, tun)
			out.WireGuard = append(out.WireGuard, proof)
		}
	}

	// A route get capture no interface used is refused with the reason, whether its
	// endpoint matches no interface, the interface was refused before its lookup was
	// read, or the interface is not a single-peer WireGuard device.
	for i, c := range routeGetCaps {
		if !used[i] {
			dst, _ := isRouteGetFibmatchCommand(c.Command)
			out.refuse(c.Source, c.Node, "", fmt.Sprintf("is not used: no wireguard interface of node %s is reported with endpoint %s, so the lookup proves nothing", c.Node, dst))
		}
	}

	slices.SortFunc(out.Tunnels, compareTunnels)
	slices.SortFunc(out.Unproven, compareUnproven)
	slices.SortFunc(out.WireGuard, compareWireGuard)
	slices.SortFunc(out.Refused, compareRefusals)
	return out, nil
}

func (r *TunnelImport) refuse(source, node, iface, reason string) {
	r.Refused = append(r.Refused, TunnelRefusal{Source: source, Node: node, Interface: iface, Reason: reason})
}

func compareUnproven(a, b UnprovenTunnel) int {
	return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.VRF, b.VRF), cmp.Compare(a.Interface, b.Interface), cmp.Compare(a.Endpoint.Source, b.Endpoint.Source))
}

// compareWireGuard orders the evidence by node, then interface, as the records are.
func compareWireGuard(a, b WireGuardProof) int {
	return cmp.Or(cmp.Compare(a.Node, b.Node), cmp.Compare(a.Interface, b.Interface))
}

func compareRefusals(a, b TunnelRefusal) int {
	return cmp.Or(cmp.Compare(a.Source, b.Source), cmp.Compare(a.Node, b.Node), cmp.Compare(a.Interface, b.Interface), cmp.Compare(a.Reason, b.Reason))
}

// proveWGUnderlay checks that rgCap shows where a single-peer WireGuard device
// sends its encapsulated packets, and returns the Tunnel record with the evidence
// behind it. The proof holds only when all of these are true: the endpoint is IPv4,
// since the node's rules are read for IPv4 only; the device and its egress device
// sit in the default routing domain; the node's IPv4 rules are the kernel default
// set; and the lookup is one unicast route out of the main table through an egress
// device that is neither the tunnel itself nor a VRF.
func proveWGUnderlay(set linkSet, u UnprovenTunnel, rgCap TunnelCapture, rules ruleState) (Tunnel, WireGuardProof, error) {
	if !u.Remote.Is4() {
		return Tunnel{}, WireGuardProof{}, errors.New(errIPv6Endpoint)
	}
	if rules.reason != "" {
		return Tunnel{}, WireGuardProof{}, fmt.Errorf("the underlay routing table is not proven: %s", rules.reason)
	}
	rg, err := parseRouteGet(rgCap.Data, u.Remote)
	if err != nil {
		return Tunnel{}, WireGuardProof{}, err
	}
	if rg.dev == u.Interface {
		return Tunnel{}, WireGuardProof{}, errors.New("the route lookup leaves through the tunnel's own device, so the underlay is not shown")
	}
	egress, ok := set.links[rg.dev]
	if !ok {
		return Tunnel{}, WireGuardProof{}, fmt.Errorf("the route lookup egress device %q is not in the link capture", rg.dev)
	}
	if egress.kind() == "vrf" {
		return Tunnel{}, WireGuardProof{}, errors.New("the route lookup leaves through a vrf device, which the import does not validate")
	}
	underlayVRF, err := vrfOf(set.links, egress.Name, "the underlay device")
	if err != nil {
		return Tunnel{}, WireGuardProof{}, err
	}
	if err := defaultRoutingDomains(u.VRF, underlayVRF); err != nil {
		return Tunnel{}, WireGuardProof{}, err
	}
	device := netmodel.Provenance{Source: set.capture.Source, CollectedAt: set.capture.CollectedAt}
	return Tunnel{
		Provenance:  device,
		Node:        u.Node,
		VRF:         u.VRF,
		Interface:   u.Interface,
		Remote:      u.Remote,
		UnderlayVRF: underlayVRF,
	}, WireGuardProof{
		Node:      u.Node,
		Interface: u.Interface,
		Egress:    rg.dev,
		Device:    device,
		Endpoint:  u.Endpoint,
		Lookup:    netmodel.Provenance{Source: rgCap.Source, CollectedAt: rgCap.CollectedAt},
		Rules:     rules.prov,
	}, nil
}

// ipRouteGet is the full FIB route matched for an endpoint and its unique egress.
type ipRouteGet struct {
	dev string
}

// routeGetString reads key of obj as a JSON string. present is false when the key is
// absent. A value that is not a string, including null, is an error.
func routeGetString(obj map[string]json.RawMessage, key string) (value string, present bool, err error) {
	raw, ok := obj[key]
	if !ok {
		return "", false, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil || string(bytes.TrimSpace(raw)) == "null" {
		return "", true, fmt.Errorf("has a %s field that is not a string", key)
	}
	return value, true, nil
}

// parseRouteGet reads one ip -j route get fibmatch array. It requires exactly one
// full FIB route covering the requested endpoint, with one unicast path out of the
// main table. Errors name the problem, never the bytes of the capture.
func parseRouteGet(data []byte, wantDst netip.Addr) (ipRouteGet, error) {
	elems, err := readObjects(data, "ip -j route get fibmatch")
	if err != nil {
		return ipRouteGet{}, err
	}
	if len(elems) != 1 {
		return ipRouteGet{}, fmt.Errorf("lists %d FIB route objects; the import needs exactly one", len(elems))
	}
	obj, err := object(elems[0])
	if err != nil {
		return ipRouteGet{}, err
	}
	if err := checkKeyCase(obj, "dst", "dev", "gateway", "prefsrc", "table", "protocol", "flags", "uid", "cache", "type", "error", "nexthops", "nhid"); err != nil {
		return ipRouteGet{}, err
	}
	if _, ok := obj["nhid"]; ok {
		return ipRouteGet{}, errUnresolvedNexthop
	}
	// iproute2 prints an error field as an integer, and only when it is not zero. A
	// field of any other shape cannot be read as "no error", so it refuses.
	if raw, ok := obj["error"]; ok {
		code, convErr := strconv.Atoi(string(bytes.TrimSpace(raw)))
		switch {
		case convErr != nil:
			return ipRouteGet{}, errors.New("route lookup has an error field that is not an integer")
		case code != 0:
			return ipRouteGet{}, errors.New("route lookup reports an error")
		}
	}
	typ, hasType, err := routeGetString(obj, "type")
	if err != nil {
		return ipRouteGet{}, err
	}
	if hasType && typ != "unicast" {
		if plainKernelName(typ) {
			return ipRouteGet{}, fmt.Errorf("route lookup is %s, not a unicast route", typ)
		}
		return ipRouteGet{}, errors.New("route lookup has a route type that is not a unicast route")
	}
	table, hasTable, err := routeGetString(obj, "table")
	if err != nil {
		return ipRouteGet{}, err
	}
	if hasTable && table != "main" {
		return ipRouteGet{}, errors.New("route lookup used a table other than main, which the default policy rules do not select")
	}
	if raw, ok := obj["flags"]; ok {
		var flags []string
		if err := json.Unmarshal(raw, &flags); err != nil || flags == nil {
			return ipRouteGet{}, errors.New("route lookup has a flags field that is not a list of strings")
		}
		if slices.Contains(flags, "dead") || slices.Contains(flags, "linkdown") {
			return ipRouteGet{}, errors.New("route lookup is marked dead or linkdown, so its egress device carries no traffic")
		}
	}
	dev, hasDev, err := routeGetString(obj, "dev")
	if err != nil {
		return ipRouteGet{}, err
	}
	if raw, ok := obj["nexthops"]; ok {
		var hops []json.RawMessage
		if err := json.Unmarshal(raw, &hops); err != nil || hops == nil {
			return ipRouteGet{}, errors.New("route lookup has a nexthops field that is not a list")
		}
		switch len(hops) {
		case 0:
			return ipRouteGet{}, errors.New("full FIB route has an empty nexthop set")
		case 1:
			hop, err := object(hops[0])
			if err != nil {
				return ipRouteGet{}, errors.New("full FIB route has an invalid nexthop")
			}
			if err := checkKeyCase(hop, "dev", "gateway", "weight", "flags", "onlink", "via", "encap", "nhid"); err != nil {
				return ipRouteGet{}, err
			}
			if _, ok := hop["nhid"]; ok {
				return ipRouteGet{}, errUnresolvedNexthop
			}
			if flagsRaw, ok := hop["flags"]; ok {
				var flags []string
				if err := json.Unmarshal(flagsRaw, &flags); err != nil || flags == nil {
					return ipRouteGet{}, errors.New("single FIB nexthop has a flags field that is not a list of strings")
				}
				if slices.Contains(flags, "dead") || slices.Contains(flags, "linkdown") {
					return ipRouteGet{}, errors.New("single FIB nexthop is marked dead or linkdown")
				}
			}
			hopDev, _, err := routeGetString(hop, "dev")
			if err != nil || hopDev == "" {
				return ipRouteGet{}, errors.New("single FIB nexthop names no egress device")
			}
			if hasDev && dev != hopDev {
				return ipRouteGet{}, errors.New("full FIB route has inconsistent egress devices")
			}
			dev, hasDev = hopDev, true
		default:
			return ipRouteGet{}, errAmbiguousFibRoute
		}
	}
	switch {
	case !hasDev || dev == "":
		return ipRouteGet{}, errors.New("route lookup names no egress device")
	case !validIfaceName(dev):
		return ipRouteGet{}, errors.New("route lookup egress device is not a valid Linux interface name")
	}
	dst, _, err := routeGetString(obj, "dst")
	if err != nil {
		return ipRouteGet{}, err
	}
	if !fibRouteContains(dst, wantDst) {
		return ipRouteGet{}, errors.New("full FIB route destination does not cover the peer endpoint")
	}
	return ipRouteGet{dev: dev}, nil
}

// fibRouteContains accepts the destination prefix printed by fibmatch and the
// address form printed for host routes. A FIB entry is useful only if it covers
// the exact WireGuard peer endpoint.
func fibRouteContains(dst string, want netip.Addr) bool {
	if dst == "default" {
		return want.Is4()
	}
	if prefix, err := netip.ParsePrefix(dst); err == nil {
		return prefix.Addr().Is4() == want.Is4() && prefix.Contains(want)
	}
	addr, err := netip.ParseAddr(dst)
	return err == nil && addr == want
}

// linkSet is the one ip -d -j link capture a node has in an import, with its
// devices by name.
type linkSet struct {
	capture TunnelCapture
	links   map[string]ipLink
}

// ipLink is one object of ip -d -j link. Only the keys named here are read, so a
// key a newer iproute2 adds cannot change what the importer reads. raw holds every
// key the object lists, for the presence checks a fallback device needs.
type ipLink struct {
	Name      string          `json:"ifname"`
	Index     int             `json:"ifindex"`
	Master    string          `json:"master"`
	Link      string          `json:"link"`
	LinkType  string          `json:"link_type"`
	NetnsID   json.RawMessage `json:"link_netnsid"`
	Address   string          `json:"address"`
	Flags     []string        `json:"flags"`
	OperState string          `json:"operstate"`
	Info      *ipLinkInfo     `json:"linkinfo"`
	raw       map[string]json.RawMessage
}

// ipLinkInfo is a device's linkinfo object. keys holds every key the object lists,
// so an attribute the import does not read is seen rather than skipped.
type ipLinkInfo struct {
	Kind string                     `json:"info_kind"`
	Data map[string]json.RawMessage `json:"info_data"`
	keys map[string]json.RawMessage
}

// watchedInfoKeys are the info_data attributes that can change where a device's
// packets go or whether it is keyed. A spelling of one of them in another case is
// refused, since encoding/json would match it silently.
var watchedInfoKeys = []string{"external", "fwmark", "ikey", "okey", "key", "iseq", "oseq", "csum", "icsum", "ocsum", "local", "remote", "proto", "ttl", "pmtudisc", "erspan_index", "erspan_ver"}

// kind is the device kind ip -d -j link prints, or empty for a device with none.
func (l ipLink) kind() string {
	if l.Info == nil {
		return ""
	}
	return l.Info.Kind
}

// modeledNodes lists the nodes m holds a configured, control, or fib observation
// for, sorted. Only these nodes can hold a tunnel record, so each one needs a usable
// ip -d -j link capture before the import is complete. Observations of other planes,
// such as intended and observed, do not make a node modeled.
func modeledNodes(m netmodel.Model) []string {
	var out []string
	for _, o := range m.Observations() {
		if slices.Contains(readPlanes, o.Plane) && !slices.Contains(out, o.Node) {
			out = append(out, o.Node)
		}
	}
	slices.Sort(out)
	return out
}

// plainKinds are the device kinds that carry no tunnel, so reading them adds
// nothing to a topology. A vrf is a routing domain, but the import reads no route
// table, so naming one adds nothing either. A device of any other kind is refused,
// since the import has not read what it carries.
var plainKinds = map[string]bool{"vrf": true, "bridge": true, "bond": true, "vlan": true, "macvlan": true, "ipvlan": true, "veth": true, "dummy": true}

// ruleState is what one node's ip -j rule show captures prove. reason is empty when
// the rules are the kernel default set, and prov is then the capture that shows
// it. Otherwise reason says why the rules do not prove a gre underlay.
type ruleState struct {
	prov   netmodel.Provenance
	reason string
}

// proveRules reads the rules capture of node, if it has exactly one. Zero captures
// and several captures both leave the node's rules unproven, and a capture whose
// rules are not the kernel default set is refused with the rule that differs.
func (r *TunnelImport) proveRules(node string, list []TunnelCapture) ruleState {
	switch len(list) {
	case 0:
		return ruleState{reason: fmt.Sprintf("node %s has no ip -j rule show capture, so its policy rules are not shown", node)}
	case 1:
	default:
		for _, c := range list {
			r.refuse(c.Source, c.Node, "", fmt.Sprintf("node %s has %d ip -j rule show captures; the import needs one", node, len(list)))
		}
		return ruleState{reason: fmt.Sprintf("node %s has %d ip -j rule show captures, so its policy rules are not shown", node, len(list))}
	}
	c := list[0]
	if err := checkDefaultRules(c.Data); err != nil {
		r.refuse(c.Source, c.Node, "", err.Error())
		return ruleState{reason: fmt.Sprintf("node %s: %v", node, err)}
	}
	return ruleState{prov: netmodel.Provenance{Source: c.Source, CollectedAt: c.CollectedAt}}
}

// kernelRules are the IPv4 policy rules every Linux kernel starts with, by
// priority, with the table each one names.
var kernelRules = map[int]string{0: "local", 32766: "main", 32767: "default"}

// ruleKeys are the only keys of an ip -j rule show object the import reads. A
// rule must carry each one, and each exactly once.
var ruleKeys = []string{"priority", "src", "table"}

// errNotRule is the refusal for a rule capture that is not ip -j rule show output: a
// value that is not an object, or a key that is not a string.
var errNotRule = errors.New("is not ip -j rule show output")

// errRuleKey is the refusal for a rule that carries a key the import does not read.
// A kernel default rule prints only priority, src, and table, so any other key makes
// it a policy rule the import cannot show to be default. The key is not named.
var errRuleKey = errors.New("a rule has a key the import does not read, so it cannot be a kernel default rule")

// ipRule is one ip -j rule show object whose keys are all present and exact.
type ipRule struct {
	Priority int
	Src      string
	Table    string
}

// checkDefaultRules reads one ip -j rule show array and reports the first way it
// is not the kernel default set: a rule the import cannot read exactly, a rule
// count other than three, a priority outside the default set or listed twice, a
// source other than all sources, or a table other than the default one for its
// priority. Errors name the rule, never the bytes of the capture.
func checkDefaultRules(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var objs []json.RawMessage
	if err := dec.Decode(&objs); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return fmt.Errorf("is not valid JSON at byte %d", syntax.Offset)
		}
		return errNotRule
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("has data after the ip -j rule show array")
	}
	rules := make([]ipRule, 0, len(objs))
	for _, obj := range objs {
		r, err := parseRule(obj)
		if err != nil {
			return err
		}
		rules = append(rules, r)
	}
	if len(rules) != len(kernelRules) {
		return fmt.Errorf("lists %d IPv4 policy rules; the kernel default set has %d", len(rules), len(kernelRules))
	}
	listed := map[int]bool{}
	for _, r := range rules {
		want, ok := kernelRules[r.Priority]
		switch {
		case !ok:
			return errors.New("a rule has a priority that is not one of the kernel default rules")
		case listed[r.Priority]:
			return fmt.Errorf("policy rule at priority %d is listed twice", r.Priority)
		case r.Src != "all":
			return fmt.Errorf("policy rule at priority %d selects by a source other than all sources", r.Priority)
		case r.Table != want:
			return fmt.Errorf("policy rule at priority %d looks up a table other than %s", r.Priority, want)
		}
		listed[r.Priority] = true
	}
	return nil
}

// parseRule reads one ip -j rule show object. Its keys must be exact and each
// present once, and its values must have the types the import needs. The
// priority must be an integer literal that prints back as written, so "-0" and
// "null" are refused.
func parseRule(obj json.RawMessage) (ipRule, error) {
	fields, err := ruleFields(obj)
	if err != nil {
		return ipRule{}, err
	}
	prio := string(fields["priority"])
	n, err := strconv.Atoi(prio)
	if err != nil || strconv.Itoa(n) != prio {
		return ipRule{}, errors.New("a rule has a priority that is not an integer")
	}
	src, ok := jsonString(fields["src"])
	if !ok {
		return ipRule{}, errors.New("a rule has a source that is not a string")
	}
	table, ok := jsonString(fields["table"])
	if !ok {
		return ipRule{}, errors.New("a rule has a table that is not a string")
	}
	return ipRule{Priority: n, Src: src, Table: table}, nil
}

// ruleFields maps each key of one rule object to its raw value. It refuses any
// key the import does not read, any key that repeats, and any key that is
// missing. Errors name the key, never its value.
func ruleFields(obj json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(obj))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errNotRule
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			return nil, errNotRule
		}
		if !slices.Contains(ruleKeys, key) {
			return nil, errRuleKey
		}
		if _, repeated := fields[key]; repeated {
			return nil, fmt.Errorf("a rule repeats its %s, so its value is ambiguous", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, errNotRule
		}
		fields[key] = value
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errNotRule
	}
	for _, key := range ruleKeys {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("a rule has no %s, so it cannot be shown to be a default rule", key)
		}
	}
	return fields, nil
}

// isNull reports whether a raw JSON value is the literal null.
func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// namedValue names a kind or link type the capture supplied. A value the kernel could
// print is quoted; any other is not echoed, since the capture is untrusted input.
func namedValue(what, v string) string {
	if !plainKernelName(v) {
		return "a " + what
	}
	return fmt.Sprintf("%s %q", what, v)
}

// plainKernelName reports whether v has the shape of a kernel link kind or link type
// name: 1 to 32 bytes of lowercase letters, digits, and underscores, starting with a
// letter.
func plainKernelName(v string) bool {
	if v == "" || len(v) > 32 || v[0] < 'a' || v[0] > 'z' {
		return false
	}
	for i := range len(v) {
		c := v[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// jsonString reads a raw JSON value that must be a string. A null is not one.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// underlayProven says why a gre device's underlay routing table is not proven, or
// returns nil when it is. The device and its underlay device must sit in the
// default routing domain, and the node's IPv4 rules must be the kernel default set.
// Then every IPv4 lookup of the encapsulated packet ends in the main table, whichever
// device it leaves by, so the table is known from these facts alone.
func underlayProven(w wireTunnel, rules ruleState) error {
	if err := defaultRoutingDomains(w.VRF, w.UnderlayVRF); err != nil {
		return err
	}
	if rules.reason != "" {
		return fmt.Errorf("the underlay routing table is not proven: %s", rules.reason)
	}
	return nil
}

// defaultRoutingDomains gives GRE and WireGuard the same conservative domain check.
// A captured route can support a tunnel record only when both devices are in default.
func defaultRoutingDomains(tunnelVRF, underlayVRF string) error {
	switch {
	case tunnelVRF != "default":
		return errors.New("the tunnel is enslaved to a vrf, which the import does not validate")
	case underlayVRF != "default":
		return errors.New("the underlay device is enslaved to a vrf, which the import does not validate")
	}
	return nil
}

// parseIPLink reads one ip -d -j link array. Errors give a byte offset or a fixed
// phrase, never the bytes themselves.
func parseIPLink(data []byte) ([]ipLink, error) {
	elems, err := readObjects(data, TunnelCommandIPLink)
	if err != nil {
		return nil, err
	}
	// Linux always lists at least lo, so an empty list, or JSON null, is a capture
	// that shows no inventory. It must not read as a node with no devices.
	if len(elems) == 0 {
		return nil, errors.New("lists no devices, so it shows no device inventory")
	}
	links := make([]ipLink, 0, len(elems))
	for _, raw := range elems {
		l, err := decodeIPLink(raw)
		if err != nil {
			return nil, err
		}
		links = append(links, l)
	}
	return links, nil
}

// decodeIPLink reads one device object. A key repeated in it, or spelled in another
// case than the one the import reads, refuses the object, since encoding/json would
// otherwise keep one value or match the key to a field silently.
func decodeIPLink(raw json.RawMessage) (ipLink, error) {
	obj, err := object(raw)
	if err != nil {
		return ipLink{}, err
	}
	if err := checkKeyCase(obj, "ifname", "ifindex", "master", "link", "link_type", "link_netnsid", "address", "flags", "operstate", "linkinfo", "netns-immutable"); err != nil {
		return ipLink{}, err
	}
	// iproute2 never prints these fields as null, so a null is a capture the import
	// cannot read, not a zero. "link" is not here: every device with no underlay
	// prints "link": null, which is its normal shape.
	for _, key := range []string{"ifname", "ifindex", "link_type", "address", "flags", "operstate", "linkinfo"} {
		if raw, ok := obj[key]; ok && isNull(raw) {
			return ipLink{}, fmt.Errorf("has a null %s, where the import needs a value", key)
		}
	}
	var l ipLink
	if err := json.Unmarshal(raw, &l); err != nil {
		return ipLink{}, errors.New("has a field of the wrong type")
	}
	l.raw = obj
	if l.Info != nil {
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(obj["linkinfo"], &keys); err != nil {
			return ipLink{}, errors.New("has a linkinfo of the wrong type")
		}
		if err := checkKeyCase(keys, "info_kind", "info_data"); err != nil {
			return ipLink{}, err
		}
		// A device with no kind is accepted as plain ethernet, and a bridge or VRF port
		// with no kind of its own prints only info_slave_kind. So only a null kind, or
		// info data with no kind, is refused: either could hide a gre device.
		kind, hasKind := keys["info_kind"]
		_, hasData := keys["info_data"]
		if hasKind && isNull(kind) || !hasKind && hasData {
			return ipLink{}, errors.New("has a linkinfo with no kind")
		}
		if err := checkKeyCase(l.Info.Data, watchedInfoKeys...); err != nil {
			return ipLink{}, err
		}
		l.Info.keys = keys
	}
	return l, nil
}

// readObjects reads one JSON array and returns each element's bytes. A syntax error,
// data after the array, or a null in place of the array is refused with a byte offset
// or a fixed phrase. An empty array is kept: it is what the kernel prints for none.
func readObjects(data []byte, command string) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var elems []json.RawMessage
	if err := dec.Decode(&elems); err != nil {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			return nil, fmt.Errorf("is not valid JSON at byte %d", syntax.Offset)
		}
		return nil, fmt.Errorf("is not %s output", command)
	}
	if elems == nil {
		return nil, fmt.Errorf("is not %s output", command)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("has data after the %s array", command)
	}
	return elems, nil
}

// object reads one array element as a JSON object. A key repeated in it, or in an
// object it holds, refuses the element. The error never names the key.
func object(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dup, err := hasRepeatedKey(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return nil, errors.New("is not valid JSON")
	}
	if dup {
		return nil, errors.New("repeats a key in one object, so one of its values is not known")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errors.New("has an element that is not an object")
	}
	return obj, nil
}

// hasRepeatedKey reports whether the next JSON value repeats a key in any object it
// holds, at any depth. encoding/json keeps the last of two equal keys, so a repeat
// would otherwise change what is read without any sign.
func hasRepeatedKey(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return false, nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			kt, err := dec.Token()
			if err != nil {
				return false, err
			}
			key, _ := kt.(string)
			if seen[key] {
				return true, nil
			}
			seen[key] = true
		}
		if dup, err := hasRepeatedKey(dec); dup || err != nil {
			return dup, err
		}
	}
	_, err = dec.Token()
	return false, err
}

// checkKeyCase refuses a key of obj spelled in another case than one of names, since
// encoding/json would match it to that name silently. A key that no name is close to
// is left alone, because iproute2 prints fields the import has no reason to read.
// The error names the spelling the import reads, never the key it found.
func checkKeyCase(obj map[string]json.RawMessage, names ...string) error {
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		for _, name := range names {
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("has a key that differs from %q only in case", name)
			}
		}
	}
	return nil
}

// indexLinks keys one capture's devices by name. A name listed twice makes the
// capture ambiguous, so the whole capture is refused.
func indexLinks(entries []ipLink) (map[string]ipLink, error) {
	out := make(map[string]ipLink, len(entries))
	for _, l := range entries {
		if l.Name == "" {
			return nil, errors.New("has a device with no ifname")
		}
		if _, dup := out[l.Name]; dup {
			return nil, errors.New("lists an interface twice")
		}
		out[l.Name] = l
	}
	return out, nil
}

// vrfOf names the routing domain of a device as ip -d -j link shows it. A device
// with no master is in the default domain. A master names the domain only when
// the same capture lists it as a vrf device, so the domain is the master's name.
// Any other master is refused. subject says which device the error is about.
func vrfOf(links map[string]ipLink, name, subject string) (string, error) {
	master := links[name].Master
	if master == "" {
		return "default", nil
	}
	if m, ok := links[master]; ok && m.Info != nil && m.Info.Kind == "vrf" {
		return master, nil
	}
	return "", fmt.Errorf("%s is enslaved to a device the capture does not show as a vrf", subject)
}

// tunnelFromLink reads one gre or ipip device. Its remote must be one IPv4
// address, and its underlay device must be in the same capture, so the underlay
// routing domain is the one that device's master names.
func tunnelFromLink(c TunnelCapture, links map[string]ipLink, l ipLink) (wireTunnel, error) {
	if raw := l.NetnsID; len(raw) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		return wireTunnel{}, errors.New("has a link_netnsid, so its underlay device is in another network namespace")
	}
	if raw, ok := l.Info.Data["external"]; ok && string(bytes.TrimSpace(raw)) != "false" {
		return wireTunnel{}, errors.New("is externally controlled, so the device does not hold its remote")
	}
	remote, err := singleRemote(l.Info.Data["remote"])
	if err != nil {
		return wireTunnel{}, err
	}
	if l.Link == "" {
		return wireTunnel{}, errors.New("names no underlay device, so its underlay routing domain is not proven")
	}
	if _, ok := links[l.Link]; !ok {
		return wireTunnel{}, errors.New("its underlay device is not in the capture")
	}
	vrf, err := vrfOf(links, l.Name, "the tunnel")
	if err != nil {
		return wireTunnel{}, err
	}
	underlay, err := vrfOf(links, l.Link, "the underlay device")
	if err != nil {
		return wireTunnel{}, err
	}
	return wireTunnel{
		Source:      c.Source,
		CollectedAt: utcText(c.CollectedAt),
		Node:        c.Node,
		VRF:         vrf,
		Interface:   l.Name,
		Remote:      remote,
		UnderlayVRF: underlay,
	}, nil
}

// singleRemote reads the remote of a gre or ipip device. It must be one IPv4
// unicast address. "any" is the multipoint form, and it is refused.
func singleRemote(raw json.RawMessage) (string, error) {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil || s == "" {
		return "", errors.New("names no remote")
	}
	if s == "any" {
		return "", errors.New("remote any is a multipoint tunnel, which names no single remote")
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("remote is not an IP address")
	}
	if a.Is6() {
		return "", errors.New("remote is IPv6; gre and ipip are read as IPv4 here")
	}
	return s, nil
}

// wgIface is one interface of a wg show all dump, with the peers that follow it.
type wgIface struct {
	name   string
	fwmark string
	peers  []wgPeer
}

// wgPeer keeps the one column of a peer line the importer reads. The public key,
// preshared key, and allowed IPs are not kept, so no key leaves the parse.
type wgPeer struct {
	endpoint string
}

// wgFact is one interface of one dump, with the capture it came from.
type wgFact struct {
	capture TunnelCapture
	iface   wgIface
}

// parseWGDump reads a wg show all dump. An interface line has five tab-separated
// fields and a peer line has nine. The parse copies a name, a fwmark, and an
// endpoint, and nothing else. A name must pass validIfaceName first. No name and no
// field is ever echoed: errors give a line number and a field count, never the line,
// since a line holds private and preshared keys.
func parseWGDump(data []byte) ([]wgIface, error) {
	text := strings.TrimSuffix(string(data), "\n")
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("is empty")
	}
	var out []wgIface
	index := map[string]int{}
	for n, line := range strings.Split(text, "\n") {
		no := n + 1
		f := strings.Split(line, "\t")
		if (len(f) == 5 || len(f) == 9) && !validIfaceName(f[0]) {
			return nil, fmt.Errorf("line %d names an interface that is not a Linux interface name", no)
		}
		switch len(f) {
		case 5:
			if _, dup := index[f[0]]; dup {
				return nil, fmt.Errorf("line %d repeats an interface", no)
			}
			index[f[0]] = len(out)
			out = append(out, wgIface{name: f[0], fwmark: f[4]})
		case 9:
			i, ok := index[f[0]]
			if !ok {
				return nil, fmt.Errorf("line %d is a peer line with no interface line before it", no)
			}
			out[i].peers = append(out[i].peers, wgPeer{endpoint: f[3]})
		default:
			return nil, fmt.Errorf("line %d has %d fields; an interface line has 5 and a peer line has 9", no, len(f))
		}
	}
	return out, nil
}

// validIfaceName reports whether s can name a Linux interface, after the kernel's
// own rules: at most 15 bytes, none of them a space, control byte, "/", or ":",
// and not "." or "..". Only a name that passes is ever echoed in an error.
func validIfaceName(s string) bool {
	if s == "" || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, c := range []byte(s) {
		if c <= ' ' || c >= 0x7f || c == '/' || c == ':' {
			return false
		}
	}
	return true
}

// sameWGFacts reports whether two dumps give one interface the same fwmark and
// the same endpoints. Peer keys are not kept, so two dumps that differ only in a
// key agree here.
func sameWGFacts(a, b wgIface) bool {
	return a.fwmark == b.fwmark && slices.EqualFunc(a.peers, b.peers, func(x, y wgPeer) bool { return x.endpoint == y.endpoint })
}

// wgPartner returns the source of a dump in group that disagrees with f about the
// interface, and false when every dump in group agrees with f.
func wgPartner(group []wgFact, f wgFact) (string, bool) {
	for _, g := range group {
		if !sameWGFacts(f.iface, g.iface) {
			return g.capture.Source, true
		}
	}
	return "", false
}

// wgEndpoint reads one WireGuard interface of a dump into an unproven tunnel. The
// device must be a wireguard device in its node's ip capture, in one routing
// domain, and the dump must give it exactly one peer that names an endpoint. A
// set fwmark steers the endpoint lookup by policy rule, which no capture records,
// so it is refused. An off fwmark does not prove the lookup's routing domain
// either, since policy rules can match other selectors. The dump names no routing
// domain, and the ip capture names only the device's own, so the endpoint's
// domain is unknown here.
func wgEndpoint(set linkSet, c TunnelCapture, w wgIface) (UnprovenTunnel, error) {
	l, ok := set.links[w.name]
	if !ok {
		return UnprovenTunnel{}, fmt.Errorf("is not in the ip -d -j link capture of %s", c.Node)
	}
	if l.Info == nil || l.Info.Kind != "wireguard" {
		return UnprovenTunnel{}, errors.New("is not a wireguard device in the ip -d -j link capture")
	}
	vrf, err := vrfOf(set.links, w.name, "the device")
	if err != nil {
		return UnprovenTunnel{}, err
	}
	if w.fwmark != "off" {
		return UnprovenTunnel{}, errors.New("has a fwmark, which steers the endpoint lookup by policy rule that the capture does not record")
	}
	switch len(w.peers) {
	case 0:
		return UnprovenTunnel{}, errors.New("has no peer, so it names no remote")
	case 1:
	default:
		return UnprovenTunnel{}, fmt.Errorf("has %d peers; a single-remote tunnel needs exactly one", len(w.peers))
	}
	p := w.peers[0]
	if p.endpoint == "(none)" {
		return UnprovenTunnel{}, errors.New("its peer names no endpoint, so no remote is proven")
	}
	ap, err := netip.ParseAddrPort(p.endpoint)
	if err != nil {
		return UnprovenTunnel{}, errors.New("its peer endpoint is not an address and port")
	}
	if err := checkRemote(ap.Addr()); err != nil {
		return UnprovenTunnel{}, err
	}
	return UnprovenTunnel{
		Node:      c.Node,
		VRF:       vrf,
		Interface: w.name,
		Remote:    ap.Addr(),
		Device:    netmodel.Provenance{Source: set.capture.Source, CollectedAt: set.capture.CollectedAt},
		Endpoint:  netmodel.Provenance{Source: c.Source, CollectedAt: c.CollectedAt},
	}, nil
}

// MergeTunnelImport adds the tunnels of an import to base. The import must be
// complete: it refuses nothing and lists nothing unproven, so each candidate the
// captures showed is either a record or was never a tunnel. A record that base
// already holds for the same node, VRF, and interface is refused, not chosen
// between. The merged tunnels keep the order Decode gives them.
func MergeTunnelImport(base File, imp TunnelImport) (File, error) {
	if len(imp.Unproven) > 0 || len(imp.Refused) > 0 || len(imp.Uncovered) > 0 {
		return File{}, fmt.Errorf("the import is incomplete: %d refused, %d unproven, %d without a usable capture", len(imp.Refused), len(imp.Unproven), len(imp.Uncovered))
	}
	out := base
	out.Tunnels = slices.Clone(base.Tunnels)
	for _, t := range imp.Tunnels {
		if slices.ContainsFunc(out.Tunnels, func(b Tunnel) bool { return compareTunnels(b, t) == 0 }) {
			return File{}, fmt.Errorf("the base topology already has a tunnel on %s (%s) %s", t.Node, t.VRF, t.Interface)
		}
		out.Tunnels = append(out.Tunnels, t)
	}
	slices.SortFunc(out.Tunnels, compareTunnels)
	return out, nil
}
