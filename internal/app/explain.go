package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/ospf"
	"github.com/heymaikol/network-doctor/v2/internal/routepath"
	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// runExplain explains how traffic to one destination should leave the network
// described in a topology file. Like compare, it reads what it is given and
// sends nothing, so no probe setting applies. It exits 0 once it has an
// explanation, including one that says the path is broken, and 2 when the
// input cannot be read, the destination is not an address, or the failure to
// simulate is not in the file.
func runExplain(paths []string, setFlags map[string]bool, jsonOut bool, fail, failOSPF, failNextHop string, stdout, stderr io.Writer) int {
	if rejectRunFlags("explain", setFlags, stderr) {
		return 2
	}
	if len(paths) != 2 {
		fmt.Fprintln(stderr, "netdoc: -explain needs a topology file and a destination: netdoc --explain topology.json DEST")
		return 2
	}
	dest, err := explainDestination(paths[1])
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -explain: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	data, err := readTopologyFile(paths[0])
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -explain: %s\n", textsafe.Clean(err.Error()))
		return 2
	}
	file, err := routepath.Decode(data)
	if err != nil {
		fmt.Fprintf(stderr, "netdoc: -explain: %s: %s\n", textsafe.Clean(paths[0]), textsafe.Clean(err.Error()))
		return 2
	}
	result := routepath.Explain(file, dest)
	var sim *routepath.Simulation
	simText := ""
	flag, failure := "fail", routepath.Failure{}
	if fail != "" {
		node, iface, colon := strings.Cut(fail, ":")
		if colon && iface == "" {
			fmt.Fprintf(stderr, "netdoc: -fail: %q names no interface after the colon\n", fail)
			return 2
		}
		failure = routepath.Failure{Node: node, Interface: iface}
	}
	if failOSPF != "" {
		// The node ends at the first colon and the neighbor starts after the
		// last, so an interface name may hold colons and the two names may not.
		node, rest, _ := strings.Cut(failOSPF, ":")
		cut := strings.LastIndex(rest, ":")
		if node == "" || cut <= 0 || cut == len(rest)-1 {
			fmt.Fprintf(stderr, "netdoc: -fail-ospf: %q is not node:interface:neighbor\n", failOSPF)
			return 2
		}
		flag, failure = "fail-ospf", routepath.Failure{Node: node, Interface: rest[:cut], OSPFNeighbor: rest[cut+1:]}
	}
	if failNextHop != "" {
		node, vrf, addr, iface, ok := splitNextHop(failNextHop)
		if !ok {
			fmt.Fprintf(stderr, "netdoc: -fail-next-hop: %q is not node[@vrf]:address[%%interface]\n", failNextHop)
			return 2
		}
		flag, failure = "fail-next-hop", routepath.Failure{Node: node, VRF: vrf, NextHop: addr, Interface: iface}
	}
	if fail != "" || failOSPF != "" || failNextHop != "" {
		s, err := routepath.Simulate(file, failure, dest)
		if err != nil {
			fmt.Fprintf(stderr, "netdoc: -%s: %s\n", flag, textsafe.Clean(err.Error()))
			return 2
		}
		sim, simText = &s, s.Text()
	}
	report := ospf.Analyze(file.Model)
	if jsonOut {
		out := explainOutput{Explanation: result, Failure: sim}
		if len(report.Findings) > 0 {
			out.OSPF = &report
		}
		encoded, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
		fmt.Fprintln(stdout, string(encoded))
		return 0
	}
	fmt.Fprint(stdout, result.Text()+simText+report.Text())
	return 0
}

// splitNextHop splits a -fail-next-hop selector. The node ends at the first
// colon, so an IPv6 address keeps its colons, and a routing domain follows the
// node after the first at sign. The interface starts at the first percent sign
// after the colon, so an interface name may hold colons and percent signs, and
// a node name may hold neither a colon nor an at sign. The address is checked
// by routepath, which reads it against the file.
func splitNextHop(s string) (node, vrf, addr, iface string, ok bool) {
	head, rest, colon := strings.Cut(s, ":")
	node, vrf, at := strings.Cut(head, "@")
	addr, iface, pct := strings.Cut(rest, "%")
	return node, vrf, addr, iface, colon && node != "" && (!at || vrf != "") && addr != "" && (!pct || iface != "")
}

// explainOutput is the --explain JSON object. Its failure field is present only
// with -fail, -fail-ospf, or -fail-next-hop, and its ospf field only when the
// topology holds OSPF evidence that yields a finding, so any other run encodes
// the same bytes as routepath.Explanation.JSON.
type explainOutput struct {
	routepath.Explanation
	Failure *routepath.Simulation `json:"failure,omitempty"`
	OSPF    *ospf.Report          `json:"ospf,omitempty"`
}

// explainDestination takes an address literal only. A name would need a
// resolver, and which resolver answers decides which route is under test, so
// the name is refused rather than resolved.
func explainDestination(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("destination %q must be an IP address; -explain resolves no names", s)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, errors.New("destination must not carry an interface zone")
	}
	return addr, nil
}

// readTopologyFile reads the file the user named, and stops one byte past the
// limit so an oversized file is refused without being read whole.
func readTopologyFile(path string) ([]byte, error) {
	// #nosec G304 -- the path is the user's own argument, and reading the
	// file they named is the whole command.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() // #nosec G104 -- read-only handle; a close error cannot affect data already read
	return io.ReadAll(io.LimitReader(f, routepath.MaxFileBytes+1))
}
