package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/heymaikol/network-doctor/internal/ospf"
	"github.com/heymaikol/network-doctor/internal/routepath"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// runExplain explains how traffic to one destination should leave the network
// described in a topology file. Like compare, it reads what it is given and
// sends nothing, so no probe setting applies. It exits 0 once it has an
// explanation, including one that says the path is broken, and 2 when the
// input cannot be read or the destination is not an address.
func runExplain(paths []string, setFlags map[string]bool, jsonOut bool, stdout, stderr io.Writer) int {
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
	report := ospf.Analyze(file.Model)
	if jsonOut {
		out := explainOutput{Explanation: result}
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
	fmt.Fprint(stdout, result.Text()+report.Text())
	return 0
}

// explainOutput is the --explain JSON object. Its ospf field is present only
// when the topology holds OSPF evidence that yields a finding, so any other file
// encodes the same bytes as routepath.Explanation.JSON.
type explainOutput struct {
	routepath.Explanation
	OSPF *ospf.Report `json:"ospf,omitempty"`
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
