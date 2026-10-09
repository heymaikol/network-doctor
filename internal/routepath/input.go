package routepath

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// FileVersion is the topology file format this build reads. A file must state
// it, so a later format can never be read as this one by accident.
const FileVersion = 1

// MaxFileBytes bounds a topology file. A lab of a few hundred routers is far
// below it, and the limit keeps a wrong path from exhausting memory.
const MaxFileBytes = 1 << 20

// The wire types are the JSON form of a topology file. netmodel keeps no JSON
// tags, because its canonical ordering breaks ties with json.Marshal, and a tag
// would change that order.
type wireFile struct {
	Version      int               `json:"version"`
	Source       wireStart         `json:"source"`
	Observations []wireObservation `json:"observations"`
	Checks       []wireCheck       `json:"checks"`
	Boundaries   []wireBoundary    `json:"boundaries"`
}

type wireStart struct {
	Node    string `json:"node"`
	VRF     string `json:"vrf"`
	Address string `json:"address"`
}

type wireBoundary struct {
	Source      string `json:"source"`
	CollectedAt string `json:"collected_at"`
	Node        string `json:"node"`
	VRF         string `json:"vrf"`
	Kind        string `json:"kind"`
}

type wireObservation struct {
	Source         string          `json:"source"`
	CollectedAt    string          `json:"collected_at"`
	Plane          string          `json:"plane"`
	Node           string          `json:"node"`
	VRF            string          `json:"vrf"`
	RoutesComplete bool            `json:"routes_complete"`
	Interfaces     []wireInterface `json:"interfaces"`
	Neighbors      []wireNeighbor  `json:"neighbors"`
	Routes         []wireRoute     `json:"routes"`
}

type wireInterface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

type wireNeighbor struct {
	LocalInterface  string `json:"local_interface"`
	RemoteNode      string `json:"remote_node"`
	RemoteInterface string `json:"remote_interface"`
	RemoteAddr      string `json:"remote_addr"`
}

type wireRoute struct {
	Prefix   string        `json:"prefix"`
	Origin   string        `json:"origin"`
	Metric   *uint32       `json:"metric"`
	Discard  bool          `json:"discard"`
	NextHops []wireNextHop `json:"next_hops"`
}

type wireNextHop struct {
	Addr      string `json:"addr"`
	Interface string `json:"interface"`
}

type wireCheck struct {
	Source      string `json:"source"`
	CollectedAt string `json:"collected_at"`
	Node        string `json:"node"`
	VRF         string `json:"vrf"`
	Interface   string `json:"interface"`
	Destination string `json:"destination"`
	NextHop     string `json:"next_hop"`
	Result      string `json:"result"`
}

// Decode reads a topology file. Unknown fields are rejected, so a misspelled key
// cannot silently drop evidence, and a model that netmodel refuses is refused
// here with the reason.
func Decode(data []byte) (File, error) {
	if len(data) > MaxFileBytes {
		return File{}, fmt.Errorf("exceeds the maximum topology size of %d bytes", MaxFileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var w wireFile
	if err := dec.Decode(&w); err != nil {
		return File{}, fmt.Errorf("invalid topology file: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return File{}, errors.New("invalid topology file: data follows the topology object")
	}
	switch {
	case w.Version == 0:
		return File{}, fmt.Errorf(`topology file needs "version": %d`, FileVersion)
	case w.Version != FileVersion:
		return File{}, fmt.Errorf(`topology file version %d is not supported; this netdoc reads "version": %d`, w.Version, FileVersion)
	case w.Source.Node == "" || w.Source.VRF == "":
		return File{}, errors.New(`topology file "source" needs a node and a vrf`)
	}

	obs := make([]netmodel.Observation, 0, len(w.Observations))
	for i, wo := range w.Observations {
		o, err := observation(wo)
		if err != nil {
			return File{}, fmt.Errorf("observation %d: %w", i, err)
		}
		obs = append(obs, o)
	}
	m, err := netmodel.New(obs...)
	if err != nil {
		return File{}, fmt.Errorf("invalid topology: %w", err)
	}

	checks := make([]Check, 0, len(w.Checks))
	for i, wc := range w.Checks {
		c, err := decodeCheck(wc)
		if err != nil {
			return File{}, fmt.Errorf("check %d: %w", i, err)
		}
		checks = append(checks, c)
	}
	srcAddr, err := optionalAddr(w.Source.Address)
	if err != nil {
		return File{}, fmt.Errorf(`topology file "source" address: %w`, err)
	}
	bounds := make([]Boundary, 0, len(w.Boundaries))
	for i, wb := range w.Boundaries {
		b, err := decodeBoundary(wb)
		if err != nil {
			return File{}, fmt.Errorf("boundary %d: %w", i, err)
		}
		bounds = append(bounds, b)
	}
	slices.SortFunc(bounds, compareBoundaries)
	return File{
		Source:     Start{Node: w.Source.Node, VRF: w.Source.VRF},
		SourceAddr: srcAddr,
		Model:      m,
		Checks:     checks,
		Boundaries: bounds,
	}, nil
}

func decodeBoundary(w wireBoundary) (Boundary, error) {
	at, err := parseTime(w.CollectedAt)
	if err != nil {
		return Boundary{}, err
	}
	if w.Source == "" || w.Node == "" || w.VRF == "" {
		return Boundary{}, errors.New("needs source, node, and vrf")
	}
	kind := BoundaryKind(w.Kind)
	switch kind {
	case BoundaryStatefulFirewall, BoundaryNAT, BoundaryTunnel:
	default:
		return Boundary{}, fmt.Errorf(`kind %q is not "stateful_firewall", "nat", or "tunnel"`, w.Kind)
	}
	return Boundary{
		Provenance: netmodel.Provenance{Source: w.Source, CollectedAt: at},
		Node:       w.Node,
		VRF:        w.VRF,
		Kind:       kind,
	}, nil
}

// compareBoundaries orders boundaries by every field, provenance included, so
// two rows that differ only in source still sort the same way in any file order.
func compareBoundaries(a, b Boundary) int {
	return cmp.Or(
		cmp.Compare(a.Node, b.Node),
		cmp.Compare(a.VRF, b.VRF),
		cmp.Compare(string(a.Kind), string(b.Kind)),
		cmp.Compare(a.Source, b.Source),
		a.CollectedAt.Compare(b.CollectedAt),
	)
}

func observation(w wireObservation) (netmodel.Observation, error) {
	at, err := parseTime(w.CollectedAt)
	if err != nil {
		return netmodel.Observation{}, err
	}
	o := netmodel.Observation{
		Provenance:     netmodel.Provenance{Source: w.Source, CollectedAt: at},
		Plane:          netmodel.Plane(w.Plane),
		Node:           w.Node,
		VRF:            w.VRF,
		RoutesComplete: w.RoutesComplete,
	}
	for _, wi := range w.Interfaces {
		i := netmodel.Interface{Name: wi.Name}
		for _, a := range wi.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return netmodel.Observation{}, fmt.Errorf("interface %q address %q: %w", wi.Name, a, err)
			}
			i.Addresses = append(i.Addresses, p)
		}
		o.Interfaces = append(o.Interfaces, i)
	}
	for _, wn := range w.Neighbors {
		n := netmodel.Neighbor{LocalInterface: wn.LocalInterface, RemoteNode: wn.RemoteNode, RemoteInterface: wn.RemoteInterface}
		if n.RemoteAddr, err = optionalAddr(wn.RemoteAddr); err != nil {
			return netmodel.Observation{}, fmt.Errorf("neighbor %q remote_addr: %w", wn.RemoteNode, err)
		}
		o.Neighbors = append(o.Neighbors, n)
	}
	for _, wr := range w.Routes {
		p, err := netip.ParsePrefix(wr.Prefix)
		if err != nil {
			return netmodel.Observation{}, fmt.Errorf("route prefix %q: %w", wr.Prefix, err)
		}
		r := netmodel.Route{Prefix: p, Origin: wr.Origin, Discard: wr.Discard}
		if wr.Metric != nil {
			r.Metric, r.MetricKnown = *wr.Metric, true
		}
		for _, h := range wr.NextHops {
			addr, err := optionalAddr(h.Addr)
			if err != nil {
				return netmodel.Observation{}, fmt.Errorf("route %s next hop %q: %w", wr.Prefix, h.Addr, err)
			}
			r.NextHops = append(r.NextHops, netmodel.NextHop{Addr: addr, Interface: h.Interface})
		}
		o.Routes = append(o.Routes, r)
	}
	return o, nil
}

func decodeCheck(w wireCheck) (Check, error) {
	at, err := parseTime(w.CollectedAt)
	if err != nil {
		return Check{}, err
	}
	dest, err := netip.ParseAddr(w.Destination)
	if err != nil {
		return Check{}, fmt.Errorf("destination %q: %w", w.Destination, err)
	}
	nextHop, err := optionalAddr(w.NextHop)
	if err != nil {
		return Check{}, fmt.Errorf("next_hop %q: %w", w.NextHop, err)
	}
	if w.Node == "" || w.VRF == "" || w.Interface == "" || w.Source == "" {
		return Check{}, errors.New("needs source, node, vrf, and interface")
	}
	var result CheckResult
	switch CheckResult(w.Result) {
	case CheckPass, CheckFail:
		result = CheckResult(w.Result)
	default:
		return Check{}, fmt.Errorf(`result %q is not "pass" or "fail"`, w.Result)
	}
	return Check{
		Provenance:  netmodel.Provenance{Source: w.Source, CollectedAt: at},
		Node:        w.Node,
		VRF:         w.VRF,
		Interface:   w.Interface,
		Destination: dest,
		NextHop:     nextHop,
		Result:      result,
	}, nil
}

// optionalAddr parses an address that may be absent. An absent next hop address
// means on-link, and an absent remote address means the neighbor did not say.
func optionalAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	return netip.ParseAddr(s)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("collected_at is empty")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("collected_at %q: %w", s, err)
	}
	return t, nil
}
