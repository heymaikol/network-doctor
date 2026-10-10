package routepath

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"

	"github.com/heymaikol/network-doctor/internal/netmodel"
)

// Encode writes f as a topology file that Decode reads back as the same
// evidence. It refuses anything version FileVersion cannot carry instead of
// dropping it. It also refuses a file over MaxFileBytes. The bytes are returned
// only after Decode reads them back and the result matches f, so a caller that
// writes them writes a file Decode accepts.
//
// Encode writes exactly what f holds. It invents no routes, checks, areas,
// source addresses, or completeness flags.
func Encode(f File) ([]byte, error) {
	if f.Source.Node == "" || f.Source.VRF == "" {
		return nil, errors.New("topology needs a source node and a source vrf")
	}
	w := wireFile{
		Version:      FileVersion,
		Source:       wireStart{Node: f.Source.Node, VRF: f.Source.VRF, Address: addrText(f.SourceAddr)},
		Observations: []wireObservation{},
		Checks:       []wireCheck{},
		Boundaries:   []wireBoundary{},
	}
	for i, o := range f.Model.Observations() {
		wo, err := encodeObservation(o)
		if err != nil {
			return nil, fmt.Errorf("observation %d: %w", i, err)
		}
		w.Observations = append(w.Observations, wo)
	}
	for _, c := range f.Checks {
		w.Checks = append(w.Checks, wireCheck{
			Source:      c.Source,
			CollectedAt: utcText(c.CollectedAt),
			Node:        c.Node,
			VRF:         c.VRF,
			Interface:   c.Interface,
			Destination: addrText(c.Destination),
			NextHop:     addrText(c.NextHop),
			Result:      string(c.Result),
		})
	}
	for _, b := range f.Boundaries {
		w.Boundaries = append(w.Boundaries, wireBoundary{
			Source:      b.Source,
			CollectedAt: utcText(b.CollectedAt),
			Node:        b.Node,
			VRF:         b.VRF,
			Kind:        string(b.Kind),
		})
	}
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("the topology is %d bytes; the limit is %d", len(data), MaxFileBytes)
	}
	back, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("the topology does not read back: %w", err)
	}
	if !sameEvidence(f, back) {
		return nil, errors.New("the topology does not read back as the same evidence")
	}
	return data, nil
}

// encodeObservation writes one observation. netmodel holds the VLAN fields that
// version 1 has no place for, so a set VLAN is refused here, not dropped.
func encodeObservation(o netmodel.Observation) (wireObservation, error) {
	w := wireObservation{
		Source:            o.Source,
		CollectedAt:       utcText(o.CollectedAt),
		Plane:             string(o.Plane),
		Node:              o.Node,
		VRF:               o.VRF,
		RoutesComplete:    o.RoutesComplete,
		NeighborsComplete: o.NeighborsComplete,
		Interfaces:        []wireInterface{},
		Neighbors:         []wireNeighbor{},
		Routes:            []wireRoute{},
	}
	for _, i := range o.Interfaces {
		if i.VLANKnown {
			return wireObservation{}, fmt.Errorf("interface %q has a VLAN, which topology version %d cannot carry", i.Name, FileVersion)
		}
		wi := wireInterface{Name: i.Name, Addresses: []string{}, Attributes: encodeAttributes(i.Attributes)}
		for _, p := range i.Addresses {
			wi.Addresses = append(wi.Addresses, p.String())
		}
		w.Interfaces = append(w.Interfaces, wi)
	}
	for _, n := range o.Neighbors {
		w.Neighbors = append(w.Neighbors, wireNeighbor{
			LocalInterface:  n.LocalInterface,
			RemoteNode:      n.RemoteNode,
			RemoteInterface: n.RemoteInterface,
			RemoteAddr:      addrText(n.RemoteAddr),
			Attributes:      encodeAttributes(n.Attributes),
		})
	}
	for _, r := range o.Routes {
		wr := wireRoute{
			Prefix:     r.Prefix.String(),
			Origin:     r.Origin,
			Discard:    r.Discard,
			NextHops:   []wireNextHop{},
			Attributes: encodeAttributes(r.Attributes),
		}
		if r.MetricKnown {
			metric := r.Metric
			wr.Metric = &metric
		}
		for _, h := range r.NextHops {
			wr.NextHops = append(wr.NextHops, wireNextHop{Addr: addrText(h.Addr), Interface: h.Interface})
		}
		w.Routes = append(w.Routes, wr)
	}
	return w, nil
}

func encodeAttributes(attrs []netmodel.Attribute) []wireAttribute {
	out := make([]wireAttribute, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, wireAttribute{Key: a.Key, Value: a.Value})
	}
	return out
}

// evidence is what Decode must reproduce. Times compare in UTC, because the file
// holds UTC. Empty lists compare as nil, and boundaries compare sorted, because
// Decode sorts them.
type evidence struct {
	Source     Start
	SourceAddr netip.Addr
	Model      []netmodel.Observation
	Checks     []Check
	Boundaries []Boundary
}

func evidenceOf(f File) evidence {
	e := evidence{Source: f.Source, SourceAddr: f.SourceAddr, Model: f.Model.Observations()}
	for i := range e.Model {
		e.Model[i].CollectedAt = e.Model[i].CollectedAt.UTC()
	}
	for _, c := range f.Checks {
		c.CollectedAt = c.CollectedAt.UTC()
		e.Checks = append(e.Checks, c)
	}
	for _, b := range f.Boundaries {
		b.CollectedAt = b.CollectedAt.UTC()
		e.Boundaries = append(e.Boundaries, b)
	}
	slices.SortFunc(e.Boundaries, compareBoundaries)
	return e
}

// sameEvidence compares every field of both files. A netmodel field that the
// wire format drops would show up here as a difference, because reflect walks
// all of them.
func sameEvidence(a, b File) bool {
	return reflect.DeepEqual(evidenceOf(a), evidenceOf(b))
}
