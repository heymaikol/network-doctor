package diagnostic

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// ProbeSelection filters a built probe DAG by stable ID.
type ProbeSelection struct {
	Check map[ProbeID]struct{}
	Skip  map[ProbeID]struct{}
	// NoReferenceEgress drops every node the graph marked as built-in
	// reference egress, and with it, through the same closure Skip already
	// walks, everything that depended on one.
	//
	// It is a flag rather than a set of IDs because which IDs those are is a
	// property of the run: a DNS row asked about the user's target is not the
	// row that resolves a compiled-in name because there is no target. The
	// graph that was built is what knows, so this reads Probe.Reference rather
	// than a list resolved somewhere else and possibly for another run. That
	// matters in the TUI, where a target switch rebuilds the graph in a shape
	// the command line never saw.
	NoReferenceEgress bool
}

// StableProbe describes one probe accepted by --check and --skip, using the
// row's base name without a run-specific target.
type StableProbe struct {
	ID   ProbeID
	Name string
}

// Validate rejects IDs that are not stable nodes in any normal probe DAG.
func (s ProbeSelection) Validate() error {
	if len(s.Check) == 0 && len(s.Skip) == 0 {
		return nil
	}
	probes := StableProbes()
	known := make(map[ProbeID]struct{}, len(probes))
	valid := make([]string, len(probes))
	for i, probe := range probes {
		known[probe.ID] = struct{}{}
		valid[i] = string(probe.ID)
	}
	for _, group := range []struct {
		name string
		ids  map[ProbeID]struct{}
	}{{"check", s.Check}, {"skip", s.Skip}} {
		var unknown []string
		for id := range group.ids {
			if _, ok := known[id]; !ok {
				unknown = append(unknown, string(id))
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("--%s: unknown probe ID %q; valid IDs: %s", group.name, unknown[0], strings.Join(valid, ","))
		}
	}
	return nil
}

// StableProbes derives the public inventory from the same descriptor builder
// used for runs. Building descriptors performs no probe work.
func StableProbes() []StableProbe {
	const host = "example.invalid"
	target := &Target{Host: host, Port: 443}
	hostPort := fmt.Sprintf("%s:%d", target.Host, target.Port)
	seen := map[ProbeID]struct{}{}
	var stable []StableProbe
	add := func(probes []Probe) {
		for _, p := range probes {
			if _, ok := seen[p.ID]; ok {
				continue
			}
			seen[p.ID] = struct{}{}
			name := strings.TrimSuffix(p.Name, " "+hostPort)
			name = strings.TrimSuffix(name, " "+host)
			stable = append(stable, StableProbe{ID: p.ID, Name: name})
		}
	}
	for proto := range protoNames {
		target.Proto = Proto(proto)
		add(defaultOps.buildProbes(target, DefaultPublicDNS, true))
	}
	add(defaultOps.buildProbes(nil, DefaultPublicDNS, true))
	return stable
}

func selectableProbeIDs() []ProbeID {
	probes := StableProbes()
	ids := make([]ProbeID, len(probes))
	for i, probe := range probes {
		ids[i] = probe.ID
	}
	return ids
}

// Apply returns the selected DAG in its original order. Check pulls in the
// actual dependency closure; Skip removes a node and every node that can no
// longer satisfy its dependencies.
func (s ProbeSelection) Apply(probes []Probe) []Probe {
	skip := s.Skip
	// Folded into the skip set rather than filtered separately, so a reference
	// row removes its dependents exactly the way an explicit --skip does.
	if s.NoReferenceEgress {
		skip = make(map[ProbeID]struct{}, len(s.Skip)+len(probes))
		maps.Copy(skip, s.Skip)
		for _, p := range probes {
			if p.Reference {
				skip[p.ID] = struct{}{}
			}
		}
	}
	if len(s.Check) == 0 && len(skip) == 0 {
		return probes
	}
	byID := make(map[ProbeID]Probe, len(probes))
	for _, p := range probes {
		byID[p.ID] = p
	}

	keep := make(map[ProbeID]struct{}, len(probes))
	var add func(ProbeID)
	add = func(id ProbeID) {
		if _, ok := keep[id]; ok {
			return
		}
		p, ok := byID[id]
		if !ok {
			return
		}
		keep[id] = struct{}{}
		for _, dep := range p.Deps {
			add(dep)
		}
	}
	if len(s.Check) == 0 {
		for _, p := range probes {
			keep[p.ID] = struct{}{}
		}
	} else {
		for _, p := range probes {
			if _, ok := s.Check[p.ID]; ok {
				add(p.ID)
			}
		}
	}
	for id := range skip {
		delete(keep, id)
	}

	for changed := true; changed; {
		changed = false
		for _, p := range probes {
			if _, ok := keep[p.ID]; !ok {
				continue
			}
			for _, dep := range p.Deps {
				if _, ok := keep[dep]; !ok {
					delete(keep, p.ID)
					changed = true
					break
				}
			}
		}
	}
	if len(s.Check) > 0 {
		needed := make(map[ProbeID]struct{}, len(keep))
		var addNeeded func(ProbeID)
		addNeeded = func(id ProbeID) {
			if _, ok := keep[id]; !ok {
				return
			}
			if _, ok := needed[id]; ok {
				return
			}
			needed[id] = struct{}{}
			for _, dep := range byID[id].Deps {
				addNeeded(dep)
			}
		}
		for _, p := range probes {
			if _, requested := s.Check[p.ID]; requested {
				addNeeded(p.ID)
			}
		}
		keep = needed
	}

	selected := make([]Probe, 0, len(keep))
	for _, p := range probes {
		if _, ok := keep[p.ID]; ok {
			selected = append(selected, p)
		}
	}
	return selected
}
