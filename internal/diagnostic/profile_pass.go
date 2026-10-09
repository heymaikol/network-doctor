package diagnostic

import (
	"context"
	"maps"
	"slices"
	"sync"
)

// ProfilePass builds local component graphs with one source configuration and
// one raw sample of iface, internet_tcp and proxy_connect per pass. Callers use
// the same probe timeout for every component and discard the pass after use.
// Targets, selections, schedulers, result maps and Finalize remain independent.
// Reference destinations and the proxy question are fixed by the native graph;
// target DNS (including public DNS), TCP and all protocol evidence stay local.
type ProfilePass struct {
	ops      netops
	iface    profileObservation
	internet profileObservation
	proxy    profileObservation
}

// NewProfilePass captures the source binding and native operations for one
// local profile pass. A new instance is required for each Watch refresh.
func NewProfilePass(sources *SourceAddresses) *ProfilePass {
	return &ProfilePass{ops: *opsFromSources(sources)}
}

// BuildProbes constructs and filters a fresh native component graph before
// sharing. Different selections therefore cannot resurrect excluded rows.
func (pass *ProfilePass) BuildProbes(t *Target, selection ProbeSelection, publicDNS string, publicDNSAuto bool) []Probe {
	o := pass.ops
	probeOps(t, &o)
	probes := selection.Apply(o.timedProbes(t, publicDNS, publicDNSAuto, slices.Collect(maps.Keys(selection.Check))...))
	pass.share(probes, &o)
	return probes
}

// share accepts only graphs built above with the pass's fixed source and
// operations. ID alone is insufficient: the native dependency shape must also
// match, and each shared child must consume the shared interface observation.
func (pass *ProfilePass) share(probes []Probe, o *netops) {
	iface := false
	for _, p := range probes {
		iface = iface || p.ID == ProbeIface && len(p.Deps) == 0
	}
	if !iface {
		return
	}
	for i := range probes {
		probe := &probes[i]
		p := *probe
		var observation *profileObservation
		switch {
		case p.ID == ProbeIface && len(p.Deps) == 0:
			observation = &pass.iface
		case p.ID == ProbeInternet && slices.Equal(p.Deps, []ProbeID{ProbeIface}):
			observation = &pass.internet
		case p.ID == ProbeProxy && slices.Equal(p.Deps, []ProbeID{ProbeIface}):
			observation = &pass.proxy
		default:
			continue
		}
		probe.Run = func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
			r := observation.run(ctx, p, deps)
			if p.ID == ProbeIface {
				// Target and DNS route explanations must use the same yardstick
				// as the interface row, while their destination lookups stay local.
				o.routes.referenceOnce.Do(func() { o.routes.reference = cloneRoutes(r.Routes) })
			}
			return r
		}
	}
}

type profileObservation struct {
	mu     sync.Mutex
	done   chan struct{}
	result ProbeResult
}

func (observation *profileObservation) run(ctx context.Context, p Probe, deps map[ProbeID]ProbeResult) ProbeResult {
	observation.mu.Lock()
	first := observation.done == nil
	if first {
		observation.done = make(chan struct{})
	}
	done := observation.done
	observation.mu.Unlock()
	if first {
		observation.result = cloneProbeResult(p.Run(ctx, deps))
		observation.result.ID = p.ID
		close(done)
	} else {
		select {
		case <-done:
		case <-ctx.Done():
			return ProbeResult{ID: p.ID, Status: StatusFail, Cause: ConnectionFailureCause(ctx.Err()), Detail: ctx.Err().Error()}
		}
	}
	return cloneProbeResult(observation.result)
}

// Clone before every handoff, including the first: Finalize can reinterpret
// egress using one component's target without changing another's raw sample.
func cloneProbeResult(r ProbeResult) ProbeResult {
	if r.Families != nil {
		families := *r.Families
		r.Families = &families
	}
	if r.Portal != nil {
		portal := *r.Portal
		r.Portal = &portal
	}
	if r.Addrs != nil {
		r.Addrs = cloneIPs(r.Addrs)
	}
	r.SelectedIP, r.Source = slices.Clone(r.SelectedIP), slices.Clone(r.Source)
	r.ResolverTargets = slices.Clone(r.ResolverTargets)
	r.Routes = cloneRoutes(r.Routes)
	r.Attempts = slices.Clone(r.Attempts)
	for i := range r.Attempts {
		r.Attempts[i].IP = slices.Clone(r.Attempts[i].IP)
	}
	r.alternateDefaults = maps.Clone(r.alternateDefaults)
	for family, defaults := range r.alternateDefaults {
		defaults = slices.Clone(defaults)
		for i := range defaults {
			defaults[i].gateway = slices.Clone(defaults[i].gateway)
		}
		r.alternateDefaults[family] = defaults
	}
	return r
}

func cloneRoutes(routes []RouteDecision) []RouteDecision {
	routes = slices.Clone(routes)
	for i := range routes {
		routes[i].Destination = slices.Clone(routes[i].Destination)
		routes[i].Gateway = slices.Clone(routes[i].Gateway)
		routes[i].Source = slices.Clone(routes[i].Source)
		routes[i].Competing = slices.Clone(routes[i].Competing)
	}
	return routes
}
