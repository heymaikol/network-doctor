package diagnostic

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"
)

// watchMaxAge bounds how long a passing protocol observation may stand in for
// a fresh run. It is also the safety refresh: a change that no fresh row can
// see is found by the next run of the observation, at most this long after it
// was sampled.
const watchMaxAge = 60 * time.Second

// watchReusable lists the rows a Watch pass may answer from its last passing
// observation. Every other row runs on every pass: the interface, Wi-Fi, system
// DNS, public DNS, the reference TCP egress, the target's TCP connect, and path
// MTU. Public DNS is fresh because reconcileDNS compares its answers with the
// system answers of the same pass. Path MTU is fresh because it sends its payload
// on every pass, and that transfer is the measurement. The rest are the liveness
// signals the reusable rows are keyed on. A row added later is fresh until
// someone lists it here.
var watchReusable = map[ProbeID]bool{
	ProbeTLS:          true,
	ProbeHTTP:         true,
	ProbeHTTPS:        true,
	ProbeSSH:          true,
	ProbeSMTP:         true,
	ProbeQUIC:         true,
	ProbeDNSEncrypted: true,
	ProbeProxy:        true,
}

// WatchSession holds what one Watch session may reuse between passes. A target
// switch or a different probe selection needs a new session. Only the owner
// that publishes passes may touch it: the Update loop in the TUI, or the loop
// in headless Watch.
type WatchSession struct {
	now   func() time.Time
	cache map[ProbeID]watchObservation
	// last is the verdict of every row in the last published pass.
	last map[ProbeID]watchVerdict
	// force makes the next pass acquire every row fresh. It stays set until a
	// pass that ran fresh is published, so a cancelled forced pass is retried.
	force bool
	// requests counts each request for a fresh pass, from Force or from a
	// discarded pass. A pass records the count when it begins. Publishing clears
	// force only if no request came after that, so a retest that arrives while a
	// pass runs still gets its fresh pass.
	requests uint64
}

// watchObservation is one passing, reusable row and the evidence it was
// sampled from. Its result is a private copy that no pass changes.
type watchObservation struct {
	result      ProbeResult
	fingerprint string
	sampled     time.Time
	// inputs is the fingerprint of each dependency when this row was sampled.
	// Reuse needs every dependency to match, which is what carries an
	// interface, route, or address change down to the rows built on it.
	inputs map[ProbeID]string
}

// watchVerdict is what a pass says about one row, without the evidence behind
// it. A pass is confirmed when its verdicts match the last published pass.
type watchVerdict struct {
	status Status
	cause  string
}

// NewWatchSession returns a session whose first pass is fresh. A nil clock
// means time.Now.
func NewWatchSession(now func() time.Time) *WatchSession {
	if now == nil {
		now = time.Now
	}
	return &WatchSession{now: now, cache: map[ProbeID]watchObservation{}, force: true}
}

// Force makes the next pass acquire every row fresh. A user-requested retest
// asks for it.
func (s *WatchSession) Force() {
	s.force = true
	s.requests++
}

// Begin starts one pass over base, the probe graph of this session's target.
// Run the probes Begin returns, then give the results to Publish.
func (s *WatchSession) Begin(base []Probe) *WatchPass {
	pass := &WatchPass{
		session:      s,
		force:        s.force,
		requested:    s.requests,
		cache:        maps.Clone(s.cache),
		ran:          map[ProbeID]watchObservation{},
		reused:       map[ProbeID]bool{},
		fingerprints: map[ProbeID]string{},
	}
	pass.probes = make([]Probe, len(base))
	for i, probe := range base {
		pass.probes[i] = pass.wrap(probe)
	}
	return pass
}

// WatchPass is one pass of a Watch session. Its probes run concurrently, so
// they touch only the copy of the cache taken at Begin and their own records,
// which mu guards. The session changes only in Publish.
type WatchPass struct {
	session   *WatchSession
	force     bool
	requested uint64
	probes    []Probe
	cache     map[ProbeID]watchObservation

	mu     sync.Mutex
	ran    map[ProbeID]watchObservation
	reused map[ProbeID]bool
	// fingerprints holds each finished row's fingerprint, so a row computes
	// its own once however many rows depend on it.
	fingerprints map[ProbeID]string
}

// Probes returns the graph to run. The probes are the same rows as the graph
// Begin was given, with each reusable row consulting the session before it runs.
func (p *WatchPass) Probes() []Probe {
	return p.probes
}

func (p *WatchPass) wrap(probe Probe) Probe {
	run := probe.Run
	if run == nil {
		return probe
	}
	id, deps := probe.ID, probe.Deps
	reusable := watchReusable[id]
	probe.Run = func(ctx context.Context, in map[ProbeID]ProbeResult) ProbeResult {
		sampled := p.session.now()
		if reusable {
			if r, fp, ok := p.reuse(id, deps, in, sampled); ok {
				p.setFingerprint(id, fp)
				return r
			}
		}
		r := run(ctx, in)
		fp := fingerprint(r)
		p.setFingerprint(id, fp)
		if reusable && r.Status == StatusPass {
			p.record(id, fp, deps, in, sampled, r)
		}
		return r
	}
	return probe
}

// reuse answers a row from its passing observation when nothing it was
// sampled from has changed, and the observation is younger than watchMaxAge.
// It never answers a forced pass.
func (p *WatchPass) reuse(id ProbeID, deps []ProbeID, in map[ProbeID]ProbeResult, now time.Time) (ProbeResult, string, bool) {
	if p.force {
		return ProbeResult{}, "", false
	}
	ob, ok := p.cache[id]
	if !ok {
		return ProbeResult{}, "", false
	}
	if age := now.Sub(ob.sampled); age < 0 || age >= watchMaxAge {
		return ProbeResult{}, "", false
	}
	for _, d := range deps {
		r, ok := in[d]
		if !ok || p.fingerprintOf(d, r) != ob.inputs[d] {
			return ProbeResult{}, "", false
		}
	}
	p.mu.Lock()
	p.reused[id] = true
	p.mu.Unlock()
	// The reused copy did not run this pass, so it reports no duration. Its
	// attempts keep their addresses and outcomes, which are the evidence.
	r := cloneProbeResult(ob.result)
	r.Dur = 0
	for i := range r.Attempts {
		r.Attempts[i].Dur = 0
	}
	return r, ob.fingerprint, true
}

func (p *WatchPass) record(id ProbeID, fp string, deps []ProbeID, in map[ProbeID]ProbeResult, sampled time.Time, r ProbeResult) {
	inputs := make(map[ProbeID]string, len(deps))
	for _, d := range deps {
		inputs[d] = p.fingerprintOf(d, in[d])
	}
	p.mu.Lock()
	p.ran[id] = watchObservation{result: cloneProbeResult(r), fingerprint: fp, sampled: sampled, inputs: inputs}
	p.mu.Unlock()
}

func (p *WatchPass) setFingerprint(id ProbeID, fp string) {
	p.mu.Lock()
	p.fingerprints[id] = fp
	p.mu.Unlock()
}

// fingerprintOf returns the fingerprint of a dependency's result. The row that
// produced the result has usually recorded it already; a row the pass never ran
// (a skipped prerequisite) is measured here.
func (p *WatchPass) fingerprintOf(id ProbeID, r ProbeResult) string {
	p.mu.Lock()
	fp, ok := p.fingerprints[id]
	p.mu.Unlock()
	if ok {
		return fp
	}
	return fingerprint(r)
}

// Publish takes the finished pass's results, after the diagnosis has been
// finalized, and reports whether they may be recorded. A forced pass, and a
// pass that reused no row, is always published: every row in it is fresh.
// A pass that reused a row is published only when every row has the same
// status and cause as in the last published pass. Such a pass may still carry
// new addresses or routes, because a row whose inputs changed was run again.
// A reused pass whose status or cause differs may have judged a change against
// evidence older than this pass, so nothing from it is kept and the next pass
// runs fresh. When Publish returns false, the caller runs the next pass straight
// away.
func (p *WatchPass) Publish(results map[ProbeID]ProbeResult) bool {
	s := p.session
	verdicts := make(map[ProbeID]watchVerdict, len(results))
	for id, r := range results {
		verdicts[id] = watchVerdict{status: r.Status, cause: r.Cause}
	}
	p.mu.Lock()
	reused := len(p.reused)
	p.mu.Unlock()
	if !p.force && reused > 0 && !maps.Equal(s.last, verdicts) {
		s.force = true
		s.requests++
		return false
	}
	next := make(map[ProbeID]watchObservation, len(p.ran)+len(p.reused))
	for id, ob := range p.ran {
		next[id] = ob
	}
	for id := range p.reused {
		next[id] = p.cache[id]
	}
	s.cache = next
	s.last = verdicts
	if s.requests == p.requested {
		s.force = false
	}
	return true
}

// fingerprint names what a row tells the rows built on it and the diagnosis: its
// outcome, and the addresses, interface, routes, and family state it was
// measured through. Duration, detail text, and attempt timing are left out, so a
// row that measures the same thing again compares equal.
func fingerprint(r ProbeResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "status=%d cause=%q causeFamily=%q iface=%q ambiguous=%t network=%q",
		r.Status, r.Cause, r.causeFamily, r.Iface, r.ifaceAmbiguous, r.Network)
	fmt.Fprintf(&b, " selected=%v source=%v addrs=%v dnsNotFound=%t", r.SelectedIP, r.Source, r.Addrs, r.DNSNotFound)
	fmt.Fprintf(&b, " resolvers=%q resolver=%q routes=%+v", r.ResolverTargets, r.resolver, r.Routes)
	fmt.Fprintf(&b, " alternates=%v downgraded=%t timedOut=%t cleartext=%t", r.alternateDefaults, r.downgraded, r.timedOut, r.ConnectCleartext)
	if r.Families != nil {
		fmt.Fprintf(&b, " families=%+v", *r.Families)
	}
	if r.Portal != nil {
		fmt.Fprintf(&b, " portal=%q", r.Portal.RedirectURL)
	}
	for _, a := range r.Attempts {
		fmt.Fprintf(&b, " attempt=%v/%t/%q/%v", a.IP, a.Aborted, a.Cause, a.Err)
	}
	return b.String()
}
