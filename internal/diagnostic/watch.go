package diagnostic

import (
	"context"
	"fmt"
	"maps"
	"slices"
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
	// path names the routes the rows that run on every pass measured in the last
	// published pass. A reused row describes the path it was sampled on, so a
	// pass that measured a different path is not published with it.
	path string
	// settled says the last published pass was OK: every row reported and none
	// failed. Only a settled session reuses a row. After a failing pass, every
	// row runs again, so a failure is followed, and its recovery confirmed, on
	// evidence measured in full.
	settled bool
	// lastFull is when the last published pass that reused no row began. Every
	// row in such a pass was measured by it, so it is the newest whole
	// measurement the session holds.
	lastFull time.Time
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
	// inputs is the fingerprint of every row this one reads, directly or through
	// another row, when it was sampled. Reuse needs each of them unchanged. Only
	// direct dependencies would miss a change that reaches a row through a
	// dependency whose own result stayed the same.
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
//
// A pass acquires every row when the session is forced, when the last
// published pass was not settled, or when the last whole measurement is no
// longer within watchMaxAge. The last rule is what bounds the age of a whole
// measurement. Rows that reach their maximum age at different times, after an
// input changed, could otherwise leave no pass in which every row was measured.
func (s *WatchSession) Begin(base []Probe) *WatchPass {
	at := s.now()
	pass := &WatchPass{
		session:      s,
		at:           at,
		force:        s.force || !s.settled || !within(at.Sub(s.lastFull)),
		requested:    s.requests,
		cache:        maps.Clone(s.cache),
		ancestors:    ancestorsOf(base),
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

// ancestorsOf returns, for each row, every row it reads directly or through
// another row. A row can change because something behind its direct dependency
// changed, even when that dependency's own result is identical.
func ancestorsOf(base []Probe) map[ProbeID][]ProbeID {
	direct := make(map[ProbeID][]ProbeID, len(base))
	for _, probe := range base {
		direct[probe.ID] = probe.Deps
	}
	out := make(map[ProbeID][]ProbeID, len(base))
	for _, probe := range base {
		seen := map[ProbeID]bool{}
		stack := append([]ProbeID(nil), probe.Deps...)
		for len(stack) > 0 {
			id := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[id] {
				continue
			}
			seen[id] = true
			out[probe.ID] = append(out[probe.ID], id)
			stack = append(stack, direct[id]...)
		}
	}
	return out
}

// WatchPass is one pass of a Watch session. Its probes run concurrently, so
// they touch only the copy of the cache taken at Begin and their own records,
// which mu guards. The session changes only in Publish.
type WatchPass struct {
	session   *WatchSession
	at        time.Time
	force     bool
	requested uint64
	probes    []Probe
	cache     map[ProbeID]watchObservation
	ancestors map[ProbeID][]ProbeID

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
	id := probe.ID
	reusable := watchReusable[id]
	probe.Run = func(ctx context.Context, in map[ProbeID]ProbeResult) ProbeResult {
		sampled := p.session.now()
		if reusable {
			if r, fp, ok := p.reuse(id, sampled); ok {
				p.setFingerprint(id, fp)
				return r
			}
		}
		r := run(ctx, in)
		fp := fingerprint(r)
		p.setFingerprint(id, fp)
		if reusable && r.Status == StatusPass {
			p.record(id, fp, sampled, r)
		}
		return r
	}
	return probe
}

// within reports whether an age is inside the window a measurement stands for.
// A negative age means the clock went back, and nothing is trusted from it.
func within(age time.Duration) bool {
	return age >= 0 && age < watchMaxAge
}

// reuse answers a row from its passing observation when nothing it was sampled
// from has changed, and the observation is within watchMaxAge. It never answers
// a forced pass.
func (p *WatchPass) reuse(id ProbeID, now time.Time) (ProbeResult, string, bool) {
	if p.force {
		return ProbeResult{}, "", false
	}
	ob, ok := p.cache[id]
	if !ok {
		return ProbeResult{}, "", false
	}
	if !within(now.Sub(ob.sampled)) {
		return ProbeResult{}, "", false
	}
	for _, a := range p.ancestors[id] {
		fp, ok := p.fingerprintFor(a)
		if !ok || fp != ob.inputs[a] {
			return ProbeResult{}, "", false
		}
	}
	p.mu.Lock()
	p.reused[id] = true
	p.mu.Unlock()
	// The reused copy did not run this pass, so it reports no duration and no
	// socket: the socket it names belonged to the graph of the pass that sampled
	// it, and that graph has been released. Its attempts keep their addresses and
	// outcomes, which are the evidence.
	r := cloneProbeResult(ob.result)
	r.Dur = 0
	r.acquisition = 0
	r.reusedFrom = ob.sampled
	for i := range r.Attempts {
		r.Attempts[i].Dur = 0
	}
	return r, ob.fingerprint, true
}

// Fresh reports whether every row in a published pass was measured by that
// pass. It is false when any row was answered from an earlier one. Only a fresh
// pass measures the whole graph, so it is the only kind a caller may record as
// one run's evidence.
func (p *WatchPass) Fresh() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reused) == 0
}

func (p *WatchPass) record(id ProbeID, fp string, sampled time.Time, r ProbeResult) {
	inputs := make(map[ProbeID]string, len(p.ancestors[id]))
	for _, a := range p.ancestors[id] {
		afp, ok := p.fingerprintFor(a)
		if !ok {
			// A row runs only after every row it reads has finished, because a
			// failed or skipped one blocks it. A gap here means nothing can be
			// checked later, so nothing is kept.
			return
		}
		inputs[a] = afp
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

// fingerprintFor returns the fingerprint of a row that has finished this pass.
func (p *WatchPass) fingerprintFor(id ProbeID) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fp, ok := p.fingerprints[id]
	return fp, ok
}

// Publish takes the finished pass's results, after the diagnosis has been
// finalized, and reports whether they may be recorded. A forced pass, and a
// pass that reused no row, is always published: every row in it is fresh.
// A pass that reused a row is published only when every row has the same
// status and cause as in the last published pass, and the routes its rows that
// always run measured are the same. Such a pass may still carry new addresses,
// because a row whose inputs changed was run again. A reused pass whose
// verdicts or routes differ may have judged a change against evidence older
// than this pass, so nothing from it is kept and the next pass runs fresh. When
// Publish returns false, the caller runs the next pass straight away.
//
// Publish also records whether the session may reuse at all. Only a pass whose
// results are OK settles it, and only a pass that reused no row moves lastFull.
// Fresh tells a caller which of the two a published pass was.
func (p *WatchPass) Publish(results map[ProbeID]ProbeResult) bool {
	s := p.session
	verdicts := make(map[ProbeID]watchVerdict, len(results))
	for id, r := range results {
		verdicts[id] = watchVerdict{status: r.Status, cause: r.Cause}
	}
	path := p.pathOf(results)
	p.mu.Lock()
	reused := len(p.reused)
	p.mu.Unlock()
	if !p.force && reused > 0 && (!maps.Equal(s.last, verdicts) || path != s.path) {
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
	s.path = path
	s.settled = p.settledBy(results)
	if reused == 0 {
		s.lastFull = p.at
	}
	if s.requests == p.requested {
		s.force = false
	}
	return true
}

// settledBy reports whether results are OK over the rows this pass ran.
func (p *WatchPass) settledBy(results map[ProbeID]ProbeResult) bool {
	for _, probe := range p.probes {
		r, reported := results[probe.ID]
		if !okResult(r, reported) {
			return false
		}
	}
	return true
}

// pathOf names the routes the rows that run on every pass measured. Each
// decision contributes its row, interface, next hop, source, and tunnel state.
// The destination is left out, because a target's chosen address can rotate
// while its route stays the same. Reusable rows are left out, even when they
// carry routes: whether one was reused depends on the pass before, so its
// routes would change the key on the pass after it was run, and every other
// pass would be discarded. The rows that always run are the path evidence each
// pass has in common.
func (p *WatchPass) pathOf(results map[ProbeID]ProbeResult) string {
	var decisions []string
	for id, r := range results {
		if watchReusable[id] {
			continue
		}
		for _, d := range r.Routes {
			decisions = append(decisions, fmt.Sprintf("%s %s %s %s %s", id, d.Iface, d.Gateway, d.Source, d.Tunnel))
		}
	}
	slices.Sort(decisions)
	return strings.Join(decisions, "\n")
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
