package diagnostic

import (
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// watchMaxAge bounds how long a passing protocol observation may stand in for
// a fresh run. It is also the safety refresh: a change that no fresh row can
// see is found by the next run of the observation, at most this long after it
// was sampled. A route, address, link, rule or nexthop change reported by
// Invalidate ends the stand-in sooner. Without a route event source, watchMaxAge
// is the only bound.
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
	now func() time.Time
	// unbiased reads the unbiased interrupt-time count, which a suspend does not
	// advance. It is nil where the monotonic clock already stops in a suspend;
	// see SystemUnbiasedClock.
	unbiased func() (uint64, bool)
	cache    map[ProbeID]watchObservation
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
	// generation counts the route, address, link, rule and nexthop changes reported
	// to this session by Invalidate. An observation records the generation its pass
	// began with, and is reused only while the session still has that generation.
	// It is atomic because a route event source calls Invalidate from its own goroutine.
	generation atomic.Uint64
	// feed is the running route-event subscription, if FollowRouteEvents started
	// one. Only the owner that publishes passes touches it.
	feed *routeFeed
}

// watchObservation is one passing, reusable row and the evidence it was
// sampled from. Its result is a private copy that no pass changes.
type watchObservation struct {
	result      ProbeResult
	fingerprint string
	sampled     time.Time
	// generation is the session generation when the pass that sampled this row
	// began. It is taken at Begin, not when the row finishes, so a change that
	// lands while the row runs still makes the observation stale.
	generation uint64
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
	return &WatchSession{now: now, unbiased: SystemUnbiasedClock, cache: map[ProbeID]watchObservation{}, force: true}
}

// Force makes the next pass acquire every row fresh. A user-requested retest
// asks for it.
func (s *WatchSession) Force() {
	s.force = true
	s.requests++
}

// Invalidate reports a route, address, link, rule or nexthop change. Every
// reusable observation sampled before the call is refused from now on, so the
// next pass runs those rows fresh instead of waiting out watchMaxAge. The rows that
// always run are untouched, and the pass is not forced: a pass that reuses nothing
// is published as fresh.
//
// It is safe from any goroutine, and repeated calls only move the generation
// on, so a burst of events costs one fresh pass, not one per event. A change
// reported while a pass runs refuses reuse from the next row that asks, and
// the rows that already answered are kept until the next pass.
//
// Every change refuses every reusable row, whatever address family it names.
// An IPv4 path can leave through an IPv6 underlay: an XFRM policy adds no device
// that a route lookup names, and a tunnel kind missing from encapsulatingKinds
// reads as direct. An IPv6 message therefore does not prove that an IPv4 row is
// unaffected, so no event is scoped to a family.
func (s *WatchSession) Invalidate() {
	s.generation.Add(1)
}

// Begin starts one pass over base, the probe graph of this session's target.
// timeout is the per-probe timeout the pass runs under, the same value given to
// RunAll. Run the probes Begin returns, then give the results to Publish.
//
// A pass acquires every row when the session is forced, when the last
// published pass was not settled, or when the last whole measurement is no
// longer within watchMaxAge. The last rule is what bounds the age of a whole
// measurement. Rows that reach their maximum age at different times, after an
// input changed, could otherwise leave no pass in which every row was measured.
func (s *WatchSession) Begin(base []Probe, timeout time.Duration) *WatchPass {
	at := s.now()
	pass := &WatchPass{
		session:      s,
		at:           at,
		window:       passWindow(base, timeout),
		force:        s.force || !s.settled || !within(at, s.lastFull),
		requested:    s.requests,
		cache:        maps.Clone(s.cache),
		generation:   s.generation.Load(),
		ancestors:    ancestorsOf(base),
		ran:          map[ProbeID]watchObservation{},
		reused:       map[ProbeID]bool{},
		fingerprints: map[ProbeID]string{},
	}
	if s.unbiased != nil {
		if ticks, ok := s.unbiased(); ok {
			pass.unbiased, pass.start, pass.hasUnbiased = s.unbiased, ticks, true
		} else {
			// The platform has the count but cannot read it now. The pass keeps
			// watchMaxAge, so it claims no more protection than that bound gives.
			pass.window = watchMaxAge
		}
	}
	pass.probes = make([]Probe, len(base))
	for i, probe := range base {
		pass.probes[i] = pass.wrap(probe)
	}
	return pass
}

// passWindow is how long after Begin a pass may still publish. The window is
// watchMaxAge unless the probes may legitimately run longer. Each rung of the
// deepest dependency chain spends at most one timeout, and the factor of two
// leaves room for a probe that returns just past its deadline. So a pass that
// honors its deadlines finishes inside the window, whatever the timeout is.
func passWindow(base []Probe, timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	limit := time.Duration(2 * chainDepth(base))
	if limit == 0 {
		return watchMaxAge
	}
	// --timeout has no upper bound outside peer mode, so the product saturates
	// rather than wrapping negative, which would refuse every pass.
	if timeout > math.MaxInt64/limit {
		return math.MaxInt64
	}
	return max(watchMaxAge, timeout*limit)
}

// chainDepth returns how many rows lie on the longest dependency chain in base,
// the row itself included. A cycle is a graph bug that the budget test rejects;
// here it only has to terminate.
func chainDepth(base []Probe) int {
	deps := make(map[ProbeID][]ProbeID, len(base))
	for _, p := range base {
		deps[p.ID] = p.Deps
	}
	memo := make(map[ProbeID]int, len(base))
	var depth func(ProbeID) int
	depth = func(id ProbeID) int {
		if d, ok := memo[id]; ok {
			return d
		}
		memo[id] = 1
		longest := 0
		for _, dep := range deps[id] {
			longest = max(longest, depth(dep))
		}
		memo[id] = longest + 1
		return memo[id]
	}
	deepest := 0
	for _, p := range base {
		deepest = max(deepest, depth(p.ID))
	}
	return deepest
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
	session    *WatchSession
	at         time.Time
	force      bool
	requested  uint64
	generation uint64
	window     time.Duration // how long after at the pass may publish; see passWindow
	// unbiased and start hold the unbiased count when the pass began.
	// hasUnbiased says that count was readable, so publication checks it too.
	unbiased    func() (uint64, bool)
	start       uint64
	hasUnbiased bool
	probes      []Probe
	cache       map[ProbeID]watchObservation
	ancestors   map[ProbeID][]ProbeID

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

// inWindow reports whether an age is inside a window. A negative age means the
// clock went back, and nothing is trusted from it.
func inWindow(age, window time.Duration) bool {
	return age >= 0 && age < window
}

// within reports whether a measurement taken at then is still inside its window
// at now. Times without a monotonic reading compare on the wall clock alone.
func within(now, then time.Time) bool {
	mono, wall := elapsed(now, then)
	return fresh(mono, wall)
}

// elapsed returns the time from then to now on the monotonic clock and on the
// wall clock. Round(0) strips the monotonic reading, so the second value is wall.
func elapsed(now, then time.Time) (mono, wall time.Duration) {
	return now.Sub(then), now.Round(0).Sub(then.Round(0))
}

// fresh reports whether a measurement is inside its window on both clocks. The
// monotonic age does not count a suspend on some systems, as the time package
// documents, so alone it would let a measurement from before a suspend stand.
// The wall age advances through a suspend and refuses it. The monotonic age
// bounds a wall clock that steps back, which the wall age alone would extend
// without limit.
func fresh(mono, wall time.Duration) bool {
	return inWindow(mono, watchMaxAge) && inWindow(wall, watchMaxAge)
}

// Clock drift allowance bounds. The floor covers reads of the two clocks landing
// at different moments. The slew term is 500 ppm, the Linux kernel's NTP frequency
// limit (MAXFREQ in timex.h), taken as the bound for a clock whose monotonic source
// is not slewed. Linux CLOCK_MONOTONIC follows frequency adjustments (clock_gettime(2)),
// so there the term does no work. The cap keeps a suspend of a minute or more
// visible however long the pass runs, on a system whose monotonic clock stops in a
// suspend.
const (
	driftFloor = time.Second
	driftCap   = 10 * time.Second
)

// driftAllowance returns how far the wall clock may move away from the monotonic
// clock over a pass that ran mono long. The cap is what stops a long timeout from
// hiding a suspend on a system whose monotonic clock stops in one: the suspend
// shows as drift, so the allowance may not reach the freshness limit.
func driftAllowance(mono time.Duration) time.Duration {
	return min(driftFloor+mono/2000, driftCap)
}

// passCurrent reports whether a pass that began mono ago on the monotonic clock
// and wall ago on the wall clock may publish, inside window. The wall clock runs
// through a suspend, so the window refuses a pass that a suspend carried past it.
// A suspend that stops the monotonic clock shows as wall minus monotonic, and that
// drift is refused even inside the window once it exceeds driftAllowance. A system
// whose monotonic clock runs through a suspend shows no drift, so there the window
// alone stands. Both ages lie in [0, window) before the difference is taken, so
// the subtraction cannot overflow.
func passCurrent(mono, wall, window time.Duration) bool {
	if !inWindow(mono, window) || !inWindow(wall, window) {
		return false
	}
	drift := wall - mono
	if drift < 0 {
		drift = -drift
	}
	return drift <= driftAllowance(mono)
}

// unbiasedTick is one unit of the unbiased count, which Windows reports in 100 ns.
const unbiasedTick = 100 * time.Nanosecond

// ticksElapsed returns the time from start to end on the unbiased count. A count
// that moved backward is not a measurement, so it returns -1, which refuses the
// pass. A difference too large for a Duration saturates.
func ticksElapsed(start, end uint64) time.Duration {
	if end < start {
		return -1
	}
	ticks := end - start
	if ticks > math.MaxInt64/uint64(unbiasedTick) {
		return math.MaxInt64
	}
	return time.Duration(ticks) * unbiasedTick
}

// unbiasedCurrent reports whether the unbiased count agrees with the monotonic
// clock over a pass. Where the monotonic clock counts a suspend and the count does
// not, the gap between the two is the suspend. The allowance is the one passCurrent
// gives the monotonic age, so the two checks share one bound. Both ages lie in
// [0, window) before the difference is taken, so the subtraction cannot overflow.
func unbiasedCurrent(mono, working, window time.Duration) bool {
	if !inWindow(mono, window) || !inWindow(working, window) {
		return false
	}
	drift := mono - working
	if drift < 0 {
		drift = -drift
	}
	return drift <= driftAllowance(mono)
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
	// Read live, not from the pass: a change reported while this pass runs
	// refuses every observation sampled before it, from here on.
	if ob.generation != p.session.generation.Load() {
		return ProbeResult{}, "", false
	}
	if !within(now, ob.sampled) {
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

// Straddled reports whether the session's generation moved while this pass was
// in flight. A pass that straddles a route change can hold rows from before the
// change and rows from after it, so it describes no single network state. It is
// still published and, when fresh, still counts as a run; a caller that keeps
// baselines must not take a healthy straddled pass as one.
func (p *WatchPass) Straddled() bool {
	return p.session.generation.Load() != p.generation
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
	p.ran[id] = watchObservation{result: cloneProbeResult(r), fingerprint: fp, sampled: sampled, generation: p.generation, inputs: inputs}
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
// finalized, and reports whether they may be recorded. A pass is refused first
// when it is no longer current: it began more than its window ago (see
// passWindow), or a row it reused has aged out. Such a pass is discarded and the
// next one runs fresh.
// Otherwise a forced pass, and a pass that reused no row, is published: every
// row in it is fresh. A pass that reused a row is published only when every row
// has the same status and cause as in the last published pass, and the routes
// its rows that always run measured are the same. Such a pass may still carry
// new addresses, because a row whose inputs changed was run again. A reused
// pass whose verdicts or routes differ may have judged a change against
// evidence older than this pass, so nothing from it is kept and the next pass
// runs fresh. When Publish returns false, the caller runs the next pass straight
// away.
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
	if !p.current(s.now()) || (!p.force && reused > 0 && (!maps.Equal(s.last, verdicts) || path != s.path)) {
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

// current reports whether everything this pass publishes is still inside its
// window at now. The pass must have begun within its window, which covers the
// rows it ran. Every reused observation must have been sampled within
// watchMaxAge. A suspend or clock step during the pass fails one of these, and
// the evidence it would publish has aged out. Where the platform has an unbiased
// count, the pass also checks it, and a count that cannot be read now refuses.
func (p *WatchPass) current(now time.Time) bool {
	mono, wall := elapsed(now, p.at)
	if !passCurrent(mono, wall, p.window) {
		return false
	}
	if p.hasUnbiased {
		ticks, ok := p.unbiased()
		if !ok || !unbiasedCurrent(mono, ticksElapsed(p.start, ticks), p.window) {
			return false
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.reused {
		if !within(now, p.cache[id].sampled) {
			return false
		}
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
