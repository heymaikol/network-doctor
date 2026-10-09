package diagnostic

// ProbeScheduler owns one pass's dependency counts and ready queue. Only the
// executor's scheduling loop may use it; workers receive result snapshots.
type ProbeScheduler struct {
	probes     []Probe
	remaining  []int
	blocked    []bool
	dependents map[ProbeID][]int
	started    map[ProbeID]bool
	completed  map[ProbeID]bool
	ready      []int
	head       int
}

// NewProbeScheduler builds the reverse edges once. started belongs to this
// scheduler and its executor; results is read only during initialization, so
// a TUI can resume a partially completed pass without rescanning it later.
// Unknown dependencies and cycles stay pending, as in the scan scheduler.
func NewProbeScheduler(probes []Probe, started map[ProbeID]bool, results map[ProbeID]ProbeResult) *ProbeScheduler {
	if started == nil {
		started = make(map[ProbeID]bool, len(probes))
	}
	s := &ProbeScheduler{
		probes:     probes,
		remaining:  make([]int, len(probes)),
		blocked:    make([]bool, len(probes)),
		dependents: make(map[ProbeID][]int, len(probes)),
		started:    started,
		completed:  make(map[ProbeID]bool, len(probes)),
		ready:      make([]int, 0, len(probes)),
	}
	for id := range results {
		s.completed[id] = true
	}
	for i, p := range probes {
		for _, dep := range p.Deps {
			if r, ok := results[dep]; ok {
				s.blocked[i] = s.blocked[i] || r.Status == StatusFail || r.Status == StatusSkip
			} else {
				s.remaining[i]++
				s.dependents[dep] = append(s.dependents[dep], i)
			}
		}
		if s.remaining[i] == 0 {
			s.ready = append(s.ready, i)
		}
	}
	return s
}

// Next dispatches one ready probe exactly once per ID. blocked probes must be
// recorded as SkipPrereq and completed synchronously by the executor. Queue
// order follows probe order, then completion order and declared reverse edges.
func (s *ProbeScheduler) Next() (index int, blocked, ok bool) {
	for s.head < len(s.ready) {
		i := s.ready[s.head]
		s.head++
		id := s.probes[i].ID
		if s.started[id] {
			continue
		}
		s.started[id] = true
		return i, s.blocked[i], true
	}
	return 0, false, false
}

// Complete visits only the result's outgoing edges. Even a blocked dependent
// waits for every parent, preserving DepsState's all-dependencies-ready rule.
// Repeated completions cannot decrement a dependency twice.
func (s *ProbeScheduler) Complete(r ProbeResult) {
	if s.completed[r.ID] {
		return
	}
	s.completed[r.ID] = true
	for _, i := range s.dependents[r.ID] {
		s.blocked[i] = s.blocked[i] || r.Status == StatusFail || r.Status == StatusSkip
		s.remaining[i]--
		if s.remaining[i] == 0 {
			s.ready = append(s.ready, i)
		}
	}
}
