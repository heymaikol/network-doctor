package simulation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Scheduled fault types. Each one changes an already-built topology while
// netdoc is running, at offsets measured from a single simulation epoch.
const (
	// FaultScheduledNetem moves one node interface between netem states.
	FaultScheduledNetem = "scheduled_netem"
	// FaultScheduledDNS moves one simulator DNS service between response
	// behaviours: answering, SERVFAIL, silence, or a bounded delay.
	FaultScheduledDNS = "scheduled_dns"
	// FaultScheduledLink administratively raises or lowers one node interface.
	FaultScheduledLink = "scheduled_link"
)

// Scheduled DNS outcomes. DNSOutcomeAnswer and DNSOutcomeSERVFAIL are shared
// with the per-query DNSFault schedule.
const (
	// DNSOutcomeDrop sends nothing at all, so the client waits out its timeout.
	DNSOutcomeDrop = "drop"
	// DNSOutcomeDelay answers correctly, late.
	DNSOutcomeDelay = "delay"
)

// Link states a scheduled_link event may ask for.
const (
	LinkStateUp   = "up"
	LinkStateDown = "down"
)

// Bounds. A scenario is rejected before any namespace exists when it exceeds
// them, so a pathological file costs nothing.
const (
	maxScheduledEvents  = 16
	maxTimelineEvents   = 64
	maxScheduledOffset  = 30 * time.Second
	maxDNSResponseDelay = 5 * time.Second
	// minDNSResponseDelay is the smallest delay the node holder can be told
	// to hold an answer for: the wire format carries whole milliseconds, so
	// anything shorter would serialize to 0 and be rejected there.
	minDNSResponseDelay = time.Millisecond
)

// ScheduledEvent is one timed change written in a scenario file. Every field is
// a validated value: no command, device name, qdisc handle or path can be
// spelled here.
type ScheduledEvent struct {
	// At is the offset from T0, as a Go duration ("700ms").
	At string `yaml:"at"`
	// Latency, Jitter and LossPercent describe a scheduled_netem state. All
	// three absent means an unimpaired link.
	Latency     string  `yaml:"latency"`
	Jitter      string  `yaml:"jitter"`
	LossPercent float64 `yaml:"loss_percent"`
	// Outcome and Delay describe a scheduled_dns state. Delay is required by,
	// and only by, the delay outcome.
	Outcome string `yaml:"outcome"`
	Delay   string `yaml:"delay"`
	// State describes a scheduled_link event: up or down.
	State string `yaml:"state"`
}

// TimedEvent is one fully resolved scheduled change. The campaign generator and
// the scenario loader both produce these before T0; nothing about them is
// decided while the simulation runs.
type TimedEvent struct {
	Offset      time.Duration `json:"offset_ms"`
	Type        string        `json:"type"`
	Node        string        `json:"node,omitempty"`
	Segment     string        `json:"segment,omitempty"`
	Service     string        `json:"service,omitempty"`
	Latency     time.Duration `json:"latency_ms,omitempty"`
	Jitter      time.Duration `json:"jitter_ms,omitempty"`
	LossPercent float64       `json:"loss_percent,omitempty"`
	NetemSeed   uint32        `json:"netem_seed,omitempty"`
	Outcome     string        `json:"outcome,omitempty"`
	Delay       time.Duration `json:"delay_ms,omitempty"`
	State       string        `json:"state,omitempty"`
}

// Results of trying to apply one scheduled event.
const (
	EventApplied = "applied"
	// EventSkipped means the run ended, or was cancelled, before this event's
	// offset arrived. It was never applied.
	EventSkipped = "skipped"
	EventFailed  = "error"
)

// FaultEventEvidence is what actually happened to one scheduled event. The
// scheduled offset is the contract; the applied offset is the OS's answer to it.
type FaultEventEvidence struct {
	Event           TimedEvent    `json:"event"`
	ScheduledOffset time.Duration `json:"scheduled_offset_ms"`
	AppliedOffset   time.Duration `json:"applied_offset_ms"`
	State           string        `json:"state"`
	// Observed is what the environment read back after applying the event:
	// the kernel's own rendering of the new qdisc or link state, with the
	// generated device name and qdisc handle left out.
	Observed string `json:"observed,omitempty"`
	Result   string `json:"result"`
	Error    string `json:"error,omitempty"`
}

// validateEvents checks the shape every scheduled fault shares: a bounded,
// strictly increasing, non-negative offset list. checkOne validates the fields
// that belong to this fault's own type.
func (f *Fault) validateEvents(checkOne func(i int, e *ScheduledEvent) error) error {
	if len(f.Events) == 0 {
		return errors.New("events: at least one event is required")
	}
	if len(f.Events) > maxScheduledEvents {
		return fmt.Errorf("events: %d entries, maximum is %d", len(f.Events), maxScheduledEvents)
	}
	previous := time.Duration(-1)
	for i := range f.Events {
		e := &f.Events[i]
		at, err := time.ParseDuration(e.At)
		if err != nil {
			return fmt.Errorf("events[%d].at: %w", i, err)
		}
		switch {
		case at < 0:
			return fmt.Errorf("events[%d].at must not be negative", i)
		case at > maxScheduledOffset:
			return fmt.Errorf("events[%d].at must not exceed %s", i, maxScheduledOffset)
		case at <= previous:
			return fmt.Errorf("events[%d].at %s must be later than the previous event at %s", i, at, previous)
		}
		previous = at
		if err := checkOne(i, e); err != nil {
			return err
		}
	}
	return nil
}

// validateNetemEvent bounds one scheduled netem state.
func validateNetemEvent(i int, e *ScheduledEvent) error {
	if e.Outcome != "" || e.Delay != "" || e.State != "" {
		return fmt.Errorf("events[%d]: scheduled_netem takes latency, jitter and loss_percent only", i)
	}
	for label, raw := range map[string]string{"latency": e.Latency, "jitter": e.Jitter} {
		if raw == "" {
			continue
		}
		if err := validateNetemDuration(fmt.Sprintf("events[%d].%s", i, label), label, raw); err != nil {
			return err
		}
	}
	if e.Jitter != "" && e.Latency == "" {
		return fmt.Errorf("events[%d]: jitter needs a latency to vary", i)
	}
	if math.IsNaN(e.LossPercent) || math.IsInf(e.LossPercent, 0) || e.LossPercent < 0 || e.LossPercent > 100 {
		return fmt.Errorf("events[%d].loss_percent must satisfy 0 <= loss_percent <= 100", i)
	}
	return nil
}

// validateNetemDuration bounds one netem latency or jitter value. label is the
// field path the error names, field the bare name the relation reads with. It
// is the single source of the accepted range, so a campaign variable and the
// scheduled event it compiles into cannot drift apart.
func validateNetemDuration(label, field, raw string) error {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if d < 0 || d > maxNetemDuration {
		return fmt.Errorf("%s must satisfy 0 <= %s <= %s", label, field, maxNetemDuration)
	}
	return nil
}

// validateDNSEvent bounds one scheduled resolver state.
func validateDNSEvent(i int, e *ScheduledEvent) error {
	if e.Latency != "" || e.Jitter != "" || e.LossPercent != 0 || e.State != "" {
		return fmt.Errorf("events[%d]: scheduled_dns takes outcome and delay only", i)
	}
	switch e.Outcome {
	case DNSOutcomeAnswer, DNSOutcomeSERVFAIL, DNSOutcomeDrop:
		if e.Delay != "" {
			return fmt.Errorf("events[%d]: delay belongs to the %q outcome", i, DNSOutcomeDelay)
		}
	case DNSOutcomeDelay:
		d, err := time.ParseDuration(e.Delay)
		if err != nil {
			return fmt.Errorf("events[%d].delay: %w", i, err)
		}
		if d < minDNSResponseDelay || d > maxDNSResponseDelay {
			return fmt.Errorf("events[%d].delay must satisfy %s <= delay <= %s", i, minDNSResponseDelay, maxDNSResponseDelay)
		}
	default:
		return fmt.Errorf("events[%d]: unknown outcome %q (%s, %s, %s or %s)", i, e.Outcome,
			DNSOutcomeAnswer, DNSOutcomeSERVFAIL, DNSOutcomeDrop, DNSOutcomeDelay)
	}
	return nil
}

// validateLinkEvent bounds one scheduled link transition.
func validateLinkEvent(i int, e *ScheduledEvent) error {
	if e.Latency != "" || e.Jitter != "" || e.LossPercent != 0 || e.Outcome != "" || e.Delay != "" {
		return fmt.Errorf("events[%d]: scheduled_link takes state only", i)
	}
	if e.State != LinkStateUp && e.State != LinkStateDown {
		return fmt.Errorf("events[%d]: unknown state %q (%s or %s)", i, e.State, LinkStateUp, LinkStateDown)
	}
	return nil
}

// resolve turns one validated scheduled fault into its timed events. The
// durations were already parsed once by validation, so the errors are gone.
func (f *Fault) resolve() []TimedEvent {
	out := make([]TimedEvent, 0, len(f.Events))
	for _, e := range f.Events {
		at, _ := time.ParseDuration(e.At)
		event := TimedEvent{Offset: at, Type: f.Type, Node: f.Node, Segment: f.Segment, Service: f.Service}
		switch f.Type {
		case FaultScheduledNetem:
			event.Latency, _ = time.ParseDuration(e.Latency)
			event.Jitter, _ = time.ParseDuration(e.Jitter)
			event.LossPercent, event.NetemSeed = e.LossPercent, f.Seed
		case FaultScheduledDNS:
			event.Outcome = e.Outcome
			event.Delay, _ = time.ParseDuration(e.Delay)
		case FaultScheduledLink:
			event.State = e.State
		}
		out = append(out, event)
	}
	return out
}

// timelineFrom collects every scheduled fault into one canonically ordered
// timeline. Two scenarios that ask for the same changes at the same offsets
// produce the same slice regardless of the order the faults were written in.
func timelineFrom(faults []Fault) []TimedEvent {
	var out []TimedEvent
	for i := range faults {
		switch faults[i].Type {
		case FaultScheduledNetem, FaultScheduledDNS, FaultScheduledLink:
			out = append(out, faults[i].resolve()...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// key is the canonical rendering of one event. It is what ordering and
// fingerprinting agree on: requested values only, never an applied timestamp,
// simulation id, kernel interface name or error text.
func (e TimedEvent) key() string {
	return strings.Join([]string{
		fmt.Sprintf("%020d", e.Offset),
		e.Type, e.Node, e.Segment, e.Service,
		strconv.FormatInt(int64(e.Latency), 10),
		strconv.FormatInt(int64(e.Jitter), 10),
		strconv.FormatFloat(e.LossPercent, 'f', 2, 64),
		strconv.FormatUint(uint64(e.NetemSeed), 10),
		e.Outcome,
		strconv.FormatInt(int64(e.Delay), 10),
		e.State,
	}, "\x00")
}

// summary is the one-line human rendering used in the fault timeline block.
func (e TimedEvent) summary() string {
	switch e.Type {
	case FaultScheduledNetem:
		var parts []string
		if e.Latency > 0 {
			parts = append(parts, "latency "+e.Latency.String())
		}
		if e.Jitter > 0 {
			parts = append(parts, "jitter "+e.Jitter.String())
		}
		if e.LossPercent > 0 {
			parts = append(parts, fmt.Sprintf("loss %.2f%%", e.LossPercent))
		}
		if len(parts) == 0 {
			parts = append(parts, "unimpaired")
		}
		return fmt.Sprintf("%s/%s %s", e.Node, e.Segment, strings.Join(parts, ", "))
	case FaultScheduledDNS:
		switch e.Outcome {
		case DNSOutcomeAnswer:
			return e.Service + " answers normally"
		case DNSOutcomeSERVFAIL:
			return e.Service + " returns SERVFAIL"
		case DNSOutcomeDrop:
			return e.Service + " responses dropped"
		case DNSOutcomeDelay:
			return e.Service + " answers after " + e.Delay.String()
		}
	case FaultScheduledLink:
		return fmt.Sprintf("%s/%s link %s", e.Node, e.Segment, e.State)
	}
	return e.Type
}

// timelineFingerprint identifies a requested timeline. Equivalent timelines
// hash identically; how long the OS actually took to apply them never enters.
func timelineFingerprint(events []TimedEvent) string {
	h := sha256.New()
	for _, e := range events {
		h.Write([]byte(e.key()))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// scheduler applies a precomputed timeline from one epoch. It is a single
// goroutine driving a single timer: no event is decided, reordered or created
// while the simulation runs, and none survives cancellation.
type scheduler struct {
	done     chan struct{}
	ready    chan struct{}
	evidence []FaultEventEvidence
}

// startScheduler begins applying events. t0 is the simulation epoch every
// offset is measured from, the instant just before the first netdoc process
// starts. Cancelling ctx stops the scheduler; wait joins it.
func startScheduler(ctx context.Context, env Env, events []TimedEvent, t0 time.Time) *scheduler {
	s := &scheduler{done: make(chan struct{}), ready: make(chan struct{})}
	go s.run(ctx, env, events, t0)
	// Offset-zero events describe the topology's initial scheduled state. Do
	// not let the first netdoc process race those baseline transitions.
	<-s.ready
	return s
}

func (s *scheduler) run(ctx context.Context, env Env, events []TimedEvent, t0 time.Time) {
	defer close(s.done)
	ready := false
	markReady := func() {
		if !ready {
			close(s.ready)
			ready = true
		}
	}
	defer markReady()
	// One timer for the whole timeline, reset per event, rather than a
	// time.After per iteration.
	timer := time.NewTimer(time.Hour)
	stop := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	stop()
	defer timer.Stop()

	for i, event := range events {
		if event.Offset > 0 {
			markReady()
		}
		if wait := event.Offset - time.Since(t0); wait > 0 {
			timer.Reset(wait)
			select {
			case <-ctx.Done():
				stop()
				s.skip(events[i:])
				return
			case <-timer.C:
			}
		}
		// Cancellation between the timer firing and the apply must still stop:
		// cleanup may already be dismantling what this event would touch.
		if ctx.Err() != nil {
			s.skip(events[i:])
			return
		}
		item := FaultEventEvidence{Event: event, ScheduledOffset: event.Offset,
			State: event.summary(), Result: EventApplied}
		observed, err := env.ApplyTimedEvent(ctx, event)
		item.AppliedOffset, item.Observed = time.Since(t0), observed
		if err != nil {
			item.Result, item.Error = EventFailed, err.Error()
		}
		s.evidence = append(s.evidence, item)
	}
}

func (s *scheduler) skip(remaining []TimedEvent) {
	for _, event := range remaining {
		s.evidence = append(s.evidence, FaultEventEvidence{Event: event, ScheduledOffset: event.Offset,
			State: event.summary(), Result: EventSkipped})
	}
}

// wait joins the scheduler goroutine and returns what it did. Callers must call
// it before teardown starts: no scheduled event may reach an environment that
// is being cleaned up.
func (s *scheduler) wait() []FaultEventEvidence {
	<-s.done
	return s.evidence
}

// transitionsDuring returns the events applied inside a half-open window, which
// is how the report answers "did the network change while this probe ran".
func transitionsDuring(timeline []FaultEventEvidence, from, to time.Duration) []FaultEventEvidence {
	var out []FaultEventEvidence
	for _, item := range timeline {
		if item.Result == EventApplied && item.AppliedOffset >= from && item.AppliedOffset < to {
			out = append(out, item)
		}
	}
	return out
}
