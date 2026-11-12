package collector

import "sync"

type Stage uint8

const (
	StageRefused Stage = iota
	StageDecoded
	StageLaunchVerified
	StageProducersStopped
	StageInputsFrozen
	StagePackageVerified
	StageHandoffComplete
	StageConsumed
)

// Lifecycle is a handle to one attempt. Copies share state and consumption.
// It has no public promotion API. A future trusted supervisor must own promotion,
// not an envelope, a caller-supplied validation flag, or a serialized receipt.
type Lifecycle struct{ attempt *attempt }

type attempt struct {
	mu       sync.Mutex
	stage    Stage
	envelope Envelope
	err      *Refusal
}

func NewLifecycle(u UntrustedEnvelope) *Lifecycle {
	a := &attempt{stage: StageDecoded, envelope: u.Claims()}
	if u.envelope == nil {
		a.stage, a.err = StageRefused, refusal(Unauthenticated)
	}
	return &Lifecycle{attempt: a}
}

func (l *Lifecycle) State() Stage {
	if l == nil || l.attempt == nil {
		return StageRefused
	}
	l.attempt.mu.Lock()
	defer l.attempt.mu.Unlock()
	return l.attempt.stage
}

// advance models the trusted stages only. No runtime caller exists in this slice.
// Wiring a caller requires independent review of the supervisor and handoff.
func (l *Lifecycle) advance(next Stage) error {
	if l == nil || l.attempt == nil {
		return refusal(Unauthenticated)
	}
	a := l.attempt
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	if a.stage == StageConsumed {
		return refusal(Replay)
	}
	if next != a.stage+1 || next < StageLaunchVerified || next > StageHandoffComplete {
		a.stage, a.err = StageRefused, refusal(InvalidTransition)
		return a.err
	}
	a.stage = next
	return nil
}

// Abort is terminal. A consumed result cannot be issued again or revoked here.
func (l *Lifecycle) Abort() {
	if l == nil || l.attempt == nil {
		return
	}
	a := l.attempt
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stage != StageConsumed && a.err == nil {
		a.stage, a.err = StageRefused, refusal(Aborted)
	}
}

// Result consumes one completed internal handoff. Calling early refuses the
// attempt permanently. All publicly constructible lifecycles are incomplete.
func (l *Lifecycle) Result() (TrustedResult, error) {
	if l == nil || l.attempt == nil {
		return TrustedResult{}, refusal(Unauthenticated)
	}
	a := l.attempt
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return TrustedResult{}, a.err
	}
	if a.stage == StageConsumed {
		return TrustedResult{}, refusal(Replay)
	}
	if a.stage != StageHandoffComplete {
		a.stage, a.err = StageRefused, refusal(Incomplete)
		return TrustedResult{}, a.err
	}
	a.stage = StageConsumed
	return TrustedResult{receipt: &receipt{envelope: a.envelope}}, nil
}

type receipt struct{ envelope Envelope }

// TrustedResult is an in-process receipt, never a portable authentication seal.
// Only a completed internal lifecycle can create one. Zero values are invalid.
type TrustedResult struct{ receipt *receipt }

func (r TrustedResult) Valid() bool { return r.receipt != nil }

// SelectedFIBVerified is always false, including for a completed cohort handoff.
// A historical kernel ACK does not prove a selected-FIB checkpoint.
func (r TrustedResult) SelectedFIBVerified() bool { return false }

func (r TrustedResult) Claims() (Envelope, error) {
	if r.receipt == nil {
		return Envelope{}, refusal(Unauthenticated)
	}
	return r.receipt.envelope, nil
}

func (r TrustedResult) MarshalJSON() ([]byte, error) { return nil, refusal(Unauthenticated) }

func (r *TrustedResult) UnmarshalJSON([]byte) error {
	r.receipt = nil
	return refusal(Unauthenticated)
}
