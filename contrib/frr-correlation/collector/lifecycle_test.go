package collector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func decoded(t *testing.T) UntrustedEnvelope {
	t.Helper()
	u, err := Decode(bytes.NewReader(encode(t, exampleEnvelope())))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// modelAt exercises only the transition model, not live authentication.
func modelAt(t *testing.T, stage Stage) *Lifecycle {
	t.Helper()
	l := NewLifecycle(decoded(t))
	for next := StageLaunchVerified; next <= stage; next++ {
		if err := l.advance(next); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func refusalProof(result TrustedResult, err error) error {
	if err == nil || result.Valid() || result.SelectedFIBVerified() {
		return errors.New("invalid evidence became a trusted result")
	}
	if _, claimErr := result.Claims(); claimErr == nil {
		return errors.New("invalid result exposes trusted claims")
	}
	return nil
}

func TestLifecycleRequiresEveryStage(t *testing.T) {
	for stage := StageDecoded; stage <= StageHandoffComplete; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			l := modelAt(t, stage)
			result, err := l.Result()
			if stage != StageHandoffComplete {
				requireCode(t, err, Incomplete)
				if err := refusalProof(result, err); err != nil {
					t.Fatal(err)
				}
				if l.State() != StageRefused {
					t.Fatal("early result did not terminate attempt")
				}
				return
			}
			if err != nil || !result.Valid() || result.SelectedFIBVerified() {
				t.Fatal("complete model failed", err)
			}
			claims, err := result.Claims()
			if err != nil || claims != exampleEnvelope() {
				t.Fatal("receipt lost identity")
			}
			if l.State() != StageConsumed {
				t.Fatal("not consumed")
			}
			_, err = l.Result()
			requireCode(t, err, Replay)
		})
	}
}

func TestEveryInvalidTransitionIsTerminal(t *testing.T) {
	for current := StageDecoded; current <= StageHandoffComplete; current++ {
		for next := StageRefused; next <= StageConsumed+1; next++ {
			if next == current+1 && next <= StageHandoffComplete {
				continue
			}
			t.Run(fmt.Sprintf("%d_to_%d", current, next), func(t *testing.T) {
				l := modelAt(t, current)
				requireCode(t, l.advance(next), InvalidTransition)
				if l.State() != StageRefused {
					t.Fatal("invalid transition did not terminate")
				}
				requireCode(t, l.advance(StageHandoffComplete), InvalidTransition)
				result, err := l.Result()
				if err := refusalProof(result, err); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestZeroValuesCannotCreateTrust(t *testing.T) {
	for _, l := range []*Lifecycle{nil, {}, NewLifecycle(UntrustedEnvelope{})} {
		if l.State() != StageRefused {
			t.Fatal("zero lifecycle state")
		}
		result, err := l.Result()
		requireCode(t, err, Unauthenticated)
		if err := refusalProof(result, err); err != nil {
			t.Fatal(err)
		}
		requireCode(t, l.advance(StageLaunchVerified), Unauthenticated)
		l.Abort()
	}
	var result TrustedResult
	if result.Valid() || result.SelectedFIBVerified() {
		t.Fatal("zero result trusted")
	}
}

func TestAbortCannotBeReversed(t *testing.T) {
	for stage := StageDecoded; stage <= StageHandoffComplete; stage++ {
		l := modelAt(t, stage)
		l.Abort()
		l.Abort()
		requireCode(t, l.advance(StageHandoffComplete), Aborted)
		result, err := l.Result()
		requireCode(t, err, Aborted)
		if err := refusalProof(result, err); err != nil {
			t.Fatal(err)
		}
	}
}

func TestForgedIdentityAndReplayRemainUntrusted(t *testing.T) {
	for _, field := range []string{"namespace", "cohort", "boot", "pid", "start", "epoch", "build", "certificate", "capture", "bundle"} {
		t.Run(field, func(t *testing.T) {
			v := exampleEnvelope()
			switch field {
			case "namespace":
				v.Namespace.Inode++
			case "cohort":
				v.CohortID = v.BootID
			case "boot":
				v.BootID = v.CohortID
			case "pid":
				v.Producers.BGPD.PID++
				v.Producers.Zebra.PID++
			case "start":
				v.Producers.BGPD.StartTimeTicks++
			case "epoch":
				v.Producers.BGPD.Epoch = v.CohortID
			case "build":
				v.BuildID = v.BundleSHA256
			case "certificate":
				v.CertificateSHA256 = v.BundleSHA256
			case "capture":
				v.Producers.BGPD.CaptureSHA256 = v.Producers.Zebra.CaptureSHA256
			case "bundle":
				v.BundleSHA256 = v.BuildID
			}
			// Replaying syntactically valid claims does not authenticate either attempt.
			for range 2 {
				u, err := Decode(bytes.NewReader(encode(t, v)))
				if err != nil {
					t.Fatal("forgery should be syntactically valid", err)
				}
				result, err := NewLifecycle(u).Result()
				if err := refusalProof(result, err); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestInvalidInputCannotBecomeTrusted(t *testing.T) {
	u, err := Decode(bytes.NewReader([]byte(`{"authenticated":true}`)))
	if err == nil {
		t.Fatal("invalid input accepted")
	}
	result, err := NewLifecycle(u).Result()
	if err := refusalProof(result, err); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptCannotBeSerializedOrForged(t *testing.T) {
	result, err := modelAt(t, StageHandoffComplete).Result()
	if err != nil {
		t.Fatal(err)
	}
	_, err = json.Marshal(result)
	requireCode(t, err, Unauthenticated)
	for _, data := range [][]byte{[]byte(`{}`), []byte(`null`), encode(t, exampleEnvelope()), []byte(`{"receipt":{},"authenticated":true,"selected_fib_verified":false}`)} {
		// Even reusing a previously valid destination cannot retain trust.
		copy := result
		requireCode(t, json.Unmarshal(data, &copy), Unauthenticated)
		if copy.Valid() {
			t.Fatal("serialized receipt retained trust")
		}
	}
}

func TestRefusalProofNegativeControl(t *testing.T) {
	accepted, err := modelAt(t, StageHandoffComplete).Result()
	if err != nil {
		t.Fatal(err)
	}
	if refusalProof(accepted, errors.New("pretend refusal")) == nil {
		t.Fatal("oracle missed unexpected trusted acceptance")
	}
	if refusalProof(TrustedResult{}, nil) == nil {
		t.Fatal("oracle missed unexpected success status")
	}
}

func TestLifecycleCopiesShareConsumption(t *testing.T) {
	l := modelAt(t, StageHandoffComplete)
	copy := *l
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_ = copy.State()
			result, err := copy.Result()
			if err == nil {
				if !result.Valid() {
					t.Error("empty successful result")
				}
				accepted.Add(1)
			} else {
				var r *Refusal
				if !errors.As(err, &r) || r.Code() != Replay {
					t.Errorf("unexpected concurrent result: %v", err)
				}
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("result consumed more than once")
	}
	if l.State() != StageConsumed {
		t.Fatal("copy bypassed consumption")
	}
	requireCode(t, l.advance(StageHandoffComplete), Replay)
	l.Abort()
	if l.State() != StageConsumed {
		t.Fatal("abort changed consumed state")
	}
}

func TestConcurrentAbortAndCompletion(t *testing.T) {
	for range 32 {
		l := modelAt(t, StagePackageVerified)
		var wg sync.WaitGroup
		wg.Go(l.Abort)
		wg.Go(func() { _ = l.advance(StageHandoffComplete) })
		wg.Go(func() { _, _ = l.Result() })
		wg.Wait()
		if state := l.State(); state != StageConsumed && state != StageRefused {
			t.Fatal("nonterminal shutdown", state)
		}
	}
}
