package diagnostic

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// The probe timeout has one accepted precision, and this is the table that says
// what it is. Everything downstream (the remote request, the snapshot option,
// the comparison that reads it back) is an integer millisecond field, so the
// values rejected here are exactly the ones that could not survive the trip.
func TestValidateProbeTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      time.Duration
		wantErr string
	}{
		{"default", DefaultProbeTimeout, ""},
		{"smallest accepted", time.Millisecond, ""},
		{"ordinary whole milliseconds", 250 * time.Millisecond, ""},
		{"seconds", 4 * time.Second, ""},
		{"largest whole millisecond duration", time.Duration(MaxProbeTimeoutMs) * time.Millisecond, ""},
		{"zero", 0, "must be positive"},
		{"negative", -time.Second, "must be positive"},
		{"negative sub-millisecond", -time.Microsecond, "must be positive"},
		{"sub-millisecond", 500 * time.Microsecond, "whole number of milliseconds"},
		{"one nanosecond", time.Nanosecond, "whole number of milliseconds"},
		{"999us", 999 * time.Microsecond, "whole number of milliseconds"},
		{"1.1ms", 1_100 * time.Microsecond, "whole number of milliseconds"},
		{"1.5ms", 1_500 * time.Microsecond, "whole number of milliseconds"},
		{"1.9ms", 1_900 * time.Microsecond, "whole number of milliseconds"},
		{"maximum duration", time.Duration(math.MaxInt64), "whole number of milliseconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProbeTimeout(tc.in)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("ValidateProbeTimeout(%v) = %v, want accepted", tc.in, err)
			case tc.wantErr == "":
				return
			case err == nil:
				t.Fatalf("ValidateProbeTimeout(%v) accepted, want %q", tc.in, tc.wantErr)
			case !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("ValidateProbeTimeout(%v) = %q, want it to mention %q", tc.in, err, tc.wantErr)
			}
		})
	}
}

// Every accepted timeout survives the round trip through the millisecond field
// exactly. That is the whole point of the restriction above: the projection is
// not approximately right for accepted values, it is the same duration back.
func TestAcceptedProbeTimeoutRoundTripsThroughMilliseconds(t *testing.T) {
	for _, d := range []time.Duration{
		time.Millisecond, 2 * time.Millisecond, 250 * time.Millisecond,
		DefaultProbeTimeout, 30 * time.Second, time.Hour,
		time.Duration(MaxProbeTimeoutMs) * time.Millisecond,
	} {
		if err := ValidateProbeTimeout(d); err != nil {
			t.Fatalf("ValidateProbeTimeout(%v) = %v, want accepted", d, err)
		}
		ms := ProbeTimeoutMs(d)
		back, err := ProbeTimeoutFromMs(ms)
		if err != nil {
			t.Fatalf("ProbeTimeoutFromMs(%d) = %v, want accepted", ms, err)
		}
		if back != d {
			t.Errorf("%v projected to %dms and came back as %v", d, ms, back)
		}
	}
}

// The millisecond field is untrusted int64 wherever it arrives from, and the
// range check has to happen before the multiplication. 18446744073710 is the
// case that makes that concrete: multiplied first, it wraps all the way around
// int64 into a small positive duration, which no positive-only check can catch.
func TestProbeTimeoutFromMs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ms      int64
		want    time.Duration
		wantErr string
	}{
		{name: "smallest accepted", ms: 1, want: time.Millisecond},
		{name: "ordinary", ms: 4000, want: 4 * time.Second},
		{name: "largest representable", ms: MaxProbeTimeoutMs, want: time.Duration(MaxProbeTimeoutMs) * time.Millisecond},
		{name: "zero", ms: 0, wantErr: "must be positive"},
		{name: "negative", ms: -1, wantErr: "must be positive"},
		{name: "limit plus one", ms: MaxProbeTimeoutMs + 1, wantErr: "must not exceed"},
		{name: "overflows negative", ms: 9223372036855, wantErr: "must not exceed"},
		{name: "overflows back to a plausible positive", ms: 18446744073710, wantErr: "must not exceed"},
		{name: "maximum int64", ms: math.MaxInt64, wantErr: "must not exceed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProbeTimeoutFromMs(tc.ms)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ProbeTimeoutFromMs(%d) = %v, want %q", tc.ms, got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ProbeTimeoutFromMs(%d) = %q, want it to mention %q", tc.ms, err, tc.wantErr)
				}
				if got != 0 {
					t.Errorf("ProbeTimeoutFromMs(%d) returned %v alongside its error", tc.ms, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProbeTimeoutFromMs(%d) = %v, want accepted", tc.ms, err)
			}
			if got != tc.want {
				t.Errorf("ProbeTimeoutFromMs(%d) = %v, want %v", tc.ms, got, tc.want)
			}
			if err := ValidateProbeTimeout(got); err != nil {
				t.Errorf("ProbeTimeoutFromMs(%d) produced %v, which the invocation contract rejects: %v", tc.ms, got, err)
			}
		})
	}
}

// The overflow above is reachable as data, not only as a literal: a JSON number
// that large decodes into int64 fine and only becomes wrong when multiplied.
func TestProbeTimeoutFromMsRejectsAnOverflowingJSONNumber(t *testing.T) {
	var req struct {
		TimeoutMs int64 `json:"timeout_ms"`
	}
	if err := json.Unmarshal([]byte(`{"timeout_ms":18446744073710}`), &req); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeTimeoutFromMs(req.TimeoutMs); err == nil {
		t.Fatalf("ProbeTimeoutFromMs(%d) accepted a value that overflows int64 nanoseconds", req.TimeoutMs)
	}
}
