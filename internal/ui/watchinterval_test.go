package ui

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/charmbracelet/x/ansi"
)

func TestValidateWatchIntervalRefusesBelowTheFloor(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second, 999 * time.Millisecond} {
		if err := ValidateWatchInterval(d); err == nil {
			t.Errorf("ValidateWatchInterval(%v) = nil, want an error", d)
		}
	}
	for _, d := range []time.Duration{time.Second, 1500 * time.Millisecond, time.Minute} {
		if err := ValidateWatchInterval(d); err != nil {
			t.Errorf("ValidateWatchInterval(%v) = %v, want nil", d, err)
		}
	}
}

// The tick that starts the next pass fires after the configured gap. A run
// that set none waits the package default, read when the tick is armed.
func TestWatchCmdWaitsTheConfiguredGap(t *testing.T) {
	prev := WatchEvery
	WatchEvery = 7 * time.Second
	t.Cleanup(func() { WatchEvery = prev })
	cases := []struct {
		name string
		m    model
		want time.Duration
	}{
		{"configured", model{watch: true, watchEvery: 30 * time.Second, generation: 4}, 30 * time.Second},
		{"default", model{watch: true, generation: 4}, 7 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				msg := tc.m.watchCmd()()
				if got := time.Since(start); got != tc.want {
					t.Errorf("tick fired after %v, want %v", got, tc.want)
				}
				if wm, ok := msg.(watchMsg); !ok || wm.gen != 4 {
					t.Errorf("tick sent %#v, want a watchMsg for generation 4", msg)
				}
			})
		})
	}
}

// A non-positive option leaves the run on the package default, as
// WithProbeTimeout does for its own zero value.
func TestWithWatchIntervalIgnoresNonPositiveValues(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		m := model{}
		WithWatchInterval(d)(&m)
		if got := m.watchInterval(); got != WatchEvery {
			t.Errorf("WithWatchInterval(%v) gives %v, want the default %v", d, got, WatchEvery)
		}
	}
}

// The interval a watch run uses is shown in the context strip with the
// session, so a person can see the cadence they are looking at.
func TestContextStripShowsTheEffectiveWatchInterval(t *testing.T) {
	const target = "edge-router-observability-control-plane.documentation.example:8443"
	for _, tc := range []struct {
		name  string
		every time.Duration
		want  string
	}{
		{"configured", 30 * time.Second, "watch 30s"},
		{"fractional", 1500 * time.Millisecond, "watch 1.5s"},
		{"default", 0, "watch 5s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := contextHierarchyModel(t, target, 3, true, true)
			m.width, m.height = 100, 40
			m.watchEvery = tc.every
			plain := ansi.Strip(m.headerView())
			lines := strings.Split(plain, "\n")
			if len(lines) < 2 || !strings.Contains(lines[1], tc.want) {
				t.Errorf("operational row = %q, want it to contain %q", lines[1], tc.want)
			}
		})
	}
}
