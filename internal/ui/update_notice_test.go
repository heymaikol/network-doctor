package ui

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/update"
)

// updateView builds the interactive model with one update check whose answer
// is status, and returns it with the request counter.
func updateView(t *testing.T, res update.Result) (model, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	check := func() update.Result {
		calls.Add(1)
		return res
	}
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "2.2.1", "", false,
		diagnostic.ProbeSelection{}, WithUpdateNotice(check)).(model)
	m.width, m.height = 120, 40
	return m, &calls
}

// The header names a newer stable release and nothing else.
func TestUpdateNoticeShowsOnlyANewerRelease(t *testing.T) {
	const phrase = "newer Network Doctor release on GitHub: v2.3.0"
	cases := []struct {
		name string
		res  update.Result
		want bool
	}{
		{"newer release", update.Result{Status: update.UpdateAvailable, Installed: "2.2.1", Latest: "v2.3.0"}, true},
		{"up to date", update.Result{Status: update.UpToDate, Installed: "2.3.0", Latest: "v2.3.0"}, false},
		{"unknown build", update.Result{Status: update.UnknownVersion, Installed: "dev"}, false},
		{"offline", update.Result{Status: update.Offline, Installed: "2.2.1"}, false},
		{"disabled", update.Result{Status: update.Disabled, Installed: "2.2.1"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := updateView(t, tc.res)
			next, _ := m.Update(updateMsg{res: tc.res})
			got := strings.Contains(next.(model).View(), phrase)
			if got != tc.want {
				t.Fatalf("header names the release = %v, want %v", got, tc.want)
			}
		})
	}
}

// Init starts no request itself. The check runs only when its command runs.
func TestInitStartsNoRequestItself(t *testing.T) {
	m, calls := updateView(t, update.Result{Status: update.UpToDate})
	started := time.Now()
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init returned no command")
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("Init made %d requests", n)
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("Init took %v", took)
	}
}

// Negative control: a checker that never returns does not stop the view from
// handling its own messages, so the probes are never held back by the check.
func TestBlockedCheckDoesNotStopTheView(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	m := NewWithSelection(mustTarget(t, "example.com:443"), nil, false, false, "", "2.2.1", "", false,
		diagnostic.ProbeSelection{}, WithUpdateNotice(func() update.Result {
			<-block
			return update.Result{}
		})).(model)
	batch, ok := m.Init()().(tea.BatchMsg)
	if !ok {
		t.Fatal("Init did not batch its commands")
	}
	for _, c := range batch {
		if c != nil {
			go c()
		}
	}
	done := make(chan struct{})
	go func() {
		m.Update(scheduleMsg{gen: 0})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handling a message waited on the blocked update check")
	}
}
