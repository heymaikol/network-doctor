// The Checks panel's collateral marking: an offline machine fails four probes
// at once, and only one of them is a thing to go and fix.

package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/v2/internal/diagnostic"
)

// finishedRun fills every probe with a result: the ones named take the status
// given, the rest pass. Finalize runs afterwards so the cross-probe passes the
// real runner applies (the proxy-only egress downgrade above all) have shaped
// the results the view reads.
func finishedRun(m *model, status map[diagnostic.ProbeID]diagnostic.Status) {
	for _, p := range m.probes {
		s, ok := status[p.ID]
		if !ok {
			s = diagnostic.StatusPass
		}
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: s, Detail: "detail", Fix: "fix"}
	}
	diagnostic.Finalize(m.results)
}

// probeRow is the Checks panel's row for one probe, "" when the panel drew
// none. The name is matched after the label is taken off and in full, because
// "DNS" is a prefix of two other probe names.
func probeRow(v, name string) string {
	for _, row := range checksRows(v) {
		text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(row), consequenceLabel))
		text = strings.TrimSpace(strings.TrimPrefix(text, "›"))
		if _, rest, ok := strings.Cut(text, " "); ok && rest == name {
			return row
		}
	}
	return ""
}

// offlineRun is the finding's case: the interface is up and nothing else is.
// Egress is the failure to act on; QUIC, DNS and encrypted DNS are three more
// probes reporting the same dead path.
func offlineRun(t *testing.T, target *diagnostic.Target) model {
	t.Helper()
	m := newModel(target, false)
	finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
		diagnostic.ProbeInternet:     diagnostic.StatusFail,
		diagnostic.ProbeQUIC:         diagnostic.StatusFail,
		diagnostic.ProbeDNS:          diagnostic.StatusFail,
		diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
		diagnostic.ProbeDNSPublic:    diagnostic.StatusNA,
		diagnostic.ProbeProxy:        diagnostic.StatusNA,
		diagnostic.ProbeSSID:         diagnostic.StatusNA,
		diagnostic.ProbeTargetTCP:    diagnostic.StatusSkip,
		diagnostic.ProbePMTU:         diagnostic.StatusSkip,
		diagnostic.ProbeTLS:          diagnostic.StatusSkip,
		diagnostic.ProbeHTTP:         diagnostic.StatusSkip,
		diagnostic.ProbeHTTPS:        diagnostic.StatusSkip,
	})
	return m
}

// TestChecksPanelMarksCollateralFailures renders the real view and reads the
// Checks panel back. The positive half is the offline shape: the row worth
// acting on keeps its plain failure treatment and the three rows that are the
// same outage seen again say so. The negative half is every diagnosis that
// blames a row further down the list, which must not lose its prominence just
// for having a failure above it.
func TestChecksPanelMarksCollateralFailures(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T) model
		want   []diagnostic.ProbeID
		actual diagnostic.ProbeID // the row the diagnosis blames
	}{
		{
			name:  "offline",
			build: func(t *testing.T) model { return offlineRun(t, nil) },
			want: []diagnostic.ProbeID{
				diagnostic.ProbeQUIC, diagnostic.ProbeDNS, diagnostic.ProbeDNSEncrypted,
			},
			actual: diagnostic.ProbeInternet,
		},
		{
			name: "DNS failing while egress works",
			build: func(t *testing.T) model {
				m := newModel(nil, false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeDNS:       diagnostic.StatusFail,
					diagnostic.ProbeProxy:     diagnostic.StatusNA,
					diagnostic.ProbeDNSPublic: diagnostic.StatusNA,
				})
				return m
			},
			actual: diagnostic.ProbeDNS,
		},
		{
			name: "encrypted DNS blocked on its own",
			build: func(t *testing.T) model {
				m := newModel(nil, false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
					diagnostic.ProbeProxy:        diagnostic.StatusNA,
					diagnostic.ProbeDNSPublic:    diagnostic.StatusNA,
				})
				return m
			},
			actual: diagnostic.ProbeDNSEncrypted,
		},
		{
			name: "QUIC blocked on its own",
			build: func(t *testing.T) model {
				m := newModel(nil, false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeQUIC:      diagnostic.StatusFail,
					diagnostic.ProbeProxy:     diagnostic.StatusNA,
					diagnostic.ProbeDNSPublic: diagnostic.StatusNA,
				})
				return m
			},
			actual: diagnostic.ProbeQUIC,
		},
		{
			name: "proxy-only network with the resolver down too",
			build: func(t *testing.T) model {
				m := newModel(nil, false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeInternet:     diagnostic.StatusFail,
					diagnostic.ProbeQUIC:         diagnostic.StatusFail,
					diagnostic.ProbeDNS:          diagnostic.StatusFail,
					diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
					diagnostic.ProbeDNSPublic:    diagnostic.StatusNA,
				})
				return m
			},
			// The proxy proves the network carries traffic, so the resolver
			// failing on top of it is its own problem and keeps its red. The
			// rows that go direct by construction do not: the direct path is
			// down, so their failures are that one dead path seen again.
			want:   []diagnostic.ProbeID{diagnostic.ProbeQUIC, diagnostic.ProbeDNSEncrypted},
			actual: diagnostic.ProbeDNS,
		},
		{
			name: "the target's own service failing",
			build: func(t *testing.T) model {
				m := newModel(mustTarget(t, "example.com:443"), false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeTLS:       diagnostic.StatusFail,
					diagnostic.ProbeHTTPS:     diagnostic.StatusSkip,
					diagnostic.ProbeProxy:     diagnostic.StatusNA,
					diagnostic.ProbeDNSPublic: diagnostic.StatusNA,
				})
				return m
			},
			actual: diagnostic.ProbeTLS,
		},
		{
			name: "three failures a working path leaves independently actionable",
			build: func(t *testing.T) model {
				m := newModel(nil, false)
				finishedRun(&m, map[diagnostic.ProbeID]diagnostic.Status{
					diagnostic.ProbeQUIC:         diagnostic.StatusFail,
					diagnostic.ProbeProxy:        diagnostic.StatusFail,
					diagnostic.ProbeDNSEncrypted: diagnostic.StatusFail,
					diagnostic.ProbeDNSPublic:    diagnostic.StatusNA,
				})
				return m
			},
			actual: diagnostic.ProbeQUIC,
		},
		{
			name:  "offline against a target, where the verdict names DNS",
			build: func(t *testing.T) model { return offlineRun(t, mustTarget(t, "example.com:443")) },
			want: []diagnostic.ProbeID{
				diagnostic.ProbeQUIC, diagnostic.ProbeDNSEncrypted,
			},
			// The egress row failed first, but the sentence on screen is about
			// the resolver, so that is the row the reader is sent to.
			actual: diagnostic.ProbeDNS,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := c.build(t)
			nm, v := renderAt(t, m)
			v = ansi.Strip(v)
			marked := map[diagnostic.ProbeID]bool{}
			for _, id := range c.want {
				marked[id] = true
			}
			failed := 0
			for _, probe := range rowProbes(nm) {
				if nm.results[probe.ID].Status != diagnostic.StatusFail {
					continue
				}
				failed++
				row := probeRow(v, probe.Name)
				if row == "" {
					t.Fatalf("failed probe %s has no row:\n%s", probe.ID, v)
				}
				got := strings.Contains(row, consequenceLabel)
				if got != marked[probe.ID] {
					t.Errorf("row %q labelled %v, want %v:\n%s", row, got, marked[probe.ID], v)
				}
			}
			if failed == 0 {
				t.Fatal("no failed rows, so nothing about their treatment is under test")
			}
			// The row the diagnosis blames is the one the banner takes its Fix
			// from, so it can never be the row that is dimmed.
			if c.actual != "" {
				if i := nm.focusRow(); i < 0 || nm.probes[i].ID != c.actual {
					t.Fatalf("the run blames row %d, want %s", i, c.actual)
				}
				if row := probeRow(v, nm.probes[nm.focusRow()].Name); strings.Contains(row, consequenceLabel) {
					t.Errorf("the blamed row %q is marked a consequence:\n%s", row, v)
				}
			}
			// Presentation only: the probe results the report and the JSON
			// output are built from say exactly what they said before.
			for id := range marked {
				if got := nm.results[id].Status; got != diagnostic.StatusFail {
					t.Errorf("%s is %s in the results, want Fail", id, got)
				}
			}
		})
	}
}

// TestCollateralLabelWaitsForTheDiagnosis: nothing is a consequence of
// anything until every probe has reported. A run still in flight has no
// verdict to derive the labels from, and guessing one mid-run would move the
// labels around as results land.
func TestCollateralLabelWaitsForTheDiagnosis(t *testing.T) {
	m := newModel(nil, false)
	m.results[diagnostic.ProbeIface] = diagnostic.ProbeResult{ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass}
	m.results[diagnostic.ProbeInternet] = diagnostic.ProbeResult{ID: diagnostic.ProbeInternet, Status: diagnostic.StatusFail}
	m.results[diagnostic.ProbeQUIC] = diagnostic.ProbeResult{ID: diagnostic.ProbeQUIC, Status: diagnostic.StatusFail}
	if _, v := renderAt(t, m); strings.Contains(ansi.Strip(v), consequenceLabel) {
		t.Errorf("an unfinished run already marks consequences:\n%s", v)
	}
}

// TestCollateralLabelFollowsTheLatestWatchPass: the labels are derived from the
// results on screen, so a watch pass that repairs the path takes them away
// with it rather than leaving the previous outage's marking behind.
func TestCollateralLabelFollowsTheLatestWatchPass(t *testing.T) {
	m := offlineRun(t, nil)
	m.watch = true
	for _, p := range m.probes {
		m.runHistory[p.ID] = []diagnostic.Status{m.results[p.ID].Status}
	}
	nm, v := renderAt(t, m)
	if !strings.Contains(ansi.Strip(v), consequenceLabel) {
		t.Fatalf("the offline pass marks no consequences:\n%s", v)
	}
	finishedRun(&nm, nil) // the next pass: everything works
	for _, p := range nm.probes {
		nm.runHistory[p.ID] = append(nm.runHistory[p.ID], nm.results[p.ID].Status)
	}
	if _, v := renderAt(t, nm); strings.Contains(ansi.Strip(v), consequenceLabel) {
		t.Errorf("a healthy pass still carries the previous pass's labels:\n%s", v)
	}
}

// TestCollateralLabelSurvivesNarrowTerminals: the label is placed against the
// panel's own width, so it never widens the block past the terminal and never
// costs the Checks panel a row it did not account for.
func TestCollateralLabelSurvivesNarrowTerminals(t *testing.T) {
	for _, width := range []int{40, 60, 80, 100, 140} {
		m := offlineRun(t, nil)
		m.width, m.height = width, 40
		block := m.bodyView(false, 0)
		if got := lipgloss.Width(block); got > width {
			t.Errorf("width %d: the block is %d columns wide:\n%s", width, got, block)
		}
		if n := unclosedPanels(block); n != 0 {
			t.Errorf("width %d: %d panel border(s) left unclosed:\n%s", width, n, block)
		}
		if n := strings.Count(ansi.Strip(block), consequenceLabel); n != 3 {
			t.Errorf("width %d: %d consequence labels, want 3:\n%s", width, n, block)
		}
	}
}
