package main

import (
	"context"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// startCheckMsg asks the model to begin check idx. gen guards against stale
// reruns: a startCheckMsg whose gen no longer matches the model is ignored.
type startCheckMsg struct {
	idx int
	gen int
}

// checkDoneMsg carries a finished check's result back to Update. It is accepted
// only when running && gen matches && idx is the in-flight check.
type checkDoneMsg struct {
	idx int
	gen int
	res Result
}

// checkRow pairs a check with its result (nil result = pending).
type checkRow struct {
	check  Check
	result *Result
}

type model struct {
	rows     []checkRow
	inFlight int
	spinner  spinner.Model

	generation int
	running    bool

	// Active check's context lifecycle. Owned exclusively by Update — no
	// tea.Cmd ever writes these. cancel is nil when no check is in flight.
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	passStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	failStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	faintStyle = lipgloss.NewStyle().Faint(true)
)

func newModel(cs []Check) model {
	rows := make([]checkRow, len(cs))
	for i, c := range cs {
		rows[i] = checkRow{check: c}
	}
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	return model{rows: rows, spinner: sp}
}

// Init returns only the start command. It sets no state and creates no context
// (value semantics: Init's receiver is not persisted, and a cmd cannot store a
// context for the model).
func (m model) Init() tea.Cmd {
	return func() tea.Msg { return startCheckMsg{idx: 0, gen: 0} }
}

// runCheck runs a check under ctx and reports the result. It reads ctx but
// never writes model state.
func runCheck(ctx context.Context, c Check, idx, gen int) tea.Cmd {
	return func() tea.Msg {
		return checkDoneMsg{idx: idx, gen: gen, res: c.Run(ctx)}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.clearCancel()
			return m, tea.Quit
		case "r":
			// Cancel the in-flight check, invalidate outstanding msgs via a
			// new generation, reset to pending, and restart from the top.
			// Does NOT touch running or seed a tick — the startCheckMsg
			// handler decides based on the running edge.
			m.clearCancel()
			m.generation++
			for i := range m.rows {
				m.rows[i].result = nil
			}
			m.inFlight = 0
			gen := m.generation
			return m, func() tea.Msg { return startCheckMsg{idx: 0, gen: gen} }
		}
		return m, nil

	case startCheckMsg:
		if msg.gen != m.generation {
			return m, nil // stale rerun
		}
		if msg.idx >= len(m.rows) {
			return m, nil
		}
		// Create and store the per-check context synchronously — this is the
		// single place context lifecycle is owned.
		ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
		m.ctx = ctx
		m.cancel = cancel
		m.inFlight = msg.idx

		wasRunning := m.running
		m.running = true

		cmds := []tea.Cmd{runCheck(ctx, m.rows[msg.idx].check, msg.idx, m.generation)}
		if !wasRunning {
			cmds = append(cmds, m.spinner.Tick) // seed exactly one tick on idle->running
		}
		return m, tea.Batch(cmds...)

	case checkDoneMsg:
		// Accept only the live, in-flight check for the current generation.
		if !m.running || msg.gen != m.generation || msg.idx != m.inFlight {
			return m, nil
		}
		m.clearCancel()
		res := msg.res
		m.rows[msg.idx].result = &res

		if msg.idx+1 < len(m.rows) {
			gen := m.generation
			next := msg.idx + 1
			return m, func() tea.Msg { return startCheckMsg{idx: next, gen: gen} }
		}
		m.running = false // tick chain self-terminates
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if !m.running {
			return m, nil // drop the cmd so the chain stops
		}
		return m, cmd
	}

	return m, nil
}

// clearCancel calls and nils the active check's cancel func, if any.
func (m *model) clearCancel() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

func (m model) View() string {
	var b []byte
	b = append(b, "Network Doctor\n\n"...)
	for _, row := range m.rows {
		var glyph string
		if row.result == nil {
			glyph = m.spinner.View()
		} else if row.result.Status {
			glyph = passStyle.Render("✓")
		} else {
			glyph = failStyle.Render("✗")
		}
		line := glyph + " " + row.check.Name
		if row.result != nil && row.result.Detail != "" {
			line += " — " + row.result.Detail
		}
		b = append(b, line...)
		b = append(b, '\n')
		if row.result != nil && !row.result.Status && row.result.Fix != "" {
			b = append(b, faintStyle.Render("    → Fix: "+row.result.Fix)...)
			b = append(b, '\n')
		}
	}
	b = append(b, '\n')
	b = append(b, faintStyle.Render("r: rerun · q: quit")...)
	b = append(b, '\n')
	return string(b)
}
