package ui

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/compare"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/incident"
	ndoc "github.com/heymaikol/network-doctor/internal/snapshot"
)

// recordIncident converts a completed Watch pass through the canonical
// snapshot builder, then hands it to the bounded incident state machine.
func (m *model) recordIncident(at time.Time) {
	s := diagnostic.BuildSnapshot(m.target, m.probes, m.results)
	s.CreatedAt = at.UTC().Format(time.RFC3339)
	s.Tool = ndoc.Tool{Version: m.version, OS: runtime.GOOS, Arch: runtime.GOARCH}
	s.Options = ndoc.Options{
		ProbeTimeoutMs: diagnostic.ProbeTimeoutMs(m.probeTimeout),
		PublicDNS:      m.publicDNS, PublicDNSAuto: m.publicDNSAuto,
		Check: append([]string(nil), m.snapshotCheck...), Skip: append([]string(nil), m.snapshotSkip...),
	}
	if m.sources != nil {
		source := ndoc.Source{Interface: m.sources.Iface}
		if m.sources.IPv4 != nil {
			source.IPv4 = m.sources.IPv4.String()
		}
		if m.sources.IPv6 != nil {
			source.IPv6 = m.sources.IPv6.String()
		}
		s.Options.Source = &source
	}
	m.incidents.Observe(at, s)
	if !m.incidentViewing {
		m.incidentSelected = max(len(m.incidents.Incidents())-1, 0)
		return
	}
	m.incidentSelected = min(m.incidentSelected, max(len(m.incidents.Incidents())-1, 0))
	m.refreshIncidentViewport(false)
}

func (m model) incidentNow() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *model) openIncidentViewer() {
	m.incidentViewing = true
	m.incidentSelected = max(len(m.incidents.Incidents())-1, 0)
	m.incidentVP = viewport.New(max(m.width, 1), max(m.height-4, 1))
	m.incidentVP.KeyMap = viewport.KeyMap{}
	m.refreshIncidentViewport(true)
}

func (m model) selectedIncident() (incident.Incident, bool) {
	items := m.incidents.Incidents()
	if len(items) == 0 {
		return incident.Incident{}, false
	}
	at := min(max(m.incidentSelected, 0), len(items)-1)
	return items[at], true
}

func (m *model) refreshIncidentViewport(reset bool) {
	selected, ok := m.selectedIncident()
	if !ok {
		m.incidentViewing = false
		return
	}
	width := max(m.width, 1)
	height := 20
	if m.height > 0 {
		height = max(m.height-4, 1)
	}
	offset := m.incidentVP.YOffset
	m.incidentVP.Width, m.incidentVP.Height = width, height
	report := incidentReport(selected, m.incidentSelected+1, len(m.incidents.Incidents()), m.incidentNow())
	m.incidentVP.SetContent(ansi.Wrap(report, width, ""))
	if reset {
		m.incidentVP.GotoTop()
	} else {
		m.incidentVP.SetYOffset(offset)
	}
}

func (m model) incidentView() string {
	total := len(m.incidents.Incidents())
	header := m.st.title.Render(fmt.Sprintf("Watch incidents  %d of %d", m.incidentSelected+1, total))
	if dropped := m.incidents.Dropped(); dropped > 0 {
		header += m.st.faint.Render(fmt.Sprintf("  ·  %d older discarded", dropped))
	}
	top, bottom, lines := m.incidentVP.YOffset+1, m.incidentVP.YOffset+m.incidentVP.Height, m.incidentVP.TotalLineCount()
	if bottom > lines {
		bottom = lines
	}
	if top > bottom {
		top = bottom
	}
	context := m.st.faint.Render(fmt.Sprintf("lines %d-%d of %d", top, bottom, lines))
	footer := helpKeys(m.st, m.width, "←/→", "incident", "↑/↓", "scroll", "pgup/pgdn", "page", "y", "copy", "w", "save .ndoc", "esc/q", "back")
	if notice := m.noticeView(); notice != "" {
		footer = notice
	}
	return header + "\n" + m.incidentVP.View() + "\n" + context + "\n" + footer
}

func (m model) handleIncidentKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q", "i":
		m.incidentViewing = false
		return m, nil
	case "left", "h":
		if m.incidentSelected > 0 {
			m.incidentSelected--
			m.refreshIncidentViewport(true)
		}
	case "right", "l":
		if m.incidentSelected+1 < len(m.incidents.Incidents()) {
			m.incidentSelected++
			m.refreshIncidentViewport(true)
		}
	case "up", "k":
		m.incidentVP.ScrollUp(1)
	case "down", "j":
		m.incidentVP.ScrollDown(1)
	case "pgup":
		m.incidentVP.PageUp()
	case "pgdown":
		m.incidentVP.PageDown()
	case "home":
		m.incidentVP.GotoTop()
	case "end":
		m.incidentVP.GotoBottom()
	case "y":
		selected, _ := m.selectedIncident()
		if err := copyReport(incidentReport(selected, m.incidentSelected+1, len(m.incidents.Incidents()), m.incidentNow())); err != nil {
			return m, m.setNotice("copy failed: "+err.Error(), false)
		}
		return m, m.setNotice("incident sent to clipboard (OSC 52); w saves an .ndoc", true)
	case "w":
		selected, _ := m.selectedIncident()
		notice, ok := exportIncident(selected)
		return m, m.setNotice(notice, ok)
	}
	return m, nil
}

func incidentReport(i incident.Incident, position, total int, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Network Doctor incident %d of %d\n", position, total)
	state := "active"
	if !i.Active() {
		state = "recovered"
	}
	fmt.Fprintf(&b, "state: %s\nstarted: %s\nduration: %s\nfailing passes: %d\n", state,
		i.Started.UTC().Format(time.RFC3339), durationText(i.Duration(now)), i.Passes)
	if !i.Ended.IsZero() {
		fmt.Fprintf(&b, "recovered: %s\n", i.Ended.UTC().Format(time.RFC3339))
	}
	if i.Before == nil {
		b.WriteString("pre-failure state: unavailable; this watch session began during the failure\n")
	} else {
		fmt.Fprintf(&b, "pre-failure state: %s at %s\n", snapshotVerdict(i.Before.Snap), i.Before.At.UTC().Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "failure onset: %s\n", snapshotVerdict(i.Onset.Snap))
	b.WriteString("\nChanges at failure onset\n")
	writeChanges(&b, "Recorded path and configuration changes", incident.Environment(i.OnsetChanges))
	writeChanges(&b, "Diagnostic outcome changes", incident.Outcome(i.OnsetChanges))
	b.WriteString("\nTemporal evidence\n  " + i.Note() + "\n")
	b.WriteString("\nDiagnosis\n  " + snapshotVerdict(i.Onset.Snap) + "\n")
	writeCausalEvidence(&b, i.Onset.Snap)

	b.WriteString("\nWhile failing\n")
	if i.StepsDropped > 0 {
		fmt.Fprintf(&b, "  %d older state changes discarded by the retention bound\n", i.StepsDropped)
	}
	if len(i.Steps) == 0 {
		b.WriteString("  No additional semantic state change was recorded.\n")
	}
	for _, step := range i.Steps {
		fmt.Fprintf(&b, "  %s\n", step.At.UTC().Format(time.RFC3339))
		for _, change := range step.Changes {
			b.WriteString("    - " + change.Summary + "\n")
		}
	}
	if i.During != nil {
		b.WriteString("  final failing state: " + snapshotVerdict(i.During.Snap) + "\n")
	}

	if i.Recovered != nil {
		b.WriteString("\nRecovery\n  " + snapshotVerdict(i.Recovered.Snap) + "\n")
		writeChanges(&b, "Changes when connectivity returned", i.RecoveryChanges)
	}
	return strings.TrimRight(b.String(), "\n")
}

func snapshotVerdict(s ndoc.Snapshot) string {
	if s.Diagnosis.Verdict == "" && s.Diagnosis.Summary == "" {
		if s.OK {
			return "ok"
		}
		return "not ok"
	}
	if s.Diagnosis.Summary == "" {
		return s.Diagnosis.Verdict
	}
	return s.Diagnosis.Verdict + ": " + s.Diagnosis.Summary
}

func writeChanges(b *strings.Builder, heading string, changes []compare.Change) {
	b.WriteString("  " + heading + ":\n")
	if len(changes) == 0 {
		b.WriteString("    none recorded\n")
		return
	}
	for _, change := range changes {
		b.WriteString("    - " + change.Summary + "\n")
	}
}

func writeCausalEvidence(b *strings.Builder, s ndoc.Snapshot) {
	if len(s.Diagnosis.Findings) == 0 || len(s.Diagnosis.Findings[0].CausalEvidence) == 0 {
		b.WriteString("  causal evidence: none recorded\n")
		return
	}
	b.WriteString("  causal evidence:\n")
	for _, evidence := range s.Diagnosis.Findings[0].CausalEvidence {
		b.WriteString("    - " + snapshotEvidenceLine(s, evidence) + "\n")
	}
}

func snapshotEvidenceLine(s ndoc.Snapshot, evidence ndoc.CausalEvidence) string {
	label, detail := evidence.Check, ""
	for _, check := range s.Checks {
		if check.ID == evidence.Check {
			if check.Name != "" {
				label = check.Name
			}
			detail = check.Detail
			break
		}
	}
	observation := evidence.Observation
	if detail != "" {
		observation = detail
	} else if evidence.Value != "" {
		observation += ": " + evidence.Value
	}
	switch evidence.Kind {
	case ndoc.EvidenceRuledOut:
		return "ruled out " + evidence.Candidate + " using " + label + ": " + observation
	case ndoc.EvidenceContradiction:
		return "against " + evidence.Candidate + " from " + label + ": " + observation
	case ndoc.EvidenceNotEvaluated:
		return label + " not evaluated: " + evidence.Reason
	default:
		return label + ": " + observation
	}
}

func durationText(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

var incidentWriteFile = writeFileExcl

func exportIncident(i incident.Incident) (string, bool) {
	data, err := ndoc.Encode(i.Artifact())
	if err != nil {
		return "save failed: " + err.Error(), false
	}
	name := "network-doctor-incident-" + i.Started.UTC().Format("20060102-150405") + ndoc.Extension
	path, err := filepath.Abs(name)
	if err == nil {
		err = incidentWriteFile(path, data, 0o600)
	}
	if err != nil {
		home, homeErr := reportUserHomeDir()
		if homeErr != nil {
			return "save failed: " + homeErr.Error(), false
		}
		path, err = filepath.Abs(filepath.Join(home, name))
		if err == nil {
			err = incidentWriteFile(path, data, 0o600)
		}
	}
	if err != nil {
		return "save failed: " + err.Error(), false
	}
	return "incident saved to " + path, true
}
