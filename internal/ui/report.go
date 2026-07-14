package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// exportReport saves the report next to the user (save=true) or copies it to
// the clipboard via OSC 52, and returns the one-line notice for the help bar
// plus whether the export succeeded.
func exportReport(rep string, save bool) (notice string, ok bool) {
	if save {
		name := fmt.Sprintf("network-doctor-%s.txt", time.Now().Format("20060102-150405"))
		if err := os.WriteFile(name, []byte(rep), 0o600); err != nil {
			return "save failed: " + err.Error(), false
		}
		return "report saved to " + name, true
	}
	// stderr, because Bubble Tea owns stdout: both reach the tty, but only one
	// of them is fighting the renderer for it mid-frame.
	if _, err := fmt.Fprint(os.Stderr, osc52Sequence(rep)); err != nil {
		return "copy failed: " + err.Error(), false
	}
	return "report copied to clipboard (terminal must support OSC 52)", true
}

// osc52Sequence wraps OSC 52 in the multiplexer-specific DCS passthrough
// required for the containing terminal to receive it. TMUX takes precedence
// when both environment markers are present, matching conventional detection.
func osc52Sequence(rep string) string {
	osc := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(rep)) + "\x07"
	switch {
	case os.Getenv("TMUX") != "":
		return "\x1bPtmux;\x1b" + osc + "\x1b\\"
	case os.Getenv("STY") != "":
		return "\x1bP" + osc + "\x1b\\"
	default:
		return osc
	}
}

// report renders the finished run as plain text safe to paste into a ticket
// or chat: no ANSI styling, and every field that can carry external bytes
// (probe details, attempt errors, SSIDs, tool output) goes through
// textsafe.Clean.
func (m model) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network-doctor report — %s\n", time.Now().UTC().Format(time.RFC3339))
	if m.target != nil {
		fmt.Fprintf(&b, "target: %s (%s)\n", m.targetHP(), m.target.Proto)
	} else {
		b.WriteString("target: none — general connection check\n")
	}
	b.WriteString("verdict: " + m.verdictLine() + "\n\nchecks:\n")
	for _, p := range m.probes {
		r := m.results[p.ID]
		fmt.Fprintf(&b, "  [%s] %s — %s\n", r.Status, p.Name, textsafe.Clean(r.Detail))
		if (r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusWarn) && r.Fix != "" {
			b.WriteString("        fix: " + textsafe.Clean(r.Fix) + "\n")
		}
		if r.Source != nil {
			b.WriteString("        src: " + r.Source.String() + " " + textsafe.Clean(r.Iface) + "\n")
		}
		if r.Network != "" {
			b.WriteString("        wifi: " + textsafe.Clean(r.Network) + "\n")
		}
		for _, a := range r.Attempts {
			st := "ok"
			if a.Err != nil {
				st = textsafe.Clean(a.Err.Error())
			}
			fmt.Fprintf(&b, "        attempt: %s %dms %s\n", a.IP, a.Dur.Milliseconds(), st)
		}
	}
	var stdout []string
	for _, line := range m.jobLines {
		if !line.stderr {
			stdout = append(stdout, line.text)
		}
	}
	if len(stdout) > 0 && (m.jobStatus == JobDone || m.jobStatus == JobFailed) {
		const reportTailLines = 15
		if len(stdout) > reportTailLines {
			stdout = stdout[len(stdout)-reportTailLines:]
		}
		fmt.Fprintf(&b, "\ntool output ($ %s):\n", textsafe.Clean(m.jobDisplay))
		for _, line := range stdout {
			b.WriteString("  " + textsafe.Clean(line) + "\n")
		}
	}
	return b.String()
}

// verdictLine is the banner verdict without styling: PASS/WARN/FAIL plus the
// diagnosis summary.
func (m model) verdictLine() string {
	order, firstFail, anyWarn := m.resultState()
	summary := diagnostic.Diagnose(m.target, order, m.results)
	switch {
	case firstFail != nil:
		return "FAIL — " + summary
	case anyWarn:
		return "WARN — " + summary
	}
	return "PASS — " + summary
}
