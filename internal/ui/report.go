package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/textsafe"
)

// exportReport saves the report next to the user (save=true) or copies it to
// the clipboard via OSC 52, and returns the one-line notice for the help bar.
// ponytail: raw OSC 52 on stderr — add tmux/screen passthrough if someone asks.
func exportReport(rep string, save bool) string {
	if save {
		name := fmt.Sprintf("network-doctor-%s.txt", time.Now().Format("20060102-150405"))
		if err := os.WriteFile(name, []byte(rep), 0o600); err != nil {
			return "save failed: " + err.Error()
		}
		return "report saved to " + name
	}
	if _, err := fmt.Fprintf(os.Stderr, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(rep))); err != nil {
		return "copy failed: " + err.Error()
	}
	return "report copied to clipboard (terminal must support OSC 52)"
}

// report renders the finished run as plain text safe to paste into a ticket
// or chat: no ANSI styling, and every field that can carry external bytes
// (probe details, attempt errors, SSIDs, tool facts) goes through
// textsafe.Clean.
func (m model) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network-doctor report — %s\n", time.Now().UTC().Format(time.RFC3339))
	if m.target != nil {
		fmt.Fprintf(&b, "target: %s:%d (%s)\n", m.target.Host, m.target.Port, m.target.Proto)
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
	if len(m.facts) > 0 {
		fmt.Fprintf(&b, "\ntool facts ($ %s):\n", textsafe.Clean(m.jobDisplay))
		for _, f := range m.facts {
			b.WriteString("  " + f.Key + ": " + textsafe.Clean(f.Value) + "\n")
		}
	}
	return b.String()
}

// verdictLine is the banner verdict without styling: PASS/WARN/FAIL plus the
// diagnosis summary.
func (m model) verdictLine() string {
	order := make([]diagnostic.ProbeID, len(m.probes))
	anyFail, anyWarn := false, false
	for i, p := range m.probes {
		order[i] = p.ID
		switch m.results[p.ID].Status {
		case diagnostic.StatusFail:
			anyFail = true
		case diagnostic.StatusWarn:
			anyWarn = true
		}
	}
	summary := diagnostic.Diagnose(m.target, order, m.results)
	switch {
	case anyFail:
		if summary == "" {
			summary = "a check failed"
		}
		return "FAIL — " + summary
	case anyWarn:
		if summary == "" {
			summary = "checks passed with warnings"
		}
		return "WARN — " + summary
	}
	if summary == "" {
		summary = "all checks passed"
	}
	return "PASS — " + summary
}
