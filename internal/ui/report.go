package ui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aymanbagabas/go-osc52/v2"
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
	if err := copyReport(rep); err != nil {
		return "copy failed: " + err.Error(), false
	}
	return "report copied to clipboard", true
}

var (
	clipboardLookPath = exec.LookPath
	clipboardRun      = func(path string, args []string, rep string) error {
		cmd := exec.Command(path, args...)
		cmd.Stdin = strings.NewReader(rep)
		return cmd.Run()
	}
)

func copyReport(rep string) error {
	for _, c := range []struct {
		name string
		args []string
	}{
		{name: "wl-copy"},
		{name: "xclip", args: []string{"-selection", "clipboard"}},
		{name: "pbcopy"},
	} {
		path, err := clipboardLookPath(c.name)
		if err == nil && clipboardRun(path, c.args, rep) == nil {
			return nil
		}
	}
	// stderr, because Bubble Tea owns stdout: both reach the tty, but only one
	// of them is fighting the renderer for it mid-frame.
	_, err := osc52.New(rep).Mode(osc52Mode()).WriteTo(os.Stderr)
	return err
}

func osc52Mode() osc52.Mode {
	switch {
	case os.Getenv("TMUX") != "":
		return osc52.TmuxMode
	case os.Getenv("STY") != "":
		return osc52.ScreenMode
	default:
		return osc52.DefaultMode
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
