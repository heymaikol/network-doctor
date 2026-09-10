package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		// cwd first (where the user is looking), $HOME as fallback, since the cwd
		// may be read-only when launched from an installed location.
		// Milliseconds in the name: two saves in the same second would otherwise
		// collide on O_EXCL and land in $HOME, which is not where the user looked.
		name := fmt.Sprintf("network-doctor-%s.txt", time.Now().Format("20060102-150405.000"))
		path, err := filepath.Abs(name)
		if err == nil {
			err = reportWriteFile(path, []byte(rep), 0o600)
		}
		if err != nil {
			home, homeErr := reportUserHomeDir()
			if homeErr != nil {
				return "save failed: " + homeErr.Error(), false
			}
			path, err = filepath.Abs(filepath.Join(home, name))
			if err == nil {
				err = reportWriteFile(path, []byte(rep), 0o600)
			}
		}
		if err != nil {
			return "save failed: " + err.Error(), false
		}
		return "report saved to " + path, true
	}
	if err := copyReport(rep); err != nil {
		return "copy failed: " + err.Error(), false
	}
	return "report sent to clipboard (OSC 52); w saves a file", true
}

var (
	reportWriteFile   = writeFileExcl
	reportUserHomeDir = os.UserHomeDir
)

// writeFileExcl is os.WriteFile with O_EXCL instead of O_TRUNC: the report
// filename is timestamped and predictable, so refusing to write through an
// existing name (or a symlink planted at it) beats silently overwriting.
func writeFileExcl(path string, data []byte, perm os.FileMode) error {
	// #nosec G304 -- exportReport generates path in cwd or the user's home and uses O_EXCL.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// copyReport writes the OSC 52 escape to stderr, because Bubble Tea owns
// stdout: both reach the tty, but only one of them is fighting the renderer
// for it mid-frame.
//
// A nil error means the escape reached the terminal, not that the clipboard
// changed: OSC 52 is fire-and-forget, and terminals without it (legacy
// conhost) or with it switched off (tmux set-clipboard off, some SSH setups)
// drop the sequence in silence. Callers must not promise the paste worked.
func copyReport(rep string) error {
	_, err := os.Stderr.WriteString(osc52Sequence(rep))
	return err
}

// osc52Sequence encodes rep as an OSC 52 clipboard escape, the "please copy
// this" request terminals honor even over SSH. Inside tmux the sequence must
// ride tmux's DCS passthrough envelope, or tmux quietly eats it.
func osc52Sequence(rep string) string {
	seq := "\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(rep)) + "\a"
	if os.Getenv("TMUX") != "" {
		return "\x1bPtmux;\x1b" + seq + "\x1b\\"
	}
	return seq
}

// report renders the finished run as plain text safe to paste into a ticket
// or chat: no ANSI styling, and no external bytes untamed. Probe results
// arrive sanitized from BuildProbesFromSources; tool output is cleaned here, since it
// comes from a subprocess this package launched.
func (m model) report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network-doctor report: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "version: %s\nos: %s/%s\n", m.version, runtime.GOOS, runtime.GOARCH)
	b.WriteString("review before sharing: tool output may contain sensitive data\n")
	if m.target != nil {
		fmt.Fprintf(&b, "target: %s (%s)\n", m.targetHP(), m.target.Proto)
	} else {
		b.WriteString("target: none (general connection check)\n")
	}
	b.WriteString("verdict: " + m.verdictLine() + "\n")
	if why := m.whyLines(); len(why) > 1 {
		b.WriteString("why:\n")
		for _, line := range why[1:] {
			b.WriteString("  " + line + "\n")
		}
	}
	// The remediation reads from the same diagnosis as the verdict above it, so
	// a pasted report carries the advice the screen showed rather than a second
	// opinion. The command is labelled as a suggestion: a report that lists a
	// command with no such label reads as a record of one that was run.
	if rem, ok := m.remediation(); ok {
		fmt.Fprintf(&b, "next action: %s\n", rem.Action)
		if rem.Why != "" {
			b.WriteString("  why: " + rem.Why + "\n")
		}
		for _, step := range rem.Steps {
			b.WriteString("  step: " + step + "\n")
		}
		if line := rem.CommandLine(); line != "" {
			b.WriteString("  run (suggested, not executed): " + line + "\n")
		}
		if rem.Expect != "" {
			b.WriteString("  expect: " + rem.Expect + "\n")
		}
	}
	b.WriteString("\nchecks:\n")
	for _, p := range m.probes {
		r := m.results[p.ID]
		fmt.Fprintf(&b, "  [%s] %s: %s\n", r.Status, p.Name, r.Detail)
		// A working http:// proxy row keeps its earned status, so its advice
		// would otherwise never be shown: the cleartext observation is the one
		// non-failing result that carries a line worth reading.
		if (r.Status == diagnostic.StatusFail || r.Status == diagnostic.StatusWarn || r.ConnectCleartext) && r.Fix != "" {
			b.WriteString("        fix: " + r.Fix + "\n")
		}
		if r.Portal != nil && r.Portal.RedirectURL != "" {
			b.WriteString("        portal: " + r.Portal.RedirectURL + "\n")
		}
		if r.Source != nil {
			b.WriteString("        src: " + r.Source.String() + " " + r.Iface + "\n")
		}
		if r.Network != "" {
			b.WriteString("        wifi: " + r.Network + "\n")
		}
		for _, a := range r.Attempts {
			st := "ok"
			if a.Err != nil {
				st = a.Err.Error()
			}
			fmt.Fprintf(&b, "        attempt: %s %dms %s\n", a.IP, diagnostic.Ms(a.Dur), st)
		}
	}
	for j := range m.jobs {
		const reportTailLines = 15
		lines := j.lines
		if len(lines) > reportTailLines {
			lines = lines[len(lines)-reportTailLines:]
		}
		fmt.Fprintf(&b, "\ntool output ($ %s):\n", textsafe.Clean(j.display))
		fmt.Fprintf(&b, "  status: %s\n  duration: %s\n", j.status, j.dur.Round(time.Millisecond))
		fmt.Fprintf(&b, "  output tail: %d of %d retained lines", len(lines), len(j.lines))
		if j.evicted > 0 || j.dropped > 0 {
			fmt.Fprintf(&b, " (%d evicted, %d dropped)", j.evicted, j.dropped)
		}
		b.WriteByte('\n')
		for _, line := range lines {
			b.WriteString("    " + textsafe.Clean(line) + "\n")
		}
	}
	return b.String()
}

// verdictLine is the banner verdict without styling: PASS/WARN/FAIL plus the
// diagnosis summary, off the same verdict the banner reads.
func (m model) verdictLine() string {
	summary, verdict := m.diagnose(m.probeOrder())
	return verdictStatus(verdict).String() + ": " + summary
}
