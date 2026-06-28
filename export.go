package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// exportReport writes a sanitized markdown report of the current state to a
// timestamped, no-clobber file with mode 0600. Tool/remote output is
// double-safe: control/ANSI sanitized AND emitted as a 4-space-indented code
// block (no closing fence to inject, so attacker output can't smuggle
// Markdown/HTML or remote-image beacons). Returns the path written.
func exportReport(m model) (string, error) {
	var b strings.Builder
	b.WriteString("# network-doctor report\n\n")
	b.WriteString("_Generated " + time.Now().Format(time.RFC3339) + ". Contains local network details — handle with care._\n\n")

	tgt := "generic (no target)"
	if m.target != nil {
		tgt = fmt.Sprintf("%s:%d", m.target.Host, m.target.Port)
	}
	b.WriteString("Target: " + sanitize(tgt) + "\n\n")
	b.WriteString("## Diagnosis\n\n" + sanitize(diagnose(m.target, m.order, m.results)) + "\n\n")

	b.WriteString("## Probes\n\n")
	for _, id := range m.order {
		name := sanitize(m.byID[id].Name)
		r, ok := m.results[id]
		if !ok {
			b.WriteString("- [ ] " + name + " — not run\n")
			continue
		}
		b.WriteString(fmt.Sprintf("- %s **%s** — %s\n", statusMark(r.Status), name, sanitize(r.Detail)))
		if r.Status == StatusFail && r.Fix != "" {
			b.WriteString("  - fix: " + sanitize(r.Fix) + "\n")
		}
	}

	if m.jobStatus != JobQueued || len(m.jobOut) > 0 {
		b.WriteString("\n## Last tool: " + sanitize(m.jobName) + " (" + m.jobStatus.String() + ")\n\n")
		b.WriteString(indentBlock("$ " + m.jobDisplay))
		b.WriteString(indentBlock(strings.Join(m.jobOut, "\n")))
		if len(m.jobErr) > 0 {
			b.WriteString(indentBlock(strings.Join(m.jobErr, "\n")))
		}
		if len(m.facts) > 0 {
			b.WriteString("Extracted:\n\n")
			for _, f := range m.facts {
				b.WriteString("- " + sanitize(f.Key) + ": " + sanitize(f.Value) + "\n")
			}
		}
	}

	path := uniquePath()
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// indentBlock renders untrusted text as a 4-space-indented code block, every
// line sanitized — no fence delimiter exists for the output to break out of.
func indentBlock(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, ln := range strings.Split(s, "\n") {
		b.WriteString("    " + sanitize(ln) + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

func statusMark(s Status) string {
	switch s {
	case StatusPass:
		return "✓"
	case StatusFail:
		return "✗"
	case StatusSkip:
		return "⊘"
	case StatusNA:
		return "–"
	}
	return "?"
}

// uniquePath returns a timestamped report filename that doesn't already exist.
func uniquePath() string {
	base := "network-doctor-" + time.Now().Format("20060102-150405")
	path := base + ".md"
	for i := 1; ; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path
		}
		path = fmt.Sprintf("%s-%d.md", base, i)
	}
}
