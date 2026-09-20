package compare

import (
	"strconv"
	"strings"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// Text renders the human report: what the two runs were, one row per check,
// and then the differences in the order the comparison found them.
//
// Every value printed here comes out of a file the user was handed, which may
// not be a file netdoc wrote, so all of it goes through the same sanitizer the
// probes' output does before it reaches a terminal.
func (c Comparison) Text() string {
	var b strings.Builder
	b.WriteString("Network Doctor snapshot comparison\n\n")
	switch {
	case c.SameTarget:
	case c.targetsNotComparable():
		// The pair that cannot answer the question says so in those words. It
		// is not the sentence below: claiming two different endpoints here
		// would be exactly the kind of unearned identity claim that reading
		// pseudonyms across two artifacts already is.
		b.WriteString("These snapshots do not establish whether they observed one target: " +
			clean(display(c.Before.Target)) + " before, " + clean(display(c.After.Target)) + " after, " +
			"and at least one of those names is a support pseudonym belonging to its own file.\n\n")
	default:
		// First, and before the columns: every row below then describes two
		// different endpoints, and that has to be read before the rows are.
		b.WriteString("These snapshots observed different targets: " +
			clean(display(c.Before.Target)) + " before, " + clean(display(c.After.Target)) + " after.\n\n")
	}
	rows := [][3]string{
		{"Target", c.Before.Target, c.After.Target},
		{"Captured", c.Before.CreatedAt, c.After.CreatedAt},
		{"Tool", toolWord(c.Before), toolWord(c.After)},
		{"Verdict", c.Before.Verdict, c.After.Verdict},
		{"Overall", okWord(c.Before.OK), okWord(c.After.OK)},
	}
	// Only when one of them is: on two ordinary snapshots this row would say
	// "full" twice on every comparison anybody ever runs, which is noise. On a
	// support artifact it is the one thing a reader has to know before reading
	// a single hostname or address below.
	if c.Before.Sanitized || c.After.Sanitized {
		rows = append(rows, [3]string{"Fidelity", fidelityWord(c.Before.Sanitized), fidelityWord(c.After.Sanitized)})
	}
	writeTable(&b, "", rows)
	if len(c.Checks) > 0 {
		b.WriteString("\n")
		rows := make([][3]string, 0, len(c.Checks))
		for _, row := range c.Checks {
			rows = append(rows, [3]string{row.ID, row.Before, row.After})
		}
		notes := make([]string, len(c.Checks))
		for i, row := range c.Checks {
			notes[i] = note(row)
		}
		writeTableWithNotes(&b, "Checks", rows, notes)
	}
	b.WriteString("\n")
	if len(c.Changes) == 0 {
		b.WriteString("No meaningful differences.\n")
		writeCaveats(&b, c.Caveats)
		return b.String()
	}
	b.WriteString("Changes:\n")
	for _, change := range c.Changes {
		line := "  " + clean(change.Summary)
		if change.Direction != "" {
			line += " (" + change.Direction + ")"
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n" + strconv.Itoa(len(c.Changes)) + " " + plural(len(c.Changes), "change") + ".\n")
	writeCaveats(&b, c.Caveats)
	return b.String()
}

// writeCaveats prints what the rows above are worth, last, where the two-sided
// reading prints its own: a caveat qualifies the report and is read after it.
func writeCaveats(b *strings.Builder, caveats []string) {
	if len(caveats) == 0 {
		return
	}
	b.WriteString("\nCaveats:\n")
	for _, caveat := range caveats {
		b.WriteString("  " + clean(caveat) + "\n")
	}
}

// note is the trailing word on a check row: what kind of difference it holds,
// so a long table does not have to be read column against column. A row whose
// status held but whose evidence moved is called out too, since that is the
// difference a status-only reading would miss.
func note(row CheckRow) string {
	switch {
	case row.Kind == KindAdded:
		return "after only"
	case row.Kind == KindRemoved:
		return "before only"
	case row.Kind == KindChanged && row.Direction != "":
		return "changed (" + row.Direction + ")"
	case row.Kind == KindChanged:
		return "changed"
	case row.Differs:
		return "evidence changed"
	}
	return ""
}

func toolWord(s Side) string {
	parts := []string{}
	if s.Tool.Version != "" {
		parts = append(parts, s.Tool.Version)
	}
	if s.Tool.OS != "" || s.Tool.Arch != "" {
		parts = append(parts, s.Tool.OS+"/"+s.Tool.Arch)
	}
	return strings.Join(parts, " ")
}

// fidelityWord names what a side's values are: the machine's own, or stand-ins
// chosen for sharing.
func fidelityWord(sanitized bool) string {
	if sanitized {
		return "sanitized"
	}
	return "full"
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func writeTable(b *strings.Builder, heading string, rows [][3]string) {
	writeTableWithNotes(b, heading, rows, make([]string, len(rows)))
}

func writeTableWithNotes(b *strings.Builder, heading string, rows [][3]string, notes []string) {
	writeColumns(b, heading, "BEFORE", "AFTER", rows, notes)
}

// writeColumns lays out the label column and two value columns at widths taken
// from the widest cell, so the table fits its own contents rather than a
// guessed terminal width. Trailing spaces are trimmed, which keeps the output
// stable to compare and paste into a bug report. The two column headings are
// the caller's, because two readings of the same pair of snapshots name their
// sides differently: one has a before and an after, the other has two machines.
func writeColumns(b *strings.Builder, heading, leftHeading, rightHeading string, rows [][3]string, notes []string) {
	const gap = 2
	label, before, after := width(heading), width(leftHeading), width(rightHeading)
	for _, row := range rows {
		label = max(label, width(clean(row[0])))
		before = max(before, width(clean(display(row[1]))))
		after = max(after, width(clean(display(row[2]))))
	}
	b.WriteString(strings.TrimRight(pad(heading, label+gap)+pad(leftHeading, before+gap)+rightHeading, " ") + "\n")
	for i, row := range rows {
		line := pad(clean(row[0]), label+gap) + pad(clean(display(row[1])), before+gap)
		if notes[i] == "" {
			b.WriteString(strings.TrimRight(line+clean(display(row[2])), " ") + "\n")
			continue
		}
		// The note gets a column of its own rather than trailing the value, so
		// a short status and a long one do not put their notes in two places.
		b.WriteString(line + pad(clean(display(row[2])), after+gap) + notes[i] + "\n")
	}
}

// width counts runes rather than bytes: a hostname is not necessarily ASCII,
// and the sanitizer has already removed the zero-width runes that would make
// even a rune count wrong.
func width(s string) int { return len([]rune(s)) }

func pad(s string, to int) string {
	if n := to - width(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

func clean(s string) string { return textsafe.Clean(s) }
