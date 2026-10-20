package compare

import (
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/snapshot"
)

// lineFor returns the rendered line that starts with prefix, so a test asserts
// on one row without pinning the whole layout.
func lineFor(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("no line starting with %q in:\n%s", prefix, text)
	return ""
}

// The three questions the report exists to answer: what changed, what stayed
// the same, and which way the results moved.
func TestTextAnswersWhatChangedAndWhatDidNot(t *testing.T) {
	before, after := fixture(t), fixture(t)
	check(t, &after, "dns").Status = snapshot.StatusFail
	check(t, &after, "iface").Observed.Interface = "wg0"
	after.Diagnosis.Verdict = "dns"

	text := Snapshots(before, after).Text()
	if !strings.HasPrefix(text, "Network Doctor snapshot comparison\n") {
		t.Errorf("report does not open with its title:\n%s", text)
	}
	// The header names both runs.
	if got := lineFor(t, text, "Captured"); !strings.Contains(got, before.CreatedAt) {
		t.Errorf("captured row = %q", got)
	}
	// A check that moved, with its direction, and one that did not.
	if got := lineFor(t, text, "dns  "); !strings.Contains(got, "PASS") ||
		!strings.Contains(got, "FAIL") || !strings.Contains(got, "changed (worse)") {
		t.Errorf("dns row = %q", got)
	}
	if got := lineFor(t, text, "ssid"); strings.Contains(got, "changed") {
		t.Errorf("ssid row claims a change: %q", got)
	}
	// A status that held over evidence that did not is called out, or a reader
	// scanning the status columns would conclude nothing happened there.
	if got := lineFor(t, text, "iface"); !strings.Contains(got, "evidence changed") {
		t.Errorf("iface row = %q", got)
	}
	// And the changes, spelled out.
	for _, want := range []string{
		"Changes:",
		"verdict changed from network to dns",
		"iface interface changed from eth0 to wg0",
		"dns changed from PASS to FAIL (worse)",
		"3 changes.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not contain %q:\n%s", want, text)
		}
	}
}

func TestTextSaysNothingChanged(t *testing.T) {
	s := fixture(t)
	text := Snapshots(s, s).Text()
	if !strings.Contains(text, "No meaningful differences.") {
		t.Errorf("report does not say the runs match:\n%s", text)
	}
	if strings.Contains(text, "Changes:") {
		t.Errorf("report opened a changes list with nothing in it:\n%s", text)
	}
	// The check table is still there, because "what stayed the same" is half
	// of what the command was asked.
	if !strings.Contains(text, "Checks") || !strings.Contains(text, "target_tcp") {
		t.Errorf("report dropped the check table:\n%s", text)
	}
}

func TestTextCountsOneChangeInTheSingular(t *testing.T) {
	before, after := fixture(t), fixture(t)
	check(t, &after, "dns").Status = snapshot.StatusFail
	if text := Snapshots(before, after).Text(); !strings.Contains(text, "\n1 change.\n") {
		t.Errorf("report does not count one change in the singular:\n%s", text)
	}
}

// Two different endpoints is the first thing a reader has to know, because
// every row underneath then describes two different things.
func TestTextLeadsWithDifferentTargets(t *testing.T) {
	before, after := fixture(t), fixture(t)
	after.Target.Raw, after.Target.Host = "github.com", "github.com"

	text := Snapshots(before, after).Text()
	notice := "These snapshots observed different targets:"
	if !strings.Contains(text, notice) {
		t.Fatalf("report does not warn about the targets:\n%s", text)
	}
	if strings.Index(text, notice) > strings.Index(text, "Target ") {
		t.Errorf("the warning comes after the table it applies to:\n%s", text)
	}
	if !strings.Contains(text, "example.com:443 tls+http before") ||
		!strings.Contains(text, "github.com:443 tls+http after") {
		t.Errorf("the warning does not name both endpoints:\n%s", text)
	}
	// Two runs of the same endpoint get no such line.
	if got := Snapshots(before, before).Text(); strings.Contains(got, notice) {
		t.Errorf("same-target comparison warned anyway:\n%s", got)
	}
}

func TestTextSpellsAbsenceRatherThanLeavingItBlank(t *testing.T) {
	before, after := fixture(t), fixture(t)
	before.Target = nil
	after.Checks = append(after.Checks, snapshot.Check{ID: "http", Status: snapshot.StatusFail, Ran: true})

	text := Snapshots(before, after).Text()
	if got := lineFor(t, text, "Target"); !strings.Contains(got, absent) {
		t.Errorf("target row = %q, want the missing side spelled out", got)
	}
	if got := lineFor(t, text, "http"); !strings.Contains(got, absent) || !strings.Contains(got, "after only") {
		t.Errorf("http row = %q", got)
	}
}

// A snapshot is a file the user was handed, not necessarily one netdoc wrote,
// and every value in it reaches a terminal through this renderer.
func TestTextStripsTerminalControlSequences(t *testing.T) {
	const hostile = "example.com\x1b[2J\x1b]0;pwned\x07"
	before, after := fixture(t), fixture(t)
	after.Target.Host = hostile
	check(t, &after, "dns").Cause = hostile
	after.Tool.Version = hostile

	text := Snapshots(before, after).Text()
	if strings.ContainsAny(text, "\x1b\x07") {
		t.Errorf("escape bytes reached the report: %q", text)
	}
	// Stripped, not dropped: the difference is still reported.
	if !strings.Contains(text, "target host changed") {
		t.Errorf("sanitizing removed the change itself:\n%s", text)
	}
}

// The table sizes itself to its contents, and no row is padded past the end of
// its last column, so the output pastes into a bug report unchanged.
func TestTextHasNoTrailingWhitespace(t *testing.T) {
	before, after := fixture(t), fixture(t)
	check(t, &after, "dns").Status = snapshot.StatusFail
	after.Tool.Version = "a-deliberately-long-version-string"

	for i, line := range strings.Split(Snapshots(before, after).Text(), "\n") {
		if line != strings.TrimRight(line, " \t") {
			t.Errorf("line %d has trailing whitespace: %q", i+1, line)
		}
	}
}

// Column widths come from the widest cell, so a long value pushes the columns
// out rather than running into the next one.
func TestTextColumnsStayAligned(t *testing.T) {
	before, after := fixture(t), fixture(t)
	check(t, &after, "dns").Status = snapshot.StatusIncomplete
	after.OK = false

	text := Snapshots(before, after).Text()
	header := lineFor(t, text, "Checks")
	afterColumn := strings.Index(header, "AFTER")
	if afterColumn < 0 {
		t.Fatalf("no AFTER column in %q", header)
	}
	for _, id := range []string{"iface", "internet_tcp", "dns", "target_tcp"} {
		row := lineFor(t, text, id)
		if len(row) <= afterColumn || strings.HasPrefix(row[afterColumn:], " ") {
			t.Errorf("%s row does not put its after value under the AFTER header: %q", id, row)
		}
	}
}
