package main

import (
	"os"
	"strings"
	"testing"
)

// Export must strip escapes and never leave an un-indented ``` fence that
// attacker-controlled output could use to break out into Markdown/HTML.
func TestExportSanitizesAndIndents(t *testing.T) {
	t.Chdir(t.TempDir())

	m := newModel(mustTarget(t, "github.com"))
	m.results[pIface] = ProbeResult{Status: StatusFail, Detail: "evil\x1b[31m```\n# heading\n<script>", Fix: "do x"}
	m.jobName, m.jobStatus = "ping", JobDone
	m.jobOut = []string{"```injected fence", "\x1b]0;title\x07normal"}

	path, err := exportReport(m)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	if strings.ContainsRune(s, 0x1b) {
		t.Error("ESC survived in export")
	}
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(ln, "```") {
			t.Errorf("un-indented fence in export: %q", ln)
		}
	}
}

func TestExportNoClobber(t *testing.T) {
	t.Chdir(t.TempDir())
	m := newModel(nil)
	p1, err := exportReport(m)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := exportReport(m)
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Errorf("export reused path %q — must not clobber", p1)
	}
}
