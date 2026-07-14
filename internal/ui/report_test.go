package ui

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aymanbagabas/go-osc52/v2"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func TestCopyReportPrefersNativeClipboard(t *testing.T) {
	oldLookPath, oldRun := clipboardLookPath, clipboardRun
	t.Cleanup(func() { clipboardLookPath, clipboardRun = oldLookPath, oldRun })

	var lookedUp, run []string
	clipboardLookPath = func(name string) (string, error) {
		lookedUp = append(lookedUp, name)
		if name == "wl-copy" || name == "xclip" {
			return name, nil
		}
		return "", exec.ErrNotFound
	}
	clipboardRun = func(path string, args []string, rep string) error {
		run = append(run, strings.Join(append([]string{path}, args...), " ")+":"+rep)
		if path == "wl-copy" {
			return errors.New("broken")
		}
		return nil
	}

	if notice, ok := exportReport("hello", false); !ok || notice != "report copied to clipboard" {
		t.Fatalf("exportReport() = %q, %v", notice, ok)
	}
	if got := strings.Join(lookedUp, ","); got != "wl-copy,xclip" {
		t.Errorf("lookups = %q", got)
	}
	if got := strings.Join(run, ","); got != "wl-copy:hello,xclip -selection clipboard:hello" {
		t.Errorf("commands = %q", got)
	}
}

func TestOSC52Mode(t *testing.T) {
	tests := []struct {
		name string
		tmux string
		sty  string
		want osc52.Mode
	}{
		{name: "terminal", want: osc52.DefaultMode},
		{name: "tmux", tmux: "tmux", want: osc52.TmuxMode},
		{name: "screen", sty: "screen", want: osc52.ScreenMode},
		{name: "nested prefers tmux", tmux: "tmux", sty: "screen", want: osc52.TmuxMode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TMUX", tt.tmux)
			t.Setenv("STY", tt.sty)
			if got := osc52Mode(); got != tt.want {
				t.Errorf("osc52Mode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportSanitized(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass, Detail: "ok"}
	}
	m.results[m.probes[0].ID] = diagnostic.ProbeResult{
		ID:     m.probes[0].ID,
		Status: diagnostic.StatusFail,
		Detail: "boom \x1b[31mred\x1b[0m",
		Fix:    "restart \x1b]0;evil\x07it",
		Attempts: []diagnostic.Attempt{
			{IP: net.ParseIP("93.184.216.34"), Dur: 12 * time.Millisecond, Err: errors.New("\x1b[2Jrefused")},
		},
	}
	for i := 0; i < 16; i++ {
		m.jobLines = append(m.jobLines, outLine{false, fmt.Sprintf("line %02d", i)})
	}
	m.jobLines = append(m.jobLines,
		outLine{true, "stderr must not be reported"},
		outLine{false, "result 200\x1b[31m"},
	)
	m.jobStatus = JobDone
	m.jobDisplay = "curl https://example.com"

	rep := m.report()
	for _, want := range []string{
		"target: example.com:443",
		"verdict: FAIL",
		"boom red",
		"fix: restart it",
		"attempt: 93.184.216.34 12ms refused",
		"tool output ($ curl https://example.com)",
		"line 02",
		"result 200",
		"curl https://example.com",
	} {
		if !strings.Contains(rep, want) {
			t.Errorf("report missing %q\n%s", want, rep)
		}
	}
	for _, unwanted := range []string{"line 00", "line 01", "stderr must not be reported"} {
		if strings.Contains(rep, unwanted) {
			t.Errorf("report unexpectedly contains %q\n%s", unwanted, rep)
		}
	}
	if strings.ContainsRune(rep, 0x1b) {
		t.Errorf("escape byte leaked into report:\n%q", rep)
	}
}

func TestReportBracketsIPv6(t *testing.T) {
	tgt, err := diagnostic.ParseTarget("[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	m := newModel(tgt, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	if rep := m.report(); !strings.Contains(rep, "target: [2001:db8::1]:443") {
		t.Errorf("IPv6 target not bracketed:\n%s", rep)
	}
}

func TestReportVerdictPass(t *testing.T) {
	m := newModel(nil, false)
	for _, p := range m.probes {
		m.results[p.ID] = diagnostic.ProbeResult{ID: p.ID, Status: diagnostic.StatusPass}
	}
	rep := m.report()
	if !strings.Contains(rep, "verdict: PASS") || !strings.Contains(rep, "target: none") {
		t.Errorf("bad generic pass report:\n%s", rep)
	}
}
