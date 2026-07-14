package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Only exercises paths that return before the TUI starts.
func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		want       int
		wantStdout string
		wantStderr string
	}{
		{"version", []string{"-version"}, 0, "network-doctor dev", ""},
		{"bad flag", []string{"-nope"}, 2, "", "flag provided but not defined"},
		{"extra args", []string{"example.com", "extra"}, 2, "", "unexpected arguments"},
		{"bad target", []string{"bad_host!"}, 2, "", "network-doctor:"},
		{"json+toolbox", []string{"-json", "-toolbox"}, 2, "", "cannot be combined"},
		{"bad timeout", []string{"-timeout", "-1s", "-version"}, 2, "", "-timeout must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d", tt.args, got, tt.want)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want contains %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want contains %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// Pins the seams around the shared TargetForms const: the "Target forms:"
// header, the blank line before "Flags:", and no trailing newline in the
// const itself — without freezing stdlib flag formatting.
func TestPrintUsageTargetForms(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf, flag.NewFlagSet("network-doctor", flag.ContinueOnError))
	want := "Target forms:\n" + diagnostic.TargetForms + "\n\nFlags:"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("usage output missing the target-forms section:\n%s", buf.String())
	}
}

func TestBuildReport(t *testing.T) {
	target, err := diagnostic.ParseTarget("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	probes := []diagnostic.Probe{
		{ID: diagnostic.ProbeIface, Name: "Interface"},
		{ID: diagnostic.ProbeDNS, Name: "DNS example.com"},
	}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Detail: "interface eth0 is up", Iface: "eth0"},
		diagnostic.ProbeDNS:   {ID: diagnostic.ProbeDNS, Status: diagnostic.StatusFail, Detail: "cannot resolve example.com", Fix: "check DNS"},
	}
	rep := buildReport(target, probes, results)

	if rep.OK {
		t.Error("OK = true, want false (DNS failed)")
	}
	if rep.Target == nil || rep.Target.Host != "example.com" || rep.Target.Port != 443 || rep.Target.Protocol != "tls+http" {
		t.Errorf("target = %+v", rep.Target)
	}
	if len(rep.Checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(rep.Checks))
	}
	if rep.Checks[0].Status != "PASS" || rep.Checks[0].Fix != "" {
		t.Errorf("iface check = %+v", rep.Checks[0])
	}
	if rep.Checks[1].Status != "FAIL" || rep.Checks[1].Fix != "check DNS" {
		t.Errorf("dns check = %+v", rep.Checks[1])
	}
	if !strings.Contains(rep.Summary, "Cannot resolve example.com") {
		t.Errorf("summary = %q", rep.Summary)
	}

	// The report must round-trip as JSON with the stable field names.
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"version"`, `"target"`, `"checks"`, `"summary"`, `"ok"`, `"status"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON missing %s: %s", key, b)
		}
	}
}

func TestBuildReportGenericAllPass(t *testing.T) {
	probes := []diagnostic.Probe{{ID: diagnostic.ProbeIface, Name: "Interface"}}
	results := map[diagnostic.ProbeID]diagnostic.ProbeResult{
		diagnostic.ProbeIface: {ID: diagnostic.ProbeIface, Status: diagnostic.StatusPass, Detail: "up"},
	}
	rep := buildReport(nil, probes, results)
	if !rep.OK {
		t.Error("OK = false, want true")
	}
	if rep.Target != nil {
		t.Errorf("target = %+v, want nil", rep.Target)
	}
	if rep.Summary == "" {
		t.Error("summary empty, want all-clear text")
	}
}
