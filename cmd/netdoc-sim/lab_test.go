package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

func TestLabCLIIsOfflineAndPreservesExitSemantics(t *testing.T) {
	backends := stubBackends(t, false)
	directors := stubDirectors(t, &fakeDirectors{})
	t.Setenv("HTTPS_PROXY", "http://unresolvable.invalid:1")
	t.Setenv("ALL_PROXY", "socks5://unresolvable.invalid:1")
	tests := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"lab", "list"}, exitOK, "mtu-blackhole"},
		{[]string{"lab", "describe", "vpn-dns-leak"}, exitOK, "dns-outside-tunnel"},
		{[]string{"lab", "run", "healthy-ipv4"}, exitOK, "Evidence support and semantic validation: PASS"},
		{[]string{"lab", "run", "mtu-blackhole", "--trace"}, exitOK, "Simulator-only exchanges"},
		{[]string{"lab", "run", "tcp-port-blocked"}, exitOK, "Evidence support and semantic validation: PASS"},
		{[]string{"lab", "run", "--all", "--json"}, exitOK, ""},
		{[]string{"lab", "run", "--all", "healthy-ipv4"}, exitUsage, ""},
		{[]string{"lab", "run"}, exitUsage, ""},
		{[]string{"lab", "run", "missing"}, exitUsage, ""},
		{[]string{"lab", "run", "healthy-ipv4", "extra"}, exitUsage, ""},
		{[]string{"lab", "run", "-h"}, exitOK, ""},
		{[]string{"lab", "describe", "missing"}, exitUsage, ""},
		{[]string{"lab", "list", "extra"}, exitUsage, ""},
		{[]string{"lab"}, exitUsage, ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, "/"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, &out, &errOut); code != tt.code {
				t.Fatalf("code=%d want=%d stderr=%s", code, tt.code, errOut.String())
			}
			if !strings.Contains(out.String(), tt.contains) {
				t.Fatalf("missing %q", tt.contains)
			}
			if strings.Contains(strings.Join(tt.args, " "), "--json") {
				var reports []simulation.LabReport
				if err := json.Unmarshal(out.Bytes(), &reports); err != nil {
					t.Fatal(err)
				}
				if len(reports) != len(simulation.LabScenarios()) {
					t.Fatal("--all omitted scenarios")
				}
				failures := 0
				for _, r := range reports {
					if !r.Passed() {
						failures++
					}
				}
				if failures != 0 {
					t.Fatalf("semantic validation failures: %d", failures)
				}
			}
		})
	}
	if len(backends.calls) != 0 || len(directors.calls) != 0 {
		t.Fatal("lab attempted namespace execution")
	}
}
