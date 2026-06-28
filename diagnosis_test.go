package main

import (
	"strings"
	"testing"
)

func TestDiagnoseGeneric(t *testing.T) {
	order := []ProbeID{pIface, pInternet, pDNS}
	cases := []struct {
		name          string
		internet, dns Status
		want          string
	}{
		{"online", StatusPass, StatusPass, "Online"},
		{"dns down", StatusPass, StatusFail, "DNS resolution is failing"},
		{"no egress", StatusFail, StatusPass, "no direct TCP egress"},
		{"offline", StatusFail, StatusFail, "Offline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := map[ProbeID]ProbeResult{
				pIface:    {Status: StatusPass},
				pInternet: {Status: c.internet},
				pDNS:      {Status: c.dns},
			}
			if v := diagnose(nil, order, res); !strings.Contains(v, c.want) {
				t.Errorf("got %q, want substring %q", v, c.want)
			}
		})
	}
}

func TestDiagnoseIncomplete(t *testing.T) {
	order := []ProbeID{pIface, pInternet, pDNS}
	res := map[ProbeID]ProbeResult{pIface: {Status: StatusPass}}
	if v := diagnose(nil, order, res); !strings.Contains(v, "Running") {
		t.Errorf("incomplete should report running, got %q", v)
	}
}

func TestDiagnoseTarget(t *testing.T) {
	tg := mustTarget(t, "github.com")
	order := []ProbeID{pIface, pInternet, pDNS, pTargetTCP, pTLS, pHTTP}

	// DNS + internet OK, Target TCP fails → remote port/firewall verdict.
	res := map[ProbeID]ProbeResult{
		pIface: {Status: StatusPass}, pInternet: {Status: StatusPass},
		pDNS: {Status: StatusPass}, pTargetTCP: {Status: StatusFail},
		pTLS: {Status: StatusSkip}, pHTTP: {Status: StatusSkip},
	}
	if v := diagnose(tg, order, res); !strings.Contains(v, "unreachable") {
		t.Errorf("got %q, want 'unreachable'", v)
	}

	// Everything passes → reachable.
	for _, id := range order {
		res[id] = ProbeResult{Status: StatusPass}
	}
	if v := diagnose(tg, order, res); !strings.Contains(v, "reachable and responding") {
		t.Errorf("got %q, want success verdict", v)
	}
}
