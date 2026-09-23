package snapshot

import (
	"fmt"
	"testing"
)

// benchSnapshot is a watch incident whose four passes each run checks rows,
// every row naming its own host, interface, addresses, and route prefix in both
// structured fields and prose. That is the shape that grows the alias and
// address mappings along with the number of text fields that read them.
func benchSnapshot(checks int) Snapshot {
	pass := func(at string) Snapshot {
		s := supportFixture()
		s.CreatedAt = at
		for i := range checks {
			a, b := i/250, i%250
			host := fmt.Sprintf("svc%d.bench.example", i)
			iface := fmt.Sprintf("bench-if-%d", i)
			address := fmt.Sprintf("10.%d.%d.10", a, b)
			s.Checks = append(s.Checks, Check{
				ID: fmt.Sprintf("bench_%d", i), Name: "TCP " + host, Status: StatusFail, Ran: true, DurationMs: 3,
				Detail: fmt.Sprintf("dial %s:443 via %s from %s failed; user=benchuser%d path /home/benchuser%d/cfg",
					address, iface, fmt.Sprintf("192.168.%d.%d", a, b), i, i),
				Fix: "check " + host + " on " + iface,
				Observed: &Observed{
					Addresses: []string{address}, SelectedIP: address, Interface: iface,
					Attempts: []Attempt{{IP: address, Error: "connect " + address + ": timeout", Cause: "timeout"}},
					Routes: []Route{{
						Destination: address, Family: "ipv4", Interface: iface,
						Gateway: fmt.Sprintf("10.%d.%d.1", a, b), Prefix: fmt.Sprintf("10.%d.%d.0/24", a, b),
					}},
				},
			})
			s.Diagnosis.Findings = append(s.Diagnosis.Findings, Finding{
				ID: fmt.Sprintf("bench_%d", i), Verdict: "network", Summary: host + " unreachable at " + address,
			})
		}
		return s
	}
	onset := pass("2026-08-25T17:00:00Z")
	before, during, recovered := pass("2026-08-25T16:59:55Z"), pass("2026-08-25T17:00:02Z"), pass("2026-08-25T17:00:05Z")
	onset.Incident = &Incident{
		StartedAt: onset.CreatedAt, EndedAt: recovered.CreatedAt, Passes: 3,
		Before: &before, During: &during, Recovered: &recovered,
	}
	return onset
}

func benchmarkSanitize(b *testing.B, checks int) {
	pinLocalIdentity(b)
	s := benchSnapshot(checks)
	b.ReportAllocs()
	for b.Loop() {
		SanitizeForSupport(s)
	}
}

func BenchmarkSanitizeSmall(b *testing.B) { benchmarkSanitize(b, 5) }
func BenchmarkSanitizeLarge(b *testing.B) { benchmarkSanitize(b, 100) }
func BenchmarkSanitizeHuge(b *testing.B)  { benchmarkSanitize(b, 300) }
