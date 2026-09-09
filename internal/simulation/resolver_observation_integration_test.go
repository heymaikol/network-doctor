//go:build integration

package simulation

import (
	"context"
	"slices"
	"testing"
)

func TestIndependentResolverWireOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, query, want string
		fault             *DNSFault
	}{
		{"address answer", "example.test", lookupAnswered, nil},
		{"name absent", "absent.test", lookupNotFound, nil},
		{"A succeeds while AAAA fails", "example.test", lookupAnswered, &DNSFault{AAAA: []string{DNSOutcomeSERVFAIL}}},
		{"A negative while AAAA fails", "absent.test", lookupFailed, &DNSFault{AAAA: []string{DNSOutcomeSERVFAIL}}},
		{"SERVFAIL is not name absence", "example.test", lookupFailed, &DNSFault{A: []string{DNSOutcomeSERVFAIL}, AAAA: []string{DNSOutcomeSERVFAIL}}},
		{"REFUSED is not name absence", "example.test", lookupFailed, &DNSFault{A: []string{DNSOutcomeREFUSED}, AAAA: []string{DNSOutcomeREFUSED}}},
		{"drop is not name absence", "example.test", lookupFailed, &DNSFault{A: []string{DNSOutcomeDrop}, AAAA: []string{DNSOutcomeDrop}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fault != nil {
				tc.fault.A = slices.Repeat(tc.fault.A, 16)
				tc.fault.AAAA = slices.Repeat(tc.fault.AAAA, 16)
			}
			server := startDNSFaultServer(t, tc.fault)
			got := observeResolver(context.Background(), tc.query, server)
			if got.State != tc.want {
				t.Fatalf("lookup = %+v, want %s", got, tc.want)
			}
			if tc.want == lookupAnswered && len(got.Addresses) == 0 {
				t.Fatal("answer lost")
			}
			if tc.want != lookupAnswered && len(got.Addresses) != 0 {
				t.Fatal("failed lookup invented addresses")
			}
		})
	}
}

func TestIndependentResolverDoesNotCreditHostsFile(t *testing.T) {
	// A local hosts answer can bypass a custom resolver Dial entirely, or be
	// returned after DNS failure. It is not a second resolver's answer.
	got := observeResolver(context.Background(), "localhost", "127.0.0.1:1")
	if got.State == lookupAnswered || got.State == lookupNotFound {
		t.Fatalf("local override became independent DNS evidence: %+v", got)
	}
}
