package diagnostic_test

import (
	"context"
	"reflect"
	"testing"

	d "github.com/heymaikol/network-doctor/v2/internal/diagnostic"
	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

func TestLabAdaptersAgreeWithNativeControls(t *testing.T) {
	for _, tt := range []struct {
		name                               string
		dual, failIPv6, portal, dnsTimeout bool
	}{
		{name: "healthy-ipv4"}, {name: "healthy-dual-stack", dual: true},
		{name: "ipv6-unavailable", dual: true, failIPv6: true},
		{name: "captive-portal", portal: true}, {name: "dns-resolver-unreachable", dnsTimeout: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			native := d.NativeLabControlsForTest(tt.dual, tt.failIPv6, tt.portal, tt.dnsTimeout)
			s, err := simulation.FindLabScenario(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			lab, err := simulation.RunLab(context.Background(), s)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range lab.Views[0].Measured {
				r, ok := native[d.ProbeID(c.ID)]
				if !ok {
					continue
				}
				if c.Status != r.Status.String() || c.Cause != r.Cause {
					t.Fatalf("%s adapter=%s/%s native=%s/%s", c.ID, c.Status, c.Cause, r.Status, r.Cause)
				}
				if c.ID == "internet_tcp" {
					if c.Observed.Families.IPv4 != r.Families.IPv4 || c.Observed.Families.IPv6 != r.Families.IPv6 {
						t.Fatal("family observations differ")
					}
					if (c.Observed.Portal == nil) != (r.Portal == nil) {
						t.Fatal("portal observations differ")
					}
					if r.Portal != nil && c.Observed.Portal.RedirectURL != r.Portal.RedirectURL {
						t.Fatal("portal identity differs")
					}
				} else {
					var ips []string
					for _, ip := range r.Addrs {
						ips = append(ips, ip.String())
					}
					if !reflect.DeepEqual(c.Observed.Addresses, ips) || !reflect.DeepEqual(c.Observed.ResolverTargets, r.ResolverTargets) {
						t.Fatal("DNS observations differ")
					}
				}
			}
		})
	}
}
