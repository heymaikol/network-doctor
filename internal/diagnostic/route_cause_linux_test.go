//go:build linux

package diagnostic

import "testing"

func TestRouteFailureCauseFromKernelTables(t *testing.T) {
	header := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
	arpHeader := "IP address HW type Flags HW address Mask Device\n"
	tests := []struct {
		name, routes, arp, want string
	}{
		{"no default", header + "eth0 00024D0A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n", arpHeader, RouteCauseNoDefaultRoute},
		{"dead gateway", header + "eth0 00000000 01014D0A 0003 0 0 100 00000000 0 0 0\n",
			arpHeader + "10.77.1.1 0x1 0x0 00:00:00:00:00:00 * eth0\n", RouteCauseGatewayUnreachable},
		{"reachable selected path", header + "eth0 00000000 01014D0A 0003 0 0 100 00000000 0 0 0\n",
			arpHeader + "10.77.1.1 0x1 0x2 02:00:00:00:00:01 * eth0\n", RouteCauseSelectedPathFailed},
		{"multiple defaults", header +
			"eth1 00000000 01034D0A 0003 0 0 50 00000000 0 0 0\n" +
			"eth0 00000000 01014D0A 0003 0 0 100 00000000 0 0 0\n", arpHeader, RouteCausePreferredPathFailed},
		{"equal metric defaults are ECMP", header +
			"eth1 00000000 01034D0A 0003 0 0 50 00000000 0 0 0\n" +
			"eth0 00000000 01014D0A 0003 0 0 50 00000000 0 0 0\n", arpHeader, RouteCauseSelectedPathFailed},
		{"one dead equal metric gateway listed first", header +
			"eth0 00000000 01014D0A 0003 0 0 50 00000000 0 0 0\n" +
			"eth1 00000000 01034D0A 0003 0 0 50 00000000 0 0 0\n",
			arpHeader + "10.77.1.1 0x1 0x0 00:00:00:00:00:00 * eth0\n", RouteCauseSelectedPathFailed},
		{"one dead equal metric gateway listed last", header +
			"eth1 00000000 01034D0A 0003 0 0 50 00000000 0 0 0\n" +
			"eth0 00000000 01014D0A 0003 0 0 50 00000000 0 0 0\n",
			arpHeader + "10.77.1.1 0x1 0x0 00:00:00:00:00:00 * eth0\n", RouteCauseSelectedPathFailed},
		{"every equal metric gateway dead", header +
			"eth0 00000000 01014D0A 0003 0 0 50 00000000 0 0 0\n" +
			"eth1 00000000 01034D0A 0003 0 0 50 00000000 0 0 0\n",
			arpHeader + "10.77.1.1 0x1 0x0 00:00:00:00:00:00 * eth0\n" +
				"10.77.3.1 0x1 0x0 00:00:00:00:00:00 * eth1\n", RouteCauseGatewayUnreachable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeFailureCauseFrom([]byte(tc.routes), []byte(tc.arp)); got != tc.want {
				t.Errorf("cause = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseDefaultRoutesRejectsMalformedRows(t *testing.T) {
	raw := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask\n" +
		"bad 00000000 nothex 0003 0 0 1 00000000\n" +
		"down 00000000 01014D0A 0002 0 0 1 00000000\n")
	if got := parseDefaultRoutes(raw); len(got) != 0 {
		t.Errorf("malformed routes = %+v", got)
	}
}

func TestIPv6RouteFailureCauseFromKernelTable(t *testing.T) {
	zero := "00000000000000000000000000000000"
	viaPreferred := "20010db8007900010000000000000001"
	viaAlternate := "20010db8007900030000000000000001"
	routes := zero + " 00 " + zero + " 00 " + viaAlternate + " 00000064 00000000 00000000 00000003 alt0\n" +
		zero + " 00 " + zero + " 00 " + viaPreferred + " 00000032 00000000 00000000 00000003 pref0\n"
	if got := routeFailureCauseIPv6From([]byte(routes)); got != RouteCausePreferredPathFailed {
		t.Fatalf("IPv6 cause = %q, want %q", got, RouteCausePreferredPathFailed)
	}
	parsed := parseIPv6DefaultRoutes([]byte(routes))
	if len(parsed) != 2 || parsed[0].metric != 100 || parsed[1].metric != 50 ||
		parsed[0].gateway.String() != "2001:db8:79:3::1" || parsed[1].gateway.String() != "2001:db8:79:1::1" {
		t.Fatalf("parsed IPv6 defaults = %+v", parsed)
	}
}

func TestIPv6RouteFailureCauseRejectsMissingAndMalformedDefaults(t *testing.T) {
	zero := "00000000000000000000000000000000"
	if got := routeFailureCauseIPv6From(nil); got != RouteCauseNoDefaultRoute {
		t.Fatalf("missing IPv6 default cause = %q", got)
	}
	raw := zero + " 01 " + zero + " 00 " + zero + " 00000032 00000000 00000000 00000003 eth0\n" +
		zero + " 00 " + zero + " 00 nothex 00000032 00000000 00000000 00000003 eth0\n"
	if got := parseIPv6DefaultRoutes([]byte(raw)); len(got) != 0 {
		t.Fatalf("malformed IPv6 defaults = %+v", got)
	}
}

func TestParseIPv6DefaultRoutesMetricRange(t *testing.T) {
	zero := "00000000000000000000000000000000"
	tests := []struct {
		metric string
		want   uint64
		ok     bool
	}{
		{"00000000", 0, true},
		{"7fffffff", 0x7fffffff, true},
		{"80000000", 0x80000000, true},
		{"ffffffff", 0xffffffff, true},
		{"nothex", 0, false},
		{"-0000001", 0, false},
		{"100000000", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.metric, func(t *testing.T) {
			raw := zero + " 00 " + zero + " 00 " + zero + " " + tc.metric + " 00000000 00000000 00000001 eth0\n"
			parsed := parseIPv6DefaultRoutes([]byte(raw))
			if !tc.ok {
				if len(parsed) != 0 {
					t.Fatalf("parsed = %+v, want rejected", parsed)
				}
				return
			}
			if len(parsed) != 1 || parsed[0].metric != tc.want {
				t.Fatalf("parsed = %+v, want one route with metric %#x", parsed, tc.want)
			}
			if got := routeFailureCauseIPv6From([]byte(raw)); got != RouteCauseSelectedPathFailed {
				t.Fatalf("cause = %q, want %q", got, RouteCauseSelectedPathFailed)
			}
		})
	}
}

func TestIPv6RouteFailureCauseOrdersMetricsAcrossInt32Max(t *testing.T) {
	zero := "00000000000000000000000000000000"
	routes := zero + " 00 " + zero + " 00 20010db8007900030000000000000001 80000000 00000000 00000000 00000003 alt0\n" +
		zero + " 00 " + zero + " 00 20010db8007900010000000000000001 7fffffff 00000000 00000000 00000003 pref0\n"
	if got := routeFailureCauseIPv6From([]byte(routes)); got != RouteCausePreferredPathFailed {
		t.Fatalf("IPv6 cause = %q, want %q", got, RouteCausePreferredPathFailed)
	}
}
