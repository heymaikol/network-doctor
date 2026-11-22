package diagnostic

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func lanTestLink() lanLink {
	return lanLink{
		source: netip.MustParseAddr("192.168.10.1"),
		prefix: netip.MustParsePrefix("192.168.10.0/29"),
	}
}

func TestLANCombinesIndependentEvidence(t *testing.T) {
	ip := func(last byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 168, 10, last}) }
	calls := 0
	cache := func() ([]netip.Addr, error) {
		calls++
		if calls == 1 {
			return []netip.Addr{ip(4), ip(4), ip(5), ip(1), ip(7), ip(200)}, nil
		}
		return []netip.Addr{ip(5), ip(6)}, nil
	}
	echo := func(_ context.Context, addr netip.Addr) (bool, error) {
		return addr == ip(2) || addr == ip(5), nil
	}
	dial := func(_ context.Context, network, endpoint string) (net.Conn, error) {
		if network != "tcp4" {
			t.Errorf("dial used network %q", network)
		}
		switch endpoint {
		case "192.168.10.3:443":
			conn, server := net.Pipe()
			_ = server.Close()
			return conn, nil
		case "192.168.10.5:80", "192.168.10.5:443":
			return nil, connectionRefusedErrno
		default:
			return nil, context.DeadlineExceeded
		}
	}
	got := make(map[netip.Addr]LANEvidence)
	warnings, err := scanLAN(t.Context(), lanTestLink(), echo, nil, dial, cache, func(o LANObservation) {
		previous := got[o.IP]
		if o.Evidence == previous || o.Evidence&previous != previous {
			t.Errorf("duplicate or regressive observation: %v after %v", o, previous)
		}
		got[o.IP] = o.Evidence
	})
	if len(warnings) != 0 || err != nil || calls != 2 || len(got) != 5 {
		t.Fatalf("scan reports %v, %v, cache reads %d, observations %v", warnings, err, calls, got)
	}
	for address, want := range map[netip.Addr]LANEvidence{
		ip(2): LANICMP, ip(3): LANTCP, ip(4): LANNeighbor, ip(5): LANICMP | LANTCP | LANNeighbor, ip(6): LANNeighbor,
	} {
		if got[address] != want || got[address].Confirmed() != (want != LANNeighbor) {
			t.Errorf("%s: got %v (confirmed %t), want %v", address, got[address], got[address].Confirmed(), want)
		}
	}
}

func TestLANScopeStaysOnSelectedInterface(t *testing.T) {
	list := func() ([]net.Interface, error) {
		return []net.Interface{{Name: "other", Index: 4, Flags: net.FlagUp}, {Name: "chosen", Index: 7, Flags: net.FlagUp}}, nil
	}
	addrs := func(iface *net.Interface) ([]net.Addr, error) {
		cidrs := []string{"10.20.30.6/29"}
		if iface.Name == "other" {
			cidrs = []string{"10.20.30.6/16", "10.20.30.5/24"}
		}
		var addresses []net.Addr
		for _, cidr := range cidrs {
			ip, subnet, _ := net.ParseCIDR(cidr)
			subnet.IP = ip
			addresses = append(addresses, subnet)
		}
		return addresses, nil
	}
	source := netip.MustParseAddr("10.20.30.6")
	if _, err := findLANLink(source, "", list, addrs); err == nil {
		t.Fatal("ambiguous source selected an interface")
	}
	link, err := findLANLink(source, "chosen", list, addrs)
	if err != nil || link.Index != 7 || !link.sharedSource {
		t.Fatalf("selected link = %+v, %v", link, err)
	}
	if want := []netip.Addr{netip.MustParseAddr("10.20.30.1"), netip.MustParseAddr("10.20.30.2"), netip.MustParseAddr("10.20.30.3"), netip.MustParseAddr("10.20.30.4")}; !slices.Equal(link.targets(), want) {
		t.Fatalf("targets %v, want %v", link.targets(), want)
	}
	larger, err := findLANLink(source, "other", list, addrs)
	if err != nil || len(larger.targets()) != 254 || larger.targets()[0].String() != "10.20.30.0" {
		t.Fatalf("larger link escaped the /24 cap or missed a unicast address: %v", err)
	}
	for _, src := range []string{"203.0.113.6", "fd00::6", "10.20.1.6"} {
		if _, err := findLANLink(netip.MustParseAddr(src), "chosen", list, addrs); err == nil {
			t.Errorf("accepted invalid source %s", src)
		}
	}
}

func TestLANServiceLinkRejectsChangedSnapshots(t *testing.T) {
	source, peer := netip.MustParseAddr("192.168.12.34"), netip.MustParseAddr("192.168.12.1")
	lan := net.Interface{Name: "lan", Index: 7, Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 7}}
	other := net.Interface{Name: "vpn", Index: 18, Flags: net.FlagUp}
	ifaces := []net.Interface{other, lan}
	cidrs := map[string]string{"lan": "192.168.12.34/24", "vpn": "192.168.12.2/28"}
	list := func() ([]net.Interface, error) { return ifaces, nil }
	addrs := func(iface *net.Interface) ([]net.Addr, error) {
		ip, subnet, err := net.ParseCIDR(cidrs[iface.Name])
		if err != nil {
			return nil, err
		}
		subnet.IP = ip
		return []net.Addr{subnet}, nil
	}
	link, err := findLANLink(source, "", list, addrs)
	if err != nil {
		t.Fatal(err)
	}
	binding := link.binding()
	selected, err := binding.serviceLink(peer, list, addrs)
	if err != nil || selected.Name != lan.Name || selected.Index != lan.Index {
		t.Fatalf("overlapping subnet selected %+v, %v, want original LAN", selected, err)
	}
	dial := selected.dialer()
	if local := dial.LocalAddr.(*net.TCPAddr); !local.IP.Equal(net.IP(source.AsSlice())) || dial.Control == nil {
		t.Fatalf("drill-down dialer lacks source or interface binding: %+v", dial)
	}

	t.Run("interface down", func(t *testing.T) {
		ifaces[1].Flags = 0
		defer func() { ifaces[1] = lan }()
		if _, err := binding.serviceLink(peer, list, addrs); err == nil {
			t.Fatal("accepted an inactive snapshot interface")
		}
	})
	t.Run("interface replaced", func(t *testing.T) {
		ifaces[1].Index++
		defer func() { ifaces[1] = lan }()
		if _, err := binding.serviceLink(peer, list, addrs); err == nil {
			t.Fatal("accepted a replacement adapter with the old name and address")
		}
	})
	t.Run("source moved to overlapping subnet", func(t *testing.T) {
		ifaces = ifaces[:1]
		cidrs[other.Name] = "192.168.12.34/24"
		defer func() {
			ifaces = ifaces[:2]
			cidrs[other.Name] = "192.168.12.2/28"
		}()
		if _, err := binding.serviceLink(peer, list, addrs); err == nil {
			t.Fatal("followed the source to the other interface")
		}
	})
	t.Run("same interface changed subnet", func(t *testing.T) {
		cidrs[lan.Name] = "192.168.12.34/25"
		defer func() { cidrs[lan.Name] = "192.168.12.34/24" }()
		if _, err := binding.serviceLink(peer, list, addrs); err == nil {
			t.Fatal("accepted an old snapshot after a prefix change")
		}
	})
}

func TestLANUnavailableMechanisms(t *testing.T) {
	unavailable := errors.New("unavailable on this system")
	noCache := func() ([]netip.Addr, error) { return nil, unavailable }
	cache := func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.10.4")}, nil }
	noTCP := func(context.Context, string, string) (net.Conn, error) { return nil, errLANUnavailable }
	refused := func(context.Context, string, string) (net.Conn, error) { return nil, connectionRefusedErrno }
	for _, tc := range []struct {
		name      string
		dial      func(context.Context, string, string) (net.Conn, error)
		cache     func() ([]netip.Addr, error)
		warnings  int
		evidence  LANEvidence
		observed  int
		wantError bool
	}{
		{"TCP only", refused, noCache, 2, LANTCP, 5, false},
		{"cache only", noTCP, cache, 3, LANNeighbor, 1, false},
		{"unsupported", noTCP, noCache, 4, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			warnings, err := scanLAN(t.Context(), lanTestLink(), nil, unavailable, tc.dial, tc.cache, func(o LANObservation) {
				n++
				if o.Evidence != tc.evidence {
					t.Errorf("evidence = %v, want %v", o.Evidence, tc.evidence)
				}
			})
			if len(warnings) != tc.warnings || (err != nil) != tc.wantError || n != tc.observed {
				t.Fatalf("warnings %v, error %v, observations %d", warnings, err, n)
			}
		})
	}
}

func TestLANICMPPermissionDenialsRequireEveryDestination(t *testing.T) {
	for _, tc := range []struct {
		name      string
		allDenied bool
		wantErr   bool
		wantWarns int
	}{
		{"all sends denied", true, true, 4},
		{"one destination denied", false, false, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			link := lanTestLink()
			echo := func(_ context.Context, dst netip.Addr) (bool, error) {
				attempts.Add(1)
				if tc.allDenied || dst == netip.MustParseAddr("192.168.10.2") {
					return false, errLANICMPSendDenied
				}
				return false, nil // sent, but the peer did not reply
			}
			dial := func(context.Context, string, string) (net.Conn, error) { return nil, errLANUnavailable }
			cache := func() ([]netip.Addr, error) { return nil, errors.New("no neighbor cache") }
			warnings, err := scanLAN(t.Context(), link, echo, nil, dial, cache, func(o LANObservation) {
				t.Errorf("permission denied peer became reachable: %v", o)
			})
			if (err != nil) != tc.wantErr || len(warnings) != tc.wantWarns || int(attempts.Load()) != len(link.targets()) {
				t.Fatalf("attempted %d peers, warnings %v, error %v", attempts.Load(), warnings, err)
			}
			if got := slices.ContainsFunc(warnings, func(w string) bool { return strings.HasPrefix(w, "ICMP echo unavailable:") }); got != tc.allDenied {
				t.Fatalf("ICMP method warning = %t, want %t: %v", got, tc.allDenied, warnings)
			}
		})
	}
}

func TestLANScanPreservesPartialResultsOnCancellationAndDeadline(t *testing.T) {
	for _, timedOut := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "deadline"}[timedOut], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				want := context.Canceled
				if timedOut {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 2*lanAttempt)
					defer stop()
					want = context.DeadlineExceeded
				}
				peer := netip.MustParseAddr("192.168.10.2")
				echo := func(ctx context.Context, ip netip.Addr) (bool, error) {
					if ip == peer {
						return true, nil
					}
					<-ctx.Done()
					return false, nil
				}
				dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > lanAttempt {
						t.Error("attempt has no per-probe deadline")
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}
				link := lanTestLink()
				link.prefix = netip.MustParsePrefix("192.168.10.0/24") // at least three waves
				var observations []LANObservation
				_, err := scanLAN(ctx, link, echo, nil, dial, func() ([]netip.Addr, error) { return nil, nil }, func(o LANObservation) {
					observations = append(observations, o)
					if !timedOut {
						cancel()
					}
				})
				if !errors.Is(err, want) || !slices.Equal(observations, []LANObservation{{IP: peer, Evidence: LANICMP}}) {
					t.Fatalf("observations %v, error %v, want one echo and %v", observations, err, want)
				}
			})
		})
	}
}

func TestLANWorkerBudgetWithSilentPeers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active atomic.Int32
		probe := func(ctx context.Context) {
			if active.Add(1) > 3*lanWorkers {
				t.Error("active probe concurrency exceeded")
			}
			defer active.Add(-1)
			<-ctx.Done()
		}
		start := time.Now()
		link := lanTestLink()
		link.prefix = netip.PrefixFrom(link.source, 24).Masked()
		_, err := scanLAN(t.Context(), link,
			func(ctx context.Context, _ netip.Addr) (bool, error) { probe(ctx); return false, nil }, nil,
			func(ctx context.Context, _, _ string) (net.Conn, error) { probe(ctx); return nil, ctx.Err() },
			func() ([]netip.Addr, error) { return nil, nil },
			func(o LANObservation) { t.Errorf("silent peer became a device: %v", o) })
		if want := 8 * lanAttempt; err != nil || time.Since(start) != want {
			t.Fatalf("silent /24 took %v, %v, want %v", time.Since(start), err, want)
		}
	})
}
