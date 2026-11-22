//go:build integration && linux

package diagnostic

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func loopbackLAN(tb testing.TB) lanLink {
	tb.Helper()
	const source = "127.0.0.1"
	ifaces, err := net.Interfaces()
	if err != nil {
		tb.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return lanLink{Interface: iface, source: netip.MustParseAddr(source),
				prefix: netip.MustParsePrefix("127.0.0.0/24")}
		}
	}
	tb.Fatal("no loopback interface")
	return lanLink{}
}

func TestLANBoundLoopback(t *testing.T) {
	link := loopbackLAN(t)
	ctx, cancel := context.WithTimeout(t.Context(), lanAttempt)
	defer cancel()
	echo, err := lanEchoProbe(link)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := echo(ctx, netip.MustParseAddr("127.0.0.2")); !ok || err != nil {
		t.Fatalf("bound ICMP loopback reply = %t, %v", ok, err)
	}

	listen, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listen.Close() }()
	dial := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(link.source.AsSlice())}, Control: lanSocketControl(link)}
	conn, err := dial.DialContext(ctx, "tcp4", listen.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if ip := conn.LocalAddr().(*net.TCPAddr).IP; !ip.Equal(net.IP(link.source.AsSlice())) {
		t.Fatalf("bound TCP source = %v, want %v", ip, link.source)
	}
	link.Index = 1<<31 - 1
	dial.Control = lanSocketControl(link)
	if conn, err := dial.DialContext(ctx, "tcp4", listen.Addr().String()); err == nil {
		_ = conn.Close()
		t.Fatal("TCP fell back to an unbound socket")
	}
}

func BenchmarkLANLoopback(b *testing.B) {
	link := loopbackLAN(b)
	peers := len(link.targets())
	b.Run("HEAD_Nmap", func(b *testing.B) {
		for b.Loop() {
			ctx, cancel := context.WithTimeout(b.Context(), LANScanTimeout)
			// -n isolates discovery from name resolution in both arms.
			out, err := exec.CommandContext(ctx, "nmap", "--unprivileged", "-sn", "-T3", "--host-timeout", "5s", "-oG", "-", "-n", "127.0.0.2-254").Output()
			cancel()
			if n := strings.Count(string(out), "\tStatus: Up"); err != nil || n != peers {
				b.Fatalf("Nmap found %d of %d loopback peers: %v", n, peers, err)
			}
		}
	})
	b.Run("Combined", func(b *testing.B) {
		echo, echoErr := lanEchoProbe(link)
		dial := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(link.source.AsSlice())}, Control: lanSocketControl(link)}
		for b.Loop() {
			seen := make(map[netip.Addr]LANEvidence, peers)
			warnings, err := scanLAN(b.Context(), link, echo, echoErr, dial.DialContext, func() ([]netip.Addr, error) {
				return lanNeighbors(link)
			}, func(o LANObservation) { seen[o.IP] = o.Evidence })
			if len(warnings) != 0 || err != nil || len(seen) != peers {
				b.Fatalf("combined scan found %d of %d loopback peers: %v, %v", len(seen), peers, warnings, err)
			}
			for addr, evidence := range seen {
				if evidence != LANICMP|LANTCP {
					b.Fatalf("%s supplied %v, want both fresh responses", addr, evidence)
				}
			}
		}
	})
}
