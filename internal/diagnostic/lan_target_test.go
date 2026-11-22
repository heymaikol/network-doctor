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
)

func lanTargetFixture(t *testing.T) (*netops, LANBinding, func(string, net.Interface, string)) {
	t.Helper()
	const active = net.FlagUp | net.FlagRunning
	ifaces := []net.Interface{{Name: "vpn", Index: 18, Flags: active}, {Name: "lan", Index: 7, Flags: active}}
	cidrs := map[string]string{"vpn": "192.168.12.2/28", "lan": "192.168.12.34/24"}
	o := &netops{
		interfaces: func() ([]net.Interface, error) { return ifaces, nil },
		interfaceAddrs: func(iface *net.Interface) ([]net.Addr, error) {
			ip, subnet, err := net.ParseCIDR(cidrs[iface.Name])
			if err != nil {
				return nil, err
			}
			subnet.IP = ip
			return []net.Addr{subnet}, nil
		},
	}
	link, err := findLANLink(netip.MustParseAddr("192.168.12.34"), "", o.interfaces, o.interfaceAddrs)
	if err != nil {
		t.Fatal(err)
	}
	change := func(name string, replacement net.Interface, cidr string) {
		if i := slices.IndexFunc(ifaces, func(iface net.Interface) bool { return iface.Name == name }); i >= 0 {
			ifaces = slices.Delete(ifaces, i, i+1)
		}
		if replacement.Name != "" {
			ifaces = append(ifaces, replacement)
			cidrs[replacement.Name] = cidr
		}
	}
	return o, link.binding(), change
}

func TestLANSelectedServiceProbesUseSnapshotPath(t *testing.T) {
	o, binding, _ := lanTargetFixture(t)
	target, err := binding.ServiceTarget(LocalService{Port: 22, Scheme: "ssh"}, "192.168.12.1")
	if err != nil {
		t.Fatal(err)
	}
	var lanDials, ordinaryDials atomic.Int32
	o.dialContext = func(context.Context, string, string) (net.Conn, error) {
		ordinaryDials.Add(1)
		return nil, errors.New("ordinary route")
	}
	o.dialLAN = func(_ context.Context, link lanLink, addr string) (net.Conn, error) {
		lanDials.Add(1)
		if link.binding() != binding || addr != "192.168.12.1:22" {
			t.Errorf("dialed %s through %+v, want original LAN %+v", addr, link.binding(), binding)
		}
		return &scriptConn{
			fakeConn: fakeConn{local: &net.TCPAddr{IP: net.IP(binding.Source.AsSlice())}},
			r:        strings.NewReader("SSH-2.0-lan-device\r\n"),
		}, nil
	}
	probes := o.timedProbes(target, "", false)
	run := func(id ProbeID, deps map[ProbeID]ProbeResult) ProbeResult {
		i := slices.IndexFunc(probes, func(p Probe) bool { return p.ID == id })
		return probes[i].Run(t.Context(), deps)
	}
	dns := run(ProbeDNS, nil)
	tcp := run(ProbeTargetTCP, map[ProbeID]ProbeResult{ProbeDNS: dns})
	ssh := run(ProbeSSH, map[ProbeID]ProbeResult{ProbeTargetTCP: tcp})
	if tcp.Status != StatusPass || tcp.Iface != binding.Interface || !tcp.Source.Equal(binding.Source.AsSlice()) ||
		ssh.Status != StatusPass || !strings.Contains(ssh.Detail, "lan-device") || lanDials.Load() != 2 || ordinaryDials.Load() != 0 {
		t.Fatalf("TCP %+v, SSH %+v, LAN dials %d, ordinary dials %d", tcp, ssh, lanDials.Load(), ordinaryDials.Load())
	}
	run(ProbeInternet, nil)
	if ordinaryDials.Load() == 0 || lanDials.Load() != 2 {
		t.Fatal("Internet check inherited the LAN target binding")
	}
}

func TestLANSelectedServiceRejectsChangedBinding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale func(func(string, net.Interface, string))
	}{
		{"interface vanished", func(change func(string, net.Interface, string)) { change("lan", net.Interface{}, "") }},
		{"interface index changed", func(change func(string, net.Interface, string)) {
			change("lan", net.Interface{Name: "lan", Index: 77, Flags: net.FlagUp}, "192.168.12.34/24")
		}},
		{"source reassigned", func(change func(string, net.Interface, string)) {
			change("lan", net.Interface{Name: "lan", Index: 7, Flags: net.FlagUp}, "192.168.12.35/24")
			change("vpn", net.Interface{Name: "vpn", Index: 18, Flags: net.FlagUp}, "192.168.12.34/24")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, binding, change := lanTargetFixture(t)
			target, err := binding.ServiceTarget(LocalService{Port: 443}, "192.168.12.1")
			if err != nil {
				t.Fatal(err)
			}
			o.dialLAN = func(context.Context, lanLink, string) (net.Conn, error) {
				tc.stale(change)
				return fakeConn{local: &net.TCPAddr{IP: net.IP(binding.Source.AsSlice())}}, nil
			}
			probes := o.timedProbes(target, "", false)
			t.Cleanup(func() { ReleaseProbes(probes) })
			i := slices.IndexFunc(probes, func(p Probe) bool { return p.ID == ProbeTargetTCP })
			deps := map[ProbeID]ProbeResult{ProbeDNS: {Addrs: []net.IP{target.IP}}}
			for _, name := range []string{"in-flight change", "stale on next run"} {
				got := probes[i].Run(t.Context(), deps)
				if got.Status != StatusFail || got.Cause != ConnectionCauseLANBinding || got.SelectedIP != nil || !strings.Contains(got.Detail, "LAN snapshot interface") ||
					TargetSocketOpen(probes) {
					t.Fatalf("%s reported usable evidence: %+v", name, got)
				}
				d := Interpret(target, []ProbeID{ProbeTargetTCP}, map[ProbeID]ProbeResult{ProbeTargetTCP: got})
				if !strings.Contains(d.Summary, "LAN binding") {
					t.Fatalf("invalid local binding was blamed on the device: %+v", d)
				}
			}
		})
	}
}

func TestLANSelectedServiceBindingFailures(t *testing.T) {
	for _, tc := range []struct {
		id   ProbeID
		port int
	}{
		{ProbeTargetTCP, 443}, {ProbeTLS, 443}, {ProbeHTTPS, 443}, {ProbeHTTP, 443},
		{ProbeHTTP, 80}, {ProbeSSH, 22}, {ProbeSMTP, 25}, {ProbeSMTP, 465}, {ProbePMTU, 443},
	} {
		t.Run(string(tc.id)+LocalService{Port: tc.port}.Target(""), func(t *testing.T) {
			o, binding, _ := lanTargetFixture(t)
			service := LocalService{Port: tc.port}
			if tc.id == ProbeSMTP {
				service.Scheme = "smtp"
			}
			target, err := binding.ServiceTarget(service, "192.168.12.1")
			if err != nil {
				t.Fatal(err)
			}
			o.dialLAN = func(context.Context, lanLink, string) (net.Conn, error) { return nil, errLANUnavailable }
			probes := o.timedProbes(target, "", false)
			t.Cleanup(func() { ReleaseProbes(probes) })
			i := slices.IndexFunc(probes, func(p Probe) bool { return p.ID == tc.id })
			if i < 0 {
				t.Fatalf("probe %s missing for %s", tc.id, target.Raw)
			}
			ip := target.IP
			got := probes[i].Run(t.Context(), map[ProbeID]ProbeResult{
				ProbeDNS: {Addrs: []net.IP{ip}}, ProbeTargetTCP: {SelectedIP: ip}, ProbeTLS: {SelectedIP: ip},
			})
			if got.Status != StatusFail || !strings.Contains(got.Detail, "interface binding unavailable") || !probes[i].fresh {
				t.Fatalf("failed binding did not fail %s explicitly: %+v", tc.id, got)
			}
		})
	}
}
