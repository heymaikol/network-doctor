//go:build acceptance

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// hostRouteTool on macOS is /sbin/route, the documented user space interface to
// the routing socket. netdoc writes its own RTM_GET and parses the reply; route
// builds and reads its own. A mistake in either the request netdoc sends or the
// reply it decodes shows up here as a disagreement rather than as two copies of
// the same answer.
const hostRouteTool = "/sbin/route -n get"

// hostRouteLookup asks route about one destination. It reports found=false only
// when route says there is no route, and fails the test when route itself could
// not be run or produced something unreadable.
func hostRouteLookup(t *testing.T, dst netip.Addr) (hostRoute, bool) {
	t.Helper()
	family := "-inet"
	if dst.Is6() {
		family = "-inet6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", family, dst.String()).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("route -n get %s did not finish: %v\n%s", dst, err, out)
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("run /sbin/route for %s: %v", dst, err)
		}
		t.Fatalf("route -n get %s exited %v:\n%s", dst, err, out)
	}
	if darwinNoRouteOutput(out) {
		t.Logf("route -n get found no route to %s:\n%s", dst, out)
		return hostRoute{}, false
	}
	got, err := parseDarwinRouteOutput(dst, out)
	if err != nil {
		t.Fatalf("parse route -n get %s: %v\n%s", dst, err, out)
	}
	return got, true
}

func darwinNoRouteOutput(out []byte) bool {
	text := string(out)
	if strings.Contains(text, "route: writing to routing socket: not in table") {
		return true
	}
	for _, code := range []syscall.Errno{syscall.ESRCH, syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH} {
		if strings.Contains(text, fmt.Sprintf("message indicates error %d:", code)) {
			return true
		}
	}
	return false
}

func parseDarwinRouteOutput(dst netip.Addr, out []byte) (hostRoute, error) {
	// Every field route prints is "name: value" with the first colon as the
	// separator, which leaves an IPv6 value intact.
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	got := hostRoute{Iface: fields["interface"], WasCloned: strings.Contains(darwinFlags(fields), ",WASCLONED,")}
	if got.Iface == "" {
		return hostRoute{}, errors.New("route named no interface")
	}
	if raw := fields["gateway"]; raw != "" {
		gateway, err := netip.ParseAddr(raw)
		if err == nil {
			gateway = gateway.Unmap().WithZone("")
			if !gateway.IsUnspecified() {
				got.Gateway = gateway
			}
		} else if !strings.HasPrefix(raw, "link#") && !strings.HasPrefix(raw, "index:") {
			return hostRoute{}, fmt.Errorf("route named unreadable gateway %q", raw)
		}
	}
	prefix, err := darwinRoutePrefix(dst, fields)
	if err != nil {
		return hostRoute{}, err
	}
	got.Prefix = prefix
	return got, nil
}

// darwinFlags is the route's flag list wrapped in the separator it uses, so a
// whole flag can be matched without also matching a longer one containing it.
func darwinFlags(fields map[string]string) string {
	return "," + strings.Trim(fields["flags"], "<>") + ","
}

func darwinRoutePrefix(dst netip.Addr, fields map[string]string) (netip.Prefix, error) {
	rawDestination := fields["destination"]
	if rawDestination == "" {
		return netip.Prefix{}, errors.New("route named no matched destination")
	}
	if rawDestination == "default" {
		return netip.PrefixFrom(dst, 0).Masked(), nil
	}
	matched, err := netip.ParseAddr(rawDestination)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("route named unreadable destination %q", rawDestination)
	}
	matched = matched.Unmap().WithZone("")
	if matched.Is4() != dst.Is4() {
		return netip.Prefix{}, fmt.Errorf("route destination %s has the wrong family for %s", matched, dst)
	}
	bits := dst.BitLen()
	if !strings.Contains(darwinFlags(fields), ",HOST,") {
		rawMask := fields["mask"]
		if rawMask == "" {
			return netip.Prefix{}, errors.New("non-host route named no mask")
		}
		if rawMask == "default" {
			bits = 0
		} else {
			mask, err := netip.ParseAddr(rawMask)
			if err != nil {
				return netip.Prefix{}, fmt.Errorf("route named unreadable mask %q", rawMask)
			}
			mask = mask.Unmap()
			if mask.Is4() != dst.Is4() {
				return netip.Prefix{}, fmt.Errorf("route mask %s has the wrong family for %s", mask, dst)
			}
			var total int
			bits, total = net.IPMask(mask.AsSlice()).Size()
			if total != dst.BitLen() {
				return netip.Prefix{}, fmt.Errorf("route mask %s is not contiguous", mask)
			}
		}
	}
	prefix := netip.PrefixFrom(matched, bits).Masked()
	if !prefix.Contains(dst) {
		return netip.Prefix{}, fmt.Errorf("route prefix %s does not contain queried destination %s", prefix, dst)
	}
	return prefix, nil
}

func TestNativeDarwinRouteOutputParser(t *testing.T) {
	cases := []struct {
		name, dst, output, prefix, gateway string
		cloned                             bool
	}{
		{"IPv4 default", "1.1.1.1", `route to: 1.1.1.1
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
`, "0.0.0.0/0", "192.0.2.1", false},
		{"IPv6 network on link", "2606:4700:4700::1111", `route to: 2606:4700:4700::1111
destination: 2606:4700::
       mask: ffff:ffff::
    gateway: link#7
  interface: en0
      flags: <UP,DONE,STATIC>
`, "2606:4700::/32", "", false},
		{"IPv6 host", "2001:db8::7", `route to: 2001:db8::7
destination: 2001:db8::7
  interface: utun3
      flags: <UP,HOST,DONE,IFSCOPE>
`, "2001:db8::7/128", "", false},
		// Captured from macOS 26 after a connected UDP socket to this address:
		// the kernel cloned the default route, and route answers the clone. The
		// shape is identical to the configured host route above apart from the
		// flag, which is why the flag is what provenance is read from.
		{"IPv4 host cloned from the default route", "1.1.1.1", `route to: 1.1.1.1
destination: 1.1.1.1
    gateway: 192.168.64.1
  interface: en0
      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>
`, "1.1.1.1/32", "192.168.64.1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDarwinRouteOutput(netip.MustParseAddr(c.dst), []byte(c.output))
			if err != nil {
				t.Fatal(err)
			}
			gateway := ""
			if got.Gateway.IsValid() {
				gateway = got.Gateway.String()
			}
			if got.Prefix.String() != c.prefix || gateway != c.gateway || got.Iface == "" || got.WasCloned != c.cloned {
				t.Errorf("parsed route = %+v, want prefix %s gateway %s cloned=%v and an interface", got, c.prefix, c.gateway, c.cloned)
			}
		})
	}
	if _, err := parseDarwinRouteOutput(netip.MustParseAddr("1.1.1.1"), []byte("destination: 192.0.2.0\ninterface: en0\n")); err == nil {
		t.Error("a non-host route without a mask was accepted")
	}
	if !darwinNoRouteOutput([]byte("route: writing to routing socket: not in table\n")) ||
		!darwinNoRouteOutput([]byte("route: message indicates error 51: Network is unreachable\n")) ||
		darwinNoRouteOutput([]byte("route: message indicates error 55: No buffer space available\n")) {
		t.Error("no-route kernel errors were not separated from route-tool failures")
	}
}
