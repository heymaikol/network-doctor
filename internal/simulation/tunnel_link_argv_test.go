package simulation

import (
	"reflect"
	"testing"
)

// tunnelLinkArgv is the three commands that create a tunnel device: the device with its
// kind and endpoints, pinned by dev to the segment interface that carries its outer
// packets, then its overlay address, then the device up. addTunnel runs them through
// Env.Exec. It uses no netns types, so ordinary runs can check the commands too.
func tunnelLinkArgv(kind, name, local, remote, overlay, dev string) [][]string {
	return [][]string{
		{"ip", "link", "add", name, "type", kind, "local", local, "remote", remote, "dev", dev},
		{"ip", "addr", "add", overlay, "dev", name},
		{"ip", "link", "set", "dev", name, "up"},
	}
}

// TestTunnelLinkArgv pins the commands that create the GRE and IPIP devices the live cases
// build. A swapped kind, name, or overlay fails here, without a namespace.
func TestTunnelLinkArgv(t *testing.T) {
	for _, c := range []struct{ kind, name, overlay string }{
		{"gre", "gre1", "172.31.0.1/30"},
		{"ipip", "ipip1", "172.32.0.1/30"},
	} {
		want := [][]string{
			{"ip", "link", "add", c.name, "type", c.kind, "local", "10.71.14.1", "remote", "10.71.30.1", "dev", "s14"},
			{"ip", "addr", "add", c.overlay, "dev", c.name},
			{"ip", "link", "set", "dev", c.name, "up"},
		}
		if got := tunnelLinkArgv(c.kind, c.name, "10.71.14.1", "10.71.30.1", c.overlay, "s14"); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: commands\n%v\nwant\n%v", c.kind, got, want)
		}
	}
}
