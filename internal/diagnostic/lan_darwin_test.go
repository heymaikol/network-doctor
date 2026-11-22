package diagnostic

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinLANNeighbors(t *testing.T) {
	mac := []byte{2, 1, 2, 3, 4, 5}
	proxy := neighbor(unix.AF_INET, 7, "10.0.0.4", mac)
	proxy.Flags |= unix.RTF_PROXY
	rows := []route.Message{
		neighbor(unix.AF_INET, 7, "10.0.0.1", mac),
		neighbor(unix.AF_INET, 8, "10.0.0.2", mac),
		neighbor(unix.AF_INET, 7, "10.0.0.3", nil),
		proxy,
		neighbor(unix.AF_INET6, 7, "fe80::1", mac),
	}
	if got := darwinLANNeighbors(rows, 7); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("10.0.0.1")}) {
		t.Fatalf("selected neighbors = %v", got)
	}
}
