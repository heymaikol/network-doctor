package diagnostic

import (
	"net/netip"
	"slices"
	"testing"
)

func TestLinuxLANNeighbors(t *testing.T) {
	const raw = `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         02:01:02:03:04:05     *        selected
10.0.0.2         0x1         0x2         02:01:02:03:04:06     *        other
10.0.0.3         0x1         0x0         00:00:00:00:00:00     *        selected
10.0.0.4         0x1         0xa         02:01:02:03:04:07     *        selected
10.0.0.5         0x1         0x2         ff:ff:ff:ff:ff:ff     *        selected
malformed        0x1         0x2         02:01:02:03:04:07     *        selected`
	if got := linuxLANNeighbors(raw, "selected"); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("10.0.0.1")}) {
		t.Fatalf("selected neighbors = %v", got)
	}
}
