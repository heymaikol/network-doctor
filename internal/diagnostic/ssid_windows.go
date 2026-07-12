//go:build windows

package diagnostic

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// ssid returns iface's Wi-Fi network name via the built-in netsh tool, or ""
// when iface isn't a WLAN interface or netsh fails (display-only garnish).
func ssid(ctx context.Context, iface string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return ""
	}
	// Console output is OEM code page; make invalid bytes visible, not silent.
	return textsafe.Clean(parseNetshSSID(strings.ToValidUTF8(string(out), "?"), iface))
}
