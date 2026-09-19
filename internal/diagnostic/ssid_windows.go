//go:build windows

package diagnostic

import (
	"context"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// ssid returns iface's Wi-Fi network name via the built-in netsh tool, or ""
// when iface isn't a WLAN interface or netsh fails (display-only garnish).
func ssid(ctx context.Context, iface string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := ssidCommand(ctx, "netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return ""
	}
	// netsh writes OEM code page bytes; decode before parsing so non-ASCII
	// interface names still match their block.
	return textsafe.Clean(parseNetshSSID(decodeSSIDOutput(string(out)), iface))
}

// decodeSSIDOutput converts netsh's OEM console bytes to UTF-8. Tests replace
// it to prove the decode happens before parseNetshSSID.
var decodeSSIDOutput = textsafe.DecodeOEM
