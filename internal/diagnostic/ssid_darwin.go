//go:build darwin

package diagnostic

import (
	"context"
	"os/exec"
	"time"

	"github.com/heymaikol/network-doctor/internal/textsafe"
)

// ssid returns iface's Wi-Fi network name via the built-in networksetup tool,
// or "" when not Wi-Fi, not associated, or the tool fails (display-only
// garnish; Apple removed `airport`, this is the surviving CLI path).
func ssid(ctx context.Context, iface string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "networksetup", "-getairportnetwork", iface).Output()
	if err != nil {
		return ""
	}
	return textsafe.Clean(parseAirportSSID(string(out)))
}
