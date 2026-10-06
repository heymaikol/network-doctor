// Parsers for the networksetup (macOS) and netsh (Windows) SSID output
// formats, runnable from any OS.

package diagnostic

import "testing"

func TestParseAirportSSID(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
	}{
		{"success", "Current Wi-Fi Network: HomeNet 5G\n", "HomeNet 5G"},
		// The name is taken whole, not up to some delimiter inside it.
		{"colon in ssid", "Current Wi-Fi Network: Cafe: Ristretto\n", "Cafe: Ristretto"},
		{"unicode ssid", "Current Wi-Fi Network: Caf\u00e9 \u65e5\u672c\n", "Caf\u00e9 \u65e5\u672c"},
		{"padded separator", "  Current Wi-Fi Network:    HomeNet   \n", "HomeNet"},
		// A renamed or translated label degrades to "" by design; it must not
		// fall back to splitting on the colon.
		{"localized label", "R\u00e9seau Wi-Fi actuel : HomeNet\n", ""},
		{"legacy label", "Current AirPort Network: HomeNet\n", ""},
		{"not associated", "You are not associated with an AirPort network.\n", ""},
		// Colon-shaped status line: proof that a diagnostic never becomes an SSID.
		{"non-wifi iface", "networksetup: en5 is not a Wi-Fi interface.\n", ""},
		{"label without value", "Current Wi-Fi Network: \n", ""},
		{"empty output", "", ""},
	} {
		if got := parseAirportSSID(tc.out); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Two-adapter capture: the block is selected by the *value* of its first field,
// the interface name, and the exact "SSID" key excludes BSSID.
const netshTwoAdapters = "There are 2 interfaces on the system:\r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi\r\n" +
	"    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r\n" +
	"    GUID                   : 12345678-1234-1234-1234-123456789abc\r\n" +
	"    Physical address       : aa:bb:cc:dd:ee:ff\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : HomeNet\r\n" +
	"    BSSID                  : 11:22:33:44:55:66\r\n" +
	"    Radio type             : 802.11ax\r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi 2\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : OtherNet\r\n" +
	"    BSSID                  : 66:55:44:33:22:11\r\n"

// Non-English capture (German labels): the localized "Name" label is never
// consulted: the block still matches by its first field's value, and "SSID" is
// untranslated.
const netshGerman = "Es gibt 1 Schnittstelle auf dem System:\r\n" +
	"\r\n" +
	"    Name                   : WLAN\r\n" +
	"    Beschreibung           : Intel Wireless\r\n" +
	"    Status                 : Verbunden\r\n" +
	"    SSID                   : CafeNetz\r\n" +
	"    BSSID                  : aa:bb:cc:11:22:33\r\n"

func TestParseNetshSSID(t *testing.T) {
	if got := parseNetshSSID(netshTwoAdapters, "Wi-Fi"); got != "HomeNet" {
		t.Errorf("Wi-Fi: got %q, want HomeNet", got)
	}
	if got := parseNetshSSID(netshTwoAdapters, "Wi-Fi 2"); got != "OtherNet" {
		t.Errorf("Wi-Fi 2: got %q, want OtherNet", got)
	}
	// No fallback: an Ethernet/VPN iface must never acquire a Wi-Fi SSID.
	if got := parseNetshSSID(netshTwoAdapters, "Ethernet"); got != "" {
		t.Errorf("Ethernet: got %q, want empty", got)
	}
	if got := parseNetshSSID(netshGerman, "WLAN"); got != "CafeNetz" {
		t.Errorf("German locale: got %q, want CafeNetz", got)
	}
	// An SSID value alone must not select a block.
	if got := parseNetshSSID(netshTwoAdapters, "HomeNet"); got != "" {
		t.Errorf("SSID as iface: got %q, want empty", got)
	}
	// #244: block 1's SSID equals the requested iface; only block 2's name
	// field may select a block.
	collision := "    Name                   : Wi-Fi\r\n" +
		"    SSID                   : Office\r\n" +
		"\r\n" +
		"    Name                   : Office\r\n" +
		"    SSID                   : Home\r\n"
	if got := parseNetshSSID(collision, "Office"); got != "Home" {
		t.Errorf("SSID collision: got %q, want Home", got)
	}
	if got := parseNetshSSID("", "Wi-Fi"); got != "" {
		t.Errorf("empty output: got %q, want empty", got)
	}
}
