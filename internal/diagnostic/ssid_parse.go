package diagnostic

import "strings"

// parseAirportSSID parses stdout from `networksetup -getairportnetwork
// <iface>`, whose success form is one line: "Current Wi-Fi Network: <name>".
//
// The English label is load-bearing and cannot be swapped for a generic "value
// after the first colon" rule, because networksetup's status lines have the
// same shape: "networksetup: en5 is not a Wi-Fi interface." would then parse as
// the SSID "en5 is not a Wi-Fi interface.". The label is the only token
// separating a network name from a diagnostic, so the label is what we match.
//
// This is why the tool differs from netsh (see parseNetshSSID), which keeps an
// untranslated "SSID" key and a second field to match a value against;
// networksetup exposes neither. Apple documents no output format here, and the
// label is not guaranteed: it already changed once, from "Current AirPort
// Network:" on older releases. Whether it can also be localized could not be
// established. Either way the failure is the safe one: an unrecognized label
// yields "", the display-only Wi-Fi line is dropped, and a status message is
// never reported as a network name.
//
// The name is returned verbatim after trimming, so SSIDs containing spaces,
// colons, or non-ASCII text survive intact.
func parseAirportSSID(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Current Wi-Fi Network:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseNetshSSID extracts iface's SSID from `netsh wlan show interfaces`.
// Blocks are blank-line separated; a block matches only when its first line's
// *value* (text after the first ':', trimmed) equals iface. In known netsh
// output that first field is the interface name, so the localized "Name" label
// is never consulted, and no other field (SSID, Description) can select a
// block. An unexpected layout yields "", never another adapter's SSID. Within
// the matching block the line whose key is exactly "SSID" wins (netsh does not
// translate that label; the exact match excludes "BSSID"). No fallback: netsh
// lists only WLAN interfaces, so a wired/VPN iface never acquires a Wi-Fi SSID.
func parseNetshSSID(out, iface string) string {
	var blocks [][]string
	var cur []string
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(ln) == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, ln)
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	for _, block := range blocks {
		if _, v, ok := strings.Cut(block[0], ":"); !ok || strings.TrimSpace(v) != iface {
			continue
		}
		for _, ln := range block {
			if k, v, ok := strings.Cut(ln, ":"); ok && strings.TrimSpace(k) == "SSID" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}
