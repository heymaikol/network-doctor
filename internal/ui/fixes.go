package ui

import "github.com/heymaikol/network-doctor/internal/diagnostic"

// fixFor returns the automatic fix command for a failed probe on goos, or nil
// when no safe local fix exists (target TCP/TLS/HTTP failures are remote
// problems). Fixes are deliberately mild — no sudo, no config rewrites, just
// flush a cache or re-enable networking. The rerun that follows the fix is the
// real verdict, so a fix that turns out to be a no-op is harmless.
func fixFor(id diagnostic.ProbeID, goos string) *Tool {
	quote := shellArgs
	if goos == "windows" {
		quote = psArgs
	}
	mk := func(name, bin string, args ...string) *Tool {
		t := staticTool(quote, "f", name, bin, args...)
		return &t
	}
	switch id {
	case diagnostic.ProbeIface:
		if goos == "darwin" || goos == "windows" {
			return nil // no reliable non-admin command to bring a link up
		}
		return mk("enable networking", "nmcli", "networking", "on")
	case diagnostic.ProbeDNS:
		switch goos {
		case "darwin":
			return mk("flush DNS cache", "dscacheutil", "-flushcache")
		case "windows":
			return mk("flush DNS cache", "ipconfig", "/flushdns")
		default:
			return mk("flush DNS cache", "resolvectl", "flush-caches")
		}
	}
	return nil
}
