package ui

import (
	"path/filepath"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

func decodeToolOutput(name, line string) string {
	if isWindowsOEMTool(name) {
		return textsafe.DecodeOEM(line)
	}
	return strings.ToValidUTF8(line, "?")
}

func isWindowsOEMTool(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(filepath.Base(name)), ".exe")
	switch name {
	case "route", "netstat", "ping", "nslookup", "tracert", "pathping":
		return true
	default:
		return false
	}
}
