//go:build linux

package diagnostic

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	procIPv4Routes = "/proc/net/route"
	procIPv6Routes = "/proc/net/ipv6_route"
	procARPTable   = "/proc/net/arp"
	routeFlagUp    = 0x1
	routeFlagGW    = 0x2
)

func routeFailureCause(destination net.IP) string {
	if destination.To4() != nil {
		routes, err := os.ReadFile(procIPv4Routes)
		if err != nil {
			return ""
		}
		arp, _ := os.ReadFile(procARPTable)
		return routeFailureCauseFrom(routes, arp)
	}
	if destination.To16() == nil {
		return ""
	}
	routes, err := os.ReadFile(procIPv6Routes)
	if err != nil {
		return ""
	}
	return routeFailureCauseIPv6From(routes)
}

func routeFailureCauseFrom(routeData, arpData []byte) string {
	routes := parseDefaultRoutes(routeData)
	return classifyDefaultRoutes(routes, func(route defaultRouteState) bool {
		return route.gateway != nil && arpGatewayFailed(arpData, route.gateway.String(), route.iface)
	})
}

func routeFailureCauseIPv6From(routeData []byte) string {
	return classifyDefaultRoutes(parseIPv6DefaultRoutes(routeData), nil)
}

func parseIPv6DefaultRoutes(raw []byte) []defaultRouteState {
	var out []defaultRouteState
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != strings.Repeat("0", 32) || fields[1] != "00" ||
			fields[2] != strings.Repeat("0", 32) || fields[3] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil || flags&routeFlagUp == 0 {
			continue
		}
		metric, err := strconv.ParseInt(fields[5], 16, 32)
		if err != nil || metric < 0 {
			continue
		}
		gatewayRaw, err := hex.DecodeString(fields[4])
		if err != nil || len(gatewayRaw) != net.IPv6len {
			continue
		}
		var gateway net.IP
		if !net.IP(gatewayRaw).IsUnspecified() {
			gateway = net.IP(gatewayRaw)
		}
		out = append(out, defaultRouteState{iface: fields[9], gateway: gateway, metric: int(metric)})
	}
	return out
}

func parseDefaultRoutes(raw []byte) []defaultRouteState {
	lines := strings.Split(string(raw), "\n")
	var out []defaultRouteState
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&routeFlagUp == 0 {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil || metric < 0 {
			continue
		}
		var gateway net.IP
		if flags&routeFlagGW != 0 {
			gateway = parseProcIPv4(fields[2])
			if gateway == nil {
				continue
			}
		}
		out = append(out, defaultRouteState{iface: fields[0], gateway: gateway, metric: metric})
	}
	return out
}

func parseProcIPv4(raw string) net.IP {
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != net.IPv4len {
		return nil
	}
	return net.IPv4(b[3], b[2], b[1], b[0])
}

// arpGatewayFailed reads unresolved ARP state after reference TCP attempts fail.
// This /proc representation does not distinguish resolution still in progress
// (NUD_INCOMPLETE) from NUD_FAILED; the entry alone is not proof of a dead peer.
func arpGatewayFailed(raw []byte, gateway, iface string) bool {
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != gateway || fields[5] != iface {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil {
			return false
		}
		return flags == 0 || fields[3] == "00:00:00:00:00:00"
	}
	return false
}
