package snapshot

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// validateProvenance is shared by ordinary runs and profile envelopes. Build
// labels are identities, not a closed inventory of this reader's platforms.
func validateProvenance(createdAt string, tool Tool) error {
	at, err := time.Parse(time.RFC3339, createdAt)
	_, offset := at.Zone()
	if err != nil || offset != 0 {
		return fmt.Errorf("snapshot created_at %q is not RFC 3339 UTC", createdAt)
	}
	if strings.TrimSpace(tool.Version) == "" || strings.TrimSpace(tool.OS) == "" || strings.TrimSpace(tool.Arch) == "" {
		return fmt.Errorf("snapshot has incomplete tool provenance")
	}
	return nil
}

// validateInvocation checks what the artifact itself can establish. It does
// not reparse Raw: supported schemes, default ports and hostname policy belong
// to the producer, and support redaction may change the original spelling.
func validateInvocation(target *Target, options Options) error {
	if target != nil {
		if strings.TrimSpace(target.Raw) == "" || strings.TrimSpace(target.Host) == "" || strings.TrimSpace(target.Protocol) == "" {
			return fmt.Errorf("snapshot target has no raw spelling, host, or protocol")
		}
		if target.Port < 1 || target.Port > 65535 {
			return fmt.Errorf("snapshot target port %d is outside 1..65535", target.Port)
		}
		hostIP, ip := net.ParseIP(target.Host), net.ParseIP(target.IP)
		if target.IP != "" && (ip == nil || hostIP == nil || !ip.Equal(hostIP)) || target.IP == "" && hostIP != nil {
			return fmt.Errorf("snapshot target IP does not agree with its literal host")
		}
	}
	// Milliseconds truncates a positive sub-millisecond timeout to zero. The
	// artifact cannot distinguish that from an omitted numeric field.
	if options.ProbeTimeoutMs < 0 {
		return fmt.Errorf("snapshot probe timeout must not be negative")
	}
	if options.PublicDNS != "" && net.ParseIP(options.PublicDNS) == nil {
		return fmt.Errorf("snapshot public DNS resolver is not an IP address")
	}
	// Selection IDs need not occur in Checks: skip removes rows, target-specific
	// selections can be inapplicable, and future producers can add probe IDs.
	for _, ids := range [][]string{options.Check, options.Skip} {
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("snapshot probe selection has a blank ID")
			}
		}
	}
	if source := options.Source; source != nil {
		if source.IPv4 == "" && source.IPv6 == "" {
			return fmt.Errorf("snapshot source has no address")
		}
		if source.Interface == "" && source.IPv4 != "" && source.IPv6 != "" {
			return fmt.Errorf("snapshot exact source IP binding has two address families")
		}
		for _, family := range []struct {
			value string
			v4    bool
		}{{source.IPv4, true}, {source.IPv6, false}} {
			if family.value == "" {
				continue
			}
			ip := net.ParseIP(family.value)
			if ip == nil || (ip.To4() != nil) != family.v4 || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("snapshot source address %q is not a usable address in its family", family.value)
			}
		}
	}
	return nil
}
