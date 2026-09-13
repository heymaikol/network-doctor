package snapshot

import (
	"fmt"
	"net"
	"net/netip"
)

// validateObservation checks the portable meanings of measurements, not which
// probe may collect them or which diagnosis should follow. Optional values stay
// optional, and causes, route reasons and device kinds remain extensible.
func validateObservation(c Check, sanitized bool) error {
	if c.DurationMs < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if !validObservationFamily(c.CauseFamily) {
		return fmt.Errorf("unknown cause_family %q", c.CauseFamily)
	}
	o := c.Observed
	if o == nil {
		return nil
	}
	for i, address := range o.Addresses {
		if err := observationIP(fmt.Sprintf("addresses[%d]", i), address, false, sanitized); err != nil {
			return err
		}
	}
	for _, field := range []struct{ name, value string }{
		{"selected_ip", o.SelectedIP}, {"source_ip", o.SourceIP}, {"resolver", o.Resolver},
	} {
		if err := observationIP(field.name, field.value, true, sanitized); err != nil {
			return err
		}
	}
	if o.Families != nil {
		for _, field := range []struct{ name, value string }{{"ipv4", o.Families.IPv4}, {"ipv6", o.Families.IPv6}} {
			switch field.value {
			case "", "reachable", "unreachable":
			default:
				return fmt.Errorf("address_families.%s has unknown reachability %q", field.name, field.value)
			}
		}
	}
	for i, a := range o.Attempts {
		if a.DurationMs < 0 {
			return fmt.Errorf("attempts[%d].duration_ms must not be negative", i)
		}
		if err := observationIP(fmt.Sprintf("attempts[%d].ip", i), a.IP, false, sanitized); err != nil {
			return err
		}
	}
	for i, r := range o.Routes {
		if err := validateObservedRoute(r, sanitized); err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
		}
	}
	return nil
}

func observationIP(field, value string, optional, sanitized bool) error {
	// support-v1 explicitly permits this erasure marker. It is not an IP and
	// must never be accepted as one without the artifact's redaction metadata.
	if sanitized && value == redactedAddress {
		return nil
	}
	if optional && value == "" {
		return nil
	}
	if net.ParseIP(value) == nil {
		return fmt.Errorf("%s is not an IP address: %q", field, value)
	}
	return nil
}

func validObservationFamily(value string) bool {
	return value == "" || value == "ipv4" || value == "ipv6"
}

func validateObservedRoute(r Route, sanitized bool) error {
	if err := observationIP("destination", r.Destination, false, sanitized); err != nil {
		return err
	}
	if !validObservationFamily(r.Family) {
		return fmt.Errorf("unknown family %q", r.Family)
	}
	if r.Family != "" && r.Destination != redactedAddress && (net.ParseIP(r.Destination).To4() != nil) != (r.Family == "ipv4") {
		return fmt.Errorf("family %q contradicts destination %q", r.Family, r.Destination)
	}
	for _, field := range []struct{ name, value string }{{"gateway", r.Gateway}, {"source", r.Source}} {
		if err := observationIP(field.name, field.value, true, sanitized); err != nil {
			return err
		}
	}
	if r.Prefix != "" {
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			return fmt.Errorf("prefix is not CIDR: %q", r.Prefix)
		}
		// Prefix is the entry the kernel said it matched, and every producer
		// that fills it builds it from the destination that was looked up:
		// Windows and Darwin both derive it with dst.Prefix on an unmapped
		// destination, and Linux leaves it unset. A prefix in the other family
		// is an entry no platform could have matched. Unmap keeps a mapped
		// IPv4 prefix reading as IPv4, the same way the destination does.
		//
		// Containment is deliberately not checked here: support
		// pseudonymization maps a prefix and the addresses inside it
		// separately and documents that it may lose that relationship.
		if v4, known := routeAddressFamilyIsIPv4(r); known && prefix.Addr().Unmap().Is4() != v4 {
			return fmt.Errorf("prefix %q is not in the route's address family", r.Prefix)
		}
	}
	if r.InterfaceMTU < 0 {
		return fmt.Errorf("interface_mtu must not be negative")
	}
	switch r.Tunnel {
	case "", TunnelStateDirect, TunnelStateLikely, TunnelStateTunnel:
	default:
		return fmt.Errorf("unknown tunnel state %q", r.Tunnel)
	}
	if r.TunnelKind != "" && r.Tunnel != TunnelStateTunnel {
		return fmt.Errorf("tunnel_kind requires tunnel state %q", TunnelStateTunnel)
	}
	// Table predates TableKnown in v1. A legacy name without the knowledge bit
	// must remain readable as unknown; it must not be upgraded to known here.
	return nil
}

// routeAddressFamilyIsIPv4 reports which address family a route decision is
// about, and whether the artifact states it at all. The destination is the
// identity of the decision, so it answers first, and the family label is
// already validated against it. Support erasure can replace the destination,
// and then the recorded family is the only surviving statement of that fact.
func routeAddressFamilyIsIPv4(r Route) (bool, bool) {
	if ip := net.ParseIP(r.Destination); ip != nil {
		return ip.To4() != nil, true
	}
	if r.Family != "" {
		return r.Family == "ipv4", true
	}
	return false, false
}
