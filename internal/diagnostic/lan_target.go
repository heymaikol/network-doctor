package diagnostic

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// forTarget isolates the target's socket operations from DNS and reference
// probes, which continue to use the run's configured sources.
func (o *netops) forTarget(t *Target) (*netops, func(Probe) Probe) {
	if t.lanBinding == nil {
		return o, func(p Probe) Probe { return p }
	}
	binding := *t.lanBinding
	ip, _ := netip.AddrFromSlice(t.IP)
	peer := ip.Unmap()
	validate := func() (lanLink, error) {
		return binding.serviceLink(peer, o.interfaces, o.interfaceAddrs)
	}
	target := *o
	target.lanBinding = &binding
	// A route lookup for an ordinary socket can report the competing link.
	target.routes = nil
	target.dialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		endpoint, err := netip.ParseAddrPort(addr)
		if err != nil || endpoint.Addr() != peer || (network != "tcp" && network != "tcp4") {
			return nil, fmt.Errorf("%w: LAN snapshot only permits TCP to %s", errLANUnavailable, peer)
		}
		link, err := validate()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errLANUnavailable, err)
		}
		conn, err := o.dialLAN(ctx, link, addr)
		if lanDialUnavailable(err) {
			return nil, fmt.Errorf("LAN snapshot interface %q: %w: %w", binding.Interface, errLANUnavailable, err)
		}
		if err != nil {
			return nil, err
		}
		if src, ok := conn.LocalAddr().(*net.TCPAddr); !ok || !src.IP.Equal(binding.Source.AsSlice()) {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: socket did not use LAN snapshot source %s", errLANUnavailable, binding.Source)
		}
		return conn, nil
	}
	target.dialTLS = dialTLSWith(target.dialContext)
	return &target, func(p Probe) Probe {
		run, link := p.Run, p.link
		p.fresh = true // Watch must revalidate before publishing target evidence.
		p.Run = func(ctx context.Context, deps map[ProbeID]ProbeResult) ProbeResult {
			// A shared TCP or TLS socket also needs a current snapshot binding.
			if _, err := validate(); err != nil {
				link.release()
				return lanTargetFailure(err)
			}
			result := run(ctx, deps)
			if _, err := validate(); err != nil {
				link.release()
				return lanTargetFailure(err)
			}
			return result
		}
		return p
	}
}

func lanTargetFailure(err error) ProbeResult {
	return ProbeResult{Status: StatusFail, Cause: ConnectionCauseLANBinding, Detail: err.Error(), Fix: "rescan the LAN and select the service again"}
}
