package simulation

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// ResolverLookupEvidence is a client-side exchange, not a server's intention
// to answer. Stable means two bounded lookups returned the same complete result
// and the collected service history showed no outcome transition for that name.
// A failed lookup never proves name absence. NotFound requires the resolver's
// explicit negative answer, as classified by the standard Go resolver.
type ResolverLookupEvidence struct {
	Node      string   `json:"node"`
	Name      string   `json:"name"`
	Resolver  string   `json:"resolver"`
	State     string   `json:"state"`
	Addresses []string `json:"addresses,omitempty"`
	Stable    bool     `json:"stable"`
}

const lookupNotFound = "not_found"
const lookupFailed = "failed"
const lookupAnswered = "answered"
const lookupLocal = "local_answer"

func resolverHistoryStable(queries []DNSQueryEvidence, name string) bool {
	outcomes := map[string]string{}
	for _, query := range queries {
		if dnsKey(query.Name) != dnsKey(name) {
			continue
		}
		key := query.Node + "\x00" + query.Service + "\x00" + query.QueryType
		if previous, ok := outcomes[key]; ok && previous != query.ActualOutcome {
			return false
		}
		outcomes[key] = query.ActualOutcome
	}
	return true
}

func observeResolver(ctx context.Context, name, server string) ResolverLookupEvidence {
	out := ResolverLookupEvidence{Name: dnsKey(name), State: lookupFailed}
	resolver := &net.Resolver{PreferGo: true}
	if server != "" {
		resolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// Combined LookupIPAddr can return NXDOMAIN when one family was negative
	// and the other failed, even with StrictErrors. Ask each family separately:
	// either positive answer resolves the name; only two negatives prove absence.
	var results [2]struct {
		addresses []net.IP
		err       error
	}
	var wg sync.WaitGroup
	for i, family := range []string{"ip4", "ip6"} {
		wg.Go(func() { results[i].addresses, results[i].err = resolver.LookupIP(ctx, family, name) })
	}
	wg.Wait()
	negative := true
	for _, result := range results {
		var dnsErr *net.DNSError
		if !errors.As(result.err, &dnsErr) || !dnsErr.IsNotFound || dnsErr.IsTimeout || dnsErr.IsTemporary {
			negative = false
		}
		for _, address := range result.addresses {
			if ip, ok := netip.AddrFromSlice(address); ok {
				out.Addresses = append(out.Addresses, ip.Unmap().String())
			}
		}
	}
	if negative {
		out.State = lookupNotFound
	}
	if server != "" && len(out.Addresses) > 0 {
		// A custom Dial does not bypass /etc/hosts. Prove that these answers
		// required DNS; otherwise this is not an independent resolver opinion.
		local := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("simulator DNS disabled for local-answer check")
		}}
		if ips, localErr := local.LookupIPAddr(context.WithoutCancel(ctx), name); localErr == nil && len(ips) > 0 {
			out.State = lookupLocal
			out.Addresses = nil
			return out
		}
	}
	slices.Sort(out.Addresses)
	out.Addresses = slices.Compact(out.Addresses)
	if len(out.Addresses) > 0 {
		out.State = lookupAnswered
	}
	return out
}

// This private holder request accepts a DNS name and either "system" or a
// literal resolver address. It cannot execute a command or choose a timeout.
func holderLookupReply(raw string) string {
	var request struct{ Name, Resolver string }
	if len(raw) > 1024 || json.Unmarshal([]byte(raw), &request) != nil || len(request.Name) == 0 || len(request.Name) > 253 || strings.ContainsAny(request.Name, " \r\n\t") {
		return "lookup-result error"
	}
	server := ""
	if request.Resolver != "system" {
		addr, err := netip.ParseAddr(request.Resolver)
		if err != nil || addr.Zone() != "" {
			return "lookup-result error"
		}
		server = net.JoinHostPort(addr.String(), "53")
	}
	first := observeResolver(context.Background(), request.Name, server)
	second := observeResolver(context.Background(), request.Name, server)
	first.Stable = first.State == second.State && slices.Equal(first.Addresses, second.Addresses)
	data, _ := json.Marshal(first)
	return "lookup-result " + string(data)
}
