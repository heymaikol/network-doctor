//go:build darwin

package diagnostic

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Absolute so a PATH entry ahead of /usr/bin can't stand in for the system
// browser: this runs against whatever the LAN says, with no privileges to lose
// but a terminal to write to.
const dnssdPath = "/usr/bin/dns-sd"

var dnssdCommand = func(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, dnssdPath, args...)
}

const maxDNSSDOutput = 1 << 18

type cappedDNSSDOutput []byte

// Write stores up to maxDNSSDOutput bytes while consuming the full write.
func (out *cappedDNSSDOutput) Write(p []byte) (int, error) {
	*out = append(*out, p[:min(len(p), maxDNSSDOutput-len(*out))]...)
	return len(p), nil
}

// dnssdTypes are the service types worth asking about. dns-sd browses one type
// per process, since there is no --all, so this is a fixed list rather than a
// `_services._dns-sd._udp` enumeration: these are the types that carry a label
// a person would recognize, and the rest cost a process to learn nothing.
var dnssdTypes = []string{
	"_googlecast._tcp",
	"_airplay._tcp",
	"_raop._tcp",
	"_companion-link._tcp",
	"_device-info._tcp",
	"_hap._tcp",
	"_ipp._tcp",
	"_printer._tcp",
	"_smb._tcp",
	"_ssh._tcp",
}

// AdvertisedNames returns the device names advertised through the platform's
// DNS-SD browser, keyed by IP. They win over reverse DNS because they are
// usually the user-facing label configured on the device, so callers should
// ask here first and only fall back to ReverseName for what's left, keeping a
// row's first name its final one.
//
// dns-sd prints no addresses, so each instance's SRV target has to be resolved
// back to an IP through the system resolver, which answers .local off
// mDNSResponder.
func AdvertisedNames(ctx context.Context, ips []string) map[string]string {
	if _, err := os.Stat(dnssdPath); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// dns-sd stops itself at -t and flushes on the way out; this context is the
	// backstop for a process that somehow doesn't, and it has to outlast -t or
	// every browse dies holding its results.
	browseCtx, cancelBrowse := context.WithTimeout(ctx, 5*time.Second)
	defer cancelBrowse()

	outs := make([][]byte, len(dnssdTypes))
	var wg sync.WaitGroup
	for i, svc := range dnssdTypes {
		wg.Go(func() { outs[i] = browseZone(browseCtx, svc) })
	}
	wg.Wait()

	var entries []zoneEntry
	for _, out := range outs {
		entries = append(entries, parseDNSSDZone(out)...)
	}

	addrs := resolveTargets(ctx, entries)
	wanted := make(map[string]bool, len(ips))
	for _, ip := range ips {
		wanted[ip] = true
	}

	best := bestNames{}
	for _, entry := range entries {
		host := strings.TrimSuffix(strings.TrimSuffix(unescapeDNS(entry.host), "."), ".local")
		name, score := nameCandidate(host, entry.instance, entry.svc, entry.txt)
		for _, addr := range addrs[entry.host] {
			if wanted[addr] {
				best.put(addr, name, score)
			}
		}
	}
	return best.plain()
}

// resolveTargets maps each distinct SRV target to its addresses. The target
// count comes from the LAN, not from us, and an office or a hotel advertises
// hundreds of instances, so lookups queue behind a fixed number of in-flight
// queries rather than arriving at mDNSResponder all at once. The outer context
// still bounds the queue: targets that never get a turn resolve to nothing,
// which is what an unresolvable target would have yielded anyway.
func resolveTargets(ctx context.Context, entries []zoneEntry) map[string][]string {
	addrs := make(map[string][]string, len(entries))
	seen := make(map[string]bool, len(entries))
	sem := make(chan struct{}, 16)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, entry := range entries {
		if seen[entry.host] {
			continue
		}
		seen[entry.host] = true
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			// Timed from the turn, not from the queue, so a deep queue doesn't
			// hand the last targets a timeout that has already run out.
			lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			found, err := net.DefaultResolver.LookupHost(lctx, entry.host)
			if err != nil {
				return
			}
			mu.Lock()
			addrs[entry.host] = found
			mu.Unlock()
		})
	}
	wg.Wait()
	return addrs
}

// browseZone returns the bounded DNS-SD zone output for svc.
func browseZone(ctx context.Context, svc string) []byte {
	cmd := dnssdCommand(ctx, "-t", "3", "-Z", svc, "local.")
	cmd.WaitDelay = time.Second // don't hang on Wait if a child holds the pipe
	var out cappedDNSSDOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil
	}
	return out
}
