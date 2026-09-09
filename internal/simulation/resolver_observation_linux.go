//go:build linux

package simulation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

// Only the final test on each node is compared with final evidence. The name
// comes from the test input, never from Network Doctor's output or DNS rows.
func (e *netnsEnv) observeResolvers(ctx context.Context, out *Evidence) error {
	seen := map[string]bool{}
	for i := len(e.scenario.Tests) - 1; i >= 0; i-- {
		test := e.scenario.Tests[i]
		if seen[test.Node] {
			continue
		}
		seen[test.Node] = true
		// The holder's default source is not a test's explicitly bound source.
		if test.SourceSegment != "" {
			continue
		}
		name := "connectivitycheck.gstatic.com"
		if test.Target != "" {
			target, err := diagnostic.ParseTarget(test.Target)
			if err != nil || target.IP != nil {
				continue
			}
			name = target.Host
		}
		np := e.byName[test.Node]
		if np == nil {
			continue
		}
		for _, resolver := range []string{"system", "1.1.1.1"} {
			item, err := np.lookup(ctx, name, resolver)
			if err != nil {
				return fmt.Errorf("observe DNS from %s: %w", test.Node, err)
			}
			item.Node, item.Resolver = test.Node, resolver
			out.ResolverLookups = append(out.ResolverLookups, item)
		}
	}
	return nil
}

func (np *nodeProc) lookup(ctx context.Context, name, resolver string) (ResolverLookupEvidence, error) {
	np.mu.Lock()
	defer np.mu.Unlock()
	if np.stopped || np.stdin == nil || np.stdout == nil {
		return ResolverLookupEvidence{}, fmt.Errorf("node holder is not running")
	}
	request, _ := json.Marshal(struct{ Name, Resolver string }{name, resolver})
	if _, err := io.WriteString(np.stdin, "lookup "+string(request)+"\n"); err != nil {
		return ResolverLookupEvidence{}, err
	}
	reply, err := np.reply(ctx, "lookup-result")
	if err != nil {
		return ResolverLookupEvidence{}, err
	}
	var out ResolverLookupEvidence
	if err := json.Unmarshal([]byte(strings.TrimPrefix(reply, "lookup-result ")), &out); err != nil {
		return out, err
	}
	return out, nil
}
