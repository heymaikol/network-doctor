package app

import (
	"errors"
	"flag"
	"strings"

	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

type probeList []diagnostic.ProbeID

func (p *probeList) String() string {
	ids := make([]string, len(*p))
	for i, id := range *p {
		ids[i] = string(id)
	}
	return strings.Join(ids, ",")
}

func (p *probeList) Set(value string) error {
	ids := strings.Split(value, ",")
	for _, id := range ids {
		if id == "" {
			return errors.New("empty probe ID")
		}
	}
	for _, id := range ids {
		*p = append(*p, diagnostic.ProbeID(id))
	}
	return nil
}

func (p probeList) set() map[diagnostic.ProbeID]struct{} {
	if len(p) == 0 {
		return nil
	}
	set := make(map[diagnostic.ProbeID]struct{}, len(p))
	for _, id := range p {
		set[id] = struct{}{}
	}
	return set
}

func (p probeList) strings() []string {
	ids := make([]string, len(p))
	for i, id := range p {
		ids[i] = string(id)
	}
	return ids
}

// setFlagNames is the set of flags the user actually spelled out, which is how
// a mode rejects a combination without mistaking a flag's default for a
// request. fs.Visit walks only the ones that were set.
func setFlagNames(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}
