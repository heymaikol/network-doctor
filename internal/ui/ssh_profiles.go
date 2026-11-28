package ui

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// listSSHHostProfiles suggests only literal Host aliases from the user's main
// SSH config. It never evaluates Include, Match exec, or SSH configuration.
// The installed OpenSSH client resolves the chosen alias when the user selects
// it. An alias is a suggestion, never evidence that a LAN device is trusted.
func listSSHHostProfiles(ctx context.Context) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	f, err := openSSHProfileConfig(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(b) > 1<<20 || ctx.Err() != nil {
		return nil
	}
	return parseSSHHostProfiles(string(b))
}

func parseSSHHostProfiles(config string) []string {
	var profiles []string
	seen := map[string]bool{}
	for line := range strings.SplitSeq(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		separator := strings.IndexAny(line, " \t=")
		if separator < 0 || !strings.EqualFold(line[:separator], "Host") {
			continue
		}
		value := strings.TrimSpace(line[separator:])
		value = strings.TrimSpace(strings.TrimPrefix(value, "="))
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		for _, alias := range fields {
			// A wildcard, negation or quoted pattern is not a selectable host.
			if strings.ContainsAny(alias, "*?!\"'\\") || strings.HasPrefix(alias, "-") {
				continue
			}
			key := strings.ToLower(alias)
			if !seen[key] && len(profiles) < 64 {
				profiles = append(profiles, alias)
				seen[key] = true
			}
		}
	}
	return profiles
}
