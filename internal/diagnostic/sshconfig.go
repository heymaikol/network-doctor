package diagnostic

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// sshAliasRe keeps aliases that render safely inside the map's "ip (name)"
// format; ssh allows almost anything in a Host pattern, but a name with
// spaces or parens would corrupt the display and the parse behind it.
var sshAliasRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// SSHHostAliases maps IP literals from ~/.ssh/config HostName lines to their
// Host alias, the name the user actually calls the machine, which often
// exists in no DNS at all.
// Only the top-level file is read; an Include'd alias simply doesn't appear.
// The alias is decoration on a LAN map that already has the IP, so chasing
// includes (relative paths, globs, ~ expansion, cycles) buys a nicer label
// at the price of a second config parser.
func SSHHostAliases() map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	// #nosec G304 -- this intentionally reads the current user's fixed SSH config path.
	f, err := os.Open(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseSSHAliases(f)
}

// splitSSHConfigDirective parses one ssh_config line into a keyword and its
// arguments. OpenSSH accepts "Keyword value", "Keyword=value", and
// "Keyword = value" (optional whitespace around a single '=').
func splitSSHConfigDirective(line string) (keyword string, args []string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, false
	}
	i := 0
	for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
		i++
	}
	if i == 0 {
		return "", nil, false
	}
	keyword = line[:i]
	rest := strings.TrimSpace(line[i:])
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimSpace(rest[1:])
	}
	if rest == "" {
		return keyword, nil, true
	}
	return keyword, strings.Fields(rest), true
}

func parseSSHAliases(r io.Reader) map[string]string {
	names := make(map[string]string)
	var aliases []string
	// Read the whole config instead of scanning it; a bufio.Scanner gives up on
	// every later Host block once one line exceeds its buffer.
	// The 1 MiB cap keeps a pathological config from eating memory; a real
	// ssh config never comes close, so truncating past it is the intent.
	b, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	for _, line := range strings.Split(string(b), "\n") {
		keyword, args, ok := splitSSHConfigDirective(line)
		if !ok || len(args) == 0 {
			continue
		}
		switch strings.ToLower(keyword) {
		case "host":
			aliases = args
		case "hostname":
			// ssh honors only the first HostName per block; so do we,
			// even when it isn't an IP literal.
			blockAliases := aliases
			aliases = nil
			if net.ParseIP(args[0]) == nil {
				continue
			}
			for _, a := range blockAliases {
				if sshAliasRe.MatchString(a) {
					names[args[0]] = a
					break
				}
			}
		}
	}
	return names
}