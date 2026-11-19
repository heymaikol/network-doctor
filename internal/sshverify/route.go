package sshverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/heymaikol/network-doctor/v2/internal/textsafe"
)

// RouteKind is what a configuration read established about the route to a
// destination. Only RouteDirect lets a headless run connect without a proxy.
type RouteKind int

const (
	// RouteUnknown means the read cannot establish the route. Route.Reason says why,
	// and the caller must not connect by any route it would have to guess.
	RouteUnknown RouteKind = iota
	// RouteDirect means the read establishes a route with no proxy, and no configured
	// command decides trust or the route.
	RouteDirect
	// RouteProxied means the read names a proxy, ProxyJump or ProxyCommand, and it is
	// not none. A headless run never uses it.
	RouteProxied
)

func (k RouteKind) String() string {
	switch k {
	case RouteDirect:
		return "direct"
	case RouteProxied:
		return "proxied"
	}
	return "unknown"
}

// Route is the typed result of reading a destination's configuration.
type Route struct {
	Kind   RouteKind
	Reason string // for RouteUnknown: the first rule that refused the read
	// Listing is the complete `ssh -G` output the read produced. It is set for
	// RouteDirect and RouteProxied, and for RouteUnknown when the read completed.
	Listing []byte
}

// ReadRoute reads the configuration for the destination in args and classifies the
// route. An error means the read did not happen or did not complete, and nothing was
// sent. Unknown is a completed read whose configuration netdoc cannot match to the
// user's own ssh, and it is returned as a Route, not an error.
//
// The read runs twice. A file or the listing that differs between the two runs makes
// the route unknown, so a configuration changed mid-read is not classified from a mix
// of its two states. The contents classified are the bytes that were read.
func ReadRoute(ctx context.Context, program string, args []string) (Route, error) {
	if !configPlatformSupported {
		return Route{}, unsupportedPlatform()
	}
	if err := canaryCheck(ctx, program); err != nil {
		return Route{}, err
	}
	first, err := captureConfig(ctx, program, args)
	if err != nil {
		return Route{}, err
	}
	second, err := captureConfig(ctx, program, args)
	if err != nil {
		return Route{}, err
	}
	if !first.same(second) {
		return Route{Kind: RouteUnknown, Reason: "the SSH configuration changed while netdoc read it, so no route is established; nothing was sent"}, nil
	}
	return classify(first, !TerminalAvailable()), nil
}

func unsupportedPlatform() error {
	return fmt.Errorf("SSH credential verification is not supported on %s in this build: netdoc cannot yet read the SSH configuration there safely; nothing was sent", runtime.GOOS)
}

// capture is one complete read: the listing, the files it names, and their contents.
type capture struct {
	listing  []byte
	diag     []byte
	files    []string
	contents [][]byte
}

// captureConfig runs the client with -v and returns the complete listing and the
// contents of every configuration file the diagnostic output names. A read whose
// diagnostic output does not show the configuration reads netdoc recognizes is an
// error, because netdoc cannot then say which files were read.
func captureConfig(ctx context.Context, program string, args []string) (capture, error) {
	out, diag, err := readConfig(ctx, program, append([]string{"-v"}, args...), nil)
	if err != nil {
		return capture{}, err
	}
	if !bytes.Contains(diag, []byte(readingMarker)) {
		return capture{}, errors.New("the SSH client's diagnostic output is not in a form netdoc recognizes, so it cannot check which configuration rules ran; nothing was sent")
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		return capture{}, errors.New("the SSH configuration output was incomplete")
	}
	files := readingFiles(diag)
	contents := make([][]byte, len(files))
	for i, f := range files {
		data, err := readConfigFile(f)
		if err != nil {
			return capture{}, fmt.Errorf("the configuration file %s could not be read as a regular file, so no route is established; nothing was sent", textsafe.Clean(f))
		}
		contents[i] = data
	}
	return capture{listing: out, diag: diag, files: files, contents: contents}, nil
}

// readConfigFile returns the bytes of one configuration file the client named. Only a
// regular file is read, and it is read up to the bound: a FIFO, a device such as
// /dev/stdin, or a directory would block the read or consume input, and ssh would not
// have read a configuration from it. The check is by stat before the open, so a file
// that is not regular is never opened.
func readConfigFile(name string) ([]byte, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := os.Open(name) // #nosec G304 -- a configuration file the client named in its diagnostic output, checked as regular above
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("larger than netdoc reads")
	}
	return data, nil
}

// same reports whether two reads saw the same listing, the same files and the same
// bytes in each file.
func (c capture) same(o capture) bool {
	if !bytes.Equal(c.listing, o.listing) || len(c.files) != len(o.files) {
		return false
	}
	for i := range c.files {
		if c.files[i] != o.files[i] || !bytes.Equal(c.contents[i], o.contents[i]) {
			return false
		}
	}
	return true
}

// readingFiles returns the configuration files named by the Reading lines, in order
// and without repeats. OpenSSH prints some of these lines twice in the default read.
func readingFiles(diag []byte) []string {
	seen := map[string]bool{}
	var files []string
	for _, line := range strings.Split(string(diag), "\n") {
		i := strings.Index(line, readingMarker)
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[i+len(readingMarker):])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		files = append(files, name)
	}
	return files
}

// classify turns one complete read into a route. The rules are checked in order and
// the first that refuses names the reason. headless is true when netdoc has no
// terminal of its own, which selects the stricter $ rule.
func classify(c capture, headless bool) Route {
	unknown := func(reason string) Route {
		return Route{Kind: RouteUnknown, Reason: reason, Listing: c.listing}
	}
	if bytes.Contains(c.diag, []byte(execMarker)) {
		return unknown("a Match exec command runs in the configuration; its answer depends on the environment, which netdoc cannot reproduce")
	}
	for i, body := range c.contents {
		if reason := scanFile(body, headless); reason != "" {
			return unknown(fmt.Sprintf("%s (in %s)", reason, textsafe.Clean(c.files[i])))
		}
	}
	if value, set := listingValue(c.listing, "canonicalizehostname"); !set || value != "false" {
		// Canonicalization re-reads the configuration under the canonical name, so the
		// Host blocks that apply can change after resolution. A name resolved in another
		// environment can then give another route, so it is not known here.
		return unknown("CanonicalizeHostname is on, or the listing does not report it, so the Host blocks that apply may change after the name is resolved")
	}
	if _, set := listingValue(c.listing, "hostname"); !set {
		// Every client that reads -G prints hostname. Its absence means the listing is
		// not one netdoc can match, so silence is an unanswered question, not a route.
		return unknown("the configuration listing has no hostname line")
	}
	if value, set := listingValue(c.listing, "knownhostscommand"); set && value != "none" {
		return unknown("KnownHostsCommand is set: it decides host-key trust when a connection is made, and netdoc does not run it")
	}
	if value, set := listingValue(c.listing, "proxyjump"); set && value != "none" {
		return Route{Kind: RouteProxied, Listing: c.listing}
	}
	if value, set := listingValue(c.listing, "proxycommand"); set && value != "none" {
		return Route{Kind: RouteProxied, Listing: c.listing}
	}
	return Route{Kind: RouteDirect, Listing: c.listing}
}

// literalOnTerminal are the keywords whose value a variable does not change, on the
// installed client (measured on OpenSSH 10.5p1, and checked at run time by the canary's
// environment probe). A terminal run may keep a $ on these keywords. Every other $ is
// refused, so a keyword that is not on this list fails closed.
var literalOnTerminal = map[string]bool{"hostname": true, "host": true, "identityfile": true}

// scanFile checks one configuration file's text the way ssh reads it, line by line.
// Full-line comments are skipped, because ssh does not parse them. It returns the
// reason to refuse, or "" when nothing in the file refuses the read.
//
// The Match rule is a substring rule on purpose: exec anywhere after the keyword
// refuses, so quoted, negated, canonical and "=" forms are all covered. A
// `Match host "exec"` is refused too, which is a false refusal that is accepted.
//
// The $ rule. ssh expands environment variables in keywords that choose a host, an
// account, a trust file or an agent, and the expansion depends on the environment the
// client runs in. A headless run has an environment netdoc cannot match to the user's,
// so it refuses every $ outside a comment. A terminal run uses the user's environment
// when netdoc was started from the user's shell, so it refuses a $ only where the
// keyword is not measured as literal: an Include, a Match, and any keyword that is not
// on literalOnTerminal. That is the narrowed rule, and it fails closed for a keyword
// it has not measured.
func scanFile(text []byte, headless bool) string {
	for _, raw := range strings.Split(string(text), "\n") {
		// OpenSSH splits a line on a carriage return as well as on a space or a tab, so
		// "Match\rcommand" is a Match directive to ssh. Read the same way here.
		line := strings.TrimLeft(strings.ReplaceAll(raw, "\r", " "), " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		// A quote before any blank or '=' is part of the keyword. ssh removes the quotes by a rule
		// that joins the text around them, so "Match", Ma"tch" and "Match"command all name Match,
		// and the Match checks below would miss them. netdoc does not model that rule, so the line
		// is refused rather than classified. A quoted argument is not affected.
		if q := strings.IndexByte(line, '"'); q >= 0 && !strings.ContainsAny(line[:q], " \t=") {
			return "a keyword is quoted, so netdoc cannot show how ssh reads the line"
		}
		kw := keywordOf(line)
		if strings.Contains(line, "$") {
			switch {
			case headless:
				return "a directive uses an environment variable, which a headless run cannot match"
			case kw == "include":
				return "an Include uses an environment variable, so netdoc cannot show which file ssh reads"
			case !literalOnTerminal[kw]:
				return "a directive uses an environment variable whose value can change the route, account, identity, trust or agent, and netdoc cannot show that value"
			}
		}
		if kw == "match" && strings.Contains(strings.ToLower(line[len(kw):]), "exec") {
			return "a Match exec test"
		}
		if kw == "match" && !matchCriteriaKnown(strings.TrimLeft(line[len(kw):], "= \t")) {
			return "a Match criterion is decided by the connection, such as the remote command, which the read does not evaluate"
		}
	}
	return ""
}

// Match criteria whose answer comes from the configuration alone. The route read runs
// ssh -G with no remote command and no session, so these criteria give a connection the
// same answer the read gave. Any other criterion, such as command, sessiontype,
// localnetwork or tagged, depends on the connection, and a proxy it selects would be
// missed. A criterion that is not on either list is refused, so the list fails closed.
var (
	matchCriteriaAlone     = map[string]bool{"all": true, "canonical": true, "final": true}
	matchCriteriaWithValue = map[string]bool{"host": true, "originalhost": true, "user": true, "localuser": true}
)

// matchCriteriaKnown reports whether every criterion on a Match line, after its keyword,
// is one of the known ones. A value that is not a criterion makes the line unknown.
func matchCriteriaKnown(rest string) bool {
	fields := strings.Fields(rest)
	for i := 0; i < len(fields); i++ {
		name := strings.ToLower(strings.TrimPrefix(strings.Trim(fields[i], "\"'"), "!"))
		switch {
		case matchCriteriaAlone[name]:
		case matchCriteriaWithValue[name]:
			i++
		default:
			return false
		}
	}
	return true
}

// keywordOf returns the keyword at the start of a configuration line, lower-cased.
// ssh ends a keyword at white space or '='.
func keywordOf(line string) string {
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		end = len(line)
	}
	return strings.ToLower(line[:end])
}

// listingValue returns the value the listing gives a keyword, and whether it is there.
// The listing carries one line per keyword, the effective value, so a none written in
// any form is absent or the word none.
// Endpoint returns the host name and port the configuration resolved dest to, as the read
// reported them. Both are empty when the listing does not report them.
func (r Route) Endpoint() (host, port string) {
	host, _ = listingValue(r.Listing, "hostname")
	port, _ = listingValue(r.Listing, "port")
	return host, port
}

func listingValue(listing []byte, key string) (string, bool) {
	for _, line := range strings.Split(string(listing), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), " ")
		if ok && strings.ToLower(k) == key {
			return strings.ToLower(strings.TrimSpace(v)), true
		}
	}
	return "", false
}
