// Package update decides whether a newer stable Network Doctor release exists.
// It imports only the standard library, and nothing in it touches the network
// until the fetch added alongside it.
package update

import (
	"strconv"
	"strings"
)

// Version is a stable release: MAJOR.MINOR.PATCH with no suffix.
type Version struct {
	Major, Minor, Patch int
}

// ParseStable reads a stable version in either form netdoc reports or the
// release tags carry: "2.2.1" from a release binary, "v2.2.1" from a module
// build and from the GitHub tag. Anything else is not a stable release and
// reports false: development builds ("dev", "(devel)"), pseudo-versions such as
// "v2.2.2-0.20261120012900-e88e9b22d6f3", prereleases, build metadata such as
// "+dirty", leading zeros, signs, spaces, and control or bidi characters.
func ParseStable(s string) (Version, bool) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var n [3]int
	for i, p := range parts {
		v, ok := canonicalNumber(p)
		if !ok {
			return Version{}, false
		}
		n[i] = v
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2]}, true
}

// canonicalNumber accepts only plain decimal digits without leading zeros.
// strconv.Atoi refuses values that overflow an int.
func canonicalNumber(p string) (int, bool) {
	if p == "" || (len(p) > 1 && p[0] == '0') {
		return 0, false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(p)
	return v, err == nil
}

// Newer reports whether latest is a stable release strictly newer than
// installed. If either side is not a stable version, it reports false, so an
// unknown build is never told to upgrade.
func Newer(installed, latest string) bool {
	a, okA := ParseStable(installed)
	b, okB := ParseStable(latest)
	return okA && okB && a.less(b)
}

func (a Version) less(b Version) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor < b.Minor
	}
	return a.Patch < b.Patch
}
