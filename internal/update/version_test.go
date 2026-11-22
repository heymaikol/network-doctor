package update

import "testing"

// A newer stable release is reported only when both sides are plain stable
// versions, and the comparison is numeric, not textual.
func TestNewer(t *testing.T) {
	cases := []struct {
		name, installed, latest string
		want                    bool
	}{
		{"patch newer", "2.2.1", "v2.2.2", true},
		{"minor newer", "2.2.1", "v2.3.0", true},
		{"major newer", "2.2.1", "v3.0.0", true},
		{"numeric not textual", "2.9.0", "v2.10.0", true},
		{"module form installed", "v2.2.1", "v2.3.0", true},
		{"equal", "2.2.1", "v2.2.1", false},
		{"installed ahead", "2.3.0", "v2.2.1", false},
		{"installed ahead by minor", "2.10.0", "v2.9.0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Newer(tc.installed, tc.latest); got != tc.want {
				t.Fatalf("Newer(%q, %q) = %v, want %v", tc.installed, tc.latest, got, tc.want)
			}
		})
	}
}

// Negative control: an installed build that is not a stable release is never
// told to upgrade, however new the latest release is.
func TestNewerRefusesUnknownInstalledBuilds(t *testing.T) {
	for _, installed := range []string{
		"dev",
		"(devel)",
		"",
		"v2.2.2-0.20261120012900-e88e9b22d6f3",
		"2.2.1+dirty",
		"2.3.0-rc.1",
		"2.2.1-1",
	} {
		if Newer(installed, "v9.9.9") {
			t.Errorf("Newer(%q, v9.9.9) = true; an unknown build must not be told to upgrade", installed)
		}
	}
}

// A release tag that is not a plain stable version is never a notice, so a
// prerelease, a malformed or hostile tag, or an out-of-range number cannot
// produce one.
func TestNewerRefusesUnstableLatest(t *testing.T) {
	for _, latest := range []string{
		"v2.3.0-rc.1",
		"v2.3",
		"2.3.0.0",
		"v02.3.0",
		"v2.3.0\n",
		"v2.3.0\u202e",
		"v2.3.0 ",
		"v99999999999999999999.0.0",
		"",
	} {
		if Newer("2.2.1", latest) {
			t.Errorf("Newer(2.2.1, %q) = true; the latest tag must be a plain stable version", latest)
		}
	}
}

// Positive control for the negative tests above: the same comparison that
// refuses bad input accepts a well-formed one.
func TestParseStableAcceptsBothReleaseForms(t *testing.T) {
	for _, s := range []string{"2.2.1", "v2.2.1"} {
		v, ok := ParseStable(s)
		if !ok || v != (Version{Major: 2, Minor: 2, Patch: 1}) {
			t.Errorf("ParseStable(%q) = %v, %v; want 2.2.1, true", s, v, ok)
		}
	}
}
