package diagnostic

import (
	"maps"
	"strings"
	"testing"
)

func TestParseSSHAliases(t *testing.T) {
	// The overlong comment must not cost us the Host blocks behind it.
	config := "#" + strings.Repeat("a", 70<<10) + `
# comment
Host github.com
  HostName github.com
  User git

Host pihole
  HostName 192.168.1.1
  User pi

Host pi-nas backup-nas
	HostName 192.168.1.2

Host *.example !prod
  HostName 192.168.1.3

Host stray
  # HostName commented out

Host v6box
  HostName fd00::7

Host myserver
  HostName myserver.example.com
  HostName 10.0.0.5

Host equals-host
  HostName=10.0.0.10

Host=equals-host2
  HostName=10.0.0.11

Host = spaced-equals
  HostName = 10.0.0.12

HoSt MixedCase
  hOsTnAmE 10.0.0.13

Host mixed-seps
  HostName=10.0.0.14

Host=mixed-seps2
  HostName 10.0.0.15

Host = mixed-seps3
  HostName=10.0.0.16
`
	got := parseSSHAliases(strings.NewReader(config))
	want := map[string]string{
		"192.168.1.1": "pihole",
		"192.168.1.2": "pi-nas",
		"fd00::7":     "v6box",
		"10.0.0.10":   "equals-host",
		"10.0.0.11":   "equals-host2",
		"10.0.0.12":   "spaced-equals",
		"10.0.0.13":   "MixedCase",
		"10.0.0.14":   "mixed-seps",
		"10.0.0.15":   "mixed-seps2",
		"10.0.0.16":   "mixed-seps3",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("parseSSHAliases = %v, want %v (non-IP hostnames and pattern aliases skipped)", got, want)
	}
}

func TestSplitSSHConfigDirective(t *testing.T) {
	cases := []struct {
		line    string
		keyword string
		args    []string
		ok      bool
	}{
		{"", "", nil, false},
		{"# comment", "", nil, false},
		{"Host pihole", "Host", []string{"pihole"}, true},
		{"Host=pihole", "Host", []string{"pihole"}, true},
		{"Host = pihole", "Host", []string{"pihole"}, true},
		{"HostName 192.168.1.1", "HostName", []string{"192.168.1.1"}, true},
		{"HostName=192.168.1.1", "HostName", []string{"192.168.1.1"}, true},
		{"HostName = 192.168.1.1", "HostName", []string{"192.168.1.1"}, true},
		{"  HostName=192.168.1.1  ", "HostName", []string{"192.168.1.1"}, true},
		{"Host a b", "Host", []string{"a", "b"}, true},
		{"Host=a b", "Host", []string{"a", "b"}, true},
	}
	for _, tc := range cases {
		keyword, args, ok := splitSSHConfigDirective(tc.line)
		if ok != tc.ok || keyword != tc.keyword || !slicesEqual(args, tc.args) {
			t.Fatalf("splitSSHConfigDirective(%q) = (%q, %v, %v), want (%q, %v, %v)",
				tc.line, keyword, args, ok, tc.keyword, tc.args, tc.ok)
		}
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}