//go:build linux

package diagnostic

import "testing"

func TestParseESSID(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		n    int
		want string
	}{
		{"plain", []byte("HomeWiFi\x00\x00"), 8, "HomeWiFi"},
		{"trailing NUL counted", []byte("Net\x00"), 4, "Net"},
		{"empty", []byte("\x00\x00"), 0, ""},
		{"n over len clamps", []byte("AB"), 99, "AB"},
		{"negative n", []byte("AB"), -1, ""},
		{"strips ANSI", []byte("a\x1b[31mEVIL"), 10, "aEVIL"},
	}
	for _, c := range cases {
		if got := parseESSID(c.buf, c.n); got != c.want {
			t.Errorf("%s: parseESSID(%q,%d)=%q want %q", c.name, c.buf, c.n, got, c.want)
		}
	}
}
