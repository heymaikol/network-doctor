package main

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func noControl(t *testing.T, in, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("sanitize(%q) produced invalid UTF-8: %q", in, out)
	}
	for _, r := range out {
		if r != ' ' && unicode.IsControl(r) {
			t.Errorf("sanitize(%q) left control rune %U in %q", in, r, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("sanitize(%q) left ESC: %q", in, out)
	}
}

func TestSanitize(t *testing.T) {
	cases := []string{
		"\x1b[31mred\x1b[0m",
		"\x1b]0;title\x07evil",
		"plain\x00\x07\x1bbad",
		"line1\nline2",
		"\x1b[2J\x1b[H",
		"tab\there",
		"\x9b31m raw c1 byte",
		"\xff\xfe invalid utf8",
	}
	for _, in := range cases {
		noControl(t, in, sanitize(in))
	}
	if got := sanitize("\x1b[31mhello\x1b[0m"); got != "hello" {
		t.Errorf("escape strip = %q, want %q", got, "hello")
	}
}

func FuzzSanitize(f *testing.F) {
	for _, s := range []string{"\x1b[31mhi\x1b[0m", "\x1b]0;x\x07", "\xff\xfe", "ok"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		noControl(t, s, sanitize(s))
	})
}
