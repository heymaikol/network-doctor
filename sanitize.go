package main

import (
	"regexp"
	"strings"
	"unicode"
)

// escapeRe matches the escape sequences we strip from untrusted text:
// CSI (ESC [ ... final), OSC (ESC ] ... BEL|ST), and any other two-byte
// ESC sequence. Ordered CSI/OSC first so the generic 2-byte form can't swallow
// a CSI/OSC introducer.
var escapeRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]`)

// sanitize strips ANSI/OSC/CSI escape sequences and control runes from text that
// originates from external tools or remote servers (banners, error strings), so
// a hostile peer can't drive the terminal. Tabs become spaces; everything else
// in the control range (incl. lone ESC, C1, newlines) and invalid UTF-8 is
// dropped. ponytail: single-line oriented — keep newlines too when multi-line
// tool output lands in Phase 2.
func sanitize(s string) string {
	s = escapeRe.ReplaceAllString(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case r == unicode.ReplacementChar: // invalid UTF-8 decoded byte
			return -1
		case unicode.IsControl(r): // C0 + C1, incl. ESC and \n
			return -1
		default:
			return r
		}
	}, s)
}
