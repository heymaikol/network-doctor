package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// stubVerifyStdin feeds readVerifySecret a fixed standard input, as a pipe would, and
// reports that standard input is not a terminal.
func stubVerifyStdin(t *testing.T, input string) {
	t.Helper()
	savedStdin, savedTTY := verifyStdin, verifyIsTTY
	t.Cleanup(func() { verifyStdin, verifyIsTTY = savedStdin, savedTTY })
	verifyStdin = strings.NewReader(input)
	verifyIsTTY = func() bool { return false }
}

// -password-stdin takes one line. A line that is longer than the limit, or that has
// text after a carriage return inside it, is refused whole. It is never cut short to
// fit, so no truncated password can reach an authentication attempt.
func TestPasswordStdinRefusesOversizedAndTruncatedLines(t *testing.T) {
	max := strings.Repeat("a", maxSecretLen)
	cases := []struct {
		name    string
		input   string
		want    string
		refused bool
	}{
		{"longest line with LF", max + "\n", max, false},
		{"longest line with CRLF", max + "\r\n", max, false},
		{"short line with CRLF", "pw\r\n", "pw", false},
		{"one byte past the limit", max + "a\n", "", true},
		{"carriage return then text, then LF", max + "\rtail\n", "", true},
		{"carriage return then text, at end of input", max + "\rtail", "", true},
		{"carriage return then a second carriage return", max + "\r\r\n", "", true},
		{"no line end, far past the limit", strings.Repeat("a", 5*maxSecretLen), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubVerifyStdin(t, tc.input)
			got, err := readVerifySecret(context.Background(), io.Discard, "Password: ", true)
			if tc.refused {
				if err == nil {
					t.Fatalf("accepted %d bytes; a refused line must not reach an attempt", len(got))
				}
				if len(got) != 0 {
					t.Fatalf("a refused line still returned %d bytes", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a valid line: %v", err)
			}
			if !bytes.Equal(got, []byte(tc.want)) {
				t.Fatalf("read %d bytes, want %d", len(got), len(tc.want))
			}
		})
	}
}
