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

// trimOneLineEnd removes an LF, and a CR only when it directly precedes that LF. Every other CR is
// part of the secret, so no input is turned into a different secret.
func TestTrimOneLineEndRemovesACROnlyBeforeAnLF(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"CRLF", "pw\r\n", "pw"},
		{"LF", "pw\n", "pw"},
		{"CR at end of input, no LF", "pw\r", "pw\r"},
		{"no line end at all", "pw", "pw"},
		{"CR inside the secret, LF end", "a\rb\n", "a\rb"},
		{"CR inside the secret, end of input", "a\rb", "a\rb"},
		{"CR before the LF, and one before that", "pw\r\r\n", "pw\r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(trimOneLineEnd([]byte(tc.in))); got != tc.want {
				t.Fatalf("trimOneLineEnd(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A password whose input ends in a CR with no LF keeps that CR, so the credential sent is the one typed.
// At the length limit, the same CR makes the secret one byte too long, and it is refused, not truncated.
func TestPasswordStdinKeepsACRAtEndOfInput(t *testing.T) {
	stubVerifyStdin(t, "pw\r")
	got, err := readVerifySecret(context.Background(), io.Discard, "Password: ", true)
	if err != nil {
		t.Fatalf("refused a password that ends in CR: %v", err)
	}
	if !bytes.Equal(got, []byte("pw\r")) {
		t.Fatalf("sent %q, want the typed %q", got, "pw\r")
	}

	stubVerifyStdin(t, strings.Repeat("a", maxSecretLen)+"\r")
	got, err = readVerifySecret(context.Background(), io.Discard, "Password: ", true)
	if err == nil {
		t.Fatalf("accepted %d bytes; a secret with a trailing CR at the limit must be refused, not truncated", len(got))
	}
	if len(got) != 0 {
		t.Fatalf("a refused secret still returned %d bytes", len(got))
	}
}
