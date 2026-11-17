package sshverify

import (
	"strings"
	"testing"
)

const testReading = "debug1: Reading configuration data /etc/ssh/ssh_config\n"
const testExec = "debug1: Executing command: 'true'\n"

// The classifier accepts a read only when the client reported its configuration
// reads and no Match exec test ran. Anything else is refused, and nothing is sent.
func TestDiagnosticsAcceptOnlyAReadWithNoExec(t *testing.T) {
	cases := []struct {
		name string
		diag string
		ok   bool
		want string
	}{
		{"reads reported, no exec", testReading, true, ""},
		{"no reading marker", "debug1: something else\n", false, "not in a form netdoc recognizes"},
		{"empty diagnostics", "", false, "not in a form netdoc recognizes"},
		{"an exec ran", testReading + testExec, false, "a Match exec command runs in it"},
		{"an exec ran after a long prefix", testReading + strings.Repeat("debug2: x\n", 1000) + testExec, false, "a Match exec command runs in it"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkDiagnostics([]byte(c.diag))
			if c.ok {
				if err != nil {
					t.Fatalf("a clean read was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal containing %q", err, c.want)
			}
		})
	}
}

// The debug lines are stripped only from failure text; the classifier still sees
// them, so a Match exec is found even in a failed run's diagnostics.
func TestWithoutDebugLinesKeepsTheRealMessage(t *testing.T) {
	got := string(withoutDebugLines([]byte(testReading + "Bad configuration option: nope\n" + testExec)))
	if strings.Contains(got, "debug") || !strings.Contains(got, "Bad configuration option") {
		t.Fatalf("the failure text was %q; want only the real message", got)
	}
}
