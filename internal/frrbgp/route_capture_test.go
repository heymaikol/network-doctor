package frrbgp

import (
	"reflect"
	"strings"
	"testing"
)

// routeTranscript frames body the way FRR's VTY prints a route table: the echo,
// the body, and the prompt, each line ending in CRLF, with nothing after the
// prompt. The body is given as FRR prints it, so a space after its brace is kept.
func routeTranscript(node, body string) []byte {
	body = strings.ReplaceAll(body, "\n", "\r\n")
	return []byte(CommandRoute + "\r\n" + body + "\r\n" + node + "> ")
}

// TestRouteCaptureReadsTheCommittedTables checks that the framed decoder reads each
// genuine table to the same value as the body decoder.
func TestRouteCaptureReadsTheCommittedTables(t *testing.T) {
	for _, node := range []string{"r1", "r2"} {
		raw, body := routeCapture(t, node)
		framed, err := DecodeRouteCapture(raw, node)
		if err != nil {
			t.Fatalf("%s: %v", node, err)
		}
		plain, err := DecodeRouteTable(body)
		if err != nil {
			t.Fatalf("%s body: %v", node, err)
		}
		if !reflect.DeepEqual(framed, plain) {
			t.Errorf("%s: framed decode %+v differs from body decode %+v", node, framed, plain)
		}
	}
}

// TestRouteCaptureFraming checks the framing the route decoder shares with the summary
// decoder, and the one allowance it adds: spaces between the table's closing brace and
// the CRLF before the prompt.
func TestRouteCaptureFraming(t *testing.T) {
	const table = `{"routes":{}}`
	tests := []struct {
		name string
		node string
		data []byte
		want string // empty means the capture must decode
	}{
		{"FRR's trailing space", "r1", routeTranscript("r1", table+" "), ""},
		{"no trailing space", "r1", routeTranscript("r1", table), ""},
		{"two trailing spaces", "r1", routeTranscript("r1", table+"  "), ""},
		{"tab before the CRLF", "r1", routeTranscript("r1", table+"\t"), "not a JSON object"},
		{"blank line before the prompt", "r1", []byte(CommandRoute + "\r\n" + table + " \r\n\r\nr1> "), "not a JSON object"},
		{"blank line after the echo", "r1", []byte(CommandRoute + "\r\n\r\n" + table + " \r\nr1> "), "not a JSON object"},
		{"LF before the prompt", "r1", []byte(CommandRoute + "\r\n" + table + " \nr1> "), "prompt"},
		{"prompt of another node", "r2", routeTranscript("r1", table+" "), "prompt"},
		{"prompt without its space", "r1", []byte(CommandRoute + "\r\n" + table + " \r\nr1>"), "prompt"},
		{"no prompt, a partial capture", "r1", []byte(CommandRoute + "\r\n" + table + " "), "prompt"},
		{"vtysh error text", "r1", []byte(CommandRoute + "\r\n% Unknown command.\r\nr1> "), "not a JSON object"},
		{"table cut short", "r1", routeTranscript("r1", `{"routes":{}`), "reject-only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRouteCapture(tc.data, tc.node)
			if tc.want == "" {
				if err != nil {
					t.Errorf("err = %v, want the capture to decode", err)
				}
				return
			}
			if tc.want == "reject-only" {
				if err == nil {
					t.Error("truncated route table was accepted")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestRouteCaptureTrailingSpaceIsRouteOnly checks that the summary decoder still refuses
// the space that the route decoder accepts, so the summary's accept and refuse set is
// unchanged.
func TestRouteCaptureTrailingSpaceIsRouteOnly(t *testing.T) {
	summary := []byte(CommandSummary + "\r\n" + oneEstablishedOneActive + "\r\nr1> ")
	if _, err := Decode(summary, "r1"); err != nil {
		t.Fatalf("summary without a space: %v", err)
	}
	spaced := []byte(CommandSummary + "\r\n" + oneEstablishedOneActive + " \r\nr1> ")
	if _, err := Decode(spaced, "r1"); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("summary with a space before the CRLF: err = %v, want refusal as not a JSON object", err)
	}
}

// TestRouteCaptureRefusesTheOtherCommand checks that each decoder refuses the other
// command's transcript, so a swapped file cannot be read as the wrong table.
func TestRouteCaptureRefusesTheOtherCommand(t *testing.T) {
	if _, err := DecodeRouteCapture(readFixture(t, "r1"), "r1"); err == nil || !strings.Contains(err.Error(), "command echo") {
		t.Errorf("route decoder took a summary transcript: err = %v", err)
	}
	raw, _ := routeCapture(t, "r1")
	if _, err := Decode(raw, "r1"); err == nil || !strings.Contains(err.Error(), "command echo") {
		t.Errorf("summary decoder took a route transcript: err = %v", err)
	}
}
