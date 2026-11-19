package app

import (
	"bytes"
	"strings"
	"testing"
)

// The watch combinations that no supported command runs: a watch over -via, and a watch that saves.
// Each is refused by flag validation before any probe runs, so the refusal needs no network. The
// message names the flag, the exit status is the usage status, and nothing reaches stdout.
func TestUnsupportedWatchCombinationsAreRefused(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"watch with via", []string{"--via", "probe", "--watch", "--json"}, "-watch cannot be combined with -via"},
		{"watch with via, profile", []string{"-profile", "github", "-via", "probe", "-watch", "-json"}, "-watch cannot be combined with -via"},
		{"save with watch", []string{"--json", "--watch", "--save", "/nonexistent-dir-audit/x.ndoc"}, "-save and -watch cannot be combined"},
		{"save with watch, profile", []string{"-profile", "github", "-json", "-watch", "-save", "/nonexistent-dir-audit/x.json"}, "-save and -watch cannot be combined"},
		{"support with watch, profile", []string{"-profile", "github", "-json", "-watch", "-support", "/nonexistent-dir-audit/x.json"}, "-support and -watch cannot be combined"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(c.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit = %d, want 2; stderr %q", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), c.want) {
				t.Errorf("stderr = %q, want %q", stderr.String(), c.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want nothing", stdout.String())
			}
		})
	}
}
