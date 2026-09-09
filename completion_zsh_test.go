package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The Zsh completion decides what a positional argument means from the flags
// already on the line, and the bracket-balance check in packaging_test.go
// cannot see that decision: it passes whether _netdoc_wants_snapshots is wired
// correctly, wired backwards, or never reached at all.
//
// These tests drive a real zsh instead. The shell runs completion on a
// prepared line under a pseudo-terminal, and the test reads the match list it
// prints back, so what is pinned is the behaviour a user gets rather than the
// shape of the file.
//
// zsh is not a build dependency, so the test skips when it is absent. It is
// present on the Linux and macOS runners this repository builds on.

// zshProbe runs completion for cmdline in dir and returns everything zsh
// printed in response to the Tab.
//
// It uses zsh's own zpty module, which is how zsh's test suite drives
// completion: the completion system needs a terminal and a zle context, and
// neither exists when a script merely sources the file.
const zshProbe = `
emulate -L zsh
zmodload zsh/zpty || exit 77
compdir=$1; shift
zpty -b Z zsh -f
zpty -w Z 'PROMPT="RDY>"'
zpty -w Z "fpath=($compdir \$fpath)"
zpty -w Z 'autoload -Uz compinit; compinit -u -D'
zpty -w Z 'setopt NO_BEEP NO_ALWAYS_LAST_PROMPT AUTO_LIST NO_LIST_AMBIGUOUS'
zpty -w Z 'zstyle ":completion:*" completer _complete'
zpty -w Z 'zstyle ":completion:*" menu no'
zpty -w Z 'zstyle ":completion:*" format ""'
drain() {
  local chunk buf=""
  local -i i
  for (( i = 0; i < $1; i++ )); do
    if zpty -r -t Z chunk 2>/dev/null; then buf+=$chunk; fi
    sleep 0.1
  done
  print -rn -- "$buf"
}
drain 12 >/dev/null
zpty -n -w Z "$*"
drain 4 >/dev/null
zpty -n -w Z $'\t'
drain 30
zpty -d
`

var zshEscape = regexp.MustCompile("\x1b" + `\[[0-9?]*[a-zA-Z]`)

// completionMatches types cmdline into a real zsh, presses Tab, and returns
// the resulting screen with escape sequences removed.
func completionMatches(t *testing.T, dir, cmdline string) string {
	t.Helper()

	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skipf("zsh not installed: %v", err)
	}

	probe := filepath.Join(t.TempDir(), "probe.zsh")
	if err := os.WriteFile(probe, []byte(zshProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	completions, err := filepath.Abs(filepath.Join("packaging", "completions"))
	if err != nil {
		t.Fatal(err)
	}

	// compinit reads the completion by the name it is installed under.
	linked := filepath.Join(t.TempDir(), "_netdoc")
	//nolint:gosec // G304: the path is this repository's own completion file, joined from constants.
	source, err := os.ReadFile(filepath.Join(completions, "netdoc.zsh"))
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: linked is under the test's own TempDir, not caller input.
	if err := os.WriteFile(linked, source, 0o600); err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // G204: the binary is zsh from PATH and the arguments are test-owned paths and lines.
	cmd := exec.Command(zsh, probe, filepath.Dir(linked), cmdline)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 77 {
			t.Skip("this zsh has no zpty module")
		}
		t.Fatalf("zsh probe failed: %v\n%s", err, out)
	}
	return zshEscape.ReplaceAllString(strings.ReplaceAll(string(out), "\r", "\n"), "")
}

// completionFixture is a directory holding one snapshot, one file that is not
// a snapshot, and a subdirectory, so "offered a file" and "offered nothing"
// are told apart by name rather than by counting.
func completionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"alpha.ndoc", "beta.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestZshCompletionOffersSnapshotsOnlyWhereTheyAreRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("zpty needs a pseudo-terminal")
	}

	cases := []struct {
		name string
		line string
		// files is whether the local snapshot is offered as a match.
		files bool
		// flags is whether the option list is still reachable, which is the
		// behaviour an ordinary target had before snapshot completion existed.
		flags bool
	}{
		{
			name:  "compare takes two snapshots",
			line:  "netdoc --compare ",
			files: true,
		},
		{
			name: "compare takes a second snapshot",
			// Both arguments are snapshots, so the rest argument has to be
			// '*:snapshot:', not ':snapshot:'. beta.txt is the one typed and
			// alpha.ndoc the one looked for, because the captured screen holds
			// the echoed line too and a match already on it proves nothing.
			line:  "netdoc --compare beta.txt ",
			files: true,
		},
		{
			name:  "offline two-sided takes snapshots",
			line:  "netdoc --two-sided ",
			files: true,
		},
		{
			name:  "offline two-sided takes a second snapshot",
			line:  "netdoc --two-sided beta.txt ",
			files: true,
		},
		{
			name: "two-sided with via has a live side B",
			line: "netdoc --two-sided --via h1 ",
			// Side B is a host, not a file. Bash and Fish carry the same
			// condition; a file offered here would be wrong in all three.
			files: false,
		},
		{
			name: "two-sided with an attached via value has a live side B",
			line: "netdoc --two-sided --via=h1 ",
			// --via=h1 is the same run as --via h1, so it has to reach the
			// same answer: side B is a host, so no snapshot here. That
			// suppression is what this row pins, rather than the flag list.
			// The flags were only reachable while _arguments could not read
			// the attached value as the option and spent the positional on
			// it. The option spec now takes '=', so the attached form parses
			// like the separated form above and leaves the positional open,
			// and both forms offer neither a snapshot nor the flag list.
			files: false,
		},
		{
			name:  "two-sided with a single-dash attached via value has a live side B",
			line:  "netdoc --two-sided -via=h1 ",
			files: false,
		},
		{
			name: "an ordinary target is not a filename",
			line: "netdoc ",
			// Targets are hostnames, URLs and IP literals. None enumerable,
			// so the local directory is the wrong thing to offer.
			files: false,
		},
		{
			name: "flags stay reachable after an ordinary target",
			line: "netdoc example.com ",
			// The regression this test exists for. A '*:target:' rest
			// argument keeps consuming positionals, so once its action
			// declines to add matches there is nothing to fall back to and
			// the flag list disappears.
			files: false,
			flags: true,
		},
	}

	fixture := completionFixture(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := completionMatches(t, fixture, tc.line)
			if offered := strings.Contains(got, "alpha.ndoc"); offered != tc.files {
				t.Errorf("%q offered the local snapshot = %t, want %t\n%s", tc.line, offered, tc.files, got)
			}
			if offered := strings.Contains(got, "--json"); offered != tc.flags {
				t.Errorf("%q offered the flag list = %t, want %t\n%s", tc.line, offered, tc.flags, got)
			}
		})
	}
}
