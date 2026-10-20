package main

import (
	"context"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/simulation"
)

// The man page, three completion files, and rendered usage expose copies of
// netdoc-sim's command and flag surface. Nothing here keeps a list of that
// surface: the commands come out of the dispatch switch and the flags out of
// the real flag sets, and every shipped surface has to declare exactly that,
// in its own declaration syntax, so a name that only appears in prose, a
// comment or an example does not count.
//
// netdoc-sim is hierarchical, so every check below is per command: -cases
// belongs to hunt and triage, and finding the word somewhere in a file is not
// evidence that hunt completes it.

func packagingFile(t *testing.T, name ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "packaging"}, name...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// publicCommands reads the case labels of the dispatch switch in run(). A
// command is a string literal: the director commands are named constants and
// the node holder is simulation.NodeCommand, so the internal entry points stay
// out without anything here having to know their spelling. Labels starting
// with a dash are flag spellings of a command (-version), not commands.
func publicCommands(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "run" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			for _, stmt := range sw.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, expr := range clause.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil || strings.HasPrefix(value, "-") {
						continue
					}
					names = append(names, value)
				}
			}
			return true
		})
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) < 5 {
		t.Fatalf("parsed %d commands out of run()'s dispatch switch; the function's shape changed", len(names))
	}
	return names
}

// commandFlags is every command's public flags, read out of the flag sets the
// commands themselves parse with.
func commandFlags(t *testing.T) map[string][]string {
	t.Helper()
	sets := map[string]*flag.FlagSet{
		"run":       newRunFlags(io.Discard).fs,
		"campaign":  newCampaignFlags(io.Discard).fs,
		"hunt":      newHuntFlags(io.Discard).fs,
		"triage":    newTriageFlags(io.Discard).fs,
		"challenge": newChallengeFlags(io.Discard).fs,
	}
	cleanupSet, _ := newCleanupFlags(io.Discard)
	sets["cleanup"] = cleanupSet

	// The map above is the one place a command could be forgotten, so it is
	// checked against the declarations rather than trusted: every new*Flags
	// function in the package has to appear in it, under the command it names.
	declared := flagConstructors(t)
	built := make([]string, 0, len(sets))
	for name := range sets {
		built = append(built, name)
	}
	slices.Sort(built)
	if !slices.Equal(declared, built) {
		t.Fatalf("flag sets declared in the package are %v, this test reads %v; add the new command here", declared, built)
	}

	out := make(map[string][]string, len(sets))
	for command, fs := range sets {
		var names []string
		fs.VisitAll(func(f *flag.Flag) {
			// Flags the launcher hands its own director inside the namespaces
			// say so in their usage string. They are not a public surface, and
			// documenting or completing them would advertise an interface
			// nobody is meant to type.
			if strings.HasPrefix(f.Usage, "internal:") {
				return
			}
			names = append(names, f.Name)
		})
		slices.Sort(names)
		out[command] = names
	}
	// Lab is nested and constructs its flag set inline. Read standard help
	// from the real parser rather than maintaining a second flag list.
	var help strings.Builder
	if code := runLab(context.Background(), []string{"run", "-h"}, io.Discard, &help); code != exitOK {
		t.Fatal("lab help failed")
	}
	for _, match := range regexp.MustCompile(`(?m)^  -([a-z-]+)`).FindAllStringSubmatch(help.String(), -1) {
		out["lab run"] = append(out["lab run"], match[1])
	}
	if len(out["lab run"]) == 0 {
		t.Fatal("parsed no lab flags")
	}
	return out
}

// flagConstructors is the command name behind every new<Command>Flags function
// in the package, taken from the source rather than from a list.
func flagConstructors(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	name := regexp.MustCompile(`^new([A-Z][A-Za-z]*)Flags$`)
	var commands []string
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if m := name.FindStringSubmatch(fn.Name.Name); m != nil {
				commands = append(commands, strings.ToLower(m[1]))
			}
		}
	}
	slices.Sort(commands)
	return commands
}

// manText is the man page with roff's literal-hyphen escape undone, so a name
// reads the way it does on the command line.
func manText(t *testing.T) string {
	t.Helper()
	return strings.ReplaceAll(packagingFile(t, "netdoc-sim.1"), `\-`, "-")
}

// manSection returns the body of one .SH section.
func manSection(data, name string) string {
	_, body, ok := strings.Cut(data, "\n.SH "+name+"\n")
	if !ok {
		return ""
	}
	body, _, _ = strings.Cut(body, "\n.SH ")
	return body
}

// taggedParagraphs returns the line after each .TP, which is where roff puts
// the thing being defined. Reading only those lines is what makes the man page
// checks structural: -json named inside another flag's body paragraph, or in
// EXAMPLES, is not a declaration of its own.
func taggedParagraphs(body string) []string {
	lines := strings.Split(body, "\n")
	var tags []string
	for i, line := range lines {
		if strings.TrimSpace(line) != ".TP" || i+1 >= len(lines) {
			continue
		}
		// .B run, .BI cleanup " [id]", .BI \-max\-faults " n": the macro, then
		// the name. \- is roff for a literal hyphen.
		fields := strings.Fields(lines[i+1])
		if len(fields) < 2 {
			continue
		}
		tags = append(tags, strings.ReplaceAll(fields[1], `\`, ""))
	}
	return tags
}

func manCommands(data string) []string {
	return sorted(taggedParagraphs(manSection(data, "COMMANDS")))
}

// manFlags reads the per-command subsections of OPTIONS: .SS <command>, then
// one .TP per flag it accepts.
func manFlags(data string) map[string][]string {
	out := map[string][]string{}
	chunks := strings.Split(manSection(data, "OPTIONS"), "\n.SS ")
	for _, chunk := range chunks[1:] {
		command, body, _ := strings.Cut(chunk, "\n")
		var names []string
		for _, tag := range taggedParagraphs(body) {
			if flag, ok := strings.CutPrefix(tag, "-"); ok {
				names = append(names, flag)
			}
		}
		out[strings.TrimSpace(command)] = sorted(names)
	}
	return out
}

// usageCommands reads only the command declarations in the Commands block.
func usageCommands(data string) []string {
	_, body, ok := strings.Cut(data, "\nCommands:\n")
	if !ok {
		return nil
	}
	body, _, _ = strings.Cut(body, "\n\n")
	var names []string
	for _, line := range strings.Split(body, "\n") {
		line, ok := strings.CutPrefix(line, "  ")
		fields := strings.Fields(line)
		if !ok || len(fields) == 0 {
			continue
		}
		names = append(names, fields[0])
	}
	return sorted(names)
}

// usageFlagDeclarations reads only declarations in Flags for <command> blocks.
func usageFlagDeclarations(data string) map[string]map[string]string {
	out := map[string]map[string]string{}
	command := ""
	for _, line := range strings.Split(data, "\n") {
		if name, ok := strings.CutPrefix(line, "Flags for "); ok && strings.HasSuffix(name, ":") {
			command = strings.TrimSuffix(name, ":")
			continue
		}
		if command == "" {
			continue
		}
		if line == "" {
			command = ""
			continue
		}
		declaration, ok := strings.CutPrefix(line, "  -")
		fields := strings.Fields(declaration)
		if !ok || len(fields) == 0 {
			continue
		}
		name := fields[0]
		name, _, _ = strings.Cut(name, "[")
		if out[command] == nil {
			out[command] = map[string]string{}
		}
		out[command][name] = line
	}
	return out
}

func usageFlags(data string) map[string][]string {
	out := map[string][]string{}
	for command, declarations := range usageFlagDeclarations(data) {
		for name := range declarations {
			out[command] = append(out[command], name)
		}
		out[command] = sorted(out[command])
	}
	return out
}

func renderedUsage(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	usage(&out)
	return out.String()
}

var (
	bashCommandList = regexp.MustCompile(`(?s)_netdoc_sim_commands="([^"]*)"`)
	bashFlagList    = regexp.MustCompile(`(?m)^\s+"?([a-z][a-z -]*)"?\)\s+echo "([^"]*)"`)
)

func bashCommands(data string) []string {
	m := bashCommandList.FindStringSubmatch(data)
	if m == nil {
		return nil
	}
	return sorted(strings.Fields(m[1]))
}

func bashFlags(data string) map[string][]string {
	out := map[string][]string{}
	for _, m := range bashFlagList.FindAllStringSubmatch(data, -1) {
		out[m[1]] = sorted(strings.Fields(m[2]))
	}
	return out
}

var (
	zshCommandEntry = regexp.MustCompile(`(?m)^\s+'([a-z]+):`)
	zshCaseLabel    = regexp.MustCompile(`^ {4}([a-z]+)\)$`)
	zshOptionSpec   = regexp.MustCompile(`\{--([a-zA-Z0-9-]+),`)
)

func zshCommands(data string) []string {
	_, body, ok := strings.Cut(data, "\ncommands=(\n")
	if !ok {
		return nil
	}
	body, _, _ = strings.Cut(body, "\n)\n")
	var names []string
	for _, m := range zshCommandEntry.FindAllStringSubmatch(body, -1) {
		names = append(names, m[1])
	}
	return sorted(names)
}

// zshFlags walks the per-command case arms, so an option spec counts for the
// command whose arm it sits in and for no other.
func zshFlags(data string) map[string][]string {
	out := map[string][]string{}
	command := ""
	for _, line := range strings.Split(data, "\n") {
		if m := zshCaseLabel.FindStringSubmatch(line); m != nil {
			command = m[1]
			if _, seen := out[command]; !seen {
				out[command] = nil
			}
			continue
		}
		if command == "" {
			continue
		}
		if strings.HasPrefix(command, "lab") && strings.HasPrefix(strings.TrimSpace(line), "describe)") {
			command = "lab describe"
		}
		if command == "lab" && strings.TrimSpace(line) == "run)" {
			command = "lab run"
		}
		for _, m := range zshOptionSpec.FindAllStringSubmatch(line, -1) {
			out[command] = append(out[command], m[1])
		}
	}
	for command := range out {
		out[command] = sorted(out[command])
	}
	return out
}

var fishCondition = regexp.MustCompile(`__fish_seen_subcommand_from ([a-z ]+)`)

// quoted strips the quoted runs of a fish complete line, so a word inside a
// description can never be mistaken for one of the line's own options.
var quoted = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// fishToken returns the argument of an option on a complete line, ignoring
// anything inside quotes.
func fishToken(line, option string) string {
	fields := strings.Fields(quoted.ReplaceAllString(line, " "))
	if i := slices.Index(fields, option); i >= 0 && i+1 < len(fields) {
		return fields[i+1]
	}
	return ""
}

func fishCommands(data string) []string {
	var names []string
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "complete ") || !strings.Contains(line, "__fish_use_subcommand") {
			continue
		}
		if name := fishToken(line, "-a"); name != "" {
			names = append(names, name)
		}
	}
	return sorted(names)
}

// fishFlags reads each complete line's subcommand condition and its long
// option, so a flag counts only for the commands its own condition names.
func fishFlags(data string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "complete ") {
			continue
		}
		// The old root conditions exclude lab before testing their root
		// command; lab's positive condition scopes its nested run separately.
		condition := strings.ReplaceAll(line, "not __fish_seen_subcommand_from lab; and ", "")
		m := fishCondition.FindStringSubmatch(condition)
		name := fishToken(line, "-l")
		if m == nil || name == "" {
			continue
		}
		if strings.TrimSpace(m[1]) == "lab" {
			if strings.Contains(condition, "; and __fish_seen_subcommand_from run'") {
				out["lab run"] = append(out["lab run"], name)
			} else {
				out["lab"] = append(out["lab"], name)
			}
			continue
		}
		for _, command := range strings.Fields(m[1]) {
			out[command] = append(out[command], name)
		}
	}
	for command := range out {
		out[command] = sorted(out[command])
	}
	return out
}

func sorted(names []string) []string {
	slices.Sort(names)
	return slices.Compact(names)
}

type shippedSurface struct {
	path     []string
	name     string
	content  func(*testing.T) string
	commands func(string) []string
	flags    func(string) map[string][]string
}

func (s shippedSurface) read(t *testing.T) (string, string) {
	t.Helper()
	if s.content != nil {
		return s.name, s.content(t)
	}
	return filepath.Join(s.path...), packagingFile(t, s.path...)
}

var shippedSurfaces = []shippedSurface{
	{path: []string{"netdoc-sim.1"}, commands: manCommands, flags: manFlags},
	{path: []string{"completions", "netdoc-sim.bash"}, commands: bashCommands, flags: bashFlags},
	{path: []string{"completions", "netdoc-sim.zsh"}, commands: zshCommands, flags: zshFlags},
	{path: []string{"completions", "netdoc-sim.fish"}, commands: fishCommands, flags: fishFlags},
	{name: "netdoc-sim help", content: renderedUsage, commands: usageCommands, flags: usageFlags},
}

var challengeIDLiteral = regexp.MustCompile(`\bV[0-9]+-[0-9A-Fa-f]{6}\b`)

func TestCurrentChallengeExamplesUseCurrentGeneration(t *testing.T) {
	type exampleSurface struct {
		name, content string
	}
	surfaces := []exampleSurface{
		{"netdoc-sim help", renderedUsage(t)},
		{"netdoc-sim.1", manText(t)},
	}
	for _, name := range []string{"Dockerfile", "README.md", filepath.Join("docs", "simulation.md"),
		filepath.Join("cmd", "netdoc-sim", "challenge.go")} {
		// #nosec G304 -- name comes from the fixed repository-owned list above.
		data, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		surfaces = append(surfaces, exampleSurface{name, string(data)})
	}
	for _, surface := range surfaces {
		ids := challengeIDLiteral.FindAllString(surface.content, -1)
		if len(ids) == 0 {
			t.Errorf("%s has no current challenge-id example", surface.name)
			continue
		}
		for _, id := range ids {
			version, _, _ := strings.Cut(id, "-")
			if version != simulation.ChallengeIDVersion {
				t.Errorf("%s uses stale challenge-id example %q; current generation is %s",
					surface.name, id, simulation.ChallengeIDVersion)
			}
			if _, err := simulation.BuildChallenge(id); err != nil {
				t.Errorf("%s challenge-id example %q does not resolve: %v", surface.name, id, err)
			}
		}
	}
}

func TestShippedSurfacesDeclareExactlyTheRealCommands(t *testing.T) {
	want := publicCommands(t)
	for _, surface := range shippedSurfaces {
		name, content := surface.read(t)
		got := surface.commands(content)
		if len(got) == 0 {
			t.Fatalf("%s: parsed no command declarations at all; the file's syntax changed", name)
		}
		for _, command := range want {
			if !slices.Contains(got, command) {
				t.Errorf("%s never declares the %s command; netdoc-sim accepts it, so this surface has to ship it too", name, command)
			}
		}
		for _, command := range got {
			if !slices.Contains(want, command) {
				t.Errorf("%s declares the %s command, which netdoc-sim does not accept; drop it or restore the command", name, command)
			}
		}
	}
}

func TestShippedSurfacesDeclareExactlyTheRealFlagsPerCommand(t *testing.T) {
	commands := publicCommands(t)
	want := commandFlags(t)
	for _, surface := range shippedSurfaces {
		name, content := surface.read(t)
		got := surface.flags(content)
		if len(got) == 0 {
			t.Fatalf("%s: parsed no flag declarations at all; the file's syntax changed", name)
		}
		// Every command, not only the ones with flags: a surface that grew
		// options for a command that takes none is drift in the other
		// direction.
		checked := slices.Clone(commands)
		for command := range want {
			checked = append(checked, command)
		}
		for command := range got {
			checked = append(checked, command)
		}
		for _, command := range sorted(checked) {
			for _, flag := range want[command] {
				if !slices.Contains(got[command], flag) {
					t.Errorf("%s never declares -%s under %s; netdoc-sim %s accepts it, so this surface has to ship it too",
						name, flag, command, command)
				}
			}
			for _, flag := range got[command] {
				if !slices.Contains(want[command], flag) {
					t.Errorf("%s declares -%s under %s, which netdoc-sim %s does not accept; drop it or restore the flag",
						name, flag, command, command)
				}
			}
		}
	}
}

// The flags with a finite vocabulary are completed with that vocabulary, and
// the list is the program's own. Comparing the whole list as one string checks
// both directions at once: a value added, removed or renamed in the simulation
// package stops matching what the completions offer.
func TestShippedSurfacesOfferTheRealFixedVocabularies(t *testing.T) {
	severities := make([]string, len(simulation.HuntSeverities))
	for i, severity := range simulation.HuntSeverities {
		severities[i] = string(severity)
	}
	vocabularies := []struct {
		what   string
		values []string
	}{
		{"hunt base scenarios", simulation.HuntBaseNames()},
		{"hunt generator versions", simulation.HuntGeneratorVersions()},
		{"Hunt lanes", simulation.HuntLaneNames()},
		{"starter packs", simulation.StarterPackNames()},
		{"authored challenge slugs", simulation.AuthoredChallengeSlugs()},
		{"challenge answers", simulation.ChallengeAnswerNames()},
		{"challenge difficulties", simulation.ChallengeDifficulties},
		{"hunt severities", severities},
	}
	completions := []struct {
		path           []string
		prefix, suffix string
	}{
		{[]string{"completions", "netdoc-sim.bash"}, `-W "`, `"`},
		{[]string{"completions", "netdoc-sim.zsh"}, `(`, `)`},
		{[]string{"completions", "netdoc-sim.fish"}, `-a '`, `'`},
	}
	for _, vocabulary := range vocabularies {
		list := strings.Join(vocabulary.values, " ")
		for _, completion := range completions {
			if !strings.Contains(packagingFile(t, completion.path...), completion.prefix+list+completion.suffix) {
				t.Errorf("%s does not offer the %s as %q", filepath.Join(completion.path...), vocabulary.what, list)
			}
		}
		// The man page spaces its lists over roff lines, so each value is
		// checked on its own there.
		man := manText(t)
		for _, value := range vocabulary.values {
			if !strings.Contains(man, value) {
				t.Errorf("netdoc-sim.1 never names %s %q", vocabulary.what, value)
			}
		}
	}
	helpDifficulties := usageFlagDeclarations(renderedUsage(t))["challenge"]["difficulty"]
	if helpDifficulties == "" {
		t.Fatal("netdoc-sim help has no structured -difficulty declaration")
	}
	if len(simulation.ChallengeDifficulties) == 0 {
		t.Fatal("the challenge difficulty vocabulary is empty")
	}
	wantDifficulties := strings.Join(simulation.ChallengeDifficulties[:len(simulation.ChallengeDifficulties)-1], ", ")
	if len(simulation.ChallengeDifficulties) > 1 {
		wantDifficulties += " or "
	}
	wantDifficulties += simulation.ChallengeDifficulties[len(simulation.ChallengeDifficulties)-1]
	_, gotDifficulties, hasPrefix := strings.Cut(helpDifficulties, "draw an ")
	gotDifficulties, hasSuffix := strings.CutSuffix(gotDifficulties, " challenge")
	if !hasPrefix || !hasSuffix || gotDifficulties != wantDifficulties {
		t.Errorf("netdoc-sim help offers challenge difficulties %q, want %q", gotDifficulties, wantDifficulties)
	}
	// The triage baselines are documented but not completed: -scenarios takes a
	// comma-separated list, which none of the three shells completes usefully,
	// and netdoc's own -check and -skip offer nothing for the same reason.
	man := manText(t)
	for _, baseline := range simulation.TriageBaselines() {
		if !strings.Contains(man, baseline.Scenario) {
			t.Errorf("netdoc-sim.1 never names the triage baseline %q", baseline.Scenario)
		}
	}
}
