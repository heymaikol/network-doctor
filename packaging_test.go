package main

import (
	"bytes"
	goversion "go/version"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/heymaikol/network-doctor/internal/app"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
	"github.com/heymaikol/network-doctor/internal/profile"
	"github.com/heymaikol/network-doctor/internal/ui"
	"gopkg.in/yaml.v3"
)

// Two independent paths build the Linux packages: GoReleaser's nfpm section
// produces the deb/rpm/apk attached to the release, and packaging/network-doctor.spec
// is rebuilt from source by COPR. A user installing from either one has to end
// up with the same executables, so these tests read both and compare them
// rather than trusting the two files to be edited together.

type goreleaserBuild struct {
	ID     string   `yaml:"id"`
	Binary string   `yaml:"binary"`
	Main   string   `yaml:"main"`
	Goos   []string `yaml:"goos"`
}

type goreleaserConfig struct {
	Builds   []goreleaserBuild `yaml:"builds"`
	Archives []struct {
		ID  string   `yaml:"id"`
		IDs []string `yaml:"ids"`
	} `yaml:"archives"`
	NFPMs []struct {
		IDs      []string      `yaml:"ids"`
		Bindir   string        `yaml:"bindir"`
		Contents []nfpmContent `yaml:"contents"`
	} `yaml:"nfpms"`
}

// nfpmContent is one file the deb/rpm/apk installs, and where it lands.
type nfpmContent struct {
	Src string `yaml:"src"`
	Dst string `yaml:"dst"`
}

func loadGoreleaserConfig(t *testing.T) goreleaserConfig {
	t.Helper()
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var cfg goreleaserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Builds) == 0 || len(cfg.NFPMs) != 1 {
		t.Fatalf("unexpected config shape: %d builds, %d nfpms", len(cfg.Builds), len(cfg.NFPMs))
	}
	return cfg
}

// linuxBinaries is the contract every Linux install path owes the user.
func (c goreleaserConfig) linuxBinaries() []string {
	var names []string
	for _, b := range c.Builds {
		if slices.Contains(b.Goos, "linux") {
			names = append(names, b.Binary)
		}
	}
	slices.Sort(names)
	return names
}

func TestReleaseBuildsNetdocSim(t *testing.T) {
	cfg := loadGoreleaserConfig(t)

	i := slices.IndexFunc(cfg.Builds, func(b goreleaserBuild) bool { return b.Binary == "netdoc-sim" })
	if i < 0 {
		t.Fatal("no release build produces netdoc-sim")
	}
	sim := cfg.Builds[i]
	if sim.Main != "./cmd/netdoc-sim" {
		t.Errorf("netdoc-sim built from %q, want ./cmd/netdoc-sim", sim.Main)
	}
	// The backend is Linux namespaces. A darwin or windows artifact would be a
	// binary whose every real command returns ErrUnsupported, so shipping one
	// would advertise a simulator that cannot simulate. See docs/simulation.md.
	if !slices.Equal(sim.Goos, []string{"linux"}) {
		t.Errorf("netdoc-sim targets %v; it has no non-Linux backend, so keep it linux-only", sim.Goos)
	}
}

// Every build needs exactly one archive, or a binary either never reaches the
// release page or two of them race for the same filename.
func TestEveryBuildHasOneArchive(t *testing.T) {
	cfg := loadGoreleaserConfig(t)
	for _, b := range cfg.Builds {
		var archives []string
		for _, a := range cfg.Archives {
			if slices.Contains(a.IDs, b.ID) {
				archives = append(archives, a.ID)
			}
		}
		if len(archives) != 1 {
			t.Errorf("build %q is in archives %v, want exactly one", b.ID, archives)
		}
	}
}

// No ids filter on nfpms means every Linux build is packaged, which is how one
// `dnf install network-doctor` lands both executables.
func TestLinuxPackagesShipEveryLinuxBuild(t *testing.T) {
	cfg := loadGoreleaserConfig(t)
	if ids := cfg.NFPMs[0].IDs; len(ids) != 0 {
		t.Errorf("nfpms filters builds to %v; drop the filter so every Linux build is packaged", ids)
	}
	if want := []string{"netdoc", "netdoc-sim"}; !slices.Equal(cfg.linuxBinaries(), want) {
		t.Errorf("Linux builds are %v, want %v", cfg.linuxBinaries(), want)
	}
}

// The container image is the third install path, and it owes the user the same
// pair of executables the packages do: from one build, at one version, in one
// directory, because that is what makes netdoc-sim find the netdoc beside it.
// container_test.go proves this against a built image; this proves it against
// the file, in the ordinary gate, where nobody needs a container engine.
func TestDockerfileShipsTheSameBinariesAsTheLinuxPackages(t *testing.T) {
	data, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(data)

	for _, binary := range loadGoreleaserConfig(t).linuxBinaries() {
		if !strings.Contains(dockerfile, "-o /out/"+binary+" ") {
			t.Errorf("the image never builds %s, which the Linux packages ship", binary)
		}
		if !strings.Contains(dockerfile, "COPY --from=build /out/"+binary+" /usr/bin/"+binary) {
			t.Errorf("the image never installs %s into /usr/bin, where netdoc-sim looks for its sibling", binary)
		}
	}
	// One version string for both, injected the same way GoReleaser injects it.
	// An image whose netdoc and netdoc-sim disagreed would make every recorded
	// challenge result ambiguous about which build it graded.
	if got := strings.Count(dockerfile, "-X main.version=${VERSION}"); got != 2 {
		t.Errorf("%d builds stamp -X main.version, want 2", got)
	}
	// Digest-pinned bases: a floating tag would make two builds of one commit
	// different images, and dependabot keeps the pins current.
	for _, line := range strings.Split(dockerfile, "\n") {
		if !strings.HasPrefix(line, "FROM ") {
			continue
		}
		if !strings.Contains(line, "@sha256:") {
			t.Errorf("base image is not pinned by digest: %s", line)
		}
	}
	// netdoc-sim owns the argument parsing. An entrypoint that re-parsed
	// anything would be a second CLI to keep in step with this one.
	if !strings.Contains(dockerfile, `ENTRYPOINT ["/usr/bin/netdoc-sim"]`) {
		t.Error("the image entrypoint is not netdoc-sim")
	}
}

func TestPackagingToolchainsMeetGoModRequirement(t *testing.T) {
	moduleVersion := goModVersion(t)

	t.Run("RPM spec", func(t *testing.T) {
		data, err := os.ReadFile("packaging/network-doctor.spec")
		if err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile(`(?m)^BuildRequires:\s+golang\s+(>=)\s+([0-9]+(?:\.[0-9]+){1,2})\s*$`).FindStringSubmatch(string(data))
		if match == nil {
			t.Fatal("RPM spec must declare BuildRequires: golang >= <Go version>")
		}
		if !goversion.IsValid("go" + match[2]) {
			t.Fatalf("RPM spec has invalid Go version %q", match[2])
		}
		if goversion.Compare("go"+match[2], "go"+moduleVersion) < 0 {
			t.Errorf("RPM requires Go %s, below go.mod's Go %s", match[2], moduleVersion)
		}
	})

	t.Run("Docker builder", func(t *testing.T) {
		data, err := os.ReadFile("Dockerfile")
		if err != nil {
			t.Fatal(err)
		}
		match := regexp.MustCompile(`(?m)^FROM\s+.*golang:([0-9]+(?:\.[0-9]+){1,2})(?:-|@)`).FindStringSubmatch(string(data))
		if match == nil {
			t.Fatal("Dockerfile has no versioned golang builder image")
		}
		builderVersion := match[1]
		if strings.Count(builderVersion, ".") == 1 {
			builderVersion += ".0"
		}
		if !goversion.IsValid("go" + builderVersion) {
			t.Fatalf("Docker builder has invalid Go version %q", match[1])
		}
		if goversion.Compare("go"+builderVersion, "go"+moduleVersion) < 0 {
			t.Errorf("Docker builder uses Go %s, below go.mod's Go %s", match[1], moduleVersion)
		}
	})
}

func goModVersion(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			if !goversion.IsValid("go" + fields[1]) {
				t.Fatalf("go.mod has invalid Go version %q", fields[1])
			}
			return fields[1]
		}
	}
	t.Fatal("go.mod has no go directive")
	return ""
}

func TestReleaseWorkflowRestrictsCOPRTargets(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	const configure = "copr-cli modify heymaikol/network-doctor --follow-fedora-branching off --chroot fedora-rawhide-x86_64 --chroot fedora-rawhide-aarch64"
	workflow := string(data)
	configuredAt := strings.Index(workflow, configure)
	buildAt := strings.Index(workflow, "copr-cli build heymaikol/network-doctor")
	if configuredAt < 0 {
		t.Fatalf("release workflow must restrict COPR to Rawhide x86_64 and aarch64 with %q", configure)
	}
	if buildAt < 0 || configuredAt > buildAt {
		t.Error("release workflow must restrict COPR chroots before submitting the build")
	}
}

func TestREADMEPresentsCOPRAsFedoraRawhideOnly(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, linux, ok := strings.Cut(string(data), "\n### Linux\n")
	if !ok {
		t.Fatal("README has no Linux installation section")
	}
	linux, _, ok = strings.Cut(linux, "\n### ")
	if !ok {
		t.Fatal("README's Linux installation section never ends")
	}

	stableAt := strings.Index(linux, "Fedora stable")
	stableInstallAt := strings.Index(linux, "dnf install ./network-doctor_")
	coprEnableAt := strings.Index(linux, "dnf copr enable")
	if stableAt < 0 || stableInstallAt < 0 || coprEnableAt < 0 {
		t.Fatal("Fedora guidance must include separate stable RPM and Rawhide COPR installation paths")
	}
	rawhideAt := strings.LastIndex(linux[:coprEnableAt], "Fedora Rawhide")
	if rawhideAt < 0 {
		t.Fatal("the COPR command must identify Fedora Rawhide as its installation path")
	}
	if stableAt >= stableInstallAt || stableInstallAt >= rawhideAt || rawhideAt >= coprEnableAt {
		t.Error("Fedora stable's release RPM must appear before the Rawhide-only COPR command")
	}
}

// The release publishes the image from the tag it is building, with that tag as
// the version the binaries report. Reading it from the workflow keeps the two
// halves of "the image tag names the build inside it" from drifting apart.
func TestReleaseWorkflowPublishesTheImageAtTheTag(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	for _, want := range []string{
		"VERSION=${{ github.ref_name }}",
		"ghcr.io/${{ github.repository_owner }}/netdoc-sim:${{ github.ref_name }}",
		"platforms: linux/amd64,linux/arm64",
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("the release workflow does not contain %q", want)
		}
	}
}

// The man page and the three completion files are hand-maintained copies of the
// flag list in main.go, so a new flag silently ships undocumented and
// uncompletable, and a deleted one stays advertised. Read the flags back out of
// the real usage output and require every shipped surface to declare exactly
// that set, in that surface's own declaration syntax, so a name that only
// turns up in prose, a comment, or an example does not count as documented.

// flagNames pulls capture group 1 out of every match, which is the flag name in
// each of the patterns below.
func flagNames(re *regexp.Regexp, data string) []string {
	var names []string
	for _, m := range re.FindAllStringSubmatch(data, -1) {
		// Single letters are aliases (-h), which the flag package never
		// defines and PrintDefaults never prints; only the long spelling is
		// compared.
		if len(m[1]) > 1 {
			names = append(names, m[1])
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// declaredBy reads flag names straight out of a file with one pattern.
func declaredBy(pattern string) func(string) []string {
	re := regexp.MustCompile(pattern)
	return func(data string) []string { return flagNames(re, data) }
}

// manOptions reads the OPTIONS section of the man page. An option is declared
// on the line after a .TP, so the flags named in a body paragraph (-toolbox's
// "Cannot be combined with \-json") and in the EXAMPLES section are not
// mistaken for declarations of their own.
func manOptions(data string) []string {
	_, opts, ok := strings.Cut(data, "\n.SH OPTIONS\n")
	if !ok {
		return nil
	}
	opts, _, _ = strings.Cut(opts, "\n.SH ")
	lines := strings.Split(opts, "\n")
	var decls []string
	for i, line := range lines {
		if strings.TrimSpace(line) == ".TP" && i+1 < len(lines) {
			// \- is roff for a literal hyphen; drop the escapes so the names
			// read the way they do on the command line.
			decls = append(decls, strings.ReplaceAll(lines[i+1], `\`, ""))
		}
	}
	return flagNames(regexp.MustCompile(`-([a-zA-Z0-9][a-zA-Z0-9-]*)`), strings.Join(decls, "\n"))
}

var flagSurfaces = map[string]func(string) []string{
	"packaging/netdoc.1": manOptions,
	// The compgen word list spells every flag both ways on one line
	// ("-json --json"). The case labels above it separate the two spellings
	// with a pipe, so only the list matches.
	"packaging/completions/netdoc.bash": declaredBy(`-[a-zA-Z0-9-]+ --([a-zA-Z0-9-]+)`),
	// _arguments option specs: {--json,-json}. The exclusion lists in front of
	// them are parenthesized, not braced.
	"packaging/completions/netdoc.zsh": declaredBy(`\{--([a-zA-Z0-9-]+),`),
	// complete -c netdoc -o json -l json -d '...'; -l is the long option.
	"packaging/completions/netdoc.fish": declaredBy(`(?m)^complete\b.*? -l ([a-zA-Z0-9-]+)`),
}

func TestShippedSurfacesDeclareExactlyTheRealFlags(t *testing.T) {
	var usage bytes.Buffer
	if code := app.Run(version, []string{"--help"}, &usage, io.Discard); code != 0 {
		t.Fatalf("app.Run(--help) = %d, want 0", code)
	}
	// PrintDefaults writes "  -name value", then the usage text on its own
	// indented line.
	want := flagNames(regexp.MustCompile(`(?m)^  -(\S+)`), usage.String())
	if len(want) < 2 {
		t.Fatalf("parsed %d flags out of the usage output:\n%s", len(want), usage.String())
	}
	// The one flag PrintDefaults cannot report: the flag package answers -help
	// itself, by returning flag.ErrHelp rather than by being a defined flag.
	// The successful run above is the proof that netdoc still accepts it.
	want = append(want, "help")
	slices.Sort(want)

	for path, declared := range flagSurfaces {
		// #nosec G304 -- path is a repository-owned key from the fixed flagSurfaces table.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := declared(string(data))
		if len(got) == 0 {
			t.Fatalf("%s: parsed no flag declarations at all; the file's syntax changed", path)
		}
		for _, name := range want {
			if !slices.Contains(got, name) {
				t.Errorf("%s never declares --%s; netdoc accepts it, so this surface has to ship it too", path, name)
			}
		}
		for _, name := range got {
			if !slices.Contains(want, name) {
				t.Errorf("%s declares --%s, which netdoc does not accept; drop it or restore the flag", path, name)
			}
		}
	}
}

func completionVocabulary(t *testing.T, path, pattern string) []string {
	t.Helper()
	// #nosec G304 -- path is a repository-owned value from the fixed completions table.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(pattern).FindStringSubmatch(string(data))
	if match == nil {
		t.Fatalf("%s: could not parse the -keys completion", path)
	}
	return strings.Fields(match[1])
}

func manOptionBody(data, name string) string {
	_, options, ok := strings.Cut(data, "\n.SH OPTIONS\n")
	if !ok {
		return ""
	}
	options, _, _ = strings.Cut(options, "\n.SH ")
	lines := strings.Split(options, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != ".TP" || !slices.Contains(flagNames(regexp.MustCompile(`-([a-zA-Z0-9][a-zA-Z0-9\\-]*)`), strings.ReplaceAll(lines[i+1], `\`, "")), name) {
			continue
		}
		end := len(lines)
		for j := i + 2; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == ".TP" {
				end = j
				break
			}
		}
		return strings.Join(lines[i+2:end], "\n")
	}
	return ""
}

func manKeyPresets(data string) []string {
	body := manOptionBody(data, "keys")
	_, values, ok := strings.Cut(body, "Keybinding preset for the terminal UI, either\n")
	if !ok {
		return nil
	}
	values, _, ok = strings.Cut(values, "\nThe\n")
	if !ok {
		return nil
	}
	return flagNames(regexp.MustCompile(`(?m)^\.BR? ([a-zA-Z0-9][a-zA-Z0-9-]*)`), values)
}

func TestShippedSurfacesOfferTheRealKeyPresets(t *testing.T) {
	want := ui.KeyPresets()
	completions := []struct {
		path, pattern string
	}{
		{"packaging/completions/netdoc.bash", `(?s)-keys \| --keys\).*?compgen -W "([^"]*)".*?\n\s*;;`},
		{"packaging/completions/netdoc.zsh", `(?m)^.*\{--keys,-keys\}=.*:preset:\(([^)]*)\).*$`},
		{"packaging/completions/netdoc.fish", `(?m)^complete -c netdoc [^\n]* -l keys [^\n]*\\\n[ \t]*-a '([^']*)'$`},
	}
	for _, completion := range completions {
		if got := completionVocabulary(t, completion.path, completion.pattern); !slices.Equal(got, want) {
			t.Errorf("%s offers -keys values %v, want %v", completion.path, got, want)
		}
	}
	data, err := os.ReadFile("packaging/netdoc.1")
	if err != nil {
		t.Fatal(err)
	}
	if got := manKeyPresets(string(data)); !slices.Equal(got, want) {
		t.Errorf("packaging/netdoc.1 documents -keys values %v, want %v", got, want)
	}
}

func TestShippedSurfacesOfferTheRealProbeIDs(t *testing.T) {
	// -check and -skip take stable probe IDs, and the three completion files
	// each carry their own copy of the list. StableProbes() is the source of
	// truth, so this fails the build rather than letting a new or renamed probe
	// leave the shells offering an ID that no longer exists.
	probes := diagnostic.StableProbes()
	want := make([]string, 0, len(probes))
	for _, probe := range probes {
		want = append(want, string(probe.ID))
	}
	if len(want) == 0 {
		t.Fatal("StableProbes() returned nothing; this test would pass vacuously")
	}

	completions := []struct {
		path, pattern string
	}{
		{"packaging/completions/netdoc.bash", `(?s)-check \| --check \| -skip \| --skip\).*?compgen -P "\$prefix" -W "([^"]*)".*?
\s*;;`},
		{"packaging/completions/netdoc.zsh", `(?m)^\s*_values -s , 'probe ID' (.*)$`},
		{"packaging/completions/netdoc.fish", `(?m)^set -l netdoc_probes (.*)$`},
	}
	for _, completion := range completions {
		if got := completionVocabulary(t, completion.path, completion.pattern); !slices.Equal(got, want) {
			t.Errorf("%s offers probe IDs %v, want %v", completion.path, got, want)
		}
	}
	// The fish file names that list once, so -check and -skip are each checked
	// to offer it, and to offer it through __fish_complete_list: a plain -a
	// replaces the whole comma-separated token, and without -f the flag falls
	// back to completing filenames.
	fish, err := os.ReadFile("packaging/completions/netdoc.fish")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"check", "skip"} {
		declaration := regexp.MustCompile(`(?m)^complete -c netdoc -o ` + flag + ` [^\n]* -f [^\n]*\\\n[ \t]*-a "\(__fish_complete_list , \\"printf '%s\\n' \$netdoc_probes\\"\)"$`)
		if !declaration.Match(fish) {
			t.Errorf("packaging/completions/netdoc.fish: -%s must complete $netdoc_probes through __fish_complete_list and pass -f", flag)
		}
	}
}

// The -f at the top of netdoc.fish suppresses file candidates for the whole
// command, but an option-specific -r can quietly turn them back on for that
// one option. Every value-taking option whose value is not a path therefore
// has to repeat -f on its own declaration; the exceptions are the options
// that genuinely take files, which stay spelled with -F.
func TestFishKeepsNonPathValuesOffFileCompletion(t *testing.T) {
	data, err := os.ReadFile("packaging/completions/netdoc.fish")
	if err != nil {
		t.Fatal(err)
	}
	fish := string(data)

	// -profile, -check, -skip and -via gained -f when their value
	// completions landed; the rest are the cases that still fell back to
	// filenames. Kept as one list so a new non-path option has to opt out.
	noFiles := []string{
		"profile", "check", "skip", "via",
		"peer-listen", "iface", "public-dns", "keys", "timeout",
	}
	for _, flag := range noFiles {
		declaration := regexp.MustCompile(`(?m)^complete -c netdoc -o ` + flag + `[^\n]* -f`).FindString(fish)
		if declaration == "" {
			t.Errorf("packaging/completions/netdoc.fish: --%s takes a value that is not a path, so its declaration must pass -f", flag)
			continue
		}
		if strings.Contains(declaration, " -F") {
			t.Errorf("packaging/completions/netdoc.fish: --%s passes -F, which brings file candidates back", flag)
		}
	}

	// -save and -support write .ndoc files, and the snapshot arguments of
	// -compare and offline --two-sided are files too, so those keep -F.
	for _, flag := range []string{"save", "support"} {
		if !regexp.MustCompile(`(?m)^complete -c netdoc -o ` + flag + `[^\n]* -F`).MatchString(fish) {
			t.Errorf("packaging/completions/netdoc.fish: --%s writes a file, so its declaration must keep -F", flag)
		}
	}
	for _, condition := range []string{
		`-n '__fish_seen_argument -o compare -l compare' -F`,
		`-n '__fish_seen_argument -o two-sided -l two-sided; and not __fish_seen_argument -o via -l via' -F`,
	} {
		if !strings.Contains(fish, condition) {
			t.Errorf("packaging/completions/netdoc.fish: snapshot file completion must stay gated behind %s", condition)
		}
	}
}

func TestShippedSurfacesOfferTheRealProfiles(t *testing.T) {
	want := append(profile.Builtins().Names(), "list")
	completions := []struct {
		path, pattern string
	}{
		{"packaging/completions/netdoc.bash", `(?s)-profile \| --profile\).*?compgen -W "([^"]*)".*?\n\s*;;`},
		{"packaging/completions/netdoc.zsh", `(?m)^.*\{--profile,-profile\}=.*:profile:\(([^)]*)\).*$`},
		{"packaging/completions/netdoc.fish", `(?m)^complete -c netdoc [^\n]* -l profile [^\n]*\\\n[ \t]*-a '([^']*)'$`},
	}
	for _, completion := range completions {
		if got := completionVocabulary(t, completion.path, completion.pattern); !slices.Equal(got, want) {
			t.Errorf("%s offers -profile values %v, want %v", completion.path, got, want)
		}
	}
	data, err := os.ReadFile("packaging/netdoc.1")
	if err != nil {
		t.Fatal(err)
	}
	body := manOptionBody(string(data), "profile")
	for _, name := range want {
		if !strings.Contains(body, name) {
			t.Errorf("packaging/netdoc.1 does not document profile %q", name)
		}
	}
}

// The CLI accepts --flag=value. Zsh only offers that form when the option spec
// includes '=', and Bash only reaches the value cases after splitting on '='.
func TestCompletionsHandleAttachedFlagValues(t *testing.T) {
	zsh, err := os.ReadFile("packaging/completions/netdoc.zsh")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"profile", "keys", "check", "skip"} {
		if !regexp.MustCompile(`\{--` + name + `,-` + name + `\}=`).Match(zsh) {
			t.Errorf("packaging/completions/netdoc.zsh: --%s must be declared with '=' so --%s=value completes", name, name)
		}
	}

	bash, err := os.ReadFile("packaging/completions/netdoc.bash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bash), `[[ $cur == -*=* ]]`) {
		t.Error("packaging/completions/netdoc.bash must split --flag=value so the existing value cases apply to the attached form")
	}
}

func TestBashCompletesAttachedAndSeparatedFlagValues(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}

	dir := t.TempDir()
	// Files that filename completion would offer for the prefixes below.
	// The enumerable flags must not fall back to them.
	for _, name := range []string{"gith", "github-file", "vimrc", "tls-file", "dns-file"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, tt := range []struct {
		name  string
		words []string
		cword int
		want  []string
	}{
		{"attached profile", []string{"netdoc", "--profile=git"}, 1, []string{"github"}},
		{"attached single-dash profile", []string{"netdoc", "-profile=git"}, 1, []string{"github"}},
		{"attached keys", []string{"netdoc", "--keys=vi"}, 1, []string{"vim"}},
		{"attached single-dash keys", []string{"netdoc", "-keys=vi"}, 1, []string{"vim"}},
		{"attached check prefix", []string{"netdoc", "--check=dn"}, 1, []string{"dns", "dns_public", "dns_encrypted"}},
		{"attached skip prefix", []string{"netdoc", "--skip=tl"}, 1, []string{"tls"}},
		{"attached check keeps comma prefix", []string{"netdoc", "--check=dns,tl"}, 1, []string{"dns,tls"}},
		{"attached skip keeps comma prefix", []string{"netdoc", "--skip=tls,ht"}, 1, []string{"tls,http", "tls,https"}},
		{"attached single-dash check keeps comma prefix", []string{"netdoc", "-check=dns,tl"}, 1, []string{"dns,tls"}},
		{"separated profile", []string{"netdoc", "--profile", "git"}, 2, []string{"github"}},
		{"separated keys", []string{"netdoc", "--keys", "vi"}, 2, []string{"vim"}},
		{"separated check keeps comma prefix", []string{"netdoc", "--check", "dns,tl"}, 2, []string{"dns,tls"}},
		{"readline split profile equals-glued", []string{"netdoc", "--profile", "=git"}, 2, []string{"github"}},
		{"readline split profile three words", []string{"netdoc", "--profile", "=", "git"}, 3, []string{"github"}},
		{"readline split profile equals on prev", []string{"netdoc", "--profile=", "git"}, 2, []string{"github"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := bashComplete(t, dir, tt.words, tt.cword)
			if !slices.Equal(got, tt.want) {
				t.Errorf("complete %q = %v, want %v", strings.Join(tt.words, " "), got, tt.want)
			}
		})
	}
}

func bashComplete(t *testing.T, dir string, words []string, cword int) []string {
	t.Helper()
	script, err := filepath.Abs("packaging/completions/netdoc.bash")
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-c", `source "$1"
cword=$2
shift 2
COMP_WORDS=("$@")
COMP_CWORD=$cword
COMP_LINE="${COMP_WORDS[*]}"
COMP_POINT=${#COMP_LINE}
COMPREPLY=()
_netdoc
if ((${#COMPREPLY[@]})); then
  printf '%s\n' "${COMPREPLY[@]}"
fi
`, "bash-complete", script, strconv.Itoa(cword)}, words...)
	cmd := exec.Command("bash", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("bash completion %q: %v\n%s", strings.Join(words, " "), err, ee.Stderr)
		}
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(out), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// reference is the man page and completions one installed binary owes its
// users. A binary that ships without them sends the reader to GitHub for the
// command surface, which is the one thing a packaged install should not need.
type reference struct {
	src string
	dst string
	// specFile is the %files entry, which is the destination in RPM's macro
	// spelling; the man page's is a glob because brp-compress adds a suffix.
	specDir  string
	specFile string
}

func referencesFor(binary string) []reference {
	return []reference{
		{src: "packaging/" + binary + ".1",
			dst:      "/usr/share/man/man1/" + binary + ".1",
			specDir:  "%{_mandir}/man1/",
			specFile: "%{_mandir}/man1/" + binary + ".1*"},
		{src: "packaging/completions/" + binary + ".bash",
			dst:      "/usr/share/bash-completion/completions/" + binary,
			specDir:  "%{_datadir}/bash-completion/completions/",
			specFile: "%{_datadir}/bash-completion/completions/" + binary},
		{src: "packaging/completions/" + binary + ".zsh",
			dst:      "/usr/share/zsh/site-functions/_" + binary,
			specDir:  "%{_datadir}/zsh/site-functions/",
			specFile: "%{_datadir}/zsh/site-functions/_" + binary},
		{src: "packaging/completions/" + binary + ".fish",
			dst:      "/usr/share/fish/vendor_completions.d/" + binary + ".fish",
			specDir:  "%{_datadir}/fish/vendor_completions.d/",
			specFile: "%{_datadir}/fish/vendor_completions.d/" + binary + ".fish"},
	}
}

// Whatever ships a binary ships that binary's reference material, in both
// package builds, at the destinations the other binary already uses. Driving
// this off linuxBinaries means a third executable cannot be added with a man
// page nobody installs.
func TestEveryShippedBinaryShipsItsManPageAndCompletions(t *testing.T) {
	cfg := loadGoreleaserConfig(t)
	data, err := os.ReadFile("packaging/network-doctor.spec")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(data)
	install := strings.Join(specSection(t, spec, "%install"), "\n")
	files := specSection(t, spec, "%files")

	for _, binary := range cfg.linuxBinaries() {
		for _, ref := range referencesFor(binary) {
			if _, err := os.Stat(ref.src); err != nil {
				t.Errorf("%s ships %s, but %s does not exist", binary, ref.dst, ref.src)
				continue
			}
			if !slices.Contains(cfg.NFPMs[0].Contents, nfpmContent{Src: ref.src, Dst: ref.dst}) {
				t.Errorf("the deb/rpm/apk never install %s to %s", ref.src, ref.dst)
			}
			if !strings.Contains(install, ref.src+" %{buildroot}"+ref.specDir) {
				t.Errorf("spec %%install never installs %s into %s", ref.src, ref.specDir)
			}
			if !slices.Contains(files, ref.specFile) {
				t.Errorf("spec %%files never lists %s", ref.specFile)
			}
		}
	}
}

func TestShippedManPagesHaveValidMetadata(t *testing.T) {
	headerRE := regexp.MustCompile(`^\.TH (\S+) (\S+) "([^"]+)" "network-doctor" "User Commands"$`)
	const manDir = "/usr/share/man/man"
	pages := 0
	for _, content := range loadGoreleaserConfig(t).NFPMs[0].Contents {
		destination, ok := strings.CutPrefix(content.Dst, manDir)
		if !ok {
			continue
		}
		section, name, ok := strings.Cut(destination, "/")
		if !ok || section == "" {
			t.Errorf("invalid shipped man-page destination %q", content.Dst)
			continue
		}
		binary, ok := strings.CutSuffix(name, "."+section)
		if !ok {
			t.Errorf("shipped man-page destination %q must end in .%s", content.Dst, section)
			continue
		}
		pages++
		path := content.Src
		// #nosec G304 -- path comes from this repository's checked-in GoReleaser config.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			continue
		}
		header, _, _ := strings.Cut(string(data), "\n")
		match := headerRE.FindStringSubmatch(header)
		wantTitle := strings.ReplaceAll(strings.ToUpper(binary), "-", `\-`)
		if len(match) != 4 || match[1] != wantTitle || match[2] != section {
			t.Errorf("%s: first line must be .TH %s %s \"YYYY-MM-DD\" \"network-doctor\" \"User Commands\"", path, wantTitle, section)
			continue
		}
		date, err := time.Parse(time.DateOnly, match[3])
		if err != nil {
			t.Errorf("%s: invalid .TH date %q: %v", path, match[3], err)
			continue
		}
		if date.IsZero() || date.After(time.Now().UTC().Add(24*time.Hour)) {
			t.Errorf("%s: implausible .TH date %q", path, match[3])
		}
	}
	if pages == 0 {
		t.Fatal("GoReleaser ships no man pages")
	}
}

// The two binaries are one install, so each man page has to be findable from
// the other. A reader who has only ever run netdoc should still learn that the
// simulator exists, and vice versa.
func TestManPagesCrossReferenceEachOther(t *testing.T) {
	for _, tt := range []struct{ page, wants string }{
		{"packaging/netdoc.1", `.BR netdoc\-sim (1)`},
		{"packaging/netdoc-sim.1", `.BR netdoc (1)`},
	} {
		data, err := os.ReadFile(tt.page)
		if err != nil {
			t.Fatal(err)
		}
		seeAlso := manSeeAlso(string(data))
		if seeAlso == "" {
			t.Errorf("%s has no SEE ALSO section", tt.page)
			continue
		}
		if !strings.Contains(seeAlso, tt.wants) {
			t.Errorf("%s's SEE ALSO does not reference %q", tt.page, tt.wants)
		}
	}
}

// manSeeAlso returns the SEE ALSO section, so a name that merely turns up in
// the prose somewhere is not mistaken for a cross-reference.
func manSeeAlso(data string) string {
	_, body, ok := strings.Cut(data, "\n.SH SEE ALSO\n")
	if !ok {
		return ""
	}
	body, _, _ = strings.Cut(body, "\n.SH ")
	return body
}

// specSection returns the lines of one %section of an RPM spec, so an assertion
// can tell "installed and listed" from "mentioned in a comment somewhere".
func specSection(t *testing.T, spec, name string) []string {
	t.Helper()
	// An allowlist, not "any line starting with %": %files' own body is made of
	// directives like %license and %doc, which are content rather than a new
	// section.
	sections := []string{"%description", "%prep", "%build", "%install", "%files", "%changelog"}
	var lines []string
	in := false
	for _, line := range strings.Split(spec, "\n") {
		if head := strings.Fields(line); len(head) > 0 && slices.Contains(sections, head[0]) {
			in = head[0] == name
			continue
		}
		if in && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	if len(lines) == 0 {
		t.Fatalf("spec section %s not found", name)
	}
	return lines
}

// The invariant that keeps a GitHub .deb and a COPR .rpm from disagreeing.
func TestRPMSpecShipsTheSameBinariesAsNFPM(t *testing.T) {
	data, err := os.ReadFile("packaging/network-doctor.spec")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(data)

	var packaged []string
	for _, line := range specSection(t, spec, "%files") {
		if name, ok := strings.CutPrefix(line, "%{_bindir}/"); ok {
			packaged = append(packaged, name)
		}
	}
	slices.Sort(packaged)

	want := loadGoreleaserConfig(t).linuxBinaries()
	if !slices.Equal(packaged, want) {
		t.Errorf("spec %%files ships %v, GoReleaser's Linux packages ship %v", packaged, want)
	}

	// %files can list a path %install never wrote; rpmbuild catches that, but
	// only on a Fedora host with the tarballs. Catch it in the ordinary gate.
	install := strings.Join(specSection(t, spec, "%install"), "\n")
	for _, name := range want {
		if !strings.Contains(install, "%{buildroot}%{_bindir}/"+name) {
			t.Errorf("spec %%install never installs %s", name)
		}
	}

	builds := make(map[string][]string)
	for _, command := range specSection(t, spec, "%build") {
		command, _, _ = strings.Cut(command, " #")
		fields := strings.Fields(command)
		if len(fields) < 2 || fields[0] != "go" || fields[1] != "build" {
			continue
		}
		if strings.Contains(command, " && ") || strings.Contains(command, " || ") || strings.Contains(command, ";") {
			t.Errorf("ambiguous RPM go build command %q; keep each build in its own command", command)
			continue
		}
		var outputs []string
		for i := 2; i < len(fields); i++ {
			switch {
			case fields[i] == "-o" && i+1 < len(fields):
				outputs = append(outputs, fields[i+1])
			case strings.HasPrefix(fields[i], "-o="):
				outputs = append(outputs, strings.TrimPrefix(fields[i], "-o="))
			}
		}
		if len(outputs) != 1 {
			t.Errorf("RPM go build command %q has outputs %v, want exactly one", command, outputs)
			continue
		}
		output := strings.Trim(outputs[0], `'"`)
		builds[output] = append(builds[output], command)
	}
	for _, name := range want {
		commands := builds[name]
		if len(commands) != 1 {
			t.Errorf("RPM %%build has %d go build commands producing %s, want exactly one", len(commands), name)
			continue
		}
		if !strings.Contains(commands[0], "-X main.version=%{version}") {
			t.Errorf("RPM go build command producing %s does not inject -X main.version=%%{version}: %s", name, commands[0])
		}
	}

	if !strings.Contains(strings.Join(specSection(t, spec, "%build"), "\n"), "./cmd/netdoc-sim") {
		t.Error("the spec's build section never compiles ./cmd/netdoc-sim")
	}
}

// GoReleaser still publishes the cask to heymaikol/tap so existing installs of
// it keep upgrading, but homebrew/core carries the formula now. The README is
// the page that converts a new user, so it hands out the Core one-liner and
// never the tap, the cask, or the quarantine dance the unsigned cask needed.
func TestREADMEInstallsHomebrewFromCore(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, install, ok := strings.Cut(string(readme), "\n## Install\n")
	if !ok {
		t.Fatal("README.md has no `## Install` section")
	}
	install, _, ok = strings.Cut(install, "\n## ")
	if !ok {
		t.Fatal("README.md's `## Install` section never ends; the heading structure changed")
	}

	if !strings.Contains(install, "brew install network-doctor") {
		t.Error("README Install section never hands out `brew install network-doctor`")
	}
	for _, stale := range []string{"heymaikol/tap", "brew install --cask", "com.apple.quarantine", "Gatekeeper", "xattr"} {
		if strings.Contains(install, stale) {
			t.Errorf("README Install section still advertises %q; homebrew/core replaced the cask", stale)
		}
	}
}
