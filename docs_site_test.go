package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The documentation site is published by GitHub Pages at an address derived
// entirely from the repository's owner and name. Nothing in the repository is
// told that address by GitHub, so several files hard-code it: the Jekyll config
// serves from it, cmd/docsite writes every internal link against it, and the
// package managers advertise it as the project's homepage. These tests derive
// it once from the module path and hold all of them to it, because a base path
// that is merely plausible produces a site of 404s that still deploys green.

// pagesURL is where a GitHub project page for this module is served.
func pagesURL(t *testing.T) (site, baseurl string) {
	t.Helper()
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^module\s+github\.com/([^/\s]+)/([^/\s]+)\s*$`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("go.mod has no github.com/<owner>/<repo> module path to derive the Pages URL from")
	}
	owner, repo := strings.ToLower(m[1]), m[2]
	return "https://" + owner + ".github.io/" + repo + "/", "/" + repo
}

func siteConfig(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("site/_config.yml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// A project page is served under /<repo>/. Getting url or baseurl wrong does not
// fail any build: it produces canonical tags, a sitemap, and asset paths that
// all point somewhere that does not exist.
func TestSiteIsConfiguredForItsGitHubPagesAddress(t *testing.T) {
	site, baseurl := pagesURL(t)
	cfg := siteConfig(t)

	wantURL := strings.TrimSuffix(site, baseurl+"/")
	if got, _ := cfg["url"].(string); got != wantURL {
		t.Errorf("site/_config.yml url is %q, want %q", got, wantURL)
	}
	if got, _ := cfg["baseurl"].(string); got != baseurl {
		t.Errorf("site/_config.yml baseurl is %q, want %q: a project page is served under its repository name", got, baseurl)
	}
	for _, plugin := range []string{"jekyll-seo-tag", "jekyll-sitemap"} {
		plugins, _ := yaml.Marshal(cfg["plugins"])
		if !strings.Contains(string(plugins), plugin) {
			t.Errorf("site/_config.yml does not enable %s; the site would publish without %s", plugin,
				map[string]string{"jekyll-seo-tag": "titles, descriptions, or canonical URLs", "jekyll-sitemap": "a sitemap"}[plugin])
		}
	}
}

// The audit this change answers found the project's advertised homepage
// pointing at a download page. Every package manager's homepage is a place to
// learn the tool, so all of them point at the documentation site, and none of
// them may quietly go back to a releases URL.
func TestPackagedHomepagesPointAtTheDocumentationSite(t *testing.T) {
	site, _ := pagesURL(t)
	data, err := os.ReadFile(".goreleaser.yaml")
	if err != nil {
		t.Fatal(err)
	}
	homepages := regexp.MustCompile(`(?m)^\s*homepage:\s*(\S+)\s*$`).FindAllStringSubmatch(string(data), -1)
	if len(homepages) < 3 {
		t.Fatalf("found %d homepage fields in .goreleaser.yaml; the test is not reaching the publish targets", len(homepages))
	}
	for _, m := range homepages {
		if m[1] != site {
			t.Errorf("a .goreleaser.yaml homepage is %q, want the documentation site %q", m[1], site)
		}
	}
}

// The RPM spec's URL is not a homepage advertisement: Source0 and Source1 are
// written as %{url}/releases/download/..., so repointing it at the site would
// break the source fetch COPR builds from. It stays the repository.
func TestRPMSpecURLStaysTheRepositoryItsSourcesComeFrom(t *testing.T) {
	data, err := os.ReadFile("packaging/network-doctor.spec")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(data)
	m := regexp.MustCompile(`(?m)^URL:\s+(\S+)\s*$`).FindStringSubmatch(spec)
	if m == nil {
		t.Fatal("the spec has no URL: field")
	}
	if !strings.HasPrefix(m[1], "https://github.com/") {
		t.Errorf("spec URL is %q; Source0 derives from it and must stay a github.com repository URL", m[1])
	}
	if !strings.Contains(spec, "Source0:        %{url}/releases/download/") {
		t.Error("the spec no longer derives Source0 from %{url}; this test's reason to exist changed")
	}
}

// Repointing the homepage is not a licence to rewrite every GitHub URL: the
// README's download links are supposed to point at the latest release, and a
// mechanical replacement would send people to documentation instead of files.
func TestREADMEKeepsDownloadLinksOnTheReleasesPage(t *testing.T) {
	site, _ := pagesURL(t)
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(data)

	if strings.Count(readme, "/releases/latest") < 3 {
		t.Error("README no longer sends downloads to /releases/latest; the .deb/.rpm/.apk and prebuilt-binary links need it")
	}
	if !strings.Contains(readme, site) {
		t.Errorf("README never links to the documentation site %s, which is how the site gets found", site)
	}
	if !strings.Contains(readme, "## Documentation") {
		t.Error("README has no Documentation section pointing at the site")
	}
}

func TestPublicSupportUsesCanonicalURLs(t *testing.T) {
	for _, surface := range []struct {
		file, url string
		count     int
	}{
		{"README.md", "https://tally.so/r/KYK7Y7", 1},
		{"site/index.md", "https://tally.so/r/KYK7Y7", 1},
		{"README.md", "https://github.com/sponsors/heymaikol", 2},
		{"site/index.md", "https://github.com/sponsors/heymaikol", 1},
		{".goreleaser.yaml", "https://github.com/sponsors/heymaikol", 1},
	} {
		// #nosec G304 -- file comes from this fixed list of public surfaces.
		data, err := os.ReadFile(surface.file)
		if err != nil {
			t.Fatal(err)
		}
		if count := strings.Count(string(data), surface.url); count != surface.count {
			t.Errorf("%s contains %s %d times, want %d", surface.file, surface.url, count, surface.count)
		}
	}
}

// The README's complete contributor gate promises to use the same tool
// versions as CI. Keep that promise tied to the commands and action inputs that
// actually run them, rather than to version strings copied into this test.
func TestREADMEValidationToolVersionsMatchCI(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, gate, ok := strings.Cut(string(readme), "\n## Tests\n")
	if !ok {
		t.Fatal("README.md has no `## Tests` section")
	}
	gate, _, ok = strings.Cut(gate, "\n## ")
	if !ok {
		t.Fatal("README.md's `## Tests` section never ends; the heading structure changed")
	}

	data, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("ci.yml is not valid YAML: %v", err)
	}
	lint, ok := workflow.Jobs["lint"]
	if !ok {
		t.Fatal("ci.yml has no lint job")
	}

	ciVersions := map[string][]string{}
	govulncheck := regexp.MustCompile(`(?m)^\s*go run golang\.org/x/vuln/cmd/govulncheck@(\S+)\s`)
	for _, step := range lint.Steps {
		switch {
		case strings.HasPrefix(step.Uses, "golangci/golangci-lint-action@"):
			ciVersions["golangci-lint"] = append(ciVersions["golangci-lint"], step.With["version"])
		case step.Uses == "":
			for _, match := range govulncheck.FindAllStringSubmatch(step.Run+"\n", -1) {
				ciVersions["govulncheck"] = append(ciVersions["govulncheck"], match[1])
			}
		case strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@"):
			args := strings.Fields(step.With["args"])
			if len(args) == 1 && args[0] == "check" {
				ciVersions["goreleaser"] = append(ciVersions["goreleaser"], step.With["version"])
			}
		}
	}

	for _, tool := range []struct {
		name, module string
	}{
		{"golangci-lint", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"},
		{"govulncheck", "golang.org/x/vuln/cmd/govulncheck"},
		{"goreleaser", "github.com/goreleaser/goreleaser/v2"},
	} {
		matches := regexp.MustCompile(`(?m)^\s*go run `+regexp.QuoteMeta(tool.module)+`@(\S+)\s`).FindAllStringSubmatch(gate+"\n", -1)
		if len(matches) != 1 {
			t.Errorf("README Tests gate has %d go run commands for %s, want exactly one", len(matches), tool.name)
			continue
		}
		versions := ciVersions[tool.name]
		if len(versions) != 1 {
			t.Errorf("CI lint job has %d matching %s invocations, want exactly one", len(versions), tool.name)
			continue
		}
		if matches[0][1] != versions[0] {
			t.Errorf("README Tests gate runs %s %s, but CI lint runs %s; keep the contributor gate and CI tool versions in sync", tool.name, matches[0][1], versions[0])
		}
	}
}

// The site only exists if the workflow builds and deploys it, from both of its
// sources, with the supply-chain practice the rest of this repository uses.
func TestPagesWorkflowBuildsBothSourcesAndPinsItsActions(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/pages.yml")
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)

	for _, want := range []struct{ needle, why string }{
		{".wiki.git", "the wiki is never checked out, so the explanatory pages never reach the site"},
		{"go run ./cmd/docsite -wiki", "the site is never staged from docs/ and the wiki"},
		{"go run ./cmd/docsite -verify", "a site with broken links or base paths would deploy unnoticed"},
		{"actions/jekyll-build-pages@", "nothing renders the Markdown"},
		{"actions/upload-pages-artifact@", "the built site is never handed to Pages"},
		{"actions/deploy-pages@", "nothing deploys"},
		{"gollum:", "editing a wiki page would not republish the site"},
	} {
		if !strings.Contains(workflow, want.needle) {
			t.Errorf("pages.yml has no %q: %s", want.needle, want.why)
		}
	}

	// Same pinning rule the other workflows follow: a commit SHA, with the
	// human-readable version in a trailing comment.
	pinned := regexp.MustCompile(`uses: \S+@(\S+)`)
	uses := pinned.FindAllStringSubmatch(workflow, -1)
	if len(uses) < 4 {
		t.Fatalf("found %d action uses in pages.yml; the test is not reaching the workflow", len(uses))
	}
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, m := range uses {
		if !sha.MatchString(m[1]) {
			t.Errorf("pages.yml uses %q, which is not pinned to a commit SHA", m[0])
		}
	}

	// Least privilege: read-only by default, with write scopes only on the
	// job that deploys.
	before, after, ok := strings.Cut(workflow, "\njobs:")
	if !ok {
		t.Fatal("pages.yml has no jobs block")
	}
	if !strings.Contains(before, "permissions:\n  contents: read") {
		t.Error("pages.yml does not default to contents: read")
	}
	build, deploy, ok := strings.Cut(after, "\n  deploy:")
	if !ok {
		t.Fatal("pages.yml has no deploy job")
	}
	if strings.Contains(build, "write") {
		t.Error("the build job grants a write permission; only the deploy job needs one")
	}
	for _, scope := range []string{"pages: write", "id-token: write"} {
		if !strings.Contains(deploy, scope) {
			t.Errorf("the deploy job is missing %q, which Pages deployment requires", scope)
		}
	}
	if !strings.Contains(deploy, "github.ref == 'refs/heads/main'") {
		t.Error("the deploy job does not restrict itself to main")
	}
}

// The verifier that holds every internal link, heading anchor, and base path is
// only useful before a merge, so the workflow runs on pull requests too. That
// costs a rule about the concurrency group: it is shared repository-wide, and a
// newly queued run cancels the group's previously pending run. Keyed by ref, the
// deploying events all land on refs/heads/main and still serialize against each
// other, while pull requests sit in groups of their own. Keyed by nothing, a
// busy pull request can discard a pending main deploy and leave the published
// site stale with no failure anywhere to say so.
func TestPagesWorkflowVerifiesPullRequestsWithoutContendingWithDeploys(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/pages.yml")
	if err != nil {
		t.Fatal(err)
	}
	// Pointers and raw nodes: every field here is written as an empty or false
	// value, so "absent" and "present" are otherwise the same decode.
	var workflow struct {
		On          map[string]yaml.Node `yaml:"on"`
		Concurrency struct {
			Group            string `yaml:"group"`
			CancelInProgress *bool  `yaml:"cancel-in-progress"`
		} `yaml:"concurrency"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}

	if _, ok := workflow.On["pull_request"]; !ok {
		t.Error("pages.yml does not trigger on pull_request, so a broken link or moved anchor goes green and only fails after it has merged")
	}
	// Unfiltered: the site is staged from docs/, the wiki, site/, cmd/docsite,
	// and the summaries in internal/diagnostic, and its base path comes from the
	// module path, so no subset of this repository is safe to skip. A bare
	// `pull_request:` decodes to a null scalar; any branch or path filter makes
	// it a mapping instead, which is what this rejects.
	if node, ok := workflow.On["pull_request"]; ok && node.Tag != "!!null" {
		t.Errorf("pages.yml filters the pull_request trigger with %s; any filter leaves some pull request able to break a link unchecked", node.Tag)
	}

	// The whole expression, not the substring: `github.ref_name` and
	// `github.ref_type` both contain "github.ref" and neither partitions a pull
	// request away from refs/heads/main. Surrounding text is still free.
	if !regexp.MustCompile(`\$\{\{\s*github\.ref\s*\}\}`).MatchString(workflow.Concurrency.Group) {
		t.Errorf("concurrency group is %q, which does not interpolate ${{ github.ref }}: pull request runs would share the deploying runs' group and could cancel a pending main deploy", workflow.Concurrency.Group)
	}
	if workflow.Concurrency.CancelInProgress == nil || *workflow.Concurrency.CancelInProgress {
		t.Error("concurrency cancel-in-progress is not false; a half-replaced site is worse than a late one")
	}
}
