package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The site is assembled from documents nobody edits with the site open: the
// repository docs and a separate wiki repository. What can silently rot between
// them is links, so that is what this tests. Titles, anchors, permalinks and
// metadata are the GitHub Pages plugin set's job and are not restated here.

// fixture writes a miniature repository: a Jekyll shell, two repository docs,
// three wiki pages, and two files that are linked to but never published.
func fixture(t *testing.T) (docs, wiki, shell string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("site/_config.yml", "baseurl: /network-doctor\n")
	write("docs/reference.md", "# Reference\n\nSee [scenarios](scenarios.md#authoring), the [receipt](receipt.json) and the [README](../README.md).\n")
	write("docs/scenarios.md", "# Scenarios\n\n## Authoring\n\nBody.\n")
	write("wiki/Home.md", "# Wiki\n\nStart at [Getting Started](Getting-Started).\n")
	write("wiki/Getting-Started.md", "# Getting Started\n\nBack to [Home](Home), on to [Challenge Mode](Challenge-Mode#scoring).\n")
	write("wiki/Challenge-Mode.md", "# Challenge Mode\n\n## Scoring\n\nBody.\n")
	write("wiki/_Sidebar.md", "wiki chrome\n")
	write("docs/receipt.json", "{}\n")
	write("README.md", "# Network Doctor\n")
	write("assets/hero.gif", "gif")
	write("assets/social-preview.png", "png")
	t.Chdir(root)
	return "docs", "wiki", "site"
}

func stageFixture(t *testing.T, baseurl string) string {
	t.Helper()
	docs, wiki, shell := fixture(t)
	out := filepath.Join(t.TempDir(), "_docsite")
	if err := build(baseurl, shell, docs, wiki, "assets", out); err != nil {
		t.Fatal(err)
	}
	return out
}

func read(t *testing.T, dir, rel string) string {
	t.Helper()
	// #nosec G304 -- dir is this test's own staged output and rel is a literal.
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Both halves of the documentation have to reach the site, from where they
// already live, with a way back to the one copy that is editable.
func TestStagesBothSourcesWithoutCopyingThemIntoTheRepository(t *testing.T) {
	out := stageFixture(t, "")

	for _, want := range []string{"docs/reference.md", "docs/scenarios.md", "wiki/Getting-Started.md", "wiki/Challenge-Mode.md", "assets/hero.gif"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s did not reach the staged site", want)
		}
	}
	// The wiki's hub page and the wiki UI's own chrome are not pages.
	for _, skip := range []string{"wiki/Home.md", "wiki/_Sidebar.md"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(skip))); err == nil {
			t.Errorf("%s was published; it is not a documentation page", skip)
		}
	}
	if got := read(t, out, "docs/reference.md"); !strings.Contains(got, "source: "+repoURL+"/blob/main/docs/reference.md") {
		t.Errorf("staged docs page does not point at its editable copy:\n%s", got)
	}
	if got := read(t, out, "wiki/Getting-Started.md"); !strings.Contains(got, "source: "+repoURL+"/wiki/Getting-Started/_edit") {
		t.Errorf("staged wiki page does not point at its editable copy:\n%s", got)
	}
}

// The links this step touches are the ones that name a file rather than a URL,
// or that name a file the site does not publish. Everything already usable,
// whether an absolute URL or a same-page anchor, is left exactly as written.
// This site is served from the root of its own domain, so every internal link
// it writes starts at /. The project-page form is covered separately, because
// the base path is a value read from the config rather than a constant here.
func TestRewritesOnlyTheLinksJekyllCannotResolve(t *testing.T) {
	out := stageFixture(t, "")

	for _, tc := range []struct{ file, want string }{
		{"wiki/Getting-Started.md", "[Challenge Mode](/wiki/Challenge-Mode/#scoring)"},
		{"wiki/Getting-Started.md", "[Home](/)"},
		{"docs/reference.md", "[scenarios](/docs/scenarios/#authoring)"},
		// Links out of the published pages still name the repository, which
		// moving the site to its own domain does not change.
		{"docs/reference.md", "[README](" + repoURL + "/blob/main/README.md)"},
		{"docs/reference.md", "[receipt](" + repoURL + "/blob/main/docs/receipt.json)"},
	} {
		if got := read(t, out, tc.file); !strings.Contains(got, tc.want) {
			t.Errorf("%s does not contain %q:\n%s", tc.file, tc.want, got)
		}
	}
}

// A nonempty base path still produces a project page's links, so the same
// generator keeps working for a site served under /<repo>.
func TestANonemptyBasePathStillWritesProjectPageLinks(t *testing.T) {
	out := stageFixture(t, "/network-doctor")

	for _, tc := range []struct{ file, want string }{
		// A bare wiki page name resolves against the current page on a
		// rendered site, so it becomes a site URL.
		{"wiki/Getting-Started.md", "[Challenge Mode](/network-doctor/wiki/Challenge-Mode/#scoring)"},
		// The wiki's hub page is the site's landing page.
		{"wiki/Getting-Started.md", "[Home](/network-doctor/)"},
		// A link out of docs/ names a file the site does not publish.
		{"docs/reference.md", "[README](" + repoURL + "/blob/main/README.md)"},
		// So does a sibling data file: docs/ publishes its Markdown pages,
		// and a page that cites a receipt beside them still has to link to
		// the copy the repository serves.
		{"docs/reference.md", "[receipt](" + repoURL + "/blob/main/docs/receipt.json)"},
		// A docs cross-link names a file; the site serves a URL.
		{"docs/reference.md", "[scenarios](/network-doctor/docs/scenarios/#authoring)"},
	} {
		if got := read(t, out, tc.file); !strings.Contains(got, tc.want) {
			t.Errorf("%s does not contain %q:\n%s", tc.file, tc.want, got)
		}
	}
}

// A page that names something that is not there fails the build, because the
// alternative is publishing documentation with holes in it.
func TestBrokenSourcesFailTheBuild(t *testing.T) {
	for _, tc := range []struct{ name, file, body, want string }{
		{"link to a wiki page that does not exist", "wiki/Getting-Started.md",
			"# Getting Started\n\n[gone](Removed-Page)\n", `"Removed-Page"`},
		{"link to a docs page that does not exist", "docs/reference.md",
			"# Reference\n\n[gone](removed.md)\n", "docs/removed.md"},
		{"link out of docs to a file that does not exist", "docs/reference.md",
			"# Reference\n\n[gone](../NOPE.md)\n", "does not exist"},
		{"link to a docs data file that does not exist", "docs/reference.md",
			"# Reference\n\n[gone](gone.json)\n", "does not exist"},
		{"link that escapes the repository", "docs/reference.md",
			"# Reference\n\n[out](../../etc/passwd)\n", "escapes the repository"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, wiki, shell := fixture(t)
			if err := os.WriteFile(filepath.FromSlash(tc.file), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			err := build("/network-doctor", shell, docs, wiki, "assets", filepath.Join(t.TempDir(), "out"))
			if err == nil {
				t.Fatal("the build published a document with a broken link")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The wiki is a separate repository cloned during the build. If that clone
// produced nothing, the site is not complete and must not be published.
func TestAMissingWikiFailsRatherThanPublishingHalfASite(t *testing.T) {
	docs, wiki, shell := fixture(t)
	for _, name := range []string{"Home.md", "Getting-Started.md", "Challenge-Mode.md"} {
		if err := os.Remove(filepath.Join(wiki, name)); err != nil {
			t.Fatal(err)
		}
	}
	err := build("/network-doctor", shell, docs, wiki, "assets", filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "no publishable Markdown pages") {
		t.Fatalf("an empty wiki gave %v, want a build failure", err)
	}
}

// The base path lives in the Jekyll config and nowhere else, because a link
// written against a different one is a 404 that still deploys green.
func TestBaseURLComesFromTheJekyllConfig(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		yaml, want string
		wantErr    bool
	}{
		// An empty base path is the site this repository publishes: served
		// from the root of its own domain, where there is no prefix to add.
		{yaml: `baseurl: ""` + "\n", want: ""},
		{yaml: "baseurl: /network-doctor\n", want: "/network-doctor"},
		{yaml: "baseurl: network-doctor\n", wantErr: true},
		{yaml: "baseurl: /network-doctor/\n", wantErr: true},
		// A root site is written as the empty string, not as a bare slash,
		// which Jekyll would turn into doubled slashes in every link.
		{yaml: "baseurl: /\n", wantErr: true},
		// No baseurl at all is not a root site: it is a config nobody decided.
		// A key with no value says as little, so it is rejected the same way.
		{yaml: "title: no baseurl\n", wantErr: true},
		{yaml: "baseurl:\n", wantErr: true},
	} {
		path := filepath.Join(dir, "_config.yml")
		if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readBaseURL(path)
		if tc.wantErr {
			if err == nil {
				t.Errorf("readBaseURL(%q) = %q, want an error", tc.yaml, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("readBaseURL(%q) = %q, %v, want %q", tc.yaml, got, err, tc.want)
		}
	}
}

// The base path the site actually ships with has to be one readBaseURL accepts,
// or every documentation build fails at its first step.
func TestTheRepositoryConfigIsAReadableBasePath(t *testing.T) {
	t.Chdir("../..")
	got, err := readBaseURL(filepath.Join("site", "_config.yml"))
	if err != nil {
		t.Fatalf("site/_config.yml: %v", err)
	}
	if got != "" {
		t.Errorf("site/_config.yml baseurl is %q, want \"\": the site is served from the root of networkdoctor.dev", got)
	}
}

// The navigation is hand-written, so nothing stops it naming a page that no
// longer exists. Wiki pages are checked against the built site once the wiki
// has been cloned; the repository's own docs can be checked here.
func TestNavigationCoversTheRepositoryDocs(t *testing.T) {
	t.Chdir("../..")
	data, err := os.ReadFile(filepath.Join("site", "_data", "nav.yml"))
	if err != nil {
		t.Fatal(err)
	}
	nav := string(data)
	docs, err := pageNames("docs", false)
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for _, name := range docs {
		url := "/docs/" + name + "/"
		published[url] = true
		if !strings.Contains(nav, "url: "+url+"\n") {
			t.Errorf("docs/%s.md is published but not in the navigation, so nothing on the site links to it", name)
		}
	}
	for _, line := range strings.Split(nav, "\n") {
		url, ok := strings.CutPrefix(strings.TrimSpace(line), "url: ")
		if ok && strings.HasPrefix(url, "/docs/") && !published[url] {
			t.Errorf("the navigation lists %s, which docs/ does not publish", url)
		}
	}
}
