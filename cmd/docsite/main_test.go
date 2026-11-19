package main

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
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
	write("assets/hero.mp4", "\x00mp4\xff")
	write("assets/hero-poster.png", "\x00png\xff")
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

	for _, want := range []string{"docs/reference.md", "docs/scenarios.md", "wiki/Getting-Started.md", "wiki/Challenge-Mode.md", "assets/hero.mp4", "assets/hero-poster.png", "assets/social-preview.png"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s did not reach the staged site", want)
		}
	}
	for name, want := range map[string]string{"hero.mp4": "\x00mp4\xff", "hero-poster.png": "\x00png\xff"} {
		if got := read(t, out, "assets/"+name); got != want {
			t.Errorf("%s changed during staging", name)
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

// snapshot records every entry under dir: directories as "<dir>", symlinks by
// target, files by their bytes. Comparing two snapshots proves nothing was
// created, removed or rewritten, which an existence check would not.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			got[rel] = "-> " + target
		case d.IsDir():
			got[rel] = "<dir>"
		default:
			//nolint:gosec // G122, G304: p is inside a directory this test built under t.TempDir, read-only.
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			got[rel] = string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// put writes content to path, creating its directory.
func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A -out that names a source, the shell, or a directory this tool did not
// generate is refused before the build writes anything. "unrelated" holds data,
// and "link" is a symlink to a generated site, which must not be followed.
func TestBuildRefusesOutputsItDidNotGenerate(t *testing.T) {
	for _, out := range []string{"", "docs", "wiki", "assets", "site", "unrelated", "link"} {
		t.Run(out, func(t *testing.T) {
			docs, wiki, shell := fixture(t)
			switch out {
			case "unrelated":
				put(t, filepath.Join(out, "keep.txt"), "unrelated data")
			case "link":
				put(t, filepath.Join("generated", generatedMarker), "generated")
				if err := os.Symlink("generated", out); err != nil {
					t.Skipf("cannot create a symlink: %v", err)
				}
			}
			before := snapshot(t, ".")
			if err := build("", shell, docs, wiki, "assets", out); err == nil {
				t.Fatalf("build accepted -out %q", out)
			}
			if !maps.Equal(before, snapshot(t, ".")) {
				t.Fatalf("-out %q changed the tree", out)
			}
		})
	}
}

// Go's RemoveAll deletes recursively through a path ending in "..", so naming
// the parent of the working directory would remove it. The gate must refuse
// that before anything is removed: the parent and everything in it must be
// unchanged afterward.
func TestBuildRefusesParentOfWorkingDirectory(t *testing.T) {
	docs, wiki, shell := fixture(t)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(cwd)
	put(t, filepath.Join(parent, "keep.txt"), "unrelated data")
	before := snapshot(t, parent)
	if err := build("", shell, docs, wiki, "assets", ".."); err == nil || !strings.Contains(err.Error(), "was not generated by docsite") {
		t.Fatalf("build did not refuse the parent at the gate: %v", err)
	}
	if !maps.Equal(before, snapshot(t, parent)) {
		t.Fatal("the parent of the working directory changed")
	}
}

// A marked output is removed whole. The gate accepts it because it carries the
// marker, so the build must refuse one that is or contains a source before
// removing anything. Each case moves a source under a marked output, so the
// tree changes only if the build removes it.
func TestBuildRefusesMarkedOutputThatHoldsASource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (out, shell, docs string)
	}{
		{"equal to the shell", func(t *testing.T) (string, string, string) {
			markedDir(t, "site")
			return "site", "site", "docs"
		}},
		{"contains the shell", func(t *testing.T) (string, string, string) {
			markedDir(t, "outer")
			if err := os.Rename("site", filepath.Join("outer", "site")); err != nil {
				t.Fatal(err)
			}
			return "outer", "outer/site", "docs"
		}},
		{"contains docs", func(t *testing.T) (string, string, string) {
			markedDir(t, "outer")
			if err := os.Rename("docs", filepath.Join("outer", "docs")); err != nil {
				t.Fatal(err)
			}
			return "outer", "site", "outer/docs"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, wiki, _ := fixture(t)
			out, shell, docs := tc.setup(t)
			before := snapshot(t, ".")
			if err := build("", shell, docs, wiki, "assets", out); err == nil || !strings.Contains(err.Error(), "or contains the source") {
				t.Fatalf("build did not refuse the output holding a source: %v", err)
			}
			if !maps.Equal(before, snapshot(t, ".")) {
				t.Fatal("the tree changed")
			}
		})
	}
}

// A source path that does not resolve is an error when an output exists. It must
// not be read as "nothing can be inside the output": the output would then be
// removed, and the build would fail after deleting its own media.
func TestBuildKeepsMarkedOutputWhenASourceIsMissing(t *testing.T) {
	docs, wiki, shell := fixture(t)
	markedDir(t, "assets")
	before := snapshot(t, ".")
	// The raw path, not filepath.Join, which would clean it to "assets".
	if err := build("", shell, docs, wiki, "missing/../assets", "assets"); err == nil {
		t.Fatal("build accepted a source that does not resolve")
	}
	if !maps.Equal(before, snapshot(t, ".")) {
		t.Fatal("the output was changed by a build that failed on a missing source")
	}
}

// markedDir creates dir holding only the generated marker.
func markedDir(t *testing.T, dir string) {
	t.Helper()
	put(t, filepath.Join(dir, generatedMarker), "generated")
}

// Copying the shell into a directory inside it would copy the shell into
// itself. The build must refuse every spelling of such a path, through a
// symlink or not, and leave the shell exactly as it was.
func TestBuildRefusesOutputInsideShell(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     string
		aliasTo string // when set, "alias" is a symlink to this directory
		rootRel bool
	}{
		{"relative", "site/generated", "", false},
		{"root-relative", "generated", "", true},
		{"symlink then dotdot", "alias/../site/generated", "work/child", false},
		{"symlink into shell", "alias/generated", "site/sub", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, wiki, shell := fixture(t)
			out := tc.out
			if tc.aliasTo != "" {
				if err := os.MkdirAll(tc.aliasTo, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(tc.aliasTo, "alias"); err != nil {
					t.Skipf("cannot create a symlink: %v", err)
				}
			}
			if tc.rootRel {
				abs, err := filepath.Abs(shell)
				if err != nil {
					t.Fatal(err)
				}
				out = filepath.Join(abs[len(filepath.VolumeName(abs)):], "generated")
			}
			before := snapshot(t, shell)
			err := build("", shell, docs, wiki, "assets", out)
			if err == nil || !strings.Contains(err.Error(), "inside the site shell") {
				t.Fatalf("build did not refuse -out %q inside the shell: %v", out, err)
			}
			if !maps.Equal(before, snapshot(t, shell)) {
				t.Fatalf("shell changed after -out %q", out)
			}
		})
	}
	// A missing parent inside the shell is refused by the containment check's
	// stat, before anything is created, so the error is ErrNotExist, not the
	// shell message.
	t.Run("missing parent", func(t *testing.T) {
		docs, wiki, shell := fixture(t)
		before := snapshot(t, shell)
		if err := build("", shell, docs, wiki, "assets", filepath.Join("site", "new", "generated")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("build did not refuse a missing parent: %v", err)
		}
		if !maps.Equal(before, snapshot(t, shell)) {
			t.Fatal("shell changed after a refused missing parent")
		}
	})
}

// A failed build must leave output that the next build may replace. The marker
// is written before any step that can fail, so each failure below leaves a
// generated directory, whether the output was absent, empty, or generated.
func TestBuildRetriesAfterFailedBuild(t *testing.T) {
	failures := []struct {
		name   string
		inject func(t *testing.T) (repair func())
		want   string // a fragment of the error the injected failure produces
	}{
		{"document link", func(t *testing.T) func() {
			orig := read(t, ".", "docs/reference.md")
			put(t, "docs/reference.md", "[broken](missing.md)")
			return func() { put(t, "docs/reference.md", orig) }
		}, "missing.md"},
		{"missing asset", func(t *testing.T) func() {
			orig := read(t, ".", "assets/hero.mp4")
			if err := os.Remove("assets/hero.mp4"); err != nil {
				t.Fatal(err)
			}
			return func() { put(t, "assets/hero.mp4", orig) }
		}, "hero.mp4"},
		{"shell copy", func(t *testing.T) func() {
			put(t, filepath.Join("site", generatedMarker), "a shell file named like the marker")
			return func() {
				if err := os.Remove(filepath.Join("site", generatedMarker)); err != nil {
					t.Fatal(err)
				}
			}
		}, "copy site shell"},
	}
	states := []struct {
		name  string
		setup func(t *testing.T, docs, wiki, shell, out string)
	}{
		{"absent", func(t *testing.T, docs, wiki, shell, out string) {}},
		{"empty", func(t *testing.T, docs, wiki, shell, out string) {
			if err := os.Mkdir(out, 0o750); err != nil {
				t.Fatal(err)
			}
		}},
		{"generated", func(t *testing.T, docs, wiki, shell, out string) {
			if err := build("", shell, docs, wiki, "assets", out); err != nil {
				t.Fatal(err)
			}
			put(t, filepath.Join(out, "stale.md"), "old output")
		}},
	}
	for _, f := range failures {
		for _, s := range states {
			t.Run(f.name+"/"+s.name, func(t *testing.T) {
				docs, wiki, shell := fixture(t)
				out := "_docsite"
				s.setup(t, docs, wiki, shell, out)
				repair := f.inject(t)
				if err := build("", shell, docs, wiki, "assets", out); err == nil || !strings.Contains(err.Error(), f.want) {
					t.Fatalf("injected failure did not stop the build: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(out, generatedMarker)); err != nil {
					t.Fatalf("failed build left no marker, so the next build would refuse its output: %v", err)
				}
				repair()
				if err := build("", shell, docs, wiki, "assets", out); err != nil {
					t.Fatalf("retry after the failed build was refused: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(out, "stale.md")); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("retry kept output from the earlier build: %v", err)
				}
				read(t, out, "docs/reference.md")
			})
		}
	}
}

// The gate reports a filesystem error as itself. It must not call an unreadable
// directory a foreign one, and it must leave the directory as it found it.
func TestBuildSurfacesFilesystemErrorsAtGate(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits do not restrict this process here")
	}
	for _, tc := range []struct {
		name string
		mode fs.FileMode
	}{
		{"unreadable", 0},
		{"unsearchable", 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docs, wiki, shell := fixture(t)
			out := "_docsite"
			put(t, filepath.Join(out, "keep.txt"), "unrelated data")
			if err := os.Chmod(out, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				//nolint:gosec // G302: restores a directory this test created, so the test can remove it.
				_ = os.Chmod(out, 0o750)
			})
			if err := build("", shell, docs, wiki, "assets", out); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("build did not report the permission error: %v", err)
			}
		})
	}
}

// os.CopyFS recreates symlinks, and pages are written through the copy, so a
// symlink in the shell would send a write into the source tree.
func TestBuildRejectsSymlinkInSiteShell(t *testing.T) {
	docs, wiki, shell := fixture(t)
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "reference.md")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, filepath.Join(shell, "docs")); err != nil {
		t.Skipf("cannot create a symlink: %v", err)
	}
	if err := build("", shell, docs, wiki, "assets", filepath.Join(t.TempDir(), "_docsite")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("build did not reject a symlink in the site shell: %v", err)
	}
	if got := read(t, targetDir, "reference.md"); got != "untouched" {
		t.Fatalf("staging wrote through a shell symlink: %q", got)
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
