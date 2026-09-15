// Command docsite stages the Jekyll source that GitHub Pages builds.
//
// The site has two content sources and neither is copied into this repository:
// docs/*.md lives here, and the explanatory half lives in the GitHub wiki,
// which is its own git repository. This command copies both into one tree and
// never writes back, so there is exactly one editable copy of every page, in
// the place it already lived.
//
// Almost everything a documentation site needs is already in the GitHub Pages
// plugin set and needs no code here: jekyll-optional-front-matter publishes
// plain Markdown, jekyll-titles-from-headings takes each page's title from its
// own H1, kramdown's GFM parser gives every heading GitHub's anchor, and
// jekyll-seo-tag and jekyll-sitemap write the metadata and the sitemap.
//
// What is left is the links, because no plugin knows this site's shape:
//
//   - wiki pages link to each other by bare page name ("Getting-Started"),
//     which a browser resolves against the current page and 404s;
//   - docs/*.md cross-links name a file, not a URL. jekyll-relative-links
//     rewrites most of them, but it matches a link on one line and this
//     documentation wraps its prose, so the ones split across a newline are
//     silently left pointing at a .md file the site does not serve;
//   - the remaining relative links in docs/ ("../README.md", or a sibling
//     data file a page cites) name files the site does not publish, and
//     belong on github.com.
//
// Those are rewritten here rather than being littered into the sources with
// environment-specific hacks, and a link that names nothing fails the build.
//
//	go run ./cmd/docsite -wiki ../network-doctor.wiki -out _docsite
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const repoURL = "https://github.com/heymaikol/network-doctor"

// wikiHome is the wiki's own hub page, whose job the site's landing page does
// with the same links. Publishing both would put two competing hubs at two
// URLs, so it is skipped and links to it land on the landing page.
const wikiHome = "Home"

func main() {
	log.SetFlags(0)
	shell := flag.String("shell", "site", "directory holding the Jekyll shell (_config.yml, layouts, landing page)")
	docsDir := flag.String("docs", "docs", "directory of repository documentation to publish")
	wikiDir := flag.String("wiki", "", "clone of the GitHub wiki repository (required)")
	assetsDir := flag.String("assets", "assets", "directory of images the site links to")
	out := flag.String("out", "_docsite", "directory to write the staged Jekyll source into")
	check := flag.String("verify", "", "instead of staging, check the built site in this directory and exit")
	flag.Parse()

	baseurl, err := readBaseURL(filepath.Join(*shell, "_config.yml"))
	if err != nil {
		log.Fatalf("docsite: %v", err)
	}
	if *check != "" {
		err = verify(*check, baseurl)
	} else if *wikiDir == "" {
		err = fmt.Errorf("-wiki is required: clone %s.wiki.git and pass the directory", repoURL)
	} else {
		err = build(baseurl, *shell, *docsDir, *wikiDir, *assetsDir, *out)
	}
	if err != nil {
		log.Fatalf("docsite: %v", err)
	}
}

func build(baseurl, shell, docsDir, wikiDir, assetsDir, out string) error {
	docs, err := pageNames(docsDir, false)
	if err != nil {
		return err
	}
	wiki, err := pageNames(wikiDir, true)
	if err != nil {
		return err
	}
	s := &stager{baseurl: baseurl, docsDir: docsDir, docs: map[string]bool{}, wiki: map[string]bool{}}
	for _, name := range docs {
		s.docs[name] = true
	}
	for _, name := range wiki {
		s.wiki[name] = true
	}

	if err := os.RemoveAll(out); err != nil {
		return err
	}
	if err := os.CopyFS(out, os.DirFS(shell)); err != nil {
		return fmt.Errorf("copy site shell %s: %w", shell, err)
	}
	// The landing page and the social card reuse the images the README already
	// ships; copying beats a second checked-in copy.
	for _, name := range []string{"hero.gif", "social-preview.png"} {
		if err := copyFile(filepath.Join(assetsDir, name), filepath.Join(out, "assets", name)); err != nil {
			return err
		}
	}

	for _, name := range docs {
		src := filepath.Join(docsDir, name+".md")
		if err := s.stage("docs", src, filepath.Join(out, "docs", name+".md"),
			repoURL+"/blob/main/"+filepath.ToSlash(docsDir)+"/"+name+".md"); err != nil {
			return err
		}
	}
	for _, name := range wiki {
		src := filepath.Join(wikiDir, name+".md")
		if err := s.stage("wiki", src, filepath.Join(out, "wiki", name+".md"),
			repoURL+"/wiki/"+name+"/_edit"); err != nil {
			return err
		}
	}
	return nil
}

// readBaseURL keeps the site's base path in exactly one place: the Jekyll
// config. Every link this command writes is built from what Jekyll is
// configured to serve, so the two cannot drift apart.
//
// Two shapes are valid. An empty baseurl is a site served from the root of its
// own domain, which is what this site's custom domain gives it; a nonempty one
// is a project page under github.io, served from /<repo>. What stays invalid is
// a config with no baseurl at all, because then nobody decided which of the two
// this is, and a malformed nonempty path, because it deploys green as a site of
// 404s.
func readBaseURL(configPath string) (string, error) {
	// #nosec G304 -- configPath is the site shell's own config, from a flag this build tool is run with.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg struct {
		// A pointer so a missing key is distinguishable from baseurl: "",
		// which is now a meaningful value rather than the zero one.
		Baseurl *string `yaml:"baseurl"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", fmt.Errorf("%s: %w", configPath, err)
	}
	if cfg.Baseurl == nil {
		return "", fmt.Errorf(`%s: no baseurl: set "" for a site at its own domain root, or /<repo> for a project page`, configPath)
	}
	base := *cfg.Baseurl
	if base != "" && (!strings.HasPrefix(base, "/") || strings.HasSuffix(base, "/")) {
		return "", fmt.Errorf(`%s: baseurl %q is neither "" for a domain root nor a base path such as /network-doctor`, configPath, base)
	}
	return base, nil
}

// pageNames lists the Markdown pages a source directory publishes, without
// their extension. Files starting with an underscore are the wiki UI's own
// chrome (_Sidebar, _Footer), which the site has a layout for.
func pageNames(dir string, isWiki bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".md" || strings.HasPrefix(name, "_") {
			continue
		}
		if name = strings.TrimSuffix(name, ".md"); isWiki && name == wikiHome {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no publishable Markdown pages; the source is empty or was not checked out", dir)
	}
	return names, nil
}

type stager struct {
	baseurl string
	docsDir string
	docs    map[string]bool
	wiki    map[string]bool
}

var linkRE = regexp.MustCompile(`\]\(([^)\s]+)\)`)

// stage copies one document, rewriting the links that would not resolve on the
// site and adding the front matter that points an editor at the one copy of
// the page that is editable.
func (s *stager) stage(section, src, dst, source string) error {
	// #nosec G304 -- src is a Markdown file this tool just enumerated in the documentation directories it was pointed at.
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	var bad error
	body := linkRE.ReplaceAllStringFunc(strings.ReplaceAll(string(data), "\r\n", "\n"), func(m string) string {
		target := linkRE.FindStringSubmatch(m)[1]
		fixed, err := s.fixLink(section, target)
		if err != nil && bad == nil {
			bad = fmt.Errorf("%s: %w", src, err)
		}
		return "](" + fixed + ")"
	})
	if bad != nil {
		return bad
	}
	return writeFile(dst, "---\nsource: "+source+"\n---\n\n"+body)
}

// fixLink maps one link target onto the published site. A same-page anchor, an
// absolute URL to anywhere else, and anything already rooted at the site are
// returned exactly as written.
func (s *stager) fixLink(section, target string) (string, error) {
	link, frag, _ := strings.Cut(target, "#")

	// Links written for GitHub's rendering of the other half of the
	// documentation. Keeping them inside the site is what makes the two halves
	// one site rather than two.
	if name, ok := strings.CutPrefix(link, repoURL+"/wiki/"); ok {
		return s.wikiLink(strings.TrimSuffix(name, "/"), frag)
	}
	if name, ok := strings.CutPrefix(link, repoURL+"/blob/main/"+filepath.ToSlash(s.docsDir)+"/"); ok {
		if name = strings.TrimSuffix(name, ".md"); s.docs[name] {
			return s.docsLink(name, frag)
		}
	}
	switch {
	case link == "", strings.Contains(link, ":"), strings.HasPrefix(link, "/"):
		return target, nil

	// A bare wiki page name: no slash, no extension. This is how every wiki
	// page links to its neighbours, and how none of them can link on a site.
	case section == "wiki" && !strings.Contains(link, "/") && path.Ext(link) == "":
		return s.wikiLink(link, frag)

	// A docs/*.md cross-link names a file; the site serves a URL.
	case section == "docs" && !strings.Contains(link, "/") && path.Ext(link) == ".md":
		return s.docsLink(strings.TrimSuffix(link, ".md"), frag)

	// Any other relative link from docs/. It names a repository file rather
	// than a published page: something above docs/, or a sibling that is not
	// one of its Markdown pages, such as a data file a page cites. The site
	// does not serve those, so they go to the repository, where the file is
	// authoritative.
	case section == "docs":
		rel := path.Clean(path.Join(filepath.ToSlash(s.docsDir), link))
		if strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("link %q escapes the repository", target)
		}
		info, err := os.Stat(rel)
		if err != nil {
			return "", fmt.Errorf("link %q resolves to %s, which does not exist", target, rel)
		}
		kind := "blob"
		if info.IsDir() {
			kind = "tree"
		}
		return withFragment(repoURL+"/"+kind+"/main/"+rel, frag), nil
	}
	return target, nil
}

func (s *stager) docsLink(name, frag string) (string, error) {
	if !s.docs[name] {
		return "", fmt.Errorf("link to %s/%s.md, which the site does not publish", s.docsDir, name)
	}
	return withFragment(s.baseurl+"/docs/"+name+"/", frag), nil
}

func (s *stager) wikiLink(name, frag string) (string, error) {
	if name == wikiHome {
		return withFragment(s.baseurl+"/", frag), nil
	}
	if !s.wiki[name] {
		return "", fmt.Errorf("link to wiki page %q, which the site does not publish", name)
	}
	return withFragment(s.baseurl+"/wiki/"+name+"/", frag), nil
}

func withFragment(url, frag string) string {
	if frag == "" {
		return url
	}
	return url + "#" + frag
}

// writeFile writes a file of a static website. World-readable is the point:
// the Jekyll build and the artifact upload that follow run as other users.
func writeFile(dst, content string) error {
	// #nosec G301 -- a published site directory is readable by everyone by design.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	// #nosec G306 G703 -- dst is built from this tool's own output flag; a published site file is readable by everyone by design.
	return os.WriteFile(dst, []byte(content), 0o644)
}

func copyFile(src, dst string) error {
	// #nosec G304 -- src is an image path from this tool's own fixed list, under the assets flag.
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFile(dst, string(data))
}
