package main

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// verify reads the site Jekyll actually produced and fails on the breakage that
// only exists after rendering: a link to a page Jekyll never wrote, a heading
// anchor that moved, or an href written against the wrong base path, which
// would 404 for every visitor. This site is served from the root of its own
// domain, so its base path is empty and every absolute link is already in the
// site; the base path check still holds a project page under github.io, where
// an href that forgot /<repo> lands on the account's root site.
//
// This is the site's link check. Staging deliberately rewrites only what it
// must and leaves the rest to the GitHub Pages plugins, so this pass, not the
// staging code, is what proves the published bytes hang together.
func verify(dir, baseurl string) error {
	pages, err := readSite(dir, baseurl)
	if err != nil {
		return err
	}
	for _, required := range []string{"/index.html", "/sitemap.xml", "/robots.txt"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(required))); err != nil {
			return fmt.Errorf("%s: the build produced no %s", dir, required)
		}
	}
	// robots.txt and the sitemap are read by crawlers, not browsers. Both are
	// pages in the source tree, so the site's default layout will wrap either
	// one in the navigation chrome unless it opts out, and a robots.txt that
	// is a web page is a robots.txt no crawler can read. At the root of its own
	// domain this is the policy for the whole site, rather than a decorative
	// copy under a project page that no crawler ever asked for.
	for _, plain := range []string{"/robots.txt", "/sitemap.xml"} {
		// #nosec G304 -- plain is from this fixed list, under the built site directory.
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(plain)))
		if err != nil {
			return err
		}
		if head := strings.TrimSpace(string(data)); strings.HasPrefix(strings.ToLower(head), "<!doctype html") {
			return fmt.Errorf("%s: %s was rendered as an HTML page; it needs layout: none in its front matter", dir, plain)
		}
	}
	var problems []string
	for _, url := range sortedKeys(pages.ids) {
		for _, ref := range pages.refs[url] {
			if err := pages.check(url, ref); err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", url, err))
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		return fmt.Errorf("%s: %d broken references in the built site:\n  %s", dir, len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

type builtSite struct {
	baseurl string
	// served maps every URL path the site answers to true.
	served map[string]bool
	// ids maps an HTML page's URL to the anchors it defines.
	ids  map[string]map[string]bool
	refs map[string][]string
}

var (
	refRE = regexp.MustCompile(`(?:href|src)="([^"]+)"`)
	idRE  = regexp.MustCompile(`\bid="([^"]+)"`)
)

func readSite(dir, baseurl string) (*builtSite, error) {
	s := &builtSite{
		baseurl: baseurl,
		served:  map[string]bool{},
		ids:     map[string]map[string]bool{},
		refs:    map[string][]string{},
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(p, dir))
		url := baseurl + "/" + strings.TrimPrefix(rel, "/")
		s.served[url] = true
		if !strings.HasSuffix(url, ".html") {
			return nil
		}
		// A directory index is served at the directory URL, which is the
		// URL every generated link uses.
		url = strings.TrimSuffix(url, "index.html")
		s.served[url] = true

		// #nosec G304 G122 -- p is a file this walk just found under the built site directory.
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		text := string(data)
		ids := map[string]bool{}
		for _, m := range idRE.FindAllStringSubmatch(text, -1) {
			ids[m[1]] = true
		}
		s.ids[url] = ids
		for _, m := range refRE.FindAllStringSubmatch(text, -1) {
			s.refs[url] = append(s.refs[url], m[1])
		}
		return nil
	})
	return s, err
}

func (s *builtSite) check(from, ref string) error {
	switch {
	case ref == "", strings.Contains(ref, "://"), strings.HasPrefix(ref, "mailto:"),
		strings.HasPrefix(ref, "data:"), strings.HasPrefix(ref, "#"):
		if strings.HasPrefix(ref, "#") && !s.ids[from][strings.TrimPrefix(ref, "#")] {
			return fmt.Errorf("link to %s, which is not an id on this page", ref)
		}
		return nil
	}

	target, frag, _ := strings.Cut(ref, "#")
	if strings.HasPrefix(target, "/") {
		// A project page is served under its base path. An absolute link
		// without it resolves to the account's root site, not this one. At a
		// domain root the base path is empty and this check passes everything,
		// which is correct: there is no prefix to forget.
		if target != s.baseurl && !strings.HasPrefix(target, s.baseurl+"/") {
			return fmt.Errorf("link %q is missing the %s base path", ref, s.baseurl)
		}
	} else {
		target = path.Join(from, target)
	}
	if !s.served[target] && !s.served[strings.TrimSuffix(target, "/")+"/"] {
		return fmt.Errorf("link %q resolves to %s, which the site does not serve", ref, target)
	}
	if frag != "" {
		ids, ok := s.ids[target]
		if !ok {
			ids = s.ids[strings.TrimSuffix(target, "/")+"/"]
		}
		if ids != nil && !ids[frag] {
			return fmt.Errorf("link %q points at #%s, which is not an id on that page", ref, frag)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
