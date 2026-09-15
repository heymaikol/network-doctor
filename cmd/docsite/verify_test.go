package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// builtSite writes a minimal rendered site: a landing page, one document, and a
// stylesheet, all at base, plus the files a crawler needs. base is "" for a site
// served from the root of its own domain and /<repo> for a github.io project
// page, and every link in here is written the way that site would write it.
func builtFixture(t *testing.T, base string, pages map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	all := map[string]string{
		"index.html":                      `<link href="` + base + `/assets/style.css"><a href="` + base + `/wiki/Getting-Started/">Start</a>`,
		"wiki/Getting-Started/index.html": `<h1 id="getting-started">Start</h1><a href="` + base + `/">Home</a>`,
		"assets/style.css":                "body{}\n",
		"sitemap.xml":                     `<urlset/>`,
		"robots.txt":                      "User-agent: *\n",
	}
	for path, content := range pages {
		all[path] = content
	}
	for path, content := range all {
		if err := writeFile(filepath.Join(dir, filepath.FromSlash(path)), content); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Both shapes of site verify: the root of a custom domain, which is what this
// project publishes, and a project page under a base path.
func TestVerifyAcceptsAWorkingSite(t *testing.T) {
	for _, base := range []string{"", "/network-doctor"} {
		t.Run("baseurl "+base, func(t *testing.T) {
			if err := verify(builtFixture(t, base, nil), base); err != nil {
				t.Fatalf("a working site failed verification: %v", err)
			}
		})
	}
}

// Each case is breakage that only exists once the site is rendered, which is
// why it is checked against the built bytes rather than the sources.
func TestVerifyRejectsASiteThatWouldNotWork(t *testing.T) {
	for _, tc := range []struct {
		name, base, path, content, want string
	}{
		{
			// The failure mode of a project page: an absolute link
			// without the base path goes to the account's root site.
			name: "link that dropped the project base path", base: "/network-doctor",
			path: "index.html", content: `<a href="/wiki/Getting-Started/">Start</a>`,
			want: "missing the /network-doctor base path",
		},
		{
			name: "asset that dropped the project base path", base: "/network-doctor",
			path: "index.html", content: `<link href="/assets/style.css">`,
			want: "missing the /network-doctor base path",
		},
		{
			// The failure mode of the move to a custom domain: a link left
			// over from the project page prefixes a path the root site has
			// nothing at.
			name: "link still carrying the old project base path", base: "",
			path: "index.html", content: `<a href="/network-doctor/wiki/Getting-Started/">Start</a>`,
			want: "which the site does not serve",
		},
		{
			name: "asset still carrying the old project base path", base: "",
			path: "index.html", content: `<link href="/network-doctor/assets/style.css">`,
			want: "which the site does not serve",
		},
		{
			name: "link to a page the site never built", base: "/network-doctor",
			path: "index.html", content: `<a href="/network-doctor/wiki/Retired/">Gone</a>`,
			want: "which the site does not serve",
		},
		{
			name: "link to an anchor that moved", base: "",
			path: "index.html", content: `<a href="/wiki/Getting-Started/#renamed">Gone</a>`,
			want: "not an id on that page",
		},
		{
			name: "same-page anchor that does not exist", base: "",
			path: "index.html", content: `<a href="#nowhere">Skip</a>`,
			want: "not an id on this page",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verify(builtFixture(t, tc.base, map[string]string{tc.path: tc.content}), tc.base)
			if err == nil {
				t.Fatal("verification passed; the site would have deployed broken")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain %q", err, tc.want)
			}
		})
	}
}

// robots.txt is the crawler policy for the whole domain now that the site is
// served from its root, and the site's default layout would turn it into a web
// page no crawler can read.
func TestVerifyRejectsCrawlerFilesRenderedAsPages(t *testing.T) {
	for _, plain := range []string{"robots.txt", "sitemap.xml"} {
		t.Run(plain, func(t *testing.T) {
			dir := builtFixture(t, "", map[string]string{plain: "<!doctype html>\n<html><body>policy</body></html>"})
			err := verify(dir, "")
			if err == nil || !strings.Contains(err.Error(), "layout: none") {
				t.Fatalf("verify with %s rendered as a page returned %v, want a failure naming the fix", plain, err)
			}
		})
	}
}

func TestVerifyRejectsAnIncompleteBuild(t *testing.T) {
	for _, missing := range []string{"sitemap.xml", "robots.txt", "index.html"} {
		t.Run("no "+missing, func(t *testing.T) {
			dir := builtFixture(t, "", nil)
			if err := os.Remove(filepath.Join(dir, missing)); err != nil {
				t.Fatal(err)
			}
			err := verify(dir, "")
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("verify without %s returned %v, want a failure naming it", missing, err)
			}
		})
	}
}
