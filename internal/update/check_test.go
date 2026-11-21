//nolint:bodyclose // every response here is built in memory by the stub and read through the client; no body is left open
package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stub answers requests in place of the network, so no test opens a socket.
type stub struct {
	calls atomic.Int32
	do    func(*http.Request) (*http.Response, error)
}

func (s *stub) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return s.do(req)
}

func (s *stub) client() *http.Client {
	return &http.Client{Transport: s, CheckRedirect: NewClient().CheckRedirect}
}

func reply(code int, body string) func(*http.Request) (*http.Response, error) {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: code,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
}

func release(tag string, draft, prerelease bool) string {
	b, _ := json.Marshal(map[string]any{"tag_name": tag, "draft": draft, "prerelease": prerelease})
	return string(b)
}

func TestLatestReadsTheStableTag(t *testing.T) {
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	tag, outcome := Latest(context.Background(), s.client())
	if tag != "v2.3.0" || outcome != outcomeOK {
		t.Fatalf("Latest = %q, %q; want v2.3.0, ok", tag, outcome)
	}
}

// Every way an answer can be unusable maps to an outcome that notifies nobody.
func TestLatestOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		do      func(*http.Request) (*http.Response, error)
		outcome string
	}{
		{"rate limited 403", reply(403, "{}"), outcomeRateLimit},
		{"rate limited 429", reply(429, "{}"), outcomeRateLimit},
		{"not found", reply(404, "{}"), outcomeBad},
		{"server error", reply(500, "{}"), outcomeBad},
		{"malformed JSON", reply(200, "{not json"), outcomeBad},
		{"oversized body", reply(200, `{"tag_name":"v2.3.0","pad":"`+strings.Repeat("x", maxBody)+`"}`), outcomeBad},
		{"prerelease", reply(200, release("v2.3.0", false, true)), outcomeBad},
		{"draft", reply(200, release("v2.3.0", true, false)), outcomeBad},
		{"tag without v", reply(200, release("2.3.0", false, false)), outcomeBad},
		{"prerelease tag", reply(200, release("v2.3.0-rc.1", false, false)), outcomeBad},
		{"control and bidi in tag", reply(200, release("v2.3.0\u202e", false, false)), outcomeBad},
		{"transport failure", func(*http.Request) (*http.Response, error) {
			return nil, io.ErrUnexpectedEOF
		}, outcomeOffline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stub{do: tc.do}
			tag, outcome := Latest(context.Background(), s.client())
			if outcome != tc.outcome || tag != "" {
				t.Fatalf("Latest = %q, %q; want \"\", %q", tag, outcome, tc.outcome)
			}
		})
	}
}

// A request that never answers ends at the caller's deadline, not at some
// later time, so a slow GitHub cannot hold the program open.
func TestLatestIsBoundedByTheCallersDeadline(t *testing.T) {
	s := &stub{do: func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, outcome := Latest(ctx, s.client())
	if outcome != outcomeOffline {
		t.Fatalf("outcome = %q, want offline", outcome)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("the request outlived its deadline by %v", took)
	}
}

// The TUI passes a background context, so the request's own bound is the only
// thing that stops a stuck answer from running forever. The request must carry
// a deadline no later than Deadline.
func TestLatestBoundsRequestsWithoutACallerDeadline(t *testing.T) {
	bounded := false
	s := &stub{do: func(req *http.Request) (*http.Response, error) {
		dl, ok := req.Context().Deadline()
		bounded = ok && time.Until(dl) <= Deadline
		return reply(200, release("v2.3.0", false, false))(req)
	}}
	Latest(context.Background(), s.client())
	if !bounded {
		t.Fatal("a request made with a background context has no deadline of its own")
	}
}

// Negative control for the client: without refusing redirects, the stub would
// be asked a second time at the redirect target.
func TestRedirectsAreRefused(t *testing.T) {
	s := &stub{do: func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://example.invalid/elsewhere"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}}
	_, outcome := Latest(context.Background(), s.client())
	if outcome != outcomeBad {
		t.Fatalf("outcome = %q, want bad_response", outcome)
	}
	if n := s.calls.Load(); n != 1 {
		t.Fatalf("the redirect was followed: %d requests", n)
	}
}

// The request sends only what the endpoint needs: a GET, no query, no body,
// no credential, and a user agent that does not name the installed version.
func TestRequestShape(t *testing.T) {
	var seen *http.Request
	s := &stub{do: func(req *http.Request) (*http.Response, error) {
		seen = req
		return reply(200, release("v2.3.0", false, false))(req)
	}}
	Latest(context.Background(), s.client())
	if seen == nil {
		t.Fatal("no request was made")
	}
	if seen.Method != http.MethodGet || seen.URL.String() != Endpoint {
		t.Fatalf("request = %s %s, want GET %s", seen.Method, seen.URL, Endpoint)
	}
	if seen.URL.RawQuery != "" || (seen.Body != nil && seen.Body != http.NoBody) {
		t.Fatalf("request carries a query or body: %s", seen.URL)
	}
	for _, h := range []string{"Authorization", "Cookie"} {
		if seen.Header.Get(h) != "" {
			t.Fatalf("request carries %s", h)
		}
	}
	if ua := seen.Header.Get("User-Agent"); ua != userAgent || strings.ContainsAny(ua, "0123456789") {
		t.Fatalf("User-Agent = %q, want the generic name without a version", ua)
	}
}

// cachePath is a cache file in a fresh directory.
func cachePath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "netdoc", "update-check")
}

// The notice comes from the cache and the installed version, computed fresh
// on every call.
func TestCheckComputesTheVerdictFromTheCache(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, installed string
		want            string
	}{
		{"older install is told", "2.2.1", UpdateAvailable},
		{"current install is not", "2.3.0", UpToDate},
		{"newer install is not", "2.4.0", UpToDate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := cachePath(t)
			save(path, record{CheckedAt: now.Add(-time.Hour), Outcome: outcomeOK, Latest: "v2.3.0"})
			s := &stub{do: reply(500, "")}
			res := Check(context.Background(), s.client(), path, tc.installed, now, true)
			if res.Status != tc.want || !res.Cached {
				t.Fatalf("status = %q cached=%v, want %q from the cache", res.Status, res.Cached, tc.want)
			}
			if n := s.calls.Load(); n != 0 {
				t.Fatalf("a fresh cache still made %d requests", n)
			}
		})
	}
}

// Negative control: a cache written before an upgrade does not notify the
// upgraded install, because the verdict is recomputed and never stored.
func TestCheckDoesNotNoticeAnAlreadyInstalledRelease(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now.Add(-time.Hour), Outcome: outcomeOK, Latest: "v2.3.0"})
	res := Check(context.Background(), (&stub{do: reply(500, "")}).client(), path, "v2.3.0", now, true)
	if res.Status == UpdateAvailable {
		t.Fatalf("status = %q after the upgrade to the latest release", res.Status)
	}
}

// Stale and absent caches are refreshed, one request each, and the new
// attempt is recorded.
func TestCheckRefreshesAStaleCache(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now.Add(-TTL - time.Minute), Outcome: outcomeOK, Latest: "v2.2.1"})
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	res := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if res.Status != UpdateAvailable || res.Cached {
		t.Fatalf("status = %q cached=%v, want a fresh update_available", res.Status, res.Cached)
	}
	if n := s.calls.Load(); n != 1 {
		t.Fatalf("a stale cache made %d requests, want 1", n)
	}
	if r := load(path); r.Latest != "v2.3.0" || !r.CheckedAt.Equal(now) {
		t.Fatalf("the attempt was not recorded: %+v", r)
	}
}

// A failed attempt is cached for the TTL too: offline, rate limited, or a bad
// answer produces no further request until the TTL passes.
func TestFailedAttemptIsNotRepeatedWithinTheTTL(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	s := &stub{do: reply(429, "{}")}
	first := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if first.Status != RateLimited {
		t.Fatalf("first status = %q, want rate_limited", first.Status)
	}
	again := Check(context.Background(), s.client(), path, "2.2.1", now.Add(time.Hour), true)
	if again.Status != RateLimited || !again.Cached {
		t.Fatalf("second status = %q cached=%v, want the cached failure", again.Status, again.Cached)
	}
	if n := s.calls.Load(); n != 1 {
		t.Fatalf("a failed attempt was repeated: %d requests", n)
	}
	s.do = reply(200, release("v2.3.0", false, false))
	after := Check(context.Background(), s.client(), path, "2.2.1", now.Add(TTL), true)
	if after.Status != UpdateAvailable || s.calls.Load() != 2 {
		t.Fatalf("after the TTL: status %q, requests %d; want a fresh attempt", after.Status, s.calls.Load())
	}
}

// Negative controls: each gate makes no request at all.
func TestNoRequestWhenDisabledOrUnknown(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name, installed string
		allow           bool
		want            string
	}{
		{"opted out", "2.2.1", false, Disabled},
		{"development build", "dev", true, UnknownVersion},
		{"module pseudo-version", "v2.2.2-0.20261120012900-e88e9b22d6f3", true, UnknownVersion},
		{"dirty build", "2.2.1+dirty", true, UnknownVersion},
		{"prerelease install", "2.3.0-rc.1", true, UnknownVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stub{do: reply(200, release("v9.9.9", false, false))}
			res := Check(context.Background(), s.client(), cachePath(t), tc.installed, now, tc.allow)
			if res.Status != tc.want {
				t.Fatalf("status = %q, want %q", res.Status, tc.want)
			}
			if n := s.calls.Load(); n != 0 {
				t.Fatalf("made %d requests", n)
			}
		})
	}
}

// A corrupt cache reads as stale, one request refreshes it, and no error
// reaches the caller.
func TestCorruptCacheIsRefreshedQuietly(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	res := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if res.Status != UpdateAvailable || s.calls.Load() != 1 {
		t.Fatalf("status %q, requests %d; want one request and update_available", res.Status, s.calls.Load())
	}
}

// A cache holding a tag that is not a stable release is not trusted.
func TestImplausibleCacheIsNotTrusted(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now, Outcome: outcomeOK, Latest: "v9.9.9\u202e"})
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	res := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if res.Latest == "v9.9.9\u202e" || s.calls.Load() != 1 {
		t.Fatalf("the implausible cache was used: latest %q, requests %d", res.Latest, s.calls.Load())
	}
}

// A clock that moved backwards does not freeze the cache: a future timestamp
// is treated as stale.
func TestFutureTimestampIsStale(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now.Add(48 * time.Hour), Outcome: outcomeOK, Latest: "v2.3.0"})
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if s.calls.Load() != 1 {
		t.Fatalf("a future timestamp was trusted: %d requests", s.calls.Load())
	}
}

// An unwritable cache location costs the cache only: the answer still comes
// back, and the caller sees no error.
func TestUnwritableCacheStillAnswers(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "netdoc", "update-check")
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	res := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if res.Status != UpdateAvailable {
		t.Fatalf("status = %q, want update_available despite the unwritable cache", res.Status)
	}
}

// A cache with an outcome this version does not know is not trusted, so it
// costs one request like any other unreadable cache.
func TestUnknownCachedOutcomeIsStale(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now, Outcome: "from_the_future", Latest: ""})
	s := &stub{do: reply(200, release("v2.3.0", false, false))}
	res := Check(context.Background(), s.client(), path, "2.2.1", now, true)
	if res.Cached || s.calls.Load() != 1 {
		t.Fatalf("an unknown outcome was trusted: cached=%v requests=%d", res.Cached, s.calls.Load())
	}
}

// The cache is read while another process rewrites it. A successful read must
// see the old record or the new one, never a truncated file that reads as
// corrupt, because that would cost an extra request.
func TestCacheReadsNeverSeeAPartialWrite(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	save(path, record{CheckedAt: now, Outcome: outcomeOK, Latest: "v2.3.0"})
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
				save(path, record{CheckedAt: now, Outcome: outcomeOK, Latest: "v2.3.0"})
			}
		}
	}()
	defer func() {
		close(stop)
		<-writerDone
	}()
	reads := 0
	for i := 0; i < 2000; i++ {
		// A read can fail outright while a replace holds the file (a Windows sharing
		// violation). That is not a partial record; a successful read of truncated or
		// empty content is the failure this test exists to catch.
		data, err := os.ReadFile(path) // #nosec G304 -- the test's own cache file under a temporary directory
		if err != nil {
			continue
		}
		reads++
		var r record
		if json.Unmarshal(data, &r) != nil || r.Outcome != outcomeOK {
			t.Fatalf("read %d saw a partial record: %q", i, data)
		}
	}
	if reads == 0 {
		t.Fatal("no read of the cache succeeded")
	}
}

// An attempt the process abandons mid-request, because the view quit first,
// still counts toward the TTL. The attempt never returns here, which is what a
// quit looks like: the cache must already say an attempt happened.
func TestAbandonedAttemptIsNotRepeated(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	path := cachePath(t)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	// The abandoned Check is released and waited for before the directory is
	// removed, so its last write cannot race the cleanup.
	t.Cleanup(func() { close(release); <-done })
	var once sync.Once
	s := &stub{do: func(*http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		<-release
		return nil, io.ErrUnexpectedEOF
	}}
	go func() {
		Check(context.Background(), s.client(), path, "2.2.1", now, true)
		close(done)
	}()
	<-started
	if r := load(path); !r.CheckedAt.Equal(now) {
		t.Fatalf("the attempt is not recorded while it is in flight: %+v", r)
	}
	again := Check(context.Background(), s.client(), path, "2.2.1", now.Add(time.Minute), true)
	if n := s.calls.Load(); n != 1 {
		t.Fatalf("an abandoned attempt was repeated: %d requests, want 1", n)
	}
	if again.Status != Offline || !again.Cached {
		t.Fatalf("reopening reported %q cached=%v, want the cached attempt", again.Status, again.Cached)
	}
}
