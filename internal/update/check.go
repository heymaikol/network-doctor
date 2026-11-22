package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Endpoint is the one request an update check makes: GitHub's latest stable
// release. It carries no query, no body, and no credential.
const Endpoint = "https://api.github.com/repos/heymaikol/network-doctor/releases/latest"

// Deadline bounds one request, and TTL is how long an answer is reused before
// the next request. A failed attempt is cached for the same TTL, so offline
// use, timeouts and rate limits never cause repeated requests. An attempt the
// process abandons before it answers is asked again after interruptedRetry
// instead, so one quit cannot hide the next notice for a day.
const (
	Deadline         = 5 * time.Second
	TTL              = 24 * time.Hour
	interruptedRetry = time.Hour
	maxBody          = 64 << 10
)

// userAgent names the program without the installed version, so the request
// does not say which release is running.
const userAgent = "NetworkDoctor-update-check"

// Outcomes of one request, as cached and reported.
const (
	outcomeOK        = "ok"
	outcomeOffline   = "offline"
	outcomeRateLimit = "rate_limited"
	outcomeBad       = "bad_response"
	// outcomeInterrupted marks an attempt that had not answered when the process
	// left. It is never a verdict.
	outcomeInterrupted = "interrupted"
)

// Statuses reported for one check.
const (
	UpdateAvailable = "update_available"
	UpToDate        = "up_to_date"
	UnknownVersion  = "unknown_version"
	Disabled        = "disabled"
	Offline         = "offline"
	RateLimited     = "rate_limited"
	BadResponse     = "bad_response"
)

// NewClient returns the client a check uses. Redirects are refused, so the
// answer can only come from the endpoint it was asked of.
func NewClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Latest asks for the newest stable release and returns its tag with an
// outcome. A tag is returned only when it is "v" followed by a plain stable
// version, and the release is neither a draft nor a prerelease.
func Latest(ctx context.Context, client *http.Client) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, Deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint, nil)
	if err != nil {
		return "", outcomeBad
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", outcomeOffline
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return "", outcomeRateLimit
	default:
		return "", outcomeBad
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return "", outcomeOffline
	}
	if len(body) > maxBody {
		return "", outcomeBad
	}
	var rel struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.Unmarshal(body, &rel) != nil || rel.Draft || rel.Prerelease {
		return "", outcomeBad
	}
	if !validTag(rel.TagName) {
		return "", outcomeBad
	}
	return rel.TagName, outcomeOK
}

// validTag accepts only "v" followed by a plain stable version.
func validTag(tag string) bool {
	if !strings.HasPrefix(tag, "v") {
		return false
	}
	_, ok := ParseStable(tag)
	return ok
}

// record is what the cache file holds: when the last attempt ran, what it
// got, and the tag it found. It never holds a verdict, so a result stays
// correct after the installed version changes.
type record struct {
	CheckedAt time.Time `json:"checked_at"`
	Outcome   string    `json:"outcome"`
	Latest    string    `json:"latest,omitempty"`
}

// load reads the cache. A missing, corrupt or implausible file reads as an
// empty record, which is always stale, so it costs one request and no error.
func load(path string) record {
	var r record
	data, err := os.ReadFile(path) // #nosec G304 -- the cache is this user's own file under its config directory
	if err != nil || json.Unmarshal(data, &r) != nil {
		return record{}
	}
	switch r.Outcome {
	case outcomeOK:
		if !validTag(r.Latest) {
			return record{}
		}
	case outcomeOffline, outcomeRateLimit, outcomeBad, outcomeInterrupted:
	default:
		return record{}
	}
	return r
}

// save writes the cache. A failure only means the next run asks again.
func save(path string, r record) {
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	// Write beside the cache and rename into place, so a concurrent reader never
	// sees a truncated file. On Windows the rename can fail while another process
	// has the cache open; the old record then stays, and the next run asks again.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-check-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// staleAfter is how old a record may be before the next request, by outcome.
func staleAfter(outcome string) time.Duration {
	if outcome == outcomeInterrupted {
		return interruptedRetry
	}
	return TTL
}

// Result is one check's answer, recomputed against the installed version.
type Result struct {
	Status     string
	Installed  string
	Latest     string
	ReleaseURL string
	CheckedAt  time.Time
	Cached     bool
}

// Check answers whether a newer stable release exists than installed, for the
// automatic check. It makes no request when allow is false, when installed is
// not a stable release, or when the cache is younger than its retry interval
// (TTL, or interruptedRetry after an interrupted attempt) and not in the future.
// Otherwise it makes one request and records the attempt, success or
// failure. It never returns an error: a broken cache or an unwritable directory
// only costs the cache.
func Check(ctx context.Context, client *http.Client, cachePath, installed string, now time.Time, allow bool) Result {
	return check(ctx, client, cachePath, installed, now, allow, false)
}

// CheckNow is Check for an explicit request. A cache whose last attempt did not
// succeed (offline, rate limited, a bad answer, or an attempt that never
// finished) is asked again instead of being reused within the TTL.
func CheckNow(ctx context.Context, client *http.Client, cachePath, installed string, now time.Time, allow bool) Result {
	return check(ctx, client, cachePath, installed, now, allow, true)
}

func check(ctx context.Context, client *http.Client, cachePath, installed string, now time.Time, allow, explicit bool) Result {
	res := Result{Installed: installed}
	if !allow {
		res.Status = Disabled
		return res
	}
	if _, ok := ParseStable(installed); !ok {
		res.Status = UnknownVersion
		return res
	}
	r := load(cachePath)
	age := now.Sub(r.CheckedAt)
	if r.CheckedAt.IsZero() || age < 0 || age >= staleAfter(r.Outcome) || (explicit && r.Outcome != outcomeOK) {
		// Record the attempt before asking, as interrupted until it answers. An
		// attempt the process abandons mid-request, because the view quit first,
		// counts toward interruptedRetry rather than the TTL, so reopening does not
		// repeat it and the next notice is not held for a day.
		save(cachePath, record{CheckedAt: now, Outcome: outcomeInterrupted})
		tag, outcome := Latest(ctx, client)
		r = record{CheckedAt: now, Outcome: outcome, Latest: tag}
		save(cachePath, r)
	} else {
		res.Cached = true
	}
	res.CheckedAt = r.CheckedAt
	switch r.Outcome {
	case outcomeOK:
		res.Latest = r.Latest
		res.ReleaseURL = "https://github.com/heymaikol/network-doctor/releases/tag/" + r.Latest
		if Newer(installed, r.Latest) {
			res.Status = UpdateAvailable
		} else {
			res.Status = UpToDate
		}
	case outcomeOffline, outcomeInterrupted:
		// An interrupted attempt obtained no answer, so it reads as offline.
		res.Status = Offline
	case outcomeRateLimit:
		res.Status = RateLimited
	default:
		res.Status = BadResponse
	}
	return res
}
