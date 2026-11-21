package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/heymaikol/network-doctor/v2/internal/update"
)

// updateClient builds the client an update check uses. Tests replace it so no
// check opens a socket.
var updateClient = update.NewClient

// updateSchema names the JSON contract `-update-check -json` writes. The
// published schema is schema/netdoc-update-check-v1.schema.json.
const updateSchema = "netdoc.update-check.v1"

// updateCachePath is the cache beside the target history and the theme. An
// empty path means no config directory, and the check then just asks.
func updateCachePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "netdoc", "update-check")
}

// updateReport is the JSON object `-update-check -json` writes.
type updateReport struct {
	Schema     string `json:"schema"`
	Status     string `json:"status"`
	Installed  string `json:"installed"`
	Latest     string `json:"latest,omitempty"`
	ReleaseURL string `json:"release_url,omitempty"`
	CheckedAt  string `json:"checked_at,omitempty"`
	Cached     bool   `json:"cached"`
}

// runUpdateCheck answers an explicit request for the update status. The user
// asked for it directly, so it overrides the automatic-check opt-out, but it
// still obeys --no-reference-egress. It exits 0 for every answer, since no
// answer is a diagnosis.
func runUpdateCheck(setFlags map[string]bool, positional []string, jsonOut bool, stdout, stderr io.Writer) int {
	noEgress := setFlags["no-reference-egress"]
	delete(setFlags, "update-check")
	delete(setFlags, "json")
	delete(setFlags, "no-reference-egress")
	if len(positional) != 0 || len(setFlags) != 0 {
		fmt.Fprintln(stderr, "netdoc: -update-check cannot be combined with a target or other flags, except -json and -no-reference-egress")
		return 2
	}
	res := update.Check(context.Background(), updateClient(), updateCachePath(), version, time.Now(), !noEgress)
	if jsonOut {
		out := updateReport{Schema: updateSchema, Status: res.Status, Installed: res.Installed, Latest: res.Latest, ReleaseURL: res.ReleaseURL, Cached: res.Cached}
		if !res.CheckedAt.IsZero() {
			out.CheckedAt = res.CheckedAt.UTC().Format(time.RFC3339)
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}
	fmt.Fprintln(stdout, updateSentence(res))
	return 0
}

// updateSentence is the one-line human answer to an explicit check.
func updateSentence(res update.Result) string {
	switch res.Status {
	case update.UpdateAvailable:
		return fmt.Sprintf("A newer Network Doctor release is available on GitHub: %s (you have %s).\n%s", res.Latest, res.Installed, res.ReleaseURL)
	case update.UpToDate:
		return fmt.Sprintf("Network Doctor is up to date (latest stable release %s).", res.Latest)
	case update.UnknownVersion:
		return "This netdoc is not a stable release, so there is no release to compare it with."
	case update.Disabled:
		return "The update check is disabled by --no-reference-egress."
	case update.RateLimited:
		return "GitHub is limiting update checks for now; try again later."
	case update.BadResponse:
		return "GitHub's answer was not a stable release; no update was found."
	default:
		return "Could not reach GitHub to check for updates."
	}
}
