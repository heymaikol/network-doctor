package simulation

import (
	"os"
	"slices"
	"strings"
)

// gitHubCredentialVars are the variables gh reads a token from. Only the
// launcher's own gh call needs one (realGH). No simulator child does, and a
// child that inherits one can read it.
var gitHubCredentialVars = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// ChildEnv is the environment the simulator's child processes are started with:
// the launcher's environment without the GitHub credentials. A command started
// with no environment set inherits all of them, so starts set Env from here.
// The tc -V version probe is the one exception; it takes no credential and
// inherits its director's filtered environment. Values passed explicitly to
// Exec and ExecInteractive are appended
// after it, unfiltered; callers build those from scenario data, never from the
// host environment.
func ChildEnv() []string {
	return withoutCredentials(os.Environ())
}

// withoutCredentials drops entries whose name is a credential variable. Names
// match case-insensitively, as Windows matches them, so a near miss such as
// GH_TOKEN_FILE is kept. The result is never nil: a nil Env means inherit
// everything.
func withoutCredentials(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.ContainsFunc(gitHubCredentialVars, func(v string) bool { return strings.EqualFold(v, name) }) {
			out = append(out, kv)
		}
	}
	return out
}
