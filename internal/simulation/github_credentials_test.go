//go:build linux

package simulation

import (
	"slices"
	"strings"
	"testing"
)

// gitHubCredentialNames are the variables gh reads a token from. Every value
// these tests set is a dummy, and the tests compare names only, never values.
var gitHubCredentialNames = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// envVarNames returns the names in NAME=value entries, without the values.
func envVarNames(entries []string) []string {
	var names []string
	for _, kv := range entries {
		if name, _, ok := strings.Cut(kv, "="); ok {
			names = append(names, name)
		}
	}
	return names
}

// simEnv is the base of every node command's environment, so a node command
// must not see the launcher's GitHub credentials. Runs without namespaces.
func TestSimEnvWithholdsGitHubCredentials(t *testing.T) {
	for _, name := range gitHubCredentialNames {
		t.Setenv(name, "dummy-"+strings.ToLower(name))
	}
	t.Setenv("GH_TOKEN_FILE", "kept")
	t.Setenv("NETDOC_PROBE_LEGIT", "kept")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")
	t.Setenv("SSL_CERT_FILE", "/dummy/ca.pem")
	t.Setenv("SSL_CERT_DIR", "/dummy/certs")
	names := envVarNames(simEnv())
	for _, name := range gitHubCredentialNames {
		if slices.Contains(names, name) {
			t.Errorf("node environment carries %s", name)
		}
	}
	for _, name := range []string{"GH_TOKEN_FILE", "NETDOC_PROBE_LEGIT"} {
		if !slices.Contains(names, name) {
			t.Errorf("node environment dropped %s", name)
		}
	}
	// Proxy and trust variables are stripped as before, in any letter case.
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if slices.Contains(names, name) {
			t.Errorf("node environment carries %s, which simEnv must strip", name)
		}
	}
}
