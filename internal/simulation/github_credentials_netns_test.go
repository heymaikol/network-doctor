//go:build netns_integration && linux

package simulation

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// githubCredentialProbe is set only on the copy of this test binary that
// TestSimulatorChildrenWithholdGitHubCredentials launches as its director.
var githubCredentialProbe = flag.String("github-credential-probe", "", "internal: run the GitHub credential probe director and write its findings to this file")

// credentialProbe lists, for each process context, the variable names it saw.
// Names only: the probe never records a value.
type credentialProbe struct {
	Director    []string `json:"director"`
	Holder      []string `json:"holder"`
	Exec        []string `json:"exec"`
	Interactive []string `json:"interactive"`
}

// The launcher sets GitHub credentials and a legitimate variable, then starts
// a real director in a real namespace. The director records the variable names
// its own process, a namespace holder, an Exec command and an interactive
// command each see.
func TestSimulatorChildrenWithholdGitHubCredentials(t *testing.T) {
	if *githubCredentialProbe != "" {
		directGitHubCredentialProbe(t, *githubCredentialProbe)
		return
	}
	requireBackend(t)
	for _, name := range gitHubCredentialNames {
		t.Setenv(name, "dummy-"+strings.ToLower(name))
	}
	t.Setenv("NETDOC_PROBE_LEGIT", "kept")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "probe.json")
	var log bytes.Buffer
	code, err := LaunchDirector(context.Background(), self, []string{
		"-test.run=^TestSimulatorChildrenWithholdGitHubCredentials$", "-github-credential-probe=" + out,
	}, nil, &log, &log)
	if err != nil || code != 0 {
		t.Fatalf("director exit %d (%v):\n%s", code, err, log.String())
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var probe credentialProbe
	if err := json.Unmarshal(blob, &probe); err != nil {
		t.Fatal(err)
	}
	contexts := []struct {
		name  string
		names []string
	}{
		{"director", probe.Director}, {"holder", probe.Holder},
		{"exec", probe.Exec}, {"interactive", probe.Interactive},
	}
	for _, c := range contexts {
		for _, token := range gitHubCredentialNames {
			if slices.Contains(c.names, token) {
				t.Errorf("%s inherited %s", c.name, token)
			}
		}
		if !slices.Contains(c.names, "NETDOC_PROBE_LEGIT") {
			t.Errorf("%s lost NETDOC_PROBE_LEGIT", c.name)
		}
	}
	// Proxy handling is unchanged: the launcher still hands the director its
	// proxy, and node commands still strip it.
	if !slices.Contains(probe.Director, "HTTPS_PROXY") {
		t.Error("director lost HTTPS_PROXY")
	}
	for _, c := range contexts[2:] {
		if slices.Contains(c.names, "HTTPS_PROXY") {
			t.Errorf("%s inherited HTTPS_PROXY", c.name)
		}
	}
	if !slices.Contains(probe.Exec, "NETDOC_PROBE_EXPLICIT") || !slices.Contains(probe.Interactive, "NETDOC_PROBE_EXPLICIT") {
		t.Error("an explicit environment value did not reach the node command")
	}
}

func directGitHubCredentialProbe(t *testing.T, out string) {
	ctx := context.Background()
	s, err := LibraryScenario("healthy")
	if err != nil {
		t.Fatal(err)
	}
	env, err := DefaultBackend(false, nil).Prepare(ctx, s, NewID())
	if env != nil {
		defer env.Cleanup(ctx, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	ne := env.(*netnsEnv)
	explicit := []string{"NETDOC_PROBE_EXPLICIT=1"}
	probe := credentialProbe{
		Director: envVarNames(os.Environ()),
		Holder:   procEnvNames(t, ne.byName["client"].pid),
	}
	res := ne.Exec(ctx, "client", []string{"env"}, explicit)
	if res.Err != nil || res.ExitCode != 0 {
		t.Fatalf("env in node: exit %d, err %v", res.ExitCode, res.Err)
	}
	probe.Exec = envVarNames(strings.Split(string(res.Stdout), "\n"))
	var interactive bytes.Buffer
	if err := ne.ExecInteractive(ctx, "client", []string{"env"}, explicit, nil, &interactive, io.Discard); err != nil {
		t.Fatal(err)
	}
	probe.Interactive = envVarNames(strings.Split(interactive.String(), "\n"))
	blob, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// procEnvNames reads the environment a live process was started with. The
// kernel keeps it NUL-separated.
func procEnvNames(t *testing.T, pid int) []string {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		t.Fatal(err)
	}
	return envVarNames(strings.Split(string(blob), "\x00"))
}
