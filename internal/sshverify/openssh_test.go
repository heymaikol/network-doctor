package sshverify

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// openSSHRequiredEnv is set where the OpenSSH tests must run, as in CI. A missing client then
// fails the run, so the tests cannot be green by skipping.
const openSSHRequiredEnv = "NETDOC_REQUIRE_OPENSSH"

// requireOpenSSH skips a test that needs the OpenSSH client when none is installed, unless
// openSSHRequiredEnv is set, in which case the test fails.
func requireOpenSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		missingOpenSSH(t, "OpenSSH is not installed")
	}
}

// missingOpenSSH fails the test when OpenSSH is required, and skips it otherwise.
func missingOpenSSH(t *testing.T, why string) {
	t.Helper()
	if os.Getenv(openSSHRequiredEnv) != "" {
		t.Fatalf("%s, and %s is set, so the test must run rather than skip", why, openSSHRequiredEnv)
	}
	t.Skip(why)
}

// childOpenSSHEnv marks the child run that TestMissingOpenSSHFailsOnlyWhenRequired starts.
const childOpenSSHEnv = "NETDOC_CHILD_OPENSSH_TEST"

// TestMissingOpenSSHChild is run only by the test below, in a child process with no client on
// PATH. It asks for the client, as the OpenSSH tests do.
func TestMissingOpenSSHChild(t *testing.T) {
	if os.Getenv(childOpenSSHEnv) == "" {
		t.Skip("run by TestMissingOpenSSHFailsOnlyWhenRequired")
	}
	requireOpenSSH(t)
}

// With the variable set and no client on PATH, a test that needs OpenSSH fails. Without it, the
// test skips. CI sets the variable, so a missing client there is a failure, not a green skip.
func TestMissingOpenSSHFailsOnlyWhenRequired(t *testing.T) {
	run := func(required bool) (string, error) {
		env := []string{childOpenSSHEnv + "=1", "PATH="}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, openSSHRequiredEnv+"=") && !strings.HasPrefix(kv, "PATH=") && !strings.HasPrefix(kv, childOpenSSHEnv+"=") {
				env = append(env, kv)
			}
		}
		if required {
			env = append(env, openSSHRequiredEnv+"=1")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestMissingOpenSSHChild$", "-test.v") // #nosec G204 G702 -- this test binary, with fixed arguments
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}

	out, err := run(true)
	if err == nil || strings.Contains(out, "--- SKIP") {
		t.Fatalf("with %s set, a missing client did not fail the test: %v\n%s", openSSHRequiredEnv, err, out)
	}
	out, err = run(false)
	if err != nil || !strings.Contains(out, "--- SKIP") {
		t.Fatalf("without %s, a missing client did not skip the test: %v\n%s", openSSHRequiredEnv, err, out)
	}
}
