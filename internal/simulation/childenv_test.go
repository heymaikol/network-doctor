package simulation

import (
	"slices"
	"testing"
)

// Names decide, not substrings: a near-miss name such as GH_TOKEN_FILE is an
// ordinary variable and must pass through.
func TestWithoutCredentialsDropsExactNamesOnly(t *testing.T) {
	in := []string{
		"GH_TOKEN=dummy", "GITHUB_TOKEN=dummy", "GH_ENTERPRISE_TOKEN=dummy", "GITHUB_ENTERPRISE_TOKEN=dummy",
		"gh_token=dummy", "GH_TOKEN_FILE=/x", "MY_GH_TOKEN=dummy", "GH_HOST=example.test", "PATH=/usr/bin",
	}
	want := []string{"GH_TOKEN_FILE=/x", "MY_GH_TOKEN=dummy", "GH_HOST=example.test", "PATH=/usr/bin"}
	if got := withoutCredentials(in); !slices.Equal(got, want) {
		t.Errorf("withoutCredentials = %q, want %q", got, want)
	}
}

// Without any credential, the environment passes through unchanged.
func TestWithoutCredentialsLeavesOtherEnvAlone(t *testing.T) {
	want := []string{"PATH=/usr/bin", "HOME=/home/nobody", "GH_HOST=example.test"}
	if got := withoutCredentials(want); !slices.Equal(got, want) {
		t.Errorf("withoutCredentials = %q, want %q", got, want)
	}
}

// Only credentials in the environment: the result must be empty but not nil,
// because a nil Env makes exec inherit every variable, tokens included.
func TestWithoutCredentialsNeverReturnsNil(t *testing.T) {
	if got := withoutCredentials([]string{"GH_TOKEN=dummy"}); got == nil || len(got) != 0 {
		t.Errorf("withoutCredentials = %#v, want an empty non-nil slice", got)
	}
}
