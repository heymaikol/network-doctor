package ui

import (
	"strings"
	"testing"
)

func TestSSHProfileHostEqualsSeparators(t *testing.T) {
	config := "Host=equal\nHost = spaced\nHost =inline\nHost= separated\n"
	if got := strings.Join(parseSSHHostProfiles(config), ","); got != "equal,spaced,inline,separated" {
		t.Fatalf("profiles with an equals separator = %q", got)
	}
}
