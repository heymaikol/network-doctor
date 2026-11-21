package remote

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/heymaikol/network-doctor/v2/internal/sshverify"
)

// The route read runs the same permission-checked client that verification runs. A
// client that other users can write is refused before any configuration is read with it,
// so a route decision and a verification never trust different programs.
func TestRouteReadRefusesAClientWritableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not gate the client on this platform")
	}
	useFakeSSH(t, "config")
	if err := os.Chmod(sshProgram, 0o777); err != nil { // #nosec G302 -- a test makes its own stand-in writable on purpose, to check the refusal
		t.Fatal(err)
	}
	route := Route(context.Background(), "ideapad")
	if route.Kind != sshverify.RouteUnknown || !strings.Contains(route.Reason, "writable by other users") {
		t.Fatalf("a client writable by others gave %s (%q); want it refused before any read", route.Kind, route.Reason)
	}
}
