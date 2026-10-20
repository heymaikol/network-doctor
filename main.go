// The netdoc CLI. The implementation lives in internal/app; this entrypoint
// is kept at the module root so go build -o netdoc . and the release,
// container, and RPM build paths that target it keep working. The go install
// entrypoint is cmd/netdoc, which is the same CLI.
package main

import (
	"os"

	"github.com/heymaikol/network-doctor/v2/internal/app"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(version, os.Args[1:], os.Stdout, os.Stderr))
}
