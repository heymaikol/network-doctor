// Command netdoc is the Network Doctor CLI. It is the go install entrypoint:
// go install github.com/heymaikol/network-doctor/v2/cmd/netdoc@latest puts a
// binary named netdoc on the PATH, the same CLI the repository root builds.
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
