# Validation and testing

This file is the authoritative, copy-pasteable list of the checks that run
against Network Doctor, and what each layer of evidence does and does not
prove. [CONTRIBUTING.md](../CONTRIBUTING.md) covers the contribution workflow
around it, and the wiki's
[Development and Contributing](https://github.com/heymaikol/network-doctor/wiki/Development-and-Contributing)
page explains why each stage exists.

## What an ordinary pull request needs

```sh
./scripts/check
```

That is gofmt, `go vet`, a `CGO_ENABLED=0` build, macOS and Windows
cross-compiles, a FreeBSD build that only proves the fallbacks for unsupported
platforms still compile, and `go test ./...`, with no root and no Docker needed
(a Go toolchain and a POSIX shell: on Windows, Git Bash or WSL). Add `--race`
when race testing is relevant to the change. The checks make no network calls,
though the Go toolchain downloads on a cold module cache or an out-of-date
`toolchain` line.

Then run the tests nearest your change and any additional checks clearly
relevant to the files or behavior you changed. That is almost all a small
external contribution needs.

The exhaustive gate below exists for CI, maintainership, releases, and the
specific checks that apply to your change; a small contribution does not have
to reproduce every CI environment locally.

## The complete gate

The core Go checks run directly, and external validation tools use pinned
`go run` commands, so a Go toolchain is the only prerequisite:

```sh
go vet ./...
CGO_ENABLED=0 go build ./...
go test ./...
go test -tags integration ./internal/app ./internal/diagnostic ./internal/peer ./internal/simulation
go test -tags acceptance -count=1 -run '^TestNative' . ./internal/ui
go test -tags netns_integration -count=1 -v ./internal/simulation
go test -race ./...
go test -race -tags integration ./internal/app ./internal/diagnostic ./internal/peer ./internal/simulation
go test -fuzz=FuzzSanitize -fuzztime=10s ./internal/textsafe
go test -fuzz=FuzzEncryptedDNSResponseVerifier -fuzztime=10s ./internal/diagnostic
go test -fuzz=FuzzParseTarget -fuzztime=10s ./internal/diagnostic
go test -fuzz=FuzzDecodeMessage -fuzztime=10s ./internal/peer
go test -fuzz=FuzzGenerateHuntCase -fuzztime=10s ./internal/simulation
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.1 run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run github.com/goreleaser/goreleaser/v2@v2.17.1 check
```

Those tool versions are held equal to the ones CI's lint job runs, so the gate
cannot drift away from what a pull request is actually measured against.

Race, fuzz, and network-namespace checks run only on Linux in CI. The
`netns_integration` tests skip themselves on a host without unprivileged user
namespaces; they never need root. That gate keeps `-v` because a skipped run and
a real one both print just `ok` otherwise, and `-count=1` because a cached
result would not have exercised any namespace at all.

## Additional checks, by what you touched

CI also syntax-checks every shipped Bash, Zsh, and Fish completion script with
its native shell. Run the same focused check after changing a file under
`packaging/completions/`:

```sh
(
  set -e
  for script in packaging/completions/*.bash; do bash -n "$script"; done
  for script in packaging/completions/*.zsh; do zsh -n "$script"; done
  for script in packaging/completions/*.fish; do fish -n "$script"; done
)
```

If the change touched the `Dockerfile` or the image's release job, also build the
image and test the artifact. It needs Docker or Podman, which is why it is not in
the gate above:

```sh
docker build --build-arg VERSION=dev -t netdoc-sim:test .
NETDOC_CONTAINER_IMAGE=netdoc-sim:test go test -tags container -count=1 -v .
```

If the change touched `docs/`, `site/`, or `cmd/docsite`, also build the
documentation site the way [the pages workflow](../.github/workflows/pages.yml)
does. It needs the wiki checkout and the same container image GitHub Pages
builds with, which is why it is not in the gate above:

```sh
git clone --depth 1 https://github.com/heymaikol/network-doctor.wiki.git ../network-doctor.wiki
go run ./cmd/docsite -wiki ../network-doctor.wiki -out _docsite
docker run --rm -v "$PWD":/gh -e GITHUB_WORKSPACE=/gh \
  -e INPUT_SOURCE=_docsite -e INPUT_DESTINATION=_site \
  -e GITHUB_REPOSITORY=heymaikol/network-doctor \
  ghcr.io/actions/jekyll-build-pages:v1.0.13
go run ./cmd/docsite -verify _site
```

If the change touched a build-tagged or `_linux`/`_darwin`/`_windows` suffixed
file, also compile for macOS and Windows:

```sh
GOOS=darwin go build ./...
GOOS=windows go build ./...
```

## Native acceptance on macOS and Windows

The `acceptance` command has tests only on macOS and Windows, and CI runs it on
both native hosts. It builds the release-shaped `netdoc` and holds its native
route evidence to observations the binary did not produce: the source address
the kernel selects for a connected datagram socket, and the platform's own route
tool, `Find-NetRoute` on Windows and `/sbin/route` on macOS. It also exercises
loopback and the built-in route, socket, and ping drill-down commands. The route
oracles send no application data: a route lookup and a connected UDP socket are
local decisions, while the drill-down checks stay on loopback. It keeps
`-count=1` so a cached result can never stand in for a run that actually touched
the host.

One acceptance test is opt-in, because no hosted runner has the topology it
needs. `TestNativePreparedTargetRouteMatchesTheHostRouteTool` checks the route
evidence netdoc publishes for a user-supplied target against the platform's own
route tool on a host where a route narrower than the default covers that target
and leaves by a different interface, which is how a split tunnel or a lab route
over a second adapter looks. Set `NETDOC_ACCEPTANCE_TARGET` to the destination
as an IP literal (`10.20.0.5`, `10.20.0.5:443` or `[2001:db8::5]:443`; a
hostname is rejected, so no resolver picks which route is under test), and
nothing needs to listen on it. Without the variable the test skips, while a
variable that is present but empty fails, so a job whose value expanded to
nothing hears about it; set `NETDOC_REQUIRE_ACCEPTANCE_TARGET=1` to turn the
remaining skip into a failure too, so a job meant to run it cannot go green
having skipped it. Once opted in, a host that is not actually in that shape
fails rather than skips. The test only observes: it reads routes and opens a
connected datagram socket, and never creates, changes, or removes a route,
interface, tunnel, address, or firewall rule. Preparing that state is a manual
step on a real machine, so CI sets neither variable.

## Three layers of evidence

Three layers sit behind a release, and none of them substitutes for another:

- **Deterministic tests and the Linux namespace simulator** prove the diagnosis
  engine against controlled topologies. They prove nothing about whether the
  Windows or macOS adapter reads its own operating system correctly.
- **Native macOS and Windows acceptance** proves that reading, for the semantics
  a GitHub-hosted runner genuinely exposes: route existence, the selected
  interface, the IPv4 source address where the native API supplies it, IPv6
  source ownership, the next hop, and the matched route entry. Windows also
  checks the source and interface index/alias reported by `Find-NetRoute`. A
  runner with no real tunnel cannot prove VPN classification, so acceptance
  checks only that the native adapter populated a structurally valid link
  classification.
- **Field validation on real networks** is the only evidence for what CI cannot
  manufacture: a real VPN tunnel, a captive portal, split DNS under enterprise
  or VPN routing policy, an IPv6-only or DNS64/NAT64 network, live LAN DNS-SD
  devices, and a managed proxy-only network. Those stay open as field-validation
  issues, and a green CI run never closes one.

## Test hygiene

Ordinary tests stay deterministic, rootless, and offline. Real-socket tests keep
the `integration` build tag and stay loopback-only, and real namespace tests keep
the `netns_integration` tag. Recorded field evidence is replayed rather than
re-probed; see [`testdata/field/README.md`](../testdata/field/README.md) before
adding a case.
