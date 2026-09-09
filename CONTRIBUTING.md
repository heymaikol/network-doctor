# Contributing to Network Doctor

Thanks for helping make network troubleshooting less mysterious. Bug reports,
small fixes, platform-specific testing, and focused feature proposals are all
welcome. Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Choosing something to work on

- `good first issue` marks work intentionally scoped for someone unfamiliar
  with this repository.
- `help wanted` marks work where outside contributions are especially welcome,
  though it may need more familiarity with the repository or its domain.
- A contribution does not have to be Go code. Platform testing and real-network
  field testing are meaningful contributions too.
- When you take an existing issue, leave a short comment saying you intend to
  work on it before investing substantial effort.
- Ask on the issue when the requirements are unclear.

## Before opening an issue

- Search existing issues first.
- Run `netdoc --version` and include the result.
- Include your OS, architecture, install method, target form, and the smallest
  sequence that reproduces the problem.
- Review reports and command output before posting. They may contain hostnames,
  IP addresses, usernames, interface names, or other sensitive network details.

Please use a GitHub Security Advisory or the contact in [SECURITY.md](SECURITY.md)
for vulnerabilities instead of a public issue.

## Development

Network Doctor requires the Go version declared in `go.mod`.

```sh
git clone https://github.com/heymaikol/network-doctor.git
cd network-doctor
go test ./...
go run . github.com
```

The code is split by responsibility:

- `internal/app` owns CLI arguments, process I/O, and application startup; the root `main.go` and `cmd/netdoc/main.go` are thin entrypoints into it, the second being the `go install` path that yields a binary named `netdoc`.
- `internal/diagnostic` owns target parsing, native probes, per-OS route/SSID lookups, and verdict logic without depending on terminal presentation.
- `internal/ui` owns Bubble Tea state, rendering, and tool jobs.
- `internal/textsafe` sanitizes untrusted remote and subprocess text shared by both layers.
- `internal/simulation` + `cmd/netdoc-sim` build virtual networks to test the diagnosis engine against; nothing here ships in the `netdoc` binary.

The UI depends on diagnostics; diagnostics do not depend on the UI. Add network
semantics under `internal/diagnostic`, and interaction or rendering behavior
under `internal/ui`. The simulator depends on `internal/diagnostic` for probe
ids and target parsing, and on nothing in `internal/ui`. This is enforced by
`architecture_test.go`, not just documented; see the wiki's
[Architecture](https://github.com/heymaikol/network-doctor/wiki/Architecture)
page for the full package-dependency diagram and data flow.

Keep network semantics independent of the UI. Put OS-specific behavior in
build-tagged or platform-suffixed files, keep probes unprivileged and bounded,
and pass commands as argument slices rather than shell strings.

## Cleaning build output

Local builds and release dry runs leave generated files in the clone. Remove
them by name; the command is safe to repeat and safe when nothing is there:

```sh
rm -rf netdoc netdoc-sim network-doctor dist vendor network-doctor-*-vendor.tar.gz
```

`vendor/` matters most. GoReleaser's before-hooks write it and the matching
tarball into the repo root at release time, and a leftover `vendor/` silently
switches every later `go build` and `go test` in the clone to `-mod=vendor`,
resolving dependencies from that snapshot instead of `go.mod`. A stale `dist/`
also aborts the next GoReleaser run, which requires it empty.

Prefer the explicit list over `git clean -Xdf`: everything above is ignored,
but so are editor and tool settings such as `.claude/` and `.codex/`, which
that command would delete too.

## Validation

For an ordinary, focused pull request, run:

```sh
./scripts/check
```

That is gofmt, `go vet`, a `CGO_ENABLED=0` build, a macOS and Windows
cross-compile, and `go test ./...`. It needs a Go toolchain and a POSIX shell,
and no root and no Docker. On Windows that shell is the Git Bash that ships
with Git for Windows, or WSL; the checks themselves are the same three
platforms over. Add `--race` to include the race detector. CI runs the same
script on Linux, so it cannot rot without someone noticing.

The checks make no network calls themselves, but the Go toolchain may: a cold
or incomplete module cache downloads this module's dependencies, and a Go
older than the `toolchain` line in `go.mod` downloads that toolchain first.
Warm both once (`go mod download`) and the script runs offline after that.

Then run the tests nearest your change and anything else clearly relevant to
the files or behavior you touched.

**What the script leaves to CI, and why:** the race, fuzz, loopback-integration,
namespace, acceptance and container suites, plus the pinned external tools
(golangci-lint, govulncheck, goreleaser). Those are slower, several need Linux
or Docker, and the pinned tools download on first run. Running the rest of the
[README](README.md#tests) gate locally is worth it where a specific check
applies to your change, for CI, maintainership, or releases; a small external
contribution does not have to reproduce every CI environment.

Additional requirements:

- Real-socket tests use the `integration` build tag and loopback only.
- When a man page's documented behavior or other material content changes,
  update its `.TH` date to that change's date; unrelated source edits do not.
- Changes to `internal/textsafe` require the sanitizer fuzz test shown in the
  validation gate.
- Platform-specific changes should compile for macOS and Windows with
  `GOOS=darwin go build ./...` and `GOOS=windows go build ./...`.
- Release builds use `CGO_ENABLED=0`; do not add cgo dependencies.

## Pull requests

Keep each pull request focused on one behavior. Describe the user-visible
effect, list the validation commands you ran, and call out platform-specific or
untested behavior. Include a screenshot or terminal capture for TUI layout
changes.
