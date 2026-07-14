# Repository Guidelines

## Project Structure & Module Organization

`main.go` contains CLI handling, JSON output, and application startup. Network probes, target parsing, and diagnosis logic live in `internal/diagnostic/`; the Bubble Tea interface, tool launching, reports, and fixes live in `internal/ui/`. Output sanitization is isolated in `internal/textsafe/`. Tests are co-located as `*_test.go`. Platform implementations use suffixes such as `_linux.go`, `_darwin.go`, and `_windows.go`; release and CI configuration lives in `.goreleaser.yaml` and `.github/workflows/`.

## Build, Test, and Development Commands

- `go build -o network-doctor .` builds the local executable.
- `go run . github.com:443` runs the TUI against a target without installing it.
- `go run . --json github.com` exercises the headless reporting path.
- `go test ./...` runs the standard unit and subprocess tests.
- `go test -race ./...` checks concurrent probe and job code for races (CI runs this on Linux).
- `go test -tags integration ./internal/diagnostic` runs opt-in checks that use real network access.
- `go vet ./...` performs the static checks required by CI.
- `golangci-lint run ./...` runs the configured lint suite used by CI.

Use Go 1.26.4 or the version declared in `go.mod`.

## Coding Style & Naming Conventions

Run `gofmt -w` on changed Go files; use standard Go tabs and import grouping. Exported identifiers use `PascalCase`, internal helpers use `camelCase`, and tests use `TestBehavior` names. Keep OS behavior in build-tagged or platform-suffixed files, while passing `GOOS` into testable tables where practical. Preserve the probe dependency graph and bounded timeouts; prefer command argument slices over shell strings.

## Testing Guidelines

Add focused tests beside the changed package. Prefer table-driven tests for target parsing, diagnosis branches, and platform commands. Network-dependent tests must retain the `integration` build tag; ordinary tests should be deterministic and rootless. Before submitting, run `go vet ./...`, `go build ./...`, and `go test ./...`; use the race detector for concurrency changes.

After changing `internal/textsafe`, fuzz its sanitizer with `go test -fuzz=FuzzSanitize -fuzztime=10s ./internal/textsafe`. `internal/ui/jobs_test.go` uses `GO_HELPER` subprocesses to verify process-group cancellation.

## Cross-Platform Guidelines

After changing a platform-tagged file, compile-check the other targets with `GOOS=darwin go build ./...` and `GOOS=windows go build ./...`. Release builds use `CGO_ENABLED=0`; do not introduce cgo. Keep `internal/diagnostic` independent of `internal/ui`: network semantics belong in `diagnostic`, while interaction and rendering belong in `ui`.

## Commit & Pull Request Guidelines

Recent commits use concise, imperative subjects such as `Fix data race on ProbeResult` and `Keep the view within the terminal height`. Keep each commit scoped to one behavior. Pull requests should explain the user-visible effect, list validation commands, link relevant issues, and include screenshots or terminal captures for TUI layout changes. Call out platform-specific behavior and any untested OS explicitly.

Commit directly to `main` with no `Co-Authored-By` trailer. Keep `--help` on the standard `fs.PrintDefaults` formatting, and preserve version injection through `-ldflags "-X main.version=..."` (local builds use `dev`). A release means tagging and pushing `vX.Y.Z`; GoReleaser publishes the GitHub release, Homebrew cask, and AUR package.

## Security & Configuration Tips

Keep probes unprivileged, time-bounded, and safe for arbitrary host input. Sanitize external command output, never interpolate targets into a shell, and do not add automatic privilege escalation or configuration rewrites.
