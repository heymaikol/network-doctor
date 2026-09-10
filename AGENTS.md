# Repository Guidelines

## Build, Test, and Development Commands

Before considering an ordinary change complete, run `./scripts/check`. Use
`./scripts/check --race` when race testing is relevant to the change.

`scripts/check` is the canonical fast local validation command. It does not
replace the exhaustive validation documented in `docs/validation.md`; run
additional checks there when they apply to the change.

Before changing behavior, verify the reported issue against the current HEAD. Do not assume an audit finding, issue description, or suggested implementation is still accurate.

## Coding Style & Naming Conventions

Keep OS behavior in build-tagged or platform-suffixed files; pass `GOOS` into testable tables where practical. Preserve probe dependency graph + bounded timeouts. Prefer command argument slices over shell strings. Do not use em dashes anywhere. Rewrite naturally instead; `TestNoEmDashInTrackedTextFiles` fails the build on any that come back.

## Testing Guidelines

Real-socket tests must keep `integration` build tag, stay loopback-only. Ordinary tests deterministic + rootless.

After changing `internal/textsafe`, fuzz sanitizer: `go test -fuzz=FuzzSanitize -fuzztime=10s ./internal/textsafe`. After changing target parsing or the encrypted-DNS response verifier, fuzz it: `go test -fuzz=FuzzParseTarget -fuzztime=10s ./internal/diagnostic` or `go test -fuzz=FuzzEncryptedDNSResponseVerifier -fuzztime=10s ./internal/diagnostic`. After changing the Challenge Mode hunt generator, fuzz it: `go test -fuzz=FuzzGenerateHuntCase -fuzztime=10s ./internal/simulation`. `internal/ui/jobs_test.go` uses `GO_HELPER` subprocesses to verify process-group cancellation.

Runtime is an invariant too: `internal/diagnostic/budget_test.go` pins the probe graph's stage count, proves both executors overlap independent probes, and bounds a healthy in-memory run. Budgets there are derived from `DefaultProbeTimeout` and `attemptDelay`, not from measured wall clock; if one fails, look for a new dependency edge, a serialized executor, or a probe that waits out a deadline before widening it.

Diagnosis reasoning is also pinned against recorded evidence: `internal/diagnostic.ReplaySnapshot` recomputes a diagnosis from a stored `.ndoc` with no probes, and `testdata/field` holds the cases it is replayed against. See `testdata/field/README.md` before adding one.

## Cross-Platform Guidelines

`scripts/check` compile-checks the supported targets and portability fallback.
Release builds use `CGO_ENABLED=0`; do not introduce cgo. Keep
`internal/diagnostic` independent of `internal/ui`: network semantics in
`diagnostic`, interaction + rendering in `ui`.

## Commit & Pull Request Guidelines

One behavior per commit. PRs explain user-visible effect, list validation commands, link issues, include screenshots or terminal captures for TUI layout changes. Call out platform-specific behavior + any untested OS explicitly.

Commit direct to `main`. Keep commit subjects short, simple, and imperative. Do not use Conventional Commit type or scope prefixes (for example, `Add Star History chart`, never `docs: add Star History chart`, `feat: ...`, or `fix: ...`). Do not add AI session links or metadata such as `Claude-Session` or a `Co-Authored-By` trailer. Keep `--help` on standard `fs.PrintDefaults` formatting. Preserve version injection through `-ldflags "-X main.version=..."` (local builds use `dev`). Release = tag commit already on `main`, push `vX.Y.Z`. GoReleaser publishes the GitHub release. The Homebrew formula is maintained in `Homebrew/homebrew-core`.

## Security & Configuration Tips

Keep probes unprivileged, time-bounded, safe for arbitrary host input. Sanitize external command output. Never interpolate targets into shell. No automatic privilege escalation or config rewrites.
