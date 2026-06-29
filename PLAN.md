# Plan: KISS simplification pass on network-doctor
_Locked via grill — by Claude + mplaczek. Hardened against Codex review rounds 1–2._

> **Scope change from the user's sign-off:** the grill locked two candidates.
> Codex review round 2 showed Candidate 2 (`jobState` struct) no longer clears the
> net-complexity bar once it must preserve all partial-update semantics — it would
> add a type + nesting + churn while removing no real complexity. Per the user's own
> governing rule (KISS over DRY; no abstraction that doesn't remove more than it adds),
> Candidate 2 is **dropped**. This pass is now **Candidate 1 only**. The user is the
> final gate and can reinstate Candidate 2 if they disagree.

## Goal
Reduce complexity in the existing codebase without changing any user-observable
behavior. The native DAG probes, diagnosis engine, two-pane TUI, streaming tool
jobs, and markdown export must all work exactly as they do today. This is a
simplification pass, not a rewrite and not a feature sprint: the deliverable is a
short, honest list of changes that each remove more complexity (concepts, state,
branches, indirection) than they add. The codebase is already largely well-KISS'd
(recent commits consolidated glyph rendering, inlined ExitCode, pruned aliases),
so the qualifying list is deliberately short — padding it would itself violate KISS.

## Frozen behavior contract (must stay byte-identical / user-observable)
- CLI args and parsing; the three target axes (port / protocol / scheme); `--toolbox`
- Exit codes `0` / `1` / `2` — **as the code emits them today**, including the
  pre-existing deferred-quit defect (see Risks); this pass must not change them
- Diagnosis one-line wording (the verdict strings from `diagnosis.go` and probe `Detail`/`Fix`)
- Probe glyphs `✓ ✗ ⊘ –` and their color/status meaning, even if internal names change
- Row labels and probe ordering as shown to the user
- Export markdown format (`export.go` output) — frozen *modulo* the two inherently
  per-run values it embeds: the RFC3339 `time.Now()` generation stamp and the
  timestamped no-clobber filename from `uniquePath()`. Everything else byte-identical.
- Tool command argv, env, and display strings (`ping -c 4 -W 2 …`, the `curl …` flag set, etc.)
- Documented timeout/default behavior and any README-documented examples

**Free to change:** internal names, function boundaries, struct layout, file moves
within a package, duplicate render/state cleanup, simpler control flow, and test
reshaping — as long as the asserted behavior is unchanged.

## Proof gate (run between every commit; stop only with a clean tree)
Required, in order, all green:
1. `gofmt -l .` prints nothing (formatting clean)
2. `go vet ./...`
3. `go build ./...`
4. `go test ./...`
5. `go test -race ./...`
6. `graphify update .` (AST-only, mandated by CLAUDE.md/AGENTS.md after code changes)

Manual (once, before final sign-off): launch the TUI against a normal target,
confirm it opens, streams a tool job, renders the two-pane layout, and exits
cleanly. No deeper click matrix.

**"Clean tree" defined:** commit `PLAN.md` and `PLAN-REVIEW-LOG.md` first, so they
are tracked. Thereafter "clean" means `git status --porcelain` is empty
(`graphify-out/` is gitignored and never appears; the local binary is gitignored).
Each candidate is its own commit; the tree is clean between candidates.

## Approach (one candidate; its own commit, fully gated)

### Candidate 1 — `staticTool` helper in `internal/ui/tools.go`
Six of the seven `Tool` literals (`ip`, `ss`, `ping`, `dig`, `traceroute`, `mtr`)
share an identical `Build` closure shape:
```go
Build: func(*Target) ([]string, []string, string) {
    args := []string{ ... }
    return args, nil, "<bin> " + shellArgs(args)
}
```
Only `curl` differs (it builds a URL and sets `LC_ALL=C` in env). Introduce:
```go
func staticTool(key, name, bin string, args ...string) Tool {
    return Tool{Key: key, Name: name, Bin: bin, Build: func(*Target) ([]string, []string, string) {
        a := slices.Clone(args) // fresh slice per call — matches current per-call allocation
        return a, nil, bin + " " + shellArgs(a)
    }}
}
```
and collapse the six literals to one line each; leave `curl` as its own literal.
- **Clears the bar:** used 6×, removes the repeated boilerplate-closure concept, turns boilerplate into data.
- **Frozen-surface safe:** argv unchanged; display string unchanged (for the static
  tools the display prefix already equals `Bin`); `curl` untouched.
- **Slice aliasing (Codex r1 #3):** the variadic `args` is captured once; returning it
  directly would share one backing array across every `Build` call, unlike today's
  fresh-per-call allocation. `slices.Clone(args)` restores per-call independence.
  (`slices` is in the stdlib; module is Go 1.26.)
- **Coverage is currently absent (Codex r1 #4, r3):** `tools_test.go` only tests
  `extractFacts` and `shellArgs` — **no** test asserts any tool's definition.
  This commit MUST add a table-driven test that pins the **complete ordered list** of
  tools returned by `toolsFor` (both the no-target set and the with-host set), asserting
  for each, in order: `Key`, `Name`, `Bin`, the `Build` argv, env, and display string —
  plus that two successive `Build` calls return slices that are not the same backing
  array (slice independence). `Key`/`Name`/order are user-visible (hotkeys, labels,
  toolbox display order) and `staticTool` now sets them, so a swap or typo must fail the
  test. This test is the safety net for the refactor and must be written/passing in the
  same commit. Derive the expected values from the current literals *before* refactoring.
- **Commit alone, run the full gate.** This is the entire pass.

## Key decisions & tradeoffs
- **Net-complexity bar:** a candidate qualifies only if it removes more complexity than
  it adds. Deleting clears it by default; a new helper clears it only if used 3+ times
  and it reduces concepts, not just lines. Measured in concepts/state/branches/indirection, not LOC.
- **KISS over DRY when they disagree:** fewer hops over fewer repeated characters;
  clear `Update` message flow over clever reuse; obvious local code over abstract helpers.
- **`checks.go` is frozen-adjacent:** its `Detail`/`Fix` strings are the product wording.
  Touch only for changes provably wording-neutral (none planned here).
- **Each candidate is independently shippable and revertable** — no big-bang refactor,
  because one atomic diff hides risk and obscures which simplification actually helped.

## Rejected (evaluated, deliberately not done — reasons kept so they stay rejected)
- **Merge `statusGlyph()` + `glyph()`** — not true duplicates: `statusGlyph` returns a
  bare rune for the markdown export; `glyph` returns a styled string with a spinner
  fallback for the TUI. They share only one map lookup; the `statusGlyphs` map already
  consolidates the data. Merging would couple export formatting to TUI spinner logic.
- **Extract the 3× "cancel job → set pending → return" block** — 3 lines each; a helper
  adds an indirection hop at the call site for near-zero gain. Revisit only if it
  becomes obviously clearer.
- **Centralize the `wasTicking` spinner-tick dance** — only 2 uses (< 3); fails the bar.
- **Flatten probe-result boilerplate in `checks.go` / `diagnosis.go`** — frozen-adjacent
  product wording; idiomatic Go; near-zero readability gain for real frozen-string risk.
- **Fix the value/pointer exit-code defect (Codex r1 #1) in this pass** — it is a real
  bug (see Risks) but resolving it changes an exit code, which violates the no-behavior
  -change contract. Out of scope here; raised to the user for a separate decision.
- **Candidate 2 — `jobState` struct in `model.go` (Codex r2 #1)** — originally accepted,
  dropped after review. Once the rename must preserve every partial-update path exactly
  (r1 #2), grouping the nine flat `job*` fields into a struct adds a new type, a layer of
  nesting (`m.job.x`), and broad churn across `model.go`/`export.go`/tests while removing
  no real complexity — the nine fields and their partial-update logic all survive. That
  fails the net-complexity bar. The job-view/export characterization tests proposed as its
  precondition (r1 #5) are dropped with it; both return only if Candidate 2 is revived.

## Risks / open questions
- **Pre-existing exit-code defect (Codex r1 #1, verified):** the deferred-action path
  (`runPending`, pointer receiver) returns `*model`, but `ExitCode` only type-asserts
  `final.(model)` (value). So quitting *while a tool job is running* yields a `*model`
  to `ExitCode`, which falls through to `return 1` — even on paths the README says are
  `0` (e.g. toolbox mode where the chain never ran, or a completed no-failure chain).
  `TestDeferredQuit` confirms the `*model` return but never calls `ExitCode` on it, so
  the defect is untested. **This pass freezes and preserves this behavior** — and since
  Candidate 1 touches only `tools.go`, no code in this pass goes near the
  `runPending`/`Update` region, so the behavior is preserved by inaction. Whether to fix
  it is a separate question for the user (a one-line `ExitCode` change to also accept
  `*model`, plus a regression test — but that is a behavior change).
- With Candidate 2 dropped, this pass carries little risk: Candidate 1 is a mechanical
  change to two files (`tools.go` and `tools_test.go`). The main residual risk is the new all-tools test
  encoding a wrong expectation — mitigated by deriving expected argv/display from the
  current literals before refactoring.
- Any new duplication/simplification spotted mid-pass goes to Deferred, not acted on.

## Out of scope / deferred
- All roadmap items — `nmap`, multiple concurrent jobs, a `Warn` state, the mtr-parsed
  route-quality row. No new features during this pass.
- Any aggressive refactor of `checks.go`, `diagnosis.go`, or `target.go` (frozen-adjacent).
- The exit-code value/pointer fix (see Risks) — separate decision.
- Mid-pass discoveries: record here, defer; do not expand scope.

## Done
Two commits: (commit 0) commit the plan artifacts; (commit 1) Candidate 1 — the
`staticTool` helper (with `slices.Clone`) plus the new all-seven-tools table test —
with the full gate green. **Done** = Candidate 1 lands cleanly with a clean tree.
That is the whole pass. (If the user reinstates Candidate 2, it returns with its
characterization-test precondition as described in Rejected.)
