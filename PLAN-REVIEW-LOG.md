# Plan Review Log: KISS simplification pass on network-doctor
Act 1 (grill) complete — plan locked with the user. MAX_ROUNDS=5.

## Round 1 — Codex
1. **Exit-code contract is already false:** deferred quit returns `*model` (model.go:264), but `ExitCode` accepts only `model` (app.go:20), producing exit 1 in toolbox mode after quitting an active tool.
   Fix: Resolve the value/pointer inconsistency and add an `ExitCode` regression test for deferred quit before freezing behavior.
2. **Candidate 2's "single assignment" changes observable behavior:** failed launches currently retain selected prior fields such as `jobDropped` and sometimes `facts` (model.go:293); zeroing the struct removes them.
   Fix: Specify every job-state transition and explicitly decide whether stale-field cleanup is an authorized bug fix or behavior that must be preserved.
3. **Candidate 1 introduces mutable slice aliasing:** `staticTool` returns its captured variadic `args` slice repeatedly, whereas every current `Build` call allocates a fresh slice.
   Fix: Return `slices.Clone(args)` or `append([]string(nil), args...)` from the helper.
4. **The claimed tool coverage is inaccurate:** only ping and curl construction are asserted; exact argv/env/display for `ip`, `ss`, `dig`, `traceroute`, and `mtr` are untested.
   Fix: Add a table-driven test covering exact `Bin`, argv, env, and display for all seven tools, including repeated-build slice independence.
5. **The proof gate cannot establish "byte-identical" behavior:** generic build/test/race checks and one happy-path manual run do not cover failed launch, cancellation, timeout, pending replacement, export, or dropped-output rendering—the exact surface Candidate 2 changes.
   Fix: Add deterministic before/after golden tests for job views and exports across all job lifecycle states.
6. **The clean-tree requirement is impossible as written:** `PLAN.md` and `PLAN-REVIEW-LOG.md` are already untracked.
   Fix: Define cleanliness relative to the starting porcelain snapshot or require the plan artifacts to be committed first.
7. **Repository-required verification is omitted:** the plan excludes `gofmt`, `go vet`, and the mandated post-change `graphify update .`.
   Fix: Add formatting, vetting, and graph refresh to each candidate's verification checklist.
8. **Candidate 2 leaves its schema unresolved:** "pick" among `jb`, `jobState`, and related naming pushes a consequential ownership decision into implementation while claiming the plan is locked.
   Fix: Specify the exact type, field name, zero-state invariant, and which fields remain outside it before implementation.

VERDICT: REVISE

### Claude's response
Verified every finding against the source before acting (final arbiter; Codex advises).

- **#1 — accepted as a finding, rejected as an in-scope fix.** Confirmed real: `runPending`
  has a pointer receiver and returns `*model`; `ExitCode` only asserts `final.(model)`;
  `asModelP`'s own comment documents the `*model` return; `TestDeferredQuit` never calls
  `ExitCode`, so the defect is untested. But fixing it changes an exit code → violates the
  no-behavior-change contract. PLAN now **freezes and preserves** this behavior, documents
  it in Risks, forbids Candidate 2 from altering it, and raises the fix to the user as a
  separate decision.
- **#2 — accepted.** Confirmed current update paths are partial (failed launch leaves stale
  `dropped`/`start`; `doRerun` resets 5 of 9 fields). Candidate 2 rewritten as a *pure
  mechanical field rename* that preserves every partial update exactly; explicitly forbids
  `m.job = jobState{}` where current code is partial. Honestly noted this shrinks C2's ROI.
- **#3 — accepted.** Helper now returns `slices.Clone(args)` for per-call slice independence.
- **#4 — accepted.** Confirmed `tools_test.go` only tests `extractFacts`/`shellArgs`.
  C1 now must add a table-driven test of `Bin`/argv/env/display for all 7 tools + slice
  independence, in the same commit, as the refactor's safety net.
- **#5 — accepted, scaled down.** No golden-file framework (over-engineering); instead a
  precondition commit adds plain `testing` assertions pinning `jobView()` + `exportReport()`
  across done/canceled/failed-launch/dropped>0 states before Candidate 2.
- **#6 — accepted.** "Clean tree" now defined: commit plan artifacts first, then clean =
  empty `git status --porcelain` (graphify-out and binary are gitignored).
- **#7 — accepted.** Gate now: `gofmt -l`, `go vet`, build, test, `-race`, then
  `graphify update .` (confirmed mandated by AGENTS.md + CLAUDE.md).
- **#8 — accepted.** `jobState` schema pinned: exact type, fields, the `job jobState` field
  name, `activeJob` stays outside, and the zero-value invariant (`jobState{}` == initial state).

## Round 2 — Codex
Prior findings #1–#4, #6–#8 explicitly addressed. Remaining issues:
1. Candidate 2 no longer clears its own KISS bar: it retains all nine fields and partial-update complexity while adding a type, nesting, and broad churn.
   Fix: Drop Candidate 2 and finish after Candidate 1.
2. Its proposed tests do not pin the frozen stale-field semantics: ordinary failed-launch tests starting from zero state cannot detect accidental full resets.
   Fix: Seed sentinel values and assert exact before/after state for rerun, unavailable binary, start failure, successful launch, and completion.
3. "Byte-for-byte" export verification remains underspecified because exports contain the current timestamp.
   Fix: Normalize/inject time and compare the complete export body, not selected substrings.

VERDICT: REVISE

### Claude's response
- **#1 — accepted.** This is the cross-model check working: Codex held the plan to its own
  net-complexity bar. After the r1 #2 behavior-preservation constraint, Candidate 2 adds a
  type + nesting + churn while preserving all nine fields and their partial-update logic →
  no net complexity removed → fails the bar. **Candidate 2 dropped.** The pass is now
  Candidate 1 only. Flagged as a deviation from the user's two-candidate sign-off, for the
  user to confirm or override at the final gate.
- **#2 — moot, accepted as consequence.** The stale-field pinning tests existed only to
  de-risk Candidate 2's rename. With C2 dropped, adding tests for behavior nothing changes
  would be scope creep; they are dropped with C2 and noted as returning only if C2 revives.
- **#3 — accepted.** Confirmed `exportReport` embeds `time.Now()` (RFC3339) and a
  timestamped no-clobber filename, so literal byte-identity is impossible. Contract wording
  tightened to "frozen modulo the per-run timestamp and filename." No test added (no
  candidate touches export now).

## Round 3 — Codex
Prior findings addressed or made moot by dropping Candidate 2.
New issue: the all-tools test omits exact `Key`, `Name`, and ordering, although Candidate 1 rewrites those user-visible values and existing uniqueness tests would not catch swaps or renamed labels.
   Fix: Assert the complete ordered tool definitions: `Key`, `Name`, `Bin`, argv, env, display, and slice independence.
Also remove stale "see Candidate 2" references now that it is rejected.

VERDICT: REVISE

### Claude's response
- **Test scope — accepted.** `staticTool(key, name, bin, args...)` sets `Key`/`Name`, which
  are user-visible (hotkeys, labels) and frozen, and `toolsFor`'s order is the toolbox
  display order (also frozen). Test spec tightened: pin the complete ordered tool list from
  `toolsFor` (no-target and with-host sets), asserting Key/Name/Bin/argv/env/display per
  tool in order, plus slice independence; derive expected values from current literals
  before refactoring.
- **Stale refs — accepted.** Removed the now-irrelevant frozen-contract bullet about
  per-path job-state semantics (it existed only because Candidate 2 would touch those
  paths; nothing in this pass does). Reworded the exit-code Risks note: no code in this
  pass goes near `runPending`/`Update`, so the defect is preserved by inaction. Remaining
  "Candidate 2" mentions are intentional (scope-change note, Rejected entry, Risks, Done).

## Round 4 — Codex
All prior material findings are addressed. Candidate 2 is removed, tool tests cover complete ordered definitions, slice ownership is preserved, and verification/clean-tree requirements are explicit.
Minor wording only: "single-file change" should say two-file change because tests also change.

VERDICT: APPROVED

### Claude's response
- Accepted the wording fix: Candidate 1 touches `tools.go` and `tools_test.go` (two files).
- Converged at round 4 of 5. Plan locked for user sign-off.
